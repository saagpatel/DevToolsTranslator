use glassbox_live_source::{GapReason, LiveSourceError, LiveSourcePolicy, LiveSourceSession};
use serde::{Deserialize, Deserializer, Serialize};
use std::io::{self, BufRead, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use zeroize::Zeroizing;

const MAX_CONFIG_BYTES: usize = 16 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BrokerConfig {
    protocol_version: u16,
    bind: SocketAddr,
    session_id: String,
    source_id: String,
    source_epoch: u64,
    credential: SecretString,
    max_frame_bytes: usize,
    max_events: u64,
    max_total_bytes: u64,
    max_events_per_second: u32,
    watchdog_timeout_ms: u64,
}

struct SecretString(Zeroizing<String>);

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(|value| Self(Zeroizing::new(value)))
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum BrokerOutput {
    Ready {
        protocol_version: u16,
        bound: SocketAddr,
    },
    Complete {
        accepted_events: u64,
        accepted_bytes: u64,
        gaps: Vec<glassbox_live_source::GapReceipt>,
    },
    OutboundDenied {
        target: SocketAddr,
        error_kind: String,
    },
    Rejected {
        code: &'static str,
    },
}

#[derive(Debug, Error)]
enum BrokerError {
    #[error("configuration exceeds the 16 KiB bound")]
    ConfigTooLarge,
    #[error("configuration must be one complete JSON line")]
    MissingConfig,
    #[error("only protocol version 1 is supported")]
    UnsupportedProtocol,
    #[error("broker may bind only an IP loopback address")]
    NonLoopbackBind,
    #[error("frame length exceeds its configured bound")]
    FrameTooLarge,
    #[error("truncated frame")]
    TruncatedFrame,
    #[error("outbound connection unexpectedly succeeded")]
    OutboundUnexpectedlyAllowed,
    #[error("watchdog timeout must be between 100 ms and 30 seconds")]
    InvalidWatchdog,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Session(#[from] LiveSourceError),
}

fn main() {
    let result = if std::env::args().any(|arg| arg == "--self-test-outbound-denied") {
        outbound_denial_probe()
    } else {
        run()
    };
    if let Err(error) = result {
        let code = match error {
            BrokerError::NonLoopbackBind => "non_loopback_bind",
            BrokerError::OutboundUnexpectedlyAllowed => "outbound_allowed",
            BrokerError::Session(LiveSourceError::QuotaExceeded) => "quota_exceeded",
            BrokerError::Session(_) => "session_rejected",
            _ => "broker_failed",
        };
        let _ = write_output(&BrokerOutput::Rejected { code });
        eprintln!("glassbox OTLP broker: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), BrokerError> {
    let config = read_config()?;
    if config.protocol_version != 1 {
        return Err(BrokerError::UnsupportedProtocol);
    }
    if !config.bind.ip().is_loopback() {
        return Err(BrokerError::NonLoopbackBind);
    }
    if !(100..=30_000).contains(&config.watchdog_timeout_ms) {
        return Err(BrokerError::InvalidWatchdog);
    }
    let policy = LiveSourcePolicy {
        max_frame_bytes: config.max_frame_bytes,
        max_events: config.max_events,
        max_total_bytes: config.max_total_bytes,
        max_events_per_second: config.max_events_per_second,
    };
    let mut session = LiveSourceSession::new(
        config.session_id,
        config.source_id,
        config.source_epoch,
        config.credential.0.to_string(),
        policy,
    )?;
    let listener = TcpListener::bind(config.bind)?;
    listener.set_nonblocking(true)?;
    let bound = listener.local_addr()?;
    write_output(&BrokerOutput::Ready { protocol_version: 1, bound })?;
    let deadline = Instant::now() + Duration::from_millis(config.watchdog_timeout_ms);
    let (mut stream, peer) = loop {
        match listener.accept() {
            Ok(connection) => break connection,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                session.disconnect(GapReason::WatchdogTimeout);
                write_complete(&session, 0, 0)?;
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        }
    };
    if !peer.ip().is_loopback() {
        return Err(BrokerError::NonLoopbackBind);
    }
    stream.set_read_timeout(Some(Duration::from_millis(config.watchdog_timeout_ms)))?;
    let mut accepted_events = 0_u64;
    let mut accepted_bytes = 0_u64;
    loop {
        let mut length = [0_u8; 4];
        match stream.read_exact(&mut length) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                session.disconnect(GapReason::Disconnected);
                break;
            }
            Err(error)
                if matches!(error.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) =>
            {
                session.disconnect(GapReason::WatchdogTimeout);
                break;
            }
            Err(error) => return Err(error.into()),
        }
        let length = u32::from_be_bytes(length) as usize;
        if length > config.max_frame_bytes {
            return Err(BrokerError::FrameTooLarge);
        }
        let mut frame = vec![0_u8; length];
        if let Err(error) = stream.read_exact(&mut frame) {
            session.disconnect(
                if matches!(error.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) {
                    GapReason::WatchdogTimeout
                } else {
                    GapReason::Disconnected
                },
            );
            write_complete(&session, accepted_events, accepted_bytes)?;
            return Err(if error.kind() == io::ErrorKind::UnexpectedEof {
                BrokerError::TruncatedFrame
            } else {
                error.into()
            });
        }
        if let Err(error) = session.accept(&frame, now_ms()) {
            write_complete(&session, accepted_events, accepted_bytes)?;
            return Err(error.into());
        }
        accepted_events = accepted_events.saturating_add(1);
        accepted_bytes = accepted_bytes.saturating_add(length as u64);
    }
    if session.is_active() {
        session.disconnect(GapReason::Disconnected);
    }
    write_complete(&session, accepted_events, accepted_bytes)?;
    Ok(())
}

fn write_complete(
    session: &LiveSourceSession,
    accepted_events: u64,
    accepted_bytes: u64,
) -> Result<(), BrokerError> {
    write_output(&BrokerOutput::Complete {
        accepted_events,
        accepted_bytes,
        gaps: session.gaps().to_vec(),
    })
}

fn read_config() -> Result<BrokerConfig, BrokerError> {
    let mut input = io::stdin().lock().take((MAX_CONFIG_BYTES + 1) as u64);
    let mut line = String::new();
    input.read_line(&mut line)?;
    if line.is_empty() || !line.ends_with('\n') {
        return Err(BrokerError::MissingConfig);
    }
    if line.len() > MAX_CONFIG_BYTES {
        return Err(BrokerError::ConfigTooLarge);
    }
    serde_json::from_str(&line).map_err(Into::into)
}

fn outbound_denial_probe() -> Result<(), BrokerError> {
    let target: SocketAddr = "1.1.1.1:443".parse().expect("constant socket address");
    match TcpStream::connect_timeout(&target, Duration::from_millis(250)) {
        Ok(_) => Err(BrokerError::OutboundUnexpectedlyAllowed),
        Err(error) => {
            write_output(&BrokerOutput::OutboundDenied {
                target,
                error_kind: format!("{:?}", error.kind()),
            })?;
            Ok(())
        }
    }
}

fn write_output(output: &BrokerOutput) -> Result<(), BrokerError> {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, output)?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn non_loopback_addresses_are_rejected_by_policy() {
        for addr in ["0.0.0.0:0", "192.0.2.1:4318", "[::]:0"] {
            let parsed: SocketAddr = addr.parse().unwrap();
            assert!(!parsed.ip().is_loopback());
        }
    }
    #[test]
    fn loopback_addresses_are_allowed_by_policy() {
        for addr in ["127.0.0.1:0", "[::1]:0"] {
            let parsed: SocketAddr = addr.parse().unwrap();
            assert!(parsed.ip().is_loopback());
        }
    }
    #[test]
    fn output_never_serializes_credentials_or_payloads() {
        let output = serde_json::to_string(&BrokerOutput::Complete {
            accepted_events: 1,
            accepted_bytes: 10,
            gaps: vec![],
        })
        .unwrap();
        assert!(!output.contains("credential"));
        assert!(!output.contains("payload"));
    }
    #[test]
    fn ip_loopback_check_does_not_accept_hostnames() {
        let _: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        assert!("localhost".parse::<std::net::IpAddr>().is_err());
    }
}
