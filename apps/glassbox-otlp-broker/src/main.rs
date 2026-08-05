use glassbox_contracts::{
    LineageId, MaterializationId, NativeObservation, SemanticObservationId, SourceTrust,
    TimeInterval,
};
use glassbox_evidence_bundle::write_lossless;
use glassbox_import_worker::LiveOtlpProjector;
use glassbox_kernel::EvidenceKernel;
use glassbox_live_source::{GapReason, LiveSourceError, LiveSourcePolicy, LiveSourceSession};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufRead, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::{FromRawFd, RawFd};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use zeroize::Zeroizing;

const MAX_CONFIG_BYTES: usize = 16 * 1024;
const MAX_REJECTED_PEERS: usize = 16;
const STOP_POLL_INTERVAL: Duration = Duration::from_millis(100);

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
        evidence: Option<EvidenceReceipt>,
    },
    OutboundDenied {
        target: SocketAddr,
        error_kind: String,
    },
    Rejected {
        code: &'static str,
    },
}

#[derive(Debug, Serialize)]
struct EvidenceReceipt {
    schema_version: &'static str,
    observations: usize,
    relations: usize,
    bundle_bytes: usize,
    bundle_sha256: String,
    published_to_inherited_descriptor: bool,
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
    #[error("arguments must be empty or one bounded inherited evidence descriptor")]
    InvalidArguments,
    #[error("live evidence projection was rejected")]
    EvidenceRejected,
    #[error(transparent)]
    Projection(#[from] glassbox_import_worker::WorkerError),
    #[error(transparent)]
    Bundle(#[from] glassbox_evidence_bundle::BundleError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Session(#[from] LiveSourceError),
}

fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let result = if arguments == ["--self-test-outbound-denied"] {
        outbound_denial_probe()
    } else {
        evidence_descriptor(&arguments).and_then(run)
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

fn evidence_descriptor(arguments: &[String]) -> Result<Option<RawFd>, BrokerError> {
    if arguments.is_empty() {
        return Ok(None);
    }
    if arguments.len() != 1 {
        return Err(BrokerError::InvalidArguments);
    }
    let value = arguments[0]
        .strip_prefix("--evidence-fd=")
        .ok_or(BrokerError::InvalidArguments)?
        .parse::<RawFd>()
        .map_err(|_| BrokerError::InvalidArguments)?;
    if !(3..=1024).contains(&value) {
        return Err(BrokerError::InvalidArguments);
    }
    Ok(Some(value))
}

fn run(evidence_fd: Option<RawFd>) -> Result<(), BrokerError> {
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
    let session_id = config.session_id.clone();
    let source_id = config.source_id.clone();
    let mut projector = LiveOtlpProjector::new(&source_id, &session_id)?;
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
    let stop = stop_receiver();
    let watchdog = Duration::from_millis(config.watchdog_timeout_ms);
    let attach_deadline = Instant::now() + watchdog;
    let mut rejected_peers = 0_usize;
    let (mut stream, first_frame_bytes) = loop {
        if stop_requested(&stop) {
            session.disconnect(GapReason::Revoked);
            write_complete(&session, 0, 0, None)?;
            return Ok(());
        }
        if Instant::now() >= attach_deadline || rejected_peers >= MAX_REJECTED_PEERS {
            session.disconnect(GapReason::WatchdogTimeout);
            write_complete(&session, 0, 0, None)?;
            return Ok(());
        }
        match listener.accept() {
            Ok((mut candidate, peer)) => {
                if !peer.ip().is_loopback() {
                    return Err(BrokerError::NonLoopbackBind);
                }
                candidate.set_read_timeout(Some(STOP_POLL_INTERVAL))?;
                match read_frame_until(
                    &mut candidate,
                    config.max_frame_bytes,
                    attach_deadline,
                    &stop,
                ) {
                    Ok(FrameOutcome::Frame(frame)) => match session.accept(&frame, now_ms()) {
                        Ok(accepted) => {
                            if projector.push_payload(&accepted.payload).is_err() {
                                session.disconnect(GapReason::InvalidPayload);
                                write_complete(&session, 0, 0, None)?;
                                return Err(BrokerError::EvidenceRejected);
                            }
                            break (candidate, frame.len());
                        }
                        Err(LiveSourceError::QuotaExceeded) => {
                            write_complete(&session, 0, 0, None)?;
                            return Err(LiveSourceError::QuotaExceeded.into());
                        }
                        Err(_) => {
                            write_output(&BrokerOutput::Rejected { code: "session_rejected" })?;
                            rejected_peers = rejected_peers.saturating_add(1);
                        }
                    },
                    Ok(FrameOutcome::Stopped) => {
                        session.disconnect(GapReason::Revoked);
                        write_complete(&session, 0, 0, None)?;
                        return Ok(());
                    }
                    Ok(FrameOutcome::Deadline) => {
                        session.disconnect(GapReason::WatchdogTimeout);
                        write_complete(&session, 0, 0, None)?;
                        return Ok(());
                    }
                    Ok(FrameOutcome::Eof) | Err(BrokerError::FrameTooLarge) => {
                        write_output(&BrokerOutput::Rejected { code: "broker_failed" })?;
                        rejected_peers = rejected_peers.saturating_add(1);
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error.into()),
        }
    };
    let mut accepted_events = 1_u64;
    let mut accepted_bytes = first_frame_bytes as u64;
    loop {
        let deadline = Instant::now() + watchdog;
        match read_frame_until(&mut stream, config.max_frame_bytes, deadline, &stop) {
            Ok(FrameOutcome::Frame(frame)) => {
                let accepted = match session.accept(&frame, now_ms()) {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        write_complete(&session, accepted_events, accepted_bytes, None)?;
                        return Err(error.into());
                    }
                };
                if projector.push_payload(&accepted.payload).is_err() {
                    session.disconnect(GapReason::InvalidPayload);
                    write_complete(&session, accepted_events, accepted_bytes, None)?;
                    return Err(BrokerError::EvidenceRejected);
                }
                accepted_events = accepted_events.saturating_add(1);
                accepted_bytes = accepted_bytes.saturating_add(frame.len() as u64);
            }
            Ok(FrameOutcome::Eof) => {
                session.disconnect(GapReason::Disconnected);
                break;
            }
            Ok(FrameOutcome::Deadline) => {
                session.disconnect(GapReason::WatchdogTimeout);
                break;
            }
            Ok(FrameOutcome::Stopped) => {
                session.disconnect(GapReason::Revoked);
                break;
            }
            Err(error) => {
                session.disconnect(GapReason::Disconnected);
                write_complete(&session, accepted_events, accepted_bytes, None)?;
                return Err(error);
            }
        }
    }
    if session.is_active() {
        session.disconnect(GapReason::Disconnected);
    }
    let evidence =
        publish_evidence(projector, session.gaps(), &source_id, &session_id, evidence_fd)?;
    write_complete(&session, accepted_events, accepted_bytes, Some(evidence))?;
    Ok(())
}

enum FrameOutcome {
    Frame(Vec<u8>),
    Eof,
    Deadline,
    Stopped,
}

fn read_frame_until(
    stream: &mut TcpStream,
    maximum_bytes: usize,
    deadline: Instant,
    stop: &Receiver<()>,
) -> Result<FrameOutcome, BrokerError> {
    let mut length = [0_u8; 4];
    match read_exact_until(stream, &mut length, deadline, stop)? {
        ReadOutcome::Complete => {}
        ReadOutcome::Eof => return Ok(FrameOutcome::Eof),
        ReadOutcome::Deadline => return Ok(FrameOutcome::Deadline),
        ReadOutcome::Stopped => return Ok(FrameOutcome::Stopped),
    }
    let length = u32::from_be_bytes(length) as usize;
    if length > maximum_bytes {
        return Err(BrokerError::FrameTooLarge);
    }
    let mut frame = vec![0_u8; length];
    match read_exact_until(stream, &mut frame, deadline, stop)? {
        ReadOutcome::Complete => Ok(FrameOutcome::Frame(frame)),
        ReadOutcome::Eof => Err(BrokerError::TruncatedFrame),
        ReadOutcome::Deadline => Ok(FrameOutcome::Deadline),
        ReadOutcome::Stopped => Ok(FrameOutcome::Stopped),
    }
}

enum ReadOutcome {
    Complete,
    Eof,
    Deadline,
    Stopped,
}

fn read_exact_until(
    stream: &mut TcpStream,
    output: &mut [u8],
    deadline: Instant,
    stop: &Receiver<()>,
) -> io::Result<ReadOutcome> {
    let mut offset = 0_usize;
    while offset < output.len() {
        if stop_requested(stop) {
            return Ok(ReadOutcome::Stopped);
        }
        if Instant::now() >= deadline {
            return Ok(ReadOutcome::Deadline);
        }
        match stream.read(&mut output[offset..]) {
            Ok(0) => return Ok(ReadOutcome::Eof),
            Ok(bytes) => offset = offset.saturating_add(bytes),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::WouldBlock
                ) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(ReadOutcome::Complete)
}

fn stop_receiver() -> Receiver<()> {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut input = io::stdin().lock();
        loop {
            let mut line = String::new();
            match input.read_line(&mut line) {
                Ok(0) | Err(_) => return,
                Ok(_) if line == "stop\n" => {
                    let _ = sender.send(());
                    return;
                }
                Ok(_) => {}
            }
        }
    });
    receiver
}

fn stop_requested(stop: &Receiver<()>) -> bool {
    match stop.try_recv() {
        Ok(()) => true,
        Err(TryRecvError::Empty | TryRecvError::Disconnected) => false,
    }
}

fn write_complete(
    session: &LiveSourceSession,
    accepted_events: u64,
    accepted_bytes: u64,
    evidence: Option<EvidenceReceipt>,
) -> Result<(), BrokerError> {
    write_output(&BrokerOutput::Complete {
        accepted_events,
        accepted_bytes,
        gaps: session.gaps().to_vec(),
        evidence,
    })
}

fn publish_evidence(
    projector: LiveOtlpProjector,
    gaps: &[glassbox_live_source::GapReceipt],
    source_id: &str,
    session_id: &str,
    evidence_fd: Option<RawFd>,
) -> Result<EvidenceReceipt, BrokerError> {
    let mut batch = projector.finish()?;
    for (ordinal, gap) in gaps.iter().enumerate() {
        batch.observations.push(gap_observation(source_id, session_id, ordinal, gap)?);
    }
    let mut kernel = EvidenceKernel::default();
    kernel
        .import_atomic(batch.observations.clone(), batch.relations.clone())
        .map_err(|_| BrokerError::EvidenceRejected)?;
    let mut bundle = Vec::new();
    write_lossless(&mut bundle, &batch.observations, &batch.relations)?;
    let digest = format!("{:x}", Sha256::digest(&bundle));
    let published = if let Some(fd) = evidence_fd {
        // SAFETY: the descriptor is explicitly supplied by the parent, bounded
        // to a non-stdio integer, and ownership transfers to this process.
        let mut output = unsafe { File::from_raw_fd(fd) };
        output.write_all(&bundle)?;
        output.flush()?;
        true
    } else {
        false
    };
    Ok(EvidenceReceipt {
        schema_version: "glassbox-live-evidence/v1",
        observations: batch.observations.len(),
        relations: batch.relations.len(),
        bundle_bytes: bundle.len(),
        bundle_sha256: digest,
        published_to_inherited_descriptor: published,
    })
}

fn gap_observation(
    source_id: &str,
    session_id: &str,
    ordinal: usize,
    gap: &glassbox_live_source::GapReceipt,
) -> Result<NativeObservation, BrokerError> {
    let native_id = format!("otlp-live://{source_id}/{session_id}/gap/{ordinal}");
    let time = now_ns();
    let mut fields = BTreeMap::from([
        ("event".into(), "coverage_gap".into()),
        ("reason".into(), gap_reason_name(gap.reason).into()),
        ("source_epoch".into(), gap.source_epoch.to_string()),
    ]);
    if let Some(sequence) = gap.after_sequence {
        fields.insert("after_sequence".into(), sequence.to_string());
    }
    if let Some(sequence) = gap.next_sequence {
        fields.insert("next_sequence".into(), sequence.to_string());
    }
    Ok(NativeObservation {
        semantic_id: SemanticObservationId::derive("otel-live-gap", session_id, &native_id),
        materialization_id: MaterializationId(format!(
            "otel-live-gap-materialization:{session_id}:{ordinal}"
        )),
        lineage_id: LineageId(format!("otel-live-gap-lineage:{session_id}:{ordinal}")),
        source_kind: "otel-live-gap".into(),
        capture_session: session_id.into(),
        native_id,
        observed_time: TimeInterval::new(time, time).map_err(|_| BrokerError::EvidenceRejected)?,
        trust: SourceTrust::SourceDeclared,
        fields,
    })
}

fn gap_reason_name(reason: GapReason) -> &'static str {
    match reason {
        GapReason::SequenceGap => "sequence_gap",
        GapReason::Disconnected => "disconnected",
        GapReason::QuotaExceeded => "quota_exceeded",
        GapReason::Revoked => "revoked",
        GapReason::EpochChanged => "epoch_changed",
        GapReason::WatchdogTimeout => "watchdog_timeout",
        GapReason::InvalidPayload => "invalid_payload",
    }
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

fn now_ns() -> i128 {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    i128::from(duration.as_secs()) * 1_000_000_000 + i128::from(duration.subsec_nanos())
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
            evidence: None,
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
