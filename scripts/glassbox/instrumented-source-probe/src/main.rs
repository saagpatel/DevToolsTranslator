use serde::{Deserialize, Deserializer, Serialize};
use serde_json::json;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const MAX_CONFIG_BYTES: usize = 32 * 1024;
const MAX_EVENTS: u16 = 1_000;
const MAX_FRAME_BYTES: usize = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    protocol_version: u16,
    endpoint: SocketAddr,
    session_id: String,
    source_id: String,
    source_epoch: u64,
    credential: SecretString,
    event_count: u16,
}

struct SecretString(Zeroizing<String>);

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(|value| Self(Zeroizing::new(value)))
    }
}

#[derive(Serialize)]
struct Receipt {
    schema_version: &'static str,
    frames_sent: u16,
    bytes_sent: u64,
    endpoint_was_loopback: bool,
    credential_exposed: bool,
}

#[derive(Serialize)]
struct LiveFrame<'a> {
    protocol_version: u16,
    session_id: &'a str,
    source_id: &'a str,
    source_epoch: u64,
    sequence: u16,
    credential: &'a str,
    captured_at_ms: u64,
    payload: serde_json::Value,
}

fn main() {
    if std::env::args_os().nth(1).is_some() {
        fail("arguments_rejected");
    }
    match run() {
        Ok(receipt) => println!("{}", serde_json::to_string(&receipt).expect("receipt serializes")),
        Err(code) => fail(code),
    }
}

fn fail(code: &'static str) -> ! {
    eprintln!("glassbox reference source: {code}");
    std::process::exit(1)
}

fn run() -> Result<Receipt, &'static str> {
    let config = read_config()?;
    if config.protocol_version != 1 {
        return Err("unsupported_protocol");
    }
    if !config.endpoint.ip().is_loopback() {
        return Err("non_loopback_endpoint");
    }
    if config.event_count == 0 || config.event_count > MAX_EVENTS {
        return Err("invalid_event_count");
    }
    if config.credential.0.len() < 32
        || config.credential.0.len() > 256
        || !config.credential.0.is_ascii()
    {
        return Err("invalid_credential");
    }
    if !valid_id(&config.session_id) || !valid_id(&config.source_id) {
        return Err("invalid_identifier");
    }

    let mut stream = TcpStream::connect_timeout(&config.endpoint, Duration::from_secs(2))
        .map_err(|_| "connect_failed")?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| "socket_configuration_failed")?;
    let mut bytes_sent = 0_u64;
    for sequence in 0..config.event_count {
        let payload = json!({
                "resourceSpans": [{
                    "resource": {"attributes": [{
                        "key": "reference.private.token",
                        "value": {"stringValue": "reference-secret-do-not-retain"}
                    }]},
                    "scopeSpans": [{
                        "scope": {"name": "glassbox.reference.instrumentation"},
                        "spans": [{
                            "traceId": format!("5b8efff798038103d269b633{:08x}", sequence),
                            "spanId": format!("{:016x}", u64::from(sequence) + 1),
                            "name": "private-reference-operation",
                            "kind": 2,
                            "startTimeUnixNano": format!("{}", 1_581_452_772_000_000_321_u64 + u64::from(sequence) * 1_000),
                            "endTimeUnixNano": format!("{}", 1_581_452_773_000_000_789_u64 + u64::from(sequence) * 1_000),
                            "attributes": [],
                            "events": [],
                            "links": []
                        }]
                    }]
                }]
        });
        let frame = LiveFrame {
            protocol_version: 1,
            session_id: &config.session_id,
            source_id: &config.source_id,
            source_epoch: config.source_epoch,
            sequence,
            credential: config.credential.0.as_str(),
            captured_at_ms: now_ms().saturating_add(u64::from(sequence)),
            payload,
        };
        let encoded =
            Zeroizing::new(serde_json::to_vec(&frame).map_err(|_| "frame_encoding_failed")?);
        if encoded.len() > MAX_FRAME_BYTES {
            return Err("frame_too_large");
        }
        let length = u32::try_from(encoded.len()).map_err(|_| "frame_too_large")?.to_be_bytes();
        stream.write_all(&length).map_err(|_| "send_failed")?;
        stream.write_all(&encoded).map_err(|_| "send_failed")?;
        bytes_sent = bytes_sent.saturating_add(4 + encoded.len() as u64);
    }
    stream.flush().map_err(|_| "send_failed")?;
    stream.shutdown(Shutdown::Write).map_err(|_| "shutdown_failed")?;
    Ok(Receipt {
        schema_version: "glassbox-reference-instrumented-source/v1",
        frames_sent: config.event_count,
        bytes_sent,
        endpoint_was_loopback: true,
        credential_exposed: false,
    })
}

fn valid_id(value: &str) -> bool {
    (8..=128).contains(&value.len())
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn read_config() -> Result<Config, &'static str> {
    let mut input = io::stdin().lock().take((MAX_CONFIG_BYTES + 1) as u64);
    let mut bytes = Vec::new();
    input.read_to_end(&mut bytes).map_err(|_| "config_read_failed")?;
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err("config_too_large");
    }
    let line = bytes.strip_suffix(b"\n").ok_or("invalid_config_framing")?;
    if line.is_empty() || line.contains(&b'\n') || line.contains(&b'\r') {
        return Err("invalid_config_framing");
    }
    serde_json::from_slice(line).map_err(|_| "invalid_config")
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
