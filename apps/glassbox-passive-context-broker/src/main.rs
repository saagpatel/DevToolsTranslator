use glassbox_passive_context_broker::{parse_snapshot, MAX_SNAPSHOT_BYTES};
use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, Read};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;
use zeroize::Zeroizing;

const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(2);
const ARP_PATH: &str = "/usr/sbin/arp";
const MAX_REQUEST_BYTES: usize = 4096;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BrokerRequest {
    protocol_version: u16,
    consent_token: String,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum BrokerOutput<T> {
    Snapshot { snapshot: T },
    Rejected { code: &'static str },
}

fn main() {
    if let Err(error) = run() {
        let code = match error {
            BrokerError::NotEnabled => "not_enabled",
            BrokerError::ConsentRequired => "consent_required",
            BrokerError::ConsentRejected => "consent_rejected",
            BrokerError::UnsupportedOperation => "unsupported_operation",
            BrokerError::SnapshotTimeout => "snapshot_timeout",
            BrokerError::SnapshotTooLarge => "snapshot_too_large",
            _ => "snapshot_failed",
        };
        let _ = write_output(&BrokerOutput::<()>::Rejected { code });
        eprintln!("glassbox passive-context broker: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), BrokerError> {
    if std::env::var("GLASSBOX_PASSIVE_CONTEXT_ENABLED").as_deref() != Ok("1") {
        return Err(BrokerError::NotEnabled);
    }
    let expected = Zeroizing::new(
        std::env::var("GLASSBOX_PASSIVE_CONTEXT_CONSENT_TOKEN")
            .map_err(|_| BrokerError::ConsentRequired)?,
    );
    if expected.len() < 24 {
        return Err(BrokerError::ConsentRequired);
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut input = io::BufReader::new(io::stdin().lock());
    let request = read_request(&mut input)?;
    let supplied = Zeroizing::new(request.consent_token);
    if request.protocol_version != 1 || !constant_time_eq(supplied.as_bytes(), expected.as_bytes())
    {
        return Err(BrokerError::ConsentRejected);
    }
    let bytes = match args.as_slice() {
        [operation] if operation == "--parse-stdin" => read_bounded(input)?,
        [operation] if operation == "--snapshot" => {
            let trailing = read_bounded(input)?;
            if trailing.iter().any(|byte| !byte.is_ascii_whitespace()) {
                return Err(BrokerError::UnexpectedInput);
            }
            capture_neighbor_table()?
        }
        _ => return Err(BrokerError::UnsupportedOperation),
    };
    let snapshot = parse_snapshot(&bytes)?;
    write_output(&BrokerOutput::Snapshot { snapshot })?;
    Ok(())
}

fn read_request(reader: &mut impl BufRead) -> Result<BrokerRequest, BrokerError> {
    let mut line = String::new();
    reader.take((MAX_REQUEST_BYTES + 1) as u64).read_line(&mut line)?;
    if line.is_empty() || !line.ends_with('\n') {
        return Err(BrokerError::ConsentRequired);
    }
    if line.len() > MAX_REQUEST_BYTES {
        return Err(BrokerError::RequestTooLarge);
    }
    serde_json::from_str(&line).map_err(Into::into)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        difference |= usize::from(left_byte ^ right_byte);
    }
    difference == 0
}

fn capture_neighbor_table() -> Result<Vec<u8>, BrokerError> {
    let mut child = Command::new(ARP_PATH)
        .arg("-an")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env_clear()
        .spawn()?;
    let stdout = child.stdout.take().ok_or(BrokerError::MissingStdout)?;
    let reader = thread::spawn(move || read_bounded(stdout));
    let deadline = Instant::now() + SNAPSHOT_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                return Err(BrokerError::SnapshotCommandFailed);
            }
            return reader.join().map_err(|_| BrokerError::ReaderPanicked)?;
        }
        if Instant::now() >= deadline {
            child.kill()?;
            let _ = child.wait();
            return Err(BrokerError::SnapshotTimeout);
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn read_bounded(mut reader: impl Read) -> Result<Vec<u8>, BrokerError> {
    let mut bytes = Vec::new();
    reader.by_ref().take((MAX_SNAPSHOT_BYTES + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err(BrokerError::SnapshotTooLarge);
    }
    Ok(bytes)
}

fn write_output<T: Serialize>(output: &BrokerOutput<T>) -> Result<(), BrokerError> {
    serde_json::to_writer(io::stdout().lock(), output)?;
    println!();
    Ok(())
}

#[derive(Debug, Error)]
enum BrokerError {
    #[error("passive context is independently disabled")]
    NotEnabled,
    #[error("explicit consent is required")]
    ConsentRequired,
    #[error("consent capability was stale or invalid")]
    ConsentRejected,
    #[error("operation is not on the passive broker allowlist")]
    UnsupportedOperation,
    #[error("request exceeds 4096 bytes")]
    RequestTooLarge,
    #[error("snapshot operation received unexpected input")]
    UnexpectedInput,
    #[error("neighbor snapshot timed out")]
    SnapshotTimeout,
    #[error("neighbor snapshot exceeds its bound")]
    SnapshotTooLarge,
    #[error("neighbor snapshot command failed")]
    SnapshotCommandFailed,
    #[error("neighbor snapshot stdout was unavailable")]
    MissingStdout,
    #[error("neighbor snapshot reader panicked")]
    ReaderPanicked,
    #[error(transparent)]
    Parse(#[from] glassbox_passive_context_broker::PassiveContextError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
