use glassbox_contracts::{
    LineageId, MaterializationId, NativeObservation, SemanticObservationId, SourceTrust,
    TimeInterval,
};
use glassbox_evidence_bundle::write_lossless;
use glassbox_kernel::EvidenceKernel;
use glassbox_passive_context_broker::{
    parse_snapshot, NeighborState, Snapshot, MAX_SNAPSHOT_BYTES,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufRead, Read, Write};
use std::os::fd::{FromRawFd, RawFd};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use zeroize::Zeroizing;

const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(2);
const ARP_PATH: &str = "/usr/sbin/arp";
const MAX_REQUEST_BYTES: usize = 4096;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BrokerRequest {
    protocol_version: u16,
    capture_session: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum BrokerOutput {
    Evidence { evidence: EvidenceReceipt },
    Rejected { code: &'static str },
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

fn main() {
    if let Err(error) = run() {
        let code = match error {
            BrokerError::ConsentRequired => "consent_required",
            BrokerError::UnsupportedOperation => "unsupported_operation",
            BrokerError::SnapshotTimeout => "snapshot_timeout",
            BrokerError::SnapshotTooLarge => "snapshot_too_large",
            _ => "snapshot_failed",
        };
        let _ = write_output(&BrokerOutput::Rejected { code });
        eprintln!("glassbox passive-context broker: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), BrokerError> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (operation, evidence_fd, consent_fd) = match args.as_slice() {
        [operation, evidence, consent]
            if matches!(operation.as_str(), "--parse-stdin-evidence" | "--snapshot-evidence") =>
        {
            let evidence_fd = parse_evidence_fd(evidence)?;
            let consent_fd = parse_consent_fd(consent)?;
            if evidence_fd == consent_fd {
                return Err(BrokerError::InvalidArguments);
            }
            (operation.as_str(), evidence_fd, consent_fd)
        }
        _ => return Err(BrokerError::UnsupportedOperation),
    };
    let expected = read_inherited_consent(consent_fd)?;
    if !(24..=256).contains(&expected.len()) || !expected.is_ascii() {
        return Err(BrokerError::ConsentRequired);
    }
    let mut input = io::BufReader::new(io::stdin().lock());
    let request = read_request(&mut input)?;
    if request.protocol_version != 1 {
        return Err(BrokerError::UnexpectedInput);
    }
    let bytes = match operation {
        "--parse-stdin-evidence" => read_bounded(input)?,
        "--snapshot-evidence" => {
            let trailing = read_bounded(input)?;
            if trailing.iter().any(|byte| !byte.is_ascii_whitespace()) {
                return Err(BrokerError::UnexpectedInput);
            }
            capture_neighbor_table()?
        }
        _ => return Err(BrokerError::UnsupportedOperation),
    };
    let snapshot = parse_snapshot(&bytes)?;
    let capture_session = request.capture_session.as_deref().ok_or(BrokerError::InvalidSession)?;
    validate_session(capture_session)?;
    let evidence = publish_evidence(&snapshot, capture_session, evidence_fd)?;
    write_output(&BrokerOutput::Evidence { evidence })?;
    Ok(())
}

fn parse_consent_fd(argument: &str) -> Result<RawFd, BrokerError> {
    let descriptor = argument
        .strip_prefix("--consent-fd=")
        .ok_or(BrokerError::InvalidArguments)?
        .parse::<RawFd>()
        .map_err(|_| BrokerError::InvalidArguments)?;
    if !(3..=1024).contains(&descriptor) {
        return Err(BrokerError::InvalidArguments);
    }
    Ok(descriptor)
}

fn read_inherited_consent(descriptor: RawFd) -> Result<Zeroizing<String>, BrokerError> {
    // SAFETY: the controller passes a bounded, non-stdio descriptor and transfers
    // ownership to this one-shot process.
    let mut input = unsafe { File::from_raw_fd(descriptor) };
    let mut bytes = Zeroizing::new(Vec::new());
    Read::take(&mut input, 258).read_to_end(bytes.as_mut())?;
    if bytes.len() > 257 || bytes.last() != Some(&b'\n') {
        return Err(BrokerError::ConsentRequired);
    }
    bytes.pop();
    if bytes.contains(&b'\n') || bytes.contains(&b'\r') {
        return Err(BrokerError::ConsentRequired);
    }
    String::from_utf8(bytes.to_vec()).map(Zeroizing::new).map_err(|_| BrokerError::ConsentRequired)
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

fn parse_evidence_fd(argument: &str) -> Result<RawFd, BrokerError> {
    let descriptor = argument
        .strip_prefix("--evidence-fd=")
        .ok_or(BrokerError::InvalidArguments)?
        .parse::<RawFd>()
        .map_err(|_| BrokerError::InvalidArguments)?;
    if !(3..=1024).contains(&descriptor) {
        return Err(BrokerError::InvalidArguments);
    }
    Ok(descriptor)
}

fn validate_session(value: &str) -> Result<(), BrokerError> {
    if !(1..=128).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(BrokerError::InvalidSession);
    }
    Ok(())
}

fn publish_evidence(
    snapshot: &Snapshot,
    capture_session: &str,
    descriptor: RawFd,
) -> Result<EvidenceReceipt, BrokerError> {
    let observed_time = now_ns();
    let mut observations = snapshot
        .neighbors
        .iter()
        .enumerate()
        .map(|(index, neighbor)| {
            let ordinal = index + 1;
            let native_id = format!("neighbor-table://entry/{ordinal}");
            let fields = BTreeMap::from([
                ("event".into(), "passive_logical_context".into()),
                (
                    "state".into(),
                    match neighbor.state {
                        NeighborState::Reachable => "reachable",
                        NeighborState::Incomplete => "incomplete",
                    }
                    .into(),
                ),
                ("conflict".into(), neighbor.conflict.to_string()),
                ("role".into(), "logical_context_only".into()),
                ("trust".into(), "untrusted_local_observation".into()),
                ("active_probe_performed".into(), "false".into()),
                ("not_physical_topology".into(), "true".into()),
                ("not_device_ownership".into(), "true".into()),
                ("not_packet_or_process_attribution".into(), "true".into()),
                ("not_causal_evidence".into(), "true".into()),
            ]);
            Ok(NativeObservation {
                semantic_id: SemanticObservationId::derive(
                    "passive-neighbor-context",
                    capture_session,
                    &native_id,
                ),
                materialization_id: MaterializationId(format!(
                    "passive-neighbor-materialization:{capture_session}:{ordinal}"
                )),
                lineage_id: LineageId(format!(
                    "passive-neighbor-lineage:{capture_session}:{ordinal}"
                )),
                source_kind: "passive-neighbor-context".into(),
                capture_session: capture_session.into(),
                native_id,
                observed_time: TimeInterval::new(observed_time, observed_time)
                    .map_err(|_| BrokerError::EvidenceRejected)?,
                trust: SourceTrust::Unknown,
                fields,
            })
        })
        .collect::<Result<Vec<_>, BrokerError>>()?;
    let summary_native_id = "neighbor-table://snapshot";
    observations.push(NativeObservation {
        semantic_id: SemanticObservationId::derive(
            "passive-neighbor-snapshot",
            capture_session,
            summary_native_id,
        ),
        materialization_id: MaterializationId(format!(
            "passive-neighbor-snapshot-materialization:{capture_session}"
        )),
        lineage_id: LineageId(format!("passive-neighbor-snapshot-lineage:{capture_session}")),
        source_kind: "passive-neighbor-snapshot".into(),
        capture_session: capture_session.into(),
        native_id: summary_native_id.into(),
        observed_time: TimeInterval::new(observed_time, observed_time)
            .map_err(|_| BrokerError::EvidenceRejected)?,
        trust: SourceTrust::Unknown,
        fields: BTreeMap::from([
            ("event".into(), "passive_logical_snapshot".into()),
            ("neighbor_count".into(), snapshot.neighbors.len().to_string()),
            ("active_probe_performed".into(), "false".into()),
            ("not_physical_topology".into(), "true".into()),
            ("not_device_ownership".into(), "true".into()),
            ("not_packet_or_process_attribution".into(), "true".into()),
            ("not_causal_evidence".into(), "true".into()),
        ]),
    });
    let mut kernel = EvidenceKernel::default();
    kernel
        .import_atomic(observations.clone(), Vec::new())
        .map_err(|_| BrokerError::EvidenceRejected)?;
    let mut bundle = Vec::new();
    write_lossless(&mut bundle, &observations, &[])?;
    let bundle_sha256 = format!("{:x}", Sha256::digest(&bundle));
    // SAFETY: the caller explicitly passes a bounded, non-stdio descriptor and
    // transfers ownership to this one-shot process.
    let mut output = unsafe { File::from_raw_fd(descriptor) };
    output.write_all(&bundle)?;
    output.flush()?;
    Ok(EvidenceReceipt {
        schema_version: "glassbox-passive-evidence/v1",
        observations: observations.len(),
        relations: 0,
        bundle_bytes: bundle.len(),
        bundle_sha256,
        published_to_inherited_descriptor: true,
    })
}

fn now_ns() -> i128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .try_into()
        .unwrap_or(i128::MAX)
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

fn write_output(output: &BrokerOutput) -> Result<(), BrokerError> {
    serde_json::to_writer(io::stdout().lock(), output)?;
    println!();
    Ok(())
}

#[derive(Debug, Error)]
enum BrokerError {
    #[error("explicit consent is required")]
    ConsentRequired,
    #[error("operation is not on the passive broker allowlist")]
    UnsupportedOperation,
    #[error("arguments must contain distinct bounded inherited evidence and consent descriptors")]
    InvalidArguments,
    #[error("capture session is missing or invalid")]
    InvalidSession,
    #[error("passive evidence failed kernel validation")]
    EvidenceRejected,
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
    #[error(transparent)]
    Bundle(#[from] glassbox_evidence_bundle::BundleError),
}
