use glassbox_contracts::{
    LineageId, MaterializationId, NativeObservation, SemanticObservationId, SourceTrust,
    TimeInterval,
};
use glassbox_evidence_bundle::write_lossless;
use glassbox_kernel::EvidenceKernel;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufRead, Read, Write};
use std::os::fd::{FromRawFd, RawFd};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use zeroize::Zeroizing;

const MAX_CONFIG_BYTES: usize = 4096;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureConfig {
    protocol_version: u16,
    capture_session: String,
    process_id: i32,
    process_bundle_id: String,
    interval_ms: u64,
    maximum_samples: usize,
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

#[derive(Debug)]
struct ProcessSample {
    cpu_user_time_ns: u64,
    cpu_system_time_ns: u64,
    resident_bytes: u64,
    physical_footprint_bytes: u64,
    wakeups: u64,
}

#[cfg(target_os = "macos")]
struct ProcessReader {
    process_id: i32,
    executable_uuid: [u8; 16],
    process_start_abstime: u64,
}

#[cfg(target_os = "macos")]
impl ProcessReader {
    fn read(process_id: i32) -> Result<libc::rusage_info_v2, BrokerError> {
        let mut usage = unsafe { std::mem::zeroed::<libc::rusage_info_v2>() };
        let status = unsafe {
            libc::proc_pid_rusage(process_id, libc::RUSAGE_INFO_V2, (&raw mut usage).cast())
        };
        if status != 0 {
            return Err(BrokerError::ProcessUnavailable);
        }
        Ok(usage)
    }

    fn new(process_id: i32) -> Result<Self, BrokerError> {
        if process_id <= 0 {
            return Err(BrokerError::InvalidConfig);
        }
        let usage = Self::read(process_id)?;
        Ok(Self {
            process_id,
            executable_uuid: usage.ri_uuid,
            process_start_abstime: usage.ri_proc_start_abstime,
        })
    }

    fn sample(&self) -> Result<ProcessSample, BrokerError> {
        let usage = Self::read(self.process_id)?;
        if usage.ri_uuid != self.executable_uuid
            || usage.ri_proc_start_abstime != self.process_start_abstime
        {
            return Err(BrokerError::ProcessIdentityChanged);
        }
        Ok(ProcessSample {
            cpu_user_time_ns: usage.ri_user_time,
            cpu_system_time_ns: usage.ri_system_time,
            resident_bytes: usage.ri_resident_size,
            physical_footprint_bytes: usage.ri_phys_footprint,
            wakeups: usage.ri_pkg_idle_wkups.saturating_add(usage.ri_interrupt_wkups),
        })
    }
}

#[cfg(not(target_os = "macos"))]
struct ProcessReader;

#[cfg(not(target_os = "macos"))]
impl ProcessReader {
    fn new(_process_id: i32) -> Result<Self, BrokerError> {
        Err(BrokerError::UnsupportedPlatform)
    }

    fn sample(&self) -> Result<ProcessSample, BrokerError> {
        Err(BrokerError::UnsupportedPlatform)
    }
}

fn main() {
    if let Err(error) = run() {
        let code = match error {
            BrokerError::ConsentRequired => "consent_required",
            BrokerError::InvalidConfig => "invalid_config",
            BrokerError::ProcessUnavailable | BrokerError::ProcessIdentityChanged => {
                "process_unavailable"
            }
            BrokerError::Cancelled => "cancelled",
            _ => "capture_failed",
        };
        let _ = write_output(&BrokerOutput::Rejected { code });
        eprintln!("glassbox process-context broker: request rejected");
        std::process::exit(1);
    }
}

fn run() -> Result<(), BrokerError> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let [operation, evidence_argument, consent_argument] = arguments.as_slice() else {
        return Err(BrokerError::InvalidArguments);
    };
    if operation != "--capture" {
        return Err(BrokerError::InvalidArguments);
    }
    let evidence_descriptor = parse_descriptor(evidence_argument, "--evidence-fd=")?;
    let consent_descriptor = parse_descriptor(consent_argument, "--consent-fd=")?;
    if evidence_descriptor == consent_descriptor {
        return Err(BrokerError::InvalidArguments);
    }
    let consent = read_consent(consent_descriptor)?;
    if !(24..=256).contains(&consent.len()) || !consent.is_ascii() {
        return Err(BrokerError::ConsentRequired);
    }
    let config = {
        let mut input = io::stdin().lock();
        read_config(&mut input)?
    };
    validate_config(&config)?;
    let (send_control, receive_control) = mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        match io::stdin().lock().read_line(&mut line) {
            Ok(_) if line == "stop\n" => {
                let _ = send_control.send(Control::Stop);
            }
            _ => {}
        }
    });
    let observations = capture(&config, receive_control)?;
    let receipt = publish(&observations, evidence_descriptor)?;
    write_output(&BrokerOutput::Evidence { evidence: receipt })?;
    Ok(())
}

fn parse_descriptor(argument: &str, prefix: &str) -> Result<RawFd, BrokerError> {
    let descriptor = argument
        .strip_prefix(prefix)
        .ok_or(BrokerError::InvalidArguments)?
        .parse::<RawFd>()
        .map_err(|_| BrokerError::InvalidArguments)?;
    if !(3..=1024).contains(&descriptor) {
        return Err(BrokerError::InvalidArguments);
    }
    Ok(descriptor)
}

fn read_consent(descriptor: RawFd) -> Result<Zeroizing<String>, BrokerError> {
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

fn read_config(reader: &mut impl BufRead) -> Result<CaptureConfig, BrokerError> {
    let mut line = String::new();
    reader.take((MAX_CONFIG_BYTES + 1) as u64).read_line(&mut line)?;
    if line.is_empty() || !line.ends_with('\n') || line.len() > MAX_CONFIG_BYTES {
        return Err(BrokerError::InvalidConfig);
    }
    serde_json::from_str(&line).map_err(|_| BrokerError::InvalidConfig)
}

fn validate_config(config: &CaptureConfig) -> Result<(), BrokerError> {
    let valid_session = (1..=128).contains(&config.capture_session.len())
        && config
            .capture_session
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'));
    let valid_bundle = (3..=255).contains(&config.process_bundle_id.len())
        && config.process_bundle_id.contains('.')
        && config
            .process_bundle_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'));
    if config.protocol_version != 1
        || !valid_session
        || config.process_id <= 0
        || !valid_bundle
        || !(100..=5_000).contains(&config.interval_ms)
        || !(1..=600).contains(&config.maximum_samples)
        || config.interval_ms.saturating_mul(config.maximum_samples as u64) > 30_000
    {
        return Err(BrokerError::InvalidConfig);
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Control {
    Stop,
}

fn capture(
    config: &CaptureConfig,
    control: Receiver<Control>,
) -> Result<Vec<NativeObservation>, BrokerError> {
    let reader = ProcessReader::new(config.process_id)?;
    let mut observations = Vec::with_capacity(config.maximum_samples.saturating_add(1));
    let mut terminal_reason = "maximum_samples";
    for ordinal in 0..config.maximum_samples {
        if ordinal > 0 {
            match control.recv_timeout(Duration::from_millis(config.interval_ms)) {
                Ok(Control::Stop) => {
                    terminal_reason = "user_stop";
                    break;
                }
                Err(RecvTimeoutError::Disconnected) => return Err(BrokerError::Cancelled),
                Err(RecvTimeoutError::Timeout) => {}
            }
        } else {
            match control.try_recv() {
                Ok(Control::Stop) => {
                    terminal_reason = "user_stop";
                    break;
                }
                Err(mpsc::TryRecvError::Disconnected) => return Err(BrokerError::Cancelled),
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        let earliest = unix_time_ns()?;
        let sample = match reader.sample() {
            Ok(sample) => sample,
            Err(_) if !observations.is_empty() => {
                terminal_reason = "process_unavailable";
                break;
            }
            Err(error) => return Err(error),
        };
        let latest = unix_time_ns()?;
        observations.push(sample_observation(config, ordinal, earliest, latest, sample)?);
    }
    observations.push(terminal_observation(
        config,
        observations.len(),
        terminal_reason,
        observations.len(),
    )?);
    Ok(observations)
}

fn sample_observation(
    config: &CaptureConfig,
    ordinal: usize,
    earliest_ns: i128,
    latest_ns: i128,
    sample: ProcessSample,
) -> Result<NativeObservation, BrokerError> {
    let native_id =
        format!("sampler://process/{}/selected/sample/{ordinal}", config.capture_session);
    Ok(NativeObservation {
        semantic_id: SemanticObservationId::derive(
            "process-resource-sampler",
            &config.capture_session,
            &native_id,
        ),
        materialization_id: MaterializationId(format!(
            "process-resource-materialization:{}:{ordinal}",
            config.capture_session
        )),
        lineage_id: LineageId(format!(
            "process-resource-lineage:{}:{ordinal}",
            config.capture_session
        )),
        source_kind: "process-resource-sampler".into(),
        capture_session: config.capture_session.clone(),
        native_id,
        observed_time: TimeInterval::new(earliest_ns, latest_ns)
            .map_err(|_| BrokerError::EvidenceRejected)?,
        trust: SourceTrust::SourceDeclared,
        fields: BTreeMap::from([
            ("event".into(), "process_sample".into()),
            ("process_scope".into(), "explicit_selected_gui_application".into()),
            ("process_bundle_id".into(), config.process_bundle_id.clone()),
            ("identity_basis".into(), "user_selected_controller_claim".into()),
            ("cpu_user_time_ns".into(), sample.cpu_user_time_ns.to_string()),
            ("cpu_system_time_ns".into(), sample.cpu_system_time_ns.to_string()),
            ("resident_bytes".into(), sample.resident_bytes.to_string()),
            ("physical_footprint_bytes".into(), sample.physical_footprint_bytes.to_string()),
            ("wakeups".into(), sample.wakeups.to_string()),
            ("bundle_identifier_not_authenticated_by_helper".into(), "true".into()),
            ("not_process_pid".into(), "true".into()),
            ("not_process_path_or_arguments".into(), "true".into()),
            ("not_network_or_file_activity".into(), "true".into()),
            ("not_causal_evidence".into(), "true".into()),
        ]),
    })
}

fn terminal_observation(
    config: &CaptureConfig,
    ordinal: usize,
    reason: &str,
    sample_count: usize,
) -> Result<NativeObservation, BrokerError> {
    let time = unix_time_ns()?;
    let native_id = format!("sampler://process/{}/selected/terminal", config.capture_session);
    Ok(NativeObservation {
        semantic_id: SemanticObservationId::derive(
            "process-resource-sampler",
            &config.capture_session,
            &native_id,
        ),
        materialization_id: MaterializationId(format!(
            "process-resource-materialization:{}:{ordinal}",
            config.capture_session
        )),
        lineage_id: LineageId(format!(
            "process-resource-lineage:{}:terminal",
            config.capture_session
        )),
        source_kind: "process-resource-sampler".into(),
        capture_session: config.capture_session.clone(),
        native_id,
        observed_time: TimeInterval::new(time, time).map_err(|_| BrokerError::EvidenceRejected)?,
        trust: SourceTrust::SourceDeclared,
        fields: BTreeMap::from([
            ("event".into(), "session_end".into()),
            ("process_scope".into(), "explicit_selected_gui_application".into()),
            ("process_bundle_id".into(), config.process_bundle_id.clone()),
            ("reason".into(), reason.into()),
            ("sample_count".into(), sample_count.to_string()),
            ("not_causal_evidence".into(), "true".into()),
        ]),
    })
}

fn publish(
    observations: &[NativeObservation],
    descriptor: RawFd,
) -> Result<EvidenceReceipt, BrokerError> {
    let mut kernel = EvidenceKernel::default();
    kernel
        .import_atomic(observations.to_vec(), Vec::new())
        .map_err(|_| BrokerError::EvidenceRejected)?;
    let mut bundle = Vec::new();
    write_lossless(&mut bundle, observations, &[])?;
    let sha256 = format!("{:x}", Sha256::digest(&bundle));
    let mut output = unsafe { File::from_raw_fd(descriptor) };
    output.write_all(&bundle)?;
    output.flush()?;
    Ok(EvidenceReceipt {
        schema_version: "glassbox-process-evidence/v1",
        observations: observations.len(),
        relations: 0,
        bundle_bytes: bundle.len(),
        bundle_sha256: sha256,
        published_to_inherited_descriptor: true,
    })
}

fn unix_time_ns() -> Result<i128, BrokerError> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| BrokerError::Clock)?;
    Ok(i128::from(duration.as_secs()) * 1_000_000_000 + i128::from(duration.subsec_nanos()))
}

fn write_output(output: &BrokerOutput) -> Result<(), BrokerError> {
    serde_json::to_writer(io::stdout().lock(), output)?;
    println!();
    Ok(())
}

#[derive(Debug, Error)]
enum BrokerError {
    #[error("arguments must contain capture and two distinct inherited descriptors")]
    InvalidArguments,
    #[error("one-shot consent capability is missing or invalid")]
    ConsentRequired,
    #[error("capture configuration is invalid or outside absolute bounds")]
    InvalidConfig,
    #[error("selected process resource usage is unavailable")]
    ProcessUnavailable,
    #[error("selected process identity changed")]
    ProcessIdentityChanged,
    #[error("controller disconnected without an explicit stop")]
    Cancelled,
    #[cfg(not(target_os = "macos"))]
    #[error("process context is supported only on macOS")]
    UnsupportedPlatform,
    #[error("process evidence failed kernel validation")]
    EvidenceRejected,
    #[error("system clock is unavailable")]
    Clock,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Bundle(#[from] glassbox_evidence_bundle::BundleError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> CaptureConfig {
        CaptureConfig {
            protocol_version: 1,
            capture_session: "process_test_001".into(),
            process_id: std::process::id() as i32,
            process_bundle_id: "com.glassbox.process-test".into(),
            interval_ms: 100,
            maximum_samples: 1,
        }
    }

    #[test]
    fn config_is_strict_and_bounded() {
        let valid = config();
        assert!(validate_config(&valid).is_ok());
        let mut invalid = config();
        invalid.process_bundle_id = "not-a-bundle".into();
        assert!(validate_config(&invalid).is_err());
        let mut too_long = config();
        too_long.interval_ms = 5_000;
        too_long.maximum_samples = 7;
        assert!(validate_config(&too_long).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn self_process_sample_is_private_kernel_ready_and_relationless() {
        let (_keep_open, control) = mpsc::channel();
        let observations = capture(&config(), control).unwrap();
        assert_eq!(observations.len(), 2);
        assert_eq!(observations[0].source_kind, "process-resource-sampler");
        assert_eq!(observations[0].trust, SourceTrust::SourceDeclared);
        assert_eq!(observations[0].fields.get("event").map(String::as_str), Some("process_sample"));
        assert!(!observations[0].native_id.contains(&std::process::id().to_string()));
        for prohibited in ["pid", "path", "arguments", "username", "environment", "network"] {
            assert!(!observations[0].fields.contains_key(prohibited));
        }
        let mut kernel = EvidenceKernel::default();
        let receipt = kernel.import_atomic(observations, Vec::new()).unwrap();
        assert_eq!(receipt.inserted, 2);
        assert!(kernel.relations().is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn explicit_stop_emits_only_terminal_coverage() {
        let (send, control) = mpsc::channel();
        send.send(Control::Stop).unwrap();
        let observations = capture(&config(), control).unwrap();
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].fields.get("reason").map(String::as_str), Some("user_stop"));
    }
}
