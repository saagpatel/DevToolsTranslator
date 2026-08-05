use glassbox_contracts::{
    EvidenceRelation, LineageId, MaterializationId, NativeObservation, RelationBasis,
    RelationProvenance, RelationProvenanceRecord, SemanticObservationId, SourceTrust, TimeInterval,
};
use glassbox_import::{BatchAssembler, StagedBatch};
use glassbox_investigation::{
    build_view, validate_visual_table_equivalence, EpistemicStatus, ExportPreviewRow, Hypothesis,
    Limitation, MysteryScenario, RunComparison, ScenarioObservation, ScenarioRelation,
};
use glassbox_kernel::EvidenceKernel;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_PROJECTED_ROWS: usize = 200;
const MAX_WORKER_STREAM_BYTES: usize = 64 * 1024 * 1024;

#[derive(Serialize)]
struct KernelReceipt {
    inserted: usize,
    total: usize,
    relation_count: usize,
}

#[derive(Serialize)]
struct RowPresentation {
    time: String,
    status: String,
    uncertainty: String,
}

#[derive(Serialize)]
struct NativeShellPayload {
    schema_version: &'static str,
    kernel: KernelReceipt,
    view: glassbox_investigation::InvestigationView,
    row_presentations: BTreeMap<String, RowPresentation>,
    total_count: usize,
    visible_gap_count: usize,
    unmarked_drop_count: usize,
}

fn observation(
    id: &str,
    actor: &str,
    label: &str,
    time: &str,
    locator: &str,
    source: &str,
    anchor_kind: &str,
) -> ScenarioObservation {
    ScenarioObservation {
        id: id.into(),
        actor: actor.into(),
        label: label.into(),
        earliest_ns: time.into(),
        latest_ns: time.into(),
        native_locator: locator.into(),
        source: source.into(),
        anchor_kind: anchor_kind.into(),
    }
}

fn upload_freeze_scenario() -> MysteryScenario {
    let observations = vec![
        observation(
            "e1",
            "User action",
            "Click Upload",
            "14:07:05.812",
            "chrome://selected-tab/input/584923",
            "Chrome tab",
            "action",
        ),
        observation(
            "e2",
            "User action",
            "File selected",
            "14:07:09.231",
            "chrome://selected-tab/file/ab21",
            "Chrome tab",
            "action",
        ),
        observation(
            "e3",
            "Application",
            "Upload started",
            "14:07:10.052",
            "app://uploads/9f3a/start",
            "App logs",
            "event",
        ),
        observation(
            "e4",
            "DNS / Trace",
            "A api.example.test to 93.184.216.34",
            "14:07:10.120",
            "dnsmasq://query/22451",
            "DNS import",
            "event",
        ),
        observation(
            "e5",
            "Network",
            "POST /upload",
            "14:07:20.210",
            "pcap://packet/14331",
            "PCAP import",
            "event",
        ),
        observation(
            "e6",
            "Application",
            "Progress: 8.4 MB",
            "14:07:21.004",
            "app://uploads/9f3a/progress",
            "App logs",
            "counterevidence",
        ),
        observation(
            "e7",
            "User action",
            "Upload freeze reported",
            "14:07:23.430",
            "marker://freeze/start",
            "Manual marker",
            "symptom",
        ),
        observation(
            "e8",
            "System resources",
            "Memory pressure: high",
            "14:07:22.810",
            "sampler://memory/5521",
            "Bounded sampler",
            "event",
        ),
        observation(
            "e9",
            "Network",
            "119 packets dropped",
            "14:07:22.990",
            "pcap://gap/14352",
            "PCAP import",
            "gap",
        ),
        observation(
            "e10",
            "DNS / Trace",
            "No DNS evidence in interval",
            "14:07:23.000",
            "dnsmasq://gap/1",
            "DNS import",
            "gap",
        ),
        observation(
            "e11",
            "User action",
            "Freeze period ended",
            "14:07:53.950",
            "marker://freeze/end",
            "Manual marker",
            "symptom",
        ),
        observation(
            "e12",
            "Application",
            "Upload resumed",
            "14:07:54.321",
            "app://uploads/9f3a/resume",
            "App logs",
            "event",
        ),
    ];
    let relation = ScenarioRelation {
        from: "e7".into(),
        to: "e8".into(),
        basis: "temporal_candidate".into(),
        rule_version: "overlap-window/v1".into(),
        uncertainty: "plus or minus 200 ms symptom; plus or minus 50 ms sample; cross-source drift up to 120 ms".into(),
        supporting_evidence: vec!["e7".into(), "e8".into()],
        counterevidence: vec!["e2".into(), "e6".into()],
        missing_evidence: vec!["app signpost during freeze".into(), "server spans outside current scope".into()],
        falsifier: Some("a healthy app-thread signpost throughout the freeze".into()),
        causal_assertion: false,
    };
    MysteryScenario {
        id: "upload-freeze-base".into(),
        family: "upload_freeze".into(),
        variant: "base".into(),
        scope: vec![
            "Chrome tab".into(),
            "App logs".into(),
            "Bounded sampler".into(),
            "PCAP import".into(),
            "DNS import".into(),
        ],
        permission_tier: "standard_user_explicit_imports".into(),
        privacy_mode: "metadata_redacted".into(),
        observations,
        relations: vec![relation],
        hypotheses: vec![
            Hypothesis {
                id: "local-pressure".into(),
                status: EpistemicStatus::Correlated,
                statement: "local pressure contributed to the freeze".into(),
                premises: vec!["e7".into(), "e8".into()],
                counterevidence: vec!["e2".into()],
                missing_evidence: vec!["app signpost during freeze".into()],
                falsifier: Some("a healthy app-thread signpost throughout the freeze".into()),
                model_generated: false,
            },
            Hypothesis {
                id: "app-thread".into(),
                status: EpistemicStatus::Unknown,
                statement: "the app thread blocked independently".into(),
                premises: vec![],
                counterevidence: vec!["e6".into()],
                missing_evidence: vec!["app signpost during freeze".into()],
                falsifier: None,
                model_generated: false,
            },
            Hypothesis {
                id: "server-throttling".into(),
                status: EpistemicStatus::Unknown,
                statement: "server throttling delayed upload progress".into(),
                premises: vec![],
                counterevidence: vec!["e5".into()],
                missing_evidence: vec!["server spans outside current scope".into()],
                falsifier: None,
                model_generated: false,
            },
        ],
        limitations: vec![
            Limitation {
                kind: "gap".into(),
                detail: "2 gaps totaling 46.812 seconds".into(),
                affected_source: "multiple".into(),
            },
            Limitation {
                kind: "drop".into(),
                detail: "119 packet records dropped".into(),
                affected_source: "PCAP import".into(),
            },
            Limitation {
                kind: "redaction".into(),
                detail: "12 content-sensitive fields redacted".into(),
                affected_source: "multiple".into(),
            },
            Limitation {
                kind: "opaque".into(),
                detail: "3 encrypted payload regions remain opaque".into(),
                affected_source: "Network".into(),
            },
        ],
        comparison: Some(RunComparison {
            healthy_scenario: "upload-freeze-healthy".into(),
            differing_evidence: vec!["e7".into(), "e8".into(), "e11".into()],
            unchanged_evidence: vec!["e2".into(), "e3".into()],
        }),
        export_preview: vec![
            ExportPreviewRow {
                field: "HTTP Authorization".into(),
                classification: "credential".into(),
                action: "drop".into(),
            },
            ExportPreviewRow {
                field: "Request URL".into(),
                classification: "content_sensitive".into(),
                action: "structural_redaction".into(),
            },
            ExportPreviewRow {
                field: "Host identity".into(),
                classification: "content_sensitive".into(),
                action: "scoped_pseudonym".into(),
            },
            ExportPreviewRow {
                field: "Status code".into(),
                classification: "metadata_sensitive".into(),
                action: "preserve".into(),
            },
        ],
        expected_status: EpistemicStatus::Correlated,
        smallest_safe_next_source: Some("app-owned signpost".into()),
    }
}

fn presentations() -> BTreeMap<String, RowPresentation> {
    let row = |time: &str, status: &str, uncertainty: &str| RowPresentation {
        time: time.into(),
        status: status.into(),
        uncertainty: uncertainty.into(),
    };
    [
        ("e1", row("14:07:05.812", "observed", "±40 ms")),
        ("e2", row("14:07:09.231", "observed", "±40 ms")),
        ("e3", row("14:07:10.052", "observed", "±80 ms")),
        ("e4", row("14:07:10.120", "observed", "±20 ms")),
        ("e5", row("14:07:20.210", "observed", "±80 ms")),
        ("e6", row("14:07:21.004", "observed", "±80 ms")),
        ("e7", row("14:07:23.430", "observed", "±200 ms")),
        ("e8", row("14:07:22.810", "observed", "±50 ms")),
        ("e9", row("14:07:22.990", "gap", "duration unknown")),
        ("e10", row("14:07:23.000", "gap", "coverage gap")),
        ("e11", row("14:07:53.950", "observed", "±200 ms")),
        ("e12", row("14:07:54.321", "observed", "±80 ms")),
    ]
    .into_iter()
    .map(|(id, presentation)| (id.into(), presentation))
    .collect()
}

fn kernel_projection_input(
) -> Result<(Vec<NativeObservation>, Vec<EvidenceRelation>), Box<dyn std::error::Error>> {
    let make = |session: &str, materialization: &str, earliest: i128, latest: i128| {
        let semantic_id = SemanticObservationId::derive("native-shell", session, "upload-freeze");
        Ok::<_, Box<dyn std::error::Error>>(NativeObservation {
            semantic_id,
            materialization_id: MaterializationId(materialization.into()),
            lineage_id: LineageId(format!("lineage-{session}")),
            source_kind: "native-shell".into(),
            capture_session: session.into(),
            native_id: "upload-freeze".into(),
            observed_time: TimeInterval::new(earliest, latest)?,
            trust: SourceTrust::SourceDeclared,
            fields: BTreeMap::from([("projection".into(), "upload-freeze".into())]),
        })
    };
    let first = make("app-log", "mat-app-log", 100, 220)?;
    let second = make("resource-sample", "mat-resource", 180, 300)?;
    let relation = EvidenceRelation::derive(
        first.semantic_id.clone(),
        second.semantic_id.clone(),
        RelationBasis::TemporalCandidate,
        RelationProvenanceRecord {
            class: RelationProvenance::HeuristicJoin,
            rule_version: "overlap-window/v1".into(),
            inputs: vec![first.semantic_id.clone(), second.semantic_id.clone()],
            supporting_evidence: vec![first.semantic_id.clone(), second.semantic_id.clone()],
            counterevidence: vec![],
            missing_evidence: vec!["app signpost during freeze".into()],
            falsifier: Some("a healthy app-thread signpost throughout the freeze".into()),
            clock_uncertainty: Some(TimeInterval::new(180, 220)?),
        },
    )?;
    Ok((vec![first, second], vec![relation]))
}

fn payload() -> Result<NativeShellPayload, Box<dyn std::error::Error>> {
    let (observations, relations) = kernel_projection_input()?;
    let mut kernel = EvidenceKernel::default();
    let imported = kernel.import_atomic(observations, relations)?;
    let view = build_view(upload_freeze_scenario())?;
    if !validate_visual_table_equivalence(&view) {
        return Err("native shell timeline and table projections diverged".into());
    }
    let row_presentations = presentations();
    if row_presentations.len() != view.evidence_table.len() {
        return Err("native shell presentation metadata is incomplete".into());
    }
    Ok(NativeShellPayload {
        schema_version: "glassbox-native-shell/v1",
        kernel: KernelReceipt {
            inserted: imported.inserted,
            total: imported.total,
            relation_count: kernel.relations().len(),
        },
        view,
        row_presentations,
        total_count: 12,
        visible_gap_count: 2,
        unmarked_drop_count: 0,
    })
}

struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
}

impl<R> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self { inner, hasher: Sha256::new() }
    }

    fn digest(&self) -> String {
        format!("{:x}", self.hasher.clone().finalize())
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let count = self.inner.read(buffer)?;
        self.hasher.update(&buffer[..count]);
        Ok(count)
    }
}

#[derive(Default)]
struct LimitedWorkerStream {
    bytes: Vec<u8>,
}

impl Write for LimitedWorkerStream {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.bytes.len().saturating_add(bytes.len()) > MAX_WORKER_STREAM_BYTES {
            return Err(std::io::Error::other("worker stream limit exceeded"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn validate_source_identity(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn assemble_worker_stream(bytes: &[u8]) -> Result<StagedBatch, Box<dyn std::error::Error>> {
    let mut assembler = BatchAssembler::default();
    let mut remaining = bytes;
    while !remaining.is_empty() {
        if remaining.len() < 4 {
            return Err("truncated worker frame length".into());
        }
        let length = u32::from_be_bytes(remaining[..4].try_into()?) as usize;
        remaining = &remaining[4..];
        if length > remaining.len() {
            return Err("truncated worker frame".into());
        }
        assembler.push(&remaining[..length])?;
        remaining = &remaining[length..];
    }
    Ok(assembler.finish()?)
}

fn import_batch(
    format: &str,
    expected_sha256: &str,
    capture_session: &str,
    input: impl Read,
) -> Result<StagedBatch, Box<dyn std::error::Error>> {
    if !validate_source_identity(expected_sha256) {
        return Err("invalid source digest".into());
    }
    let mut reader = HashingReader::new(input);
    let mut output = LimitedWorkerStream::default();
    match format {
        "har" => glassbox_import_worker::translate_har(
            &mut reader,
            &mut output,
            expected_sha256,
            capture_session,
        )?,
        "otlp-jsonl" => {
            let mut buffered = BufReader::new(&mut reader);
            glassbox_import_worker::translate_otlp(
                &mut buffered,
                &mut output,
                expected_sha256,
                capture_session,
            )?
        }
        "pcap" | "pcapng" => glassbox_import_worker::translate_packet_capture(
            &mut reader,
            &mut output,
            expected_sha256,
            capture_session,
        )?,
        "glassbox" => glassbox_import_worker::translate_bundle(
            &mut reader,
            &mut output,
            expected_sha256,
            capture_session,
        )?,
        "apple-log-projection" => glassbox_import_worker::translate_apple_log(
            BufReader::new(&mut reader),
            &mut output,
            capture_session,
        )?,
        _ => return Err("unsupported import format".into()),
    };
    if reader.digest() != expected_sha256 {
        return Err("source digest mismatch".into());
    }
    assemble_worker_stream(&output.bytes)
}

fn actor_for(source_kind: &str) -> &'static str {
    match source_kind {
        "pcap" | "har" => "Network",
        "otel" => "DNS / Trace",
        "resource-sampler" => "System resources",
        _ => "Application",
    }
}

fn observation_label(observation: &NativeObservation) -> String {
    if observation.source_kind == "resource-sampler" {
        if observation.fields.get("event").map(String::as_str) == Some("system_sample") {
            return format!(
                "resource-sampler · system_sample · load_milli={}/{}/{} · memory_estimate_bytes={}/{} · pressure={}",
                observation.fields.get("load_1m_milli").map(String::as_str).unwrap_or("unknown"),
                observation.fields.get("load_5m_milli").map(String::as_str).unwrap_or("unknown"),
                observation.fields.get("load_15m_milli").map(String::as_str).unwrap_or("unknown"),
                observation
                    .fields
                    .get("memory_used_estimate_bytes")
                    .map(String::as_str)
                    .unwrap_or("unknown"),
                observation.fields.get("memory_total_bytes").map(String::as_str).unwrap_or("unknown"),
                observation.fields.get("memory_pressure").map(String::as_str).unwrap_or("unknown"),
            );
        }
        return format!(
            "resource-sampler · session_end · reason={} · sample_count={}",
            observation.fields.get("reason").map(String::as_str).unwrap_or("unknown"),
            observation.fields.get("sample_count").map(String::as_str).unwrap_or("unknown"),
        );
    }
    let detail = [
        "event",
        "method",
        "status",
        "span_kind",
        "entry_kind",
        "level",
        "opacity",
        "memory_pressure",
        "load_1m_milli",
        "reason",
        "sample_count",
        "cpu_user_time_ns",
        "cpu_system_time_ns",
        "resident_bytes",
        "physical_footprint_bytes",
        "wakeups",
    ]
    .into_iter()
    .filter_map(|key| observation.fields.get(key).map(|value| format!("{key}={value}")))
    .take(3)
    .collect::<Vec<_>>()
    .join(" · ");
    if detail.is_empty() {
        format!("{} metadata", observation.source_kind)
    } else {
        format!("{} · {detail}", observation.source_kind)
    }
}

fn relation_basis_name(basis: &RelationBasis) -> &'static str {
    match basis {
        RelationBasis::SourceAsserted => "source_asserted",
        RelationBasis::SharedAddressableKey => "shared_addressable_key",
        RelationBasis::TemporalCandidate => "temporal_candidate",
    }
}

#[derive(Debug)]
struct SystemResourceSample {
    load_1m_milli: u64,
    load_5m_milli: u64,
    load_15m_milli: u64,
    memory_used_estimate_bytes: u64,
    memory_total_bytes: u64,
    memory_pressure: &'static str,
}

struct SystemMetricsReader {
    host_port: libc::mach_port_t,
    page_size: u64,
    memory_total_bytes: u64,
}

impl SystemMetricsReader {
    #[cfg(target_os = "macos")]
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // `libc` marks this stable Darwin API deprecated only to steer callers
        // toward a larger wrapper crate. Keeping the one call local avoids
        // widening the helper's dependency and API surface.
        #[allow(deprecated)]
        let host_port = unsafe { libc::mach_host_self() };
        if host_port == 0 {
            return Err("host statistics port unavailable".into());
        }
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page_size <= 0 {
            return Err("page size unavailable".into());
        }
        let memory_total_bytes =
            sysctl_value::<u64>("hw.memsize").ok_or("physical memory size unavailable")?;
        Ok(Self { host_port, page_size: page_size as u64, memory_total_bytes })
    }

    #[cfg(not(target_os = "macos"))]
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Err("resource sampling is available only on macOS".into())
    }

    #[cfg(target_os = "macos")]
    fn sample(&self) -> Result<SystemResourceSample, Box<dyn std::error::Error>> {
        let mut statistics = unsafe { std::mem::zeroed::<libc::vm_statistics64>() };
        let mut count = libc::HOST_VM_INFO64_COUNT;
        let status = unsafe {
            libc::host_statistics64(
                self.host_port,
                libc::HOST_VM_INFO64,
                (&raw mut statistics).cast(),
                &mut count,
            )
        };
        if status != libc::KERN_SUCCESS || count != libc::HOST_VM_INFO64_COUNT {
            return Err("host memory statistics unavailable".into());
        }
        let active = u64::from(statistics.active_count);
        let wired = u64::from(statistics.wire_count);
        let compressed = u64::from(statistics.compressor_page_count);
        let speculative = u64::from(statistics.speculative_count);
        let memory_used_estimate_bytes = active
            .saturating_add(wired)
            .saturating_add(compressed)
            .saturating_add(speculative)
            .saturating_mul(self.page_size)
            .min(self.memory_total_bytes);
        let mut loads = [0.0_f64; 3];
        if unsafe { libc::getloadavg(loads.as_mut_ptr(), loads.len() as i32) } != 3 {
            return Err("system load averages unavailable".into());
        }
        let scaled_load = |value: f64| -> Result<u64, Box<dyn std::error::Error>> {
            if !value.is_finite() || !(0.0..=1_000_000.0).contains(&value) {
                return Err("system load average is outside its bound".into());
            }
            Ok((value * 1_000.0).round() as u64)
        };
        let pressure = match sysctl_value::<u32>("kern.memorystatus_vm_pressure_level") {
            Some(1) => "normal",
            Some(2) => "warning",
            Some(4) => "critical",
            _ => "unknown",
        };
        Ok(SystemResourceSample {
            load_1m_milli: scaled_load(loads[0])?,
            load_5m_milli: scaled_load(loads[1])?,
            load_15m_milli: scaled_load(loads[2])?,
            memory_used_estimate_bytes,
            memory_total_bytes: self.memory_total_bytes,
            memory_pressure: pressure,
        })
    }

    #[cfg(not(target_os = "macos"))]
    fn sample(&self) -> Result<SystemResourceSample, Box<dyn std::error::Error>> {
        Err("resource sampling is available only on macOS".into())
    }
}

#[cfg(target_os = "macos")]
fn sysctl_value<T: Copy>(name: &str) -> Option<T> {
    let name = std::ffi::CString::new(name).ok()?;
    let mut value = unsafe { std::mem::zeroed::<T>() };
    let mut size = std::mem::size_of::<T>();
    let status = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            (&raw mut value).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    (status == 0 && size == std::mem::size_of::<T>()).then_some(value)
}

fn unix_time_ns() -> Result<i128, Box<dyn std::error::Error>> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok(i128::from(duration.as_secs()) * 1_000_000_000 + i128::from(duration.subsec_nanos()))
}

fn validate_session_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn resource_observation(
    capture_session: &str,
    ordinal: usize,
    earliest_ns: i128,
    latest_ns: i128,
    sample: SystemResourceSample,
) -> Result<NativeObservation, Box<dyn std::error::Error>> {
    let native_id = format!("sampler://system/{capture_session}/sample/{ordinal}");
    Ok(NativeObservation {
        semantic_id: SemanticObservationId::derive("resource-sampler", capture_session, &native_id),
        materialization_id: MaterializationId(format!(
            "resource-materialization:{capture_session}:{ordinal}"
        )),
        lineage_id: LineageId(format!("resource-lineage:{capture_session}:{ordinal}")),
        source_kind: "resource-sampler".into(),
        capture_session: capture_session.into(),
        native_id,
        observed_time: TimeInterval::new(earliest_ns, latest_ns)?,
        // The helper samples the local OS directly, but this protocol does not
        // carry a per-session audit token proving the caller's identity.
        trust: SourceTrust::SourceDeclared,
        fields: BTreeMap::from([
            ("event".into(), "system_sample".into()),
            ("load_1m_milli".into(), sample.load_1m_milli.to_string()),
            ("load_5m_milli".into(), sample.load_5m_milli.to_string()),
            ("load_15m_milli".into(), sample.load_15m_milli.to_string()),
            ("memory_used_estimate_bytes".into(), sample.memory_used_estimate_bytes.to_string()),
            ("memory_total_bytes".into(), sample.memory_total_bytes.to_string()),
            ("memory_pressure".into(), sample.memory_pressure.into()),
        ]),
    })
}

fn resource_terminal_observation(
    capture_session: &str,
    ordinal: usize,
    reason: &str,
    sample_count: usize,
) -> Result<NativeObservation, Box<dyn std::error::Error>> {
    let time = unix_time_ns()?;
    let native_id = format!("sampler://system/{capture_session}/terminal");
    Ok(NativeObservation {
        semantic_id: SemanticObservationId::derive("resource-sampler", capture_session, &native_id),
        materialization_id: MaterializationId(format!(
            "resource-materialization:{capture_session}:{ordinal}"
        )),
        lineage_id: LineageId(format!("resource-lineage:{capture_session}:terminal")),
        source_kind: "resource-sampler".into(),
        capture_session: capture_session.into(),
        native_id,
        observed_time: TimeInterval::new(time, time)?,
        trust: SourceTrust::SourceDeclared,
        fields: BTreeMap::from([
            ("event".into(), "session_end".into()),
            ("reason".into(), reason.into()),
            ("sample_count".into(), sample_count.to_string()),
        ]),
    })
}

fn resource_sample_batch_with_stop(
    capture_session: &str,
    interval_ms: u64,
    maximum_samples: usize,
    stop: Receiver<()>,
) -> Result<StagedBatch, Box<dyn std::error::Error>> {
    if !validate_session_identifier(capture_session)
        || !(100..=5_000).contains(&interval_ms)
        || !(1..=600).contains(&maximum_samples)
        || interval_ms.saturating_mul(maximum_samples as u64) > 30_000
    {
        return Err("resource sampler configuration is outside its bounds".into());
    }
    let reader = SystemMetricsReader::new()?;
    let mut observations = Vec::with_capacity(maximum_samples.saturating_add(1));
    let mut stopped = false;
    for ordinal in 0..maximum_samples {
        if ordinal > 0 {
            match stop.recv_timeout(Duration::from_millis(interval_ms)) {
                Ok(()) | Err(RecvTimeoutError::Disconnected) => {
                    stopped = true;
                    break;
                }
                Err(RecvTimeoutError::Timeout) => {}
            }
        } else if stop.try_recv().is_ok() {
            stopped = true;
            break;
        }
        let earliest = unix_time_ns()?;
        let sample = reader.sample()?;
        let latest = unix_time_ns()?;
        observations.push(resource_observation(
            capture_session,
            ordinal,
            earliest,
            latest,
            sample,
        )?);
    }
    observations.push(resource_terminal_observation(
        capture_session,
        observations.len(),
        if stopped { "user_stop" } else { "maximum_samples" },
        observations.len(),
    )?);
    Ok(StagedBatch {
        protocol_version: 1,
        source_format: "resource-sampler-v1".into(),
        observations,
        relations: vec![],
    })
}

fn resource_sample_batch(
    capture_session: &str,
    interval_ms: u64,
    maximum_samples: usize,
) -> Result<StagedBatch, Box<dyn std::error::Error>> {
    let (send_stop, receive_stop) = mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        if std::io::stdin().lock().read_line(&mut line).is_ok() && line == "stop\n" {
            let _ = send_stop.send(());
        }
    });
    resource_sample_batch_with_stop(capture_session, interval_ms, maximum_samples, receive_stop)
}

fn import_payload(batch: StagedBatch) -> Result<NativeShellPayload, Box<dyn std::error::Error>> {
    if batch.observations.is_empty() {
        return Err("import contains no observations".into());
    }
    let is_resource_session = batch.source_format == "resource-sampler-v1";
    let total_count = batch.observations.len();
    let page = batch.observations.iter().take(MAX_PROJECTED_ROWS).cloned().collect::<Vec<_>>();
    let page_ids =
        page.iter().map(|item| item.semantic_id.as_str().to_owned()).collect::<BTreeSet<_>>();
    let scenario_observations = page
        .iter()
        .map(|item| ScenarioObservation {
            id: item.semantic_id.as_str().to_owned(),
            actor: actor_for(&item.source_kind).into(),
            label: observation_label(item),
            earliest_ns: item.observed_time.earliest_ns.to_string(),
            latest_ns: item.observed_time.latest_ns.to_string(),
            native_locator: item.native_id.clone(),
            source: item.source_kind.clone(),
            anchor_kind: "imported_evidence".into(),
        })
        .collect::<Vec<_>>();
    let scenario_relations = batch
        .relations
        .iter()
        .filter(|relation| {
            page_ids.contains(relation.from.as_str()) && page_ids.contains(relation.to.as_str())
        })
        .map(|relation| {
            let mut supporting = relation
                .provenance
                .supporting_evidence
                .iter()
                .map(|item| item.as_str().to_owned())
                .filter(|id| page_ids.contains(id))
                .collect::<Vec<_>>();
            if supporting.is_empty() {
                supporting.push(relation.from.as_str().to_owned());
            }
            ScenarioRelation {
                from: relation.from.as_str().to_owned(),
                to: relation.to.as_str().to_owned(),
                basis: relation_basis_name(&relation.basis).into(),
                rule_version: relation.provenance.rule_version.clone(),
                uncertainty: relation
                    .provenance
                    .clock_uncertainty
                    .map(|interval| format!("{}..{} ns", interval.earliest_ns, interval.latest_ns))
                    .unwrap_or_else(|| "clock uncertainty unavailable".into()),
                supporting_evidence: supporting,
                counterevidence: relation
                    .provenance
                    .counterevidence
                    .iter()
                    .map(|item| item.as_str().to_owned())
                    .filter(|id| page_ids.contains(id))
                    .collect(),
                missing_evidence: relation.provenance.missing_evidence.clone(),
                falsifier: relation.provenance.falsifier.clone(),
                causal_assertion: false,
            }
        })
        .collect::<Vec<_>>();
    let scope = page
        .iter()
        .map(|item| item.source_kind.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut limitations = vec![Limitation {
        kind: "epistemic".into(),
        detail: if is_resource_session {
            "Resource samples show bounded system context, not the cause of an application symptom"
                .into()
        } else {
            "Imported metadata is evidence, not a causal conclusion".into()
        },
        affected_source: if is_resource_session {
            "resource-sampler".into()
        } else {
            "all imported sources".into()
        },
    }];
    if total_count > page.len() {
        limitations.push(Limitation {
            kind: "bounded_page".into(),
            detail: format!("Showing {} of {total_count} validated observations", page.len()),
            affected_source: "investigation view".into(),
        });
    }
    let view = build_view(MysteryScenario {
        id: if is_resource_session {
            "resource-sampler-session".into()
        } else {
            "imported-evidence".into()
        },
        family: if is_resource_session {
            "resource_context".into()
        } else {
            "imported_evidence".into()
        },
        variant: if is_resource_session { "live_session".into() } else { "import".into() },
        scope,
        permission_tier: if is_resource_session {
            "ordinary_permission_visible_session".into()
        } else {
            "standard_user_explicit_import".into()
        },
        privacy_mode: "metadata_redacted".into(),
        observations: scenario_observations,
        relations: scenario_relations,
        hypotheses: vec![
            Hypothesis {
                id: "interpretation-pending".into(),
                status: EpistemicStatus::Unknown,
                statement: if is_resource_session {
                    "The resource samples have not established a cause".into()
                } else {
                    "The imported evidence has not established a cause".into()
                },
                premises: vec![],
                counterevidence: vec![],
                missing_evidence: vec!["independent corroborating source".into()],
                falsifier: None,
                model_generated: false,
            },
            Hypothesis {
                id: "clock-context-pending".into(),
                status: EpistemicStatus::Unknown,
                statement: "Clock and capture context may change apparent ordering".into(),
                premises: vec![],
                counterevidence: vec![],
                missing_evidence: vec!["source clock calibration".into()],
                falsifier: None,
                model_generated: false,
            },
        ],
        limitations,
        comparison: None,
        export_preview: vec![
            ExportPreviewRow {
                field: if is_resource_session {
                    "Resource metadata fields".into()
                } else {
                    "Imported metadata fields".into()
                },
                classification: "metadata_sensitive".into(),
                action: "preserve after review".into(),
            },
            ExportPreviewRow {
                field: "Raw source content".into(),
                classification: "content_sensitive".into(),
                action: "drop".into(),
            },
        ],
        expected_status: EpistemicStatus::Unknown,
        smallest_safe_next_source: Some("independent corroborating source".into()),
    })?;
    if !validate_visual_table_equivalence(&view) {
        return Err("import timeline and table projections diverged".into());
    }
    let row_presentations = page
        .iter()
        .map(|item| {
            let uncertainty = if item.observed_time.earliest_ns == item.observed_time.latest_ns {
                "source timestamp; uncertainty unavailable".into()
            } else {
                format!(
                    "bounded interval {} ns",
                    item.observed_time.latest_ns - item.observed_time.earliest_ns + 1
                )
            };
            (
                item.semantic_id.as_str().to_owned(),
                RowPresentation {
                    time: item.observed_time.earliest_ns.to_string(),
                    status: "observed".into(),
                    uncertainty,
                },
            )
        })
        .collect();
    let mut kernel = EvidenceKernel::default();
    let imported = kernel.import_atomic(batch.observations, batch.relations)?;
    Ok(NativeShellPayload {
        schema_version: "glassbox-native-shell/v1",
        kernel: KernelReceipt {
            inserted: imported.inserted,
            total: imported.total,
            relation_count: kernel.relations().len(),
        },
        view,
        row_presentations,
        total_count,
        visible_gap_count: 0,
        unmarked_drop_count: 0,
    })
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let payload = match arguments.as_slice() {
        [] => payload()?,
        [command, format, source_sha256, capture_session] if command == "--import" => {
            let batch =
                import_batch(format, source_sha256, capture_session, std::io::stdin().lock())?;
            import_payload(batch)?
        }
        [command, capture_session, interval_ms, maximum_samples]
            if command == "--sample-system" =>
        {
            let interval_ms = interval_ms.parse::<u64>()?;
            let maximum_samples = maximum_samples.parse::<usize>()?;
            import_payload(resource_sample_batch(capture_session, interval_ms, maximum_samples)?)?
        }
        _ => return Err("invalid command".into()),
    };
    serde_json::to_writer(std::io::stdout().lock(), &payload)?;
    println!();
    Ok(())
}

fn main() {
    if run().is_err() {
        eprintln!("glassbox-native-bridge: request rejected");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha256(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    #[test]
    fn payload_is_bounded_kernel_backed_and_gap_explicit() {
        let payload = payload().unwrap();
        assert_eq!(payload.kernel.inserted, 2);
        assert_eq!(payload.kernel.relation_count, 1);
        assert_eq!(payload.view.evidence_table.len(), 12);
        assert_eq!(payload.visible_gap_count, 2);
        assert_eq!(payload.unmarked_drop_count, 0);
        assert!(!payload.view.relation_explanations[0].causal_assertion);
    }

    #[test]
    fn supported_import_is_content_bound_kernel_validated_and_epistemically_unknown() {
        let input =
            include_bytes!("../../../crates/glassbox-fixtures/corpus/hostile-import/har/valid.har");
        let digest = sha256(input);
        let batch = import_batch("har", &digest, "session_001", input.as_slice()).unwrap();
        let payload = import_payload(batch).unwrap();
        assert_eq!(payload.total_count, 1);
        assert_eq!(payload.kernel.inserted, 1);
        assert_eq!(payload.kernel.relation_count, 0);
        assert_eq!(payload.view.conclusion, EpistemicStatus::Unknown);
        assert!(payload.view.relation_explanations.iter().all(|item| !item.causal_assertion));
        let encoded = serde_json::to_string(&payload).unwrap();
        for secret in [
            "seed-host.example",
            "seed-query",
            "seed-cookie",
            "seed-header",
            "seed-request-body",
            "seed-response-body",
        ] {
            assert!(!encoded.contains(secret));
        }
    }

    #[test]
    fn complete_apple_log_projection_uses_the_same_offline_kernel_boundary() {
        let input = include_bytes!(
            "../../../crates/glassbox-fixtures/corpus/hostile-import/apple-log/valid.ndjson"
        );
        let digest = sha256(input);
        let batch = import_batch(
            "apple-log-projection",
            &digest,
            "apple_log_session_001",
            input.as_slice(),
        )
        .unwrap();
        let payload = import_payload(batch).unwrap();
        assert_eq!(payload.total_count, 2);
        assert_eq!(payload.kernel.inserted, 2);
        assert_eq!(payload.kernel.relation_count, 0);
        assert_eq!(payload.view.conclusion, EpistemicStatus::Unknown);
        assert!(payload.view.relation_explanations.is_empty());
    }

    #[test]
    fn mismatched_or_truncated_import_never_produces_a_payload() {
        let input =
            include_bytes!("../../../crates/glassbox-fixtures/corpus/hostile-import/har/valid.har");
        assert!(import_batch("har", &"0".repeat(64), "session_001", input.as_slice()).is_err());
        let truncated = &input[..input.len() / 2];
        assert!(import_batch("har", &sha256(truncated), "session_001", truncated).is_err());
    }

    #[test]
    fn bounded_resource_sampler_records_metrics_terminal_coverage_and_no_causal_claim() {
        let (_keep_open, stop) = mpsc::channel();
        let batch = resource_sample_batch_with_stop("sample_001", 100, 1, stop).unwrap();
        assert_eq!(batch.source_format, "resource-sampler-v1");
        assert_eq!(batch.observations.len(), 2);
        assert_eq!(batch.observations[0].trust, SourceTrust::SourceDeclared);
        assert_eq!(
            batch.observations[0].fields.get("event").map(String::as_str),
            Some("system_sample")
        );
        assert_eq!(
            batch.observations[1].fields.get("event").map(String::as_str),
            Some("session_end")
        );
        assert_eq!(
            batch.observations[1].fields.get("reason").map(String::as_str),
            Some("maximum_samples")
        );
        let payload = import_payload(batch).unwrap();
        assert_eq!(payload.view.scenario_id, "resource-sampler-session");
        assert_eq!(payload.view.conclusion, EpistemicStatus::Unknown);
        assert!(payload.view.relation_explanations.is_empty());
    }

    #[test]
    fn resource_sampler_stop_is_explicit_and_invalid_configuration_fails_closed() {
        let (send_stop, stop) = mpsc::channel();
        send_stop.send(()).unwrap();
        let batch = resource_sample_batch_with_stop("sample_002", 100, 10, stop).unwrap();
        assert_eq!(batch.observations.len(), 1);
        assert_eq!(
            batch.observations[0].fields.get("reason").map(String::as_str),
            Some("user_stop")
        );
        let (_keep_open, stop) = mpsc::channel();
        assert!(resource_sample_batch_with_stop("bad/session", 99, 0, stop).is_err());
        let (_keep_open, stop) = mpsc::channel();
        assert!(resource_sample_batch_with_stop("too_long", 5_000, 7, stop).is_err());
    }
}
