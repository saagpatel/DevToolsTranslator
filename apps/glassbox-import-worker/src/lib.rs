//! Hostile-input worker. This package has no storage, key, network, or publication dependency.

use glassbox_apple_log_import::{parse as parse_apple_log, AppleLogRecord};
use glassbox_contracts::{EvidenceRelation, NativeObservation, SourceTrust};
use glassbox_evidence_bundle::{read_bundle, BundleRecord};
use glassbox_har_import::{parse as parse_har, HarRecord};
use glassbox_import::{WorkerFrame, MAX_EVENTS, MAX_FRAME_BYTES, MAX_RELATIONS};
use glassbox_network_import::{parse as parse_packet_capture, PacketRecord};
use glassbox_otlp_import::{
    parse as parse_otlp, parse_live_payload as parse_live_otlp, OtlpSpanRecord,
};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, Read, Write};
use thiserror::Error;

pub const MAX_RECORD_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_LIVE_OTLP_OBSERVATIONS: usize = 100_000;

#[derive(Debug, Deserialize, serde::Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum ImportRecord {
    Observation { observation: NativeObservation },
    Relation { relation: EvidenceRelation },
}

pub fn translate<R: BufRead, W: Write>(
    mut input: R,
    mut output: W,
    source_format: &str,
) -> Result<WorkerStats, WorkerError> {
    let mut stats = WorkerStats::default();
    write_frame(
        &mut output,
        &WorkerFrame::Begin { protocol_version: 1, source_format: source_format.to_owned() },
    )?;
    loop {
        let mut record = Vec::new();
        let bytes =
            Read::take(&mut input, (MAX_RECORD_BYTES + 1) as u64).read_until(b'\n', &mut record)?;
        if bytes == 0 {
            break;
        }
        if bytes > MAX_RECORD_BYTES {
            return Err(WorkerError::RecordTooLarge(bytes));
        }
        if record.last() == Some(&b'\n') {
            record.pop();
            if record.last() == Some(&b'\r') {
                record.pop();
            }
        }
        if record.is_empty() {
            continue;
        }
        match serde_json::from_slice::<ImportRecord>(&record)? {
            ImportRecord::Observation { observation } => {
                stats.observations += 1;
                if stats.observations > MAX_EVENTS {
                    return Err(WorkerError::TooManyObservations(stats.observations));
                }
                write_frame(&mut output, &WorkerFrame::Observation { observation })?;
            }
            ImportRecord::Relation { relation } => {
                stats.relations += 1;
                if stats.relations > MAX_RELATIONS {
                    return Err(WorkerError::TooManyRelations(stats.relations));
                }
                write_frame(&mut output, &WorkerFrame::Relation { relation })?;
            }
        }
    }
    write_frame(&mut output, &WorkerFrame::End)?;
    output.flush()?;
    Ok(stats)
}

pub fn translate_packet_capture<R: Read, W: Write>(
    input: R,
    mut output: W,
    capture_source: &str,
    capture_session: &str,
) -> Result<WorkerStats, WorkerError> {
    let mut stats = WorkerStats::default();
    write_frame(
        &mut output,
        &WorkerFrame::Begin { protocol_version: 1, source_format: "packet-capture-v1".into() },
    )?;
    parse_packet_capture(input, capture_source, |packet| {
        stats.observations += 1;
        if stats.observations > MAX_EVENTS {
            return Err(glassbox_network_import::NetworkImportError::TooManyPackets(
                stats.observations as u64,
            ));
        }
        let observation = packet_observation(packet, capture_session).map_err(|error| {
            glassbox_network_import::NetworkImportError::Sink(error.to_string())
        })?;
        write_frame(&mut output, &WorkerFrame::Observation { observation })
            .map_err(|error| glassbox_network_import::NetworkImportError::Sink(error.to_string()))
    })?;
    write_frame(&mut output, &WorkerFrame::End)?;
    output.flush()?;
    Ok(stats)
}

pub fn translate_apple_log<R: BufRead, W: Write>(
    input: R,
    mut output: W,
    capture_session: &str,
) -> Result<WorkerStats, WorkerError> {
    validate_identifier(capture_session)?;
    let mut stats = WorkerStats::default();
    write_frame(
        &mut output,
        &WorkerFrame::Begin {
            protocol_version: 1,
            source_format: "apple-log-projection-v1".into(),
        },
    )?;
    parse_apple_log(input, |record| {
        stats.observations += 1;
        if stats.observations > MAX_EVENTS {
            return Err(glassbox_apple_log_import::AppleLogImportError::Sink(
                "observation count exceeds worker limit".into(),
            ));
        }
        let observation = apple_log_observation(record, capture_session).map_err(|error| {
            glassbox_apple_log_import::AppleLogImportError::Sink(error.to_string())
        })?;
        write_frame(&mut output, &WorkerFrame::Observation { observation }).map_err(|error| {
            glassbox_apple_log_import::AppleLogImportError::Sink(error.to_string())
        })
    })?;
    write_frame(&mut output, &WorkerFrame::End)?;
    output.flush()?;
    Ok(stats)
}

pub fn translate_har<R: Read, W: Write>(
    input: R,
    mut output: W,
    source: &str,
    capture_session: &str,
) -> Result<WorkerStats, WorkerError> {
    validate_identifier(capture_session)?;
    let mut stats = WorkerStats::default();
    write_frame(
        &mut output,
        &WorkerFrame::Begin { protocol_version: 1, source_format: "har-v1".into() },
    )?;
    parse_har(input, source, |record| {
        stats.observations += 1;
        if stats.observations > MAX_EVENTS {
            return Err(glassbox_har_import::HarImportError::Sink(
                "observation count exceeds worker limit".into(),
            ));
        }
        let observation = har_observation(record, source, capture_session)
            .map_err(|error| glassbox_har_import::HarImportError::Sink(error.to_string()))?;
        write_frame(&mut output, &WorkerFrame::Observation { observation })
            .map_err(|error| glassbox_har_import::HarImportError::Sink(error.to_string()))
    })?;
    write_frame(&mut output, &WorkerFrame::End)?;
    output.flush()?;
    Ok(stats)
}

pub fn translate_otlp<R: BufRead, W: Write>(
    input: R,
    mut output: W,
    source: &str,
    capture_session: &str,
) -> Result<WorkerStats, WorkerError> {
    validate_identifier(capture_session)?;
    let mut stats = WorkerStats::default();
    let mut identities = Vec::new();
    write_frame(
        &mut output,
        &WorkerFrame::Begin { protocol_version: 1, source_format: "otlp-jsonl-traces-v1".into() },
    )?;
    parse_otlp(input, source, |record| {
        stats.observations += 1;
        if stats.observations > MAX_EVENTS {
            return Err(glassbox_otlp_import::OtlpImportError::Sink(
                "observation count exceeds worker limit".into(),
            ));
        }
        let (observation, identity) =
            otlp_observation(record, source, capture_session, SourceTrust::UnsignedImport)
                .map_err(|error| glassbox_otlp_import::OtlpImportError::Sink(error.to_string()))?;
        write_frame(&mut output, &WorkerFrame::Observation { observation })
            .map_err(|error| glassbox_otlp_import::OtlpImportError::Sink(error.to_string()))?;
        identities.push(identity);
        Ok(())
    })?;

    for relation in otlp_relations(identities)? {
        stats.relations += 1;
        if stats.relations > MAX_RELATIONS {
            return Err(WorkerError::TooManyRelations(stats.relations));
        }
        write_frame(&mut output, &WorkerFrame::Relation { relation })?;
    }
    write_frame(&mut output, &WorkerFrame::End)?;
    output.flush()?;
    Ok(stats)
}

/// Incrementally projects authenticated live OTLP frames into metadata-only
/// evidence. Any rejected frame permanently poisons the projector, preventing a
/// caller from publishing the valid prefix as if the session were complete.
pub struct LiveOtlpProjector {
    source: String,
    capture_session: String,
    next_line_ordinal: u64,
    observations: Vec<NativeObservation>,
    identities: Vec<OtlpIdentity>,
    poisoned: bool,
}

impl LiveOtlpProjector {
    pub fn new(source: &str, capture_session: &str) -> Result<Self, WorkerError> {
        validate_identifier(source)?;
        validate_identifier(capture_session)?;
        Ok(Self {
            source: source.into(),
            capture_session: capture_session.into(),
            next_line_ordinal: 1,
            observations: vec![],
            identities: vec![],
            poisoned: false,
        })
    }

    pub fn push_payload(
        &mut self,
        payload: &serde_json::Value,
    ) -> Result<WorkerStats, WorkerError> {
        if self.poisoned {
            return Err(WorkerError::LiveProjectionPoisoned);
        }
        let mut observations = Vec::new();
        let mut identities = Vec::new();
        let result = parse_live_otlp(payload, &self.source, self.next_line_ordinal, |record| {
            let (observation, identity) = otlp_observation(
                record,
                &self.source,
                &self.capture_session,
                SourceTrust::SourceDeclared,
            )
            .map_err(|error| glassbox_otlp_import::OtlpImportError::Sink(error.to_string()))?;
            observations.push(observation);
            identities.push(identity);
            Ok(())
        });
        let stats = match result {
            Ok(stats) => stats,
            Err(error) => {
                self.poisoned = true;
                return Err(error.into());
            }
        };
        let next_total = self.observations.len().saturating_add(observations.len());
        if next_total > MAX_LIVE_OTLP_OBSERVATIONS {
            self.poisoned = true;
            return Err(WorkerError::TooManyObservations(next_total));
        }
        self.next_line_ordinal = self
            .next_line_ordinal
            .checked_add(1)
            .ok_or(WorkerError::TooManyObservations(next_total))?;
        self.observations.extend(observations);
        self.identities.extend(identities);
        Ok(WorkerStats { observations: stats.spans as usize, relations: 0 })
    }

    pub fn finish(self) -> Result<glassbox_import::StagedBatch, WorkerError> {
        if self.poisoned {
            return Err(WorkerError::LiveProjectionPoisoned);
        }
        if self.observations.is_empty() {
            return Err(WorkerError::LiveProjectionEmpty);
        }
        let relations = otlp_relations(self.identities)?;
        let batch = glassbox_import::StagedBatch {
            protocol_version: 1,
            source_format: "otlp-live-traces-v1".into(),
            observations: self.observations,
            relations,
        };
        batch.validate()?;
        Ok(batch)
    }
}

pub fn translate_bundle<R: Read, W: Write>(
    input: R,
    mut output: W,
    source: &str,
    import_session: &str,
) -> Result<WorkerStats, WorkerError> {
    use glassbox_contracts::{LineageId, MaterializationId};
    validate_identifier(source)?;
    validate_identifier(import_session)?;
    let mut stats = WorkerStats::default();
    let mut integrity_root = None;
    let mut semantic_ids = HashSet::new();
    let mut relation_hashes = HashSet::new();
    write_frame(
        &mut output,
        &WorkerFrame::Begin { protocol_version: 1, source_format: "glassbox-bundle-v1".into() },
    )?;
    read_bundle(input, |record| {
        match record {
            BundleRecord::Manifest(manifest) => {
                integrity_root = Some(manifest.integrity_root_sha256);
            }
            BundleRecord::Observation(mut observation) => {
                if !semantic_ids.insert(observation.semantic_id.clone()) {
                    return Err(glassbox_evidence_bundle::BundleError::Sink(
                        "bundle repeats a semantic observation identifier".into(),
                    ));
                }
                stats.observations += 1;
                if stats.observations > MAX_EVENTS {
                    return Err(glassbox_evidence_bundle::BundleError::Sink(
                        "observation count exceeds worker limit".into(),
                    ));
                }
                let root = integrity_root.as_deref().ok_or_else(|| {
                    glassbox_evidence_bundle::BundleError::Sink(
                        "bundle manifest was not delivered before records".into(),
                    )
                })?;
                observation.materialization_id = MaterializationId(format!(
                    "bundle-materialization:{import_session}:{root}:{}",
                    stats.observations
                ));
                observation.lineage_id = LineageId(format!(
                    "bundle-lineage:{source}:{import_session}:{root}:{}",
                    stats.observations
                ));
                write_frame(&mut output, &WorkerFrame::Observation { observation }).map_err(
                    |error| glassbox_evidence_bundle::BundleError::Sink(error.to_string()),
                )?;
            }
            BundleRecord::Relation(relation) => {
                if !relation_hashes.insert(relation.output_hash.clone()) {
                    return Err(glassbox_evidence_bundle::BundleError::Sink(
                        "bundle repeats an evidence relation".into(),
                    ));
                }
                stats.relations += 1;
                if stats.relations > MAX_RELATIONS {
                    return Err(glassbox_evidence_bundle::BundleError::Sink(
                        "relation count exceeds worker limit".into(),
                    ));
                }
                write_frame(&mut output, &WorkerFrame::Relation { relation }).map_err(|error| {
                    glassbox_evidence_bundle::BundleError::Sink(error.to_string())
                })?;
            }
        }
        Ok(())
    })?;
    if integrity_root.is_none() {
        return Err(WorkerError::MissingBundleManifest);
    }
    write_frame(&mut output, &WorkerFrame::End)?;
    output.flush()?;
    Ok(stats)
}

struct OtlpIdentity {
    semantic_id: glassbox_contracts::SemanticObservationId,
    trace_id: String,
    span_id: String,
    parent_span_id: Option<String>,
}

fn otlp_relations(identities: Vec<OtlpIdentity>) -> Result<Vec<EvidenceRelation>, WorkerError> {
    use glassbox_contracts::{RelationBasis, RelationProvenance, RelationProvenanceRecord};
    let mut by_span = HashMap::with_capacity(identities.len());
    for identity in &identities {
        if by_span
            .insert(
                (identity.trace_id.clone(), identity.span_id.clone()),
                identity.semantic_id.clone(),
            )
            .is_some()
        {
            return Err(WorkerError::DuplicateOtlpSpan);
        }
    }
    let mut relations = Vec::new();
    for identity in identities {
        let Some(parent_span_id) = identity.parent_span_id else {
            continue;
        };
        let Some(parent) = by_span.get(&(identity.trace_id.clone(), parent_span_id)) else {
            continue;
        };
        relations.push(
            EvidenceRelation::derive(
                parent.clone(),
                identity.semantic_id.clone(),
                RelationBasis::SourceAsserted,
                RelationProvenanceRecord {
                    class: RelationProvenance::SourceAsserted,
                    rule_version: "otlp-parent/v1".into(),
                    inputs: vec![parent.clone(), identity.semantic_id.clone()],
                    supporting_evidence: vec![identity.semantic_id, parent.clone()],
                    counterevidence: vec![],
                    missing_evidence: vec![],
                    falsifier: None,
                    clock_uncertainty: None,
                },
            )
            .map_err(|_| WorkerError::InvalidOtlpRelation)?,
        );
    }
    Ok(relations)
}

fn otlp_observation(
    record: OtlpSpanRecord,
    source: &str,
    capture_session: &str,
    trust: SourceTrust,
) -> Result<(NativeObservation, OtlpIdentity), WorkerError> {
    use glassbox_contracts::{LineageId, MaterializationId, SemanticObservationId, TimeInterval};
    use std::collections::BTreeMap;
    let native_id = format!(
        "otlp://{source}/line/{}/resource/{}/scope/{}/span/{}/{}",
        record.line_ordinal,
        record.resource_ordinal,
        record.scope_ordinal,
        record.trace_id,
        record.span_id
    );
    let semantic_id = SemanticObservationId::derive("otel", capture_session, &native_id);
    let mut fields = BTreeMap::from([
        ("trace_id".into(), record.trace_id.clone()),
        ("span_id".into(), record.span_id.clone()),
        ("span_kind".into(), record.kind.to_string()),
        ("status_code".into(), record.status_code.to_string()),
        ("flags".into(), record.flags.to_string()),
        ("dropped_attributes".into(), record.dropped_attributes.to_string()),
        ("dropped_events".into(), record.dropped_events.to_string()),
        ("dropped_links".into(), record.dropped_links.to_string()),
    ]);
    if let Some(parent_span_id) = &record.parent_span_id {
        fields.insert("parent_span_id".into(), parent_span_id.clone());
    }
    let observation = NativeObservation {
        semantic_id: semantic_id.clone(),
        materialization_id: MaterializationId(format!(
            "otlp-materialization:{capture_session}:{}:{}:{}:{}",
            record.line_ordinal, record.resource_ordinal, record.scope_ordinal, record.span_ordinal
        )),
        lineage_id: LineageId(format!(
            "otlp-lineage:{capture_session}:{}:{}:{}:{}",
            record.line_ordinal, record.resource_ordinal, record.scope_ordinal, record.span_ordinal
        )),
        source_kind: "otel".into(),
        capture_session: capture_session.into(),
        native_id,
        observed_time: TimeInterval::new(record.start_ns as i128, record.end_ns as i128)
            .map_err(|_| WorkerError::TimestampOverflow)?,
        trust,
        fields,
    };
    Ok((
        observation,
        OtlpIdentity {
            semantic_id,
            trace_id: record.trace_id,
            span_id: record.span_id,
            parent_span_id: record.parent_span_id,
        },
    ))
}

fn har_observation(
    record: HarRecord,
    source: &str,
    capture_session: &str,
) -> Result<NativeObservation, WorkerError> {
    use glassbox_contracts::{
        LineageId, MaterializationId, SemanticObservationId, SourceTrust, TimeInterval,
    };
    use std::collections::BTreeMap;
    let native_id = format!("har://{source}/entry/{}", record.ordinal);
    let latest = record
        .started_ns
        .checked_add(record.duration_ns as i128)
        .ok_or(WorkerError::TimestampOverflow)?;
    let mut fields = BTreeMap::from([
        ("method".into(), record.method),
        ("status".into(), record.status.to_string()),
        ("url".into(), record.structured_url),
    ]);
    if let Some(size) = record.body_size {
        fields.insert("size".into(), size.to_string());
    }
    Ok(NativeObservation {
        semantic_id: SemanticObservationId::derive("har", capture_session, &native_id),
        materialization_id: MaterializationId(format!(
            "har-materialization:{capture_session}:{}",
            record.ordinal
        )),
        lineage_id: LineageId(format!("har-lineage:{capture_session}:{}", record.ordinal)),
        source_kind: "har".into(),
        capture_session: capture_session.into(),
        native_id,
        observed_time: TimeInterval::new(record.started_ns, latest)
            .map_err(|_| WorkerError::TimestampOverflow)?,
        trust: SourceTrust::UnsignedImport,
        fields,
    })
}

fn apple_log_observation(
    record: AppleLogRecord,
    capture_session: &str,
) -> Result<NativeObservation, WorkerError> {
    use glassbox_contracts::{
        LineageId, MaterializationId, SemanticObservationId, SourceTrust, TimeInterval,
    };
    use std::collections::BTreeMap;
    let native_id =
        format!("logarchive://{}/entry/{}", record.source_artifact_sha256, record.ordinal);
    let mut fields = BTreeMap::from([
        ("entry_kind".into(), record.entry_kind.as_str().into()),
        ("level".into(), record.level.as_str().into()),
        ("process_id".into(), record.process_id.to_string()),
        ("thread_id".into(), record.thread_id.to_string()),
        ("activity_id".into(), record.activity_id.to_string()),
    ]);
    if let Some(signpost_id) = record.signpost_id {
        fields.insert("signpost_id".into(), signpost_id.to_string());
    }
    if let Some(signpost_type) = record.signpost_type {
        fields.insert("signpost_type".into(), signpost_type.as_str().into());
    }
    Ok(NativeObservation {
        semantic_id: SemanticObservationId::derive(
            "apple-unified-log",
            capture_session,
            &native_id,
        ),
        materialization_id: MaterializationId(format!(
            "apple-log-materialization:{capture_session}:{}",
            record.ordinal
        )),
        lineage_id: LineageId(format!(
            "apple-log-lineage:{capture_session}:{}:{}",
            record.source_artifact_sha256, record.ordinal
        )),
        source_kind: "apple-unified-log".into(),
        capture_session: capture_session.into(),
        native_id,
        observed_time: TimeInterval::new(record.timestamp_unix_ns, record.timestamp_unix_ns)
            .map_err(|_| WorkerError::TimestampOverflow)?,
        trust: SourceTrust::UnsignedImport,
        fields,
    })
}

fn validate_identifier(value: &str) -> Result<(), WorkerError> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(WorkerError::InvalidIdentifier);
    }
    Ok(())
}

fn packet_observation(
    packet: PacketRecord,
    capture_session: &str,
) -> Result<NativeObservation, WorkerError> {
    use glassbox_contracts::{
        LineageId, MaterializationId, SemanticObservationId, SourceTrust, TimeInterval,
    };
    use std::collections::BTreeMap;
    let native_id = packet.native_locator.clone();
    let semantic_id = SemanticObservationId::derive("pcap", capture_session, &native_id);
    let latest = packet
        .timestamp_ns
        .checked_add(packet.timestamp_resolution_ns.saturating_sub(1) as i128)
        .ok_or(WorkerError::TimestampOverflow)?;
    let mut fields = BTreeMap::new();
    fields.insert("capture_source".into(), packet.capture_source);
    fields.insert("section_index".into(), packet.section_index.to_string());
    fields.insert("interface_id".into(), packet.interface_id.to_string());
    fields.insert("interface_name".into(), packet.interface_name);
    fields.insert("packet_ordinal".into(), packet.packet_ordinal.to_string());
    fields.insert("byte_offset".into(), packet.byte_offset.to_string());
    fields.insert("captured_len".into(), packet.captured_len.to_string());
    fields.insert("original_len".into(), packet.original_len.to_string());
    fields.insert("link_type".into(), packet.link_type.to_string());
    fields.insert("timestamp_resolution_ns".into(), packet.timestamp_resolution_ns.to_string());
    fields.insert("opacity".into(), packet.opacity.as_str().into());
    for (key, value) in [
        ("network_protocol", packet.network_protocol),
        ("source_address", packet.source_address),
        ("destination_address", packet.destination_address),
        ("transport_protocol", packet.transport_protocol),
    ] {
        if let Some(value) = value {
            fields.insert(key.into(), value);
        }
    }
    if let Some(value) = packet.source_port {
        fields.insert("source_port".into(), value.to_string());
    }
    if let Some(value) = packet.destination_port {
        fields.insert("destination_port".into(), value.to_string());
    }
    Ok(NativeObservation {
        semantic_id,
        materialization_id: MaterializationId(format!(
            "packet-materialization:{}:{}:{}",
            capture_session, packet.interface_id, packet.packet_ordinal
        )),
        lineage_id: LineageId(format!(
            "packet-lineage:{}:{}:{}",
            capture_session, packet.interface_id, packet.packet_ordinal
        )),
        source_kind: "pcap".into(),
        capture_session: capture_session.into(),
        native_id,
        observed_time: TimeInterval::new(packet.timestamp_ns, latest)
            .map_err(|_| WorkerError::TimestampOverflow)?,
        trust: SourceTrust::UnsignedImport,
        fields,
    })
}

fn write_frame<W: Write>(output: &mut W, frame: &WorkerFrame) -> Result<(), WorkerError> {
    let bytes = serde_json::to_vec(frame)?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(WorkerError::FrameTooLarge(bytes.len()));
    }
    let length = u32::try_from(bytes.len()).map_err(|_| WorkerError::FrameTooLarge(bytes.len()))?;
    output.write_all(&length.to_be_bytes())?;
    output.write_all(&bytes)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WorkerStats {
    pub observations: usize,
    pub relations: usize,
}

#[derive(Debug, Error)]
pub enum WorkerError {
    #[error("source record is {0} bytes, exceeding the 16 MiB limit")]
    RecordTooLarge(usize),
    #[error("worker frame is {0} bytes, exceeding the 1 MiB limit")]
    FrameTooLarge(usize),
    #[error("too many observations: {0}")]
    TooManyObservations(usize),
    #[error("too many relations: {0}")]
    TooManyRelations(usize),
    #[error("packet timestamp interval overflow")]
    TimestampOverflow,
    #[error("worker source/session identifier is invalid")]
    InvalidIdentifier,
    #[error("OTLP input repeats a trace/span identifier")]
    DuplicateOtlpSpan,
    #[error("OTLP parent relation could not satisfy the evidence contract")]
    InvalidOtlpRelation,
    #[error("live OTLP projection was poisoned by a rejected frame")]
    LiveProjectionPoisoned,
    #[error("live OTLP projection contains no observations")]
    LiveProjectionEmpty,
    #[error("Glassbox bundle manifest is missing")]
    MissingBundleManifest,
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Network(#[from] glassbox_network_import::NetworkImportError),
    #[error(transparent)]
    Har(#[from] glassbox_har_import::HarImportError),
    #[error(transparent)]
    Otlp(#[from] glassbox_otlp_import::OtlpImportError),
    #[error(transparent)]
    Bundle(#[from] glassbox_evidence_bundle::BundleError),
    #[error(transparent)]
    AppleLog(#[from] glassbox_apple_log_import::AppleLogImportError),
    #[error(transparent)]
    Import(#[from] glassbox_import::ImportContractError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use glassbox_contracts::{
        LineageId, MaterializationId, SemanticObservationId, SourceTrust, TimeInterval,
    };
    use std::collections::BTreeMap;
    use std::io::Cursor;

    fn observation_record() -> Vec<u8> {
        let observation = NativeObservation {
            semantic_id: SemanticObservationId::derive("fixture", "session", "native"),
            materialization_id: MaterializationId("mat".into()),
            lineage_id: LineageId("lineage".into()),
            source_kind: "fixture".into(),
            capture_session: "session".into(),
            native_id: "native".into(),
            observed_time: TimeInterval::new(1, 2).unwrap(),
            trust: SourceTrust::UnsignedImport,
            fields: BTreeMap::new(),
        };
        let mut encoded = serde_json::to_vec(&ImportRecord::Observation { observation }).unwrap();
        encoded.push(b'\n');
        encoded
    }

    fn frames(mut output: &[u8]) -> Vec<WorkerFrame> {
        let mut result = vec![];
        while !output.is_empty() {
            let length = u32::from_be_bytes(output[..4].try_into().unwrap()) as usize;
            result.push(serde_json::from_slice(&output[4..4 + length]).unwrap());
            output = &output[4 + length..];
        }
        result
    }

    #[test]
    fn emits_bounded_begin_observation_end_frames() {
        let mut output = vec![];
        let stats =
            translate(Cursor::new(observation_record()), &mut output, "fixture-ndjson").unwrap();
        assert_eq!(stats, WorkerStats { observations: 1, relations: 0 });
        let decoded = frames(&output);
        assert!(matches!(
            decoded.as_slice(),
            [WorkerFrame::Begin { .. }, WorkerFrame::Observation { .. }, WorkerFrame::End]
        ));
    }

    #[test]
    fn rejects_unknown_fields_and_oversized_records() {
        let unknown = br#"{"type":"observation","observation":{},"surprise":true}\n"#;
        assert!(matches!(
            translate(Cursor::new(unknown), vec![], "fixture"),
            Err(WorkerError::Json(_))
        ));
        let oversized = vec![b'x'; MAX_RECORD_BYTES + 1];
        assert!(matches!(
            translate(Cursor::new(oversized), vec![], "fixture"),
            Err(WorkerError::RecordTooLarge(_))
        ));
    }

    #[test]
    fn rejects_observation_that_cannot_fit_one_ipc_frame() {
        let mut record = observation_record();
        let padding = "x".repeat(MAX_FRAME_BYTES);
        let mut value: serde_json::Value = serde_json::from_slice(&record).unwrap();
        value["observation"]["fields"]["padding"] = padding.into();
        record = serde_json::to_vec(&value).unwrap();
        assert!(matches!(
            translate(Cursor::new(record), vec![], "fixture"),
            Err(WorkerError::FrameTooLarge(_))
        ));
    }

    #[test]
    fn packet_capture_emits_metadata_only_observation() {
        let packet = [
            0_u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x00, 0x45, 0, 0, 28, 0, 0, 0, 0, 0, 17,
            0, 0, 192, 0, 2, 1, 198, 51, 100, 2, 0x04, 0xd2, 0x01, 0xbb, 0, 8, 0, 0,
        ];
        let mut input = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
        input.extend_from_slice(&[0; 8]);
        input.extend_from_slice(&65535_u32.to_le_bytes());
        input.extend_from_slice(&1_u32.to_le_bytes());
        input.extend_from_slice(&1_u32.to_le_bytes());
        input.extend_from_slice(&500_000_u32.to_le_bytes());
        input.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        input.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        input.extend_from_slice(&packet);
        let mut output = vec![];
        let stats =
            translate_packet_capture(Cursor::new(input), &mut output, "capture_001", "session_001")
                .unwrap();
        assert_eq!(stats.observations, 1);
        let decoded = frames(&output);
        let WorkerFrame::Observation { observation } = &decoded[1] else {
            panic!("missing observation")
        };
        assert_eq!(observation.fields.get("destination_port").map(String::as_str), Some("443"));
        assert!(observation.native_id.starts_with("pcap://capture_001/"));
        let encoded = serde_json::to_string(observation).unwrap();
        assert!(!encoded.contains("payload"));
        assert!(!encoded.contains("process"));
    }

    #[test]
    fn har_emits_metadata_only_observation_without_secrets() {
        let input = r#"{"log":{"version":"1.2","creator":{},"entries":[{"startedDateTime":"2026-07-13T21:00:00Z","time":25,"request":{"method":"POST","url":"https://alice:pw@secret.example/private?token=seed-query","httpVersion":"HTTP/2","cookies":[],"headers":[{"name":"Authorization","value":"Bearer seed-header"}],"queryString":[],"postData":{"mimeType":"text/plain","text":"seed-body"},"headersSize":100,"bodySize":9},"response":{"status":503,"statusText":"Unavailable","httpVersion":"HTTP/2","cookies":[],"headers":[],"content":{"size":12,"mimeType":"text/plain","text":"seed-response"},"redirectURL":"","headersSize":80,"bodySize":12},"cache":{},"timings":{"send":1,"wait":20,"receive":4}}]}}"#;
        let mut output = vec![];
        let stats =
            translate_har(Cursor::new(input), &mut output, "selected_har", "session_001").unwrap();
        assert_eq!(stats.observations, 1);
        let decoded = frames(&output);
        let WorkerFrame::Observation { observation } = &decoded[1] else {
            panic!("missing observation")
        };
        assert_eq!(observation.fields.get("method").map(String::as_str), Some("POST"));
        assert_eq!(observation.fields.get("status").map(String::as_str), Some("503"));
        assert_eq!(
            observation.fields.get("url").map(String::as_str),
            Some("https://[redacted]/[redacted]?keys=1")
        );
        let encoded = serde_json::to_string(observation).unwrap();
        for secret in ["secret.example", "seed-query", "seed-header", "seed-body", "seed-response"]
        {
            assert!(!encoded.contains(secret), "secret leaked: {secret}");
        }
    }

    #[test]
    fn apple_log_projection_emits_only_allowlisted_metadata_after_terminal_digest() {
        use sha2::{Digest, Sha256};
        let header = concat!(
            "{\"type\":\"header\",\"schema_version\":\"glassbox-apple-log-projection/v1\",",
            "\"source_artifact_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}\n"
        );
        let entry = concat!(
            "{\"type\":\"entry\",\"ordinal\":1,\"timestamp_unix_ns\":\"1720000000000000000\",",
            "\"entry_kind\":\"signpost\",\"level\":\"notice\",\"process_id\":42,",
            "\"thread_id\":7,\"activity_id\":9,\"signpost_id\":11,\"signpost_type\":\"begin\"}\n"
        );
        let mut input = format!("{header}{entry}");
        let digest = format!("{:x}", Sha256::digest(input.as_bytes()));
        input.push_str(&format!(
            "{{\"type\":\"end\",\"records\":1,\"stream_sha256\":\"{digest}\"}}\n"
        ));
        let mut output = Vec::new();
        let stats =
            translate_apple_log(Cursor::new(input.as_bytes()), &mut output, "log_session_001")
                .unwrap();
        assert_eq!(stats, WorkerStats { observations: 1, relations: 0 });
        let decoded = frames(&output);
        assert!(matches!(
            decoded.as_slice(),
            [WorkerFrame::Begin { .. }, WorkerFrame::Observation { .. }, WorkerFrame::End]
        ));
        let WorkerFrame::Observation { observation } = &decoded[1] else {
            panic!("missing observation")
        };
        assert_eq!(observation.source_kind, "apple-unified-log");
        assert_eq!(observation.fields.get("process_id").map(String::as_str), Some("42"));
        assert_eq!(observation.fields.get("signpost_type").map(String::as_str), Some("begin"));
        let encoded = serde_json::to_string(observation).unwrap();
        for forbidden in ["message", "subsystem", "category", "process_name", "sender", "path"] {
            assert!(!encoded.contains(forbidden));
        }

        let truncated = &input.as_bytes()[..input.find("{\"type\":\"end\"").unwrap()];
        let mut partial = Vec::new();
        assert!(
            translate_apple_log(Cursor::new(truncated), &mut partial, "log_session_001").is_err()
        );
        assert!(!matches!(frames(&partial).last(), Some(WorkerFrame::End)));
    }

    #[test]
    fn otlp_emits_metadata_only_spans_and_source_asserted_parent_relation() {
        let input = include_str!(
            "../../../crates/glassbox-fixtures/corpus/hostile-import/otlp/valid-traces.jsonl"
        );
        let mut output = vec![];
        let stats = translate_otlp(Cursor::new(input), &mut output, "selected_otlp", "session_001")
            .unwrap();
        assert_eq!(stats, WorkerStats { observations: 2, relations: 1 });
        let decoded = frames(&output);
        assert_eq!(decoded.len(), 5);
        assert!(matches!(decoded[0], WorkerFrame::Begin { .. }));
        assert!(matches!(decoded[1], WorkerFrame::Observation { .. }));
        assert!(matches!(decoded[2], WorkerFrame::Observation { .. }));
        assert!(matches!(decoded[3], WorkerFrame::Relation { .. }));
        assert!(matches!(decoded[4], WorkerFrame::End));
        let WorkerFrame::Observation { observation } = &decoded[2] else {
            panic!("missing child span")
        };
        assert_eq!(observation.source_kind, "otel");
        assert_eq!(
            observation.fields.get("parent_span_id").map(String::as_str),
            Some("0102040800000001")
        );
        let WorkerFrame::Relation { relation } = &decoded[3] else {
            panic!("missing parent relation")
        };
        assert_eq!(relation.provenance.rule_version, "otlp-parent/v1");
        let encoded = String::from_utf8_lossy(&output);
        for secret in [
            "seed-resource",
            "seed-scope",
            "seed-root-span",
            "seed-child-span",
            "seed-host",
            "seed-query",
            "seed-event-secret",
            "seed-database-body",
            "seed-root-status",
            "seed-child-status",
            "seed-link-state",
        ] {
            assert!(!encoded.contains(secret), "secret leaked: {secret}");
        }
    }

    #[test]
    fn bundle_preserves_semantic_identity_and_rematerializes_lineage() {
        let fixture = glassbox_fixtures::gate1_fixture();
        let expected_ids: Vec<_> = fixture
            .observations
            .iter()
            .map(|observation| observation.semantic_id.clone())
            .collect();
        let mut bundle = Vec::new();
        glassbox_evidence_bundle::write_lossless(
            &mut bundle,
            &fixture.observations,
            &fixture.relations,
        )
        .unwrap();
        let mut output = Vec::new();
        let stats =
            translate_bundle(Cursor::new(bundle), &mut output, "selected_bundle", "import_001")
                .unwrap();
        assert_eq!(stats, WorkerStats { observations: 2, relations: 1 });
        let decoded = frames(&output);
        assert_eq!(decoded.len(), 5);
        for (index, expected) in expected_ids.iter().enumerate() {
            let WorkerFrame::Observation { observation } = &decoded[index + 1] else {
                panic!("missing observation")
            };
            assert_eq!(&observation.semantic_id, expected);
            assert!(observation.materialization_id.0.starts_with("bundle-materialization:"));
            assert!(observation.lineage_id.0.starts_with("bundle-lineage:selected_bundle:"));
        }
        assert!(!String::from_utf8_lossy(&output).contains("\"mat-a\""));
        assert!(matches!(decoded[3], WorkerFrame::Relation { .. }));
        assert!(matches!(decoded[4], WorkerFrame::End));
    }

    fn live_otlp_span(span_id: &str, parent_span_id: Option<&str>) -> serde_json::Value {
        let mut span = serde_json::json!({
            "traceId": "5b8efff798038103d269b633813fc60c",
            "spanId": span_id,
            "name": "seed-live-span-name",
            "kind": 2,
            "startTimeUnixNano": "1581452772000000321",
            "endTimeUnixNano": "1581452773000000789",
            "attributes": [{
                "key": "http.url",
                "value": {"stringValue": "https://seed-live-host/private?token=seed-live-query", "futureValue": "drop"},
                "futureKeyValue": "drop"
            }],
            "events": [],
            "links": [],
            "futureSpanField": "drop"
        });
        if let Some(parent) = parent_span_id {
            span["parentSpanId"] = parent.into();
        }
        serde_json::json!({
            "resourceSpans": [{"scopeSpans": [{"spans": [span]}]}],
            "futureRequestField": {"secret": "drop"}
        })
    }

    #[test]
    fn live_otlp_projector_links_across_frames_and_retains_no_raw_content() {
        let parent = "0102040800000001";
        let child = "0102040800000002";
        let mut projector = LiveOtlpProjector::new("live_source_001", "live_session_001").unwrap();
        projector.push_payload(&live_otlp_span(child, Some(parent))).unwrap();
        projector.push_payload(&live_otlp_span(parent, None)).unwrap();
        let batch = projector.finish().unwrap();
        assert_eq!(batch.source_format, "otlp-live-traces-v1");
        assert_eq!(batch.observations.len(), 2);
        assert_eq!(batch.relations.len(), 1);
        assert!(batch.observations.iter().all(|item| item.trust == SourceTrust::SourceDeclared));
        assert!(batch.observations.iter().any(|item| item.native_id.contains("/line/1/")));
        assert!(batch.observations.iter().any(|item| item.native_id.contains("/line/2/")));
        let encoded = serde_json::to_string(&batch).unwrap();
        for secret in [
            "seed-live-span-name",
            "seed-live-host",
            "seed-live-query",
            "futureSpanField",
            "futureRequestField",
        ] {
            assert!(!encoded.contains(secret), "live content leaked: {secret}");
        }
    }

    #[test]
    fn rejected_live_frame_poisons_session_and_duplicate_span_blocks_finish() {
        let valid = live_otlp_span("0102040800000001", None);
        let mut poisoned = LiveOtlpProjector::new("live_source_001", "live_session_001").unwrap();
        poisoned.push_payload(&valid).unwrap();
        assert!(poisoned
            .push_payload(&serde_json::json!({"resourceSpans": [], "resourceMetrics": []}))
            .is_err());
        assert!(matches!(poisoned.finish(), Err(WorkerError::LiveProjectionPoisoned)));

        let mut duplicate = LiveOtlpProjector::new("live_source_002", "live_session_002").unwrap();
        duplicate.push_payload(&valid).unwrap();
        duplicate.push_payload(&valid).unwrap();
        assert!(matches!(duplicate.finish(), Err(WorkerError::DuplicateOtlpSpan)));
    }
}
