//! Hostile-input worker. This package has no storage, key, network, or publication dependency.

use glassbox_contracts::{EvidenceRelation, NativeObservation};
use glassbox_import::{WorkerFrame, MAX_EVENTS, MAX_FRAME_BYTES, MAX_RELATIONS};
use glassbox_network_import::{parse as parse_packet_capture, PacketRecord};
use serde::Deserialize;
use std::io::{BufRead, Read, Write};
use thiserror::Error;

pub const MAX_RECORD_BYTES: usize = 16 * 1024 * 1024;

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
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Network(#[from] glassbox_network_import::NetworkImportError),
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
}
