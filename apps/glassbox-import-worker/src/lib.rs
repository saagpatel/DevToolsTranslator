//! Hostile-input worker. This package has no storage, key, network, or publication dependency.

use glassbox_contracts::{EvidenceRelation, NativeObservation};
use glassbox_import::{WorkerFrame, MAX_EVENTS, MAX_FRAME_BYTES, MAX_RELATIONS};
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
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
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
}
