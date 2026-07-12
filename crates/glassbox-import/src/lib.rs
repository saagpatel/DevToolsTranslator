//! Bounded, data-only protocol emitted by the hostile import worker.

use glassbox_contracts::{EvidenceRelation, NativeObservation};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
pub const MAX_EVENTS: usize = 10_000_000;
pub const MAX_RELATIONS: usize = 20_000_000;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerFrame {
    Begin { protocol_version: u16, source_format: String },
    Observation { observation: NativeObservation },
    Relation { relation: EvidenceRelation },
    End,
}

impl WorkerFrame {
    pub fn decode(frame: &[u8]) -> Result<Self, ImportContractError> {
        if frame.len() > MAX_FRAME_BYTES {
            return Err(ImportContractError::FrameTooLarge(frame.len()));
        }
        serde_json::from_slice(frame).map_err(Into::into)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagedBatch {
    pub protocol_version: u16,
    pub source_format: String,
    pub observations: Vec<NativeObservation>,
    pub relations: Vec<EvidenceRelation>,
}

impl StagedBatch {
    pub fn validate(&self) -> Result<(), ImportContractError> {
        validate_header(self.protocol_version, &self.source_format)?;
        if self.observations.len() > MAX_EVENTS {
            return Err(ImportContractError::TooManyEvents(self.observations.len()));
        }
        if self.relations.len() > MAX_RELATIONS {
            return Err(ImportContractError::TooManyRelations(self.relations.len()));
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct BatchAssembler {
    batch: Option<StagedBatch>,
    ended: bool,
}

impl BatchAssembler {
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), ImportContractError> {
        if self.ended {
            return Err(ImportContractError::FrameAfterEnd);
        }
        match WorkerFrame::decode(bytes)? {
            WorkerFrame::Begin { protocol_version, source_format } => {
                if self.batch.is_some() {
                    return Err(ImportContractError::DuplicateBegin);
                }
                validate_header(protocol_version, &source_format)?;
                self.batch = Some(StagedBatch {
                    protocol_version,
                    source_format,
                    observations: vec![],
                    relations: vec![],
                });
            }
            WorkerFrame::Observation { observation } => {
                let batch = self.batch.as_mut().ok_or(ImportContractError::MissingBegin)?;
                if batch.observations.len() == MAX_EVENTS {
                    return Err(ImportContractError::TooManyEvents(MAX_EVENTS + 1));
                }
                batch.observations.push(observation);
            }
            WorkerFrame::Relation { relation } => {
                let batch = self.batch.as_mut().ok_or(ImportContractError::MissingBegin)?;
                if batch.relations.len() == MAX_RELATIONS {
                    return Err(ImportContractError::TooManyRelations(MAX_RELATIONS + 1));
                }
                batch.relations.push(relation);
            }
            WorkerFrame::End => {
                if self.batch.is_none() {
                    return Err(ImportContractError::MissingBegin);
                }
                self.ended = true;
            }
        }
        Ok(())
    }

    pub fn finish(self) -> Result<StagedBatch, ImportContractError> {
        if !self.ended {
            return Err(ImportContractError::MissingEnd);
        }
        let batch = self.batch.ok_or(ImportContractError::MissingBegin)?;
        batch.validate()?;
        Ok(batch)
    }
}

fn validate_header(protocol_version: u16, source_format: &str) -> Result<(), ImportContractError> {
    if protocol_version != 1 {
        return Err(ImportContractError::UnsupportedProtocol(protocol_version));
    }
    if source_format.is_empty()
        || source_format.len() > 64
        || !source_format
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ImportContractError::InvalidSourceFormat);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum ImportContractError {
    #[error("worker frame is {0} bytes, exceeding the 1 MiB limit")]
    FrameTooLarge(usize),
    #[error("unsupported worker protocol version {0}")]
    UnsupportedProtocol(u16),
    #[error("source format must be a short ASCII token")]
    InvalidSourceFormat,
    #[error("batch contains too many events: {0}")]
    TooManyEvents(usize),
    #[error("batch contains too many relations: {0}")]
    TooManyRelations(usize),
    #[error("worker stream did not begin")]
    MissingBegin,
    #[error("worker stream did not end")]
    MissingEnd,
    #[error("worker stream contains more than one begin frame")]
    DuplicateBegin,
    #[error("worker stream contains data after its end frame")]
    FrameAfterEnd,
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_oversized_frame_before_parsing() {
        let frame = vec![b' '; MAX_FRAME_BYTES + 1];
        assert!(matches!(WorkerFrame::decode(&frame), Err(ImportContractError::FrameTooLarge(_))));
    }

    #[test]
    fn rejects_unknown_fields_and_protocols() {
        let unknown =
            br#"{"type":"begin","protocol_version":1,"source_format":"fixture","surprise":true}"#;
        assert!(matches!(WorkerFrame::decode(unknown), Err(ImportContractError::Json(_))));
        let mut assembler = BatchAssembler::default();
        assert!(matches!(
            assembler.push(br#"{"type":"begin","protocol_version":2,"source_format":"fixture"}"#),
            Err(ImportContractError::UnsupportedProtocol(2))
        ));
    }

    #[test]
    fn assembles_multiple_bounded_frames_and_requires_end() {
        let mut unfinished = BatchAssembler::default();
        unfinished
            .push(br#"{"type":"begin","protocol_version":1,"source_format":"fixture"}"#)
            .unwrap();
        assert!(matches!(unfinished.finish(), Err(ImportContractError::MissingEnd)));
        let mut complete = BatchAssembler::default();
        complete
            .push(br#"{"type":"begin","protocol_version":1,"source_format":"fixture"}"#)
            .unwrap();
        complete.push(br#"{"type":"end"}"#).unwrap();
        assert_eq!(complete.finish().unwrap().source_format, "fixture");
    }
}
