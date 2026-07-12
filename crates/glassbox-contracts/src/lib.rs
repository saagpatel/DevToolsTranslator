//! Stable, UI-independent evidence contracts for Glassbox.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct SemanticObservationId(String);

impl SemanticObservationId {
    pub fn derive(source_kind: &str, capture_session: &str, native_id: &str) -> Self {
        let mut hasher = Sha256::new();
        for part in ["glassbox-observation-v1", source_kind, capture_session, native_id] {
            hasher.update((part.len() as u64).to_be_bytes());
            hasher.update(part.as_bytes());
        }
        Self(format!("obs:{:x}", hasher.finalize()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct MaterializationId(pub String);

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct LineageId(pub String);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TimeInterval {
    pub earliest_ns: i128,
    pub latest_ns: i128,
}

impl TimeInterval {
    pub fn new(earliest_ns: i128, latest_ns: i128) -> Result<Self, ContractError> {
        if earliest_ns > latest_ns {
            return Err(ContractError::InvertedInterval);
        }
        Ok(Self { earliest_ns, latest_ns })
    }

    pub fn relation_to(self, other: Self) -> TemporalRelation {
        if self.latest_ns < other.earliest_ns {
            TemporalRelation::Precedes
        } else if other.latest_ns < self.earliest_ns {
            TemporalRelation::Follows
        } else {
            TemporalRelation::UnorderedOverlap
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TemporalRelation {
    Precedes,
    Follows,
    UnorderedOverlap,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SourceTrust {
    AuthenticatedLocal,
    SignedUntrusted,
    SourceDeclared,
    UnsignedImport,
    UserAsserted,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NativeObservation {
    pub semantic_id: SemanticObservationId,
    pub materialization_id: MaterializationId,
    pub lineage_id: LineageId,
    pub source_kind: String,
    pub capture_session: String,
    pub native_id: String,
    pub observed_time: TimeInterval,
    pub trust: SourceTrust,
    pub fields: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RelationBasis {
    SourceAsserted,
    SharedAddressableKey,
    TemporalCandidate,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvidenceRelation {
    pub from: SemanticObservationId,
    pub to: SemanticObservationId,
    pub basis: RelationBasis,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ContractError {
    #[error("time interval earliest bound exceeds latest bound")]
    InvertedInterval,
}
