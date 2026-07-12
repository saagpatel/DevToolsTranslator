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
    #[serde(with = "i128_decimal")]
    pub earliest_ns: i128,
    #[serde(with = "i128_decimal")]
    pub latest_ns: i128,
}

mod i128_decimal {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &i128, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<i128, D::Error> {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
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
pub enum RelationProvenance {
    SourceAsserted,
    DeterministicJoin,
    HeuristicJoin,
    ModelGenerated,
    UserAsserted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RelationProvenanceRecord {
    pub class: RelationProvenance,
    pub rule_version: String,
    pub inputs: Vec<SemanticObservationId>,
    pub supporting_evidence: Vec<SemanticObservationId>,
    pub counterevidence: Vec<SemanticObservationId>,
    pub missing_evidence: Vec<String>,
    pub falsifier: Option<String>,
    pub clock_uncertainty: Option<TimeInterval>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvidenceRelation {
    pub from: SemanticObservationId,
    pub to: SemanticObservationId,
    pub basis: RelationBasis,
    pub provenance: RelationProvenanceRecord,
    pub output_hash: String,
}

impl EvidenceRelation {
    pub fn derive(
        from: SemanticObservationId,
        to: SemanticObservationId,
        basis: RelationBasis,
        provenance: RelationProvenanceRecord,
    ) -> Result<Self, ContractError> {
        if provenance.rule_version.is_empty() {
            return Err(ContractError::MissingRelationRuleVersion);
        }
        if provenance.inputs.is_empty() || provenance.supporting_evidence.is_empty() {
            return Err(ContractError::MissingRelationInputs);
        }
        if requires_falsifier(&provenance.class) && missing_optional_text(&provenance.falsifier) {
            return Err(ContractError::MissingRelationFalsifier);
        }
        let output_hash = relation_hash(&from, &to, &basis, &provenance);
        Ok(Self { from, to, basis, provenance, output_hash })
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        let expected = relation_hash(&self.from, &self.to, &self.basis, &self.provenance);
        if expected != self.output_hash {
            return Err(ContractError::RelationHashMismatch);
        }
        if self.provenance.rule_version.is_empty() {
            return Err(ContractError::MissingRelationRuleVersion);
        }
        if self.provenance.inputs.is_empty() || self.provenance.supporting_evidence.is_empty() {
            return Err(ContractError::MissingRelationInputs);
        }
        if requires_falsifier(&self.provenance.class)
            && missing_optional_text(&self.provenance.falsifier)
        {
            return Err(ContractError::MissingRelationFalsifier);
        }
        Ok(())
    }
}

fn requires_falsifier(class: &RelationProvenance) -> bool {
    matches!(class, RelationProvenance::HeuristicJoin | RelationProvenance::ModelGenerated)
}

fn missing_optional_text(value: &Option<String>) -> bool {
    match value {
        None => true,
        Some(value) => value.is_empty(),
    }
}

fn relation_hash(
    from: &SemanticObservationId,
    to: &SemanticObservationId,
    basis: &RelationBasis,
    provenance: &RelationProvenanceRecord,
) -> String {
    let mut hasher = Sha256::new();
    for part in [
        "glassbox-relation-v1",
        from.as_str(),
        to.as_str(),
        relation_basis_name(basis),
        relation_provenance_name(&provenance.class),
        &provenance.rule_version,
        provenance.falsifier.as_deref().unwrap_or(""),
    ] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    for group in [
        provenance.inputs.as_slice(),
        provenance.supporting_evidence.as_slice(),
        provenance.counterevidence.as_slice(),
    ] {
        hasher.update((group.len() as u64).to_be_bytes());
        for id in group {
            hasher.update((id.as_str().len() as u64).to_be_bytes());
            hasher.update(id.as_str().as_bytes());
        }
    }
    hasher.update((provenance.missing_evidence.len() as u64).to_be_bytes());
    for missing in &provenance.missing_evidence {
        hasher.update((missing.len() as u64).to_be_bytes());
        hasher.update(missing.as_bytes());
    }
    if let Some(interval) = provenance.clock_uncertainty {
        for bound in [interval.earliest_ns.to_string(), interval.latest_ns.to_string()] {
            hasher.update((bound.len() as u64).to_be_bytes());
            hasher.update(bound.as_bytes());
        }
    }
    format!("sha256:{:x}", hasher.finalize())
}

fn relation_basis_name(basis: &RelationBasis) -> &'static str {
    match basis {
        RelationBasis::SourceAsserted => "source_asserted",
        RelationBasis::SharedAddressableKey => "shared_addressable_key",
        RelationBasis::TemporalCandidate => "temporal_candidate",
    }
}

fn relation_provenance_name(provenance: &RelationProvenance) -> &'static str {
    match provenance {
        RelationProvenance::SourceAsserted => "source_asserted",
        RelationProvenance::DeterministicJoin => "deterministic_join",
        RelationProvenance::HeuristicJoin => "heuristic_join",
        RelationProvenance::ModelGenerated => "model_generated",
        RelationProvenance::UserAsserted => "user_asserted",
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ContractError {
    #[error("time interval earliest bound exceeds latest bound")]
    InvertedInterval,
    #[error("derived relation is missing a rule version")]
    MissingRelationRuleVersion,
    #[error("derived relation is missing addressable inputs")]
    MissingRelationInputs,
    #[error("heuristic or model relation is missing a falsifier")]
    MissingRelationFalsifier,
    #[error("relation output hash does not match its provenance")]
    RelationHashMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_relation_requires_version_inputs_and_hash_integrity() {
        let from = SemanticObservationId::derive("test", "session", "from");
        let to = SemanticObservationId::derive("test", "session", "to");
        assert_eq!(
            EvidenceRelation::derive(
                from.clone(),
                to.clone(),
                RelationBasis::TemporalCandidate,
                RelationProvenanceRecord {
                    class: RelationProvenance::DeterministicJoin,
                    rule_version: String::new(),
                    inputs: vec![from.clone()],
                    supporting_evidence: vec![from.clone()],
                    counterevidence: vec![],
                    missing_evidence: vec![],
                    falsifier: None,
                    clock_uncertainty: None,
                },
            ),
            Err(ContractError::MissingRelationRuleVersion)
        );
        let mut relation = EvidenceRelation::derive(
            from.clone(),
            to,
            RelationBasis::TemporalCandidate,
            RelationProvenanceRecord {
                class: RelationProvenance::DeterministicJoin,
                rule_version: "temporal/v1".into(),
                inputs: vec![from.clone()],
                supporting_evidence: vec![from],
                counterevidence: vec![],
                missing_evidence: vec![],
                falsifier: None,
                clock_uncertainty: None,
            },
        )
        .unwrap();
        relation.output_hash.push('0');
        assert_eq!(relation.validate(), Err(ContractError::RelationHashMismatch));
    }
}
