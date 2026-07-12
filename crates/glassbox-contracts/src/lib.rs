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
    NativeSource,
    DeterministicRule,
    ModelGenerated,
    UserAsserted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvidenceRelation {
    pub from: SemanticObservationId,
    pub to: SemanticObservationId,
    pub basis: RelationBasis,
    pub provenance: RelationProvenance,
    pub rule_version: Option<String>,
    pub inputs: Vec<SemanticObservationId>,
    pub counterevidence: Vec<SemanticObservationId>,
    pub output_hash: String,
}

impl EvidenceRelation {
    pub fn derive(
        from: SemanticObservationId,
        to: SemanticObservationId,
        basis: RelationBasis,
        provenance: RelationProvenance,
        rule_version: Option<String>,
        inputs: Vec<SemanticObservationId>,
        counterevidence: Vec<SemanticObservationId>,
    ) -> Result<Self, ContractError> {
        if provenance != RelationProvenance::NativeSource
            && missing_rule_version(rule_version.as_deref())
        {
            return Err(ContractError::MissingRelationRuleVersion);
        }
        if provenance != RelationProvenance::NativeSource && inputs.is_empty() {
            return Err(ContractError::MissingRelationInputs);
        }
        let output_hash = relation_hash(
            &from,
            &to,
            &basis,
            &provenance,
            rule_version.as_deref(),
            &inputs,
            &counterevidence,
        );
        Ok(Self { from, to, basis, provenance, rule_version, inputs, counterevidence, output_hash })
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        let expected = relation_hash(
            &self.from,
            &self.to,
            &self.basis,
            &self.provenance,
            self.rule_version.as_deref(),
            &self.inputs,
            &self.counterevidence,
        );
        if expected != self.output_hash {
            return Err(ContractError::RelationHashMismatch);
        }
        if self.provenance != RelationProvenance::NativeSource
            && missing_rule_version(self.rule_version.as_deref())
        {
            return Err(ContractError::MissingRelationRuleVersion);
        }
        if self.provenance != RelationProvenance::NativeSource && self.inputs.is_empty() {
            return Err(ContractError::MissingRelationInputs);
        }
        Ok(())
    }
}

fn missing_rule_version(version: Option<&str>) -> bool {
    match version {
        None => true,
        Some(value) => value.is_empty(),
    }
}

fn relation_hash(
    from: &SemanticObservationId,
    to: &SemanticObservationId,
    basis: &RelationBasis,
    provenance: &RelationProvenance,
    rule_version: Option<&str>,
    inputs: &[SemanticObservationId],
    counterevidence: &[SemanticObservationId],
) -> String {
    let mut hasher = Sha256::new();
    for part in [
        "glassbox-relation-v1",
        from.as_str(),
        to.as_str(),
        relation_basis_name(basis),
        relation_provenance_name(provenance),
        rule_version.unwrap_or(""),
    ] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    for group in [inputs, counterevidence] {
        hasher.update((group.len() as u64).to_be_bytes());
        for id in group {
            hasher.update((id.as_str().len() as u64).to_be_bytes());
            hasher.update(id.as_str().as_bytes());
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
        RelationProvenance::NativeSource => "native_source",
        RelationProvenance::DeterministicRule => "deterministic_rule",
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
                RelationProvenance::DeterministicRule,
                None,
                vec![from.clone()],
                vec![],
            ),
            Err(ContractError::MissingRelationRuleVersion)
        );
        let mut relation = EvidenceRelation::derive(
            from.clone(),
            to,
            RelationBasis::TemporalCandidate,
            RelationProvenance::DeterministicRule,
            Some("temporal/v1".into()),
            vec![from],
            vec![],
        )
        .unwrap();
        relation.output_hash.push('0');
        assert_eq!(relation.validate(), Err(ContractError::RelationHashMismatch));
    }
}
