//! In-memory evidence kernel. Persistent storage is intentionally absent until the encryption spike passes.

use glassbox_contracts::{EvidenceRelation, NativeObservation, SemanticObservationId};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Default)]
pub struct EvidenceKernel {
    observations: BTreeMap<SemanticObservationId, NativeObservation>,
    relations: Vec<EvidenceRelation>,
}

impl EvidenceKernel {
    pub fn import_atomic(
        &mut self,
        observations: Vec<NativeObservation>,
        relations: Vec<EvidenceRelation>,
    ) -> Result<ImportResult, KernelError> {
        let mut staged = self.observations.clone();
        let mut inserted = 0;
        for observation in observations {
            match staged.get(&observation.semantic_id) {
                Some(existing) if existing == &observation => continue,
                Some(_) => return Err(KernelError::SemanticCollision(observation.semantic_id)),
                None => {
                    staged.insert(observation.semantic_id.clone(), observation);
                    inserted += 1;
                }
            }
        }
        for relation in &relations {
            relation.validate().map_err(KernelError::InvalidRelation)?;
            if !staged.contains_key(&relation.from) {
                return Err(KernelError::DanglingRelation(relation.from.clone()));
            }
            if !staged.contains_key(&relation.to) {
                return Err(KernelError::DanglingRelation(relation.to.clone()));
            }
        }
        self.observations = staged;
        for relation in relations {
            if !self.relations.contains(&relation) {
                self.relations.push(relation);
            }
        }
        Ok(ImportResult { inserted, total: self.observations.len() })
    }

    pub fn observation(&self, id: &SemanticObservationId) -> Option<&NativeObservation> {
        self.observations.get(id)
    }
    pub fn relations(&self) -> &[EvidenceRelation] {
        &self.relations
    }
    pub fn len(&self) -> usize {
        self.observations.len()
    }
    pub fn is_empty(&self) -> bool {
        self.observations.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImportResult {
    pub inserted: usize,
    pub total: usize,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum KernelError {
    #[error("semantic identity collision for {0:?}")]
    SemanticCollision(SemanticObservationId),
    #[error("relation references absent evidence {0:?}")]
    DanglingRelation(SemanticObservationId),
    #[error("invalid relation provenance: {0}")]
    InvalidRelation(#[from] glassbox_contracts::ContractError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use glassbox_contracts::{
        RelationBasis, RelationProvenance, RelationProvenanceRecord, TemporalRelation,
    };
    use glassbox_fixtures::gate1_fixture;

    #[test]
    fn preserves_native_id_collision_across_capture_sessions() {
        let fixture = gate1_fixture();
        assert_ne!(fixture.observations[0].semantic_id, fixture.observations[1].semantic_id);
        let mut kernel = EvidenceKernel::default();
        kernel.import_atomic(fixture.observations, fixture.relations).unwrap();
        assert_eq!(kernel.len(), 2);
    }

    #[test]
    fn retry_is_idempotent_and_native_observations_are_immutable() {
        let fixture = gate1_fixture();
        let mut kernel = EvidenceKernel::default();
        assert_eq!(
            kernel
                .import_atomic(fixture.observations.clone(), fixture.relations.clone())
                .unwrap()
                .inserted,
            2
        );
        assert_eq!(
            kernel
                .import_atomic(fixture.observations.clone(), fixture.relations.clone())
                .unwrap()
                .inserted,
            0
        );
        let mut conflicting = fixture.observations[0].clone();
        conflicting.fields.insert("url".into(), "mutated.example".into());
        assert!(matches!(
            kernel.import_atomic(vec![conflicting], vec![]),
            Err(KernelError::SemanticCollision(_))
        ));
        assert_eq!(kernel.len(), 2);
    }

    #[test]
    fn failed_import_publishes_nothing() {
        let fixture = gate1_fixture();
        let missing = SemanticObservationId::derive("cdp", "missing", "404");
        let bad = EvidenceRelation::derive(
            fixture.observations[0].semantic_id.clone(),
            missing,
            RelationBasis::TemporalCandidate,
            RelationProvenanceRecord {
                class: RelationProvenance::DeterministicJoin,
                rule_version: "temporal-window/v1".into(),
                inputs: vec![fixture.observations[0].semantic_id.clone()],
                supporting_evidence: vec![fixture.observations[0].semantic_id.clone()],
                counterevidence: vec![],
                missing_evidence: vec!["target observation".into()],
                falsifier: None,
                clock_uncertainty: None,
            },
        )
        .unwrap();
        let mut kernel = EvidenceKernel::default();
        assert!(kernel.import_atomic(fixture.observations, vec![bad]).is_err());
        assert!(kernel.is_empty());
    }

    #[test]
    fn overlapping_intervals_remain_unordered() {
        let fixture = gate1_fixture();
        assert_eq!(
            fixture.observations[0]
                .observed_time
                .relation_to(fixture.observations[1].observed_time),
            TemporalRelation::UnorderedOverlap
        );
    }

    #[test]
    fn lossless_round_trip_preserves_semantic_identity_not_materialization() {
        let fixture = gate1_fixture();
        let encoded = serde_json::to_vec(&fixture.observations[0]).unwrap();
        let mut reimported: NativeObservation = serde_json::from_slice(&encoded).unwrap();
        let original_semantic = reimported.semantic_id.clone();
        reimported.materialization_id =
            glassbox_contracts::MaterializationId("mat-reimport".into());
        reimported.lineage_id = glassbox_contracts::LineageId("lineage-reimport".into());
        assert_eq!(reimported.semantic_id, original_semantic);
        assert_ne!(reimported.materialization_id, fixture.observations[0].materialization_id);
        assert_ne!(reimported.lineage_id, fixture.observations[0].lineage_id);
    }
}
