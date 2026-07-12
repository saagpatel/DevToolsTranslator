//! Fixture-first investigation projections with epistemic and accessibility invariants.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpistemicStatus {
    Observed,
    Correlated,
    Inferred,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScenarioObservation {
    pub id: String,
    pub actor: String,
    pub label: String,
    pub earliest_ns: String,
    pub latest_ns: String,
    pub native_locator: String,
    pub source: String,
    pub anchor_kind: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScenarioRelation {
    pub from: String,
    pub to: String,
    pub basis: String,
    pub rule_version: String,
    pub uncertainty: String,
    pub supporting_evidence: Vec<String>,
    pub counterevidence: Vec<String>,
    pub missing_evidence: Vec<String>,
    pub falsifier: Option<String>,
    pub causal_assertion: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Hypothesis {
    pub id: String,
    pub status: EpistemicStatus,
    pub statement: String,
    pub premises: Vec<String>,
    pub counterevidence: Vec<String>,
    pub missing_evidence: Vec<String>,
    pub falsifier: Option<String>,
    pub model_generated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Limitation {
    pub kind: String,
    pub detail: String,
    pub affected_source: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RunComparison {
    pub healthy_scenario: String,
    pub differing_evidence: Vec<String>,
    pub unchanged_evidence: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExportPreviewRow {
    pub field: String,
    pub classification: String,
    pub action: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MysteryScenario {
    pub id: String,
    pub family: String,
    pub variant: String,
    pub scope: Vec<String>,
    pub permission_tier: String,
    pub privacy_mode: String,
    pub observations: Vec<ScenarioObservation>,
    pub relations: Vec<ScenarioRelation>,
    pub hypotheses: Vec<Hypothesis>,
    pub limitations: Vec<Limitation>,
    pub comparison: Option<RunComparison>,
    pub export_preview: Vec<ExportPreviewRow>,
    pub expected_status: EpistemicStatus,
    pub smallest_safe_next_source: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TimelineItem {
    pub id: String,
    pub actor: String,
    pub label: String,
    pub earliest_ns: String,
    pub latest_ns: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvidenceTableRow {
    pub id: String,
    pub actor: String,
    pub label: String,
    pub time_range: String,
    pub source: String,
    pub native_locator: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InvestigationView {
    pub scenario_id: String,
    pub family: String,
    pub variant: String,
    pub scope: Vec<String>,
    pub permission_tier: String,
    pub privacy_mode: String,
    pub limitations: Vec<Limitation>,
    pub anchors: Vec<String>,
    pub actor_lanes: BTreeMap<String, Vec<TimelineItem>>,
    pub evidence_table: Vec<EvidenceTableRow>,
    pub relation_explanations: Vec<ScenarioRelation>,
    pub hypotheses: Vec<Hypothesis>,
    pub comparison: Option<RunComparison>,
    pub export_preview: Vec<ExportPreviewRow>,
    pub conclusion: EpistemicStatus,
    pub smallest_safe_next_source: Option<String>,
}

pub fn build_view(scenario: MysteryScenario) -> Result<InvestigationView, InvestigationError> {
    validate_scenario(&scenario)?;
    let mut actor_lanes: BTreeMap<String, Vec<TimelineItem>> = BTreeMap::new();
    let mut evidence_table = Vec::with_capacity(scenario.observations.len());
    for observation in &scenario.observations {
        actor_lanes.entry(observation.actor.clone()).or_default().push(TimelineItem {
            id: observation.id.clone(),
            actor: observation.actor.clone(),
            label: observation.label.clone(),
            earliest_ns: observation.earliest_ns.clone(),
            latest_ns: observation.latest_ns.clone(),
        });
        evidence_table.push(EvidenceTableRow {
            id: observation.id.clone(),
            actor: observation.actor.clone(),
            label: observation.label.clone(),
            time_range: format!("{}..{}", observation.earliest_ns, observation.latest_ns),
            source: observation.source.clone(),
            native_locator: observation.native_locator.clone(),
        });
    }
    for lane in actor_lanes.values_mut() {
        lane.sort_by(|a, b| a.earliest_ns.cmp(&b.earliest_ns).then_with(|| a.id.cmp(&b.id)));
    }
    evidence_table.sort_by(|a, b| a.id.cmp(&b.id));
    let anchors = evidence_table.iter().map(|row| row.id.clone()).collect();
    Ok(InvestigationView {
        scenario_id: scenario.id,
        family: scenario.family,
        variant: scenario.variant,
        scope: scenario.scope,
        permission_tier: scenario.permission_tier,
        privacy_mode: scenario.privacy_mode,
        limitations: scenario.limitations,
        anchors,
        actor_lanes,
        evidence_table,
        relation_explanations: scenario.relations,
        hypotheses: scenario.hypotheses,
        comparison: scenario.comparison,
        export_preview: scenario.export_preview,
        conclusion: scenario.expected_status,
        smallest_safe_next_source: scenario.smallest_safe_next_source,
    })
}

pub fn validate_scenario(scenario: &MysteryScenario) -> Result<(), InvestigationError> {
    if scenario.scope.is_empty()
        || scenario.permission_tier.is_empty()
        || scenario.privacy_mode.is_empty()
    {
        return Err(InvestigationError::MissingCaptureContext);
    }
    let ids: BTreeSet<_> = scenario.observations.iter().map(|item| item.id.as_str()).collect();
    if ids.len() != scenario.observations.len() {
        return Err(InvestigationError::DuplicateObservationId);
    }
    if scenario.observations.iter().any(|item| item.native_locator.is_empty()) {
        return Err(InvestigationError::MissingNativeLocator);
    }
    if scenario.observations.iter().any(|item| item.anchor_kind.is_empty()) {
        return Err(InvestigationError::MissingAnchorKind);
    }
    for relation in &scenario.relations {
        if !ids.contains(relation.from.as_str()) || !ids.contains(relation.to.as_str()) {
            return Err(InvestigationError::DanglingRelation);
        }
        if relation.basis.is_empty()
            || relation.rule_version.is_empty()
            || relation.uncertainty.is_empty()
            || relation.supporting_evidence.is_empty()
        {
            return Err(InvestigationError::UnexplainedRelation);
        }
        if relation
            .supporting_evidence
            .iter()
            .chain(&relation.counterevidence)
            .any(|id| !ids.contains(id.as_str()))
        {
            return Err(InvestigationError::DanglingRelationEvidence);
        }
        if relation.basis == "temporal_candidate" && relation.causal_assertion {
            return Err(InvestigationError::TemporalCausalityClaim);
        }
    }
    if scenario.hypotheses.len() < 2 {
        return Err(InvestigationError::MissingHypothesis);
    }
    for hypothesis in &scenario.hypotheses {
        if hypothesis.model_generated && hypothesis.status != EpistemicStatus::Inferred {
            return Err(InvestigationError::ModelGradePromotion);
        }
        if matches!(hypothesis.status, EpistemicStatus::Correlated | EpistemicStatus::Inferred)
            && (hypothesis.premises.is_empty() || missing_text(&hypothesis.falsifier))
        {
            return Err(InvestigationError::UnsupportedHypothesis);
        }
        if hypothesis.status == EpistemicStatus::Observed && hypothesis.premises.is_empty() {
            return Err(InvestigationError::UnsupportedHypothesis);
        }
    }
    if !scenario.hypotheses.iter().any(|hypothesis| hypothesis.status == scenario.expected_status) {
        return Err(InvestigationError::ConclusionNotGrounded);
    }
    if scenario.expected_status == EpistemicStatus::Unknown {
        let names_missing =
            scenario.hypotheses.iter().any(|hypothesis| !hypothesis.missing_evidence.is_empty());
        if !names_missing || missing_text(&scenario.smallest_safe_next_source) {
            return Err(InvestigationError::UnexplainedUnknown);
        }
    }
    if scenario.limitations.is_empty() || scenario.export_preview.is_empty() {
        return Err(InvestigationError::MissingInvestigationContext);
    }
    if scenario.variant == "base" && scenario.comparison.is_none() {
        return Err(InvestigationError::MissingHealthyComparison);
    }
    Ok(())
}

fn missing_text(value: &Option<String>) -> bool {
    match value {
        None => true,
        Some(value) => value.is_empty(),
    }
}

pub fn validate_visual_table_equivalence(view: &InvestigationView) -> bool {
    let visual_ids: BTreeSet<_> =
        view.actor_lanes.values().flatten().map(|item| item.id.as_str()).collect();
    let table_ids: BTreeSet<_> = view.evidence_table.iter().map(|row| row.id.as_str()).collect();
    visual_ids == table_ids && visual_ids.len() == view.evidence_table.len()
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum InvestigationError {
    #[error("capture scope, permission tier, or privacy mode is missing")]
    MissingCaptureContext,
    #[error("duplicate observation ID")]
    DuplicateObservationId,
    #[error("observation lacks a native locator")]
    MissingNativeLocator,
    #[error("observation lacks an anchor kind")]
    MissingAnchorKind,
    #[error("relation references absent evidence")]
    DanglingRelation,
    #[error("relation evidence references absent evidence")]
    DanglingRelationEvidence,
    #[error("temporal-only relation attempted a causal assertion")]
    TemporalCausalityClaim,
    #[error("relation lacks basis, version, uncertainty, or support")]
    UnexplainedRelation,
    #[error("scenario has no competing or primary hypothesis")]
    MissingHypothesis,
    #[error("model-generated output attempted a non-inferred grade")]
    ModelGradePromotion,
    #[error("correlated or inferred hypothesis lacks premises or falsifier")]
    UnsupportedHypothesis,
    #[error("conclusion status has no corresponding structured hypothesis")]
    ConclusionNotGrounded,
    #[error("unknown conclusion does not name missing evidence and the next safe source")]
    UnexplainedUnknown,
    #[error("limitations or field-level export preview is absent")]
    MissingInvestigationContext,
    #[error("base mystery lacks a healthy-run comparison")]
    MissingHealthyComparison,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_cannot_emit_observed_claim() {
        let mut scenario = sample();
        scenario.hypotheses[0].model_generated = true;
        scenario.hypotheses[0].status = EpistemicStatus::Observed;
        assert_eq!(validate_scenario(&scenario), Err(InvestigationError::ModelGradePromotion));
    }

    #[test]
    fn timeline_and_table_are_complete_equivalents() {
        let view = build_view(sample()).unwrap();
        assert!(validate_visual_table_equivalence(&view));
    }

    #[test]
    fn temporal_candidate_cannot_assert_causality() {
        let mut scenario = sample();
        scenario.relations.push(ScenarioRelation {
            from: "a".into(),
            to: "a".into(),
            basis: "temporal_candidate".into(),
            rule_version: "test/v1".into(),
            uncertainty: "overlap".into(),
            supporting_evidence: vec!["a".into()],
            counterevidence: vec![],
            missing_evidence: vec![],
            falsifier: Some("different timing".into()),
            causal_assertion: true,
        });
        assert_eq!(validate_scenario(&scenario), Err(InvestigationError::TemporalCausalityClaim));
    }

    fn sample() -> MysteryScenario {
        MysteryScenario {
            id: "sample".into(),
            family: "test".into(),
            variant: "base".into(),
            scope: vec!["fixture".into()],
            permission_tier: "import_only".into(),
            privacy_mode: "metadata".into(),
            observations: vec![ScenarioObservation {
                id: "a".into(),
                actor: "app".into(),
                label: "event".into(),
                earliest_ns: "1".into(),
                latest_ns: "2".into(),
                native_locator: "fixture:1".into(),
                source: "fixture".into(),
                anchor_kind: "symptom".into(),
            }],
            relations: vec![],
            hypotheses: vec![
                Hypothesis {
                    id: "h".into(),
                    status: EpistemicStatus::Inferred,
                    statement: "candidate".into(),
                    premises: vec!["a".into()],
                    counterevidence: vec![],
                    missing_evidence: vec![],
                    falsifier: Some("a different event".into()),
                    model_generated: false,
                },
                Hypothesis {
                    id: "h2".into(),
                    status: EpistemicStatus::Unknown,
                    statement: "alternative".into(),
                    premises: vec![],
                    counterevidence: vec!["a".into()],
                    missing_evidence: vec!["other source".into()],
                    falsifier: None,
                    model_generated: false,
                },
            ],
            limitations: vec![Limitation {
                kind: "coverage".into(),
                detail: "fixture scope".into(),
                affected_source: "fixture".into(),
            }],
            comparison: Some(RunComparison {
                healthy_scenario: "healthy".into(),
                differing_evidence: vec!["a".into()],
                unchanged_evidence: vec![],
            }),
            export_preview: vec![ExportPreviewRow {
                field: "label".into(),
                classification: "public".into(),
                action: "preserve".into(),
            }],
            expected_status: EpistemicStatus::Inferred,
            smallest_safe_next_source: None,
        }
    }
}
