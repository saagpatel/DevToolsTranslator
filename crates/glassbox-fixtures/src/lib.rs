use glassbox_contracts::{
    EvidenceRelation, LineageId, MaterializationId, NativeObservation, RelationBasis,
    SemanticObservationId, SourceTrust, TimeInterval,
};
use std::collections::BTreeMap;

pub struct Gate1Fixture {
    pub observations: Vec<NativeObservation>,
    pub relations: Vec<EvidenceRelation>,
}

pub fn gate1_fixture() -> Gate1Fixture {
    let make = |session: &str, materialization: &str, earliest: i128, latest: i128| {
        let semantic_id = SemanticObservationId::derive("cdp", session, "request-7");
        NativeObservation {
            semantic_id,
            materialization_id: MaterializationId(materialization.into()),
            lineage_id: LineageId(format!("lineage-{session}")),
            source_kind: "cdp".into(),
            capture_session: session.into(),
            native_id: "request-7".into(),
            observed_time: TimeInterval::new(earliest, latest).unwrap(),
            trust: SourceTrust::SourceDeclared,
            fields: BTreeMap::from([("method".into(), "GET".into())]),
        }
    };
    let first = make("capture-a", "mat-a", 100, 220);
    let second = make("capture-b", "mat-b", 180, 300);
    let relation = EvidenceRelation {
        from: first.semantic_id.clone(),
        to: second.semantic_id.clone(),
        basis: RelationBasis::SourceAsserted,
    };
    Gate1Fixture { observations: vec![first, second], relations: vec![relation] }
}
