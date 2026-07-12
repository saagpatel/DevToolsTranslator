use glassbox_fixtures::gate1_fixture;
use glassbox_import::{BatchAssembler, WorkerFrame};
use glassbox_investigation::{
    build_view, EpistemicStatus, ExportPreviewRow, Hypothesis, Limitation, MysteryScenario,
    RunComparison, ScenarioObservation,
};
use glassbox_kernel::EvidenceKernel;
use glassbox_privacy::{derive_export, NativeField, PrivacyMode};
use serde_json::json;
use std::{error::Error, thread, time::Duration};

fn phase(name: &str, facts: serde_json::Value) {
    println!("{}", json!({"phase": name, "ok": true, "facts": facts}));
    thread::sleep(Duration::from_millis(1_250));
}

fn main() -> Result<(), Box<dyn Error>> {
    let fixture = gate1_fixture();
    phase(
        "fixture",
        json!({"observations": fixture.observations.len(), "relations": fixture.relations.len()}),
    );

    let mut assembler = BatchAssembler::default();
    let mut frames =
        vec![WorkerFrame::Begin { protocol_version: 1, source_format: "fixture-v1".into() }];
    frames.extend(
        fixture
            .observations
            .iter()
            .cloned()
            .map(|observation| WorkerFrame::Observation { observation }),
    );
    frames.extend(
        fixture.relations.iter().cloned().map(|relation| WorkerFrame::Relation { relation }),
    );
    frames.push(WorkerFrame::End);
    for frame in frames {
        assembler.push(&serde_json::to_vec(&frame)?)?;
    }
    let batch = assembler.finish()?;
    let mut kernel = EvidenceKernel::default();
    let imported = kernel.import_atomic(batch.observations, batch.relations)?;
    phase("import", json!({"inserted": imported.inserted, "total": imported.total}));

    let scenario = MysteryScenario {
        id: "runtime-offline".into(),
        family: "runtime".into(),
        variant: "base".into(),
        scope: vec!["fixture".into()],
        permission_tier: "import_only".into(),
        privacy_mode: "redacted".into(),
        observations: vec![ScenarioObservation {
            id: "evidence-a".into(),
            actor: "application".into(),
            label: "bounded fixture".into(),
            earliest_ns: "1".into(),
            latest_ns: "2".into(),
            native_locator: "fixture:runtime:1".into(),
            source: "fixture".into(),
            anchor_kind: "symptom".into(),
        }],
        relations: vec![],
        hypotheses: vec![
            Hypothesis {
                id: "candidate".into(),
                status: EpistemicStatus::Inferred,
                statement: "fixture supports a bounded candidate".into(),
                premises: vec!["evidence-a".into()],
                counterevidence: vec![],
                missing_evidence: vec![],
                falsifier: Some("a contradictory native observation".into()),
                model_generated: false,
            },
            Hypothesis {
                id: "alternative".into(),
                status: EpistemicStatus::Unknown,
                statement: "other explanations remain".into(),
                premises: vec![],
                counterevidence: vec![],
                missing_evidence: vec!["additional source".into()],
                falsifier: None,
                model_generated: false,
            },
        ],
        limitations: vec![Limitation {
            kind: "coverage".into(),
            detail: "fixture-only runtime probe".into(),
            affected_source: "fixture".into(),
        }],
        comparison: Some(RunComparison {
            healthy_scenario: "runtime-healthy".into(),
            differing_evidence: vec!["evidence-a".into()],
            unchanged_evidence: vec![],
        }),
        export_preview: vec![ExportPreviewRow {
            field: "http.authorization".into(),
            classification: "credential".into(),
            action: "drop".into(),
        }],
        expected_status: EpistemicStatus::Inferred,
        smallest_safe_next_source: None,
    };
    let view = build_view(scenario)?;
    phase("browse", json!({"rows": view.evidence_table.len(), "conclusion": view.conclusion}));
    let comparison = view.comparison.as_ref().ok_or("comparison missing")?;
    phase(
        "compare",
        json!({"healthy": comparison.healthy_scenario, "differences": comparison.differing_evidence.len()}),
    );

    let export = derive_export(
        b"native fixture bundle",
        &[
            NativeField { source: "http".into(), field: "method".into(), value: "GET".into() },
            NativeField {
                source: "http".into(),
                field: "authorization".into(),
                value: "Bearer must-not-export".into(),
            },
        ],
        PrivacyMode::Redacted,
        &[0x42; 32],
    )?;
    if export.fields.values().any(|value| value.contains("must-not-export")) {
        return Err("credential escaped export".into());
    }
    phase(
        "export",
        json!({"authenticity": export.manifest.authenticity, "fields": export.manifest.field_count}),
    );
    Ok(())
}
