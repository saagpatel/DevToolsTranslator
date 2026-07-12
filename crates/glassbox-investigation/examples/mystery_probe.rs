use glassbox_investigation::{
    build_view, validate_visual_table_equivalence, EpistemicStatus, ExportPreviewRow, Hypothesis,
    Limitation, MysteryScenario, RunComparison, ScenarioObservation, ScenarioRelation,
};
use serde::Deserialize;
use serde_json::json;
use std::{env, fs};

#[derive(Deserialize)]
struct RehearsalCorpus {
    schema_version: String,
    corpus_role: String,
    families: Vec<Family>,
}

#[derive(Deserialize)]
struct Family {
    family: String,
    symptom: String,
    primary: String,
    alternative: String,
    missing: String,
    next: String,
    variants: Vec<Variant>,
}

#[derive(Deserialize)]
struct Variant {
    name: String,
    status: EpistemicStatus,
    limitation: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args().nth(1).ok_or("fixture path required")?;
    let corpus: RehearsalCorpus = serde_json::from_slice(&fs::read(path)?)?;
    if corpus.schema_version != "glassbox-rehearsal-corpus/v2"
        || corpus.corpus_role != "public_rehearsal_not_held_out"
    {
        return Err("fixture must be explicitly labeled as the public rehearsal corpus".into());
    }
    let mut views = Vec::new();
    for family in corpus.families {
        for variant in &family.variants {
            let view = build_view(scenario(&family, variant))?;
            if !validate_visual_table_equivalence(&view) {
                return Err("timeline/table mismatch".into());
            }
            views.push(view);
        }
    }
    println!("{}", serde_json::to_string_pretty(&json!({ "views": views }))?);
    Ok(())
}

fn scenario(family: &Family, variant: &Variant) -> MysteryScenario {
    let id = format!("{}-{}", family.family, variant.name);
    let action_id = format!("{id}-anchor");
    let symptom_id = format!("{id}-symptom");
    let observations = vec![
        ScenarioObservation {
            id: action_id.clone(),
            actor: "user_or_source".into(),
            label: "investigation anchor".into(),
            earliest_ns: "100".into(),
            latest_ns: "120".into(),
            native_locator: format!("fixture:{id}:1"),
            source: "fixture".into(),
            anchor_kind: "action".into(),
        },
        ScenarioObservation {
            id: symptom_id.clone(),
            actor: "application_or_network".into(),
            label: family.symptom.clone(),
            earliest_ns: "110".into(),
            latest_ns: "180".into(),
            native_locator: format!("fixture:{id}:2"),
            source: "fixture".into(),
            anchor_kind: "symptom".into(),
        },
    ];
    let conclusive = variant.status != EpistemicStatus::Unknown;
    let relations = if conclusive {
        vec![ScenarioRelation {
            from: action_id.clone(),
            to: symptom_id.clone(),
            basis: "temporal_candidate".into(),
            rule_version: "mystery-fixture/v1".into(),
            uncertainty: "intervals overlap; order not invented".into(),
            supporting_evidence: vec![action_id.clone(), symptom_id.clone()],
            counterevidence: vec![],
            missing_evidence: vec![family.missing.clone()],
            falsifier: Some(format!("observe {}", family.alternative)),
            causal_assertion: false,
        }]
    } else {
        vec![]
    };
    let primary = Hypothesis {
        id: format!("{id}-primary"),
        status: variant.status,
        statement: family.primary.clone(),
        premises: if conclusive { vec![action_id.clone(), symptom_id.clone()] } else { vec![] },
        counterevidence: vec![],
        missing_evidence: if conclusive { vec![] } else { vec![family.missing.clone()] },
        falsifier: if conclusive { Some(format!("observe {}", family.alternative)) } else { None },
        model_generated: false,
    };
    let alternative = Hypothesis {
        id: format!("{id}-alternative"),
        status: EpistemicStatus::Unknown,
        statement: family.alternative.clone(),
        premises: vec![],
        counterevidence: vec![symptom_id.clone()],
        missing_evidence: vec![family.missing.clone()],
        falsifier: None,
        model_generated: false,
    };
    MysteryScenario {
        id: id.clone(),
        family: family.family.clone(),
        variant: variant.name.clone(),
        scope: vec!["fixture import".into()],
        permission_tier: "import_only".into(),
        privacy_mode: "metadata".into(),
        observations,
        relations,
        hypotheses: vec![primary, alternative],
        limitations: vec![Limitation {
            kind: variant.limitation.clone(),
            detail: format!("{} is explicitly visible", variant.limitation),
            affected_source: "fixture".into(),
        }],
        comparison: (variant.name == "base").then(|| RunComparison {
            healthy_scenario: format!("{}-healthy", family.family),
            differing_evidence: vec![symptom_id],
            unchanged_evidence: vec![action_id],
        }),
        export_preview: vec![ExportPreviewRow {
            field: "observation.label".into(),
            classification: "content_sensitive".into(),
            action: "pseudonym".into(),
        }],
        expected_status: variant.status,
        smallest_safe_next_source: (!conclusive).then(|| family.next.clone()),
    }
}
