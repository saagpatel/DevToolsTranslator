#!/usr/bin/env python3
"""Structurally validate externally produced Glassbox human-study artifacts."""
import argparse, hashlib, json, pathlib
from datetime import datetime, timedelta, timezone

SCHEMA = "glassbox-human-benchmark/v1"

def timestamp(value):
    if not isinstance(value, str): return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo is not None else None
    except ValueError: return None

def sha256_text(value):
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)

def validate(data, allow_test_fixture=False, now=None):
    errors = []
    def require(condition, code):
        if not condition: errors.append(code)
    def exact(value, keys, code):
        require(isinstance(value, dict) and set(value) == keys, code)
        return value if isinstance(value, dict) else {}
    def number(value):
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if not isinstance(data, dict):
        return ["root_object"]
    now = now or datetime.now(timezone.utc)
    required_root = {
        "schema_version", "artifact_role", "candidate_manifest_sha256",
        "corpus_manifest", "pilot", "power_analysis", "preregistration",
        "formal_study", "integrity",
    }
    require(required_root <= set(data) and set(data) <= required_root | {"test_fixture"}, "root_keys")
    require(data.get("schema_version") == SCHEMA, "schema_version")
    require(data.get("artifact_role") == "external_human_study", "artifact_role")
    require(sha256_text(data.get("candidate_manifest_sha256")), "candidate_manifest_sha256")
    require(allow_test_fixture or data.get("test_fixture") is not True, "test_fixture_rejected")
    corpus = exact(data.get("corpus_manifest"), {
        "held_out", "family_count", "scenario_count", "sha256",
        "pre_freeze_excluded_roles",
    }, "corpus_keys")
    require(corpus.get("held_out") is True, "corpus_not_held_out")
    scenario_count = corpus.get("scenario_count")
    require(corpus.get("family_count") == 5 and isinstance(scenario_count, int) and scenario_count >= 25, "corpus_scope")
    require(sha256_text(corpus.get("sha256")), "corpus_hash")
    require(set(corpus.get("pre_freeze_excluded_roles", [])) >= {"glassbox_implementer", "scenario_designer"}, "answer_key_separation")
    pilot = exact(data.get("pilot"), {
        "human_participants", "agents_as_participants", "participant_count",
        "randomized", "counterbalanced", "efficacy_claimed", "variance_estimate",
    }, "pilot_keys")
    require(pilot.get("human_participants") is True and pilot.get("agents_as_participants") is False, "pilot_humans")
    pilot_count = pilot.get("participant_count")
    require(isinstance(pilot_count, int) and 10 <= pilot_count <= 12, "pilot_participant_count")
    require(pilot.get("randomized") is True and pilot.get("counterbalanced") is True, "pilot_design")
    require(pilot.get("efficacy_claimed") is False, "pilot_no_efficacy_claim")
    require(number(pilot.get("variance_estimate")) and pilot.get("variance_estimate", 0) > 0, "pilot_variance")
    power = exact(data.get("power_analysis"), {
        "computed_from_pilot", "formal_sample_size", "method", "primary_outcome",
    }, "power_analysis_keys")
    require(power.get("computed_from_pilot") is True, "power_source")
    require(isinstance(power.get("formal_sample_size"), int) and power.get("formal_sample_size", 0) >= 12, "formal_sample_size")
    require(bool(power.get("method")) and bool(power.get("primary_outcome")), "power_analysis_fields")
    prereg = exact(data.get("preregistration"), {
        "registered_at", "formal_data_collection_started_at", "public_record",
        "primary_outcome", "statistical_test", "exclusions", "stopping_rule",
    }, "preregistration_keys")
    registered = timestamp(prereg.get("registered_at")); started = timestamp(prereg.get("formal_data_collection_started_at"))
    require(registered is not None and started is not None and registered < started, "preregistered_before_collection")
    require(started is not None and started <= now + timedelta(minutes=5), "formal_collection_not_future")
    require(bool(prereg.get("public_record")) and bool(prereg.get("primary_outcome")) and bool(prereg.get("statistical_test")), "preregistration_fields")
    require(isinstance(prereg.get("exclusions"), list) and bool(prereg.get("stopping_rule")), "preregistration_exclusions_stop")
    formal = exact(data.get("formal_study"), {
        "human_participants", "agents_as_participants", "participant_count",
        "randomized", "counterbalanced", "independent_scoring",
        "blinded_adjudication", "metrics",
    }, "formal_study_keys")
    require(formal.get("human_participants") is True and formal.get("agents_as_participants") is False, "formal_humans")
    formal_count = formal.get("participant_count")
    required_count = power.get("formal_sample_size")
    require(isinstance(formal_count, int) and isinstance(required_count, int) and formal_count >= required_count, "formal_powered_sample")
    require(formal.get("randomized") is True and formal.get("counterbalanced") is True, "formal_design")
    require(formal.get("independent_scoring") is True and formal.get("blinded_adjudication") is True, "independent_blinded_scoring")
    metrics = exact(formal.get("metrics"), {
        "addressable_evidence_citation_rate", "unsupported_causal_claim_rate",
        "seeded_secret_leaks", "visible_limitation_rate",
        "time_to_supported_conclusion_improved", "primary_p_value",
    }, "metrics_keys")
    citation_rate = metrics.get("addressable_evidence_citation_rate")
    causal_rate = metrics.get("unsupported_causal_claim_rate")
    p_value = metrics.get("primary_p_value")
    require(number(citation_rate) and citation_rate >= 0.90, "evidence_citation_target")
    require(number(causal_rate) and causal_rate < 0.05, "causal_claim_target")
    require(isinstance(metrics.get("seeded_secret_leaks"), int) and not isinstance(metrics.get("seeded_secret_leaks"), bool) and metrics.get("seeded_secret_leaks") == 0, "seeded_secret_target")
    require(number(metrics.get("visible_limitation_rate")) and metrics.get("visible_limitation_rate") == 1.0, "limitation_visibility_target")
    require(metrics.get("time_to_supported_conclusion_improved") is True, "time_improvement_direction")
    require(number(p_value) and 0 <= p_value < 0.05, "primary_significance")
    integrity_fields = {
        "participant_registry_sha256",
        "study_records_sha256",
        "scoring_export_sha256",
        "adjudication_log_sha256",
        "preregistration_record_sha256",
        "metric_recomputation_sha256",
    }
    integrity = exact(data.get("integrity"), integrity_fields, "integrity_keys")
    for field in integrity_fields:
        require(sha256_text(integrity.get(field)), f"integrity_{field}")
    return sorted(set(errors))

def self_test():
    digest = "a" * 64
    valid = {
        "schema_version":SCHEMA,"artifact_role":"external_human_study","test_fixture":True,
        "candidate_manifest_sha256":digest,
        "corpus_manifest":{"held_out":True,"family_count":5,"scenario_count":25,"sha256":digest,"pre_freeze_excluded_roles":["glassbox_implementer","scenario_designer"]},
        "pilot":{"human_participants":True,"agents_as_participants":False,"participant_count":10,"randomized":True,"counterbalanced":True,"efficacy_claimed":False,"variance_estimate":1.2},
        "power_analysis":{"computed_from_pilot":True,"formal_sample_size":24,"method":"paired simulation","primary_outcome":"time"},
        "preregistration":{"registered_at":"2026-01-01T00:00:00Z","formal_data_collection_started_at":"2026-02-01T00:00:00Z","public_record":"https://example.invalid/prereg","primary_outcome":"time","statistical_test":"paired test","exclusions":[],"stopping_rule":"fixed N"},
        "formal_study":{"human_participants":True,"agents_as_participants":False,"participant_count":24,"randomized":True,"counterbalanced":True,"independent_scoring":True,"blinded_adjudication":True,"metrics":{"addressable_evidence_citation_rate":.95,"unsupported_causal_claim_rate":.02,"seeded_secret_leaks":0,"visible_limitation_rate":1.0,"time_to_supported_conclusion_improved":True,"primary_p_value":.01}},
        "integrity":{"participant_registry_sha256":digest,"study_records_sha256":digest,"scoring_export_sha256":digest,"adjudication_log_sha256":digest,"preregistration_record_sha256":digest,"metric_recomputation_sha256":digest},
    }
    passing = not validate(valid, allow_test_fixture=True)
    invalid = json.loads(json.dumps(valid)); invalid["formal_study"]["metrics"]["unsupported_causal_claim_rate"] = .10
    causal_rejected = "causal_claim_target" in validate(invalid, allow_test_fixture=True)
    agent = json.loads(json.dumps(valid)); agent["formal_study"]["agents_as_participants"] = True
    agent_rejected = "formal_humans" in validate(agent, allow_test_fixture=True)
    heldout = json.loads(json.dumps(valid)); heldout["corpus_manifest"]["held_out"] = False
    public_rehearsal_rejected = "corpus_not_held_out" in validate(heldout, allow_test_fixture=True)
    unknown = json.loads(json.dumps(valid)); unknown["formal_study"]["unreviewed"] = True
    unknown_field_rejected = "formal_study_keys" in validate(unknown, allow_test_fixture=True)
    future = json.loads(json.dumps(valid)); future["preregistration"]["formal_data_collection_started_at"] = "2099-01-01T00:00:00Z"
    future_collection_rejected = "formal_collection_not_future" in validate(future, allow_test_fixture=True)
    boolean_metric = json.loads(json.dumps(valid)); boolean_metric["formal_study"]["metrics"]["primary_p_value"] = False
    boolean_metric_rejected = "primary_significance" in validate(boolean_metric, allow_test_fixture=True)
    checks = {"valid_structure_passes_in_self_test_only":passing,"unsupported_causality_rejected":causal_rejected,"agents_rejected_as_participants":agent_rejected,"public_rehearsal_rejected_as_held_out":public_rehearsal_rejected,"unknown_field_rejected":unknown_field_rejected,"future_collection_rejected":future_collection_rejected,"boolean_metric_rejected":boolean_metric_rejected}
    return {"schema_version":"glassbox-benchmark-validator-self-test/v1","ok":all(checks.values()),"checks":checks}

def main():
    parser=argparse.ArgumentParser(); parser.add_argument("artifact",nargs="?",type=pathlib.Path); parser.add_argument("--receipt",type=pathlib.Path); parser.add_argument("--self-test",action="store_true"); args=parser.parse_args()
    if args.self_test: result=self_test()
    else:
        if args.artifact is None: parser.error("artifact is required unless --self-test is used")
        artifact_bytes=args.artifact.read_bytes(); data=json.loads(artifact_bytes); errors=validate(data)
        result={"schema_version":"glassbox-benchmark/v1","ok":not errors,"benchmark_passed":not errors,"artifact":str(args.artifact),"artifact_sha256":hashlib.sha256(artifact_bytes).hexdigest(),"validator_sha256":hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),"candidate_manifest_sha256":data.get("candidate_manifest_sha256"),"held_out_corpus_sha256":data.get("corpus_manifest",{}).get("sha256"),"errors":errors,"verification_limit":"structural validation does not authenticate participant identity or external records"}
    encoded=json.dumps(result,indent=2,sort_keys=True)+"\n"
    if args.receipt: args.receipt.parent.mkdir(parents=True,exist_ok=True); args.receipt.write_text(encoded)
    print(encoded,end=""); return 0 if result["ok"] else 1

if __name__ == "__main__": raise SystemExit(main())
