#!/usr/bin/env python3
"""Structurally validate externally produced Glassbox human-study artifacts."""

import argparse
import hashlib
import json
import math
import pathlib
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

SCHEMA = "glassbox-human-benchmark/v2"
PRIMARY_OUTCOME = "time_to_first_evidence_supported_conclusion"


def timestamp(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo is not None else None
    except ValueError:
        return None


def sha256_text(value):
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def nonempty_text(value):
    return isinstance(value, str) and bool(value.strip())


def public_record_url(value, *, allow_invalid):
    if not nonempty_text(value):
        return False
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None:
        return False
    return allow_invalid or not parsed.hostname.endswith(".invalid")


def reject_json_constant(value):
    raise ValueError(f"invalid JSON constant: {value}")


def validate(data, allow_test_fixture=False, now=None):
    errors = []

    def require(condition, code):
        if not condition:
            errors.append(code)

    def exact(value, keys, code):
        require(isinstance(value, dict) and set(value) == keys, code)
        return value if isinstance(value, dict) else {}

    def number(value):
        return (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(value)
        )

    if not isinstance(data, dict):
        return ["root_object"]
    now = now or datetime.now(timezone.utc)
    required_root = {
        "schema_version",
        "artifact_role",
        "candidate_manifest_sha256",
        "corpus_manifest",
        "pilot",
        "power_analysis",
        "preregistration",
        "formal_study",
        "integrity",
    }
    expected_root = required_root | ({"test_fixture"} if allow_test_fixture else set())
    require(set(data) == expected_root, "root_keys")
    require(data.get("schema_version") == SCHEMA, "schema_version")
    require(data.get("artifact_role") == "external_human_study", "artifact_role")
    require(
        sha256_text(data.get("candidate_manifest_sha256")), "candidate_manifest_sha256"
    )
    require(
        data.get("test_fixture") is True
        if allow_test_fixture
        else "test_fixture" not in data,
        "test_fixture_rejected",
    )
    corpus = exact(
        data.get("corpus_manifest"),
        {
            "held_out",
            "family_count",
            "scenario_count",
            "sha256",
            "pre_freeze_excluded_roles",
        },
        "corpus_keys",
    )
    require(corpus.get("held_out") is True, "corpus_not_held_out")
    scenario_count = corpus.get("scenario_count")
    require(
        corpus.get("family_count") == 5
        and isinstance(scenario_count, int)
        and scenario_count >= 25,
        "corpus_scope",
    )
    require(sha256_text(corpus.get("sha256")), "corpus_hash")
    excluded_roles = corpus.get("pre_freeze_excluded_roles")
    require(
        isinstance(excluded_roles, list)
        and len(excluded_roles) == 2
        and set(excluded_roles) == {"glassbox_implementer", "scenario_designer"},
        "answer_key_separation",
    )
    pilot = exact(
        data.get("pilot"),
        {
            "human_participants",
            "agents_as_participants",
            "participant_count",
            "randomized",
            "counterbalanced",
            "efficacy_claimed",
            "variance_estimate",
        },
        "pilot_keys",
    )
    require(
        pilot.get("human_participants") is True
        and pilot.get("agents_as_participants") is False,
        "pilot_humans",
    )
    pilot_count = pilot.get("participant_count")
    require(
        isinstance(pilot_count, int) and 10 <= pilot_count <= 12,
        "pilot_participant_count",
    )
    require(
        pilot.get("randomized") is True and pilot.get("counterbalanced") is True,
        "pilot_design",
    )
    require(pilot.get("efficacy_claimed") is False, "pilot_no_efficacy_claim")
    require(
        number(pilot.get("variance_estimate"))
        and pilot.get("variance_estimate", 0) > 0,
        "pilot_variance",
    )
    power = exact(
        data.get("power_analysis"),
        {
            "alpha",
            "computed_from_pilot",
            "formal_sample_size",
            "method",
            "minimum_meaningful_time_reduction_fraction",
            "primary_outcome",
            "target_power",
        },
        "power_analysis_keys",
    )
    require(power.get("computed_from_pilot") is True, "power_source")
    require(
        isinstance(power.get("formal_sample_size"), int)
        and power.get("formal_sample_size", 0) >= 12,
        "formal_sample_size",
    )
    require(nonempty_text(power.get("method")), "power_analysis_method")
    require(power.get("primary_outcome") == PRIMARY_OUTCOME, "power_primary_outcome")
    alpha = power.get("alpha")
    target_power = power.get("target_power")
    meaningful_effect = power.get("minimum_meaningful_time_reduction_fraction")
    require(number(alpha) and 0 < alpha <= 0.05, "power_alpha")
    require(number(target_power) and 0.8 <= target_power <= 1, "power_target")
    require(number(meaningful_effect) and 0 < meaningful_effect < 1, "power_effect")
    prereg = exact(
        data.get("preregistration"),
        {
            "registered_at",
            "formal_data_collection_started_at",
            "minimum_meaningful_time_reduction_fraction",
            "public_record",
            "primary_outcome",
            "statistical_test",
            "exclusions",
            "stopping_rule",
        },
        "preregistration_keys",
    )
    registered = timestamp(prereg.get("registered_at"))
    started = timestamp(prereg.get("formal_data_collection_started_at"))
    require(
        registered is not None and started is not None and registered < started,
        "preregistered_before_collection",
    )
    require(
        started is not None and started <= now + timedelta(minutes=5),
        "formal_collection_not_future",
    )
    require(
        public_record_url(prereg.get("public_record"), allow_invalid=allow_test_fixture)
        and prereg.get("primary_outcome") == PRIMARY_OUTCOME
        and nonempty_text(prereg.get("statistical_test")),
        "preregistration_fields",
    )
    require(
        prereg.get("minimum_meaningful_time_reduction_fraction") == meaningful_effect,
        "preregistered_effect_threshold",
    )
    require(
        isinstance(prereg.get("exclusions"), list)
        and all(nonempty_text(item) for item in prereg.get("exclusions", []))
        and len(set(prereg.get("exclusions", []))) == len(prereg.get("exclusions", []))
        and nonempty_text(prereg.get("stopping_rule")),
        "preregistration_exclusions_stop",
    )
    formal = exact(
        data.get("formal_study"),
        {
            "human_participants",
            "agents_as_participants",
            "completed_at",
            "participant_count",
            "randomized",
            "counterbalanced",
            "independent_scoring",
            "blinded_adjudication",
            "metrics",
        },
        "formal_study_keys",
    )
    require(
        formal.get("human_participants") is True
        and formal.get("agents_as_participants") is False,
        "formal_humans",
    )
    formal_count = formal.get("participant_count")
    completed = timestamp(formal.get("completed_at"))
    required_count = power.get("formal_sample_size")
    require(
        isinstance(formal_count, int)
        and isinstance(required_count, int)
        and formal_count >= required_count,
        "formal_powered_sample",
    )
    require(
        started is not None
        and completed is not None
        and started < completed <= now + timedelta(minutes=5),
        "formal_completion_time",
    )
    require(
        formal.get("randomized") is True and formal.get("counterbalanced") is True,
        "formal_design",
    )
    require(
        formal.get("independent_scoring") is True
        and formal.get("blinded_adjudication") is True,
        "independent_blinded_scoring",
    )
    metrics = exact(
        formal.get("metrics"),
        {
            "addressable_evidence_citation_rate",
            "unsupported_causal_claim_rate",
            "seeded_secret_leaks",
            "time_reduction_confidence_interval_95",
            "time_reduction_fraction",
            "visible_limitation_rate",
            "time_to_supported_conclusion_improved",
            "primary_p_value",
        },
        "metrics_keys",
    )
    citation_rate = metrics.get("addressable_evidence_citation_rate")
    causal_rate = metrics.get("unsupported_causal_claim_rate")
    p_value = metrics.get("primary_p_value")
    require(
        number(citation_rate) and 0.90 <= citation_rate <= 1,
        "evidence_citation_target",
    )
    require(number(causal_rate) and 0 <= causal_rate < 0.05, "causal_claim_target")
    require(
        isinstance(metrics.get("seeded_secret_leaks"), int)
        and not isinstance(metrics.get("seeded_secret_leaks"), bool)
        and metrics.get("seeded_secret_leaks") == 0,
        "seeded_secret_target",
    )
    require(
        number(metrics.get("visible_limitation_rate"))
        and metrics.get("visible_limitation_rate") == 1.0,
        "limitation_visibility_target",
    )
    require(
        metrics.get("time_to_supported_conclusion_improved") is True,
        "time_improvement_direction",
    )
    effect = metrics.get("time_reduction_fraction")
    interval = exact(
        metrics.get("time_reduction_confidence_interval_95"),
        {"lower", "upper"},
        "time_reduction_interval_keys",
    )
    lower = interval.get("lower")
    upper = interval.get("upper")
    require(
        number(effect)
        and number(meaningful_effect)
        and meaningful_effect <= effect < 1,
        "meaningful_time_improvement",
    )
    require(
        number(lower)
        and number(effect)
        and number(upper)
        and 0 < lower <= effect <= upper < 1,
        "time_reduction_interval",
    )
    require(
        number(p_value) and number(alpha) and 0 <= p_value < alpha,
        "primary_significance",
    )
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
        "schema_version": SCHEMA,
        "artifact_role": "external_human_study",
        "test_fixture": True,
        "candidate_manifest_sha256": digest,
        "corpus_manifest": {
            "held_out": True,
            "family_count": 5,
            "scenario_count": 25,
            "sha256": digest,
            "pre_freeze_excluded_roles": ["glassbox_implementer", "scenario_designer"],
        },
        "pilot": {
            "human_participants": True,
            "agents_as_participants": False,
            "participant_count": 10,
            "randomized": True,
            "counterbalanced": True,
            "efficacy_claimed": False,
            "variance_estimate": 1.2,
        },
        "power_analysis": {
            "alpha": 0.05,
            "computed_from_pilot": True,
            "formal_sample_size": 24,
            "method": "paired simulation",
            "minimum_meaningful_time_reduction_fraction": 0.10,
            "primary_outcome": PRIMARY_OUTCOME,
            "target_power": 0.80,
        },
        "preregistration": {
            "registered_at": "2026-01-01T00:00:00Z",
            "formal_data_collection_started_at": "2026-02-01T00:00:00Z",
            "public_record": "https://example.invalid/prereg",
            "primary_outcome": PRIMARY_OUTCOME,
            "statistical_test": "paired test",
            "exclusions": [],
            "stopping_rule": "fixed N",
            "minimum_meaningful_time_reduction_fraction": 0.10,
        },
        "formal_study": {
            "human_participants": True,
            "agents_as_participants": False,
            "completed_at": "2026-03-01T00:00:00Z",
            "participant_count": 24,
            "randomized": True,
            "counterbalanced": True,
            "independent_scoring": True,
            "blinded_adjudication": True,
            "metrics": {
                "addressable_evidence_citation_rate": 0.95,
                "unsupported_causal_claim_rate": 0.02,
                "seeded_secret_leaks": 0,
                "visible_limitation_rate": 1.0,
                "time_to_supported_conclusion_improved": True,
                "time_reduction_fraction": 0.20,
                "time_reduction_confidence_interval_95": {
                    "lower": 0.08,
                    "upper": 0.31,
                },
                "primary_p_value": 0.01,
            },
        },
        "integrity": {
            "participant_registry_sha256": digest,
            "study_records_sha256": digest,
            "scoring_export_sha256": digest,
            "adjudication_log_sha256": digest,
            "preregistration_record_sha256": digest,
            "metric_recomputation_sha256": digest,
        },
    }
    passing = not validate(valid, allow_test_fixture=True)
    invalid = json.loads(json.dumps(valid))
    invalid["formal_study"]["metrics"]["unsupported_causal_claim_rate"] = 0.10
    causal_rejected = "causal_claim_target" in validate(
        invalid, allow_test_fixture=True
    )
    agent = json.loads(json.dumps(valid))
    agent["formal_study"]["agents_as_participants"] = True
    agent_rejected = "formal_humans" in validate(agent, allow_test_fixture=True)
    heldout = json.loads(json.dumps(valid))
    heldout["corpus_manifest"]["held_out"] = False
    public_rehearsal_rejected = "corpus_not_held_out" in validate(
        heldout, allow_test_fixture=True
    )
    unknown = json.loads(json.dumps(valid))
    unknown["formal_study"]["unreviewed"] = True
    unknown_field_rejected = "formal_study_keys" in validate(
        unknown, allow_test_fixture=True
    )
    future = json.loads(json.dumps(valid))
    future["preregistration"]["formal_data_collection_started_at"] = (
        "2099-01-01T00:00:00Z"
    )
    future_collection_rejected = "formal_collection_not_future" in validate(
        future, allow_test_fixture=True
    )
    completion_before_start = json.loads(json.dumps(valid))
    completion_before_start["formal_study"]["completed_at"] = "2026-01-15T00:00:00Z"
    invalid_completion_rejected = "formal_completion_time" in validate(
        completion_before_start, allow_test_fixture=True
    )
    boolean_metric = json.loads(json.dumps(valid))
    boolean_metric["formal_study"]["metrics"]["primary_p_value"] = False
    boolean_metric_rejected = "primary_significance" in validate(
        boolean_metric, allow_test_fixture=True
    )
    trivial_effect = json.loads(json.dumps(valid))
    trivial_effect["formal_study"]["metrics"]["time_reduction_fraction"] = 0.01
    trivial_effect_rejected = "meaningful_time_improvement" in validate(
        trivial_effect, allow_test_fixture=True
    )
    interval_crosses_zero = json.loads(json.dumps(valid))
    interval_crosses_zero["formal_study"]["metrics"][
        "time_reduction_confidence_interval_95"
    ]["lower"] = -0.01
    interval_crosses_zero_rejected = "time_reduction_interval" in validate(
        interval_crosses_zero, allow_test_fixture=True
    )
    outcome_drift = json.loads(json.dumps(valid))
    outcome_drift["preregistration"]["primary_outcome"] = "post_hoc_outcome"
    outcome_drift_rejected = "preregistration_fields" in validate(
        outcome_drift, allow_test_fixture=True
    )
    infinite_variance = json.loads(json.dumps(valid))
    infinite_variance["pilot"]["variance_estimate"] = float("inf")
    nonfinite_rejected = "pilot_variance" in validate(
        infinite_variance, allow_test_fixture=True
    )
    checks = {
        "valid_structure_passes_in_self_test_only": passing,
        "unsupported_causality_rejected": causal_rejected,
        "agents_rejected_as_participants": agent_rejected,
        "public_rehearsal_rejected_as_held_out": public_rehearsal_rejected,
        "unknown_field_rejected": unknown_field_rejected,
        "future_collection_rejected": future_collection_rejected,
        "invalid_completion_rejected": invalid_completion_rejected,
        "boolean_metric_rejected": boolean_metric_rejected,
        "trivial_effect_rejected": trivial_effect_rejected,
        "interval_crosses_zero_rejected": interval_crosses_zero_rejected,
        "outcome_drift_rejected": outcome_drift_rejected,
        "nonfinite_rejected": nonfinite_rejected,
    }
    return {
        "schema_version": "glassbox-benchmark-validator-self-test/v2",
        "ok": all(checks.values()),
        "checks": checks,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", nargs="?", type=pathlib.Path)
    parser.add_argument("--receipt", type=pathlib.Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        result = self_test()
    else:
        if args.artifact is None:
            parser.error("artifact is required unless --self-test is used")
        artifact_bytes = args.artifact.read_bytes()
        try:
            data = json.loads(artifact_bytes, parse_constant=reject_json_constant)
            errors = validate(data)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            data = {}
            errors = ["artifact_json"]
        result = {
            "schema_version": "glassbox-benchmark/v1",
            "ok": not errors,
            "benchmark_passed": not errors,
            "artifact": str(args.artifact),
            "artifact_sha256": hashlib.sha256(artifact_bytes).hexdigest(),
            "validator_sha256": hashlib.sha256(
                pathlib.Path(__file__).read_bytes()
            ).hexdigest(),
            "candidate_manifest_sha256": data.get("candidate_manifest_sha256"),
            "held_out_corpus_sha256": data.get("corpus_manifest", {}).get("sha256"),
            "errors": errors,
            "verification_limit": "structural validation does not authenticate participant identity or external records",
        }
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.receipt:
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_text(encoded)
    print(encoded, end="")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
