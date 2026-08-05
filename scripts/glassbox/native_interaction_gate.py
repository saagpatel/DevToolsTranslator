#!/usr/bin/env python3
"""Validate view-update interactions reported by the signed native Glassbox app."""

import argparse
import base64
import hashlib
import json
import pathlib
import statistics
import subprocess
from collections import Counter


def git(root: pathlib.Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True)
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, int(len(ordered) * fraction + 0.999999) - 1))]


def validate(sample: dict) -> tuple[dict, dict]:
    rows = sample.get("samples", [])
    names = {"t": "table_view", "s": "evidence_select", "o": "export_open", "c": "export_close", "l": "timeline_view"}
    normalized = [(names.get(row[0]), row[1]) for row in rows if isinstance(row, list) and len(row) == 2]
    observed_names = {name for name, _ in normalized}
    durations = [duration for _, duration in normalized]
    numeric = all(isinstance(value, (int, float)) and 0 <= value < 60_000 for value in durations)
    values = [float(value) for value in durations] if numeric else []
    by_interaction = {}
    for code, name in names.items():
        action_values = [float(row[1]) for row in rows if isinstance(row, list) and len(row) == 2 and row[0] == code and isinstance(row[1], (int, float))]
        by_interaction[name] = {
            "sample_count": len(action_values),
            "median_ms": statistics.median(action_values) if action_values else None,
            "p95_ms": percentile(action_values, 0.95) if action_values else None,
            "maximum_ms": max(action_values) if action_values else None,
        }
    measurements = {
        "sample_count": len(values),
        "interaction_names": sorted(name for name in observed_names if isinstance(name, str)),
        "median_ms": statistics.median(values) if values else None,
        "p95_ms": percentile(values, 0.95) if values else None,
        "maximum_ms": max(values) if values else None,
        "by_interaction": by_interaction,
    }
    codes = [row[0] for row in rows if isinstance(row, list) and len(row) == 2]
    expected_codes = list("tsocl") * 30
    checks = {
        "sample_schema_exact": sample.get("schema_version") == "glassbox-native-interaction-sample/v1"
        and set(sample) == {"schema_version", "samples", "errors"}
        and len(normalized) == len(rows)
        and None not in observed_names,
        "all_interactions_rendered": sample.get("errors") == [],
        "representative_interaction_set": observed_names == set(names.values()),
        "at_least_150_view_update_samples": len(values) >= 150,
        "exactly_30_samples_per_interaction_and_ordered": codes == expected_codes
        and Counter(codes) == Counter({code: 30 for code in names}),
        "durations_are_bounded_numbers": numeric,
        "p95_under_100_ms": measurements["p95_ms"] is not None and measurements["p95_ms"] <= 100.0,
        "maximum_under_500_ms": measurements["maximum_ms"] is not None and measurements["maximum_ms"] <= 500.0,
        "every_interaction_p95_under_100_ms": all(
            metric["p95_ms"] is not None and metric["p95_ms"] <= 100.0
            for metric in by_interaction.values()
        ),
        "every_interaction_maximum_under_500_ms": all(
            metric["maximum_ms"] is not None and metric["maximum_ms"] <= 500.0
            for metric in by_interaction.values()
        ),
    }
    return checks, measurements


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=pathlib.Path)
    parser.add_argument("--binary", type=pathlib.Path)
    parser.add_argument("--result", type=pathlib.Path)
    parser.add_argument("--receipt", type=pathlib.Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        bad = {"schema_version": "glassbox-native-interaction-sample/v1", "samples": [[code, 900.0] for _ in range(30) for code in "tsocl"], "errors": []}
        checks, _ = validate(bad)
        missing = {"schema_version": "glassbox-native-interaction-sample/v1", "samples": [[code, 1.0] for _ in range(29) for code in "tsocl"], "errors": []}
        missing_checks, _ = validate(missing)
        results = {
            "slow_interaction_fixture_rejected": not checks["p95_under_100_ms"]
            and not checks["maximum_under_500_ms"]
            and not checks["every_interaction_p95_under_100_ms"]
            and not checks["every_interaction_maximum_under_500_ms"],
            "missing_or_misordered_samples_rejected": not missing_checks["exactly_30_samples_per_interaction_and_ordered"],
        }
        print(json.dumps(results))
        return 0 if all(results.values()) else 1
    if not all((args.root, args.binary, args.result, args.receipt)):
        parser.error("--root, --binary, --result, and --receipt are required")
    errors = []
    try:
        encoded = args.result.read_text(encoding="ascii")
        sample = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        sample = {}
        errors.append(f"invalid interaction result: {error}")
    checks, measurements = validate(sample)
    receipt = {
        "schema_version": "glassbox-native-interaction/v1",
        "ok": all(checks.values()) and not errors,
        "git_head": git(args.root, "rev-parse", "HEAD"),
        "git_tree": git(args.root, "rev-parse", "HEAD^{tree}"),
        "git_dirty": bool(git(args.root, "status", "--porcelain")),
        "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
        "sample_sha256": hashlib.sha256(args.result.read_bytes()).hexdigest() if args.result.is_file() else None,
        "oracle_sha256": hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
        "checks": checks,
        "measurements": measurements,
        "errors": errors + [name for name, value in checks.items() if not value],
    }
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
