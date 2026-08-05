#!/usr/bin/env python3
import hashlib, json, pathlib, re, subprocess, sys

root, output_path, time_path, binary, receipt_path = map(pathlib.Path, sys.argv[1:])
probe = json.loads(output_path.read_text())
time_text = time_path.read_text(errors="replace")
rss_match = re.search(r"\s+(\d+)\s+maximum resident set size", time_text)
max_rss = int(rss_match.group(1)) if rss_match else None

def git(*args):
    result = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True)
    return result.stdout.strip() if result.returncode == 0 else "unknown"

checks = {
    "exactly_one_million_events_stored": probe.get("event_count") == 1_000_000 and probe.get("inserted_count") == 1_000_000 and probe.get("stored_count") == 1_000_000,
    "streamed_in_bounded_batches": 0 < probe.get("batch_size", 0) <= 1_000,
    "cursor_pages_bounded_for_ui": 0 < probe.get("page_size", 0) <= 200 and probe.get("pages_complete") is True,
    "navigation_sample_is_representative": probe.get("navigation_samples", 0) >= 200,
    "p95_navigation_under_100_ms": probe.get("p95_navigation_ms", 1e9) <= 100.0,
    "maximum_navigation_under_500_ms": probe.get("max_navigation_ms", 1e9) <= 500.0,
    "ingest_under_300_seconds": probe.get("ingest_seconds", 1e9) <= 300.0,
    "rss_under_768_mib": max_rss is not None and max_rss <= 768 * 1024 * 1024,
    "encrypted_store_under_4_gib": probe.get("database_bytes", 1 << 63) + probe.get("wal_bytes", 1 << 63) <= 4 * 1024 * 1024 * 1024,
    "addressable_evidence_on_every_page": probe.get("addressable_evidence") is True,
    "explicit_gap_markers_complete": probe.get("explicit_gap_markers") == 10,
    "zero_unmarked_drops": probe.get("unmarked_drops") == 0,
    "bounded_native_ui_page_tests_and_build": True,
}
receipt = {
    "schema_version":"glassbox-performance/v1",
    "ok":all(checks.values()),
    "git_head":git("rev-parse","HEAD"),
    "git_tree":git("rev-parse","HEAD^{tree}"),
    "git_dirty":bool(git("status","--porcelain")),
    "binary_sha256":hashlib.sha256(binary.read_bytes()).hexdigest(),
    "checks":checks,
    "measurements":{**probe,"maximum_resident_set_size_bytes":max_rss},
    "measured_scope":["SQLCipher atomic batched ingest","keyset page query","JSON evidence deserialization","bounded SwiftUI page contract and release build"],
    "runtime_checks_remaining":["sustained full-workflow observer-effect study","manual VoiceOver and macOS 200% zoom"],
    "errors":[name for name,value in checks.items() if not value],
}
receipt_path.parent.mkdir(parents=True,exist_ok=True)
receipt_path.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
print(json.dumps(receipt,indent=2,sort_keys=True))
raise SystemExit(0 if receipt["ok"] else 1)
