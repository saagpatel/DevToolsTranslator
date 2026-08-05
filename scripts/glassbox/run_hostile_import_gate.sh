#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
RECEIPT=${1:-"$ROOT/artifacts/glassbox-hostile-import.json"}
TARGET_DIR=${GLASSBOX_WORKER_TARGET_DIR:-"${TMPDIR:-/tmp}/glassbox-worker-target"}
SIGN_DIR=$(mktemp -d "${TMPDIR:-/tmp}/glassbox-worker-sign.XXXXXX")
VALID_OUT=$(mktemp "${TMPDIR:-/tmp}/glassbox-valid.XXXXXX")
INVALID_OUT=$(mktemp "${TMPDIR:-/tmp}/glassbox-invalid.XXXXXX")
TIME_LOG=$(mktemp "${TMPDIR:-/tmp}/glassbox-time.XXXXXX")
HAR_VALID_OUT=$(mktemp "${TMPDIR:-/tmp}/glassbox-har-valid.XXXXXX")
HAR_MALFORMED_OUT=$(mktemp "${TMPDIR:-/tmp}/glassbox-har-malformed.XXXXXX")
HAR_UNKNOWN_OUT=$(mktemp "${TMPDIR:-/tmp}/glassbox-har-unknown.XXXXXX")
HAR_INVALID_TIME_OUT=$(mktemp "${TMPDIR:-/tmp}/glassbox-har-invalid-time.XXXXXX")
HAR_TIME_LOG=$(mktemp "${TMPDIR:-/tmp}/glassbox-har-time.XXXXXX")
OTLP_VALID_OUT=$(mktemp "${TMPDIR:-/tmp}/glassbox-otlp-valid.XXXXXX")
OTLP_MALFORMED_OUT=$(mktemp "${TMPDIR:-/tmp}/glassbox-otlp-malformed.XXXXXX")
OTLP_MIXED_OUT=$(mktemp "${TMPDIR:-/tmp}/glassbox-otlp-mixed.XXXXXX")
OTLP_UNKNOWN_OUT=$(mktemp "${TMPDIR:-/tmp}/glassbox-otlp-unknown.XXXXXX")
OTLP_INVALID_TIME_OUT=$(mktemp "${TMPDIR:-/tmp}/glassbox-otlp-invalid-time.XXXXXX")
OTLP_DUPLICATE_OUT=$(mktemp "${TMPDIR:-/tmp}/glassbox-otlp-duplicate.XXXXXX")
OTLP_TIME_LOG=$(mktemp "${TMPDIR:-/tmp}/glassbox-otlp-time.XXXXXX")
APPLE_LOG_VALID_OUT=$(mktemp "${TMPDIR:-/tmp}/glassbox-apple-log-valid.XXXXXX")
APPLE_LOG_MALFORMED_OUT=$(mktemp "${TMPDIR:-/tmp}/glassbox-apple-log-malformed.XXXXXX")
APPLE_LOG_UNKNOWN_OUT=$(mktemp "${TMPDIR:-/tmp}/glassbox-apple-log-unknown.XXXXXX")
APPLE_LOG_MISSING_END_OUT=$(mktemp "${TMPDIR:-/tmp}/glassbox-apple-log-missing-end.XXXXXX")
APPLE_LOG_DIGEST_OUT=$(mktemp "${TMPDIR:-/tmp}/glassbox-apple-log-digest.XXXXXX")
APPLE_LOG_ORDINAL_OUT=$(mktemp "${TMPDIR:-/tmp}/glassbox-apple-log-ordinal.XXXXXX")
APPLE_LOG_TIME_LOG=$(mktemp "${TMPDIR:-/tmp}/glassbox-apple-log-time.XXXXXX")
BUNDLE_VALID=$(mktemp "${TMPDIR:-/tmp}/glassbox-bundle-valid.XXXXXX")
BUNDLE_DUPLICATE=$(mktemp "${TMPDIR:-/tmp}/glassbox-bundle-duplicate.XXXXXX")
BUNDLE_CORRUPT=$(mktemp "${TMPDIR:-/tmp}/glassbox-bundle-corrupt.XXXXXX")
BUNDLE_TRUNCATED=$(mktemp "${TMPDIR:-/tmp}/glassbox-bundle-truncated.XXXXXX")
BUNDLE_TRAILING=$(mktemp "${TMPDIR:-/tmp}/glassbox-bundle-trailing.XXXXXX")
BUNDLE_FUTURE=$(mktemp "${TMPDIR:-/tmp}/glassbox-bundle-future.XXXXXX")
BUNDLE_VALID_OUT=$(mktemp "${TMPDIR:-/tmp}/glassbox-bundle-valid-out.XXXXXX")
BUNDLE_DUPLICATE_OUT=$(mktemp "${TMPDIR:-/tmp}/glassbox-bundle-duplicate-out.XXXXXX")
BUNDLE_CORRUPT_OUT=$(mktemp "${TMPDIR:-/tmp}/glassbox-bundle-corrupt-out.XXXXXX")
BUNDLE_TRUNCATED_OUT=$(mktemp "${TMPDIR:-/tmp}/glassbox-bundle-truncated-out.XXXXXX")
BUNDLE_TRAILING_OUT=$(mktemp "${TMPDIR:-/tmp}/glassbox-bundle-trailing-out.XXXXXX")
BUNDLE_FUTURE_OUT=$(mktemp "${TMPDIR:-/tmp}/glassbox-bundle-future-out.XXXXXX")
BUNDLE_TIME_LOG=$(mktemp "${TMPDIR:-/tmp}/glassbox-bundle-time.XXXXXX")
FUZZ_OUT=$(mktemp "${TMPDIR:-/tmp}/glassbox-parser-fuzz.XXXXXX")
OVERSIZED=$(mktemp "${TMPDIR:-/tmp}/glassbox-oversized.XXXXXX")
OVERSIZED_OUT=$(mktemp "${TMPDIR:-/tmp}/glassbox-oversized-out.XXXXXX")
trap 'rm -rf "$SIGN_DIR"; rm -f "$VALID_OUT" "$INVALID_OUT" "$TIME_LOG" "$HAR_VALID_OUT" "$HAR_MALFORMED_OUT" "$HAR_UNKNOWN_OUT" "$HAR_INVALID_TIME_OUT" "$HAR_TIME_LOG" "$OTLP_VALID_OUT" "$OTLP_MALFORMED_OUT" "$OTLP_MIXED_OUT" "$OTLP_UNKNOWN_OUT" "$OTLP_INVALID_TIME_OUT" "$OTLP_DUPLICATE_OUT" "$OTLP_TIME_LOG" "$APPLE_LOG_VALID_OUT" "$APPLE_LOG_MALFORMED_OUT" "$APPLE_LOG_UNKNOWN_OUT" "$APPLE_LOG_MISSING_END_OUT" "$APPLE_LOG_DIGEST_OUT" "$APPLE_LOG_ORDINAL_OUT" "$APPLE_LOG_TIME_LOG" "$BUNDLE_VALID" "$BUNDLE_DUPLICATE" "$BUNDLE_CORRUPT" "$BUNDLE_TRUNCATED" "$BUNDLE_TRAILING" "$BUNDLE_FUTURE" "$BUNDLE_VALID_OUT" "$BUNDLE_DUPLICATE_OUT" "$BUNDLE_CORRUPT_OUT" "$BUNDLE_TRUNCATED_OUT" "$BUNDLE_TRAILING_OUT" "$BUNDLE_FUTURE_OUT" "$BUNDLE_TIME_LOG" "$FUZZ_OUT" "$OVERSIZED" "$OVERSIZED_OUT"' EXIT

CARGO_TARGET_DIR="$TARGET_DIR" cargo build --quiet --manifest-path "$ROOT/Cargo.toml" -p glassbox-import-worker -p glassbox-parser-fuzz
CARGO_TARGET_DIR="$TARGET_DIR" cargo build --quiet --manifest-path "$ROOT/Cargo.toml" -p glassbox-evidence-bundle --example bundle_probe
IDENTITY=${GLASSBOX_CODESIGN_IDENTITY:-$(security find-identity -v -p codesigning | sed -n 's/.*"\(Developer ID Application:[^"]*\)".*/\1/p' | head -1)}
if [ -z "$IDENTITY" ]; then
  echo "No Developer ID Application identity is available" >&2
  exit 2
fi
APP="$SIGN_DIR/GlassboxImportWorker.app"
BIN="$APP/Contents/MacOS/glassbox-import-worker"
mkdir -p "$APP/Contents/MacOS"
cp "$TARGET_DIR/debug/glassbox-import-worker" "$BIN"
cat >"$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>glassbox-import-worker</string>
<key>CFBundleIdentifier</key><string>com.glassbox.import-worker</string>
<key>CFBundleName</key><string>Glassbox Import Worker</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.1</string>
<key>CFBundleVersion</key><string>1</string>
</dict></plist>
PLIST
cat >"$SIGN_DIR/entitlements.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>com.apple.security.app-sandbox</key><true/>
</dict></plist>
PLIST
codesign --force --timestamp=none --options runtime --entitlements "$SIGN_DIR/entitlements.plist" --sign "$IDENTITY" "$APP" >/dev/null
codesign --verify --deep --strict "$APP"
"$TARGET_DIR/debug/glassbox-parser-fuzz" >"$FUZZ_OUT"
"$TARGET_DIR/debug/examples/bundle_probe" valid >"$BUNDLE_VALID"
"$TARGET_DIR/debug/examples/bundle_probe" duplicate >"$BUNDLE_DUPLICATE"
python3 - "$BUNDLE_VALID" "$BUNDLE_CORRUPT" "$BUNDLE_TRUNCATED" "$BUNDLE_TRAILING" "$BUNDLE_FUTURE" <<'PY'
import sys
from pathlib import Path
valid, corrupt, truncated, trailing, future = map(Path, sys.argv[1:])
data = valid.read_bytes()
changed = bytearray(data); changed[-2] ^= 1; corrupt.write_bytes(changed)
truncated.write_bytes(data[:-1])
trailing.write_bytes(data + b"\0")
changed = bytearray(data); changed[8:10] = (2).to_bytes(2, "big"); future.write_bytes(changed)
PY

CORPUS="$ROOT/crates/glassbox-fixtures/corpus/hostile-import"
/usr/bin/time -l env GLASSBOX_EXPECT_NO_NETWORK=1 "$BIN" <"$CORPUS/valid.ndjson" >"$VALID_OUT" 2>"$TIME_LOG"
if env GLASSBOX_EXPECT_NO_NETWORK=1 "$BIN" <"$CORPUS/unknown-field.ndjson" >"$INVALID_OUT" 2>/dev/null; then
  echo "unknown field corpus unexpectedly passed" >&2; exit 1
fi
if env GLASSBOX_EXPECT_NO_NETWORK=1 "$BIN" <"$CORPUS/malformed.ndjson" >"$INVALID_OUT" 2>/dev/null; then
  echo "malformed corpus unexpectedly passed" >&2; exit 1
fi
/usr/bin/time -l env GLASSBOX_EXPECT_NO_NETWORK=1 GLASSBOX_SOURCE_FORMAT=har-v1 GLASSBOX_HAR_SOURCE=selected_har GLASSBOX_CAPTURE_SESSION=har_session "$BIN" <"$CORPUS/har/valid.har" >"$HAR_VALID_OUT" 2>"$HAR_TIME_LOG"
if env GLASSBOX_EXPECT_NO_NETWORK=1 GLASSBOX_SOURCE_FORMAT=har-v1 GLASSBOX_HAR_SOURCE=selected_har GLASSBOX_CAPTURE_SESSION=har_session "$BIN" <"$CORPUS/har/malformed.har" >"$HAR_MALFORMED_OUT" 2>/dev/null; then
  echo "malformed HAR corpus unexpectedly passed" >&2; exit 1
fi
if env GLASSBOX_EXPECT_NO_NETWORK=1 GLASSBOX_SOURCE_FORMAT=har-v1 GLASSBOX_HAR_SOURCE=selected_har GLASSBOX_CAPTURE_SESSION=har_session "$BIN" <"$CORPUS/har/unknown-extension.har" >"$HAR_UNKNOWN_OUT" 2>/dev/null; then
  echo "unknown HAR extension unexpectedly passed" >&2; exit 1
fi
if env GLASSBOX_EXPECT_NO_NETWORK=1 GLASSBOX_SOURCE_FORMAT=har-v1 GLASSBOX_HAR_SOURCE=selected_har GLASSBOX_CAPTURE_SESSION=har_session "$BIN" <"$CORPUS/har/invalid-time.har" >"$HAR_INVALID_TIME_OUT" 2>/dev/null; then
  echo "invalid HAR time unexpectedly passed" >&2; exit 1
fi
/usr/bin/time -l env GLASSBOX_EXPECT_NO_NETWORK=1 GLASSBOX_SOURCE_FORMAT=otlp-jsonl-traces-v1 GLASSBOX_OTLP_SOURCE=selected_otlp GLASSBOX_CAPTURE_SESSION=otlp_session "$BIN" <"$CORPUS/otlp/valid-traces.jsonl" >"$OTLP_VALID_OUT" 2>"$OTLP_TIME_LOG"
if env GLASSBOX_EXPECT_NO_NETWORK=1 GLASSBOX_SOURCE_FORMAT=otlp-jsonl-traces-v1 GLASSBOX_OTLP_SOURCE=selected_otlp GLASSBOX_CAPTURE_SESSION=otlp_session "$BIN" <"$CORPUS/otlp/malformed.jsonl" >"$OTLP_MALFORMED_OUT" 2>/dev/null; then
  echo "malformed OTLP corpus unexpectedly passed" >&2; exit 1
fi
if env GLASSBOX_EXPECT_NO_NETWORK=1 GLASSBOX_SOURCE_FORMAT=otlp-jsonl-traces-v1 GLASSBOX_OTLP_SOURCE=selected_otlp GLASSBOX_CAPTURE_SESSION=otlp_session "$BIN" <"$CORPUS/otlp/mixed-signal.jsonl" >"$OTLP_MIXED_OUT" 2>/dev/null; then
  echo "mixed-signal OTLP corpus unexpectedly passed" >&2; exit 1
fi
if env GLASSBOX_EXPECT_NO_NETWORK=1 GLASSBOX_SOURCE_FORMAT=otlp-jsonl-traces-v1 GLASSBOX_OTLP_SOURCE=selected_otlp GLASSBOX_CAPTURE_SESSION=otlp_session "$BIN" <"$CORPUS/otlp/unknown-field.jsonl" >"$OTLP_UNKNOWN_OUT" 2>/dev/null; then
  echo "unknown OTLP field unexpectedly passed" >&2; exit 1
fi
if env GLASSBOX_EXPECT_NO_NETWORK=1 GLASSBOX_SOURCE_FORMAT=otlp-jsonl-traces-v1 GLASSBOX_OTLP_SOURCE=selected_otlp GLASSBOX_CAPTURE_SESSION=otlp_session "$BIN" <"$CORPUS/otlp/invalid-time.jsonl" >"$OTLP_INVALID_TIME_OUT" 2>/dev/null; then
  echo "invalid OTLP time unexpectedly passed" >&2; exit 1
fi
if env GLASSBOX_EXPECT_NO_NETWORK=1 GLASSBOX_SOURCE_FORMAT=otlp-jsonl-traces-v1 GLASSBOX_OTLP_SOURCE=selected_otlp GLASSBOX_CAPTURE_SESSION=otlp_session "$BIN" <"$CORPUS/otlp/duplicate-span.jsonl" >"$OTLP_DUPLICATE_OUT" 2>/dev/null; then
  echo "duplicate OTLP span unexpectedly passed" >&2; exit 1
fi
/usr/bin/time -l env GLASSBOX_EXPECT_NO_NETWORK=1 GLASSBOX_SOURCE_FORMAT=apple-log-projection-v1 GLASSBOX_CAPTURE_SESSION=apple_log_session "$BIN" <"$CORPUS/apple-log/valid.ndjson" >"$APPLE_LOG_VALID_OUT" 2>"$APPLE_LOG_TIME_LOG"
if env GLASSBOX_EXPECT_NO_NETWORK=1 GLASSBOX_SOURCE_FORMAT=apple-log-projection-v1 GLASSBOX_CAPTURE_SESSION=apple_log_session "$BIN" <"$CORPUS/apple-log/malformed.ndjson" >"$APPLE_LOG_MALFORMED_OUT" 2>/dev/null; then
  echo "malformed Apple log projection unexpectedly passed" >&2; exit 1
fi
if env GLASSBOX_EXPECT_NO_NETWORK=1 GLASSBOX_SOURCE_FORMAT=apple-log-projection-v1 GLASSBOX_CAPTURE_SESSION=apple_log_session "$BIN" <"$CORPUS/apple-log/unknown-sensitive-field.ndjson" >"$APPLE_LOG_UNKNOWN_OUT" 2>/dev/null; then
  echo "sensitive Apple log field unexpectedly passed" >&2; exit 1
fi
if env GLASSBOX_EXPECT_NO_NETWORK=1 GLASSBOX_SOURCE_FORMAT=apple-log-projection-v1 GLASSBOX_CAPTURE_SESSION=apple_log_session "$BIN" <"$CORPUS/apple-log/missing-end.ndjson" >"$APPLE_LOG_MISSING_END_OUT" 2>/dev/null; then
  echo "unterminated Apple log projection unexpectedly passed" >&2; exit 1
fi
if env GLASSBOX_EXPECT_NO_NETWORK=1 GLASSBOX_SOURCE_FORMAT=apple-log-projection-v1 GLASSBOX_CAPTURE_SESSION=apple_log_session "$BIN" <"$CORPUS/apple-log/digest-mismatch.ndjson" >"$APPLE_LOG_DIGEST_OUT" 2>/dev/null; then
  echo "Apple log projection with digest mismatch unexpectedly passed" >&2; exit 1
fi
if env GLASSBOX_EXPECT_NO_NETWORK=1 GLASSBOX_SOURCE_FORMAT=apple-log-projection-v1 GLASSBOX_CAPTURE_SESSION=apple_log_session "$BIN" <"$CORPUS/apple-log/ordinal-gap.ndjson" >"$APPLE_LOG_ORDINAL_OUT" 2>/dev/null; then
  echo "Apple log projection with ordinal gap unexpectedly passed" >&2; exit 1
fi
/usr/bin/time -l env GLASSBOX_EXPECT_NO_NETWORK=1 GLASSBOX_SOURCE_FORMAT=glassbox-bundle-v1 GLASSBOX_BUNDLE_SOURCE=selected_bundle GLASSBOX_IMPORT_SESSION=bundle_session "$BIN" <"$BUNDLE_VALID" >"$BUNDLE_VALID_OUT" 2>"$BUNDLE_TIME_LOG"
if env GLASSBOX_EXPECT_NO_NETWORK=1 GLASSBOX_SOURCE_FORMAT=glassbox-bundle-v1 GLASSBOX_BUNDLE_SOURCE=selected_bundle GLASSBOX_IMPORT_SESSION=bundle_session "$BIN" <"$BUNDLE_DUPLICATE" >"$BUNDLE_DUPLICATE_OUT" 2>/dev/null; then
  echo "duplicate bundle observation unexpectedly passed" >&2; exit 1
fi
if env GLASSBOX_EXPECT_NO_NETWORK=1 GLASSBOX_SOURCE_FORMAT=glassbox-bundle-v1 GLASSBOX_BUNDLE_SOURCE=selected_bundle GLASSBOX_IMPORT_SESSION=bundle_session "$BIN" <"$BUNDLE_CORRUPT" >"$BUNDLE_CORRUPT_OUT" 2>/dev/null; then
  echo "corrupt bundle unexpectedly passed" >&2; exit 1
fi
if env GLASSBOX_EXPECT_NO_NETWORK=1 GLASSBOX_SOURCE_FORMAT=glassbox-bundle-v1 GLASSBOX_BUNDLE_SOURCE=selected_bundle GLASSBOX_IMPORT_SESSION=bundle_session "$BIN" <"$BUNDLE_TRUNCATED" >"$BUNDLE_TRUNCATED_OUT" 2>/dev/null; then
  echo "truncated bundle unexpectedly passed" >&2; exit 1
fi
if env GLASSBOX_EXPECT_NO_NETWORK=1 GLASSBOX_SOURCE_FORMAT=glassbox-bundle-v1 GLASSBOX_BUNDLE_SOURCE=selected_bundle GLASSBOX_IMPORT_SESSION=bundle_session "$BIN" <"$BUNDLE_TRAILING" >"$BUNDLE_TRAILING_OUT" 2>/dev/null; then
  echo "bundle with trailing data unexpectedly passed" >&2; exit 1
fi
if env GLASSBOX_EXPECT_NO_NETWORK=1 GLASSBOX_SOURCE_FORMAT=glassbox-bundle-v1 GLASSBOX_BUNDLE_SOURCE=selected_bundle GLASSBOX_IMPORT_SESSION=bundle_session "$BIN" <"$BUNDLE_FUTURE" >"$BUNDLE_FUTURE_OUT" 2>/dev/null; then
  echo "unsupported bundle major unexpectedly passed" >&2; exit 1
fi
python3 - "$OVERSIZED" <<'PY'
import sys
from pathlib import Path
Path(sys.argv[1]).write_bytes(b"x" * (16 * 1024 * 1024 + 1))
PY
if env GLASSBOX_EXPECT_NO_NETWORK=1 "$BIN" <"$OVERSIZED" >"$OVERSIZED_OUT" 2>/dev/null; then
  echo "oversized record unexpectedly passed" >&2; exit 1
fi
python3 - "$BIN" "$VALID_OUT" "$INVALID_OUT" "$OVERSIZED" "$OVERSIZED_OUT" "$TIME_LOG" "$CORPUS" "$IDENTITY" "$RECEIPT" "$HAR_VALID_OUT" "$HAR_MALFORMED_OUT" "$HAR_UNKNOWN_OUT" "$HAR_INVALID_TIME_OUT" "$HAR_TIME_LOG" "$TARGET_DIR/debug/glassbox-parser-fuzz" "$FUZZ_OUT" "$OTLP_VALID_OUT" "$OTLP_MALFORMED_OUT" "$OTLP_MIXED_OUT" "$OTLP_UNKNOWN_OUT" "$OTLP_INVALID_TIME_OUT" "$OTLP_DUPLICATE_OUT" "$OTLP_TIME_LOG" "$BUNDLE_VALID" "$BUNDLE_DUPLICATE" "$BUNDLE_CORRUPT" "$BUNDLE_TRUNCATED" "$BUNDLE_TRAILING" "$BUNDLE_FUTURE" "$BUNDLE_VALID_OUT" "$BUNDLE_DUPLICATE_OUT" "$BUNDLE_CORRUPT_OUT" "$BUNDLE_TRUNCATED_OUT" "$BUNDLE_TRAILING_OUT" "$BUNDLE_FUTURE_OUT" "$BUNDLE_TIME_LOG" "$APPLE_LOG_VALID_OUT" "$APPLE_LOG_MALFORMED_OUT" "$APPLE_LOG_UNKNOWN_OUT" "$APPLE_LOG_MISSING_END_OUT" "$APPLE_LOG_DIGEST_OUT" "$APPLE_LOG_ORDINAL_OUT" "$APPLE_LOG_TIME_LOG" <<'PY'
import hashlib, json, os, re, subprocess, sys, time
from datetime import datetime, timezone
from pathlib import Path

binary, valid_path, invalid_path, oversized_path, oversized_out, time_path, corpus_path, identity, receipt_path, har_valid_path, har_malformed_path, har_unknown_path, har_invalid_time_path, har_time_path, fuzz_binary_path, fuzz_output_path, otlp_valid_path, otlp_malformed_path, otlp_mixed_path, otlp_unknown_path, otlp_invalid_time_path, otlp_duplicate_path, otlp_time_path, bundle_valid_path, bundle_duplicate_path, bundle_corrupt_path, bundle_truncated_path, bundle_trailing_path, bundle_future_path, bundle_valid_out, bundle_duplicate_out, bundle_corrupt_out, bundle_truncated_out, bundle_trailing_out, bundle_future_out, bundle_time_path, apple_log_valid_path, apple_log_malformed_path, apple_log_unknown_path, apple_log_missing_end_path, apple_log_digest_path, apple_log_ordinal_path, apple_log_time_path = map(Path, sys.argv[1:])
identity = str(identity)
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def git(*args):
    result = subprocess.run(["git", *args], text=True, capture_output=True)
    return result.stdout.strip() if result.returncode == 0 else "unknown"
def frames(path):
    return decode_frames(path.read_bytes())
def decode_frames(data):
    output = []
    while data:
        if len(data) < 4: raise ValueError("truncated frame length")
        length = int.from_bytes(data[:4], "big"); data = data[4:]
        if length > 1024 * 1024 or len(data) < length: raise ValueError("invalid frame length")
        output.append(json.loads(data[:length])); data = data[length:]
    return output

valid = frames(valid_path)
invalid = frames(invalid_path)
oversized_frames = frames(oversized_out)
har_valid = frames(har_valid_path)
har_invalid = {
    "malformed": frames(har_malformed_path),
    "unknown_extension": frames(har_unknown_path),
    "invalid_time": frames(har_invalid_time_path),
}
types = [item.get("type") for item in valid]
invalid_complete = bool(invalid and invalid[-1].get("type") == "end")
oversized_complete = bool(oversized_frames and oversized_frames[-1].get("type") == "end")
har_types = [item.get("type") for item in har_valid]
har_observation = har_valid[1].get("observation", {}) if len(har_valid) == 3 else {}
har_fields = har_observation.get("fields", {})
har_bytes = har_valid_path.read_bytes()
har_secrets = [
    b"seed-host.example", b"seed-query", b"seed-cookie", b"seed-header",
    b"seed-request-body", b"seed-response-body", b"203.0.113.9",
]
fuzz = json.loads(fuzz_output_path.read_text())
otlp_valid = frames(otlp_valid_path)
otlp_invalid = {
    "malformed": frames(otlp_malformed_path),
    "mixed_signal": frames(otlp_mixed_path),
    "unknown_field": frames(otlp_unknown_path),
    "invalid_time": frames(otlp_invalid_time_path),
    "duplicate_span": frames(otlp_duplicate_path),
}
otlp_types = [item.get("type") for item in otlp_valid]
otlp_observations = [item.get("observation", {}) for item in otlp_valid if item.get("type") == "observation"]
otlp_relations = [item.get("relation", {}) for item in otlp_valid if item.get("type") == "relation"]
otlp_bytes = otlp_valid_path.read_bytes()
otlp_secrets = [
    b"seed-resource", b"seed-scope", b"seed-root-span", b"seed-child-span",
    b"seed-host", b"seed-query", b"seed-event-secret", b"seed-database-body",
    b"seed-root-status", b"seed-child-status", b"seed-link-state",
]
bundle_valid = frames(bundle_valid_out)
bundle_invalid = {
    "duplicate_semantic_id": frames(bundle_duplicate_out),
    "corrupt_member": frames(bundle_corrupt_out),
    "truncated_member": frames(bundle_truncated_out),
    "trailing_data": frames(bundle_trailing_out),
    "unsupported_major": frames(bundle_future_out),
}
bundle_types = [item.get("type") for item in bundle_valid]
bundle_observations = [item.get("observation", {}) for item in bundle_valid if item.get("type") == "observation"]
bundle_manifest_length = int.from_bytes(bundle_valid_path.read_bytes()[12:16], "big")
bundle_manifest = json.loads(bundle_valid_path.read_bytes()[16:16 + bundle_manifest_length])
bundle_cases = json.loads((corpus_path / "bundle/cases.json").read_text())
apple_log_valid = frames(apple_log_valid_path)
apple_log_invalid = {
    "malformed": frames(apple_log_malformed_path),
    "unknown_sensitive_field": frames(apple_log_unknown_path),
    "missing_end": frames(apple_log_missing_end_path),
    "digest_mismatch": frames(apple_log_digest_path),
    "ordinal_gap": frames(apple_log_ordinal_path),
}
apple_log_types = [item.get("type") for item in apple_log_valid]
apple_log_observations = [item.get("observation", {}) for item in apple_log_valid if item.get("type") == "observation"]
apple_log_bytes = apple_log_valid_path.read_bytes()
apple_log_cases = json.loads((corpus_path / "apple-log/cases.json").read_text())
env = os.environ.copy(); env["GLASSBOX_EXPECT_NO_NETWORK"] = "1"
cancelled = subprocess.Popen([str(binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
time.sleep(0.2); cancelled.kill(); cancelled_output, _ = cancelled.communicate(timeout=2)
cancelled_frames = decode_frames(cancelled_output)
cancelled_complete = bool(cancelled_frames and cancelled_frames[-1].get("type") == "end")
def resident_set_size(path):
    match = re.search(r"\s+(\d+)\s+maximum resident set size", path.read_text(errors="replace"))
    return int(match.group(1)) if match else None
rss_samples = [resident_set_size(time_path), resident_set_size(har_time_path), resident_set_size(otlp_time_path), resident_set_size(bundle_time_path), resident_set_size(apple_log_time_path)]
max_rss = max((value for value in rss_samples if value is not None), default=None)
entitlements = subprocess.run(["codesign", "-d", "--entitlements", ":-", str(binary)], text=True, capture_output=True)
entitlement_text = entitlements.stdout + entitlements.stderr
corpus = {str(path.relative_to(corpus_path)):sha(path) for path in sorted(corpus_path.rglob("*")) if path.is_file()}
checks = {
    "valid_frame_sequence": types == ["begin", "observation", "end"],
    "har_valid_frame_sequence": har_types == ["begin", "observation", "end"],
    "har_metadata_projection": (
        har_observation.get("source_kind") == "har"
        and har_observation.get("native_id") == "har://selected_har/entry/1"
        and har_fields == {
            "method": "POST", "size": "18", "status": "503",
            "url": "https://[redacted]/[redacted]?keys=2",
        }
    ),
    "har_sensitive_values_absent": all(secret not in har_bytes for secret in har_secrets),
    "har_hostile_cases_have_no_end": all(
        not frames or frames[-1].get("type") != "end" for frames in har_invalid.values()
    ),
    "otlp_valid_frame_sequence": otlp_types == ["begin", "observation", "observation", "relation", "end"],
    "otlp_metadata_projection": (
        len(otlp_observations) == 2
        and all(item.get("source_kind") == "otel" for item in otlp_observations)
        and otlp_observations[1].get("fields", {}).get("parent_span_id") == "0102040800000001"
        and len(otlp_relations) == 1
        and otlp_relations[0].get("provenance", {}).get("rule_version") == "otlp-parent/v1"
    ),
    "otlp_sensitive_values_absent": all(secret not in otlp_bytes for secret in otlp_secrets),
    "otlp_hostile_cases_have_no_end": all(
        not frames or frames[-1].get("type") != "end" for frames in otlp_invalid.values()
    ),
    "bundle_valid_frame_sequence": bundle_types == ["begin", "observation", "observation", "relation", "end"],
    "bundle_identity_and_lineage_projection": (
        len(bundle_observations) == 2
        and all(item.get("materialization_id", "").startswith("bundle-materialization:") for item in bundle_observations)
        and all(item.get("lineage_id", "").startswith("bundle-lineage:selected_bundle:") for item in bundle_observations)
    ),
    "bundle_manifest_integrity_contract": (
        bundle_valid_path.read_bytes().startswith(b"GLSBX001")
        and bundle_manifest.get("schema_version") == "glassbox-evidence-bundle/v1"
        and bundle_manifest.get("authenticity") == "unsigned_local"
        and len(bundle_manifest.get("integrity_root_sha256", "")) == 64
    ),
    "bundle_hostile_cases_have_no_end": all(
        not frames or frames[-1].get("type") != "end" for frames in bundle_invalid.values()
    ),
    "bundle_hostile_case_contract_complete": set(bundle_cases.get("cases", [])) == {
        "valid", "corrupt_member", "truncated_member", "trailing_data",
        "unsupported_major", "duplicate_semantic_id",
    },
    "apple_log_valid_frame_sequence": apple_log_types == ["begin", "observation", "observation", "end"],
    "apple_log_metadata_projection": (
        len(apple_log_observations) == 2
        and all(item.get("source_kind") == "apple-unified-log" for item in apple_log_observations)
        and apple_log_observations[0].get("fields") == {
            "activity_id": "9", "entry_kind": "log", "level": "info",
            "process_id": "42", "thread_id": "7",
        }
        and apple_log_observations[1].get("fields", {}).get("signpost_type") == "begin"
    ),
    "apple_log_sensitive_values_absent": all(
        marker not in apple_log_bytes
        for marker in (b"message", b"subsystem", b"category", b"process_name", b"sender", b"path")
    ),
    "apple_log_hostile_cases_have_no_end": all(
        not frames or frames[-1].get("type") != "end" for frames in apple_log_invalid.values()
    ),
    "apple_log_hostile_case_contract_complete": set(apple_log_cases.get("cases", [])) == {
        "valid", "malformed", "unknown_sensitive_field", "missing_end",
        "digest_mismatch", "ordinal_gap",
    },
    "deterministic_parser_fuzz_passes": (
        fuzz.get("schema_version") == "glassbox-parser-fuzz/v1"
        and fuzz.get("ok") is True
        and all(
            fuzz.get(parser, {}).get("cases", 0) >= 4096
            and fuzz.get(parser, {}).get("panics") == 0
            and fuzz.get(parser, {}).get("accepted", 0)
                + fuzz.get(parser, {}).get("rejected", 0)
                == fuzz.get(parser, {}).get("cases", -1)
            for parser in ("apple_log_projection", "evidence_bundle", "har", "otlp", "packet_capture")
        )
    ),
    "worker_no_network_self_test": True,
    "invalid_stream_has_no_end": not invalid_complete,
    "oversized_record_rejected_without_end": not oversized_complete,
    "cancelled_worker_has_no_end": cancelled.returncode != 0 and not cancelled_complete,
    "rss_within_768_mib": max_rss is not None and max_rss <= 768 * 1024 * 1024,
    "app_sandbox_entitlement": "com.apple.security.app-sandbox" in entitlement_text,
    "network_entitlements_absent": "com.apple.security.network.client" not in entitlement_text and "com.apple.security.network.server" not in entitlement_text,
}
receipt = {
    "schema_version":"glassbox-hostile-import/v1", "ok":all(checks.values()),
    "generated_at":datetime.now(timezone.utc).isoformat(), "git_head":git("rev-parse","HEAD"),
    "git_tree":git("rev-parse","HEAD^{tree}"), "git_dirty":bool(git("status","--porcelain")),
    "worker_sha256":sha(binary), "codesign_identity":identity, "checks":checks,
    "parser_fuzz_binary_sha256":sha(fuzz_binary_path),
    "parser_fuzz_output_sha256":sha(fuzz_output_path),
    "parser_fuzz":fuzz,
    "valid_frame_types":types, "maximum_resident_set_size_bytes":max_rss,
    "har_valid_frame_types":har_types,
    "har_invalid_frame_types":{key:[item.get("type") for item in value] for key,value in har_invalid.items()},
    "otlp_valid_frame_types":otlp_types,
    "otlp_invalid_frame_types":{key:[item.get("type") for item in value] for key,value in otlp_invalid.items()},
    "bundle_valid_frame_types":bundle_types,
    "bundle_invalid_frame_types":{key:[item.get("type") for item in value] for key,value in bundle_invalid.items()},
    "apple_log_valid_frame_types":apple_log_types,
    "apple_log_invalid_frame_types":{key:[item.get("type") for item in value] for key,value in apple_log_invalid.items()},
    "corpus_sha256":corpus, "generated_oversized_sha256":sha(oversized_path),
    "generated_bundle_sha256":{name:sha(path) for name,path in {
        "valid":bundle_valid_path, "duplicate_semantic_id":bundle_duplicate_path,
        "corrupt_member":bundle_corrupt_path, "truncated_member":bundle_truncated_path,
        "trailing_data":bundle_trailing_path, "unsupported_major":bundle_future_path,
    }.items()},
    "cancelled_frame_types":[item.get("type") for item in cancelled_frames],
    "errors":[] if all(checks.values()) else [key for key,value in checks.items() if not value]
}
Path(receipt_path).parent.mkdir(parents=True, exist_ok=True)
Path(receipt_path).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
print(json.dumps(receipt, indent=2, sort_keys=True))
raise SystemExit(0 if receipt["ok"] else 1)
PY
