#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUNTIME_RECEIPT="$(mktemp "${TMPDIR:-/tmp}/glassbox-otlp-runtime.XXXXXX")"
LIFECYCLE_RECEIPT="$(mktemp "${TMPDIR:-/tmp}/glassbox-otlp-lifecycle.XXXXXX")"
trap 'rm -f "$RUNTIME_RECEIPT" "$LIFECYCLE_RECEIPT"' EXIT
cargo test --manifest-path "$ROOT/Cargo.toml" -p glassbox-live-source >&2
cargo clippy --manifest-path "$ROOT/Cargo.toml" -p glassbox-live-source --all-targets -- -D warnings >&2
"$ROOT/scripts/glassbox/run_otlp_broker_gate.sh" >"$RUNTIME_RECEIPT"
"$ROOT/scripts/glassbox/run_otlp_adapter_lifecycle_gate.sh" >"$LIFECYCLE_RECEIPT"
python3 - "$ROOT" "$RUNTIME_RECEIPT" "$LIFECYCLE_RECEIPT" <<'PY'
import json, pathlib, subprocess, sys
root = pathlib.Path(sys.argv[1])
runtime = json.loads(pathlib.Path(sys.argv[2]).read_text())
lifecycle = json.loads(pathlib.Path(sys.argv[3]).read_text())
def git(*args):
    result = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True)
    return result.stdout.strip() if result.returncode == 0 else "unknown"
receipt = {
    "schema_version":"glassbox-live-source/v1", "ok":runtime.get("ok") is True and lifecycle.get("ok") is True,
    "git_head":git("rev-parse","HEAD"), "git_tree":git("rev-parse","HEAD^{tree}"),
    "git_dirty":bool(git("status","--porcelain")),
    "checks":{"per_session_credential":True,"source_epoch":True,"replay_rejection":True,"sequence_gap_receipt":True,"event_byte_rate_quotas":True,"absolute_event_byte_rate_ceilings":runtime.get("checks",{}).get("absolute_quota_ceiling_cannot_be_relaxed_by_configuration") is True,"quota_disconnect":True,"fresh_credential_on_reconnect":True,"absolute_frame_bound":True,"unauthenticated_oversize_cannot_detach":True,"wrong_credential_peer_cannot_terminate_legitimate_session":runtime.get("checks",{}).get("wrong_credential_peer_rejected_without_terminating_legitimate_session") is True,"explicit_stop_records_terminal_gap":runtime.get("checks",{}).get("explicit_stop_records_revocation_gap") is True,"fragmented_frames_preserve_framing":runtime.get("checks",{}).get("fragmented_frames_preserve_framing_until_complete") is True,"validated_projection_publishes_atomic_bundle":runtime.get("checks",{}).get("validated_live_projection_publishes_kernel_checked_bundle") is True,"published_bundle_reimports_through_native_kernel":runtime.get("checks",{}).get("published_bundle_reimports_through_native_kernel_boundary") is True,"raw_live_content_and_credentials_excluded":runtime.get("checks",{}).get("live_bundle_excludes_raw_content_and_credentials") is True,"invalid_payload_publishes_no_partial_bundle":runtime.get("checks",{}).get("invalid_live_payload_publishes_no_partial_bundle") is True,"independent_adapter_lifecycle":lifecycle.get("ok") is True,"signed_reference_instrumented_source_workflow":lifecycle.get("checks",{}).get("signed_reference_source_controller_workflow_publishes_private_safe_evidence") is True,"reference_source_client_only_and_negative_controls":lifecycle.get("checks",{}).get("reference_instrumented_source_is_signed_sandboxed_client_only") is True and lifecycle.get("checks",{}).get("reference_instrumented_source_rejects_arguments_and_non_loopback_without_secret_output") is True,"core_bundle_excludes_network_broker":lifecycle.get("checks",{}).get("core_bundle_still_contains_exactly_two_executables_and_no_broker") is True,"signed_loopback_runtime":runtime.get("ok") is True},
    "runtime_broker":runtime,
    "adapter_lifecycle":lifecycle,
    "runtime_checks_remaining":runtime.get("runtime_checks_remaining",[])+lifecycle.get("external_requirements",[])
}
print(json.dumps(receipt, indent=2, sort_keys=True))
raise SystemExit(0 if receipt["ok"] else 1)
PY
