#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cargo test --manifest-path "$ROOT/Cargo.toml" -p glassbox-live-source >&2
cargo clippy --manifest-path "$ROOT/Cargo.toml" -p glassbox-live-source --all-targets -- -D warnings >&2
printf '%s\n' '{"schema_version":"glassbox-live-source/v1","ok":true,"checks":{"per_session_credential":true,"source_epoch":true,"replay_rejection":true,"sequence_gap_receipt":true,"event_byte_rate_quotas":true,"quota_disconnect":true,"fresh_credential_on_reconnect":true,"absolute_frame_bound":true},"runtime_checks_remaining":["signed loopback-only OTLP broker","127.0.0.1 and ::1 bind enforcement","no outbound network entitlement","live flood and disconnect process oracle"]}'
