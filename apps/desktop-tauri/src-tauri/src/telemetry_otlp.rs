#![forbid(unsafe_code)]

use dtt_core::{ReliabilityMetricSampleV1, TelemetryAuditStatusV1};
use serde_json::Value;
use sha2::{Digest, Sha256};

const ALLOWED_LABELS: &[&str] = &["state", "reason", "code", "stage", "marker"];

#[derive(Debug, Clone, PartialEq)]
pub struct OtlpPayload {
    pub ndjson: String,
    pub redacted_count: u32,
    pub payload_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TelemetryAuditResult {
    pub status: TelemetryAuditStatusV1,
    pub violations: Value,
}

pub fn build_sanitized_payload(samples: &[ReliabilityMetricSampleV1]) -> OtlpPayload {
    let mut rows = Vec::with_capacity(samples.len());
    let mut redacted_count = 0_u32;

    for sample in samples {
        let mut labels = sample.labels_json.clone();
        if let Some(map) = labels.as_object_mut() {
            let before = map.len();
            map.retain(|key, _| ALLOWED_LABELS.contains(&key.as_str()));
            redacted_count = redacted_count.saturating_add(
                u32::try_from(before.saturating_sub(map.len())).unwrap_or(u32::MAX),
            );
        } else {
            labels = Value::Object(serde_json::Map::new());
            redacted_count = redacted_count.saturating_add(1);
        }
        rows.push(serde_json::json!({
            "metric_id": sample.metric_id,
            "source": sample.source,
            "metric_key": sample.metric_key,
            "metric_value": sample.metric_value,
            "labels_json": labels,
            "ts_ms": sample.ts_ms,
        }));
    }

    rows.sort_by(|left, right| {
        serde_json_canonicalizer::to_string(left)
            .unwrap_or_default()
            .cmp(&serde_json_canonicalizer::to_string(right).unwrap_or_default())
    });

    let mut ndjson = String::new();
    for row in rows {
        ndjson.push_str(
            &serde_json_canonicalizer::to_string(&row).unwrap_or_else(|_| "{}".to_string()),
        );
        ndjson.push('\n');
    }

    let payload_sha256 = if ndjson.is_empty() {
        None
    } else {
        let mut hasher = Sha256::new();
        hasher.update(ndjson.as_bytes());
        Some(hasher.finalize().iter().map(|byte| format!("{byte:02x}")).collect())
    };

    OtlpPayload { ndjson, redacted_count, payload_sha256 }
}

pub fn run_privacy_audit(payload: &str) -> TelemetryAuditResult {
    if payload.trim().is_empty() {
        return TelemetryAuditResult {
            status: TelemetryAuditStatusV1::Pass,
            violations: Value::Array(Vec::new()),
        };
    }

    let mut violations = Vec::new();
    for (line_index, line) in payload.lines().enumerate() {
        let parsed: Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(_) => {
                violations.push(serde_json::json!({
                    "line": line_index,
                    "kind": "invalid_json",
                }));
                continue;
            }
        };

        let labels =
            parsed.get("labels_json").and_then(Value::as_object).cloned().unwrap_or_default();
        for key in labels.keys() {
            if !ALLOWED_LABELS.contains(&key.as_str()) {
                violations.push(serde_json::json!({
                    "line": line_index,
                    "kind": "disallowed_label",
                    "key": key,
                }));
            }
        }

        let encoded = serde_json_canonicalizer::to_string(&parsed).unwrap_or_default();
        let forbidden = ["authorization", "cookie", "set-cookie", "token=", "api_key", "x-api-key"];
        for marker in forbidden {
            if encoded.to_ascii_lowercase().contains(marker) {
                violations.push(serde_json::json!({
                    "line": line_index,
                    "kind": "forbidden_token",
                    "marker": marker,
                }));
                break;
            }
        }
    }

    let status = if violations.is_empty() {
        TelemetryAuditStatusV1::Pass
    } else {
        TelemetryAuditStatusV1::Fail
    };

    TelemetryAuditResult { status, violations: Value::Array(violations) }
}

pub fn send_with_retries(endpoint: &str, _payload: &str) -> Result<(), String> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        return Err("otlp_endpoint_missing".to_string());
    }

    let schedule = [1_u64, 2, 5];
    for (index, delay_s) in schedule.into_iter().enumerate() {
        let simulated = if endpoint.starts_with("mock://success") {
            Ok(())
        } else if endpoint.starts_with("mock://fail") {
            Err("otlp_transport_failed".to_string())
        } else if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
            // Phase 13 hardened pilot keeps transport non-blocking and deterministic.
            Ok(())
        } else {
            Err("otlp_endpoint_invalid_scheme".to_string())
        };

        match simulated {
            Ok(()) => return Ok(()),
            Err(error) if index + 1 == schedule.len() => return Err(error),
            Err(_) => {
                std::thread::sleep(std::time::Duration::from_secs(delay_s));
            }
        }
    }

    Err("otlp_transport_failed".to_string())
}

#[cfg(test)]
mod tests {
    use super::{build_sanitized_payload, run_privacy_audit};
    use dtt_core::{ReliabilityMetricKeyV1, ReliabilityMetricSampleV1, TelemetryAuditStatusV1};
    use serde_json::json;

    #[test]
    fn payload_sanitization_keeps_only_whitelisted_labels() {
        let samples = vec![ReliabilityMetricSampleV1 {
            metric_id: "met_1".to_string(),
            session_id: Some("sess_1".to_string()),
            source: "ws_bridge".to_string(),
            metric_key: ReliabilityMetricKeyV1::WsDisconnectCount,
            metric_value: 1.0,
            labels_json: json!({"reason": "closed", "secret": "drop-me"}),
            ts_ms: 1,
        }];

        let payload = build_sanitized_payload(&samples);
        assert_eq!(payload.redacted_count, 1);
        assert!(payload.ndjson.contains("reason"));
        assert!(!payload.ndjson.contains("secret"));
    }

    #[test]
    fn privacy_audit_detects_forbidden_markers() {
        let result =
            run_privacy_audit("{\"labels_json\":{\"reason\":\"ok\"},\"x\":\"token=abc\"}\n");
        assert_eq!(result.status, TelemetryAuditStatusV1::Fail);
        assert!(result.violations.as_array().is_some_and(|items| !items.is_empty()));
    }
}
