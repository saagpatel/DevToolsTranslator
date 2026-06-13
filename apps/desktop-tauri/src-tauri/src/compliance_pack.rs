#![forbid(unsafe_code)]

use dtt_core::{
    ComplianceEvidenceItemV1, ComplianceEvidencePackV1, RolloutStageV1, SigningStatusV1,
    TelemetryAuditRunV1,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq)]
pub struct CompliancePackInput {
    pub kind: String,
    pub channel: String,
    pub version: String,
    pub stage: RolloutStageV1,
    pub now_ms: i64,
    pub manual_smoke_ready: bool,
    pub compliance_checks: Vec<Value>,
    pub signature_status: SigningStatusV1,
    pub telemetry_audit: Option<TelemetryAuditRunV1>,
    pub anomaly_summary: Value,
}

pub fn generate_pack(
    root: &Path,
    input: &CompliancePackInput,
) -> std::io::Result<ComplianceEvidencePackV1> {
    let stage_raw = stage_as_str(input.stage);
    let pack_dir = root
        .join("dist")
        .join("releases")
        .join("evidence")
        .join(&input.kind)
        .join(&input.version)
        .join(stage_raw);
    fs::create_dir_all(&pack_dir)?;

    let permission_allowlist_diff = serde_json::json!({
        "checks": input.compliance_checks,
    });
    let host_permission_inventory =
        extract_check_details(&input.compliance_checks, "host_permission_inventory");
    let privacy_policy_check =
        extract_check_details(&input.compliance_checks, "privacy_policy_url_present");
    let manual_smoke_snapshot = serde_json::json!({
        "manual_smoke_ready": input.manual_smoke_ready,
    });
    let signature_snapshot = serde_json::json!({
        "status": signing_as_str(input.signature_status),
    });
    let telemetry_summary = serde_json::to_value(input.telemetry_audit.clone())
        .unwrap_or_else(|_| serde_json::json!({"status":"unknown"}));
    let anomaly_summary = input.anomaly_summary.clone();

    let mut files: Vec<(String, Vec<u8>)> = vec![
        (
            "permission_allowlist_diff.json".to_string(),
            serde_json::to_vec_pretty(&permission_allowlist_diff)
                .unwrap_or_else(|_| b"{}".to_vec()),
        ),
        (
            "host_permission_inventory.json".to_string(),
            serde_json::to_vec_pretty(&host_permission_inventory)
                .unwrap_or_else(|_| b"{}".to_vec()),
        ),
        (
            "privacy_policy_check.json".to_string(),
            serde_json::to_vec_pretty(&privacy_policy_check).unwrap_or_else(|_| b"{}".to_vec()),
        ),
        (
            "manual_smoke_snapshot.json".to_string(),
            serde_json::to_vec_pretty(&manual_smoke_snapshot).unwrap_or_else(|_| b"{}".to_vec()),
        ),
        (
            "signature_snapshot.json".to_string(),
            serde_json::to_vec_pretty(&signature_snapshot).unwrap_or_else(|_| b"{}".to_vec()),
        ),
        (
            "telemetry_audit_summary.json".to_string(),
            serde_json::to_vec_pretty(&telemetry_summary).unwrap_or_else(|_| b"{}".to_vec()),
        ),
        (
            "anomaly_summary.json".to_string(),
            serde_json::to_vec_pretty(&anomaly_summary).unwrap_or_else(|_| b"{}".to_vec()),
        ),
    ];

    files.sort_by(|left, right| left.0.cmp(&right.0));

    let mut items = Vec::new();
    for (name, bytes) in &files {
        let file_path = pack_dir.join(name);
        fs::write(&file_path, bytes)?;
        items.push(ComplianceEvidenceItemV1 {
            item_key: name.replace(".json", ""),
            path: file_path.to_string_lossy().into_owned(),
            sha256: sha256_hex(bytes),
            size_bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        });
    }

    let manifest_payload = serde_json::json!({
        "v": 1,
        "kind": input.kind,
        "channel": input.channel,
        "version": input.version,
        "stage": stage_raw,
        "created_at_ms": input.now_ms,
        "items": items,
    });
    let manifest_bytes =
        serde_json::to_vec_pretty(&manifest_payload).unwrap_or_else(|_| b"{}".to_vec());
    let manifest_sha256 = sha256_hex(&manifest_bytes);
    let manifest_path = pack_dir.join("manifest.sha256.json");
    fs::write(&manifest_path, manifest_bytes)?;

    Ok(ComplianceEvidencePackV1 {
        pack_id: format!(
            "cep_{}",
            sha256_hex(
                format!(
                    "{}:{}:{}:{stage_raw}:{}",
                    input.kind, input.channel, input.version, input.now_ms
                )
                .as_bytes()
            )
        ),
        kind: input.kind.clone(),
        channel: input.channel.clone(),
        version: input.version.clone(),
        stage: Some(input.stage),
        pack_path: pack_dir.to_string_lossy().into_owned(),
        manifest_sha256,
        items,
        created_at_ms: input.now_ms,
        status: "generated".to_string(),
        error_code: None,
        error_message: None,
    })
}

fn stage_as_str(stage: RolloutStageV1) -> &'static str {
    match stage {
        RolloutStageV1::Pct5 => "pct_5",
        RolloutStageV1::Pct25 => "pct_25",
        RolloutStageV1::Pct50 => "pct_50",
        RolloutStageV1::Pct100 => "pct_100",
    }
}

fn signing_as_str(status: SigningStatusV1) -> &'static str {
    match status {
        SigningStatusV1::NotApplicable => "not_applicable",
        SigningStatusV1::Pending => "pending",
        SigningStatusV1::Verified => "verified",
        SigningStatusV1::Failed => "failed",
    }
}

fn extract_check_details(checks: &[Value], key: &str) -> Value {
    checks
        .iter()
        .find(|entry| entry.get("check_key").and_then(Value::as_str) == Some(key))
        .and_then(|entry| {
            entry.get("details_json").cloned().or_else(|| entry.get("details").cloned())
        })
        .unwrap_or_else(|| serde_json::json!({}))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::{generate_pack, CompliancePackInput};
    use dtt_core::{RolloutStageV1, SigningStatusV1};
    use serde_json::json;

    #[test]
    fn pack_generation_writes_deterministic_files() {
        let root = std::env::temp_dir().join("dtt-compliance-pack-test");
        let _ = std::fs::remove_dir_all(&root);
        let input = CompliancePackInput {
            kind: "extension".to_string(),
            channel: "chrome_store_public".to_string(),
            version: "1.0.0".to_string(),
            stage: RolloutStageV1::Pct5,
            now_ms: 1000,
            manual_smoke_ready: true,
            compliance_checks: vec![
                json!({"check_key":"privacy_policy_url_present","details_json":{"value":"https://example.com"}}),
            ],
            signature_status: SigningStatusV1::Verified,
            telemetry_audit: None,
            anomaly_summary: json!({"critical_count":0}),
        };
        let pack = generate_pack(&root, &input).expect("generate pack");
        assert_eq!(pack.status, "generated");
        assert!(!pack.items.is_empty());
        assert!(std::path::Path::new(&pack.pack_path).exists());
    }
}
