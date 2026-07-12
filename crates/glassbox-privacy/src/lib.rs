//! Fail-closed field classification, redaction, pseudonymization, and export derivation.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use url::Url;

const POLICY_VERSION: &str = "glassbox-redaction/v1";
type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    Public,
    MetadataSensitive,
    ContentSensitive,
    Credential,
    QuarantinedNative,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyMode {
    Metadata,
    Redacted,
    Full,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Transform {
    Preserve,
    Pseudonym,
    StructuredUrl,
    Drop,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FieldRule {
    pub source: &'static str,
    pub field: &'static str,
    pub class: DataClass,
    pub metadata: Transform,
    pub redacted: Transform,
}

pub const FIELD_RULES: &[FieldRule] = &[
    rule("http", "method", DataClass::Public, Transform::Preserve, Transform::Preserve),
    rule("http", "status", DataClass::MetadataSensitive, Transform::Preserve, Transform::Preserve),
    rule("http", "size", DataClass::MetadataSensitive, Transform::Preserve, Transform::Preserve),
    rule(
        "http",
        "url",
        DataClass::ContentSensitive,
        Transform::StructuredUrl,
        Transform::StructuredUrl,
    ),
    rule("http", "authorization", DataClass::Credential, Transform::Drop, Transform::Drop),
    rule("http", "cookie", DataClass::Credential, Transform::Drop, Transform::Drop),
    rule("http", "headers", DataClass::ContentSensitive, Transform::Drop, Transform::Pseudonym),
    rule("http", "body", DataClass::ContentSensitive, Transform::Drop, Transform::Pseudonym),
    rule("filesystem", "path", DataClass::ContentSensitive, Transform::Drop, Transform::Pseudonym),
    rule("log", "message", DataClass::ContentSensitive, Transform::Drop, Transform::Pseudonym),
    rule("otel", "span_name", DataClass::ContentSensitive, Transform::Drop, Transform::Pseudonym),
    rule("otel", "resource", DataClass::ContentSensitive, Transform::Drop, Transform::Pseudonym),
    rule("otel", "baggage", DataClass::Credential, Transform::Drop, Transform::Drop),
    rule("dns", "name", DataClass::ContentSensitive, Transform::Drop, Transform::Pseudonym),
    rule(
        "packet",
        "capture_source",
        DataClass::ContentSensitive,
        Transform::Drop,
        Transform::Pseudonym,
    ),
    rule(
        "packet",
        "section_index",
        DataClass::MetadataSensitive,
        Transform::Preserve,
        Transform::Preserve,
    ),
    rule(
        "packet",
        "interface_id",
        DataClass::MetadataSensitive,
        Transform::Preserve,
        Transform::Preserve,
    ),
    rule(
        "packet",
        "interface_name",
        DataClass::ContentSensitive,
        Transform::Drop,
        Transform::Pseudonym,
    ),
    rule(
        "packet",
        "packet_ordinal",
        DataClass::MetadataSensitive,
        Transform::Preserve,
        Transform::Preserve,
    ),
    rule(
        "packet",
        "byte_offset",
        DataClass::MetadataSensitive,
        Transform::Preserve,
        Transform::Preserve,
    ),
    rule(
        "packet",
        "captured_len",
        DataClass::MetadataSensitive,
        Transform::Preserve,
        Transform::Preserve,
    ),
    rule(
        "packet",
        "original_len",
        DataClass::MetadataSensitive,
        Transform::Preserve,
        Transform::Preserve,
    ),
    rule(
        "packet",
        "link_type",
        DataClass::MetadataSensitive,
        Transform::Preserve,
        Transform::Preserve,
    ),
    rule(
        "packet",
        "timestamp_resolution_ns",
        DataClass::MetadataSensitive,
        Transform::Preserve,
        Transform::Preserve,
    ),
    rule("packet", "opacity", DataClass::Public, Transform::Preserve, Transform::Preserve),
    rule("packet", "network_protocol", DataClass::Public, Transform::Preserve, Transform::Preserve),
    rule(
        "packet",
        "source_address",
        DataClass::ContentSensitive,
        Transform::Drop,
        Transform::Pseudonym,
    ),
    rule(
        "packet",
        "destination_address",
        DataClass::ContentSensitive,
        Transform::Drop,
        Transform::Pseudonym,
    ),
    rule(
        "packet",
        "transport_protocol",
        DataClass::Public,
        Transform::Preserve,
        Transform::Preserve,
    ),
    rule(
        "packet",
        "source_port",
        DataClass::MetadataSensitive,
        Transform::Preserve,
        Transform::Preserve,
    ),
    rule(
        "packet",
        "destination_port",
        DataClass::MetadataSensitive,
        Transform::Preserve,
        Transform::Preserve,
    ),
    rule("packet", "payload", DataClass::ContentSensitive, Transform::Drop, Transform::Pseudonym),
    rule(
        "passive_neighbor",
        "address",
        DataClass::ContentSensitive,
        Transform::Drop,
        Transform::Pseudonym,
    ),
    rule(
        "passive_neighbor",
        "link_layer_id",
        DataClass::ContentSensitive,
        Transform::Drop,
        Transform::Pseudonym,
    ),
    rule(
        "passive_neighbor",
        "interface",
        DataClass::ContentSensitive,
        Transform::Drop,
        Transform::Pseudonym,
    ),
    rule(
        "passive_neighbor",
        "state",
        DataClass::MetadataSensitive,
        Transform::Preserve,
        Transform::Preserve,
    ),
    rule("passive_neighbor", "trust", DataClass::Public, Transform::Preserve, Transform::Preserve),
    rule("passive_neighbor", "role", DataClass::Public, Transform::Preserve, Transform::Preserve),
    rule(
        "passive_neighbor",
        "limitations",
        DataClass::Public,
        Transform::Preserve,
        Transform::Preserve,
    ),
    rule(
        "passive_neighbor",
        "conflict",
        DataClass::MetadataSensitive,
        Transform::Preserve,
        Transform::Preserve,
    ),
    rule(
        "diagnostic",
        "message",
        DataClass::ContentSensitive,
        Transform::Drop,
        Transform::Pseudonym,
    ),
    rule(
        "process",
        "command_line",
        DataClass::ContentSensitive,
        Transform::Drop,
        Transform::Pseudonym,
    ),
    rule(
        "generic",
        "timestamp_ns",
        DataClass::MetadataSensitive,
        Transform::Preserve,
        Transform::Preserve,
    ),
];

/// Canonical normalized schema surface. Adding a field here without a rule fails the inventory gate.
pub const SOURCE_SCHEMA_FIELDS: &[(&str, &str)] = &[
    ("http", "method"),
    ("http", "status"),
    ("http", "size"),
    ("http", "url"),
    ("http", "authorization"),
    ("http", "cookie"),
    ("http", "headers"),
    ("http", "body"),
    ("filesystem", "path"),
    ("log", "message"),
    ("otel", "span_name"),
    ("otel", "resource"),
    ("otel", "baggage"),
    ("dns", "name"),
    ("packet", "capture_source"),
    ("packet", "section_index"),
    ("packet", "interface_id"),
    ("packet", "interface_name"),
    ("packet", "packet_ordinal"),
    ("packet", "byte_offset"),
    ("packet", "captured_len"),
    ("packet", "original_len"),
    ("packet", "link_type"),
    ("packet", "timestamp_resolution_ns"),
    ("packet", "opacity"),
    ("packet", "network_protocol"),
    ("packet", "source_address"),
    ("packet", "destination_address"),
    ("packet", "transport_protocol"),
    ("packet", "source_port"),
    ("packet", "destination_port"),
    ("packet", "payload"),
    ("passive_neighbor", "address"),
    ("passive_neighbor", "link_layer_id"),
    ("passive_neighbor", "interface"),
    ("passive_neighbor", "state"),
    ("passive_neighbor", "trust"),
    ("passive_neighbor", "role"),
    ("passive_neighbor", "limitations"),
    ("passive_neighbor", "conflict"),
    ("diagnostic", "message"),
    ("process", "command_line"),
    ("generic", "timestamp_ns"),
];

const fn rule(
    source: &'static str,
    field: &'static str,
    class: DataClass,
    metadata: Transform,
    redacted: Transform,
) -> FieldRule {
    FieldRule { source, field, class, metadata, redacted }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NativeField {
    pub source: String,
    pub field: String,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FieldPreview {
    pub source: String,
    pub field: String,
    pub class: DataClass,
    pub action: String,
    pub output: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct QuarantineRecord {
    pub source: String,
    pub field: String,
    pub reason: String,
    #[serde(skip_serializing)]
    pub native_value: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RedactionResult {
    pub fields: BTreeMap<String, String>,
    pub preview: Vec<FieldPreview>,
    pub quarantine: Vec<QuarantineRecord>,
}

pub fn redact(
    fields: &[NativeField],
    mode: PrivacyMode,
    scope_key: &[u8; 32],
) -> Result<RedactionResult, PrivacyError> {
    let mut output = BTreeMap::new();
    let mut preview = Vec::with_capacity(fields.len());
    let mut quarantine = Vec::new();
    for native in fields {
        let Some(rule) = FIELD_RULES
            .iter()
            .find(|rule| rule.source == native.source && rule.field == native.field)
        else {
            quarantine.push(QuarantineRecord {
                source: native.source.clone(),
                field: native.field.clone(),
                reason: "unknown_field_or_schema".into(),
                native_value: native.value.clone(),
            });
            preview.push(FieldPreview {
                source: native.source.clone(),
                field: native.field.clone(),
                class: DataClass::QuarantinedNative,
                action: "quarantine".into(),
                output: None,
            });
            continue;
        };
        let transform = match mode {
            PrivacyMode::Metadata => rule.metadata,
            PrivacyMode::Redacted => rule.redacted,
            PrivacyMode::Full if rule.class == DataClass::Credential => Transform::Drop,
            PrivacyMode::Full => Transform::Preserve,
        };
        let transformed = apply_transform(transform, &native.value, scope_key)?;
        let key = format!("{}.{}", native.source, native.field);
        if let Some(value) = transformed.as_ref() {
            output.insert(key, value.clone());
        }
        preview.push(FieldPreview {
            source: native.source.clone(),
            field: native.field.clone(),
            class: rule.class,
            action: transform_name(transform).into(),
            output: transformed,
        });
    }
    Ok(RedactionResult { fields: output, preview, quarantine })
}

fn apply_transform(
    transform: Transform,
    value: &str,
    scope_key: &[u8; 32],
) -> Result<Option<String>, PrivacyError> {
    Ok(match transform {
        Transform::Preserve => Some(value.into()),
        Transform::Drop => None,
        Transform::Pseudonym => Some(pseudonym(scope_key, value)?),
        Transform::StructuredUrl => Some(redact_url(value, scope_key)?),
    })
}

pub fn pseudonym(scope_key: &[u8; 32], value: &str) -> Result<String, PrivacyError> {
    let mut mac = HmacSha256::new_from_slice(scope_key).map_err(|_| PrivacyError::Crypto)?;
    mac.update(b"glassbox-pseudonym-v1\0");
    mac.update(value.as_bytes());
    let encoded = hex::encode(mac.finalize().into_bytes());
    Ok(format!("psn:{}", &encoded[..24]))
}

pub fn redact_url(raw: &str, scope_key: &[u8; 32]) -> Result<String, PrivacyError> {
    let url = Url::parse(raw).map_err(|_| PrivacyError::MalformedUrl)?;
    let scheme = url.scheme();
    let host = url.host_str().ok_or(PrivacyError::MalformedUrl)?;
    let host = pseudonym(scope_key, host)?;
    let port = url.port().map(|port| format!(":{port}")).unwrap_or_default();
    let query_keys: BTreeSet<_> = url.query_pairs().map(|(key, _)| key.into_owned()).collect();
    let query = if query_keys.is_empty() {
        String::new()
    } else {
        format!("?{}", query_keys.into_iter().collect::<Vec<_>>().join("&"))
    };
    Ok(format!("{scheme}://{host}{port}/[redacted]{query}"))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExportManifest {
    pub schema_version: String,
    pub authenticity: String,
    pub privacy_mode: PrivacyMode,
    pub redaction_policy_version: String,
    pub source_bundle_sha256: String,
    pub derivation_sha256: String,
    pub integrity_root_sha256: String,
    pub field_count: usize,
    pub quarantine_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DerivedExport {
    pub manifest: ExportManifest,
    pub fields: BTreeMap<String, String>,
    pub preview: Vec<FieldPreview>,
}

pub fn derive_export(
    source_bundle: &[u8],
    fields: &[NativeField],
    mode: PrivacyMode,
    export_scope_key: &[u8; 32],
) -> Result<DerivedExport, PrivacyError> {
    let result = redact(fields, mode, export_scope_key)?;
    let fields_json = serde_json::to_vec(&result.fields)?;
    let preview_json = serde_json::to_vec(&result.preview)?;
    let source_hash = digest(source_bundle);
    let integrity_root = digest(&fields_json);
    let mut derivation = Sha256::new();
    derivation.update(POLICY_VERSION.as_bytes());
    derivation.update(source_hash.as_bytes());
    derivation.update(&fields_json);
    derivation.update(&preview_json);
    let manifest = ExportManifest {
        schema_version: "glassbox-derived-export/v1".into(),
        authenticity: "unsigned_local".into(),
        privacy_mode: mode,
        redaction_policy_version: POLICY_VERSION.into(),
        source_bundle_sha256: source_hash,
        derivation_sha256: hex::encode(derivation.finalize()),
        integrity_root_sha256: integrity_root,
        field_count: result.fields.len(),
        quarantine_count: result.quarantine.len(),
    };
    Ok(DerivedExport { manifest, fields: result.fields, preview: result.preview })
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn transform_name(transform: Transform) -> &'static str {
    match transform {
        Transform::Preserve => "preserve",
        Transform::Pseudonym => "pseudonym",
        Transform::StructuredUrl => "structured_url",
        Transform::Drop => "drop",
    }
}

pub fn validate_inventory() -> Result<(), PrivacyError> {
    let mut keys = BTreeSet::new();
    for rule in FIELD_RULES {
        if !keys.insert((rule.source, rule.field)) {
            return Err(PrivacyError::DuplicateClassification(format!(
                "{}.{}",
                rule.source, rule.field
            )));
        }
        if rule.class == DataClass::Credential
            && (rule.metadata != Transform::Drop || rule.redacted != Transform::Drop)
        {
            return Err(PrivacyError::CredentialProjection(format!(
                "{}.{}",
                rule.source, rule.field
            )));
        }
    }
    let schemas: BTreeSet<_> = SOURCE_SCHEMA_FIELDS.iter().copied().collect();
    if keys != schemas {
        return Err(PrivacyError::IncompleteClassification);
    }
    Ok(())
}

pub fn classification_inventory() -> Vec<(&'static str, &'static str, DataClass)> {
    FIELD_RULES.iter().map(|rule| (rule.source, rule.field, rule.class)).collect()
}

#[derive(Debug, Error)]
pub enum PrivacyError {
    #[error("cryptographic operation failed")]
    Crypto,
    #[error("malformed URL")]
    MalformedUrl,
    #[error("duplicate classification for {0}")]
    DuplicateClassification(String),
    #[error("credential field has a normal projection: {0}")]
    CredentialProjection(String),
    #[error("classification inventory does not exactly cover the normalized schema")]
    IncompleteClassification,
    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventory_is_unique_and_credentials_fail_closed() {
        validate_inventory().unwrap();
    }

    #[test]
    fn packet_addresses_and_interface_identifiers_do_not_survive_metadata_mode() {
        let fields = [
            NativeField {
                source: "packet".into(),
                field: "source_address".into(),
                value: "192.0.2.10".into(),
            },
            NativeField {
                source: "packet".into(),
                field: "interface_name".into(),
                value: "work-vpn".into(),
            },
            NativeField {
                source: "packet".into(),
                field: "destination_port".into(),
                value: "443".into(),
            },
        ];
        let result = redact(&fields, PrivacyMode::Metadata, &[7; 32]).unwrap();
        assert!(!result.fields.contains_key("packet.source_address"));
        assert!(!result.fields.contains_key("packet.interface_name"));
        assert_eq!(result.fields.get("packet.destination_port").map(String::as_str), Some("443"));
    }

    #[test]
    fn passive_neighbor_identifiers_do_not_survive_metadata_mode() {
        let fields = [
            NativeField {
                source: "passive_neighbor".into(),
                field: "address".into(),
                value: "192.0.2.10".into(),
            },
            NativeField {
                source: "passive_neighbor".into(),
                field: "link_layer_id".into(),
                value: "aa:bb:cc:dd:ee:ff".into(),
            },
            NativeField {
                source: "passive_neighbor".into(),
                field: "role".into(),
                value: "logical_context_only".into(),
            },
        ];
        let result = redact(&fields, PrivacyMode::Metadata, &[8; 32]).unwrap();
        assert!(!result.fields.contains_key("passive_neighbor.address"));
        assert!(!result.fields.contains_key("passive_neighbor.link_layer_id"));
        assert_eq!(
            result.fields.get("passive_neighbor.role").map(String::as_str),
            Some("logical_context_only")
        );
    }

    #[test]
    fn url_removes_userinfo_fragment_values_path_and_host() {
        let output =
            redact_url("https://alice:secret@example.test/private/42?q=secret&z=2#frag", &[4; 32])
                .unwrap();
        assert!(output.starts_with("https://psn:"));
        assert!(output.ends_with("/[redacted]?q&z"));
        for forbidden in ["alice", "secret", "example.test", "private", "42", "frag", "=2"] {
            assert!(!output.contains(forbidden));
        }
    }

    #[test]
    fn pseudonyms_are_stable_only_inside_scope() {
        let first = pseudonym(&[1; 32], "low-entropy-id").unwrap();
        assert_eq!(first, pseudonym(&[1; 32], "low-entropy-id").unwrap());
        assert_ne!(first, pseudonym(&[2; 32], "low-entropy-id").unwrap());
    }

    #[test]
    fn unknown_fields_are_quarantined_and_never_exported() {
        let native = NativeField {
            source: "new-schema".into(),
            field: "surprise".into(),
            value: "SECRET".into(),
        };
        let result = redact(&[native], PrivacyMode::Redacted, &[8; 32]).unwrap();
        assert!(result.fields.is_empty());
        assert_eq!(result.quarantine.len(), 1);
        assert_eq!(result.preview[0].class, DataClass::QuarantinedNative);
        assert!(!serde_json::to_string(&result).unwrap().contains("SECRET"));
    }

    #[test]
    fn export_has_new_derivation_and_unsigned_authenticity() {
        let field =
            NativeField { source: "http".into(), field: "method".into(), value: "GET".into() };
        let export =
            derive_export(b"native bundle", &[field], PrivacyMode::Redacted, &[1; 32]).unwrap();
        assert_eq!(export.manifest.authenticity, "unsigned_local");
        assert_eq!(export.manifest.schema_version, "glassbox-derived-export/v1");
        assert_ne!(export.manifest.source_bundle_sha256, export.manifest.integrity_root_sha256);
    }

    #[test]
    fn full_mode_still_drops_credentials() {
        let field = NativeField {
            source: "http".into(),
            field: "authorization".into(),
            value: "Bearer never-export-this".into(),
        };
        let result = redact(&[field], PrivacyMode::Full, &[1; 32]).unwrap();
        assert!(result.fields.is_empty());
        assert_eq!(result.preview[0].action, "drop");
    }
}
