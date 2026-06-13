//! SQLite migrations, ingest, and normalization for DevTools Translator.

#![forbid(unsafe_code)]

use blake3::Hasher;
use dtt_core::{
    ArtifactProvenanceV1, ClaimTruth, ComplianceEvidenceItemV1, ComplianceEvidencePackV1,
    EvidenceKind, EvidenceRefV1, EvidenceTarget, ExportBlobDescriptorV1, ExportDatasetV1,
    ExportManifestV1, ExportProfileV1, ExportRunRecordV1, ExportRunStatusV1, ExtensionChannelV1,
    FixStepV1, HeaderMap, InteractionKindV1, InteractionMemberTypeV1, JsonEnvelope, NetTable,
    OtlpSinkConfigV1, PerfAnomalySeverityV1, PerfBudgetResultV1, PerfRunRecordV1, PerfRunStatusV1,
    RedactionLevel, ReleaseArtifactV1, ReleaseChannelV1, ReleaseHealthScorecardV1,
    ReleaseHealthSnapshotV1, ReleasePlatformV1, ReleaseRunRecordV1, ReleaseRunStatusV1,
    ReleaseVisibilityV1, ReliabilityMetricKeyV1, ReliabilityMetricSampleV1,
    ReliabilityWindowSummaryV1, RetentionPolicyV1, RetentionRunModeV1, RetentionRunReportV1,
    RolloutControllerActionV1, RolloutGateReasonV1, RolloutHealthStatusV1, RolloutStageV1,
    RolloutStatusV1, SessionDeleteResultV1, SigningStatusV1, StreamSummaryV1, TelemetryAuditRunV1,
    TelemetryAuditStatusV1, TelemetryExportRunV1, TelemetryModeV1, TrustedDeviceRecordV1,
    UiBundleInspectOpenResultV1, UiClaimV1, UiConnectionStatusV1, UiConsoleRowV1,
    UiDeleteSessionResultV1, UiDiagnosticEntryV1, UiDiagnosticsSnapshotV1,
    UiEvidenceResolveResultV1, UiExportCapabilityV1, UiExportListItemV1, UiExportModeV1,
    UiExtensionComplianceSnapshotV1, UiFindingCardV1, UiGetComplianceEvidencePackResultV1,
    UiListComplianceEvidencePacksItemV1, UiListExtensionRolloutsItemV1, UiListPerfAnomaliesItemV1,
    UiNetworkRowV1, UiPerfRunListItemV1, UiPerfTrendPointV1, UiReleaseListItemV1,
    UiReleasePromotionResultV1, UiReliabilitySeriesPointV1, UiReliabilitySnapshotV1,
    UiRetentionRunResultV1, UiRetentionSettingsV1, UiSessionListItemV1, UiSessionOverviewV1,
    UiSessionStatusV1, UiSigningSnapshotV1, UiStartExtensionPublicRolloutResultV1,
    UiStartPerfRunResultV1, UiTelemetrySettingsV1, UiTimelineBundleV1, UiTimelineEventV1,
    UiTimelineInteractionV1, UiTimelineKindV1, UpdateChannelV1, ENVELOPE_VERSION, EVT_RAW_EVENT,
};
use dtt_correlation::{
    correlate, CompletionCandidateInput, ConsoleCandidateInput, CorrelationConfig,
    CorrelationInput, CorrelationOutput, LifecycleCandidateInput, LlmWeightsV1,
    RawRequestHintInput, RequestCandidateInput, ResponseCandidateInput,
};
use dtt_detectors::DetectorRunReport;
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub mod normalization;

pub use normalization::NormalizationReport;

const SCHEMA_VERSION: &str = "1.0";
const RETENTION_POLICY_KEY: &str = "retention_policy.v1";
const EXPORT_ROOT_KEY: &str = "paths.exports_root";
const BLOB_ROOT_KEY: &str = "paths.blobs_root";
const PAIRING_CONTEXT_KEY: &str = "pairing.context.v2";

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("compression error: {0}")]
    Compression(#[from] std::io::Error),
    #[error("invalid envelope: {0}")]
    InvalidEnvelope(String),
    #[error("migration checksum mismatch for {migration_id}")]
    MigrationChecksumMismatch { migration_id: &'static str },
    #[error("detector error: {0}")]
    Detector(#[from] dtt_detectors::DetectorError),
    #[error("system clock is before unix epoch")]
    Clock,
}

pub type Result<T> = std::result::Result<T, StorageError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedRawEvent {
    pub session_id: String,
    pub event_id: String,
    pub event_seq: i64,
    pub payload_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelationReport {
    pub session_id: String,
    pub request_candidates_seen: usize,
    pub interactions_written: usize,
    pub interaction_members_written: usize,
    pub unassigned_candidates: usize,
    pub skipped_candidates: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AnalysisReport {
    pub session_id: String,
    pub detectors_considered: usize,
    pub detectors_ran: usize,
    pub findings_written: usize,
    pub claims_written: usize,
    pub evidence_refs_written: usize,
    pub skipped_detectors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ExportRunCompletedUpdate {
    pub zip_path: String,
    pub bundle_blake3: String,
    pub files_blake3_path: String,
    pub manifest: ExportManifestV1,
    pub file_count: usize,
    pub integrity_ok: bool,
    pub completed_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UpdateRolloutStartInput<'a> {
    pub channel: UpdateChannelV1,
    pub version: &'a str,
    pub stage: RolloutStageV1,
    pub rollout_pct: u8,
    pub feed_url: &'a str,
    pub signature_verified: bool,
    pub started_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PerfAnomalyInsertInput<'a> {
    pub run_kind: &'a str,
    pub bucket_start_ms: i64,
    pub metric_name: &'a str,
    pub severity: PerfAnomalySeverityV1,
    pub score: f64,
    pub baseline_value: f64,
    pub observed_value: f64,
    pub details_json: &'a Value,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RolloutStageTransitionInput<'a> {
    pub kind: &'a str,
    pub channel: &'a str,
    pub version: &'a str,
    pub from_stage: Option<RolloutStageV1>,
    pub to_stage: Option<RolloutStageV1>,
    pub action: RolloutControllerActionV1,
    pub decision_json: &'a Value,
    pub decided_at_ms: i64,
}

pub struct Storage {
    conn: Connection,
}

impl Storage {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path)?;
        Self::from_connection(conn)
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::from_connection(conn)
    }

    fn from_connection(conn: Connection) -> Result<Self> {
        conn.pragma_update(None, "foreign_keys", "ON")?;
        Ok(Self { conn })
    }

    pub fn apply_migrations(&mut self) -> Result<()> {
        self.bootstrap_migration_tables()?;

        for migration in MIGRATIONS {
            self.apply_migration(*migration)?;
        }

        self.conn.execute(
            "INSERT INTO schema_meta (id, current_version, min_compatible_version)
             VALUES (1, ?1, ?1)
             ON CONFLICT(id) DO UPDATE SET
               current_version = excluded.current_version,
               min_compatible_version = excluded.min_compatible_version",
            params![SCHEMA_VERSION],
        )?;

        Ok(())
    }

    pub fn ingest_raw_event_envelope(
        &mut self,
        envelope: &JsonEnvelope,
    ) -> Result<PersistedRawEvent> {
        if envelope.v != ENVELOPE_VERSION {
            return Err(StorageError::InvalidEnvelope("unsupported envelope version".to_string()));
        }

        if envelope.envelope_type != EVT_RAW_EVENT {
            return Err(StorageError::InvalidEnvelope("envelope is not evt.raw_event".to_string()));
        }

        let session_id =
            envelope.session_id.as_ref().filter(|id| !id.is_empty()).cloned().ok_or_else(|| {
                StorageError::InvalidEnvelope("session_id is required".to_string())
            })?;
        let event_seq = envelope
            .event_seq
            .ok_or_else(|| StorageError::InvalidEnvelope("event_seq is required".to_string()))?;
        let redaction_level = envelope
            .privacy_mode
            .ok_or_else(|| StorageError::InvalidEnvelope("privacy_mode is required".to_string()))?;

        let payload_object = envelope.payload.as_object().ok_or_else(|| {
            StorageError::InvalidEnvelope("payload must be an object".to_string())
        })?;

        let cdp_method = payload_object
            .get("cdp_method")
            .and_then(Value::as_str)
            .or_else(|| payload_object.get("method").and_then(Value::as_str))
            .ok_or_else(|| {
                StorageError::InvalidEnvelope("payload.cdp_method is required".to_string())
            })?
            .to_string();

        let raw_event =
            payload_object.get("raw_event").cloned().unwrap_or_else(|| envelope.payload.clone());
        let canonical_payload = canonical_json_bytes(&raw_event)?;

        let payload_hash = blake3_hash_hex(&canonical_payload);
        let payload_len = i64::try_from(canonical_payload.len())
            .map_err(|_| StorageError::InvalidEnvelope("payload is too large".to_string()))?;
        let payload_bytes = zstd::stream::encode_all(Cursor::new(&canonical_payload), 3)?;

        let event_id = payload_object
            .get("event_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| {
                derive_event_id(&session_id, event_seq, &cdp_method, envelope.ts_ms)
            });

        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO sessions (
                session_id,
                privacy_mode,
                capture_source,
                started_at_ms,
                created_at_ms,
                updated_at_ms
            ) VALUES (?1, ?2, 'extension_mv3', ?3, ?3, ?3)
            ON CONFLICT(session_id) DO UPDATE SET
              updated_at_ms = CASE
                WHEN excluded.updated_at_ms > sessions.updated_at_ms THEN excluded.updated_at_ms
                ELSE sessions.updated_at_ms
              END",
            params![session_id, redaction_level.as_str(), envelope.ts_ms],
        )?;

        let inserted = tx.execute(
            "INSERT INTO events_raw (
                event_id,
                session_id,
                event_seq,
                ts_ms,
                cdp_method,
                payload_encoding,
                payload_bytes,
                payload_hash,
                payload_len,
                redaction_level,
                created_at_ms
            ) VALUES (?1, ?2, ?3, ?4, ?5, 'zstd', ?6, ?7, ?8, ?9, ?10)
            ON CONFLICT(session_id, event_seq) DO NOTHING",
            params![
                event_id,
                session_id,
                event_seq,
                envelope.ts_ms,
                cdp_method,
                payload_bytes,
                payload_hash,
                payload_len,
                redaction_level.as_str(),
                envelope.ts_ms,
            ],
        )?;

        let persisted = if inserted == 0 {
            let Some((existing_event_id, existing_payload_hash)) = tx
                .query_row(
                    "SELECT event_id, payload_hash
                     FROM events_raw
                     WHERE session_id = ?1 AND event_seq = ?2
                     ORDER BY created_at_ms ASC, event_id ASC
                     LIMIT 1",
                    params![session_id, event_seq],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()?
            else {
                return Err(StorageError::InvalidEnvelope(
                    "duplicate event_seq without existing row".to_string(),
                ));
            };
            PersistedRawEvent {
                session_id: session_id.clone(),
                event_id: existing_event_id,
                event_seq,
                payload_hash: existing_payload_hash,
            }
        } else {
            PersistedRawEvent {
                session_id: session_id.clone(),
                event_id: event_id.clone(),
                event_seq,
                payload_hash: payload_hash.clone(),
            }
        };

        tx.commit()?;

        Ok(persisted)
    }

    pub fn begin_session(
        &mut self,
        session_id: &str,
        privacy_mode: RedactionLevel,
        started_at_ms: i64,
        capture_source: &str,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO sessions (
                session_id,
                privacy_mode,
                capture_source,
                started_at_ms,
                created_at_ms,
                updated_at_ms
            ) VALUES (?1, ?2, ?3, ?4, ?4, ?4)
            ON CONFLICT(session_id) DO UPDATE SET
                privacy_mode = excluded.privacy_mode,
                capture_source = excluded.capture_source,
                started_at_ms = CASE
                    WHEN sessions.started_at_ms <= excluded.started_at_ms
                    THEN sessions.started_at_ms
                    ELSE excluded.started_at_ms
                END,
                updated_at_ms = CASE
                    WHEN excluded.updated_at_ms > sessions.updated_at_ms
                    THEN excluded.updated_at_ms
                    ELSE sessions.updated_at_ms
                END",
            params![session_id, privacy_mode.as_str(), capture_source, started_at_ms],
        )?;
        Ok(())
    }

    pub fn end_session(&mut self, session_id: &str, ended_at_ms: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE sessions
             SET ended_at_ms = CASE
                    WHEN ended_at_ms IS NULL THEN ?2
                    WHEN ended_at_ms < ?2 THEN ?2
                    ELSE ended_at_ms
                 END,
                 updated_at_ms = CASE
                    WHEN updated_at_ms < ?2 THEN ?2
                    ELSE updated_at_ms
                 END
             WHERE session_id = ?1",
            params![session_id, ended_at_ms],
        )?;
        Ok(())
    }

    pub fn normalize_session(&mut self, session_id: &str) -> Result<NormalizationReport> {
        normalization::normalize_session(&mut self.conn, session_id)
    }

    pub fn correlate_session(&mut self, session_id: &str) -> Result<CorrelationReport> {
        let input = load_correlation_input(&self.conn, session_id)?;
        let config = load_correlation_config()?;
        let output = correlate(input, config);
        validate_primary_members(&output)?;
        persist_correlation_output(&mut self.conn, session_id, &output)?;

        Ok(CorrelationReport {
            session_id: session_id.to_string(),
            request_candidates_seen: output.request_candidates_seen,
            interactions_written: output.interactions.len(),
            interaction_members_written: output.members.len(),
            unassigned_candidates: output.unassigned_candidates,
            skipped_candidates: output.skipped_candidates,
        })
    }

    pub fn analyze_session(&mut self, session_id: &str) -> Result<AnalysisReport> {
        let run_report = dtt_detectors::analyze_session(&self.conn, session_id)?;
        let (findings_written, claims_written, evidence_refs_written) =
            persist_detector_output(&mut self.conn, session_id, &run_report)?;

        Ok(AnalysisReport {
            session_id: session_id.to_string(),
            detectors_considered: run_report.detectors_considered,
            detectors_ran: run_report.detectors_ran,
            findings_written,
            claims_written,
            evidence_refs_written,
            skipped_detectors: run_report.skipped_detectors,
        })
    }

    pub fn list_sessions_ui(&self, limit: usize) -> Result<Vec<UiSessionListItemV1>> {
        let limit = i64::try_from(limit).map_err(|_| {
            StorageError::InvalidEnvelope("session list limit overflow".to_string())
        })?;
        let mut stmt = self.conn.prepare(
            "SELECT
                s.session_id,
                s.privacy_mode,
                s.capture_source,
                s.started_at_ms,
                s.ended_at_ms,
                CAST(COUNT(f.finding_id) AS INTEGER) AS findings_count
             FROM sessions s
             LEFT JOIN findings f ON f.session_id = s.session_id
             GROUP BY s.session_id
             ORDER BY s.started_at_ms DESC, s.session_id ASC
             LIMIT ?1",
        )?;

        let rows = stmt.query_map(params![limit], |row| {
            let started_at_ms: i64 = row.get(3)?;
            let ended_at_ms: Option<i64> = row.get(4)?;
            let findings_count: i64 = row.get(5)?;
            let status = if ended_at_ms.is_some() {
                UiSessionStatusV1::Completed
            } else {
                UiSessionStatusV1::Running
            };
            Ok(UiSessionListItemV1 {
                session_id: row.get(0)?,
                privacy_mode: parse_redaction_level(&row.get::<_, String>(1)?).map_err(
                    |error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            1,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    },
                )?,
                capture_source: row.get(2)?,
                started_at_ms,
                ended_at_ms,
                duration_ms: ended_at_ms.map(|end| (end - started_at_ms).max(0)),
                findings_count: u32::try_from(findings_count.max(0)).unwrap_or(u32::MAX),
                status,
            })
        })?;

        let mut output = Vec::new();
        for row in rows {
            output.push(row?);
        }
        Ok(output)
    }

    pub fn get_session_overview_ui(&self, session_id: &str) -> Result<Option<UiSessionOverviewV1>> {
        let Some(session) =
            self.list_sessions_ui(10_000)?.into_iter().find(|s| s.session_id == session_id)
        else {
            return Ok(None);
        };

        let interactions_count = count_by_session(&self.conn, "interactions", session_id)?;
        let network_requests_count = count_by_session(&self.conn, "network_requests", session_id)?;
        let network_responses_count =
            count_by_session(&self.conn, "network_responses", session_id)?;
        let network_completion_count =
            count_by_session(&self.conn, "network_completion", session_id)?;
        let console_entries_count = count_by_session(&self.conn, "console_entries", session_id)?;
        let findings = self.list_findings_ui(Some(session_id), 5)?;

        Ok(Some(UiSessionOverviewV1 {
            findings_count: session.findings_count,
            session,
            interactions_count,
            network_requests_count,
            network_responses_count,
            network_completion_count,
            console_entries_count,
            top_findings: findings,
        }))
    }

    pub fn list_timeline_ui(&self, session_id: &str) -> Result<UiTimelineBundleV1> {
        let mut interactions: Vec<UiTimelineInteractionV1> = Vec::new();
        {
            let mut stmt = self.conn.prepare(
                "SELECT i.interaction_id, i.interaction_kind, i.opened_at_ms, i.closed_at_ms, i.primary_member_id,
                        CAST(COUNT(im.member_id) AS INTEGER) AS members_count
                 FROM interactions i
                 LEFT JOIN interaction_members im ON im.interaction_id = i.interaction_id
                 WHERE i.session_id = ?1
                 GROUP BY i.interaction_id
                 ORDER BY i.opened_at_ms ASC, i.interaction_kind ASC, i.interaction_id ASC",
            )?;
            let rows = stmt.query_map(params![session_id], |row| {
                let kind: String = row.get(1)?;
                Ok(UiTimelineInteractionV1 {
                    interaction_id: row.get(0)?,
                    interaction_kind: parse_interaction_kind(&kind).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            1,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?,
                    opened_at_ms: row.get(2)?,
                    closed_at_ms: row.get(3)?,
                    primary_member_id: row.get(4)?,
                    members_count: u32::try_from(row.get::<_, i64>(5)?.max(0)).unwrap_or(u32::MAX),
                })
            })?;
            for row in rows {
                interactions.push(row?);
            }
        }

        let mut events: Vec<UiTimelineEventV1> = Vec::new();
        {
            let mut raw_stmt = self.conn.prepare(
                "SELECT event_id, ts_ms, cdp_method
                 FROM events_raw
                 WHERE session_id = ?1
                 ORDER BY ts_ms ASC, cdp_method ASC, event_id ASC",
            )?;
            let raw_rows = raw_stmt.query_map(params![session_id], |row| {
                let event_id: String = row.get(0)?;
                let method: String = row.get(2)?;
                Ok(UiTimelineEventV1 {
                    stable_id: format!("raw:{event_id}"),
                    ts_ms: row.get(1)?,
                    kind: UiTimelineKindV1::RawEvent,
                    label: method.clone(),
                    source_id: event_id,
                })
            })?;
            for row in raw_rows {
                events.push(row?);
            }
        }
        {
            let mut console_stmt = self.conn.prepare(
                "SELECT console_id, ts_ms, COALESCE(level, 'log')
                 FROM console_entries
                 WHERE session_id = ?1
                 ORDER BY ts_ms ASC, console_id ASC",
            )?;
            let console_rows = console_stmt.query_map(params![session_id], |row| {
                let console_id: String = row.get(0)?;
                let level: String = row.get(2)?;
                Ok(UiTimelineEventV1 {
                    stable_id: format!("console:{console_id}"),
                    ts_ms: row.get(1)?,
                    kind: UiTimelineKindV1::ConsoleEntry,
                    label: level,
                    source_id: console_id,
                })
            })?;
            for row in console_rows {
                events.push(row?);
            }
        }
        {
            let mut lifecycle_stmt = self.conn.prepare(
                "SELECT lifecycle_id, ts_ms, COALESCE(name, 'page_event')
                 FROM page_lifecycle
                 WHERE session_id = ?1
                 ORDER BY ts_ms ASC, lifecycle_id ASC",
            )?;
            let lifecycle_rows = lifecycle_stmt.query_map(params![session_id], |row| {
                let lifecycle_id: String = row.get(0)?;
                let name: String = row.get(2)?;
                Ok(UiTimelineEventV1 {
                    stable_id: format!("lifecycle:{lifecycle_id}"),
                    ts_ms: row.get(1)?,
                    kind: UiTimelineKindV1::PageLifecycle,
                    label: name,
                    source_id: lifecycle_id,
                })
            })?;
            for row in lifecycle_rows {
                events.push(row?);
            }
        }

        events.sort_by(|left, right| {
            left.ts_ms
                .cmp(&right.ts_ms)
                .then(timeline_kind_rank(left.kind).cmp(&timeline_kind_rank(right.kind)))
                .then(left.stable_id.cmp(&right.stable_id))
        });

        Ok(UiTimelineBundleV1 { interactions, events })
    }

    pub fn list_network_ui(&self, session_id: &str) -> Result<Vec<UiNetworkRowV1>> {
        let mut stmt = self.conn.prepare(
            "SELECT
                req.net_request_id,
                req.started_at_ms,
                req.method,
                req.host,
                req.path,
                resp.status_code,
                comp.duration_ms,
                resp.mime_type,
                resp.stream_summary_json,
                req.redaction_level
             FROM network_requests req
             LEFT JOIN network_responses resp ON resp.net_request_id = req.net_request_id
             LEFT JOIN network_completion comp ON comp.net_request_id = req.net_request_id
             WHERE req.session_id = ?1
             ORDER BY req.started_at_ms ASC, req.net_request_id ASC",
        )?;
        let rows = stmt.query_map(params![session_id], |row| {
            let stream_summary_json: Option<String> = row.get(8)?;
            let is_streaming = stream_summary_json
                .as_deref()
                .and_then(|json| serde_json::from_str::<StreamSummaryV1>(json).ok())
                .map(|summary| summary.is_streaming)
                .unwrap_or(false);
            Ok(UiNetworkRowV1 {
                net_request_id: row.get(0)?,
                started_at_ms: row.get(1)?,
                method: row.get(2)?,
                host: row.get(3)?,
                path: row.get(4)?,
                status_code: row.get(5)?,
                duration_ms: row.get(6)?,
                mime_type: row.get(7)?,
                is_streaming,
                redaction_level: parse_redaction_level(
                    &row.get::<_, Option<String>>(9)?
                        .unwrap_or_else(|| RedactionLevel::MetadataOnly.as_str().to_string()),
                )
                .map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        9,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?,
            })
        })?;
        let mut output = Vec::new();
        for row in rows {
            output.push(row?);
        }
        Ok(output)
    }

    pub fn list_console_ui(&self, session_id: &str) -> Result<Vec<UiConsoleRowV1>> {
        let mut stmt = self.conn.prepare(
            "SELECT console_id, ts_ms, level, source, message_redacted, message_len
             FROM console_entries
             WHERE session_id = ?1
             ORDER BY ts_ms ASC, console_id ASC",
        )?;
        let rows = stmt.query_map(params![session_id], |row| {
            Ok(UiConsoleRowV1 {
                console_id: row.get(0)?,
                ts_ms: row.get(1)?,
                level: row.get(2)?,
                source: row.get(3)?,
                message_redacted: row.get(4)?,
                message_len: row.get(5)?,
            })
        })?;
        let mut output = Vec::new();
        for row in rows {
            output.push(row?);
        }
        Ok(output)
    }

    pub fn list_findings_ui(
        &self,
        session_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<UiFindingCardV1>> {
        let limit = i64::try_from(limit).map_err(|_| {
            StorageError::InvalidEnvelope("finding list limit overflow".to_string())
        })?;
        match session_id {
            Some(session_id) => self.load_findings_rows(
                "SELECT finding_id, session_id, detector_id, detector_version, title, summary, category,
                        severity_score, confidence_score, created_at_ms, interaction_id, fix_steps_json
                 FROM findings
                 WHERE session_id = ?1
                 ORDER BY severity_score DESC, detector_id ASC, finding_id ASC
                 LIMIT ?2",
                params![session_id, limit],
            ),
            None => self.load_findings_rows(
                "SELECT finding_id, session_id, detector_id, detector_version, title, summary, category,
                        severity_score, confidence_score, created_at_ms, interaction_id, fix_steps_json
                 FROM findings
                 ORDER BY severity_score DESC, detector_id ASC, finding_id ASC
                 LIMIT ?1",
                params![limit],
            ),
        }
    }

    pub fn list_exports_ui(&self, session_id: &str) -> Result<UiExportCapabilityV1> {
        let privacy_mode = self
            .conn
            .query_row(
                "SELECT privacy_mode FROM sessions WHERE session_id = ?1",
                params![session_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten()
            .unwrap_or_else(|| RedactionLevel::MetadataOnly.as_str().to_string());
        let full_export_allowed = privacy_mode != RedactionLevel::MetadataOnly.as_str();
        let full_export_block_reason = if full_export_allowed {
            None
        } else {
            Some("Full export is blocked for metadata_only sessions.".to_string())
        };

        Ok(UiExportCapabilityV1 {
            session_id: session_id.to_string(),
            default_mode: UiExportModeV1::ShareSafe,
            full_export_allowed,
            full_export_block_reason,
            phase8_ready: true,
        })
    }

    pub fn list_exports_runs_ui(
        &self,
        session_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<UiExportListItemV1>> {
        let limit = i64::try_from(limit)
            .map_err(|_| StorageError::InvalidEnvelope("export list limit overflow".to_string()))?;
        let mut output = Vec::new();
        let (sql, bind_session): (&str, Option<&str>) = if session_id.is_some() {
            (
                "SELECT export_id, session_id, export_profile, status, zip_path, created_at_ms,
                        completed_at_ms, integrity_ok, bundle_blake3, error_code, error_message
                 FROM exports_runs
                 WHERE session_id = ?1
                 ORDER BY created_at_ms DESC, export_id ASC
                 LIMIT ?2",
                session_id,
            )
        } else {
            (
                "SELECT export_id, session_id, export_profile, status, zip_path, created_at_ms,
                        completed_at_ms, integrity_ok, bundle_blake3, error_code, error_message
                 FROM exports_runs
                 ORDER BY created_at_ms DESC, export_id ASC
                 LIMIT ?1",
                None,
            )
        };

        let mut stmt = self.conn.prepare(sql)?;
        if let Some(session_id) = bind_session {
            let rows = stmt.query_map(params![session_id, limit], |row| {
                let integrity_raw: Option<i64> = row.get(7)?;
                Ok(UiExportListItemV1 {
                    export_id: row.get(0)?,
                    session_id: row.get(1)?,
                    profile: parse_export_profile(row.get::<_, String>(2)?.as_str())?,
                    status: parse_export_status(row.get::<_, String>(3)?.as_str())?,
                    zip_path: row.get(4)?,
                    created_at_ms: row.get(5)?,
                    completed_at_ms: row.get(6)?,
                    integrity_ok: parse_optional_bool(integrity_raw),
                    bundle_blake3: row.get(8)?,
                    error_code: row.get(9)?,
                    error_message: row.get(10)?,
                })
            })?;
            for row in rows {
                output.push(row?);
            }
        } else {
            let rows = stmt.query_map(params![limit], |row| {
                let integrity_raw: Option<i64> = row.get(7)?;
                Ok(UiExportListItemV1 {
                    export_id: row.get(0)?,
                    session_id: row.get(1)?,
                    profile: parse_export_profile(row.get::<_, String>(2)?.as_str())?,
                    status: parse_export_status(row.get::<_, String>(3)?.as_str())?,
                    zip_path: row.get(4)?,
                    created_at_ms: row.get(5)?,
                    completed_at_ms: row.get(6)?,
                    integrity_ok: parse_optional_bool(integrity_raw),
                    bundle_blake3: row.get(8)?,
                    error_code: row.get(9)?,
                    error_message: row.get(10)?,
                })
            })?;
            for row in rows {
                output.push(row?);
            }
        }

        Ok(output)
    }

    pub fn get_export_run_ui(&self, export_id: &str) -> Result<Option<ExportRunRecordV1>> {
        self.conn
            .query_row(
                "SELECT export_id, session_id, status, export_profile, zip_path, created_at_ms,
                        completed_at_ms, integrity_ok, bundle_blake3, error_code, error_message
                 FROM exports_runs
                 WHERE export_id = ?1",
                params![export_id],
                |row| {
                    let integrity_raw: Option<i64> = row.get(7)?;
                    Ok(ExportRunRecordV1 {
                        export_id: row.get(0)?,
                        session_id: row.get(1)?,
                        status: parse_export_status(row.get::<_, String>(2)?.as_str())?,
                        profile: parse_export_profile(row.get::<_, String>(3)?.as_str())?,
                        zip_path: row.get(4)?,
                        created_at_ms: row.get(5)?,
                        completed_at_ms: row.get(6)?,
                        integrity_ok: parse_optional_bool(integrity_raw),
                        bundle_blake3: row.get(8)?,
                        error_code: row.get(9)?,
                        error_message: row.get(10)?,
                    })
                },
            )
            .optional()
            .map_err(StorageError::from)
    }

    pub fn insert_export_run_start(
        &self,
        session_id: &str,
        profile: ExportProfileV1,
        output_dir: &str,
    ) -> Result<ExportRunRecordV1> {
        let privacy_mode = self
            .conn
            .query_row(
                "SELECT privacy_mode FROM sessions WHERE session_id = ?1",
                params![session_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten()
            .ok_or_else(|| StorageError::InvalidEnvelope("session not found".to_string()))?;
        let created_at_ms = now_unix_ms()?;
        let export_id = format!(
            "exp_{}",
            blake3_hash_hex(
                format!("{session_id}:{}:{created_at_ms}", profile.as_str()).as_bytes()
            )
        );
        self.conn.execute(
            "INSERT INTO exports_runs (
                export_id, session_id, export_profile, privacy_mode, status, output_dir, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                export_id,
                session_id,
                profile.as_str(),
                privacy_mode,
                ExportRunStatusV1::Running.as_str(),
                output_dir,
                created_at_ms
            ],
        )?;
        Ok(ExportRunRecordV1 {
            export_id,
            session_id: session_id.to_string(),
            status: ExportRunStatusV1::Running,
            profile,
            zip_path: None,
            created_at_ms,
            completed_at_ms: None,
            integrity_ok: None,
            bundle_blake3: None,
            error_code: None,
            error_message: None,
        })
    }

    pub fn mark_export_run_completed(
        &self,
        export_id: &str,
        update: &ExportRunCompletedUpdate,
    ) -> Result<()> {
        let manifest_json = canonical_json_string(&update.manifest)?;
        let integrity_ok_db = if update.integrity_ok { 1_i64 } else { 0_i64 };
        self.conn.execute(
            "UPDATE exports_runs
             SET status = ?2,
                 zip_path = ?3,
                 integrity_ok = ?4,
                 bundle_blake3 = ?5,
                 files_blake3_path = ?6,
                 manifest_json = ?7,
                 file_count = ?8,
                 completed_at_ms = ?9,
                 error_code = NULL,
                 error_message = NULL
             WHERE export_id = ?1",
            params![
                export_id,
                ExportRunStatusV1::Completed.as_str(),
                update.zip_path,
                integrity_ok_db,
                update.bundle_blake3,
                update.files_blake3_path,
                manifest_json,
                i64::try_from(update.file_count).map_err(|_| {
                    StorageError::InvalidEnvelope("export file_count overflow".to_string())
                })?,
                update.completed_at_ms
            ],
        )?;
        Ok(())
    }

    pub fn mark_export_run_failed(
        &self,
        export_id: &str,
        status: ExportRunStatusV1,
        error_code: &str,
        error_message: &str,
        completed_at_ms: i64,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE exports_runs
             SET status = ?2,
                 completed_at_ms = ?3,
                 error_code = ?4,
                 error_message = ?5
             WHERE export_id = ?1",
            params![export_id, status.as_str(), completed_at_ms, error_code, error_message],
        )?;
        Ok(())
    }

    pub fn insert_release_run_start(
        &self,
        channel: ReleaseChannelV1,
        version: &str,
        commit_sha: &str,
        notes_md: Option<&str>,
    ) -> Result<ReleaseRunRecordV1> {
        let started_at_ms = now_unix_ms()?;
        let run_id = format!(
            "rel_{}",
            blake3_hash_hex(
                format!(
                    "{version}:{commit_sha}:{}:{started_at_ms}",
                    release_channel_as_str(channel)
                )
                .as_bytes(),
            )
        );
        let empty_artifacts = canonical_json_string(&Vec::<ReleaseArtifactV1>::new())?;
        self.conn.execute(
            "INSERT INTO release_runs (
                run_id, channel, version, commit_sha, status, artifacts_json, notes_md,
                started_at_ms, platform_matrix_json, artifact_count
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                run_id,
                release_channel_as_str(channel),
                version,
                commit_sha,
                release_status_as_str(ReleaseRunStatusV1::Running),
                empty_artifacts,
                notes_md,
                started_at_ms,
                "[]",
                0_i64
            ],
        )?;

        Ok(ReleaseRunRecordV1 {
            run_id,
            channel,
            version: version.to_string(),
            commit_sha: commit_sha.to_string(),
            status: ReleaseRunStatusV1::Running,
            artifacts: Vec::new(),
            started_at_ms,
            completed_at_ms: None,
            error_code: None,
            error_message: None,
        })
    }

    pub fn mark_release_run_completed(
        &self,
        run_id: &str,
        artifacts: &[ReleaseArtifactV1],
        completed_at_ms: i64,
    ) -> Result<()> {
        let artifacts_json = canonical_json_string(&artifacts)?;
        let platform_matrix_json = canonical_json_string(&release_platform_matrix(artifacts))?;
        let artifact_count = i64::try_from(artifacts.len()).unwrap_or(i64::MAX);
        self.conn.execute(
            "UPDATE release_runs
             SET status = ?2,
                 artifacts_json = ?3,
                 completed_at_ms = ?4,
                 platform_matrix_json = ?5,
                 artifact_count = ?6,
                 error_code = NULL,
                 error_message = NULL
             WHERE run_id = ?1",
            params![
                run_id,
                release_status_as_str(ReleaseRunStatusV1::Completed),
                artifacts_json,
                completed_at_ms,
                platform_matrix_json,
                artifact_count
            ],
        )?;
        Ok(())
    }

    pub fn mark_release_run_failed(
        &self,
        run_id: &str,
        error_code: &str,
        error_message: &str,
        completed_at_ms: i64,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE release_runs
             SET status = ?2,
                 completed_at_ms = ?3,
                 error_code = ?4,
                 error_message = ?5
             WHERE run_id = ?1",
            params![
                run_id,
                release_status_as_str(ReleaseRunStatusV1::Failed),
                completed_at_ms,
                error_code,
                error_message
            ],
        )?;
        Ok(())
    }

    pub fn list_release_runs_ui(&self, limit: usize) -> Result<Vec<UiReleaseListItemV1>> {
        let limit = i64::try_from(limit).map_err(|_| {
            StorageError::InvalidEnvelope("release list limit overflow".to_string())
        })?;
        let mut stmt = self.conn.prepare(
            "SELECT run_id, channel, version, commit_sha, status, artifacts_json, started_at_ms,
                    completed_at_ms, error_code, error_message
             FROM release_runs
             ORDER BY started_at_ms DESC, run_id ASC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |row| {
            let artifacts_raw: String = row.get(5)?;
            let artifacts = serde_json::from_str::<Vec<ReleaseArtifactV1>>(&artifacts_raw)
                .map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        5,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?;
            Ok(UiReleaseListItemV1 {
                run_id: row.get(0)?,
                channel: parse_release_channel(row.get::<_, String>(1)?.as_str())?,
                version: row.get(2)?,
                commit_sha: row.get(3)?,
                status: parse_release_status(row.get::<_, String>(4)?.as_str())?,
                artifacts,
                started_at_ms: row.get(6)?,
                completed_at_ms: row.get(7)?,
                error_code: row.get(8)?,
                error_message: row.get(9)?,
            })
        })?;
        let mut output = Vec::new();
        for row in rows {
            output.push(row?);
        }
        Ok(output)
    }

    pub fn get_release_run_ui(&self, run_id: &str) -> Result<Option<UiReleaseListItemV1>> {
        let mut runs = self.list_release_runs_ui(500)?;
        runs.retain(|run| run.run_id == run_id);
        Ok(runs.into_iter().next())
    }

    pub fn list_release_artifacts_by_platform(
        &self,
        platform: ReleasePlatformV1,
        limit_runs: usize,
    ) -> Result<Vec<ReleaseArtifactV1>> {
        let runs = self.list_release_runs_ui(limit_runs)?;
        let mut artifacts = Vec::new();
        for run in runs {
            for artifact in run.artifacts {
                if artifact.platform == platform {
                    artifacts.push(artifact);
                }
            }
        }
        artifacts.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(artifacts)
    }

    pub fn insert_release_promotion_start(
        &self,
        run_id: &str,
        channel: ReleaseChannelV1,
        visibility: ReleaseVisibilityV1,
        provenance: &ArtifactProvenanceV1,
        started_at_ms: i64,
    ) -> Result<UiReleasePromotionResultV1> {
        let provenance_json = canonical_json_string(provenance)?;
        let promotion_id =
            format!("prm_{}", blake3_hash_hex(format!("{run_id}:{started_at_ms}").as_bytes()));
        self.conn.execute(
            "INSERT INTO release_promotions (
                promotion_id, run_id, channel, visibility, status, provenance_json, started_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                promotion_id,
                run_id,
                release_channel_as_str(channel),
                release_visibility_as_str(visibility),
                release_status_as_str(ReleaseRunStatusV1::Running),
                provenance_json,
                started_at_ms
            ],
        )?;
        Ok(UiReleasePromotionResultV1 {
            promotion_id,
            channel,
            visibility,
            status: ReleaseRunStatusV1::Running,
            provenance: provenance.clone(),
            error_message: None,
        })
    }

    pub fn mark_release_promotion_completed(
        &self,
        promotion_id: &str,
        provenance: &ArtifactProvenanceV1,
        completed_at_ms: i64,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE release_promotions
             SET status = ?2,
                 provenance_json = ?3,
                 completed_at_ms = ?4,
                 error_code = NULL,
                 error_message = NULL
             WHERE promotion_id = ?1",
            params![
                promotion_id,
                release_status_as_str(ReleaseRunStatusV1::Completed),
                canonical_json_string(provenance)?,
                completed_at_ms
            ],
        )?;
        Ok(())
    }

    pub fn mark_release_promotion_failed(
        &self,
        promotion_id: &str,
        error_code: &str,
        error_message: &str,
        completed_at_ms: i64,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE release_promotions
             SET status = ?2,
                 completed_at_ms = ?3,
                 error_code = ?4,
                 error_message = ?5
             WHERE promotion_id = ?1",
            params![
                promotion_id,
                release_status_as_str(ReleaseRunStatusV1::Failed),
                completed_at_ms,
                error_code,
                error_message
            ],
        )?;
        Ok(())
    }

    pub fn list_release_promotions(&self, limit: usize) -> Result<Vec<UiReleasePromotionResultV1>> {
        let limit = i64::try_from(limit).map_err(|_| {
            StorageError::InvalidEnvelope("release promotion list limit overflow".to_string())
        })?;
        let mut stmt = self.conn.prepare(
            "SELECT promotion_id, channel, visibility, status, provenance_json, error_message
             FROM release_promotions
             ORDER BY started_at_ms DESC, promotion_id ASC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |row| {
            let provenance_raw: String = row.get(4)?;
            let provenance = serde_json::from_str::<ArtifactProvenanceV1>(&provenance_raw)
                .map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        4,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?;
            Ok(UiReleasePromotionResultV1 {
                promotion_id: row.get(0)?,
                channel: parse_release_channel(row.get::<_, String>(1)?.as_str())?,
                visibility: parse_release_visibility(row.get::<_, String>(2)?.as_str())?,
                status: parse_release_status(row.get::<_, String>(3)?.as_str())?,
                provenance,
                error_message: row.get(5)?,
            })
        })?;
        let mut output = Vec::new();
        for row in rows {
            output.push(row?);
        }
        Ok(output)
    }

    pub fn get_signing_snapshot(
        &self,
        run_id: &str,
        manual_smoke_ready: bool,
    ) -> Result<Option<UiSigningSnapshotV1>> {
        let Some(run) = self.get_release_run_ui(run_id)? else {
            return Ok(None);
        };

        let mut blocking_reasons = Vec::new();
        if !manual_smoke_ready {
            blocking_reasons.push("manual_smoke_missing".to_string());
        }
        if run.status != ReleaseRunStatusV1::Completed {
            blocking_reasons.push("release_run_not_completed".to_string());
        }
        if run.artifacts.is_empty() {
            blocking_reasons.push("release_artifacts_missing".to_string());
        }

        let mut signing_status = SigningStatusV1::Verified;
        let mut notarization_status = SigningStatusV1::Verified;
        for artifact in &run.artifacts {
            if artifact.sha256 == "dry_run" {
                signing_status = SigningStatusV1::Pending;
                notarization_status = SigningStatusV1::Pending;
                break;
            }
            if artifact.sha256.trim().is_empty() {
                signing_status = SigningStatusV1::Failed;
                notarization_status = SigningStatusV1::Failed;
                break;
            }
        }
        if !blocking_reasons.is_empty() && signing_status == SigningStatusV1::Verified {
            signing_status = SigningStatusV1::Pending;
        }

        Ok(Some(UiSigningSnapshotV1 {
            run_id: run.run_id,
            channel: run.channel,
            visibility: if run.channel == ReleaseChannelV1::StagedPublicPrerelease {
                ReleaseVisibilityV1::StagedPublic
            } else {
                ReleaseVisibilityV1::Internal
            },
            artifact_count: u32::try_from(run.artifacts.len()).unwrap_or(u32::MAX),
            signing_status,
            notarization_status,
            manual_smoke_ready,
            blocking_reasons,
        }))
    }

    pub fn insert_extension_rollout_start(
        &self,
        channel: ExtensionChannelV1,
        version: &str,
        stage: RolloutStageV1,
        cws_item_id: Option<&str>,
        notes_md: Option<&str>,
        started_at_ms: i64,
    ) -> Result<UiStartExtensionPublicRolloutResultV1> {
        let sig = format!(
            "{}:{version}:{}:{started_at_ms}",
            extension_channel_as_str(channel),
            rollout_stage_as_str(stage)
        );
        let rollout_id = format!("ext_{}", blake3_hash_hex(sig.as_bytes()));
        self.conn.execute(
            "INSERT INTO extension_rollouts (
                rollout_id, channel, version, stage, status, cws_item_id, notes_md, started_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                rollout_id,
                extension_channel_as_str(channel),
                version,
                rollout_stage_as_str(stage),
                rollout_status_as_str(RolloutStatusV1::Active),
                cws_item_id,
                notes_md,
                started_at_ms
            ],
        )?;
        Ok(UiStartExtensionPublicRolloutResultV1 {
            rollout_id,
            channel,
            version: version.to_string(),
            stage,
            status: RolloutStatusV1::Active,
            cws_item_id: cws_item_id.map(ToOwned::to_owned),
            error_message: None,
        })
    }

    pub fn mark_extension_rollout_completed(
        &self,
        rollout_id: &str,
        completed_at_ms: i64,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE extension_rollouts
             SET status = ?2,
                 completed_at_ms = ?3,
                 error_code = NULL,
                 error_message = NULL
             WHERE rollout_id = ?1",
            params![rollout_id, rollout_status_as_str(RolloutStatusV1::Completed), completed_at_ms],
        )?;
        Ok(())
    }

    pub fn mark_extension_rollout_failed(
        &self,
        rollout_id: &str,
        error_code: &str,
        error_message: &str,
        completed_at_ms: i64,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE extension_rollouts
             SET status = ?2,
                 completed_at_ms = ?3,
                 error_code = ?4,
                 error_message = ?5
             WHERE rollout_id = ?1",
            params![
                rollout_id,
                rollout_status_as_str(RolloutStatusV1::Failed),
                completed_at_ms,
                error_code,
                error_message
            ],
        )?;
        Ok(())
    }

    pub fn list_extension_rollouts(
        &self,
        limit: usize,
    ) -> Result<Vec<UiListExtensionRolloutsItemV1>> {
        let limit = i64::try_from(limit).map_err(|_| {
            StorageError::InvalidEnvelope("extension rollout list limit overflow".to_string())
        })?;
        let mut stmt = self.conn.prepare(
            "SELECT rollout_id, channel, version, stage, status, cws_item_id, started_at_ms,
                    completed_at_ms, error_code, error_message
             FROM extension_rollouts
             ORDER BY started_at_ms DESC, rollout_id ASC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |row| {
            Ok(UiListExtensionRolloutsItemV1 {
                rollout_id: row.get(0)?,
                channel: parse_extension_channel(row.get::<_, String>(1)?.as_str())?,
                version: row.get(2)?,
                stage: parse_rollout_stage(row.get::<_, String>(3)?.as_str())?,
                status: parse_rollout_status(row.get::<_, String>(4)?.as_str())?,
                cws_item_id: row.get(5)?,
                started_at_ms: row.get(6)?,
                completed_at_ms: row.get(7)?,
                error_code: row.get(8)?,
                error_message: row.get(9)?,
            })
        })?;
        let mut output = Vec::new();
        for row in rows {
            output.push(row?);
        }
        Ok(output)
    }

    pub fn insert_extension_compliance_check(
        &self,
        rollout_id: &str,
        check_key: &str,
        status: TelemetryAuditStatusV1,
        details_json: &Value,
        checked_at_ms: i64,
    ) -> Result<String> {
        let check_id = format!(
            "exc_{}",
            blake3_hash_hex(
                format!("{rollout_id}:{check_key}:{}:{checked_at_ms}", status_as_str(status))
                    .as_bytes()
            )
        );
        self.conn.execute(
            "INSERT INTO extension_compliance_checks (
                check_id, rollout_id, check_key, status, details_json, checked_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                check_id,
                rollout_id,
                check_key,
                status_as_str(status),
                canonical_json_string(details_json)?,
                checked_at_ms
            ],
        )?;
        Ok(check_id)
    }

    pub fn get_extension_compliance_snapshot(
        &self,
        rollout_id: Option<&str>,
        limit: usize,
    ) -> Result<UiExtensionComplianceSnapshotV1> {
        let target_rollout = if let Some(rollout_id) = rollout_id {
            Some(rollout_id.to_string())
        } else {
            self.conn
                .query_row(
                    "SELECT rollout_id
                     FROM extension_rollouts
                     ORDER BY started_at_ms DESC, rollout_id ASC
                     LIMIT 1",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
        };
        let Some(target_rollout) = target_rollout else {
            return Ok(UiExtensionComplianceSnapshotV1 {
                rollout_id: None,
                checks_total: 0,
                checks_passed: 0,
                checks_failed: 0,
                checks_warn: 0,
                checks: Vec::new(),
                blocking_reasons: Vec::new(),
            });
        };
        let limit = i64::try_from(limit).map_err(|_| {
            StorageError::InvalidEnvelope("extension compliance list limit overflow".to_string())
        })?;
        let mut checks = Vec::new();
        let mut checks_passed = 0_u32;
        let mut checks_failed = 0_u32;
        let mut checks_warn = 0_u32;
        let mut stmt = self.conn.prepare(
            "SELECT check_key, status, details_json, checked_at_ms
             FROM extension_compliance_checks
             WHERE rollout_id = ?1
             ORDER BY checked_at_ms DESC, check_id ASC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![target_rollout, limit], |row| {
            let check_key: String = row.get(0)?;
            let status_raw: String = row.get(1)?;
            let details_raw: String = row.get(2)?;
            let checked_at_ms: i64 = row.get(3)?;
            let details_json = serde_json::from_str::<Value>(&details_raw).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    2,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?;
            Ok((check_key, parse_telemetry_audit_status(&status_raw)?, details_json, checked_at_ms))
        })?;
        for row in rows {
            let (check_key, status, details_json, checked_at_ms) = row?;
            match status {
                TelemetryAuditStatusV1::Pass => checks_passed = checks_passed.saturating_add(1),
                TelemetryAuditStatusV1::Warn => checks_warn = checks_warn.saturating_add(1),
                TelemetryAuditStatusV1::Fail => checks_failed = checks_failed.saturating_add(1),
            }
            checks.push(serde_json::json!({
                "check_key": check_key,
                "status": status,
                "details_json": details_json,
                "checked_at_ms": checked_at_ms,
            }));
        }
        checks.sort_by(|left, right| {
            canonical_json_string(left)
                .unwrap_or_default()
                .cmp(&canonical_json_string(right).unwrap_or_default())
        });
        let mut blocking_reasons = Vec::new();
        if checks_failed > 0 {
            blocking_reasons.push("extension_compliance_failed".to_string());
        }
        Ok(UiExtensionComplianceSnapshotV1 {
            rollout_id: Some(target_rollout),
            checks_total: u32::try_from(checks.len()).unwrap_or(u32::MAX),
            checks_passed,
            checks_failed,
            checks_warn,
            checks,
            blocking_reasons,
        })
    }

    pub fn insert_update_rollout_start(
        &self,
        input: UpdateRolloutStartInput<'_>,
    ) -> Result<String> {
        let UpdateRolloutStartInput {
            channel,
            version,
            stage,
            rollout_pct,
            feed_url,
            signature_verified,
            started_at_ms,
        } = input;
        let sig = format!(
            "{}:{version}:{}:{rollout_pct}:{started_at_ms}",
            update_channel_as_str(channel),
            rollout_stage_as_str(stage)
        );
        let update_rollout_id = format!("upd_{}", blake3_hash_hex(sig.as_bytes()));
        self.conn.execute(
            "INSERT INTO update_rollouts (
                update_rollout_id, channel, version, stage, rollout_pct, status, feed_url,
                signature_verified, started_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                update_rollout_id,
                update_channel_as_str(channel),
                version,
                rollout_stage_as_str(stage),
                i64::from(rollout_pct),
                rollout_status_as_str(RolloutStatusV1::Active),
                feed_url,
                if signature_verified { 1_i64 } else { 0_i64 },
                started_at_ms
            ],
        )?;
        Ok(update_rollout_id)
    }

    pub fn mark_update_rollout_status(
        &self,
        update_rollout_id: &str,
        status: RolloutStatusV1,
        completed_at_ms: Option<i64>,
        error_code: Option<&str>,
        error_message: Option<&str>,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE update_rollouts
             SET status = ?2,
                 completed_at_ms = ?3,
                 error_code = ?4,
                 error_message = ?5
             WHERE update_rollout_id = ?1",
            params![
                update_rollout_id,
                rollout_status_as_str(status),
                completed_at_ms,
                error_code,
                error_message
            ],
        )?;
        Ok(())
    }

    pub fn get_latest_update_rollout_snapshot(
        &self,
        channel: UpdateChannelV1,
    ) -> Result<Option<dtt_core::UiUpdateRolloutSnapshotV1>> {
        self.conn
            .query_row(
                "SELECT update_rollout_id, version, stage, rollout_pct, status, feed_url,
                        signature_verified, started_at_ms, completed_at_ms, error_code, error_message
                 FROM update_rollouts
                 WHERE channel = ?1
                 ORDER BY started_at_ms DESC, update_rollout_id ASC
                 LIMIT 1",
                params![update_channel_as_str(channel)],
                |row| {
                    Ok(dtt_core::UiUpdateRolloutSnapshotV1 {
                        update_rollout_id: row.get(0)?,
                        channel,
                        version: row.get(1)?,
                        stage: row
                            .get::<_, Option<String>>(2)?
                            .as_deref()
                            .map(parse_rollout_stage)
                            .transpose()?,
                        rollout_pct: row
                            .get::<_, Option<i64>>(3)?
                            .map(|value| u8::try_from(value.max(0)).unwrap_or(u8::MAX)),
                        status: row
                            .get::<_, Option<String>>(4)?
                            .as_deref()
                            .map(parse_rollout_status)
                            .transpose()?,
                        feed_url: row.get(5)?,
                        signature_verified: row.get::<_, i64>(6)? == 1,
                        started_at_ms: row.get(7)?,
                        completed_at_ms: row.get(8)?,
                        error_code: row.get(9)?,
                        error_message: row.get(10)?,
                    })
                },
            )
            .optional()
            .map_err(StorageError::from)
    }

    pub fn list_update_rollout_snapshots(
        &self,
        limit: usize,
    ) -> Result<Vec<dtt_core::UiUpdateRolloutSnapshotV1>> {
        let limit = i64::try_from(limit).map_err(|_| {
            StorageError::InvalidEnvelope("update rollout list limit overflow".to_string())
        })?;
        let mut stmt = self.conn.prepare(
            "SELECT update_rollout_id, channel, version, stage, rollout_pct, status, feed_url,
                    signature_verified, started_at_ms, completed_at_ms, error_code, error_message
             FROM update_rollouts
             ORDER BY started_at_ms DESC, update_rollout_id ASC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |row| {
            let channel_raw: String = row.get(1)?;
            Ok(dtt_core::UiUpdateRolloutSnapshotV1 {
                update_rollout_id: row.get(0)?,
                channel: parse_update_channel(&channel_raw)?,
                version: row.get(2)?,
                stage: row
                    .get::<_, Option<String>>(3)?
                    .as_deref()
                    .map(parse_rollout_stage)
                    .transpose()?,
                rollout_pct: row
                    .get::<_, Option<i64>>(4)?
                    .map(|value| u8::try_from(value.max(0)).unwrap_or(u8::MAX)),
                status: row
                    .get::<_, Option<String>>(5)?
                    .as_deref()
                    .map(parse_rollout_status)
                    .transpose()?,
                feed_url: row.get(6)?,
                signature_verified: row.get::<_, i64>(7)? == 1,
                started_at_ms: row.get(8)?,
                completed_at_ms: row.get(9)?,
                error_code: row.get(10)?,
                error_message: row.get(11)?,
            })
        })?;
        let mut output = Vec::new();
        for row in rows {
            output.push(row?);
        }
        Ok(output)
    }

    pub fn insert_release_health_snapshot(
        &self,
        scorecard: &ReleaseHealthScorecardV1,
    ) -> Result<ReleaseHealthSnapshotV1> {
        let stage_raw = scorecard.stage.map(rollout_stage_as_str);
        let sig = format!(
            "{}:{}:{}:{}:{}:{}",
            scorecard.scope,
            scorecard.channel,
            scorecard.version,
            stage_raw.unwrap_or("none"),
            scorecard.score,
            scorecard.created_at_ms
        );
        let snapshot_id = format!("rhs_{}", blake3_hash_hex(sig.as_bytes()));
        let metrics_json = canonical_json_string(&serde_json::to_value(&scorecard.metrics)?)?;
        let gate_reasons = scorecard
            .gate_reasons
            .iter()
            .map(|value| rollout_gate_reason_as_str(*value).to_string())
            .collect::<Vec<_>>();
        let gate_reasons_json = canonical_json_string(&serde_json::to_value(gate_reasons)?)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO release_health_snapshots (
                snapshot_id, scope, channel, version, stage, health_status, score, metrics_json,
                gate_reasons_json, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                snapshot_id,
                scorecard.scope,
                scorecard.channel,
                scorecard.version,
                stage_raw,
                rollout_health_status_as_str(scorecard.overall_status),
                scorecard.score,
                metrics_json,
                gate_reasons_json,
                scorecard.created_at_ms
            ],
        )?;
        Ok(ReleaseHealthSnapshotV1 { snapshot_id, scorecard: scorecard.clone() })
    }

    pub fn get_latest_release_health_snapshot(
        &self,
        scope: &str,
        channel: &str,
        version: &str,
    ) -> Result<Option<ReleaseHealthSnapshotV1>> {
        self.conn
            .query_row(
                "SELECT snapshot_id, stage, health_status, score, metrics_json, gate_reasons_json, created_at_ms
                 FROM release_health_snapshots
                 WHERE scope = ?1 AND channel = ?2 AND version = ?3
                 ORDER BY created_at_ms DESC, snapshot_id ASC
                 LIMIT 1",
                params![scope, channel, version],
                |row| {
                    let snapshot_id: String = row.get(0)?;
                    let stage = row
                        .get::<_, Option<String>>(1)?
                        .as_deref()
                        .map(parse_rollout_stage)
                        .transpose()?;
                    let overall_status =
                        parse_rollout_health_status(row.get::<_, String>(2)?.as_str())?;
                    let score: f64 = row.get(3)?;
                    let metrics_json = parse_json_text::<Vec<dtt_core::ReleaseHealthMetricV1>>(
                        row.get::<_, String>(4)?.as_str(),
                    )?;
                    let gate_reason_values =
                        parse_json_text::<Vec<String>>(row.get::<_, String>(5)?.as_str())?;
                    let gate_reasons = gate_reason_values
                        .iter()
                        .map(|value| parse_rollout_gate_reason(value.as_str()))
                        .collect::<std::result::Result<Vec<_>, rusqlite::Error>>()?;
                    let created_at_ms: i64 = row.get(6)?;
                    Ok(ReleaseHealthSnapshotV1 {
                        snapshot_id,
                        scorecard: ReleaseHealthScorecardV1 {
                            scope: scope.to_string(),
                            channel: channel.to_string(),
                            version: version.to_string(),
                            stage,
                            overall_status,
                            score,
                            metrics: metrics_json,
                            gate_reasons,
                            created_at_ms,
                        },
                    })
                },
            )
            .optional()
            .map_err(StorageError::from)
    }

    pub fn insert_rollout_stage_transition(
        &self,
        input: RolloutStageTransitionInput<'_>,
    ) -> Result<String> {
        let RolloutStageTransitionInput {
            kind,
            channel,
            version,
            from_stage,
            to_stage,
            action,
            decision_json,
            decided_at_ms,
        } = input;
        let from_raw = from_stage.map(rollout_stage_as_str);
        let to_raw = to_stage.map(rollout_stage_as_str);
        let sig = format!(
            "{kind}:{channel}:{version}:{}:{}:{}:{decided_at_ms}",
            from_raw.unwrap_or("none"),
            to_raw.unwrap_or("none"),
            rollout_controller_action_as_str(action)
        );
        let transition_id = format!("rtr_{}", blake3_hash_hex(sig.as_bytes()));
        self.conn.execute(
            "INSERT OR REPLACE INTO rollout_stage_transitions (
                transition_id, kind, channel, version, from_stage, to_stage, action, decision_json, decided_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                transition_id,
                kind,
                channel,
                version,
                from_raw,
                to_raw,
                rollout_controller_action_as_str(action),
                canonical_json_string(decision_json)?,
                decided_at_ms
            ],
        )?;
        Ok(transition_id)
    }

    pub fn insert_compliance_evidence_pack(&self, pack: &ComplianceEvidencePackV1) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO compliance_evidence_packs (
                pack_id, kind, channel, version, stage, pack_path, manifest_sha256, items_json,
                created_at_ms, status, error_code, error_message
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                pack.pack_id,
                pack.kind,
                pack.channel,
                pack.version,
                pack.stage.map(rollout_stage_as_str),
                pack.pack_path,
                pack.manifest_sha256,
                canonical_json_string(&serde_json::to_value(&pack.items)?)?,
                pack.created_at_ms,
                pack.status,
                pack.error_code,
                pack.error_message
            ],
        )?;
        Ok(())
    }

    pub fn list_compliance_evidence_packs(
        &self,
        kind: Option<&str>,
        limit: usize,
    ) -> Result<Vec<UiListComplianceEvidencePacksItemV1>> {
        let limit = i64::try_from(limit).map_err(|_| {
            StorageError::InvalidEnvelope("compliance evidence list limit overflow".to_string())
        })?;
        let mut output = Vec::new();
        match kind {
            Some(kind) => {
                let mut stmt = self.conn.prepare(
                    "SELECT pack_id, kind, channel, version, stage, status, created_at_ms, pack_path, manifest_sha256
                     FROM compliance_evidence_packs
                     WHERE kind = ?1
                     ORDER BY created_at_ms DESC, pack_id ASC
                     LIMIT ?2",
                )?;
                let rows = stmt.query_map(params![kind, limit], parse_compliance_pack_list_row)?;
                for row in rows {
                    output.push(row?);
                }
            }
            None => {
                let mut stmt = self.conn.prepare(
                    "SELECT pack_id, kind, channel, version, stage, status, created_at_ms, pack_path, manifest_sha256
                     FROM compliance_evidence_packs
                     ORDER BY created_at_ms DESC, pack_id ASC
                     LIMIT ?1",
                )?;
                let rows = stmt.query_map(params![limit], parse_compliance_pack_list_row)?;
                for row in rows {
                    output.push(row?);
                }
            }
        }
        Ok(output)
    }

    pub fn get_compliance_evidence_pack(
        &self,
        kind: &str,
        channel: &str,
        version: &str,
        stage: Option<RolloutStageV1>,
    ) -> Result<UiGetComplianceEvidencePackResultV1> {
        let stage_raw = stage.map(rollout_stage_as_str);
        let record = self
            .conn
            .query_row(
                "SELECT pack_id, kind, channel, version, stage, pack_path, manifest_sha256,
                        items_json, created_at_ms, status, error_code, error_message
                 FROM compliance_evidence_packs
                 WHERE kind = ?1 AND channel = ?2 AND version = ?3
                   AND (stage = ?4 OR (?4 IS NULL AND stage IS NULL))
                 ORDER BY created_at_ms DESC, pack_id ASC
                 LIMIT 1",
                params![kind, channel, version, stage_raw],
                parse_compliance_pack_row,
            )
            .optional()?;
        Ok(UiGetComplianceEvidencePackResultV1 { pack: record })
    }

    pub fn insert_bundle_inspection_record(
        &self,
        inspect_id: &str,
        bundle_path: &str,
        integrity_valid: bool,
        summary_json: &Value,
        error_code: Option<&str>,
        error_message: Option<&str>,
    ) -> Result<UiBundleInspectOpenResultV1> {
        let opened_at_ms = now_unix_ms()?;
        let summary_encoded = canonical_json_string(summary_json)?;
        let integrity_value = if integrity_valid { 1_i64 } else { 0_i64 };
        self.conn.execute(
            "INSERT INTO bundle_inspections (
                inspect_id, bundle_path, session_id, integrity_valid, summary_json, opened_at_ms, error_code, error_message
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                inspect_id,
                bundle_path,
                summary_json.get("session_id").and_then(Value::as_str),
                integrity_value,
                summary_encoded,
                opened_at_ms,
                error_code,
                error_message
            ],
        )?;
        parse_bundle_inspection_summary(inspect_id, bundle_path, integrity_valid, summary_json)
    }

    pub fn get_bundle_inspection_record(
        &self,
        inspect_id: &str,
    ) -> Result<Option<UiBundleInspectOpenResultV1>> {
        self.conn
            .query_row(
                "SELECT inspect_id, bundle_path, integrity_valid, summary_json
                 FROM bundle_inspections
                 WHERE inspect_id = ?1",
                params![inspect_id],
                |row| {
                    let inspect_id: String = row.get(0)?;
                    let bundle_path: String = row.get(1)?;
                    let integrity_valid = row.get::<_, i64>(2)? == 1;
                    let summary_raw: String = row.get(3)?;
                    let summary_json =
                        serde_json::from_str::<Value>(&summary_raw).map_err(|error| {
                            rusqlite::Error::FromSqlConversionFailure(
                                3,
                                rusqlite::types::Type::Text,
                                Box::new(error),
                            )
                        })?;
                    parse_bundle_inspection_summary(
                        inspect_id.as_str(),
                        bundle_path.as_str(),
                        integrity_valid,
                        &summary_json,
                    )
                    .map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            3,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })
                },
            )
            .optional()
            .map_err(StorageError::from)
    }

    pub fn get_bundle_inspection_summary_json(&self, inspect_id: &str) -> Result<Option<Value>> {
        self.conn
            .query_row(
                "SELECT summary_json
                 FROM bundle_inspections
                 WHERE inspect_id = ?1",
                params![inspect_id],
                |row| {
                    let summary_raw: String = row.get(0)?;
                    serde_json::from_str::<Value>(&summary_raw).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })
                },
            )
            .optional()
            .map_err(StorageError::from)
    }

    pub fn close_bundle_inspection_record(
        &self,
        inspect_id: &str,
        closed_at_ms: i64,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE bundle_inspections
             SET closed_at_ms = ?2
             WHERE inspect_id = ?1",
            params![inspect_id, closed_at_ms],
        )?;
        Ok(())
    }

    pub fn compute_exported_at_ms(&self, session_id: &str) -> Result<i64> {
        let session_row: Option<(Option<i64>, i64)> = self
            .conn
            .query_row(
                "SELECT ended_at_ms, started_at_ms FROM sessions WHERE session_id = ?1",
                params![session_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (ended_at_ms, started_at_ms) = session_row
            .ok_or_else(|| StorageError::InvalidEnvelope("session not found".to_string()))?;
        if let Some(ended_at_ms) = ended_at_ms {
            return Ok(ended_at_ms);
        }
        let max_event_ts: Option<i64> = self
            .conn
            .query_row(
                "SELECT MAX(ts_ms) FROM events_raw WHERE session_id = ?1",
                params![session_id],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        if let Some(max_event_ts) = max_event_ts {
            return Ok(max_event_ts);
        }
        Ok(started_at_ms)
    }

    pub fn build_export_dataset(
        &self,
        session_id: &str,
        profile: ExportProfileV1,
    ) -> Result<ExportDatasetV1> {
        let session_row: Option<(String, i64, Option<i64>, String)> = self
            .conn
            .query_row(
                "SELECT privacy_mode, started_at_ms, ended_at_ms, capture_source
                 FROM sessions
                 WHERE session_id = ?1",
                params![session_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let (privacy_mode_raw, started_at_ms, ended_at_ms, capture_source) = session_row
            .ok_or_else(|| StorageError::InvalidEnvelope("session not found".to_string()))?;
        let privacy_mode = parse_redaction_level(privacy_mode_raw.as_str())?;
        if profile == ExportProfileV1::Full && privacy_mode == RedactionLevel::MetadataOnly {
            return Err(StorageError::InvalidEnvelope(
                "full export is blocked for metadata_only sessions".to_string(),
            ));
        }

        let exported_at_ms = self.compute_exported_at_ms(session_id)?;
        let findings_count = count_by_session(&self.conn, "findings", session_id)?;
        let session_json = serde_json::json!({
            "session_id": session_id,
            "privacy_mode": privacy_mode.as_str(),
            "capture_source": capture_source,
            "started_at_ms": started_at_ms,
            "ended_at_ms": ended_at_ms,
            "exported_at_ms": exported_at_ms,
            "findings_count": findings_count
        });

        let normalized_network_requests = self.read_export_json_rows(
            "SELECT json_object(
                'net_request_id', net_request_id,
                'session_id', session_id,
                'event_seq', event_seq,
                'started_at_ms', started_at_ms,
                'ts_ms', ts_ms,
                'scheme', scheme,
                'host', host,
                'port', port,
                'path', path,
                'query', query,
                'method', method,
                'request_headers_json', request_headers_json,
                'timing_json', timing_json,
                'redaction_level', redaction_level
             )
             FROM network_requests
             WHERE session_id = ?1
             ORDER BY started_at_ms ASC, net_request_id ASC",
            params![session_id],
        )?;
        let normalized_network_responses = self.read_export_json_rows(
            "SELECT json_object(
                'net_request_id', net_request_id,
                'session_id', session_id,
                'ts_ms', ts_ms,
                'status_code', status_code,
                'protocol', protocol,
                'mime_type', mime_type,
                'encoded_data_length', encoded_data_length,
                'response_headers_json', response_headers_json,
                'headers_hash', headers_hash,
                'stream_summary_json', stream_summary_json,
                'redaction_level', redaction_level
             )
             FROM network_responses
             WHERE session_id = ?1
             ORDER BY ts_ms ASC, net_request_id ASC",
            params![session_id],
        )?;
        let normalized_network_completion = self.read_export_json_rows(
            "SELECT json_object(
                'net_request_id', net_request_id,
                'session_id', session_id,
                'ts_ms', ts_ms,
                'duration_ms', duration_ms,
                'success', success,
                'error_text', error_text,
                'finished_at_ms', finished_at_ms,
                'canceled', canceled,
                'blocked_reason', blocked_reason
             )
             FROM network_completion
             WHERE session_id = ?1
             ORDER BY ts_ms ASC, net_request_id ASC",
            params![session_id],
        )?;
        let normalized_console_entries = self.read_export_json_rows(
            "SELECT json_object(
                'console_id', console_id,
                'session_id', session_id,
                'ts_ms', ts_ms,
                'level', level,
                'source', source,
                'message_redacted', message_redacted,
                'message_hash', message_hash,
                'message_len', message_len
             )
             FROM console_entries
             WHERE session_id = ?1
             ORDER BY ts_ms ASC, console_id ASC",
            params![session_id],
        )?;
        let normalized_page_lifecycle = self.read_export_json_rows(
            "SELECT json_object(
                'lifecycle_id', lifecycle_id,
                'session_id', session_id,
                'ts_ms', ts_ms,
                'frame_id', frame_id,
                'loader_id', loader_id,
                'name', name,
                'value_json', value_json
             )
             FROM page_lifecycle
             WHERE session_id = ?1
             ORDER BY ts_ms ASC, lifecycle_id ASC",
            params![session_id],
        )?;
        let normalized_interactions = self.read_export_json_rows(
            "SELECT json_object(
                'interaction_id', interaction_id,
                'session_id', session_id,
                'interaction_kind', interaction_kind,
                'opened_at_ms', opened_at_ms,
                'closed_at_ms', closed_at_ms,
                'primary_member_id', primary_member_id,
                'rank', rank
             )
             FROM interactions
             WHERE session_id = ?1
             ORDER BY opened_at_ms ASC, interaction_kind ASC, interaction_id ASC",
            params![session_id],
        )?;
        let normalized_interaction_members = self.read_export_json_rows(
            "SELECT json_object(
                'interaction_id', im.interaction_id,
                'member_type', im.member_type,
                'member_id', im.member_id,
                'member_rank', im.member_rank,
                'is_primary', im.is_primary
             )
             FROM interaction_members im
             JOIN interactions i ON i.interaction_id = im.interaction_id
             WHERE i.session_id = ?1
             ORDER BY im.interaction_id ASC, im.member_rank ASC, im.member_type ASC, im.member_id ASC",
            params![session_id],
        )?;

        let analysis_findings = self.read_export_json_rows(
            "SELECT json_object(
                'finding_id', finding_id,
                'session_id', session_id,
                'detector_id', detector_id,
                'detector_version', detector_version,
                'title', title,
                'summary', summary,
                'category', category,
                'severity_score', severity_score,
                'confidence_score', confidence_score,
                'created_at_ms', created_at_ms,
                'interaction_id', interaction_id,
                'fix_steps_json', fix_steps_json
             )
             FROM findings
             WHERE session_id = ?1
             ORDER BY severity_score DESC, detector_id ASC, finding_id ASC",
            params![session_id],
        )?;
        let analysis_claims = self.read_export_json_rows(
            "SELECT json_object(
                'claim_id', c.claim_id,
                'finding_id', c.finding_id,
                'claim_rank', c.claim_rank,
                'truth', c.truth,
                'title', c.title,
                'summary', c.summary,
                'confidence_score', c.confidence_score
             )
             FROM claims c
             JOIN findings f ON f.finding_id = c.finding_id
             WHERE f.session_id = ?1
             ORDER BY c.finding_id ASC, c.claim_rank ASC, c.claim_id ASC",
            params![session_id],
        )?;
        let analysis_evidence_refs = self.read_export_json_rows(
            "SELECT json_object(
                'evidence_ref_id', e.evidence_ref_id,
                'claim_id', e.claim_id,
                'evidence_rank', e.evidence_rank,
                'ref_json', e.ref_json
             )
             FROM evidence_refs e
             JOIN claims c ON c.claim_id = e.claim_id
             JOIN findings f ON f.finding_id = c.finding_id
             WHERE f.session_id = ?1
             ORDER BY c.finding_id ASC, e.evidence_rank ASC, e.evidence_ref_id ASC",
            params![session_id],
        )?;
        let mut analysis_derived_metrics: Vec<Value> = Vec::new();
        for row in &analysis_evidence_refs {
            let Some(evidence_ref_id) = row.get("evidence_ref_id").and_then(Value::as_str) else {
                continue;
            };
            let Some(ref_json_raw) = row.get("ref_json").and_then(Value::as_str) else {
                continue;
            };
            let Ok(evidence_ref) = serde_json::from_str::<EvidenceRefV1>(ref_json_raw) else {
                continue;
            };
            if let EvidenceTarget::DerivedMetric(target) = evidence_ref.target {
                analysis_derived_metrics.push(serde_json::json!({
                    "evidence_ref_id": evidence_ref_id,
                    "session_id": evidence_ref.session_id,
                    "label": evidence_ref.label,
                    "ts_ms": evidence_ref.ts_ms,
                    "metric_name": target.metric_name,
                    "value": target.value,
                    "unit": target.unit,
                    "inputs": target.inputs
                }));
            }
        }
        analysis_derived_metrics
            .sort_by(|left, right| sort_json_key(left, right, "evidence_ref_id"));

        let mut raw_events: Vec<Value> = Vec::new();
        {
            let mut stmt = self.conn.prepare(
                "SELECT event_id, event_seq, ts_ms, cdp_method, redaction_level, payload_encoding, payload_bytes
                 FROM events_raw
                 WHERE session_id = ?1
                 ORDER BY event_seq ASC",
            )?;
            let rows = stmt.query_map(params![session_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                ))
            })?;
            for row in rows {
                let (
                    event_id,
                    event_seq,
                    ts_ms,
                    cdp_method,
                    redaction_level,
                    payload_encoding,
                    payload_bytes,
                ) = row?;
                let raw_event = decode_raw_payload(&payload_encoding, &payload_bytes)?;
                let projected_raw_event = if profile == ExportProfileV1::ShareSafe {
                    sanitize_raw_event_for_share_safe(&raw_event)
                } else {
                    raw_event
                };
                raw_events.push(serde_json::json!({
                    "event_id": event_id,
                    "event_seq": event_seq,
                    "ts_ms": ts_ms,
                    "cdp_method": cdp_method,
                    "redaction_level": redaction_level,
                    "raw_event": projected_raw_event
                }));
            }
        }

        let blobs = if profile == ExportProfileV1::Full {
            let mut output = Vec::new();
            let mut stmt = self.conn.prepare(
                "SELECT blob_id, media_type, len_bytes, blake3_hash, storage_kind, storage_ref
                 FROM blobs
                 WHERE session_id = ?1
                 ORDER BY blob_id ASC",
            )?;
            let rows = stmt.query_map(params![session_id], |row| {
                Ok(ExportBlobDescriptorV1 {
                    blob_id: row.get(0)?,
                    media_type: row.get(1)?,
                    len_bytes: row.get(2)?,
                    blake3_hash: row.get(3)?,
                    storage_kind: row.get(4)?,
                    storage_ref: row.get(5)?,
                })
            })?;
            for row in rows {
                output.push(row?);
            }
            output
        } else {
            Vec::new()
        };

        Ok(ExportDatasetV1 {
            session_id: session_id.to_string(),
            privacy_mode,
            export_profile: profile,
            exported_at_ms,
            session_json,
            normalized_network_requests,
            normalized_network_responses,
            normalized_network_completion,
            normalized_console_entries,
            normalized_page_lifecycle,
            normalized_interactions,
            normalized_interaction_members,
            analysis_findings,
            analysis_claims,
            analysis_evidence_refs,
            analysis_derived_metrics,
            raw_events,
            blobs,
        })
    }

    fn read_export_json_rows<P: rusqlite::Params>(
        &self,
        sql: &str,
        params: P,
    ) -> Result<Vec<Value>> {
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map(params, |row| row.get::<_, Option<String>>(0))?;
        let mut output = Vec::new();
        for row in rows {
            let Some(json_line) = row? else {
                continue;
            };
            output.push(serde_json::from_str::<Value>(&json_line)?);
        }
        Ok(output)
    }

    pub fn get_retention_policy(&self) -> Result<RetentionPolicyV1> {
        let raw: Option<String> = self
            .conn
            .query_row(
                "SELECT value_json FROM app_settings WHERE setting_key = ?1",
                params![RETENTION_POLICY_KEY],
                |row| row.get(0),
            )
            .optional()?;
        match raw {
            Some(raw) => Ok(serde_json::from_str::<RetentionPolicyV1>(&raw)?),
            None => Ok(RetentionPolicyV1::default()),
        }
    }

    pub fn set_retention_policy(&self, policy: RetentionPolicyV1) -> Result<()> {
        if policy.retain_days == 0 || policy.max_sessions == 0 {
            return Err(StorageError::InvalidEnvelope(
                "retention policy must have retain_days > 0 and max_sessions > 0".to_string(),
            ));
        }
        let encoded = canonical_json_string(&policy)?;
        self.conn.execute(
            "INSERT INTO app_settings (setting_key, value_json, updated_at_ms)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(setting_key) DO UPDATE SET
               value_json = excluded.value_json,
               updated_at_ms = excluded.updated_at_ms",
            params![RETENTION_POLICY_KEY, encoded, now_unix_ms()?],
        )?;
        Ok(())
    }

    pub fn get_pairing_context(&self) -> Result<Option<(u16, String)>> {
        let raw: Option<String> = self
            .conn
            .query_row(
                "SELECT value_json FROM app_settings WHERE setting_key = ?1",
                params![PAIRING_CONTEXT_KEY],
                |row| row.get(0),
            )
            .optional()?;
        let Some(raw) = raw else {
            return Ok(None);
        };
        let parsed: Value = serde_json::from_str(&raw)?;
        let Some(port_u64) = parsed.get("port").and_then(Value::as_u64) else {
            return Ok(None);
        };
        let Some(token) = parsed.get("token").and_then(Value::as_str) else {
            return Ok(None);
        };
        let Ok(port) = u16::try_from(port_u64) else {
            return Ok(None);
        };
        if token.len() != 32 {
            return Ok(None);
        }
        Ok(Some((port, token.to_string())))
    }

    pub fn set_pairing_context(&self, port: u16, token: &str) -> Result<()> {
        let payload = serde_json::json!({
            "port": port,
            "token": token,
        });
        let encoded = canonical_json_string(&payload)?;
        self.conn.execute(
            "INSERT INTO app_settings (setting_key, value_json, updated_at_ms)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(setting_key) DO UPDATE SET
               value_json = excluded.value_json,
               updated_at_ms = excluded.updated_at_ms",
            params![PAIRING_CONTEXT_KEY, encoded, now_unix_ms()?],
        )?;
        Ok(())
    }

    pub fn upsert_trusted_device(
        &self,
        device_id: &str,
        browser_label: &str,
        now_ms: i64,
    ) -> Result<TrustedDeviceRecordV1> {
        self.conn.execute(
            "INSERT INTO trusted_devices (
                device_id,
                browser_label,
                first_paired_at_ms,
                last_seen_at_ms,
                revoked
             ) VALUES (?1, ?2, ?3, ?3, 0)
             ON CONFLICT(device_id) DO UPDATE SET
               browser_label = excluded.browser_label,
               last_seen_at_ms = excluded.last_seen_at_ms,
               revoked = 0",
            params![device_id, browser_label, now_ms],
        )?;
        self.conn
            .query_row(
                "SELECT device_id, browser_label, first_paired_at_ms, last_seen_at_ms, revoked
             FROM trusted_devices
             WHERE device_id = ?1",
                params![device_id],
                |row| {
                    Ok(TrustedDeviceRecordV1 {
                        device_id: row.get(0)?,
                        browser_label: row.get(1)?,
                        first_paired_at_ms: row.get(2)?,
                        last_seen_at_ms: row.get(3)?,
                        revoked: row.get::<_, i64>(4)? != 0,
                    })
                },
            )
            .map_err(StorageError::from)
    }

    pub fn revoke_trusted_device(&self, device_id: &str, now_ms: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE trusted_devices
             SET revoked = 1, last_seen_at_ms = ?2
             WHERE device_id = ?1",
            params![device_id, now_ms],
        )?;
        Ok(())
    }

    pub fn list_trusted_devices(&self, limit: usize) -> Result<Vec<TrustedDeviceRecordV1>> {
        let mut stmt = self.conn.prepare(
            "SELECT device_id, browser_label, first_paired_at_ms, last_seen_at_ms, revoked
             FROM trusted_devices
             ORDER BY revoked ASC, last_seen_at_ms DESC, device_id ASC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![i64::try_from(limit).unwrap_or(i64::MAX)], |row| {
            Ok(TrustedDeviceRecordV1 {
                device_id: row.get(0)?,
                browser_label: row.get(1)?,
                first_paired_at_ms: row.get(2)?,
                last_seen_at_ms: row.get(3)?,
                revoked: row.get::<_, i64>(4)? != 0,
            })
        })?;
        let mut output = Vec::new();
        for row in rows {
            output.push(row?);
        }
        Ok(output)
    }

    pub fn delete_session_with_artifacts(
        &self,
        session_id: &str,
        _now_ms: i64,
    ) -> Result<SessionDeleteResultV1> {
        let mut result = SessionDeleteResultV1 {
            session_id: session_id.to_string(),
            db_deleted: false,
            files_deleted: 0,
            missing_files: Vec::new(),
            blocked_paths: Vec::new(),
            errors: Vec::new(),
        };

        let ended_at_ms: Option<Option<i64>> = self
            .conn
            .query_row(
                "SELECT ended_at_ms FROM sessions WHERE session_id = ?1",
                params![session_id],
                |row| row.get(0),
            )
            .optional()?;

        let Some(ended_at_ms) = ended_at_ms else {
            result.errors.push("session_not_found".to_string());
            return Ok(result);
        };

        if ended_at_ms.is_none() {
            result.errors.push("delete_blocked_running_session".to_string());
            return Ok(result);
        }

        let policy = self.get_retention_policy()?;
        let export_roots = self.load_managed_roots(EXPORT_ROOT_KEY, default_export_root())?;
        let blob_roots = self.load_managed_roots(BLOB_ROOT_KEY, default_blob_root())?;

        if policy.delete_exports {
            let mut stmt = self.conn.prepare(
                "SELECT zip_path
                 FROM exports_runs
                 WHERE session_id = ?1
                 ORDER BY created_at_ms ASC, export_id ASC",
            )?;
            let paths =
                stmt.query_map(params![session_id], |row| row.get::<_, Option<String>>(0))?;
            for path in paths {
                if let Some(path) = path? {
                    delete_artifact_path(&path, &export_roots, &mut result);
                }
            }
        }

        if policy.delete_blobs {
            let mut stmt = self.conn.prepare(
                "SELECT storage_ref
                 FROM blobs
                 WHERE session_id = ?1
                 ORDER BY blob_id ASC",
            )?;
            let paths = stmt.query_map(params![session_id], |row| row.get::<_, String>(0))?;
            for path in paths {
                delete_artifact_path(&path?, &blob_roots, &mut result);
            }
        }

        if !result.blocked_paths.is_empty() {
            result.errors.push("delete_artifact_path_blocked".to_string());
            return Ok(result);
        }
        if !result.errors.is_empty() {
            return Ok(result);
        }

        let deleted_rows =
            self.conn.execute("DELETE FROM sessions WHERE session_id = ?1", params![session_id])?;
        result.db_deleted = deleted_rows > 0;
        if deleted_rows == 0 {
            result.errors.push("session_delete_noop".to_string());
        }

        Ok(result)
    }

    pub fn run_retention(
        &self,
        now_ms: i64,
        mode: RetentionRunModeV1,
    ) -> Result<RetentionRunReportV1> {
        Ok(self.run_retention_with_results(now_ms, mode)?.report)
    }

    pub fn run_retention_with_results(
        &self,
        now_ms: i64,
        mode: RetentionRunModeV1,
    ) -> Result<UiRetentionRunResultV1> {
        let policy = self.get_retention_policy()?;
        let ended_sessions = self.load_ended_sessions()?;
        let evaluated_sessions = u32::try_from(ended_sessions.len()).unwrap_or(u32::MAX);

        let mut candidate_ids: HashSet<String> = HashSet::new();
        if policy.enabled {
            let retain_window_ms = i64::from(policy.retain_days).saturating_mul(86_400_000);
            let age_cutoff_ms = now_ms.saturating_sub(retain_window_ms);
            for (session_id, ended_at_ms) in &ended_sessions {
                if *ended_at_ms <= age_cutoff_ms {
                    candidate_ids.insert(session_id.clone());
                }
            }

            let max_sessions = usize::try_from(policy.max_sessions).unwrap_or(usize::MAX);
            if ended_sessions.len() > max_sessions {
                let overflow = ended_sessions.len() - max_sessions;
                for (session_id, _) in ended_sessions.iter().take(overflow) {
                    candidate_ids.insert(session_id.clone());
                }
            }
        }

        let mut candidates: Vec<(String, i64)> = ended_sessions
            .iter()
            .filter(|(session_id, _)| candidate_ids.contains(session_id))
            .map(|(session_id, ended_at_ms)| (session_id.clone(), *ended_at_ms))
            .collect();
        candidates.sort_by(|left, right| left.1.cmp(&right.1).then(left.0.cmp(&right.0)));

        let candidate_sessions = u32::try_from(candidates.len()).unwrap_or(u32::MAX);
        let run_seed = format!(
            "{}:{now_ms}:{}",
            retention_mode_as_str(mode),
            candidates
                .iter()
                .map(|(session_id, ended_at_ms)| format!("{session_id}:{ended_at_ms}"))
                .collect::<Vec<String>>()
                .join("|")
        );
        let run_id = format!("rrn_{}", blake3_hash_hex(run_seed.as_bytes()));

        let mut deleted: Vec<SessionDeleteResultV1> = Vec::new();
        let mut deleted_sessions: u32 = 0;
        let mut failed_sessions: u32 = 0;

        if mode == RetentionRunModeV1::Apply {
            for (session_id, _) in &candidates {
                let outcome = self.delete_session_with_artifacts(session_id, now_ms)?;
                if outcome.db_deleted {
                    deleted_sessions = deleted_sessions.saturating_add(1);
                } else {
                    failed_sessions = failed_sessions.saturating_add(1);
                }
                deleted.push(outcome);
            }
        }

        let report = RetentionRunReportV1 {
            run_id: run_id.clone(),
            mode,
            evaluated_sessions,
            candidate_sessions,
            deleted_sessions,
            skipped_running_sessions: 0,
            failed_sessions,
            started_at_ms: now_ms,
            finished_at_ms: now_ms,
        };

        let report_json =
            canonical_json_string(&serde_json::json!({ "report": report, "deleted": deleted }))?;
        self.conn.execute(
            "INSERT INTO retention_runs (
                run_id, mode, started_at_ms, finished_at_ms, report_json,
                evaluated_sessions, deleted_sessions, failed_sessions
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                run_id,
                retention_mode_as_str(mode),
                now_ms,
                now_ms,
                report_json,
                i64::from(evaluated_sessions),
                i64::from(deleted_sessions),
                i64::from(failed_sessions),
            ],
        )?;

        Ok(UiRetentionRunResultV1 { report, deleted })
    }

    pub fn append_bridge_diagnostic(
        &self,
        session_id: Option<&str>,
        ts_ms: i64,
        kind: &str,
        message: &str,
        source: &str,
    ) -> Result<()> {
        let ordinal: i64 = self.conn.query_row(
            "SELECT COUNT(1) FROM bridge_diagnostics WHERE ts_ms = ?1",
            params![ts_ms],
            |row| row.get(0),
        )?;
        let sig = format!(
            "{}:{ts_ms}:{kind}:{source}:{message}:{ordinal}",
            session_id.unwrap_or_default()
        );
        let diag_id = format!("diag_{}", blake3_hash_hex(sig.as_bytes()));
        self.conn.execute(
            "INSERT OR REPLACE INTO bridge_diagnostics (
                diag_id, session_id, ts_ms, kind, message, source, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![diag_id, session_id, ts_ms, kind, message, source, ts_ms],
        )?;
        Ok(())
    }

    pub fn list_bridge_diagnostics(
        &self,
        session_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<UiDiagnosticEntryV1>> {
        let limit = i64::try_from(limit).map_err(|_| {
            StorageError::InvalidEnvelope("diagnostics list limit overflow".to_string())
        })?;
        let mut output = Vec::new();
        match session_id {
            Some(session_id) => {
                let mut stmt = self.conn.prepare(
                    "SELECT ts_ms, kind, message
                     FROM bridge_diagnostics
                     WHERE session_id = ?1
                     ORDER BY ts_ms DESC, diag_id ASC
                     LIMIT ?2",
                )?;
                let rows = stmt.query_map(params![session_id, limit], |row| {
                    Ok(UiDiagnosticEntryV1 {
                        ts_ms: row.get(0)?,
                        kind: row.get(1)?,
                        message: row.get(2)?,
                    })
                })?;
                for row in rows {
                    output.push(row?);
                }
            }
            None => {
                let mut stmt = self.conn.prepare(
                    "SELECT ts_ms, kind, message
                     FROM bridge_diagnostics
                     ORDER BY ts_ms DESC, diag_id ASC
                     LIMIT ?1",
                )?;
                let rows = stmt.query_map(params![limit], |row| {
                    Ok(UiDiagnosticEntryV1 {
                        ts_ms: row.get(0)?,
                        kind: row.get(1)?,
                        message: row.get(2)?,
                    })
                })?;
                for row in rows {
                    output.push(row?);
                }
            }
        }
        Ok(output)
    }

    pub fn append_reliability_metric(
        &self,
        session_id: Option<&str>,
        source: &str,
        metric_key: ReliabilityMetricKeyV1,
        metric_value: f64,
        labels_json: &Value,
        ts_ms: i64,
    ) -> Result<ReliabilityMetricSampleV1> {
        let key_raw = reliability_metric_key_as_str(metric_key);
        let labels_raw = canonical_json_string(labels_json)?;
        let ordinal: i64 = self.conn.query_row(
            "SELECT COUNT(1) FROM reliability_metrics WHERE ts_ms = ?1 AND metric_key = ?2",
            params![ts_ms, key_raw],
            |row| row.get(0),
        )?;
        let sig = format!(
            "{}:{source}:{key_raw}:{metric_value}:{ts_ms}:{ordinal}",
            session_id.unwrap_or_default()
        );
        let metric_id = format!("met_{}", blake3_hash_hex(sig.as_bytes()));
        self.conn.execute(
            "INSERT OR REPLACE INTO reliability_metrics (
                metric_id, session_id, source, metric_key, metric_value, labels_json, ts_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![metric_id, session_id, source, key_raw, metric_value, labels_raw, ts_ms],
        )?;

        Ok(ReliabilityMetricSampleV1 {
            metric_id,
            session_id: session_id.map(ToOwned::to_owned),
            source: source.to_string(),
            metric_key,
            metric_value,
            labels_json: labels_json.clone(),
            ts_ms,
        })
    }

    pub fn get_reliability_snapshot(
        &self,
        window_ms: i64,
        now_ms: i64,
    ) -> Result<UiReliabilitySnapshotV1> {
        let bounded_window_ms = window_ms.max(1);
        let from_ms = now_ms.saturating_sub(bounded_window_ms);
        let mut totals_by_key = std::collections::BTreeMap::new();
        {
            let mut stmt = self.conn.prepare(
                "SELECT metric_key, COALESCE(SUM(metric_value), 0.0)
                 FROM reliability_metrics
                 WHERE ts_ms >= ?1 AND ts_ms <= ?2
                 GROUP BY metric_key
                 ORDER BY metric_key ASC",
            )?;
            let rows = stmt.query_map(params![from_ms, now_ms], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, f64>(1)?))
            })?;
            for row in rows {
                let (key, total) = row?;
                totals_by_key.insert(key, total);
            }
        }

        let mut recent_samples = Vec::new();
        {
            let mut stmt = self.conn.prepare(
                "SELECT metric_id, session_id, source, metric_key, metric_value, labels_json, ts_ms
                 FROM reliability_metrics
                 WHERE ts_ms >= ?1 AND ts_ms <= ?2
                 ORDER BY ts_ms DESC, metric_id ASC
                 LIMIT 200",
            )?;
            let rows = stmt.query_map(params![from_ms, now_ms], |row| {
                let metric_key_raw: String = row.get(3)?;
                let labels_raw: String = row.get(5)?;
                let labels_json = serde_json::from_str::<Value>(&labels_raw).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        5,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?;
                Ok(ReliabilityMetricSampleV1 {
                    metric_id: row.get(0)?,
                    session_id: row.get(1)?,
                    source: row.get(2)?,
                    metric_key: parse_reliability_metric_key(&metric_key_raw)?,
                    metric_value: row.get(4)?,
                    labels_json,
                    ts_ms: row.get(6)?,
                })
            })?;
            for row in rows {
                recent_samples.push(row?);
            }
        }

        Ok(UiReliabilitySnapshotV1 {
            window: ReliabilityWindowSummaryV1 {
                window_ms: bounded_window_ms,
                from_ms,
                to_ms: now_ms,
                totals_by_key,
            },
            recent_samples,
        })
    }

    pub fn list_reliability_series(
        &self,
        metric_key: ReliabilityMetricKeyV1,
        from_ms: i64,
        to_ms: i64,
        bucket_ms: i64,
    ) -> Result<Vec<UiReliabilitySeriesPointV1>> {
        let bucket_ms = bucket_ms.max(1);
        let key_raw = reliability_metric_key_as_str(metric_key);
        let mut buckets: std::collections::BTreeMap<i64, f64> = std::collections::BTreeMap::new();
        let mut stmt = self.conn.prepare(
            "SELECT ts_ms, metric_value
             FROM reliability_metrics
             WHERE metric_key = ?1 AND ts_ms >= ?2 AND ts_ms <= ?3
             ORDER BY ts_ms ASC, metric_id ASC",
        )?;
        let rows = stmt.query_map(params![key_raw, from_ms, to_ms], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, f64>(1)?))
        })?;
        for row in rows {
            let (ts_ms, metric_value) = row?;
            let normalized =
                from_ms.saturating_add(((ts_ms.saturating_sub(from_ms)) / bucket_ms) * bucket_ms);
            let slot = buckets.entry(normalized).or_insert(0.0);
            *slot += metric_value;
        }

        Ok(buckets
            .into_iter()
            .map(|(bucket_start_ms, metric_value)| UiReliabilitySeriesPointV1 {
                metric_key,
                bucket_start_ms,
                metric_value,
            })
            .collect())
    }

    pub fn get_telemetry_settings(&self) -> Result<UiTelemetrySettingsV1> {
        let row = self
            .conn
            .query_row(
                "SELECT mode, otlp_config_json
                 FROM telemetry_settings
                 WHERE id = 1",
                [],
                |row| {
                    let mode_raw: String = row.get(0)?;
                    let otlp_raw: String = row.get(1)?;
                    let otlp =
                        serde_json::from_str::<OtlpSinkConfigV1>(&otlp_raw).map_err(|error| {
                            rusqlite::Error::FromSqlConversionFailure(
                                1,
                                rusqlite::types::Type::Text,
                                Box::new(error),
                            )
                        })?;
                    Ok(UiTelemetrySettingsV1 {
                        mode: parse_telemetry_mode(mode_raw.as_str())?,
                        otlp,
                    })
                },
            )
            .optional()?;
        Ok(row.unwrap_or(UiTelemetrySettingsV1 {
            mode: TelemetryModeV1::LocalOnly,
            otlp: OtlpSinkConfigV1::default(),
        }))
    }

    pub fn set_telemetry_settings(
        &self,
        settings: &UiTelemetrySettingsV1,
        updated_at_ms: i64,
    ) -> Result<UiTelemetrySettingsV1> {
        if settings.mode == TelemetryModeV1::LocalPlusOtlp
            && settings.otlp.enabled
            && settings
                .otlp
                .endpoint
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .is_none()
        {
            return Err(StorageError::InvalidEnvelope(
                "otlp endpoint is required when local_plus_otlp is enabled".to_string(),
            ));
        }

        self.conn.execute(
            "INSERT INTO telemetry_settings (id, mode, otlp_config_json, updated_at_ms)
             VALUES (1, ?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET
                mode = excluded.mode,
                otlp_config_json = excluded.otlp_config_json,
                updated_at_ms = excluded.updated_at_ms",
            params![
                telemetry_mode_as_str(settings.mode),
                canonical_json_string(&settings.otlp)?,
                updated_at_ms
            ],
        )?;
        self.get_telemetry_settings()
    }

    pub fn list_reliability_samples(
        &self,
        from_ms: i64,
        to_ms: i64,
        limit: usize,
    ) -> Result<Vec<ReliabilityMetricSampleV1>> {
        let limit = i64::try_from(limit).map_err(|_| {
            StorageError::InvalidEnvelope("reliability sample limit overflow".to_string())
        })?;
        let mut stmt = self.conn.prepare(
            "SELECT metric_id, session_id, source, metric_key, metric_value, labels_json, ts_ms
             FROM reliability_metrics
             WHERE ts_ms >= ?1 AND ts_ms <= ?2
             ORDER BY ts_ms ASC, metric_id ASC
             LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![from_ms, to_ms, limit], |row| {
            let metric_key_raw: String = row.get(3)?;
            let labels_raw: String = row.get(5)?;
            let labels_json = serde_json::from_str::<Value>(&labels_raw).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    5,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?;
            Ok(ReliabilityMetricSampleV1 {
                metric_id: row.get(0)?,
                session_id: row.get(1)?,
                source: row.get(2)?,
                metric_key: parse_reliability_metric_key(metric_key_raw.as_str())?,
                metric_value: row.get(4)?,
                labels_json,
                ts_ms: row.get(6)?,
            })
        })?;
        let mut output = Vec::new();
        for row in rows {
            output.push(row?);
        }
        Ok(output)
    }

    pub fn insert_telemetry_export_start(
        &self,
        from_ms: i64,
        to_ms: i64,
        created_at_ms: i64,
    ) -> Result<TelemetryExportRunV1> {
        let export_run_id = format!(
            "tex_{}",
            blake3_hash_hex(format!("{from_ms}:{to_ms}:{created_at_ms}").as_bytes())
        );
        self.conn.execute(
            "INSERT INTO telemetry_exports (
                export_run_id, status, from_ms, to_ms, sample_count, redacted_count, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, 0, 0, ?5)",
            params![
                export_run_id,
                perf_run_status_as_str(PerfRunStatusV1::Running),
                from_ms,
                to_ms,
                created_at_ms
            ],
        )?;
        Ok(TelemetryExportRunV1 {
            export_run_id,
            status: PerfRunStatusV1::Running,
            from_ms,
            to_ms,
            sample_count: 0,
            redacted_count: 0,
            payload_sha256: None,
            created_at_ms,
            completed_at_ms: None,
            error_code: None,
            error_message: None,
        })
    }

    pub fn mark_telemetry_export_completed(
        &self,
        export_run_id: &str,
        sample_count: u32,
        redacted_count: u32,
        payload_sha256: Option<&str>,
        completed_at_ms: i64,
    ) -> Result<TelemetryExportRunV1> {
        self.conn.execute(
            "UPDATE telemetry_exports
             SET status = ?2,
                 sample_count = ?3,
                 redacted_count = ?4,
                 payload_sha256 = ?5,
                 completed_at_ms = ?6,
                 error_code = NULL,
                 error_message = NULL
             WHERE export_run_id = ?1",
            params![
                export_run_id,
                perf_run_status_as_str(PerfRunStatusV1::Completed),
                i64::from(sample_count),
                i64::from(redacted_count),
                payload_sha256,
                completed_at_ms
            ],
        )?;
        self.get_telemetry_export(export_run_id)?.ok_or_else(|| {
            StorageError::InvalidEnvelope("missing telemetry export row".to_string())
        })
    }

    pub fn mark_telemetry_export_failed(
        &self,
        export_run_id: &str,
        error_code: &str,
        error_message: &str,
        completed_at_ms: i64,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE telemetry_exports
             SET status = ?2,
                 completed_at_ms = ?3,
                 error_code = ?4,
                 error_message = ?5
             WHERE export_run_id = ?1",
            params![
                export_run_id,
                perf_run_status_as_str(PerfRunStatusV1::Failed),
                completed_at_ms,
                error_code,
                error_message
            ],
        )?;
        Ok(())
    }

    pub fn list_telemetry_exports(&self, limit: usize) -> Result<Vec<TelemetryExportRunV1>> {
        let limit = i64::try_from(limit).map_err(|_| {
            StorageError::InvalidEnvelope("telemetry export list limit overflow".to_string())
        })?;
        let mut stmt = self.conn.prepare(
            "SELECT export_run_id, status, from_ms, to_ms, sample_count, redacted_count,
                    payload_sha256, created_at_ms, completed_at_ms, error_code, error_message
             FROM telemetry_exports
             ORDER BY created_at_ms DESC, export_run_id ASC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |row| {
            let status_raw: String = row.get(1)?;
            Ok(TelemetryExportRunV1 {
                export_run_id: row.get(0)?,
                status: parse_perf_run_status(status_raw.as_str())?,
                from_ms: row.get(2)?,
                to_ms: row.get(3)?,
                sample_count: u32::try_from(row.get::<_, i64>(4)?.max(0)).unwrap_or(u32::MAX),
                redacted_count: u32::try_from(row.get::<_, i64>(5)?.max(0)).unwrap_or(u32::MAX),
                payload_sha256: row.get(6)?,
                created_at_ms: row.get(7)?,
                completed_at_ms: row.get(8)?,
                error_code: row.get(9)?,
                error_message: row.get(10)?,
            })
        })?;
        let mut output = Vec::new();
        for row in rows {
            output.push(row?);
        }
        Ok(output)
    }

    pub fn get_telemetry_export(
        &self,
        export_run_id: &str,
    ) -> Result<Option<TelemetryExportRunV1>> {
        self.conn
            .query_row(
                "SELECT export_run_id, status, from_ms, to_ms, sample_count, redacted_count,
                        payload_sha256, created_at_ms, completed_at_ms, error_code, error_message
                 FROM telemetry_exports
                 WHERE export_run_id = ?1",
                params![export_run_id],
                |row| {
                    let status_raw: String = row.get(1)?;
                    Ok(TelemetryExportRunV1 {
                        export_run_id: row.get(0)?,
                        status: parse_perf_run_status(status_raw.as_str())?,
                        from_ms: row.get(2)?,
                        to_ms: row.get(3)?,
                        sample_count: u32::try_from(row.get::<_, i64>(4)?.max(0))
                            .unwrap_or(u32::MAX),
                        redacted_count: u32::try_from(row.get::<_, i64>(5)?.max(0))
                            .unwrap_or(u32::MAX),
                        payload_sha256: row.get(6)?,
                        created_at_ms: row.get(7)?,
                        completed_at_ms: row.get(8)?,
                        error_code: row.get(9)?,
                        error_message: row.get(10)?,
                    })
                },
            )
            .optional()
            .map_err(StorageError::from)
    }

    pub fn insert_telemetry_audit(
        &self,
        export_run_id: Option<&str>,
        status: TelemetryAuditStatusV1,
        violations_json: &Value,
        payload_sha256: Option<&str>,
        created_at_ms: i64,
    ) -> Result<TelemetryAuditRunV1> {
        let violations_count = violations_json.as_array().map_or_else(
            || {
                if violations_json.is_null() {
                    0_u32
                } else {
                    1_u32
                }
            },
            |items| u32::try_from(items.len()).unwrap_or(u32::MAX),
        );
        let audit_id = format!(
            "aud_{}",
            blake3_hash_hex(
                format!(
                    "{}:{}:{}:{}",
                    export_run_id.unwrap_or_default(),
                    status_as_str(status),
                    violations_count,
                    created_at_ms
                )
                .as_bytes()
            )
        );
        self.conn.execute(
            "INSERT INTO telemetry_audits (
                audit_id, export_run_id, status, violations_count, violations_json, payload_sha256, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                audit_id,
                export_run_id,
                status_as_str(status),
                i64::from(violations_count),
                canonical_json_string(violations_json)?,
                payload_sha256,
                created_at_ms
            ],
        )?;
        Ok(TelemetryAuditRunV1 {
            audit_id,
            export_run_id: export_run_id.map(ToOwned::to_owned),
            status,
            violations_count,
            violations_json: violations_json.clone(),
            payload_sha256: payload_sha256.map(ToOwned::to_owned),
            created_at_ms,
        })
    }

    pub fn list_telemetry_audits(&self, limit: usize) -> Result<Vec<TelemetryAuditRunV1>> {
        let limit = i64::try_from(limit).map_err(|_| {
            StorageError::InvalidEnvelope("telemetry audit list limit overflow".to_string())
        })?;
        let mut stmt = self.conn.prepare(
            "SELECT audit_id, export_run_id, status, violations_count, violations_json, payload_sha256, created_at_ms
             FROM telemetry_audits
             ORDER BY created_at_ms DESC, audit_id ASC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |row| {
            let status_raw: String = row.get(2)?;
            let violations_raw: String = row.get(4)?;
            let violations_json =
                serde_json::from_str::<Value>(&violations_raw).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        4,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?;
            Ok(TelemetryAuditRunV1 {
                audit_id: row.get(0)?,
                export_run_id: row.get(1)?,
                status: parse_telemetry_audit_status(status_raw.as_str())?,
                violations_count: u32::try_from(row.get::<_, i64>(3)?.max(0)).unwrap_or(u32::MAX),
                violations_json,
                payload_sha256: row.get(5)?,
                created_at_ms: row.get(6)?,
            })
        })?;
        let mut output = Vec::new();
        for row in rows {
            output.push(row?);
        }
        Ok(output)
    }

    pub fn insert_perf_run_start(
        &self,
        run_kind: &str,
        input_ref: &str,
        started_at_ms: i64,
    ) -> Result<PerfRunRecordV1> {
        self.insert_perf_run_start_with_target(run_kind, input_ref, started_at_ms, 0)
    }

    pub fn insert_perf_run_start_with_target(
        &self,
        run_kind: &str,
        input_ref: &str,
        started_at_ms: i64,
        run_duration_target_ms: i64,
    ) -> Result<PerfRunRecordV1> {
        let sig = format!("{run_kind}:{input_ref}:{started_at_ms}");
        let perf_run_id = format!("prf_{}", blake3_hash_hex(sig.as_bytes()));
        self.conn.execute(
            "INSERT INTO perf_runs (
                perf_run_id, run_kind, status, input_ref, summary_json, started_at_ms, run_duration_target_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                perf_run_id,
                run_kind,
                perf_run_status_as_str(PerfRunStatusV1::Running),
                input_ref,
                "{}",
                started_at_ms,
                run_duration_target_ms,
            ],
        )?;
        Ok(PerfRunRecordV1 {
            perf_run_id,
            run_kind: run_kind.to_string(),
            status: PerfRunStatusV1::Running,
            input_ref: input_ref.to_string(),
            summary_json: serde_json::json!({}),
            started_at_ms,
            completed_at_ms: None,
            error_code: None,
            error_message: None,
            run_duration_target_ms,
            actual_duration_ms: None,
            budget_result: None,
            trend_delta_pct: None,
        })
    }

    pub fn mark_perf_run_completed(
        &self,
        perf_run_id: &str,
        summary_json: &Value,
        completed_at_ms: i64,
    ) -> Result<UiStartPerfRunResultV1> {
        self.mark_perf_run_completed_with_metrics(
            perf_run_id,
            summary_json,
            completed_at_ms,
            None,
            None,
            None,
        )
    }

    pub fn mark_perf_run_completed_with_metrics(
        &self,
        perf_run_id: &str,
        summary_json: &Value,
        completed_at_ms: i64,
        actual_duration_ms: Option<i64>,
        budget_result: Option<PerfBudgetResultV1>,
        trend_delta_pct: Option<f64>,
    ) -> Result<UiStartPerfRunResultV1> {
        let summary_raw = canonical_json_string(summary_json)?;
        self.conn.execute(
            "UPDATE perf_runs
             SET status = ?2,
                 summary_json = ?3,
                 completed_at_ms = ?4,
                 actual_duration_ms = ?5,
                 budget_result = ?6,
                 trend_delta_pct = ?7,
                 error_code = NULL,
                 error_message = NULL
             WHERE perf_run_id = ?1",
            params![
                perf_run_id,
                perf_run_status_as_str(PerfRunStatusV1::Completed),
                summary_raw,
                completed_at_ms,
                actual_duration_ms,
                budget_result.map(perf_budget_result_as_str),
                trend_delta_pct,
            ],
        )?;
        Ok(UiStartPerfRunResultV1 {
            perf_run_id: perf_run_id.to_string(),
            status: PerfRunStatusV1::Completed,
            summary_json: summary_json.clone(),
            error_message: None,
        })
    }

    pub fn mark_perf_run_failed(
        &self,
        perf_run_id: &str,
        error_code: &str,
        error_message: &str,
        completed_at_ms: i64,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE perf_runs
             SET status = ?2,
                 completed_at_ms = ?3,
                 error_code = ?4,
                 error_message = ?5
             WHERE perf_run_id = ?1",
            params![
                perf_run_id,
                perf_run_status_as_str(PerfRunStatusV1::Failed),
                completed_at_ms,
                error_code,
                error_message
            ],
        )?;
        Ok(())
    }

    pub fn list_perf_runs_ui(&self, limit: usize) -> Result<Vec<UiPerfRunListItemV1>> {
        let limit = i64::try_from(limit).map_err(|_| {
            StorageError::InvalidEnvelope("perf run list limit overflow".to_string())
        })?;
        let mut stmt = self.conn.prepare(
            "SELECT perf_run_id, run_kind, status, input_ref, started_at_ms, completed_at_ms,
                    error_code, error_message
             FROM perf_runs
             ORDER BY started_at_ms DESC, perf_run_id ASC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |row| {
            let status_raw: String = row.get(2)?;
            Ok(UiPerfRunListItemV1 {
                perf_run_id: row.get(0)?,
                run_kind: row.get(1)?,
                status: parse_perf_run_status(&status_raw)?,
                input_ref: row.get(3)?,
                started_at_ms: row.get(4)?,
                completed_at_ms: row.get(5)?,
                error_code: row.get(6)?,
                error_message: row.get(7)?,
            })
        })?;
        let mut output = Vec::new();
        for row in rows {
            output.push(row?);
        }
        Ok(output)
    }

    pub fn list_perf_trends(
        &self,
        run_kind: &str,
        limit: usize,
    ) -> Result<Vec<UiPerfTrendPointV1>> {
        let limit = i64::try_from(limit).map_err(|_| {
            StorageError::InvalidEnvelope("perf trend list limit overflow".to_string())
        })?;
        let mut stmt = self.conn.prepare(
            "SELECT started_at_ms, trend_delta_pct, budget_result
             FROM perf_runs
             WHERE run_kind = ?1 AND trend_delta_pct IS NOT NULL
             ORDER BY started_at_ms DESC, perf_run_id ASC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![run_kind, limit], |row| {
            let budget_raw: Option<String> = row.get(2)?;
            let budget_result = budget_raw
                .as_deref()
                .map(parse_perf_budget_result)
                .transpose()?
                .unwrap_or(PerfBudgetResultV1::Pass);
            Ok(UiPerfTrendPointV1 {
                run_kind: run_kind.to_string(),
                bucket_start_ms: row.get(0)?,
                metric_name: "drift_pct".to_string(),
                metric_value: row.get::<_, f64>(1)?,
                baseline_value: 0.0,
                trend_delta_pct: row.get(1)?,
                budget_result,
            })
        })?;
        let mut output = Vec::new();
        for row in rows {
            output.push(row?);
        }
        output.sort_by(|left, right| {
            left.bucket_start_ms
                .cmp(&right.bucket_start_ms)
                .then(left.metric_name.cmp(&right.metric_name))
                .then(left.run_kind.cmp(&right.run_kind))
        });
        Ok(output)
    }

    pub fn insert_perf_anomaly(
        &self,
        input: PerfAnomalyInsertInput<'_>,
    ) -> Result<UiListPerfAnomaliesItemV1> {
        let PerfAnomalyInsertInput {
            run_kind,
            bucket_start_ms,
            metric_name,
            severity,
            score,
            baseline_value,
            observed_value,
            details_json,
            created_at_ms,
        } = input;
        let sig = format!(
            "{run_kind}:{bucket_start_ms}:{metric_name}:{}:{score}:{baseline_value}:{observed_value}",
            perf_anomaly_severity_as_str(severity)
        );
        let anomaly_id = format!("anm_{}", blake3_hash_hex(sig.as_bytes()));
        self.conn.execute(
            "INSERT OR REPLACE INTO perf_anomalies (
                anomaly_id, run_kind, bucket_start_ms, metric_name, severity, score, baseline_value,
                observed_value, details_json, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                anomaly_id,
                run_kind,
                bucket_start_ms,
                metric_name,
                perf_anomaly_severity_as_str(severity),
                score,
                baseline_value,
                observed_value,
                canonical_json_string(details_json)?,
                created_at_ms
            ],
        )?;
        Ok(UiListPerfAnomaliesItemV1 {
            anomaly_id,
            run_kind: run_kind.to_string(),
            bucket_start_ms,
            metric_name: metric_name.to_string(),
            severity,
            score,
            baseline_value,
            observed_value,
            details_json: details_json.clone(),
            created_at_ms,
        })
    }

    pub fn list_perf_anomalies(
        &self,
        run_kind: Option<&str>,
        limit: usize,
    ) -> Result<Vec<UiListPerfAnomaliesItemV1>> {
        let limit = i64::try_from(limit).map_err(|_| {
            StorageError::InvalidEnvelope("perf anomaly list limit overflow".to_string())
        })?;
        let mut output = Vec::new();
        match run_kind {
            Some(run_kind) => {
                let mut stmt = self.conn.prepare(
                    "SELECT anomaly_id, run_kind, bucket_start_ms, metric_name, severity, score,
                            baseline_value, observed_value, details_json, created_at_ms
                     FROM perf_anomalies
                     WHERE run_kind = ?1
                     ORDER BY bucket_start_ms DESC, anomaly_id ASC
                     LIMIT ?2",
                )?;
                let rows = stmt.query_map(params![run_kind, limit], parse_perf_anomaly_row)?;
                for row in rows {
                    output.push(row?);
                }
            }
            None => {
                let mut stmt = self.conn.prepare(
                    "SELECT anomaly_id, run_kind, bucket_start_ms, metric_name, severity, score,
                            baseline_value, observed_value, details_json, created_at_ms
                     FROM perf_anomalies
                     ORDER BY bucket_start_ms DESC, anomaly_id ASC
                     LIMIT ?1",
                )?;
                let rows = stmt.query_map(params![limit], parse_perf_anomaly_row)?;
                for row in rows {
                    output.push(row?);
                }
            }
        }
        Ok(output)
    }

    pub fn list_retention_runs_ui(&self, limit: usize) -> Result<Vec<RetentionRunReportV1>> {
        let limit = i64::try_from(limit).map_err(|_| {
            StorageError::InvalidEnvelope("retention run list limit overflow".to_string())
        })?;
        let mut stmt = self.conn.prepare(
            "SELECT run_id, mode, started_at_ms, finished_at_ms, evaluated_sessions,
                    deleted_sessions, failed_sessions, report_json
             FROM retention_runs
             ORDER BY started_at_ms DESC, run_id ASC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |row| {
            let mode: String = row.get(1)?;
            let report_json: String = row.get(7)?;
            let report_value: Value = serde_json::from_str(&report_json).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    7,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?;
            let embedded = report_value.get("report").cloned().unwrap_or(Value::Null);
            if embedded.is_object() {
                return serde_json::from_value::<RetentionRunReportV1>(embedded).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        7,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                });
            }
            Ok(RetentionRunReportV1 {
                run_id: row.get(0)?,
                mode: parse_retention_mode(&mode)?,
                started_at_ms: row.get(2)?,
                finished_at_ms: row.get(3)?,
                evaluated_sessions: u32::try_from(row.get::<_, i64>(4)?.max(0)).unwrap_or(u32::MAX),
                candidate_sessions: 0,
                deleted_sessions: u32::try_from(row.get::<_, i64>(5)?.max(0)).unwrap_or(u32::MAX),
                skipped_running_sessions: 0,
                failed_sessions: u32::try_from(row.get::<_, i64>(6)?.max(0)).unwrap_or(u32::MAX),
            })
        })?;
        let mut output = Vec::new();
        for row in rows {
            output.push(row?);
        }
        Ok(output)
    }

    pub fn ui_get_retention_settings(&self) -> Result<UiRetentionSettingsV1> {
        Ok(UiRetentionSettingsV1 { policy: self.get_retention_policy()? })
    }

    pub fn ui_delete_session(
        &self,
        session_id: &str,
        now_ms: i64,
    ) -> Result<UiDeleteSessionResultV1> {
        Ok(UiDeleteSessionResultV1 {
            result: self.delete_session_with_artifacts(session_id, now_ms)?,
        })
    }

    fn load_ended_sessions(&self) -> Result<Vec<(String, i64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT session_id, ended_at_ms
             FROM sessions
             WHERE ended_at_ms IS NOT NULL
             ORDER BY ended_at_ms ASC, session_id ASC",
        )?;
        let rows =
            stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)))?;
        let mut output = Vec::new();
        for row in rows {
            output.push(row?);
        }
        Ok(output)
    }

    fn load_managed_roots(&self, key: &str, fallback: PathBuf) -> Result<Vec<PathBuf>> {
        let raw: Option<String> = self
            .conn
            .query_row(
                "SELECT value_json FROM app_settings WHERE setting_key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?;
        let Some(raw) = raw else {
            return Ok(vec![fallback]);
        };
        let parsed: Value = serde_json::from_str(&raw)?;
        let mut roots: Vec<PathBuf> = Vec::new();
        match parsed {
            Value::String(path) => roots.push(PathBuf::from(path)),
            Value::Array(items) => {
                for item in items {
                    if let Some(path) = item.as_str() {
                        roots.push(PathBuf::from(path));
                    }
                }
            }
            _ => {}
        }
        if roots.is_empty() {
            roots.push(fallback);
        }
        Ok(roots)
    }

    pub fn get_diagnostics_ui(&self, session_id: Option<&str>) -> Result<UiDiagnosticsSnapshotV1> {
        let capture_drop_markers =
            count_marker_events(&self.conn, session_id, "DTT.capture_drop.v1")?;
        let capture_limit_markers =
            count_marker_events(&self.conn, session_id, "DTT.capture_limit.v1")?;
        Ok(UiDiagnosticsSnapshotV1 {
            pairing_port: None,
            pairing_token: None,
            connection_status: UiConnectionStatusV1::Disconnected,
            diagnostics: self.list_bridge_diagnostics(session_id, 200)?,
            capture_drop_markers,
            capture_limit_markers,
        })
    }

    pub fn resolve_evidence_ui(
        &self,
        evidence_ref_id: &str,
    ) -> Result<Option<UiEvidenceResolveResultV1>> {
        let row = self
            .conn
            .query_row(
                "SELECT e.ref_json
                 FROM evidence_refs e
                 WHERE e.evidence_ref_id = ?1",
                params![evidence_ref_id],
                |r| r.get::<_, String>(0),
            )
            .optional()?;
        let Some(ref_json) = row else {
            return Ok(None);
        };

        let evidence: EvidenceRefV1 = serde_json::from_str(&ref_json)?;

        let (route_subview, target_id, column, json_pointer, container_json) =
            match &evidence.target {
                EvidenceTarget::RawEvent(target) => (
                    "timeline".to_string(),
                    target.event_id.clone(),
                    None,
                    target.json_pointer.clone(),
                    self.load_raw_event_container(&target.event_id)?,
                ),
                EvidenceTarget::NetRow(target) => (
                    "network".to_string(),
                    target.net_request_id.clone(),
                    target.column.clone(),
                    target.json_pointer.clone(),
                    self.load_net_row_container(target.table, &target.net_request_id)?,
                ),
                EvidenceTarget::Console(target) => (
                    "console".to_string(),
                    target.console_id.clone(),
                    target.column.clone(),
                    target.json_pointer.clone(),
                    self.load_console_container(&target.console_id)?,
                ),
                EvidenceTarget::DerivedMetric(target) => (
                    "findings".to_string(),
                    target.metric_name.clone(),
                    None,
                    None,
                    Some(serde_json::to_value(target)?),
                ),
            };

        let mut exact_pointer_found = false;
        let mut fallback_reason: Option<String> = None;
        let mut highlighted_value: Option<Value> = None;

        if let Some(pointer) = json_pointer.as_deref() {
            if let Some(container) = container_json.as_ref() {
                if let Some(found) = container.pointer(pointer) {
                    exact_pointer_found = true;
                    highlighted_value = Some(found.clone());
                } else {
                    fallback_reason = Some("Exact pointer unavailable".to_string());
                }
            } else {
                fallback_reason = Some("Target container is unavailable".to_string());
            }
        } else {
            exact_pointer_found = true;
        }

        Ok(Some(UiEvidenceResolveResultV1 {
            evidence_ref_id: evidence_ref_id.to_string(),
            session_id: evidence.session_id,
            kind: evidence.kind,
            route_subview,
            target_id,
            column,
            json_pointer,
            exact_pointer_found,
            fallback_reason,
            container_json,
            highlighted_value,
        }))
    }

    fn load_claims_for_finding(&self, finding_id: &str) -> Result<Vec<UiClaimV1>> {
        let mut claims: Vec<UiClaimV1> = Vec::new();
        let mut stmt = self.conn.prepare(
            "SELECT claim_id, claim_rank, truth, title, summary, confidence_score
             FROM claims
             WHERE finding_id = ?1
             ORDER BY claim_rank ASC, claim_id ASC",
        )?;
        let rows = stmt.query_map(params![finding_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, f64>(5)?,
            ))
        })?;
        for row in rows {
            let (claim_id, claim_rank, truth, title, summary, confidence_score) = row?;
            let evidence_refs = self.load_evidence_refs_for_claim(&claim_id)?;
            claims.push(UiClaimV1 {
                claim_id,
                rank: u32::try_from(claim_rank.max(0)).unwrap_or(u32::MAX),
                truth: parse_claim_truth(&truth)?,
                title,
                summary,
                confidence_score,
                evidence_refs,
            });
        }
        Ok(claims)
    }

    fn load_findings_rows<P>(&self, sql: &str, params: P) -> Result<Vec<UiFindingCardV1>>
    where
        P: rusqlite::Params,
    {
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map(params, |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, f64>(8)?,
                row.get::<_, i64>(9)?,
                row.get::<_, Option<String>>(10)?,
                row.get::<_, Option<String>>(11)?,
            ))
        })?;

        let mut output: Vec<UiFindingCardV1> = Vec::new();
        for row in rows {
            let (
                finding_id,
                found_session_id,
                detector_id,
                detector_version,
                title,
                summary,
                category,
                severity_score,
                confidence_score,
                created_at_ms,
                interaction_id,
                fix_steps_json,
            ) = row?;

            let fix_steps = parse_fix_steps(fix_steps_json.as_deref())?;
            let claims = self.load_claims_for_finding(&finding_id)?;

            output.push(UiFindingCardV1 {
                finding_id,
                session_id: found_session_id,
                detector_id,
                detector_version,
                title,
                summary,
                category,
                severity_score: u8::try_from(severity_score.max(0)).unwrap_or(u8::MAX),
                confidence_score,
                created_at_ms,
                interaction_id,
                fix_steps_json: fix_steps,
                claims,
            });
        }
        Ok(output)
    }

    fn load_evidence_refs_for_claim(&self, claim_id: &str) -> Result<Vec<EvidenceRefV1>> {
        let mut output: Vec<EvidenceRefV1> = Vec::new();
        let mut stmt = self.conn.prepare(
            "SELECT ref_json
             FROM evidence_refs
             WHERE claim_id = ?1
             ORDER BY evidence_rank ASC, evidence_ref_id ASC",
        )?;
        let rows = stmt.query_map(params![claim_id], |row| row.get::<_, String>(0))?;
        for row in rows {
            let ref_json = row?;
            output.push(serde_json::from_str::<EvidenceRefV1>(&ref_json)?);
        }
        Ok(output)
    }

    fn load_raw_event_container(&self, event_id: &str) -> Result<Option<Value>> {
        let row = self
            .conn
            .query_row(
                "SELECT payload_encoding, payload_bytes FROM events_raw WHERE event_id = ?1",
                params![event_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?;
        let Some((encoding, payload)) = row else {
            return Ok(None);
        };
        Ok(Some(decode_raw_payload(&encoding, &payload)?))
    }

    fn load_console_container(&self, console_id: &str) -> Result<Option<Value>> {
        let row = self
            .conn
            .query_row(
                "SELECT json_object(
                    'console_id', console_id,
                    'ts_ms', ts_ms,
                    'level', level,
                    'source', source,
                    'message_redacted', message_redacted,
                    'message_hash', message_hash,
                    'message_len', message_len
                 )
                 FROM console_entries WHERE console_id = ?1",
                params![console_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten();
        row.map_or(Ok(None), |json| Ok(Some(serde_json::from_str(&json)?)))
    }

    fn load_net_row_container(
        &self,
        table: NetTable,
        net_request_id: &str,
    ) -> Result<Option<Value>> {
        let query = match table {
            NetTable::NetworkRequests => {
                "SELECT json_object(
                    'net_request_id', net_request_id,
                    'started_at_ms', started_at_ms,
                    'ts_ms', ts_ms,
                    'method', method,
                    'scheme', scheme,
                    'host', host,
                    'port', port,
                    'path', path,
                    'query', query,
                    'request_headers_json', request_headers_json,
                    'timing_json', timing_json
                 ) FROM network_requests WHERE net_request_id = ?1"
            }
            NetTable::NetworkResponses => {
                "SELECT json_object(
                    'net_request_id', net_request_id,
                    'ts_ms', ts_ms,
                    'status_code', status_code,
                    'protocol', protocol,
                    'mime_type', mime_type,
                    'encoded_data_length', encoded_data_length,
                    'response_headers_json', response_headers_json,
                    'headers_hash', headers_hash,
                    'stream_summary_json', stream_summary_json
                 ) FROM network_responses WHERE net_request_id = ?1"
            }
            NetTable::NetworkCompletion => {
                "SELECT json_object(
                    'net_request_id', net_request_id,
                    'ts_ms', ts_ms,
                    'finished_at_ms', finished_at_ms,
                    'duration_ms', duration_ms,
                    'success', success,
                    'error_text', error_text,
                    'canceled', canceled,
                    'blocked_reason', blocked_reason
                 ) FROM network_completion WHERE net_request_id = ?1"
            }
        };

        let row = self
            .conn
            .query_row(query, params![net_request_id], |row| row.get::<_, Option<String>>(0))
            .optional()?
            .flatten();
        row.map_or(Ok(None), |json| Ok(Some(serde_json::from_str(&json)?)))
    }

    pub fn debug_dump_correlation_rows(&self, session_id: &str) -> Result<Vec<String>> {
        dump_correlation_rows(&self.conn, session_id)
    }

    pub fn debug_dump_analysis_rows(&self, session_id: &str) -> Result<Vec<String>> {
        dump_analysis_rows(&self.conn, session_id)
    }

    #[must_use]
    pub fn session_count(&self) -> usize {
        self.conn
            .query_row("SELECT COUNT(1) FROM sessions", [], |row| row.get::<_, i64>(0))
            .unwrap_or(0)
            .try_into()
            .unwrap_or(0)
    }

    #[must_use]
    pub fn events_raw_count(&self) -> usize {
        self.conn
            .query_row("SELECT COUNT(1) FROM events_raw", [], |row| row.get::<_, i64>(0))
            .unwrap_or(0)
            .try_into()
            .unwrap_or(0)
    }

    #[must_use]
    pub fn session_ended_at_ms(&self, session_id: &str) -> Option<i64> {
        self.conn
            .query_row(
                "SELECT ended_at_ms FROM sessions WHERE session_id = ?1",
                params![session_id],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()
            .ok()
            .flatten()
            .flatten()
    }

    #[must_use]
    pub fn schema_version(&self) -> Option<String> {
        self.conn
            .query_row("SELECT current_version FROM schema_meta WHERE id = 1", [], |row| {
                row.get::<_, String>(0)
            })
            .optional()
            .ok()
            .flatten()
    }

    fn bootstrap_migration_tables(&self) -> Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_meta (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                current_version TEXT NOT NULL,
                min_compatible_version TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS schema_migrations (
                migration_id TEXT PRIMARY KEY,
                checksum TEXT NOT NULL,
                applied_at_ms INTEGER NOT NULL
             );",
        )?;

        Ok(())
    }

    fn apply_migration(&self, migration: Migration) -> Result<()> {
        let checksum = blake3_hash_hex(migration.sql.as_bytes());
        let existing_checksum: Option<String> = self
            .conn
            .query_row(
                "SELECT checksum FROM schema_migrations WHERE migration_id = ?1",
                params![migration.id],
                |row| row.get(0),
            )
            .optional()?;

        if let Some(existing) = existing_checksum {
            if existing == checksum {
                return Ok(());
            }

            return Err(StorageError::MigrationChecksumMismatch { migration_id: migration.id });
        }

        self.conn.execute_batch(migration.sql)?;
        self.conn.execute(
            "INSERT INTO schema_migrations (migration_id, checksum, applied_at_ms)
             VALUES (?1, ?2, ?3)",
            params![migration.id, checksum, now_unix_ms()?],
        )?;

        Ok(())
    }
}

#[derive(Clone, Copy)]
struct Migration {
    id: &'static str,
    sql: &'static str,
}

const MIGRATIONS: &[Migration] = &[
    Migration { id: "001_schema_v1", sql: include_str!("../migrations/001_schema_v1.sql") },
    Migration {
        id: "002_normalization_columns_v1",
        sql: include_str!("../migrations/002_normalization_columns_v1.sql"),
    },
    Migration { id: "003_exports_v1", sql: include_str!("../migrations/003_exports_v1.sql") },
    Migration {
        id: "004_retention_hardening_v1",
        sql: include_str!("../migrations/004_retention_hardening_v1.sql"),
    },
    Migration {
        id: "005_release_ops_v1",
        sql: include_str!("../migrations/005_release_ops_v1.sql"),
    },
    Migration {
        id: "006_phase11_reliability_perf_v1",
        sql: include_str!("../migrations/006_phase11_reliability_perf_v1.sql"),
    },
    Migration {
        id: "007_phase12_release_telemetry_endurance_v1",
        sql: include_str!("../migrations/007_phase12_release_telemetry_endurance_v1.sql"),
    },
    Migration {
        id: "008_phase13_public_updates_audit_anomaly_v1",
        sql: include_str!("../migrations/008_phase13_public_updates_audit_anomaly_v1.sql"),
    },
    Migration {
        id: "009_phase14_rollout_ops_scorecard_v1",
        sql: include_str!("../migrations/009_phase14_rollout_ops_scorecard_v1.sql"),
    },
    Migration { id: "010_pairing_ux_v2", sql: include_str!("../migrations/010_pairing_ux_v2.sql") },
];

fn parse_redaction_level(value: &str) -> Result<RedactionLevel> {
    match value {
        "metadata_only" => Ok(RedactionLevel::MetadataOnly),
        "redacted" => Ok(RedactionLevel::Redacted),
        "full" => Ok(RedactionLevel::Full),
        _ => Err(StorageError::InvalidEnvelope(format!("unknown redaction level: {value}"))),
    }
}

fn parse_claim_truth(value: &str) -> Result<ClaimTruth> {
    match value {
        "verified" => Ok(ClaimTruth::Verified),
        "inferred" => Ok(ClaimTruth::Inferred),
        "unknown" => Ok(ClaimTruth::Unknown),
        _ => Err(StorageError::InvalidEnvelope(format!("unknown claim truth: {value}"))),
    }
}

fn parse_interaction_kind(value: &str) -> Result<InteractionKindV1> {
    match value {
        "page_load" => Ok(InteractionKindV1::PageLoad),
        "api_burst" => Ok(InteractionKindV1::ApiBurst),
        "llm_message" => Ok(InteractionKindV1::LlmMessage),
        "llm_regen" => Ok(InteractionKindV1::LlmRegen),
        "upload" => Ok(InteractionKindV1::Upload),
        "other" => Ok(InteractionKindV1::Other),
        _ => Err(StorageError::InvalidEnvelope(format!("unknown interaction kind: {value}"))),
    }
}

fn parse_fix_steps(value: Option<&str>) -> Result<Vec<FixStepV1>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    if value.trim().is_empty() {
        return Ok(Vec::new());
    }
    Ok(serde_json::from_str::<Vec<FixStepV1>>(value)?)
}

fn parse_export_profile(value: &str) -> std::result::Result<ExportProfileV1, rusqlite::Error> {
    match value {
        "share_safe" => Ok(ExportProfileV1::ShareSafe),
        "full" => Ok(ExportProfileV1::Full),
        _ => Err(rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            Box::new(StorageError::InvalidEnvelope(format!("unknown export profile: {value}"))),
        )),
    }
}

fn parse_export_status(value: &str) -> std::result::Result<ExportRunStatusV1, rusqlite::Error> {
    match value {
        "queued" => Ok(ExportRunStatusV1::Queued),
        "running" => Ok(ExportRunStatusV1::Running),
        "completed" => Ok(ExportRunStatusV1::Completed),
        "failed" => Ok(ExportRunStatusV1::Failed),
        "invalid" => Ok(ExportRunStatusV1::Invalid),
        _ => Err(rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            Box::new(StorageError::InvalidEnvelope(format!("unknown export run status: {value}"))),
        )),
    }
}

fn parse_release_channel(value: &str) -> std::result::Result<ReleaseChannelV1, rusqlite::Error> {
    match value {
        "internal_beta" => Ok(ReleaseChannelV1::InternalBeta),
        "staged_public_prerelease" => Ok(ReleaseChannelV1::StagedPublicPrerelease),
        _ => Err(rusqlite::Error::FromSqlConversionFailure(
            value.len(),
            rusqlite::types::Type::Text,
            Box::new(StorageError::InvalidEnvelope(format!("unknown release channel: {value}"))),
        )),
    }
}

fn parse_extension_channel(
    value: &str,
) -> std::result::Result<ExtensionChannelV1, rusqlite::Error> {
    match value {
        "chrome_store_public" => Ok(ExtensionChannelV1::ChromeStorePublic),
        _ => Err(rusqlite::Error::FromSqlConversionFailure(
            value.len(),
            rusqlite::types::Type::Text,
            Box::new(StorageError::InvalidEnvelope(format!("unknown extension channel: {value}"))),
        )),
    }
}

fn extension_channel_as_str(value: ExtensionChannelV1) -> &'static str {
    match value {
        ExtensionChannelV1::ChromeStorePublic => "chrome_store_public",
    }
}

fn parse_rollout_stage(value: &str) -> std::result::Result<RolloutStageV1, rusqlite::Error> {
    match value {
        "pct_5" => Ok(RolloutStageV1::Pct5),
        "pct_25" => Ok(RolloutStageV1::Pct25),
        "pct_50" => Ok(RolloutStageV1::Pct50),
        "pct_100" => Ok(RolloutStageV1::Pct100),
        _ => Err(rusqlite::Error::FromSqlConversionFailure(
            value.len(),
            rusqlite::types::Type::Text,
            Box::new(StorageError::InvalidEnvelope(format!("unknown rollout stage: {value}"))),
        )),
    }
}

fn rollout_stage_as_str(value: RolloutStageV1) -> &'static str {
    match value {
        RolloutStageV1::Pct5 => "pct_5",
        RolloutStageV1::Pct25 => "pct_25",
        RolloutStageV1::Pct50 => "pct_50",
        RolloutStageV1::Pct100 => "pct_100",
    }
}

fn parse_rollout_status(value: &str) -> std::result::Result<RolloutStatusV1, rusqlite::Error> {
    match value {
        "planned" => Ok(RolloutStatusV1::Planned),
        "active" => Ok(RolloutStatusV1::Active),
        "promoted" => Ok(RolloutStatusV1::Promoted),
        "paused" => Ok(RolloutStatusV1::Paused),
        "completed" => Ok(RolloutStatusV1::Completed),
        "failed" => Ok(RolloutStatusV1::Failed),
        _ => Err(rusqlite::Error::FromSqlConversionFailure(
            value.len(),
            rusqlite::types::Type::Text,
            Box::new(StorageError::InvalidEnvelope(format!("unknown rollout status: {value}"))),
        )),
    }
}

fn rollout_status_as_str(value: RolloutStatusV1) -> &'static str {
    match value {
        RolloutStatusV1::Planned => "planned",
        RolloutStatusV1::Active => "active",
        RolloutStatusV1::Promoted => "promoted",
        RolloutStatusV1::Paused => "paused",
        RolloutStatusV1::Completed => "completed",
        RolloutStatusV1::Failed => "failed",
    }
}

fn parse_rollout_health_status(
    value: &str,
) -> std::result::Result<RolloutHealthStatusV1, rusqlite::Error> {
    match value {
        "pass" => Ok(RolloutHealthStatusV1::Pass),
        "warn" => Ok(RolloutHealthStatusV1::Warn),
        "fail" => Ok(RolloutHealthStatusV1::Fail),
        _ => Err(rusqlite::Error::FromSqlConversionFailure(
            value.len(),
            rusqlite::types::Type::Text,
            Box::new(StorageError::InvalidEnvelope(format!(
                "unknown rollout health status: {value}"
            ))),
        )),
    }
}

fn rollout_health_status_as_str(value: RolloutHealthStatusV1) -> &'static str {
    match value {
        RolloutHealthStatusV1::Pass => "pass",
        RolloutHealthStatusV1::Warn => "warn",
        RolloutHealthStatusV1::Fail => "fail",
    }
}

fn parse_rollout_gate_reason(
    value: &str,
) -> std::result::Result<RolloutGateReasonV1, rusqlite::Error> {
    match value {
        "manual_smoke_missing" => Ok(RolloutGateReasonV1::ManualSmokeMissing),
        "compliance_failed" => Ok(RolloutGateReasonV1::ComplianceFailed),
        "telemetry_audit_failed" => Ok(RolloutGateReasonV1::TelemetryAuditFailed),
        "anomaly_budget_failed" => Ok(RolloutGateReasonV1::AnomalyBudgetFailed),
        "incident_budget_failed" => Ok(RolloutGateReasonV1::IncidentBudgetFailed),
        "signature_invalid" => Ok(RolloutGateReasonV1::SignatureInvalid),
        "soak_incomplete" => Ok(RolloutGateReasonV1::SoakIncomplete),
        _ => Err(rusqlite::Error::FromSqlConversionFailure(
            value.len(),
            rusqlite::types::Type::Text,
            Box::new(StorageError::InvalidEnvelope(format!(
                "unknown rollout gate reason: {value}"
            ))),
        )),
    }
}

fn rollout_gate_reason_as_str(value: RolloutGateReasonV1) -> &'static str {
    match value {
        RolloutGateReasonV1::ManualSmokeMissing => "manual_smoke_missing",
        RolloutGateReasonV1::ComplianceFailed => "compliance_failed",
        RolloutGateReasonV1::TelemetryAuditFailed => "telemetry_audit_failed",
        RolloutGateReasonV1::AnomalyBudgetFailed => "anomaly_budget_failed",
        RolloutGateReasonV1::IncidentBudgetFailed => "incident_budget_failed",
        RolloutGateReasonV1::SignatureInvalid => "signature_invalid",
        RolloutGateReasonV1::SoakIncomplete => "soak_incomplete",
    }
}

#[allow(dead_code)]
fn parse_rollout_controller_action(
    value: &str,
) -> std::result::Result<RolloutControllerActionV1, rusqlite::Error> {
    match value {
        "advance" => Ok(RolloutControllerActionV1::Advance),
        "pause" => Ok(RolloutControllerActionV1::Pause),
        "block" => Ok(RolloutControllerActionV1::Block),
        "noop" => Ok(RolloutControllerActionV1::Noop),
        _ => Err(rusqlite::Error::FromSqlConversionFailure(
            value.len(),
            rusqlite::types::Type::Text,
            Box::new(StorageError::InvalidEnvelope(format!(
                "unknown rollout controller action: {value}"
            ))),
        )),
    }
}

fn rollout_controller_action_as_str(value: RolloutControllerActionV1) -> &'static str {
    match value {
        RolloutControllerActionV1::Advance => "advance",
        RolloutControllerActionV1::Pause => "pause",
        RolloutControllerActionV1::Block => "block",
        RolloutControllerActionV1::Noop => "noop",
    }
}

fn parse_update_channel(value: &str) -> std::result::Result<UpdateChannelV1, rusqlite::Error> {
    match value {
        "internal_beta" => Ok(UpdateChannelV1::InternalBeta),
        "staged_public_prerelease" => Ok(UpdateChannelV1::StagedPublicPrerelease),
        "public_stable" => Ok(UpdateChannelV1::PublicStable),
        _ => Err(rusqlite::Error::FromSqlConversionFailure(
            value.len(),
            rusqlite::types::Type::Text,
            Box::new(StorageError::InvalidEnvelope(format!("unknown update channel: {value}"))),
        )),
    }
}

fn update_channel_as_str(value: UpdateChannelV1) -> &'static str {
    match value {
        UpdateChannelV1::InternalBeta => "internal_beta",
        UpdateChannelV1::StagedPublicPrerelease => "staged_public_prerelease",
        UpdateChannelV1::PublicStable => "public_stable",
    }
}

fn parse_release_status(value: &str) -> std::result::Result<ReleaseRunStatusV1, rusqlite::Error> {
    match value {
        "queued" => Ok(ReleaseRunStatusV1::Queued),
        "running" => Ok(ReleaseRunStatusV1::Running),
        "completed" => Ok(ReleaseRunStatusV1::Completed),
        "failed" => Ok(ReleaseRunStatusV1::Failed),
        _ => Err(rusqlite::Error::FromSqlConversionFailure(
            value.len(),
            rusqlite::types::Type::Text,
            Box::new(StorageError::InvalidEnvelope(format!("unknown release status: {value}"))),
        )),
    }
}

fn parse_reliability_metric_key(
    value: &str,
) -> std::result::Result<ReliabilityMetricKeyV1, rusqlite::Error> {
    match value {
        "ws_disconnect_count" => Ok(ReliabilityMetricKeyV1::WsDisconnectCount),
        "ws_reconnect_count" => Ok(ReliabilityMetricKeyV1::WsReconnectCount),
        "capture_drop_count" => Ok(ReliabilityMetricKeyV1::CaptureDropCount),
        "capture_limit_count" => Ok(ReliabilityMetricKeyV1::CaptureLimitCount),
        "command_timeout_count" => Ok(ReliabilityMetricKeyV1::CommandTimeoutCount),
        "session_pipeline_fail_count" => Ok(ReliabilityMetricKeyV1::SessionPipelineFailCount),
        "permission_denied_count" => Ok(ReliabilityMetricKeyV1::PermissionDeniedCount),
        "already_attached_count" => Ok(ReliabilityMetricKeyV1::AlreadyAttachedCount),
        _ => Err(rusqlite::Error::FromSqlConversionFailure(
            value.len(),
            rusqlite::types::Type::Text,
            Box::new(StorageError::InvalidEnvelope(format!(
                "unknown reliability metric key: {value}"
            ))),
        )),
    }
}

fn reliability_metric_key_as_str(metric_key: ReliabilityMetricKeyV1) -> &'static str {
    match metric_key {
        ReliabilityMetricKeyV1::WsDisconnectCount => "ws_disconnect_count",
        ReliabilityMetricKeyV1::WsReconnectCount => "ws_reconnect_count",
        ReliabilityMetricKeyV1::CaptureDropCount => "capture_drop_count",
        ReliabilityMetricKeyV1::CaptureLimitCount => "capture_limit_count",
        ReliabilityMetricKeyV1::CommandTimeoutCount => "command_timeout_count",
        ReliabilityMetricKeyV1::SessionPipelineFailCount => "session_pipeline_fail_count",
        ReliabilityMetricKeyV1::PermissionDeniedCount => "permission_denied_count",
        ReliabilityMetricKeyV1::AlreadyAttachedCount => "already_attached_count",
    }
}

fn parse_perf_run_status(value: &str) -> std::result::Result<PerfRunStatusV1, rusqlite::Error> {
    match value {
        "queued" => Ok(PerfRunStatusV1::Queued),
        "running" => Ok(PerfRunStatusV1::Running),
        "completed" => Ok(PerfRunStatusV1::Completed),
        "failed" => Ok(PerfRunStatusV1::Failed),
        _ => Err(rusqlite::Error::FromSqlConversionFailure(
            value.len(),
            rusqlite::types::Type::Text,
            Box::new(StorageError::InvalidEnvelope(format!("unknown perf status: {value}"))),
        )),
    }
}

fn parse_perf_budget_result(
    value: &str,
) -> std::result::Result<PerfBudgetResultV1, rusqlite::Error> {
    match value {
        "pass" => Ok(PerfBudgetResultV1::Pass),
        "warn" => Ok(PerfBudgetResultV1::Warn),
        "fail" => Ok(PerfBudgetResultV1::Fail),
        _ => Err(rusqlite::Error::FromSqlConversionFailure(
            value.len(),
            rusqlite::types::Type::Text,
            Box::new(StorageError::InvalidEnvelope(format!("unknown perf budget result: {value}"))),
        )),
    }
}

fn perf_run_status_as_str(status: PerfRunStatusV1) -> &'static str {
    match status {
        PerfRunStatusV1::Queued => "queued",
        PerfRunStatusV1::Running => "running",
        PerfRunStatusV1::Completed => "completed",
        PerfRunStatusV1::Failed => "failed",
    }
}

fn perf_budget_result_as_str(value: PerfBudgetResultV1) -> &'static str {
    match value {
        PerfBudgetResultV1::Pass => "pass",
        PerfBudgetResultV1::Warn => "warn",
        PerfBudgetResultV1::Fail => "fail",
    }
}

fn release_channel_as_str(channel: ReleaseChannelV1) -> &'static str {
    match channel {
        ReleaseChannelV1::InternalBeta => "internal_beta",
        ReleaseChannelV1::StagedPublicPrerelease => "staged_public_prerelease",
    }
}

fn parse_release_visibility(
    value: &str,
) -> std::result::Result<ReleaseVisibilityV1, rusqlite::Error> {
    match value {
        "internal" => Ok(ReleaseVisibilityV1::Internal),
        "staged_public" => Ok(ReleaseVisibilityV1::StagedPublic),
        _ => Err(rusqlite::Error::FromSqlConversionFailure(
            value.len(),
            rusqlite::types::Type::Text,
            Box::new(StorageError::InvalidEnvelope(format!("unknown release visibility: {value}"))),
        )),
    }
}

fn release_visibility_as_str(value: ReleaseVisibilityV1) -> &'static str {
    match value {
        ReleaseVisibilityV1::Internal => "internal",
        ReleaseVisibilityV1::StagedPublic => "staged_public",
    }
}

fn parse_telemetry_mode(value: &str) -> std::result::Result<TelemetryModeV1, rusqlite::Error> {
    match value {
        "local_only" => Ok(TelemetryModeV1::LocalOnly),
        "local_plus_otlp" => Ok(TelemetryModeV1::LocalPlusOtlp),
        _ => Err(rusqlite::Error::FromSqlConversionFailure(
            value.len(),
            rusqlite::types::Type::Text,
            Box::new(StorageError::InvalidEnvelope(format!("unknown telemetry mode: {value}"))),
        )),
    }
}

fn telemetry_mode_as_str(value: TelemetryModeV1) -> &'static str {
    match value {
        TelemetryModeV1::LocalOnly => "local_only",
        TelemetryModeV1::LocalPlusOtlp => "local_plus_otlp",
    }
}

fn parse_telemetry_audit_status(
    value: &str,
) -> std::result::Result<TelemetryAuditStatusV1, rusqlite::Error> {
    match value {
        "pass" => Ok(TelemetryAuditStatusV1::Pass),
        "warn" => Ok(TelemetryAuditStatusV1::Warn),
        "fail" => Ok(TelemetryAuditStatusV1::Fail),
        _ => Err(rusqlite::Error::FromSqlConversionFailure(
            value.len(),
            rusqlite::types::Type::Text,
            Box::new(StorageError::InvalidEnvelope(format!(
                "unknown telemetry audit status: {value}"
            ))),
        )),
    }
}

fn status_as_str(value: TelemetryAuditStatusV1) -> &'static str {
    match value {
        TelemetryAuditStatusV1::Pass => "pass",
        TelemetryAuditStatusV1::Warn => "warn",
        TelemetryAuditStatusV1::Fail => "fail",
    }
}

fn parse_perf_anomaly_severity(
    value: &str,
) -> std::result::Result<PerfAnomalySeverityV1, rusqlite::Error> {
    match value {
        "low" => Ok(PerfAnomalySeverityV1::Low),
        "medium" => Ok(PerfAnomalySeverityV1::Medium),
        "high" => Ok(PerfAnomalySeverityV1::High),
        "critical" => Ok(PerfAnomalySeverityV1::Critical),
        _ => Err(rusqlite::Error::FromSqlConversionFailure(
            value.len(),
            rusqlite::types::Type::Text,
            Box::new(StorageError::InvalidEnvelope(format!(
                "unknown perf anomaly severity: {value}"
            ))),
        )),
    }
}

fn perf_anomaly_severity_as_str(value: PerfAnomalySeverityV1) -> &'static str {
    match value {
        PerfAnomalySeverityV1::Low => "low",
        PerfAnomalySeverityV1::Medium => "medium",
        PerfAnomalySeverityV1::High => "high",
        PerfAnomalySeverityV1::Critical => "critical",
    }
}

fn release_status_as_str(status: ReleaseRunStatusV1) -> &'static str {
    match status {
        ReleaseRunStatusV1::Queued => "queued",
        ReleaseRunStatusV1::Running => "running",
        ReleaseRunStatusV1::Completed => "completed",
        ReleaseRunStatusV1::Failed => "failed",
    }
}

fn release_platform_matrix(artifacts: &[ReleaseArtifactV1]) -> Vec<Value> {
    let mut rows: Vec<Value> = artifacts
        .iter()
        .map(|artifact| {
            serde_json::json!({
                "platform": artifact.platform,
                "arch": artifact.arch,
                "target_triple": artifact.target_triple,
            })
        })
        .collect();
    rows.sort_by(|left, right| {
        canonical_json_string(left)
            .unwrap_or_default()
            .cmp(&canonical_json_string(right).unwrap_or_default())
    });
    rows.dedup();
    rows
}

fn parse_perf_anomaly_row(
    row: &Row<'_>,
) -> std::result::Result<UiListPerfAnomaliesItemV1, rusqlite::Error> {
    let details_raw: String = row.get(8)?;
    let details_json = serde_json::from_str::<Value>(&details_raw).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(8, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(UiListPerfAnomaliesItemV1 {
        anomaly_id: row.get(0)?,
        run_kind: row.get(1)?,
        bucket_start_ms: row.get(2)?,
        metric_name: row.get(3)?,
        severity: parse_perf_anomaly_severity(row.get::<_, String>(4)?.as_str())?,
        score: row.get(5)?,
        baseline_value: row.get(6)?,
        observed_value: row.get(7)?,
        details_json,
        created_at_ms: row.get(9)?,
    })
}

fn parse_json_text<T: serde::de::DeserializeOwned>(
    value: &str,
) -> std::result::Result<T, rusqlite::Error> {
    serde_json::from_str::<T>(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
    })
}

fn parse_compliance_pack_list_row(
    row: &Row<'_>,
) -> std::result::Result<UiListComplianceEvidencePacksItemV1, rusqlite::Error> {
    Ok(UiListComplianceEvidencePacksItemV1 {
        pack_id: row.get(0)?,
        kind: row.get(1)?,
        channel: row.get(2)?,
        version: row.get(3)?,
        stage: row.get::<_, Option<String>>(4)?.as_deref().map(parse_rollout_stage).transpose()?,
        status: row.get(5)?,
        created_at_ms: row.get(6)?,
        pack_path: row.get(7)?,
        manifest_sha256: row.get(8)?,
    })
}

fn parse_compliance_pack_row(
    row: &Row<'_>,
) -> std::result::Result<ComplianceEvidencePackV1, rusqlite::Error> {
    let items_json = row.get::<_, String>(7)?;
    let items = parse_json_text::<Vec<ComplianceEvidenceItemV1>>(items_json.as_str())?;
    Ok(ComplianceEvidencePackV1 {
        pack_id: row.get(0)?,
        kind: row.get(1)?,
        channel: row.get(2)?,
        version: row.get(3)?,
        stage: row.get::<_, Option<String>>(4)?.as_deref().map(parse_rollout_stage).transpose()?,
        pack_path: row.get(5)?,
        manifest_sha256: row.get(6)?,
        items,
        created_at_ms: row.get(8)?,
        status: row.get(9)?,
        error_code: row.get(10)?,
        error_message: row.get(11)?,
    })
}

fn parse_retention_mode(value: &str) -> std::result::Result<RetentionRunModeV1, rusqlite::Error> {
    match value {
        "dry_run" => Ok(RetentionRunModeV1::DryRun),
        "apply" => Ok(RetentionRunModeV1::Apply),
        _ => Err(rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            Box::new(StorageError::InvalidEnvelope(format!("unknown retention run mode: {value}"))),
        )),
    }
}

fn retention_mode_as_str(mode: RetentionRunModeV1) -> &'static str {
    match mode {
        RetentionRunModeV1::DryRun => "dry_run",
        RetentionRunModeV1::Apply => "apply",
    }
}

fn parse_bundle_inspection_summary(
    inspect_id: &str,
    bundle_path: &str,
    integrity_valid: bool,
    summary_json: &Value,
) -> Result<UiBundleInspectOpenResultV1> {
    let session_id = summary_json.get("session_id").and_then(Value::as_str).map(ToOwned::to_owned);
    let exported_at_ms = summary_json.get("exported_at_ms").and_then(Value::as_i64);
    let privacy_mode = summary_json
        .get("privacy_mode")
        .and_then(Value::as_str)
        .map(parse_redaction_level)
        .transpose()?;
    let profile = summary_json
        .get("profile")
        .and_then(Value::as_str)
        .map(|value| match value {
            "share_safe" => Ok(ExportProfileV1::ShareSafe),
            "full" => Ok(ExportProfileV1::Full),
            _ => Err(StorageError::InvalidEnvelope(format!("unknown export profile: {value}"))),
        })
        .transpose()?;

    Ok(UiBundleInspectOpenResultV1 {
        inspect_id: inspect_id.to_string(),
        bundle_path: bundle_path.to_string(),
        integrity_valid,
        session_id,
        exported_at_ms,
        privacy_mode,
        profile,
    })
}

fn parse_optional_bool(value: Option<i64>) -> Option<bool> {
    value.map(|flag| flag != 0)
}

fn sort_json_key(left: &Value, right: &Value, key: &str) -> std::cmp::Ordering {
    let left_key = left.get(key).and_then(Value::as_str).unwrap_or_default();
    let right_key = right.get(key).and_then(Value::as_str).unwrap_or_default();
    left_key.cmp(right_key)
}

fn count_by_session(conn: &Connection, table: &str, session_id: &str) -> Result<u32> {
    let sql = format!("SELECT COUNT(1) FROM {table} WHERE session_id = ?1");
    let count = conn.query_row(&sql, params![session_id], |row| row.get::<_, i64>(0))?;
    Ok(u32::try_from(count.max(0)).unwrap_or(u32::MAX))
}

fn count_marker_events(
    conn: &Connection,
    session_id: Option<&str>,
    cdp_method: &str,
) -> Result<u64> {
    let count: i64 = match session_id {
        Some(session_id) => conn.query_row(
            "SELECT COUNT(1) FROM events_raw WHERE session_id = ?1 AND cdp_method = ?2",
            params![session_id, cdp_method],
            |row| row.get(0),
        )?,
        None => conn.query_row(
            "SELECT COUNT(1) FROM events_raw WHERE cdp_method = ?1",
            params![cdp_method],
            |row| row.get(0),
        )?,
    };
    Ok(u64::try_from(count.max(0)).unwrap_or(u64::MAX))
}

fn default_export_root() -> PathBuf {
    std::env::temp_dir().join("dtt-exports")
}

fn default_blob_root() -> PathBuf {
    std::env::temp_dir().join("dtt-blobs")
}

fn normalize_lexical_path(path: &Path) -> PathBuf {
    let mut normalized = if path.is_absolute() {
        PathBuf::new()
    } else {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"))
    };
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                let _ = normalized.pop();
            }
            _ => normalized.push(component.as_os_str()),
        }
    }
    normalized
}

fn is_under_any_root(path: &Path, roots: &[PathBuf]) -> bool {
    let normalized_path = normalize_lexical_path(path);
    roots
        .iter()
        .map(|root| normalize_lexical_path(root))
        .any(|root| normalized_path.starts_with(root))
}

fn delete_artifact_path(
    raw_path: &str,
    allowed_roots: &[PathBuf],
    result: &mut SessionDeleteResultV1,
) {
    let trimmed = raw_path.trim();
    if trimmed.is_empty() {
        return;
    }
    let path = PathBuf::from(trimmed);
    if !is_under_any_root(&path, allowed_roots) {
        result.blocked_paths.push(path.to_string_lossy().to_string());
        return;
    }

    if !path.exists() {
        result.missing_files.push(path.to_string_lossy().to_string());
        return;
    }

    let delete_result =
        if path.is_dir() { fs::remove_dir_all(&path) } else { fs::remove_file(&path) };

    match delete_result {
        Ok(()) => {
            result.files_deleted = result.files_deleted.saturating_add(1);
        }
        Err(error) => {
            result.errors.push(format!(
                "delete_artifact_io_error:{}:{}",
                path.to_string_lossy(),
                error
            ));
        }
    }
}

fn timeline_kind_rank(kind: UiTimelineKindV1) -> u8 {
    match kind {
        UiTimelineKindV1::RawEvent => 0,
        UiTimelineKindV1::ConsoleEntry => 1,
        UiTimelineKindV1::PageLifecycle => 2,
    }
}

fn sanitize_raw_event_for_share_safe(value: &Value) -> Value {
    const BODY_KEYS: &[&str] = &[
        "body",
        "bodybytes",
        "bodytext",
        "framedata",
        "payload",
        "payloaddata",
        "postdata",
        "postdataentries",
        "requestbody",
        "responsebody",
        "text",
    ];
    const HEADER_OBJECT_KEYS: &[&str] = &[
        "headers",
        "requestheaders",
        "responseheaders",
        "request_headers_json",
        "response_headers_json",
    ];
    const SENSITIVE_HEADER_KEYS: &[&str] = &[
        "authorization",
        "cookie",
        "set-cookie",
        "proxy-authorization",
        "x-api-key",
        "api-key",
        "token",
    ];

    fn sanitize(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut output = serde_json::Map::new();
                for (key, child) in map {
                    let lowered = key.to_ascii_lowercase();
                    if BODY_KEYS.iter().any(|body_key| *body_key == lowered) {
                        output.insert(key.clone(), Value::String("[stripped]".to_string()));
                        continue;
                    }
                    if HEADER_OBJECT_KEYS.iter().any(|header_key| *header_key == lowered) {
                        output.insert(key.clone(), sanitize_headers_object(child));
                        continue;
                    }
                    if SENSITIVE_HEADER_KEYS.iter().any(|header_key| *header_key == lowered) {
                        output.insert(key.clone(), Value::String("[redacted]".to_string()));
                        continue;
                    }
                    output.insert(key.clone(), sanitize(child));
                }
                Value::Object(output)
            }
            Value::Array(items) => Value::Array(items.iter().map(sanitize).collect()),
            _ => value.clone(),
        }
    }

    fn sanitize_headers_object(value: &Value) -> Value {
        let Value::Object(map) = value else {
            return sanitize(value);
        };
        let mut output = serde_json::Map::new();
        for (key, child) in map {
            let lowered = key.to_ascii_lowercase();
            let redacted = matches!(
                lowered.as_str(),
                "authorization"
                    | "cookie"
                    | "set-cookie"
                    | "proxy-authorization"
                    | "x-api-key"
                    | "api-key"
                    | "token"
            );
            if redacted {
                output.insert(key.clone(), Value::String("[redacted]".to_string()));
            } else {
                output.insert(key.clone(), sanitize(child));
            }
        }
        Value::Object(output)
    }

    sanitize(value)
}

fn now_unix_ms() -> Result<i64> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| StorageError::Clock)?;

    i64::try_from(duration.as_millis())
        .map_err(|_| StorageError::InvalidEnvelope("timestamp overflow".to_string()))
}

fn derive_event_id(session_id: &str, event_seq: i64, cdp_method: &str, ts_ms: i64) -> String {
    let input = format!("{session_id}:{event_seq}:{cdp_method}:{ts_ms}");
    format!("evr_{}", blake3_hash_hex(input.as_bytes()))
}

fn load_correlation_input(conn: &Connection, session_id: &str) -> Result<CorrelationInput> {
    let mut requests: Vec<RequestCandidateInput> = Vec::new();
    {
        let mut stmt = conn.prepare(
            "SELECT net_request_id, ts_ms, started_at_ms, method, host, path, scheme, request_headers_json
             FROM network_requests
             WHERE session_id = ?1
             ORDER BY started_at_ms, ts_ms, net_request_id",
        )?;
        let rows = stmt.query_map(params![session_id], |row| {
            let headers_json: Option<String> = row.get(7)?;
            let request_headers = parse_headers_json(headers_json.as_deref()).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    7,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?;
            Ok(RequestCandidateInput {
                net_request_id: row.get(0)?,
                ts_ms: row.get(1)?,
                started_at_ms: row.get(2)?,
                method: row.get(3)?,
                host: row.get(4)?,
                path: row.get(5)?,
                scheme: row.get(6)?,
                request_headers,
            })
        })?;
        for row in rows {
            requests.push(row?);
        }
    }

    let mut responses: Vec<ResponseCandidateInput> = Vec::new();
    {
        let mut stmt = conn.prepare(
            "SELECT net_request_id, ts_ms, status_code, mime_type, stream_summary_json
             FROM network_responses
             WHERE session_id = ?1
             ORDER BY ts_ms, net_request_id",
        )?;
        let rows = stmt.query_map(params![session_id], |row| {
            let stream_summary_json: Option<String> = row.get(4)?;
            let stream_transport =
                parse_stream_transport(stream_summary_json.as_deref()).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        4,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?;
            Ok(ResponseCandidateInput {
                net_request_id: row.get(0)?,
                ts_ms: row.get(1)?,
                status_code: row.get(2)?,
                mime_type: row.get(3)?,
                stream_transport,
            })
        })?;
        for row in rows {
            responses.push(row?);
        }
    }

    let mut completions: Vec<CompletionCandidateInput> = Vec::new();
    {
        let mut stmt = conn.prepare(
            "SELECT net_request_id, ts_ms, duration_ms, success
             FROM network_completion
             WHERE session_id = ?1
             ORDER BY ts_ms, net_request_id",
        )?;
        let rows = stmt.query_map(params![session_id], |row| {
            let success_int: Option<i64> = row.get(3)?;
            Ok(CompletionCandidateInput {
                net_request_id: row.get(0)?,
                ts_ms: row.get(1)?,
                duration_ms: row.get(2)?,
                success: success_int.map(|value| value != 0),
            })
        })?;
        for row in rows {
            completions.push(row?);
        }
    }

    let mut console_entries: Vec<ConsoleCandidateInput> = Vec::new();
    {
        let mut stmt = conn.prepare(
            "SELECT console_id, ts_ms
             FROM console_entries
             WHERE session_id = ?1
             ORDER BY ts_ms, console_id",
        )?;
        let rows = stmt.query_map(params![session_id], |row| {
            Ok(ConsoleCandidateInput { console_id: row.get(0)?, ts_ms: row.get(1)? })
        })?;
        for row in rows {
            console_entries.push(row?);
        }
    }

    let mut lifecycle_entries: Vec<LifecycleCandidateInput> = Vec::new();
    {
        let mut stmt = conn.prepare(
            "SELECT lifecycle_id, ts_ms, name
             FROM page_lifecycle
             WHERE session_id = ?1
             ORDER BY ts_ms, lifecycle_id",
        )?;
        let rows = stmt.query_map(params![session_id], |row| {
            Ok(LifecycleCandidateInput {
                lifecycle_id: row.get(0)?,
                ts_ms: row.get(1)?,
                name: row.get(2)?,
            })
        })?;
        for row in rows {
            lifecycle_entries.push(row?);
        }
    }

    let raw_request_hints = load_raw_request_hints(conn, session_id)?;

    Ok(CorrelationInput {
        session_id: session_id.to_string(),
        requests,
        responses,
        completions,
        console_entries,
        lifecycle_entries,
        raw_request_hints,
    })
}

fn load_raw_request_hints(conn: &Connection, session_id: &str) -> Result<Vec<RawRequestHintInput>> {
    let mut hints_by_request: HashMap<String, RawRequestHintInput> = HashMap::new();
    let mut stmt = conn.prepare(
        "SELECT cdp_method, payload_encoding, payload_bytes
         FROM events_raw
         WHERE session_id = ?1
         ORDER BY event_seq ASC",
    )?;

    let rows = stmt.query_map(params![session_id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Vec<u8>>(2)?))
    })?;

    for row in rows {
        let (cdp_method, payload_encoding, payload_bytes) = row?;
        let payload = decode_raw_payload(&payload_encoding, &payload_bytes)?;
        let Some(params) = payload.get("params") else {
            continue;
        };

        if cdp_method == "Network.requestWillBeSent" {
            let request_id = params.get("requestId").and_then(Value::as_str);
            if let Some(request_id) = request_id {
                let request_type = params.get("type").and_then(Value::as_str).map(str::to_string);
                hints_by_request
                    .entry(request_id.to_string())
                    .and_modify(|hint| hint.request_type = request_type.clone())
                    .or_insert(RawRequestHintInput {
                        net_request_id: request_id.to_string(),
                        request_type,
                        has_websocket_activity: false,
                    });
            }
            continue;
        }

        if cdp_method.starts_with("Network.webSocket") {
            let request_id = params
                .get("requestId")
                .or_else(|| params.get("identifier"))
                .and_then(Value::as_str);
            if let Some(request_id) = request_id {
                hints_by_request
                    .entry(request_id.to_string())
                    .and_modify(|hint| hint.has_websocket_activity = true)
                    .or_insert(RawRequestHintInput {
                        net_request_id: request_id.to_string(),
                        request_type: None,
                        has_websocket_activity: true,
                    });
            }
        }
    }

    let mut hints: Vec<RawRequestHintInput> = hints_by_request.into_values().collect();
    hints.sort_by(|left, right| left.net_request_id.cmp(&right.net_request_id));
    Ok(hints)
}

fn parse_headers_json(json: Option<&str>) -> Result<HeaderMap> {
    let Some(json) = json else {
        return Ok(HeaderMap::new());
    };
    if json.trim().is_empty() {
        return Ok(HeaderMap::new());
    }
    Ok(serde_json::from_str(json)?)
}

fn parse_stream_transport(json: Option<&str>) -> Result<Option<dtt_core::StreamTransport>> {
    let Some(json) = json else {
        return Ok(None);
    };
    if json.trim().is_empty() {
        return Ok(None);
    }
    let parsed: StreamSummaryV1 = serde_json::from_str(json)?;
    Ok(Some(parsed.transport))
}

fn load_correlation_config() -> Result<CorrelationConfig> {
    let telemetry_raw: Value =
        serde_json::from_str(include_str!("../../../config/telemetry.filters.v1.json"))?;
    let llm_raw: Value =
        serde_json::from_str(include_str!("../../../config/llm.fingerprints.v1.json"))?;

    let default_weights = LlmWeightsV1::default();
    let weights = llm_raw.get("weights").and_then(Value::as_object);

    Ok(CorrelationConfig {
        constants: dtt_core::CorrelationConstantsV1::default(),
        telemetry_host_substrings: extract_string_array(&telemetry_raw, "host_substrings"),
        telemetry_path_substrings: extract_string_array(&telemetry_raw, "path_substrings"),
        llm_provider_hosts: extract_string_array(&llm_raw, "provider_hosts"),
        llm_weights: LlmWeightsV1 {
            host_match: weights
                .and_then(|obj| obj.get("host_match"))
                .and_then(Value::as_i64)
                .unwrap_or(default_weights.host_match),
            streaming_signal: weights
                .and_then(|obj| obj.get("streaming_signal"))
                .and_then(Value::as_i64)
                .unwrap_or(default_weights.streaming_signal),
            content_type: weights
                .and_then(|obj| obj.get("content_type"))
                .and_then(Value::as_i64)
                .unwrap_or(default_weights.content_type),
            payload_markers: weights
                .and_then(|obj| obj.get("payload_markers"))
                .and_then(Value::as_i64)
                .unwrap_or(default_weights.payload_markers),
        },
        llm_primary_threshold: llm_raw
            .get("primary_threshold")
            .and_then(Value::as_i64)
            .unwrap_or(70),
    })
}

fn extract_string_array(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(Value::as_str)
                .map(|entry| entry.to_ascii_lowercase())
                .collect::<Vec<String>>()
        })
        .unwrap_or_default()
}

fn validate_primary_members(output: &CorrelationOutput) -> Result<()> {
    let mut primary_count_by_interaction: HashMap<&str, usize> = HashMap::new();
    for member in &output.members {
        if member.is_primary {
            *primary_count_by_interaction.entry(member.interaction_id.as_str()).or_insert(0) += 1;
        }
    }
    for interaction in &output.interactions {
        let primary_count = primary_count_by_interaction
            .get(interaction.interaction_id.as_str())
            .copied()
            .unwrap_or(0);
        if primary_count != 1 {
            return Err(StorageError::InvalidEnvelope(format!(
                "interaction {} has invalid primary count {primary_count}",
                interaction.interaction_id
            )));
        }
    }
    Ok(())
}

fn persist_correlation_output(
    conn: &mut Connection,
    session_id: &str,
    output: &CorrelationOutput,
) -> Result<()> {
    let tx = conn.transaction()?;
    tx.execute(
        "DELETE FROM interaction_members
         WHERE interaction_id IN (
           SELECT interaction_id FROM interactions WHERE session_id = ?1
         )",
        params![session_id],
    )?;
    tx.execute("DELETE FROM interactions WHERE session_id = ?1", params![session_id])?;

    for interaction in &output.interactions {
        tx.execute(
            "INSERT INTO interactions (
                interaction_id,
                session_id,
                interaction_kind,
                opened_at_ms,
                closed_at_ms,
                primary_member_id,
                rank
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                interaction.interaction_id,
                interaction.session_id,
                interaction_kind_as_str(interaction.interaction_kind),
                interaction.opened_at_ms,
                interaction.closed_at_ms,
                interaction.primary_member_id,
                i64::from(interaction.rank),
            ],
        )?;
    }

    for member in &output.members {
        tx.execute(
            "INSERT INTO interaction_members (
                interaction_id,
                member_type,
                member_id,
                member_rank,
                is_primary
            ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                member.interaction_id,
                interaction_member_type_as_str(member.member_type),
                member.member_id,
                i64::from(member.member_rank),
                if member.is_primary { 1 } else { 0 },
            ],
        )?;
    }

    tx.commit()?;
    Ok(())
}

fn dump_correlation_rows(conn: &Connection, session_id: &str) -> Result<Vec<String>> {
    let mut rows: Vec<String> = Vec::new();
    for statement in [
        "SELECT json_object('table','interactions','id',interaction_id,'v',json_object('kind',interaction_kind,'opened',opened_at_ms,'closed',closed_at_ms,'primary',primary_member_id,'rank',rank)) FROM interactions WHERE session_id=?1 ORDER BY opened_at_ms, interaction_kind, interaction_id",
        "SELECT json_object('table','interaction_members','id',im.interaction_id || ':' || im.member_type || ':' || im.member_id,'v',json_object('interaction_id',im.interaction_id,'member_type',im.member_type,'member_id',im.member_id,'member_rank',im.member_rank,'is_primary',im.is_primary)) FROM interaction_members im JOIN interactions i ON i.interaction_id = im.interaction_id WHERE i.session_id=?1 ORDER BY im.interaction_id, im.member_rank, im.member_type, im.member_id",
    ] {
        let mut stmt = conn.prepare(statement)?;
        let values = stmt.query_map(params![session_id], |row| row.get::<_, String>(0))?;
        for value in values {
            rows.push(value?);
        }
    }
    Ok(rows)
}

fn persist_detector_output(
    conn: &mut Connection,
    session_id: &str,
    run_report: &DetectorRunReport,
) -> Result<(usize, usize, usize)> {
    let tx = conn.transaction()?;
    tx.execute("DELETE FROM findings WHERE session_id = ?1", params![session_id])?;

    let mut findings_written = 0_usize;
    let mut claims_written = 0_usize;
    let mut evidence_refs_written = 0_usize;

    for finding in &run_report.findings {
        let fix_steps_json = canonical_json_string(&finding.fix_steps_json)?;
        tx.execute(
            "INSERT INTO findings (
                finding_id,
                session_id,
                detector_id,
                detector_version,
                title,
                summary,
                category,
                severity_score,
                confidence_score,
                created_at_ms,
                interaction_id,
                fix_steps_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                finding.finding_id,
                finding.session_id,
                finding.detector_id,
                finding.detector_version,
                finding.title,
                finding.summary,
                finding.category,
                i64::from(finding.severity_score),
                finding.confidence_score,
                finding.created_at_ms,
                finding.interaction_id,
                fix_steps_json,
            ],
        )?;
        findings_written += 1;

        for claim in &finding.claims {
            tx.execute(
                "INSERT INTO claims (
                    claim_id,
                    finding_id,
                    claim_rank,
                    truth,
                    title,
                    summary,
                    confidence_score
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    claim.claim_id,
                    claim.finding_id,
                    i64::from(claim.rank),
                    claim_truth_as_str(claim.truth),
                    claim.title,
                    claim.summary,
                    claim.confidence_score,
                ],
            )?;
            claims_written += 1;

            for (index, evidence_ref) in claim.evidence_refs.iter().enumerate() {
                let evidence_rank = i64::try_from(index + 1).map_err(|_| {
                    StorageError::InvalidEnvelope("evidence rank overflow".to_string())
                })?;
                let ref_json = canonical_json_string(evidence_ref)?;
                let target_signature = canonical_json_string(&evidence_ref.target)?;
                let evidence_ref_id = format!(
                    "evr_{}",
                    blake3_hash_hex(
                        format!(
                            "{}:{}:{}:{}",
                            claim.claim_id,
                            evidence_kind_as_str(evidence_ref.kind),
                            target_signature,
                            evidence_rank
                        )
                        .as_bytes()
                    )
                );
                tx.execute(
                    "INSERT INTO evidence_refs (
                        evidence_ref_id,
                        claim_id,
                        evidence_rank,
                        ref_json
                    ) VALUES (?1, ?2, ?3, ?4)",
                    params![evidence_ref_id, claim.claim_id, evidence_rank, ref_json],
                )?;
                evidence_refs_written += 1;
            }
        }
    }

    tx.commit()?;
    Ok((findings_written, claims_written, evidence_refs_written))
}

fn dump_analysis_rows(conn: &Connection, session_id: &str) -> Result<Vec<String>> {
    let mut rows: Vec<String> = Vec::new();
    for statement in [
        "SELECT json_object('table','findings','id',finding_id,'v',json_object('detector_id',detector_id,'severity_score',severity_score,'confidence_score',confidence_score,'interaction_id',interaction_id)) FROM findings WHERE session_id = ?1 ORDER BY severity_score DESC, detector_id, finding_id",
        "SELECT json_object('table','claims','id',c.claim_id,'v',json_object('finding_id',c.finding_id,'claim_rank',c.claim_rank,'truth',c.truth,'confidence_score',c.confidence_score)) FROM claims c JOIN findings f ON f.finding_id = c.finding_id WHERE f.session_id = ?1 ORDER BY c.finding_id, c.claim_rank, c.claim_id",
        "SELECT json_object('table','evidence_refs','id',e.evidence_ref_id,'v',json_object('claim_id',e.claim_id,'evidence_rank',e.evidence_rank,'ref_json',e.ref_json)) FROM evidence_refs e JOIN claims c ON c.claim_id = e.claim_id JOIN findings f ON f.finding_id = c.finding_id WHERE f.session_id = ?1 ORDER BY c.finding_id, e.evidence_rank, e.evidence_ref_id",
    ] {
        let mut stmt = conn.prepare(statement)?;
        let values = stmt.query_map(params![session_id], |row| row.get::<_, String>(0))?;
        for value in values {
            rows.push(value?);
        }
    }
    Ok(rows)
}

fn interaction_kind_as_str(kind: InteractionKindV1) -> &'static str {
    match kind {
        InteractionKindV1::PageLoad => "page_load",
        InteractionKindV1::ApiBurst => "api_burst",
        InteractionKindV1::LlmMessage => "llm_message",
        InteractionKindV1::LlmRegen => "llm_regen",
        InteractionKindV1::Upload => "upload",
        InteractionKindV1::Other => "other",
    }
}

fn interaction_member_type_as_str(member_type: InteractionMemberTypeV1) -> &'static str {
    match member_type {
        InteractionMemberTypeV1::NetworkRequest => "network_request",
        InteractionMemberTypeV1::NetworkResponse => "network_response",
        InteractionMemberTypeV1::NetworkCompletion => "network_completion",
        InteractionMemberTypeV1::ConsoleEntry => "console_entry",
        InteractionMemberTypeV1::PageLifecycle => "page_lifecycle",
        InteractionMemberTypeV1::RawEvent => "raw_event",
    }
}

fn claim_truth_as_str(truth: ClaimTruth) -> &'static str {
    match truth {
        ClaimTruth::Verified => "verified",
        ClaimTruth::Inferred => "inferred",
        ClaimTruth::Unknown => "unknown",
    }
}

fn evidence_kind_as_str(kind: EvidenceKind) -> &'static str {
    match kind {
        EvidenceKind::RawEvent => "raw_event",
        EvidenceKind::NetRow => "net_row",
        EvidenceKind::Console => "console",
        EvidenceKind::DerivedMetric => "derived_metric",
    }
}

pub(crate) fn decode_raw_payload(encoding: &str, payload: &[u8]) -> Result<Value> {
    let decoded = match encoding {
        "zstd" => zstd::stream::decode_all(Cursor::new(payload))?,
        "plain" => payload.to_vec(),
        other => {
            return Err(StorageError::InvalidEnvelope(format!(
                "unsupported payload encoding: {other}"
            )))
        }
    };

    Ok(serde_json::from_slice(&decoded)?)
}

pub(crate) fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>> {
    Ok(serde_json_canonicalizer::to_vec(value)?)
}

pub(crate) fn canonical_json_string(value: &impl serde::Serialize) -> Result<String> {
    Ok(serde_json_canonicalizer::to_string(value)?)
}

pub(crate) fn blake3_hash_hex(bytes: &[u8]) -> String {
    let mut hasher = Hasher::new();
    hasher.update(bytes);
    hasher.finalize().to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::{
        canonical_json_bytes, PerfAnomalyInsertInput, RolloutStageTransitionInput, Storage,
        UpdateRolloutStartInput,
    };
    use dtt_core::{
        ArtifactProvenanceV1, ComplianceEvidenceItemV1, ComplianceEvidencePackV1,
        ExportEvidenceIndexesV1, ExportManifestV1, ExportProfileV1, ExportRunStatusV1,
        ExtensionChannelV1, JsonEnvelope, ManifestIndexModeV1, OtlpSinkConfigV1,
        PerfAnomalySeverityV1, PerfBudgetResultV1, RedactionLevel, ReleaseArchV1,
        ReleaseArtifactKindV1, ReleaseChannelV1, ReleaseHealthMetricV1, ReleaseHealthScorecardV1,
        ReleasePlatformV1, ReleaseRunStatusV1, ReleaseVisibilityV1, ReliabilityMetricKeyV1,
        RetentionPolicyV1, RetentionRunModeV1, RolloutControllerActionV1, RolloutGateReasonV1,
        RolloutHealthStatusV1, RolloutStageV1, RolloutStatusV1, SigningStatusV1,
        TelemetryAuditStatusV1, TelemetryModeV1, UpdateChannelV1,
    };
    use rusqlite::params;
    use serde_json::json;
    use serde_json::Value;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn migration_apply_creates_schema_v1() {
        let mut storage = Storage::open_in_memory().expect("open in-memory db");
        storage.apply_migrations().expect("apply migrations");
        storage.apply_migrations().expect("idempotent migrations");

        assert_eq!(storage.schema_version().as_deref(), Some("1.0"));
        assert_eq!(storage.session_count(), 0);
        let release_runs_exists: i64 = storage
            .conn
            .query_row(
                "SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name='release_runs'",
                [],
                |row| row.get(0),
            )
            .expect("release_runs exists");
        let bundle_inspections_exists: i64 = storage
            .conn
            .query_row(
                "SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name='bundle_inspections'",
                [],
                |row| row.get(0),
            )
            .expect("bundle_inspections exists");
        let reliability_metrics_exists: i64 = storage
            .conn
            .query_row(
                "SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name='reliability_metrics'",
                [],
                |row| row.get(0),
            )
            .expect("reliability_metrics exists");
        let perf_runs_exists: i64 = storage
            .conn
            .query_row(
                "SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name='perf_runs'",
                [],
                |row| row.get(0),
            )
            .expect("perf_runs exists");
        let release_promotions_exists: i64 = storage
            .conn
            .query_row(
                "SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name='release_promotions'",
                [],
                |row| row.get(0),
            )
            .expect("release_promotions exists");
        let telemetry_settings_exists: i64 = storage
            .conn
            .query_row(
                "SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name='telemetry_settings'",
                [],
                |row| row.get(0),
            )
            .expect("telemetry_settings exists");
        let telemetry_exports_exists: i64 = storage
            .conn
            .query_row(
                "SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name='telemetry_exports'",
                [],
                |row| row.get(0),
            )
            .expect("telemetry_exports exists");
        let extension_rollouts_exists: i64 = storage
            .conn
            .query_row(
                "SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name='extension_rollouts'",
                [],
                |row| row.get(0),
            )
            .expect("extension_rollouts exists");
        let extension_compliance_exists: i64 = storage
            .conn
            .query_row(
                "SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name='extension_compliance_checks'",
                [],
                |row| row.get(0),
            )
            .expect("extension_compliance_checks exists");
        let update_rollouts_exists: i64 = storage
            .conn
            .query_row(
                "SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name='update_rollouts'",
                [],
                |row| row.get(0),
            )
            .expect("update_rollouts exists");
        let telemetry_audits_exists: i64 = storage
            .conn
            .query_row(
                "SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name='telemetry_audits'",
                [],
                |row| row.get(0),
            )
            .expect("telemetry_audits exists");
        let perf_anomalies_exists: i64 = storage
            .conn
            .query_row(
                "SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name='perf_anomalies'",
                [],
                |row| row.get(0),
            )
            .expect("perf_anomalies exists");
        let release_health_snapshots_exists: i64 = storage
            .conn
            .query_row(
                "SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name='release_health_snapshots'",
                [],
                |row| row.get(0),
            )
            .expect("release_health_snapshots exists");
        let rollout_stage_transitions_exists: i64 = storage
            .conn
            .query_row(
                "SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name='rollout_stage_transitions'",
                [],
                |row| row.get(0),
            )
            .expect("rollout_stage_transitions exists");
        let compliance_evidence_packs_exists: i64 = storage
            .conn
            .query_row(
                "SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name='compliance_evidence_packs'",
                [],
                |row| row.get(0),
            )
            .expect("compliance_evidence_packs exists");
        let trusted_devices_exists: i64 = storage
            .conn
            .query_row(
                "SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name='trusted_devices'",
                [],
                |row| row.get(0),
            )
            .expect("trusted_devices exists");
        assert_eq!(release_runs_exists, 1);
        assert_eq!(bundle_inspections_exists, 1);
        assert_eq!(reliability_metrics_exists, 1);
        assert_eq!(perf_runs_exists, 1);
        assert_eq!(release_promotions_exists, 1);
        assert_eq!(telemetry_settings_exists, 1);
        assert_eq!(telemetry_exports_exists, 1);
        assert_eq!(extension_rollouts_exists, 1);
        assert_eq!(extension_compliance_exists, 1);
        assert_eq!(update_rollouts_exists, 1);
        assert_eq!(telemetry_audits_exists, 1);
        assert_eq!(perf_anomalies_exists, 1);
        assert_eq!(release_health_snapshots_exists, 1);
        assert_eq!(rollout_stage_transitions_exists, 1);
        assert_eq!(compliance_evidence_packs_exists, 1);
        assert_eq!(trusted_devices_exists, 1);
    }

    #[test]
    fn pairing_context_roundtrip_in_settings() {
        let mut storage = Storage::open_in_memory().expect("open db");
        storage.apply_migrations().expect("apply migrations");
        assert_eq!(storage.get_pairing_context().expect("get empty"), None);

        storage
            .set_pairing_context(32124, "0123456789abcdef0123456789abcdef")
            .expect("set pairing");
        let read = storage.get_pairing_context().expect("get pairing");
        assert_eq!(read, Some((32124, "0123456789abcdef0123456789abcdef".to_string())));
    }

    #[test]
    fn trusted_device_upsert_and_revoke_is_deterministic() {
        let mut storage = Storage::open_in_memory().expect("open db");
        storage.apply_migrations().expect("apply migrations");

        let first =
            storage.upsert_trusted_device("chrome_dev", "Chrome", 100).expect("upsert first");
        assert_eq!(first.device_id, "chrome_dev");
        assert!(!first.revoked);

        let second = storage
            .upsert_trusted_device("chrome_dev", "Chrome Stable", 120)
            .expect("upsert second");
        assert_eq!(second.browser_label, "Chrome Stable");
        assert_eq!(second.first_paired_at_ms, 100);
        assert_eq!(second.last_seen_at_ms, 120);
        assert!(!second.revoked);

        storage.revoke_trusted_device("chrome_dev", 130).expect("revoke");
        let listed = storage.list_trusted_devices(10).expect("list");
        assert_eq!(listed.len(), 1);
        assert!(listed[0].revoked);
        assert_eq!(listed[0].last_seen_at_ms, 130);
    }

    #[test]
    fn ingest_writes_session_and_raw_event() {
        let mut storage = Storage::open_in_memory().expect("open in-memory db");
        storage.apply_migrations().expect("apply migrations");

        let envelope: JsonEnvelope = serde_json::from_value(json!({
            "v": 1,
            "type": "evt.raw_event",
            "ts_ms": 1729000000000_i64,
            "request_id": "req_1",
            "correlation_id": "corr_1",
            "session_id": "sess_1",
            "event_seq": 7,
            "privacy_mode": "metadata_only",
            "payload": {
              "event_id": "evt_1",
              "cdp_method": "Network.requestWillBeSent",
              "raw_event": {
                "method": "Network.requestWillBeSent",
                "params": {"requestId": "123.1"}
              }
            }
        }))
        .expect("parse envelope");

        let persisted = storage.ingest_raw_event_envelope(&envelope).expect("persist envelope");

        assert_eq!(persisted.session_id, "sess_1");
        assert_eq!(persisted.event_id, "evt_1");
        assert_eq!(persisted.event_seq, 7);
        assert_eq!(storage.session_count(), 1);
        assert_eq!(storage.events_raw_count(), 1);

        let second: JsonEnvelope = serde_json::from_value(json!({
            "v": 1,
            "type": "evt.raw_event",
            "ts_ms": 1729000000010_i64,
            "session_id": "sess_1",
            "event_seq": 8,
            "privacy_mode": "metadata_only",
            "payload": {
              "cdp_method": "Network.responseReceived",
              "raw_event": {
                "method": "Network.responseReceived",
                "params": {"requestId": "123.1"}
              }
            }
        }))
        .expect("parse second envelope");

        storage.ingest_raw_event_envelope(&second).expect("persist second envelope");

        assert_eq!(storage.session_count(), 1);
        assert_eq!(storage.events_raw_count(), 2);

        let parsed_mode: RedactionLevel =
            serde_json::from_str("\"metadata_only\"").expect("parse redaction enum");
        assert_eq!(parsed_mode, RedactionLevel::MetadataOnly);
    }

    #[test]
    fn duplicate_event_seq_ingest_is_idempotent() {
        let mut storage = Storage::open_in_memory().expect("open in-memory db");
        storage.apply_migrations().expect("apply migrations");

        let first: JsonEnvelope = serde_json::from_value(json!({
            "v": 1,
            "type": "evt.raw_event",
            "ts_ms": 1729000001000_i64,
            "session_id": "sess_dupe_1",
            "event_seq": 42,
            "privacy_mode": "metadata_only",
            "payload": {
              "event_id": "evt_dupe_a",
              "cdp_method": "Network.requestWillBeSent",
              "raw_event": {
                "method": "Network.requestWillBeSent",
                "params": {"requestId": "42.1"}
              }
            }
        }))
        .expect("parse first envelope");

        let second_same_seq: JsonEnvelope = serde_json::from_value(json!({
            "v": 1,
            "type": "evt.raw_event",
            "ts_ms": 1729000001999_i64,
            "session_id": "sess_dupe_1",
            "event_seq": 42,
            "privacy_mode": "metadata_only",
            "payload": {
              "event_id": "evt_dupe_b",
              "cdp_method": "Network.requestWillBeSent",
              "raw_event": {
                "method": "Network.requestWillBeSent",
                "params": {"requestId": "42.1", "retry": true}
              }
            }
        }))
        .expect("parse second envelope");

        let first_persisted =
            storage.ingest_raw_event_envelope(&first).expect("persist first envelope");
        let second_persisted = storage
            .ingest_raw_event_envelope(&second_same_seq)
            .expect("persist duplicate seq envelope");

        assert_eq!(storage.events_raw_count(), 1);
        assert_eq!(first_persisted.event_seq, 42);
        assert_eq!(second_persisted.event_seq, 42);
        assert_eq!(second_persisted.event_id, first_persisted.event_id);
        assert_eq!(second_persisted.payload_hash, first_persisted.payload_hash);
    }

    #[test]
    fn begin_and_end_session_persist_lifecycle_fields() {
        let mut storage = Storage::open_in_memory().expect("open in-memory db");
        storage.apply_migrations().expect("apply migrations");

        storage
            .begin_session(
                "sess_lifecycle_1",
                RedactionLevel::MetadataOnly,
                1_729_999_000_000,
                "extension_mv3",
            )
            .expect("begin session");
        assert_eq!(storage.session_ended_at_ms("sess_lifecycle_1"), None);

        storage.end_session("sess_lifecycle_1", 1_729_999_000_500).expect("end session");
        assert_eq!(storage.session_ended_at_ms("sess_lifecycle_1"), Some(1_729_999_000_500));
    }

    #[test]
    fn canonicalization_matches_jcs_equivalence() {
        let left = json!({"b":2,"a":1});
        let right = json!({"a":1,"b":2});

        let left_bytes = canonical_json_bytes(&left).expect("left canonical");
        let right_bytes = canonical_json_bytes(&right).expect("right canonical");
        assert_eq!(left_bytes, right_bytes);
    }

    #[test]
    fn correlate_session_populates_interactions_and_members() {
        let mut storage = Storage::open_in_memory().expect("open in-memory db");
        storage.apply_migrations().expect("apply migrations");

        ingest_fixture(&mut storage, "fx_phase4_page_api.ndjson", "fx_phase4_page_api");
        storage.normalize_session("fx_phase4_page_api").expect("normalize phase4 fixture");
        let report = storage.correlate_session("fx_phase4_page_api").expect("correlate fixture");

        assert!(report.request_candidates_seen > 0);
        assert!(report.interactions_written > 0);
        assert!(report.interaction_members_written > 0);

        let interaction_rows = count_rows(&storage, "interactions", "fx_phase4_page_api");
        let member_rows = count_rows(&storage, "interaction_members", "fx_phase4_page_api");
        assert!(interaction_rows > 0);
        assert!(member_rows > 0);

        let mut stmt = storage
            .conn
            .prepare(
                "SELECT im.interaction_id, SUM(im.is_primary)
                 FROM interaction_members im
                 JOIN interactions i ON i.interaction_id = im.interaction_id
                 WHERE i.session_id = ?1
                 GROUP BY im.interaction_id",
            )
            .expect("prepare primary count query");
        let rows = stmt
            .query_map(params!["fx_phase4_page_api"], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .expect("query primary counts");
        for row in rows {
            let (_, primary_count) = row.expect("primary row");
            assert_eq!(primary_count, 1);
        }
    }

    #[test]
    fn correlate_session_is_deterministic_across_replays() {
        let mut left = Storage::open_in_memory().expect("left db");
        left.apply_migrations().expect("left migrations");
        ingest_fixture(&mut left, "fx_phase4_llm_regen.ndjson", "fx_phase4_llm_regen");
        left.normalize_session("fx_phase4_llm_regen").expect("left normalize");
        left.correlate_session("fx_phase4_llm_regen").expect("left correlate");

        let mut right = Storage::open_in_memory().expect("right db");
        right.apply_migrations().expect("right migrations");
        ingest_fixture(&mut right, "fx_phase4_llm_regen.ndjson", "fx_phase4_llm_regen");
        right.normalize_session("fx_phase4_llm_regen").expect("right normalize");
        right.correlate_session("fx_phase4_llm_regen").expect("right correlate");

        let left_dump = dump_correlated_rows(&left, "fx_phase4_llm_regen");
        let right_dump = dump_correlated_rows(&right, "fx_phase4_llm_regen");
        assert_eq!(left_dump, right_dump);
    }

    #[test]
    fn correlation_snapshots_match_expected_outputs() {
        assert_snapshot_matches("fx_phase4_page_api.ndjson", "fx_phase4_page_api");
        assert_snapshot_matches("fx_phase4_preflight.ndjson", "fx_phase4_preflight");
        assert_snapshot_matches("fx_phase4_llm_regen.ndjson", "fx_phase4_llm_regen");
    }

    #[test]
    fn detector_snapshots_match_expected_outputs() {
        assert_detector_snapshot_matches("fx_phase3_normalization.ndjson", "fx_phase5_norm_seed");
        assert_detector_snapshot_matches("fx_phase4_page_api.ndjson", "fx_phase4_page_api");
        assert_detector_snapshot_matches("fx_phase4_preflight.ndjson", "fx_phase4_preflight");
        assert_detector_snapshot_matches("fx_phase4_llm_regen.ndjson", "fx_phase4_llm_regen");
        assert_detector_snapshot_matches(
            "fx_phase5_upload_blocked.ndjson",
            "fx_phase5_upload_blocked",
        );
        assert_detector_snapshot_matches("fx_phase5_llm_tools.ndjson", "fx_phase5_llm_tools");
    }

    #[test]
    fn no_findings_fixture_is_intentionally_empty() {
        let expected_file =
            fs::read_to_string(expected_analysis_snapshot_path("fx_phase5_norm_seed"))
                .expect("read no-findings snapshot");
        assert!(
            expected_file.trim().is_empty(),
            "fx_phase5_norm_seed analysis snapshot must stay empty"
        );
    }

    #[test]
    fn detector_analysis_is_deterministic_across_replays() {
        let mut left = Storage::open_in_memory().expect("left db");
        left.apply_migrations().expect("left migrations");
        ingest_fixture(&mut left, "fx_phase5_llm_tools.ndjson", "fx_phase5_llm_tools");
        left.normalize_session("fx_phase5_llm_tools").expect("left normalize");
        left.correlate_session("fx_phase5_llm_tools").expect("left correlate");
        left.analyze_session("fx_phase5_llm_tools").expect("left analyze");

        let mut right = Storage::open_in_memory().expect("right db");
        right.apply_migrations().expect("right migrations");
        ingest_fixture(&mut right, "fx_phase5_llm_tools.ndjson", "fx_phase5_llm_tools");
        right.normalize_session("fx_phase5_llm_tools").expect("right normalize");
        right.correlate_session("fx_phase5_llm_tools").expect("right correlate");
        right.analyze_session("fx_phase5_llm_tools").expect("right analyze");

        let left_dump =
            left.debug_dump_analysis_rows("fx_phase5_llm_tools").expect("left analysis dump");
        let right_dump =
            right.debug_dump_analysis_rows("fx_phase5_llm_tools").expect("right analysis dump");
        assert_eq!(left_dump, right_dump);
    }

    #[test]
    fn phase6_capture_drop_fixture_runs_full_pipeline_and_preserves_markers_as_skips() {
        let mut storage = Storage::open_in_memory().expect("open db");
        storage.apply_migrations().expect("apply migrations");
        ingest_fixture(&mut storage, "fx_phase6_capture_drop.ndjson", "fx_phase6_capture_drop");

        let normalize = storage
            .normalize_session("fx_phase6_capture_drop")
            .expect("normalize capture-drop fixture");
        assert!(normalize.network_requests_written > 0);
        assert!(normalize.network_responses_written > 0);
        assert!(normalize.network_completion_written > 0);
        assert!(normalize.console_entries_written > 0);
        assert!(normalize.page_lifecycle_written > 0);
        assert!(
            normalize.skipped_events > 0,
            "capture_drop marker must be skipped deterministically"
        );

        let correlate = storage
            .correlate_session("fx_phase6_capture_drop")
            .expect("correlate capture-drop fixture");
        assert!(correlate.interactions_written > 0);
        assert!(correlate.interaction_members_written > 0);

        let analysis = storage
            .analyze_session("fx_phase6_capture_drop")
            .expect("analyze capture-drop fixture");
        assert!(analysis.detectors_considered > 0);
    }

    #[test]
    fn phase6_disconnect_reconnect_fixture_is_deterministic_across_replays() {
        let mut left = Storage::open_in_memory().expect("left db");
        left.apply_migrations().expect("left migrations");
        ingest_fixture(
            &mut left,
            "fx_phase6_disconnect_reconnect.ndjson",
            "fx_phase6_disconnect_reconnect",
        );
        left.normalize_session("fx_phase6_disconnect_reconnect").expect("left normalize");
        left.correlate_session("fx_phase6_disconnect_reconnect").expect("left correlate");
        left.analyze_session("fx_phase6_disconnect_reconnect").expect("left analyze");

        let mut right = Storage::open_in_memory().expect("right db");
        right.apply_migrations().expect("right migrations");
        ingest_fixture(
            &mut right,
            "fx_phase6_disconnect_reconnect.ndjson",
            "fx_phase6_disconnect_reconnect",
        );
        right.normalize_session("fx_phase6_disconnect_reconnect").expect("right normalize");
        right.correlate_session("fx_phase6_disconnect_reconnect").expect("right correlate");
        right.analyze_session("fx_phase6_disconnect_reconnect").expect("right analyze");

        let left_corr = dump_correlated_rows(&left, "fx_phase6_disconnect_reconnect");
        let right_corr = dump_correlated_rows(&right, "fx_phase6_disconnect_reconnect");
        assert_eq!(left_corr, right_corr);

        let left_analysis = left
            .debug_dump_analysis_rows("fx_phase6_disconnect_reconnect")
            .expect("left analysis dump");
        let right_analysis = right
            .debug_dump_analysis_rows("fx_phase6_disconnect_reconnect")
            .expect("right analysis dump");
        assert_eq!(left_analysis, right_analysis);
    }

    #[test]
    fn export_dataset_builds_from_fixture_session() {
        let mut storage = Storage::open_in_memory().expect("open db");
        storage.apply_migrations().expect("apply migrations");
        ingest_fixture(&mut storage, "fx_phase4_page_api.ndjson", "fx_phase4_page_api");
        storage.normalize_session("fx_phase4_page_api").expect("normalize");
        storage.correlate_session("fx_phase4_page_api").expect("correlate");
        storage.analyze_session("fx_phase4_page_api").expect("analyze");

        let dataset = storage
            .build_export_dataset("fx_phase4_page_api", ExportProfileV1::ShareSafe)
            .expect("build export dataset");
        assert_eq!(dataset.session_id, "fx_phase4_page_api");
        assert!(!dataset.raw_events.is_empty());
        assert!(!dataset.normalized_network_requests.is_empty());
        assert!(!dataset.analysis_findings.is_empty());
    }

    #[test]
    fn export_run_registry_persists_start_and_completion() {
        let mut storage = Storage::open_in_memory().expect("open db");
        storage.apply_migrations().expect("apply migrations");
        storage
            .begin_session("sess_export_registry", RedactionLevel::Redacted, 100, "test")
            .expect("begin session");

        let started = storage
            .insert_export_run_start("sess_export_registry", ExportProfileV1::ShareSafe, "/tmp")
            .expect("insert export start");
        assert_eq!(started.status, ExportRunStatusV1::Running);

        let manifest = ExportManifestV1 {
            v: 1,
            session_id: "sess_export_registry".to_string(),
            exported_at_ms: 100,
            privacy_mode: RedactionLevel::Redacted,
            export_profile: ExportProfileV1::ShareSafe,
            files: Vec::new(),
            indexes: vec![dtt_core::ExportManifestIndexEntryV1 {
                name: "raw/events.index.ndjson".to_string(),
                maps_file: "raw/events.ndjson.zst".to_string(),
                mode: ManifestIndexModeV1::Line,
            }],
            evidence_indexes: ExportEvidenceIndexesV1 {
                raw_event: "raw/events.index.ndjson".to_string(),
                net_row: "normalized/network.index.ndjson".to_string(),
                console: "normalized/console.index.ndjson".to_string(),
                derived_metric: "analysis/derived_metrics.index.ndjson".to_string(),
            },
        };
        storage
            .mark_export_run_completed(
                &started.export_id,
                &super::ExportRunCompletedUpdate {
                    zip_path: "/tmp/export.zip".to_string(),
                    bundle_blake3: "bundle_hash".to_string(),
                    files_blake3_path: "integrity/files.blake3.json".to_string(),
                    manifest,
                    file_count: 5,
                    integrity_ok: true,
                    completed_at_ms: 200,
                },
            )
            .expect("mark completed");

        let completed =
            storage.get_export_run_ui(&started.export_id).expect("get run").expect("run exists");
        assert_eq!(completed.status, ExportRunStatusV1::Completed);
        assert_eq!(completed.zip_path.as_deref(), Some("/tmp/export.zip"));
        assert_eq!(completed.integrity_ok, Some(true));
    }

    #[test]
    fn exported_at_ms_is_deterministic_for_same_session() {
        let mut left = Storage::open_in_memory().expect("left db");
        left.apply_migrations().expect("left migrations");
        left.begin_session("sess_exported_at", RedactionLevel::MetadataOnly, 100, "test")
            .expect("left begin");
        left.end_session("sess_exported_at", 400).expect("left end");

        let mut right = Storage::open_in_memory().expect("right db");
        right.apply_migrations().expect("right migrations");
        right
            .begin_session("sess_exported_at", RedactionLevel::MetadataOnly, 100, "test")
            .expect("right begin");
        right.end_session("sess_exported_at", 400).expect("right end");

        let left_ms = left.compute_exported_at_ms("sess_exported_at").expect("left exported_at_ms");
        let right_ms =
            right.compute_exported_at_ms("sess_exported_at").expect("right exported_at_ms");
        assert_eq!(left_ms, 400);
        assert_eq!(left_ms, right_ms);
    }

    #[test]
    fn release_run_registry_persists_start_completion_and_list_order() {
        let mut storage = Storage::open_in_memory().expect("open db");
        storage.apply_migrations().expect("apply migrations");

        let started = storage
            .insert_release_run_start(
                ReleaseChannelV1::InternalBeta,
                "0.1.0-beta.1",
                "abc123",
                Some("notes"),
            )
            .expect("insert release run");
        assert_eq!(started.status, ReleaseRunStatusV1::Running);

        storage
            .mark_release_run_completed(
                &started.run_id,
                &[dtt_core::ReleaseArtifactV1 {
                    kind: ReleaseArtifactKindV1::MacZip,
                    platform: ReleasePlatformV1::Macos,
                    arch: ReleaseArchV1::X64,
                    target_triple: "x86_64-apple-darwin".to_string(),
                    path: "/tmp/dtt-desktop-macos-v0.1.0-beta.1.zip".to_string(),
                    sha256: "deadbeef".to_string(),
                    size_bytes: 1234,
                }],
                started.started_at_ms + 50,
            )
            .expect("mark release complete");

        let listed = storage.list_release_runs_ui(10).expect("list releases");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].run_id, started.run_id);
        assert_eq!(listed[0].status, ReleaseRunStatusV1::Completed);
        assert_eq!(listed[0].artifacts.len(), 1);
    }

    #[test]
    fn release_promotion_registry_and_signing_snapshot() {
        let mut storage = Storage::open_in_memory().expect("open db");
        storage.apply_migrations().expect("apply migrations");

        let started = storage
            .insert_release_run_start(
                ReleaseChannelV1::StagedPublicPrerelease,
                "0.2.0-beta.1",
                "abc456",
                Some("promotion notes"),
            )
            .expect("insert staged release run");
        storage
            .mark_release_run_completed(
                &started.run_id,
                &[dtt_core::ReleaseArtifactV1 {
                    kind: ReleaseArtifactKindV1::MacZip,
                    platform: ReleasePlatformV1::Macos,
                    arch: ReleaseArchV1::X64,
                    target_triple: "x86_64-apple-darwin".to_string(),
                    path: "/tmp/dtt-desktop-macos-v0.2.0-beta.1.zip".to_string(),
                    sha256: "feedface".to_string(),
                    size_bytes: 2048,
                }],
                started.started_at_ms + 10,
            )
            .expect("complete release run");

        let promotion = storage
            .insert_release_promotion_start(
                &started.run_id,
                ReleaseChannelV1::StagedPublicPrerelease,
                ReleaseVisibilityV1::StagedPublic,
                &ArtifactProvenanceV1 {
                    build_id: "build-1".to_string(),
                    workflow_run_id: "wf-1".to_string(),
                    source_commit: "abc456".to_string(),
                    signing_status: SigningStatusV1::Verified,
                    notarization_status: SigningStatusV1::Verified,
                },
                started.started_at_ms + 20,
            )
            .expect("start promotion");
        storage
            .mark_release_promotion_completed(
                &promotion.promotion_id,
                &promotion.provenance,
                started.started_at_ms + 25,
            )
            .expect("complete promotion");
        let listed = storage.list_release_promotions(10).expect("list promotions");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].status, ReleaseRunStatusV1::Completed);

        let snapshot = storage
            .get_signing_snapshot(&started.run_id, true)
            .expect("get signing snapshot")
            .expect("snapshot exists");
        assert_eq!(snapshot.signing_status, SigningStatusV1::Verified);
        assert_eq!(snapshot.visibility, ReleaseVisibilityV1::StagedPublic);
        assert!(snapshot.blocking_reasons.is_empty());
    }

    #[test]
    fn extension_rollout_lifecycle_and_compliance_snapshot() {
        let mut storage = Storage::open_in_memory().expect("open db");
        storage.apply_migrations().expect("apply migrations");

        let started = storage
            .insert_extension_rollout_start(
                ExtensionChannelV1::ChromeStorePublic,
                "1.2.3",
                RolloutStageV1::Pct5,
                Some("chrome_item_123"),
                Some("phase13 dry-run"),
                10_000,
            )
            .expect("start extension rollout");
        storage
            .insert_extension_compliance_check(
                &started.rollout_id,
                "permissions_allowlist",
                TelemetryAuditStatusV1::Pass,
                &json!({"diff_count": 0}),
                10_010,
            )
            .expect("insert compliance pass");
        storage
            .insert_extension_compliance_check(
                &started.rollout_id,
                "privacy_policy_url",
                TelemetryAuditStatusV1::Warn,
                &json!({"url": "https://example.com/privacy"}),
                10_011,
            )
            .expect("insert compliance warn");
        storage
            .insert_extension_compliance_check(
                &started.rollout_id,
                "version_monotonicity",
                TelemetryAuditStatusV1::Fail,
                &json!({"expected_min": "1.2.2", "actual": "1.2.1"}),
                10_012,
            )
            .expect("insert compliance fail");
        storage
            .mark_extension_rollout_completed(&started.rollout_id, 10_020)
            .expect("complete extension rollout");

        let listed = storage.list_extension_rollouts(10).expect("list extension rollouts");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].channel, ExtensionChannelV1::ChromeStorePublic);
        assert_eq!(listed[0].status, RolloutStatusV1::Completed);

        let snapshot = storage
            .get_extension_compliance_snapshot(Some(&started.rollout_id), 50)
            .expect("compliance snapshot");
        assert_eq!(snapshot.checks_total, 3);
        assert_eq!(snapshot.checks_passed, 1);
        assert_eq!(snapshot.checks_warn, 1);
        assert_eq!(snapshot.checks_failed, 1);
        assert!(snapshot
            .blocking_reasons
            .iter()
            .any(|reason| reason == "extension_compliance_failed"));
    }

    #[test]
    fn telemetry_exports_settings_and_runs_roundtrip() {
        let mut storage = Storage::open_in_memory().expect("open db");
        storage.apply_migrations().expect("apply migrations");

        let default_settings = storage.get_telemetry_settings().expect("default telemetry");
        assert_eq!(default_settings.mode, TelemetryModeV1::LocalOnly);
        assert!(!default_settings.otlp.enabled);

        let updated = storage
            .set_telemetry_settings(
                &dtt_core::UiTelemetrySettingsV1 {
                    mode: TelemetryModeV1::LocalPlusOtlp,
                    otlp: OtlpSinkConfigV1 {
                        enabled: true,
                        endpoint: Some("http://127.0.0.1:4318/v1/metrics".to_string()),
                        protocol: "http".to_string(),
                        timeout_ms: 4000,
                        batch_size: 100,
                        redaction_profile: "counters_only".to_string(),
                    },
                },
                1_000,
            )
            .expect("set telemetry");
        assert_eq!(updated.mode, TelemetryModeV1::LocalPlusOtlp);
        assert!(updated.otlp.enabled);

        let started =
            storage.insert_telemetry_export_start(100, 200, 300).expect("start telemetry export");
        assert_eq!(started.status, dtt_core::PerfRunStatusV1::Running);
        let completed = storage
            .mark_telemetry_export_completed(&started.export_run_id, 10, 2, Some("hash123"), 305)
            .expect("complete telemetry export");
        assert_eq!(completed.status, dtt_core::PerfRunStatusV1::Completed);
        assert_eq!(completed.sample_count, 10);

        let listed = storage.list_telemetry_exports(10).expect("list telemetry exports");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].payload_sha256.as_deref(), Some("hash123"));
    }

    #[test]
    fn telemetry_audit_insert_and_list_are_deterministic() {
        let mut storage = Storage::open_in_memory().expect("open db");
        storage.apply_migrations().expect("apply migrations");
        let first = storage
            .insert_telemetry_audit(
                None,
                TelemetryAuditStatusV1::Pass,
                &json!([]),
                Some("hash_pass"),
                20_000,
            )
            .expect("insert pass");
        let second = storage
            .insert_telemetry_audit(
                None,
                TelemetryAuditStatusV1::Fail,
                &json!([{"violation":"raw_url_present"}]),
                Some("hash_fail"),
                20_001,
            )
            .expect("insert fail");
        let listed = storage.list_telemetry_audits(10).expect("list telemetry audits");
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].audit_id, second.audit_id);
        assert_eq!(listed[0].status, TelemetryAuditStatusV1::Fail);
        assert_eq!(listed[1].audit_id, first.audit_id);
    }

    #[test]
    fn updater_rollout_snapshot_and_listing() {
        let mut storage = Storage::open_in_memory().expect("open db");
        storage.apply_migrations().expect("apply migrations");
        let update_rollout_id = storage
            .insert_update_rollout_start(UpdateRolloutStartInput {
                channel: UpdateChannelV1::StagedPublicPrerelease,
                version: "2.0.0",
                stage: RolloutStageV1::Pct25,
                rollout_pct: 25,
                feed_url:
                    "https://example.invalid/update-feed/staged_public_prerelease/latest.json",
                signature_verified: true,
                started_at_ms: 30_000,
            })
            .expect("insert update rollout");
        storage
            .mark_update_rollout_status(
                &update_rollout_id,
                RolloutStatusV1::Active,
                None,
                None,
                None,
            )
            .expect("mark active");

        let latest = storage
            .get_latest_update_rollout_snapshot(UpdateChannelV1::StagedPublicPrerelease)
            .expect("latest snapshot")
            .expect("snapshot exists");
        assert_eq!(latest.update_rollout_id.as_deref(), Some(update_rollout_id.as_str()));
        assert_eq!(latest.rollout_pct, Some(25));
        assert_eq!(latest.status, Some(RolloutStatusV1::Active));
        assert!(latest.signature_verified);

        let listed = storage.list_update_rollout_snapshots(10).expect("list update rollouts");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].channel, UpdateChannelV1::StagedPublicPrerelease);
    }

    #[test]
    fn bundle_inspection_record_roundtrip_and_close() {
        let mut storage = Storage::open_in_memory().expect("open db");
        storage.apply_migrations().expect("apply migrations");

        let summary = json!({
            "session_id": "sess_bundle_1",
            "exported_at_ms": 100,
            "privacy_mode": "redacted",
            "profile": "share_safe"
        });

        let inserted = storage
            .insert_bundle_inspection_record(
                "insp_1",
                "/tmp/export.zip",
                true,
                &summary,
                None,
                None,
            )
            .expect("insert inspect");
        assert_eq!(inserted.inspect_id, "insp_1");
        assert_eq!(inserted.session_id.as_deref(), Some("sess_bundle_1"));
        assert!(inserted.integrity_valid);

        let loaded = storage
            .get_bundle_inspection_record("insp_1")
            .expect("get inspect")
            .expect("inspect exists");
        assert_eq!(loaded.inspect_id, "insp_1");
        assert_eq!(loaded.profile, Some(ExportProfileV1::ShareSafe));
        assert_eq!(loaded.privacy_mode, Some(RedactionLevel::Redacted));

        storage.close_bundle_inspection_record("insp_1", 200).expect("close inspect");
        let closed_at_ms: Option<i64> = storage
            .conn
            .query_row(
                "SELECT closed_at_ms FROM bundle_inspections WHERE inspect_id = ?1",
                params!["insp_1"],
                |row| row.get(0),
            )
            .expect("closed value");
        assert_eq!(closed_at_ms, Some(200));
    }

    #[test]
    fn retention_policy_roundtrip_and_validation() {
        let mut storage = Storage::open_in_memory().expect("open db");
        storage.apply_migrations().expect("apply migrations");

        let defaults = storage.get_retention_policy().expect("default policy");
        assert!(defaults.enabled);
        assert_eq!(defaults.retain_days, 30);
        assert_eq!(defaults.max_sessions, 1000);

        storage
            .set_retention_policy(RetentionPolicyV1 {
                enabled: true,
                retain_days: 14,
                max_sessions: 250,
                delete_exports: true,
                delete_blobs: false,
            })
            .expect("set policy");
        let next = storage.get_retention_policy().expect("read policy");
        assert_eq!(next.retain_days, 14);
        assert_eq!(next.max_sessions, 250);
        assert!(!next.delete_blobs);

        let invalid = storage.set_retention_policy(RetentionPolicyV1 {
            enabled: true,
            retain_days: 0,
            max_sessions: 0,
            delete_exports: true,
            delete_blobs: true,
        });
        assert!(invalid.is_err());
    }

    #[test]
    fn retention_run_dry_run_then_apply_deletes_candidates_deterministically() {
        let mut storage = Storage::open_in_memory().expect("open db");
        storage.apply_migrations().expect("apply migrations");

        storage
            .set_retention_policy(RetentionPolicyV1 {
                enabled: true,
                retain_days: 1,
                max_sessions: 10,
                delete_exports: false,
                delete_blobs: false,
            })
            .expect("set policy");

        storage
            .begin_session("sess_old", RedactionLevel::MetadataOnly, 100, "test")
            .expect("begin old");
        storage.end_session("sess_old", 200).expect("end old");
        storage
            .begin_session("sess_new", RedactionLevel::MetadataOnly, 86_500_000, "test")
            .expect("begin new");
        storage.end_session("sess_new", 86_500_100).expect("end new");

        let dry_run = storage
            .run_retention_with_results(86_500_200, RetentionRunModeV1::DryRun)
            .expect("dry run");
        assert_eq!(dry_run.report.mode, RetentionRunModeV1::DryRun);
        assert_eq!(dry_run.report.candidate_sessions, 1);
        assert_eq!(dry_run.report.deleted_sessions, 0);
        assert!(storage.session_ended_at_ms("sess_old").is_some());

        let apply = storage
            .run_retention_with_results(86_500_200, RetentionRunModeV1::Apply)
            .expect("apply retention");
        assert_eq!(apply.report.deleted_sessions, 1);
        assert_eq!(storage.session_ended_at_ms("sess_old"), None);
        assert!(storage.session_ended_at_ms("sess_new").is_some());
    }

    #[test]
    fn delete_running_session_is_blocked() {
        let mut storage = Storage::open_in_memory().expect("open db");
        storage.apply_migrations().expect("apply migrations");
        storage
            .begin_session("sess_running", RedactionLevel::MetadataOnly, 100, "test")
            .expect("begin running");

        let result =
            storage.delete_session_with_artifacts("sess_running", 1_000).expect("delete running");
        assert!(!result.db_deleted);
        assert!(result.errors.iter().any(|error| error == "delete_blocked_running_session"));
    }

    #[test]
    fn delete_session_blocks_artifact_paths_outside_managed_roots() {
        let mut storage = Storage::open_in_memory().expect("open db");
        storage.apply_migrations().expect("apply migrations");
        storage.begin_session("sess_blocked", RedactionLevel::Redacted, 10, "test").expect("begin");
        storage.end_session("sess_blocked", 20).expect("end");

        storage
            .conn
            .execute(
                "INSERT INTO app_settings (setting_key, value_json, updated_at_ms)
                 VALUES (?1, ?2, ?3)",
                params![
                    super::EXPORT_ROOT_KEY,
                    serde_json::to_string("/tmp/dtt-allowed").expect("json"),
                    20_i64
                ],
            )
            .expect("insert export root");
        storage
            .conn
            .execute(
                "INSERT INTO exports_runs (
                    export_id, session_id, export_profile, privacy_mode, status, zip_path, output_dir, created_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    "exp_blocked",
                    "sess_blocked",
                    "share_safe",
                    "redacted",
                    "completed",
                    "/tmp/not-allowed/export.zip",
                    "/tmp/not-allowed",
                    20_i64
                ],
            )
            .expect("insert export run");

        let result =
            storage.delete_session_with_artifacts("sess_blocked", 30).expect("delete blocked");
        assert!(!result.db_deleted);
        assert!(!result.blocked_paths.is_empty());
        assert!(result.errors.iter().any(|error| error == "delete_artifact_path_blocked"));
        assert!(storage.session_ended_at_ms("sess_blocked").is_some());
    }

    #[test]
    fn persisted_bridge_diagnostics_are_sorted_and_queryable() {
        let mut storage = Storage::open_in_memory().expect("open db");
        storage.apply_migrations().expect("apply migrations");
        storage
            .begin_session("sess_diag", RedactionLevel::MetadataOnly, 10, "test")
            .expect("begin");
        storage.end_session("sess_diag", 20).expect("end");

        storage
            .append_bridge_diagnostic(Some("sess_diag"), 1000, "connected", "ok", "ws_bridge")
            .expect("append1");
        storage
            .append_bridge_diagnostic(Some("sess_diag"), 1000, "error", "boom", "ws_bridge")
            .expect("append2");
        storage
            .append_bridge_diagnostic(Some("sess_diag"), 1001, "closed", "bye", "ws_bridge")
            .expect("append3");

        let listed =
            storage.list_bridge_diagnostics(Some("sess_diag"), 10).expect("list diagnostics");
        assert_eq!(listed[0].kind, "closed");
        assert_eq!(listed[0].ts_ms, 1001);
        assert_eq!(listed.len(), 3);
    }

    #[test]
    fn reliability_metrics_snapshot_and_series_are_deterministic() {
        let mut storage = Storage::open_in_memory().expect("open db");
        storage.apply_migrations().expect("apply migrations");

        storage
            .append_reliability_metric(
                Some("sess_rel"),
                "ws_bridge",
                ReliabilityMetricKeyV1::WsDisconnectCount,
                1.0,
                &json!({ "reason": "socket_closed" }),
                1_000,
            )
            .expect("append rel1");
        storage
            .append_reliability_metric(
                Some("sess_rel"),
                "ws_bridge",
                ReliabilityMetricKeyV1::WsDisconnectCount,
                1.0,
                &json!({ "reason": "socket_closed" }),
                1_100,
            )
            .expect("append rel2");
        storage
            .append_reliability_metric(
                Some("sess_rel"),
                "pipeline",
                ReliabilityMetricKeyV1::SessionPipelineFailCount,
                2.0,
                &json!({ "stage": "analyze" }),
                1_100,
            )
            .expect("append rel3");

        let snapshot = storage.get_reliability_snapshot(500, 1_200).expect("snapshot");
        assert_eq!(snapshot.window.from_ms, 700);
        assert_eq!(snapshot.window.to_ms, 1_200);
        assert_eq!(snapshot.window.totals_by_key.get("ws_disconnect_count"), Some(&2.0));
        assert_eq!(snapshot.window.totals_by_key.get("session_pipeline_fail_count"), Some(&2.0));
        assert_eq!(snapshot.recent_samples.len(), 3);
        assert!(snapshot.recent_samples[0].ts_ms >= snapshot.recent_samples[1].ts_ms);

        let series = storage
            .list_reliability_series(ReliabilityMetricKeyV1::WsDisconnectCount, 900, 1_200, 100)
            .expect("series");
        assert_eq!(series.len(), 2);
        assert_eq!(series[0].bucket_start_ms, 1_000);
        assert_eq!(series[0].metric_value, 1.0);
        assert_eq!(series[1].bucket_start_ms, 1_100);
        assert_eq!(series[1].metric_value, 1.0);
    }

    #[test]
    fn perf_runs_start_complete_and_list_order() {
        let mut storage = Storage::open_in_memory().expect("open db");
        storage.apply_migrations().expect("apply migrations");

        let first = storage
            .insert_perf_run_start("sustained_capture", "fx_phase11_sustained_capture_30m", 1_000)
            .expect("first perf run");
        let second = storage
            .insert_perf_run_start("bundle_inspect_large", "fx_phase11_large_bundle_inspect", 1_001)
            .expect("second perf run");
        let completed = storage
            .mark_perf_run_completed(
                &first.perf_run_id,
                &json!({
                    "duration_ms": 42,
                    "throughput_events_per_s": 2500.0
                }),
                1_050,
            )
            .expect("complete first");
        assert_eq!(completed.status, dtt_core::PerfRunStatusV1::Completed);

        storage
            .mark_perf_run_failed(
                &second.perf_run_id,
                "perf_threshold_breach",
                "p95 latency exceeded",
                1_060,
            )
            .expect("fail second");

        let listed = storage.list_perf_runs_ui(10).expect("list perf runs");
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].perf_run_id, second.perf_run_id);
        assert_eq!(listed[0].status, dtt_core::PerfRunStatusV1::Failed);
        assert_eq!(listed[1].perf_run_id, first.perf_run_id);
        assert_eq!(listed[1].status, dtt_core::PerfRunStatusV1::Completed);
    }

    #[test]
    fn endurance_perf_trends_are_sorted_and_include_budget_result() {
        let mut storage = Storage::open_in_memory().expect("open db");
        storage.apply_migrations().expect("apply migrations");
        let first = storage
            .insert_perf_run_start_with_target(
                "sustained_capture_6h",
                "fx_phase12_endurance_6h",
                10_000,
                6 * 60 * 60 * 1000,
            )
            .expect("insert first perf run");
        storage
            .mark_perf_run_completed_with_metrics(
                &first.perf_run_id,
                &json!({"throughput_events_per_s": 2600.0}),
                10_010,
                Some(10),
                Some(PerfBudgetResultV1::Pass),
                Some(2.0),
            )
            .expect("complete first");

        let second = storage
            .insert_perf_run_start_with_target(
                "sustained_capture_6h",
                "fx_phase12_endurance_6h",
                10_100,
                6 * 60 * 60 * 1000,
            )
            .expect("insert second perf run");
        storage
            .mark_perf_run_completed_with_metrics(
                &second.perf_run_id,
                &json!({"throughput_events_per_s": 2400.0}),
                10_110,
                Some(10),
                Some(PerfBudgetResultV1::Warn),
                Some(12.0),
            )
            .expect("complete second");

        let trends = storage.list_perf_trends("sustained_capture_6h", 10).expect("list trends");
        assert_eq!(trends.len(), 2);
        assert!(trends[0].bucket_start_ms < trends[1].bucket_start_ms);
        assert_eq!(trends[1].budget_result, PerfBudgetResultV1::Warn);
    }

    #[test]
    fn anomaly_insert_and_list_ordering_is_deterministic() {
        let mut storage = Storage::open_in_memory().expect("open db");
        storage.apply_migrations().expect("apply migrations");
        let low = storage
            .insert_perf_anomaly(PerfAnomalyInsertInput {
                run_kind: "sustained_capture_24h",
                bucket_start_ms: 40_000,
                metric_name: "drift_pct",
                severity: PerfAnomalySeverityV1::Low,
                score: 2.6,
                baseline_value: 10.0,
                observed_value: 12.6,
                details_json: &json!({"window": 20}),
                created_at_ms: 40_100,
            })
            .expect("insert low anomaly");
        let critical = storage
            .insert_perf_anomaly(PerfAnomalyInsertInput {
                run_kind: "sustained_capture_24h",
                bucket_start_ms: 40_001,
                metric_name: "drift_pct",
                severity: PerfAnomalySeverityV1::Critical,
                score: 6.1,
                baseline_value: 10.0,
                observed_value: 16.1,
                details_json: &json!({"window": 20}),
                created_at_ms: 40_101,
            })
            .expect("insert critical anomaly");

        let listed =
            storage.list_perf_anomalies(Some("sustained_capture_24h"), 10).expect("list anomalies");
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].anomaly_id, critical.anomaly_id);
        assert_eq!(listed[0].severity, PerfAnomalySeverityV1::Critical);
        assert_eq!(listed[1].anomaly_id, low.anomaly_id);
    }

    #[test]
    fn rollout_controller_transition_and_health_scorecard_persist_deterministically() {
        let mut storage = Storage::open_in_memory().expect("open db");
        storage.apply_migrations().expect("apply migrations");
        let scorecard = ReleaseHealthScorecardV1 {
            scope: "extension".to_string(),
            channel: "chrome_store_public".to_string(),
            version: "0.2.0".to_string(),
            stage: Some(RolloutStageV1::Pct5),
            overall_status: RolloutHealthStatusV1::Warn,
            score: 78.5,
            metrics: vec![ReleaseHealthMetricV1 {
                metric_key: "telemetry_audit_fail_ratio".to_string(),
                status: RolloutHealthStatusV1::Warn,
                observed_value: 0.0,
                threshold_warn: Some(0.0),
                threshold_fail: Some(1.0),
                details_json: json!({"window": "24h"}),
            }],
            gate_reasons: vec![RolloutGateReasonV1::SoakIncomplete],
            created_at_ms: 55_000,
        };
        let inserted =
            storage.insert_release_health_snapshot(&scorecard).expect("insert scorecard");
        assert!(inserted.snapshot_id.starts_with("rhs_"));
        let latest = storage
            .get_latest_release_health_snapshot("extension", "chrome_store_public", "0.2.0")
            .expect("fetch latest")
            .expect("latest exists");
        assert_eq!(latest.snapshot_id, inserted.snapshot_id);
        assert_eq!(latest.scorecard.overall_status, RolloutHealthStatusV1::Warn);
        assert_eq!(latest.scorecard.gate_reasons, vec![RolloutGateReasonV1::SoakIncomplete]);

        let transition_id = storage
            .insert_rollout_stage_transition(RolloutStageTransitionInput {
                kind: "extension",
                channel: "chrome_store_public",
                version: "0.2.0",
                from_stage: Some(RolloutStageV1::Pct5),
                to_stage: Some(RolloutStageV1::Pct25),
                action: RolloutControllerActionV1::Pause,
                decision_json: &json!({"reasons": ["soak_incomplete"]}),
                decided_at_ms: 55_001,
            })
            .expect("insert transition");
        assert!(transition_id.starts_with("rtr_"));
    }

    #[test]
    fn compliance_pack_roundtrip_and_listing() {
        let mut storage = Storage::open_in_memory().expect("open db");
        storage.apply_migrations().expect("apply migrations");
        let pack = ComplianceEvidencePackV1 {
            pack_id: "cep_1".to_string(),
            kind: "extension".to_string(),
            channel: "chrome_store_public".to_string(),
            version: "0.2.0".to_string(),
            stage: Some(RolloutStageV1::Pct5),
            pack_path: "/tmp/dtt/extension/0.2.0/pct_5".to_string(),
            manifest_sha256: "abc123".to_string(),
            items: vec![ComplianceEvidenceItemV1 {
                item_key: "permission_allowlist_diff".to_string(),
                path: "/tmp/dtt/extension/0.2.0/pct_5/permission_allowlist_diff.json".to_string(),
                sha256: "hash1".to_string(),
                size_bytes: 42,
            }],
            created_at_ms: 66_000,
            status: "generated".to_string(),
            error_code: None,
            error_message: None,
        };
        storage.insert_compliance_evidence_pack(&pack).expect("insert pack");
        let listed =
            storage.list_compliance_evidence_packs(Some("extension"), 10).expect("list packs");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].pack_id, "cep_1");
        let fetched = storage
            .get_compliance_evidence_pack(
                "extension",
                "chrome_store_public",
                "0.2.0",
                Some(RolloutStageV1::Pct5),
            )
            .expect("get compliance pack");
        let fetched_pack = fetched.pack.expect("fetched pack");
        assert_eq!(fetched_pack.pack_id, "cep_1");
        assert_eq!(fetched_pack.items.len(), 1);
        assert_eq!(fetched_pack.items[0].item_key, "permission_allowlist_diff");
    }

    #[test]
    fn top20_fixture_catalog_has_raw_and_expected_outputs() {
        let required = [
            "fx_cors_preflight_fail",
            "fx_cors_missing_acao",
            "fx_cors_credentials_wildcard",
            "fx_csp_console_violation",
            "fx_auth_401_primary",
            "fx_429_with_retry_after",
            "fx_5xx_burst",
            "fx_blocked_by_client",
            "fx_mixed_content_block",
            "fx_dns_failure",
            "fx_tls_failure",
            "fx_stale_sw_suspected",
            "fx_cache_control_conflict",
            "fx_long_request_duration",
            "fx_large_js_response",
            "fx_llm_sse_stream",
            "fx_llm_model_identity_mix",
            "fx_llm_refusal",
            "fx_llm_tool_call_schema",
            "fx_llm_retry_backoff",
        ];
        for fixture_id in required {
            let raw = fixture_path(&format!("{fixture_id}.ndjson"));
            assert!(raw.exists(), "missing raw fixture {}", raw.display());

            let analysis = expected_analysis_snapshot_path(fixture_id);
            assert!(analysis.exists(), "missing expected analysis snapshot {}", analysis.display());
        }
    }

    #[test]
    fn phase12_fixture_fidelity_gate_rejects_placeholder_only_data() {
        let fixtures = ["fx_phase12_endurance_6h", "fx_phase12_endurance_24h"];
        for fixture_id in fixtures {
            let raw = fixture_path(&format!("{fixture_id}.ndjson"));
            let expected = expected_snapshot_path(fixture_id);
            assert!(raw.exists(), "missing phase12 raw fixture {}", raw.display());
            assert!(expected.exists(), "missing phase12 expected snapshot {}", expected.display());
            let raw_content = fs::read_to_string(&raw).expect("read raw fixture");
            let expected_content = fs::read_to_string(&expected).expect("read expected snapshot");
            assert!(
                !raw_content.to_ascii_lowercase().contains("placeholder"),
                "phase12 raw fixture must be scenario-like, not placeholder-only: {}",
                raw.display()
            );
            assert!(
                expected_content.contains("scenario_true"),
                "phase12 expected snapshot must include scenario_true marker: {}",
                expected.display()
            );
        }
    }

    #[test]
    fn ui_query_methods_return_expected_rows() {
        let mut storage = Storage::open_in_memory().expect("open db");
        storage.apply_migrations().expect("apply migrations");
        ingest_fixture(&mut storage, "fx_phase4_page_api.ndjson", "fx_phase4_page_api");
        storage.normalize_session("fx_phase4_page_api").expect("normalize");
        storage.correlate_session("fx_phase4_page_api").expect("correlate");
        storage.analyze_session("fx_phase4_page_api").expect("analyze");

        let sessions = storage.list_sessions_ui(20).expect("sessions");
        assert!(!sessions.is_empty());

        let overview = storage
            .get_session_overview_ui("fx_phase4_page_api")
            .expect("overview")
            .expect("overview value");
        assert_eq!(overview.session.session_id, "fx_phase4_page_api");
        assert!(overview.network_requests_count > 0);

        let timeline = storage.list_timeline_ui("fx_phase4_page_api").expect("timeline");
        assert!(!timeline.events.is_empty());
        assert!(!timeline.interactions.is_empty());

        let network = storage.list_network_ui("fx_phase4_page_api").expect("network");
        assert!(!network.is_empty());

        let console = storage.list_console_ui("fx_phase4_page_api").expect("console");
        assert!(!console.is_empty());

        let findings = storage.list_findings_ui(Some("fx_phase4_page_api"), 20).expect("findings");
        assert!(!findings.is_empty());

        let export = storage.list_exports_ui("fx_phase4_page_api").expect("export");
        assert_eq!(export.default_mode, dtt_core::UiExportModeV1::ShareSafe);
    }

    #[test]
    fn evidence_resolution_returns_exact_or_fallback() {
        let mut storage = Storage::open_in_memory().expect("open db");
        storage.apply_migrations().expect("apply migrations");
        ingest_fixture(&mut storage, "fx_phase4_preflight.ndjson", "fx_phase4_preflight");
        storage.normalize_session("fx_phase4_preflight").expect("normalize");
        storage.correlate_session("fx_phase4_preflight").expect("correlate");
        storage.analyze_session("fx_phase4_preflight").expect("analyze");

        let evidence_ref_id = storage
            .conn
            .query_row(
                "SELECT evidence_ref_id FROM evidence_refs ORDER BY evidence_ref_id LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .expect("first evidence ref id");

        let resolved = storage
            .resolve_evidence_ui(&evidence_ref_id)
            .expect("resolve evidence")
            .expect("resolved value");
        assert_eq!(resolved.evidence_ref_id, evidence_ref_id);
        if !resolved.exact_pointer_found {
            assert_eq!(resolved.fallback_reason.as_deref(), Some("Exact pointer unavailable"));
        }

        let missing =
            storage.resolve_evidence_ui("evr_missing").expect("resolve missing evidence ref");
        assert!(missing.is_none());
    }

    fn ingest_fixture(storage: &mut Storage, fixture_name: &str, session_id: &str) {
        let fixture_path = fixture_path(fixture_name);
        let fixture_data = fs::read_to_string(fixture_path).expect("read fixture file");

        for line in fixture_data.lines().filter(|line| !line.trim().is_empty()) {
            let mut envelope: Value = serde_json::from_str(line).expect("parse fixture envelope");
            envelope["session_id"] = Value::String(session_id.to_string());
            let parsed: JsonEnvelope =
                serde_json::from_value(envelope).expect("parse fixture envelope type");
            storage.ingest_raw_event_envelope(&parsed).expect("ingest fixture envelope");
        }
    }

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/raw").join(name)
    }

    fn expected_snapshot_path(session_id: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/expected")
            .join(format!("{session_id}.snapshot.ndjson"))
    }

    fn expected_analysis_snapshot_path(session_id: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/expected")
            .join(format!("{session_id}.analysis.ndjson"))
    }

    fn assert_snapshot_matches(fixture_name: &str, session_id: &str) {
        let mut storage = Storage::open_in_memory().expect("open db");
        storage.apply_migrations().expect("apply migrations");
        ingest_fixture(&mut storage, fixture_name, session_id);
        storage.normalize_session(session_id).expect("normalize fixture");
        storage.correlate_session(session_id).expect("correlate fixture");

        let actual_rows = dump_correlated_rows(&storage, session_id);
        let expected_file = fs::read_to_string(expected_snapshot_path(session_id))
            .expect("read expected snapshot file");
        let expected_rows: Vec<String> = expected_file
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(ToOwned::to_owned)
            .collect();

        assert_eq!(actual_rows, expected_rows);
    }

    fn assert_detector_snapshot_matches(fixture_name: &str, session_id: &str) {
        let mut storage = Storage::open_in_memory().expect("open db");
        storage.apply_migrations().expect("apply migrations");
        ingest_fixture(&mut storage, fixture_name, session_id);
        storage.normalize_session(session_id).expect("normalize fixture");
        storage.correlate_session(session_id).expect("correlate fixture");
        storage.analyze_session(session_id).expect("analyze fixture");

        let actual_rows = storage.debug_dump_analysis_rows(session_id).expect("analysis rows");
        let expected_file = fs::read_to_string(expected_analysis_snapshot_path(session_id))
            .expect("read expected analysis snapshot file");
        let expected_rows: Vec<String> = expected_file
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(ToOwned::to_owned)
            .collect();

        assert_eq!(actual_rows, expected_rows);
    }

    fn count_rows(storage: &Storage, table: &str, session_id: &str) -> usize {
        if table == "interaction_members" {
            return storage
                .conn
                .query_row(
                    "SELECT COUNT(1)
                     FROM interaction_members im
                     JOIN interactions i ON i.interaction_id = im.interaction_id
                     WHERE i.session_id = ?1",
                    params![session_id],
                    |row| row.get::<_, i64>(0),
                )
                .expect("count interaction member rows")
                .try_into()
                .expect("row count fits usize");
        }
        storage
            .conn
            .query_row(
                &format!("SELECT COUNT(1) FROM {table} WHERE session_id = ?1"),
                params![session_id],
                |row| row.get::<_, i64>(0),
            )
            .expect("count table rows")
            .try_into()
            .expect("row count fits usize")
    }

    fn dump_correlated_rows(storage: &Storage, session_id: &str) -> Vec<String> {
        storage.debug_dump_correlation_rows(session_id).expect("debug dump correlation rows")
    }
}
