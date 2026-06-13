use crate::normalization::console::{normalize_log_entry, normalize_runtime_console};
use crate::normalization::headers::{headers_hash, headers_to_json, merge_headers};
use crate::normalization::lifecycle::normalize_page_lifecycle;
use crate::normalization::network::{
    default_timing_json, parse_network_mutation, CompletionRecord, NetworkMutation, RequestRecord,
    ResponseRecord,
};
use crate::normalization::streams::StreamAccumulator;
use crate::{canonical_json_string, decode_raw_payload, Result};
use dtt_core::RedactionLevel;
use rusqlite::{params, Connection};
use std::collections::HashMap;

pub(crate) mod console;
pub(crate) mod headers;
pub(crate) mod lifecycle;
pub(crate) mod network;
pub(crate) mod streams;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizationReport {
    pub session_id: String,
    pub raw_events_seen: usize,
    pub network_requests_written: usize,
    pub network_responses_written: usize,
    pub network_completion_written: usize,
    pub console_entries_written: usize,
    pub page_lifecycle_written: usize,
    pub skipped_events: usize,
}

#[derive(Debug, Clone)]
struct RawEventRow {
    event_id: String,
    event_seq: i64,
    ts_ms: i64,
    cdp_method: String,
    payload_encoding: String,
    payload_bytes: Vec<u8>,
    redaction_level: RedactionLevel,
}

#[derive(Debug, Clone)]
struct RequestState {
    record: RequestRecord,
}

#[derive(Debug, Clone)]
struct ResponseState {
    record: ResponseRecord,
}

pub(crate) fn normalize_session(
    conn: &mut Connection,
    session_id: &str,
) -> Result<NormalizationReport> {
    // Authoritative CDP-to-table mapping:
    // - Network.requestWillBeSent / Network.requestWillBeSentExtraInfo -> network_requests
    // - Network.responseReceived / Network.responseReceivedExtraInfo -> network_responses
    // - Network.dataReceived / Network.loadingFinished / Network.loadingFailed -> stream_summary_json + network_completion
    // - Runtime.consoleAPICalled / Log.entryAdded -> console_entries
    // - Page.lifecycleEvent / Page.loadEventFired / Page.domContentEventFired -> page_lifecycle
    let raw_events = load_raw_events(conn, session_id)?;

    let tx = conn.transaction()?;
    clear_session_normalized_tables(&tx, session_id)?;

    let mut request_states: HashMap<String, RequestState> = HashMap::new();
    let mut response_states: HashMap<String, ResponseState> = HashMap::new();
    let mut stream_states: HashMap<String, StreamAccumulator> = HashMap::new();

    let mut report = NormalizationReport {
        session_id: session_id.to_string(),
        raw_events_seen: raw_events.len(),
        network_requests_written: 0,
        network_responses_written: 0,
        network_completion_written: 0,
        console_entries_written: 0,
        page_lifecycle_written: 0,
        skipped_events: 0,
    };

    for row in raw_events {
        let raw_payload = decode_raw_payload(&row.payload_encoding, &row.payload_bytes)?;
        let cdp_method = row.cdp_method.as_str().to_string();

        if let Some(mutation) = parse_network_mutation(
            &cdp_method,
            row.event_seq,
            row.ts_ms,
            &raw_payload,
            row.redaction_level,
        ) {
            apply_network_mutation(
                &tx,
                session_id,
                &mutation,
                &mut request_states,
                &mut response_states,
                &mut stream_states,
                &mut report,
            )?;
            continue;
        }

        if cdp_method == "Runtime.consoleAPICalled" {
            if let Some(console) = normalize_runtime_console(&row.event_id, &raw_payload) {
                report.console_entries_written +=
                    insert_console_entry(&tx, session_id, row.ts_ms, &console)?;
            } else {
                report.skipped_events += 1;
            }
            continue;
        }

        if cdp_method == "Log.entryAdded" {
            if let Some(console) = normalize_log_entry(&row.event_id, &raw_payload) {
                report.console_entries_written +=
                    insert_console_entry(&tx, session_id, row.ts_ms, &console)?;
            } else {
                report.skipped_events += 1;
            }
            continue;
        }

        if cdp_method.starts_with("Page.") {
            if let Some(lifecycle) =
                normalize_page_lifecycle(&row.event_id, &cdp_method, &raw_payload)
            {
                report.page_lifecycle_written +=
                    insert_page_lifecycle(&tx, session_id, row.ts_ms, &lifecycle)?;
            } else {
                report.skipped_events += 1;
            }
            continue;
        }

        report.skipped_events += 1;
    }

    tx.commit()?;
    Ok(report)
}

fn apply_network_mutation(
    conn: &Connection,
    session_id: &str,
    mutation: &NetworkMutation,
    request_states: &mut HashMap<String, RequestState>,
    response_states: &mut HashMap<String, ResponseState>,
    stream_states: &mut HashMap<String, StreamAccumulator>,
    report: &mut NormalizationReport,
) -> Result<()> {
    match mutation {
        NetworkMutation::RequestWillBeSent(request_row) => {
            let state = request_states
                .entry(request_row.net_request_id.clone())
                .or_insert_with(|| RequestState { record: request_row.clone() });

            state.record.event_seq = request_row.event_seq;
            state.record.ts_ms = request_row.ts_ms;
            state.record.started_at_ms = request_row.started_at_ms;
            state.record.method = request_row.method.clone();
            state.record.scheme = request_row.scheme.clone();
            state.record.host = request_row.host.clone();
            state.record.port = request_row.port;
            state.record.path = request_row.path.clone();
            state.record.query = request_row.query.clone();
            state.record.timing_json = request_row.timing_json.clone();
            state.record.redaction_level = request_row.redaction_level;
            merge_headers(&mut state.record.request_headers, request_row.request_headers.clone());

            report.network_requests_written +=
                upsert_network_request(conn, session_id, &state.record)?;
        }
        NetworkMutation::RequestWillBeSentExtraInfo { request_id, headers } => {
            let state = request_states.entry(request_id.clone()).or_insert_with(|| RequestState {
                record: RequestRecord {
                    net_request_id: request_id.clone(),
                    event_seq: 0,
                    ts_ms: 0,
                    started_at_ms: 0,
                    method: None,
                    scheme: None,
                    host: None,
                    port: None,
                    path: None,
                    query: None,
                    request_headers: dtt_core::HeaderMap::new(),
                    timing_json: default_timing_json(0.0),
                    redaction_level: RedactionLevel::MetadataOnly,
                },
            });

            merge_headers(&mut state.record.request_headers, headers.clone());
            report.network_requests_written +=
                upsert_network_request(conn, session_id, &state.record)?;
        }
        NetworkMutation::ResponseReceived { response, response_timing_json } => {
            let stream = stream_states.entry(response.net_request_id.clone()).or_default();
            stream.observe_response_headers(&response.response_headers);
            let summary = stream.snapshot(None);

            let mut response_clone = response.clone();
            response_clone.stream_summary_json = Some(summary);
            response_clone.headers_hash = headers_hash(&response_clone.response_headers)?;

            let state = response_states
                .entry(response_clone.net_request_id.clone())
                .or_insert_with(|| ResponseState { record: response_clone.clone() });
            state.record.ts_ms = response_clone.ts_ms;
            state.record.status_code = response_clone.status_code;
            state.record.protocol = response_clone.protocol.clone();
            state.record.mime_type = response_clone.mime_type.clone();
            state.record.encoded_data_length = response_clone.encoded_data_length;
            state.record.redaction_level = response_clone.redaction_level;
            merge_headers(
                &mut state.record.response_headers,
                response_clone.response_headers.clone(),
            );
            state.record.headers_hash = headers_hash(&state.record.response_headers)?;
            state.record.stream_summary_json = response_clone.stream_summary_json.clone();

            report.network_responses_written +=
                upsert_network_response(conn, session_id, &state.record)?;

            if let Some(timing_json) = response_timing_json {
                if let Some(request_state) = request_states.get_mut(&response_clone.net_request_id)
                {
                    request_state.record.timing_json = timing_json.clone();
                    report.network_requests_written +=
                        upsert_network_request(conn, session_id, &request_state.record)?;
                }
            }
        }
        NetworkMutation::ResponseReceivedExtraInfo { request_id, headers } => {
            let state =
                response_states.entry(request_id.clone()).or_insert_with(|| ResponseState {
                    record: ResponseRecord {
                        net_request_id: request_id.clone(),
                        ts_ms: 0,
                        status_code: None,
                        protocol: None,
                        mime_type: None,
                        encoded_data_length: None,
                        response_headers: dtt_core::HeaderMap::new(),
                        headers_hash: String::new(),
                        stream_summary_json: None,
                        redaction_level: RedactionLevel::MetadataOnly,
                    },
                });

            merge_headers(&mut state.record.response_headers, headers.clone());
            state.record.headers_hash = headers_hash(&state.record.response_headers)?;

            let stream = stream_states.entry(request_id.clone()).or_default();
            stream.observe_response_headers(&state.record.response_headers);
            state.record.stream_summary_json = Some(stream.snapshot(None));

            report.network_responses_written +=
                upsert_network_response(conn, session_id, &state.record)?;
        }
        NetworkMutation::DataReceived { request_id, ts_ms, bytes } => {
            let stream = stream_states.entry(request_id.clone()).or_default();
            stream.observe_data(*ts_ms, *bytes);

            if let Some(response_state) = response_states.get_mut(request_id) {
                response_state.record.stream_summary_json = Some(stream.snapshot(None));
                report.network_responses_written +=
                    upsert_network_response(conn, session_id, &response_state.record)?;
            }
        }
        NetworkMutation::LoadingFinished { request_id, ts_ms, encoded_data_length } => {
            let stream = stream_states.entry(request_id.clone()).or_default();
            stream.observe_encoded_total(*encoded_data_length);
            let summary = stream.snapshot(Some(true));

            if let Some(response_state) = response_states.get_mut(request_id) {
                response_state.record.stream_summary_json = Some(summary);
                report.network_responses_written +=
                    upsert_network_response(conn, session_id, &response_state.record)?;
            }

            let started_at =
                request_states.get(request_id).map(|state| state.record.started_at_ms).unwrap_or(0);
            let ts_ms = *ts_ms;

            let completion = CompletionRecord {
                net_request_id: request_id.clone(),
                ts_ms,
                finished_at_ms: ts_ms,
                duration_ms: (ts_ms - started_at).max(0),
                success: true,
                error_text: None,
                canceled: false,
                blocked_reason: None,
            };

            report.network_completion_written +=
                upsert_network_completion(conn, session_id, &completion)?;
        }
        NetworkMutation::LoadingFailed { completion } => {
            let stream = stream_states.entry(completion.net_request_id.clone()).or_default();
            let summary = stream.snapshot(Some(false));

            if let Some(response_state) = response_states.get_mut(&completion.net_request_id) {
                response_state.record.stream_summary_json = Some(summary);
                report.network_responses_written +=
                    upsert_network_response(conn, session_id, &response_state.record)?;
            }

            let started_at = request_states
                .get(&completion.net_request_id)
                .map(|state| state.record.started_at_ms)
                .unwrap_or(completion.ts_ms);

            let mut failure = completion.clone();
            failure.duration_ms = (failure.finished_at_ms - started_at).max(0);
            report.network_completion_written +=
                upsert_network_completion(conn, session_id, &failure)?;
        }
        NetworkMutation::WebSocketActivity { request_id } => {
            let stream = stream_states.entry(request_id.clone()).or_default();
            stream.observe_method("Network.webSocketFrameReceived");

            if let Some(response_state) = response_states.get_mut(request_id) {
                response_state.record.stream_summary_json = Some(stream.snapshot(None));
                report.network_responses_written +=
                    upsert_network_response(conn, session_id, &response_state.record)?;
            }
        }
    }

    Ok(())
}

fn clear_session_normalized_tables(conn: &Connection, session_id: &str) -> Result<()> {
    for table in [
        "network_requests",
        "network_responses",
        "network_completion",
        "console_entries",
        "page_lifecycle",
    ] {
        conn.execute(&format!("DELETE FROM {table} WHERE session_id = ?1"), params![session_id])?;
    }

    Ok(())
}

fn load_raw_events(conn: &Connection, session_id: &str) -> Result<Vec<RawEventRow>> {
    let mut stmt = conn.prepare(
        "SELECT event_id, event_seq, ts_ms, cdp_method, payload_encoding, payload_bytes, redaction_level
         FROM events_raw
         WHERE session_id = ?1
         ORDER BY event_seq ASC, ts_ms ASC, event_id ASC",
    )?;

    let rows = stmt.query_map(params![session_id], |row| {
        let redaction_raw: String = row.get(6)?;
        let redaction_level = match redaction_raw.as_str() {
            "metadata_only" => RedactionLevel::MetadataOnly,
            "redacted" => RedactionLevel::Redacted,
            "full" => RedactionLevel::Full,
            _ => RedactionLevel::MetadataOnly,
        };

        Ok(RawEventRow {
            event_id: row.get(0)?,
            event_seq: row.get(1)?,
            ts_ms: row.get(2)?,
            cdp_method: row.get(3)?,
            payload_encoding: row.get(4)?,
            payload_bytes: row.get(5)?,
            redaction_level,
        })
    })?;

    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }

    Ok(out)
}

fn upsert_network_request(
    conn: &Connection,
    session_id: &str,
    request: &RequestRecord,
) -> Result<usize> {
    let headers_json = canonical_json_string(&headers_to_json(&request.request_headers))?;
    let timing_json = canonical_json_string(&request.timing_json)?;

    Ok(conn.execute(
        "INSERT INTO network_requests (
            net_request_id,
            session_id,
            started_at_ms,
            ts_ms,
            method,
            host,
            path,
            request_headers_json,
            timing_json,
            event_seq,
            scheme,
            port,
            query,
            redaction_level
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
         ON CONFLICT(net_request_id) DO UPDATE SET
            session_id = excluded.session_id,
            started_at_ms = excluded.started_at_ms,
            ts_ms = excluded.ts_ms,
            method = excluded.method,
            host = excluded.host,
            path = excluded.path,
            request_headers_json = excluded.request_headers_json,
            timing_json = excluded.timing_json,
            event_seq = excluded.event_seq,
            scheme = excluded.scheme,
            port = excluded.port,
            query = excluded.query,
            redaction_level = excluded.redaction_level",
        params![
            request.net_request_id,
            session_id,
            request.started_at_ms,
            request.ts_ms,
            request.method,
            request.host,
            request.path,
            headers_json,
            timing_json,
            request.event_seq,
            request.scheme,
            request.port,
            request.query,
            request.redaction_level.as_str(),
        ],
    )?)
}

fn upsert_network_response(
    conn: &Connection,
    session_id: &str,
    response: &ResponseRecord,
) -> Result<usize> {
    let headers_json = canonical_json_string(&headers_to_json(&response.response_headers))?;
    let summary_json =
        response.stream_summary_json.as_ref().map(canonical_json_string).transpose()?;

    Ok(conn.execute(
        "INSERT INTO network_responses (
            net_request_id,
            session_id,
            ts_ms,
            status_code,
            response_headers_json,
            headers_hash,
            stream_summary_json,
            protocol,
            mime_type,
            encoded_data_length,
            redaction_level
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
         ON CONFLICT(net_request_id) DO UPDATE SET
            session_id = excluded.session_id,
            ts_ms = excluded.ts_ms,
            status_code = excluded.status_code,
            response_headers_json = excluded.response_headers_json,
            headers_hash = excluded.headers_hash,
            stream_summary_json = excluded.stream_summary_json,
            protocol = excluded.protocol,
            mime_type = excluded.mime_type,
            encoded_data_length = excluded.encoded_data_length,
            redaction_level = excluded.redaction_level",
        params![
            response.net_request_id,
            session_id,
            response.ts_ms,
            response.status_code,
            headers_json,
            response.headers_hash,
            summary_json,
            response.protocol,
            response.mime_type,
            response.encoded_data_length,
            response.redaction_level.as_str(),
        ],
    )?)
}

fn upsert_network_completion(
    conn: &Connection,
    session_id: &str,
    completion: &CompletionRecord,
) -> Result<usize> {
    Ok(conn.execute(
        "INSERT INTO network_completion (
            net_request_id,
            session_id,
            ts_ms,
            duration_ms,
            success,
            error_text,
            finished_at_ms,
            canceled,
            blocked_reason
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(net_request_id) DO UPDATE SET
            session_id = excluded.session_id,
            ts_ms = excluded.ts_ms,
            duration_ms = excluded.duration_ms,
            success = excluded.success,
            error_text = excluded.error_text,
            finished_at_ms = excluded.finished_at_ms,
            canceled = excluded.canceled,
            blocked_reason = excluded.blocked_reason",
        params![
            completion.net_request_id,
            session_id,
            completion.ts_ms,
            completion.duration_ms,
            if completion.success { 1 } else { 0 },
            completion.error_text,
            completion.finished_at_ms,
            if completion.canceled { 1 } else { 0 },
            completion.blocked_reason,
        ],
    )?)
}

fn insert_console_entry(
    conn: &Connection,
    session_id: &str,
    ts_ms: i64,
    console: &console::ConsoleEntryRecord,
) -> Result<usize> {
    Ok(conn.execute(
        "INSERT OR REPLACE INTO console_entries (
            console_id,
            session_id,
            ts_ms,
            level,
            source,
            message_redacted,
            message_hash,
            message_len
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            console.console_id,
            session_id,
            ts_ms,
            console.level,
            console.source,
            console.message_redacted,
            console.message_hash,
            console.message_len,
        ],
    )?)
}

fn insert_page_lifecycle(
    conn: &Connection,
    session_id: &str,
    ts_ms: i64,
    lifecycle: &lifecycle::LifecycleRecord,
) -> Result<usize> {
    Ok(conn.execute(
        "INSERT OR REPLACE INTO page_lifecycle (
            lifecycle_id,
            session_id,
            ts_ms,
            frame_id,
            loader_id,
            name,
            value_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            lifecycle.lifecycle_id,
            session_id,
            ts_ms,
            lifecycle.frame_id,
            lifecycle.loader_id,
            lifecycle.name,
            lifecycle.value_json,
        ],
    )?)
}

#[cfg(test)]
mod tests {
    use crate::{Storage, ENVELOPE_VERSION, EVT_RAW_EVENT};
    use rusqlite::params;
    use serde_json::Value;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn normalize_fixture_populates_required_tables() {
        let mut storage = Storage::open_in_memory().expect("open in-memory db");
        storage.apply_migrations().expect("apply migrations");

        ingest_fixture(&mut storage, "fx_phase3_normalization.ndjson", "fx_sess_001");

        let report = storage.normalize_session("fx_sess_001").expect("normalize fixture session");

        assert!(report.raw_events_seen > 0);
        assert!(report.network_requests_written > 0);
        assert!(report.network_responses_written > 0);
        assert!(report.network_completion_written > 0);
        assert!(report.console_entries_written > 0);
        assert!(report.page_lifecycle_written > 0);

        assert!(count_rows(&storage, "network_requests", "fx_sess_001") > 0);
        assert!(count_rows(&storage, "network_responses", "fx_sess_001") > 0);
        assert!(count_rows(&storage, "network_completion", "fx_sess_001") > 0);
        assert!(count_rows(&storage, "console_entries", "fx_sess_001") > 0);
        assert!(count_rows(&storage, "page_lifecycle", "fx_sess_001") > 0);
    }

    #[test]
    fn normalization_is_deterministic_across_replays() {
        let mut left = Storage::open_in_memory().expect("left db");
        left.apply_migrations().expect("left migrations");
        ingest_fixture(&mut left, "fx_phase3_normalization.ndjson", "fx_sess_001");
        left.normalize_session("fx_sess_001").expect("left normalize");

        let mut right = Storage::open_in_memory().expect("right db");
        right.apply_migrations().expect("right migrations");
        ingest_fixture(&mut right, "fx_phase3_normalization.ndjson", "fx_sess_001");
        right.normalize_session("fx_sess_001").expect("right normalize");

        let left_dump = dump_session_rows(&left, "fx_sess_001");
        let right_dump = dump_session_rows(&right, "fx_sess_001");

        assert_eq!(left_dump, right_dump);
    }

    fn ingest_fixture(storage: &mut Storage, fixture_name: &str, session_id: &str) {
        let fixture_path = fixture_path(fixture_name);
        let fixture_data = fs::read_to_string(fixture_path).expect("read fixture file");

        for line in fixture_data.lines().filter(|line| !line.trim().is_empty()) {
            let mut envelope: Value = serde_json::from_str(line).expect("parse fixture envelope");
            envelope["session_id"] = Value::String(session_id.to_string());
            let parsed = serde_json::from_value(envelope).expect("parse envelope type");
            storage.ingest_raw_event_envelope(&parsed).expect("ingest fixture envelope");
        }
    }

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/raw").join(name)
    }

    fn count_rows(storage: &Storage, table: &str, session_id: &str) -> usize {
        storage
            .conn
            .query_row(
                &format!("SELECT COUNT(1) FROM {table} WHERE session_id = ?1"),
                params![session_id],
                |row| row.get::<_, i64>(0),
            )
            .expect("count rows")
            .try_into()
            .expect("row count fits usize")
    }

    fn dump_session_rows(storage: &Storage, session_id: &str) -> Vec<String> {
        let mut rows = Vec::new();

        for statement in [
            "SELECT json_object('table','network_requests','id',net_request_id,'v',json_object('event_seq',event_seq,'method',method,'host',host,'path',path,'headers',request_headers_json,'timing',timing_json,'scheme',scheme,'port',port,'query',query,'redaction',redaction_level)) FROM network_requests WHERE session_id=?1 ORDER BY net_request_id",
            "SELECT json_object('table','network_responses','id',net_request_id,'v',json_object('status',status_code,'protocol',protocol,'mime_type',mime_type,'encoded_data_length',encoded_data_length,'headers',response_headers_json,'headers_hash',headers_hash,'stream_summary',stream_summary_json,'redaction',redaction_level)) FROM network_responses WHERE session_id=?1 ORDER BY net_request_id",
            "SELECT json_object('table','network_completion','id',net_request_id,'v',json_object('duration_ms',duration_ms,'success',success,'error_text',error_text,'finished_at_ms',finished_at_ms,'canceled',canceled,'blocked_reason',blocked_reason)) FROM network_completion WHERE session_id=?1 ORDER BY net_request_id",
            "SELECT json_object('table','console_entries','id',console_id,'v',json_object('level',level,'source',source,'message_redacted',message_redacted,'message_hash',message_hash,'message_len',message_len)) FROM console_entries WHERE session_id=?1 ORDER BY console_id",
            "SELECT json_object('table','page_lifecycle','id',lifecycle_id,'v',json_object('name',name,'frame_id',frame_id,'loader_id',loader_id,'value_json',value_json)) FROM page_lifecycle WHERE session_id=?1 ORDER BY lifecycle_id",
        ] {
            let mut stmt = storage.conn.prepare(statement).expect("prepare dump query");
            let values = stmt
                .query_map(params![session_id], |row| row.get::<_, String>(0))
                .expect("query dump rows");

            for value in values {
                rows.push(value.expect("row value"));
            }
        }

        rows
    }

    #[test]
    fn fixture_records_use_expected_envelope_version() {
        assert_eq!(ENVELOPE_VERSION, 1);
        assert_eq!(EVT_RAW_EVENT, "evt.raw_event");
    }
}
