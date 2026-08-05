use glassbox_browser_ipc::{
    AttachmentBroker, AttachmentChallenge, AttachmentRequest, BrowserFrame, ProductionPolicy,
    SessionCredential, MAX_FRAME_BYTES,
};
use glassbox_contracts::{
    EvidenceRelation, LineageId, MaterializationId, NativeObservation, RelationBasis,
    RelationProvenance, RelationProvenanceRecord, SemanticObservationId, SourceTrust, TimeInterval,
};
use glassbox_evidence_bundle::write_lossless;
use glassbox_kernel::EvidenceKernel;
use glassbox_privacy::{pseudonym, redact_url};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::Duration;
use thiserror::Error;
use zeroize::Zeroizing;

const HOST_NAME: &str = "com.glassbox.browser";
const EXTENSION_ID: &str = "giffhfldblangaphoeeeelcapcmedjbd";
const TEAM_ID: &str = "3TGZFKFNA4";
const MAX_OBSERVATIONS: usize = 100_000;
const MAX_SESSION_NS: i128 = 30 * 60 * 1_000_000_000;
const MAX_UNCERTAINTY_NS: u64 = 60 * 1_000_000_000;
const WATCHDOG_POLL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum HostRequest {
    Attach { request: AttachmentRequest },
    Exchange { challenge: AttachmentChallenge },
    Frame { frame: BrowserFrame },
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum HostResponse {
    Challenge {
        challenge: AttachmentChallenge,
    },
    Credential {
        credential: SessionCredential,
    },
    Accepted {
        sequence: u64,
    },
    Completed {
        schema_version: &'static str,
        file_name: String,
        observations: usize,
        relations: usize,
        bundle_bytes: usize,
        bundle_sha256: String,
    },
    Rejected {
        code: &'static str,
    },
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum BrowserPayload {
    Navigation {
        observed_unix_ns: String,
        uncertainty_ns: u64,
        url: String,
    },
    Request {
        observed_unix_ns: String,
        uncertainty_ns: u64,
        request_id: String,
        method: String,
        resource_type: String,
        url: String,
    },
    Response {
        observed_unix_ns: String,
        uncertainty_ns: u64,
        request_id: String,
        status: u16,
        encoded_body_bytes: Option<u64>,
    },
    UserAction {
        observed_unix_ns: String,
        uncertainty_ns: u64,
        action: UserAction,
    },
    Gap {
        observed_unix_ns: String,
        uncertainty_ns: u64,
        reason: GapReason,
        dropped_count: u64,
    },
    Stop {
        observed_unix_ns: String,
        uncertainty_ns: u64,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum UserAction {
    Click,
    Submit,
    Navigation,
    Reload,
}

impl UserAction {
    fn name(&self) -> &'static str {
        match self {
            Self::Click => "click",
            Self::Submit => "submit",
            Self::Navigation => "navigation",
            Self::Reload => "reload",
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum GapReason {
    DevtoolsOpenedLate,
    BufferOverflow,
    TabNavigated,
    BrowserDisconnect,
}

impl GapReason {
    fn name(&self) -> &'static str {
        match self {
            Self::DevtoolsOpenedLate => "devtools_opened_late",
            Self::BufferOverflow => "buffer_overflow",
            Self::TabNavigated => "tab_navigated",
            Self::BrowserDisconnect => "browser_disconnect",
        }
    }
}

struct Capture {
    capture_session: String,
    scope_key: Zeroizing<[u8; 32]>,
    first_time_ns: Option<i128>,
    last_time_ns: Option<i128>,
    observations: Vec<NativeObservation>,
    relations: Vec<EvidenceRelation>,
    requests: HashMap<String, SemanticObservationId>,
}

impl Capture {
    fn new() -> Result<Self, HostError> {
        let mut random = [0_u8; 64];
        File::open("/dev/urandom")?.read_exact(&mut random)?;
        Ok(Self {
            capture_session: format!("browser_{}", hex::encode(&random[..16])),
            scope_key: Zeroizing::new(random[32..].try_into().expect("fixed scope key")),
            first_time_ns: None,
            last_time_ns: None,
            observations: Vec::new(),
            relations: Vec::new(),
            requests: HashMap::new(),
        })
    }

    fn accept(&mut self, frame: &BrowserFrame) -> Result<bool, HostError> {
        if self.observations.len() >= MAX_OBSERVATIONS {
            return Err(HostError::LimitExceeded);
        }
        let payload: BrowserPayload =
            serde_json::from_value(frame.payload.clone()).map_err(|_| HostError::InvalidPayload)?;
        let ordinal = self.observations.len();
        let (time, event, mut fields, request_id, terminal) = match payload {
            BrowserPayload::Navigation { observed_unix_ns, uncertainty_ns, url } => (
                interval(&observed_unix_ns, uncertainty_ns)?,
                "navigation",
                BTreeMap::from([("url".into(), redact_url(&url, &self.scope_key)?)]),
                None,
                false,
            ),
            BrowserPayload::Request {
                observed_unix_ns,
                uncertainty_ns,
                request_id,
                method,
                resource_type,
                url,
            } => {
                validate_token(&request_id)?;
                if !matches!(
                    method.as_str(),
                    "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
                ) || !matches!(
                    resource_type.as_str(),
                    "document"
                        | "stylesheet"
                        | "image"
                        | "media"
                        | "font"
                        | "script"
                        | "xhr"
                        | "fetch"
                        | "websocket"
                        | "other"
                ) {
                    return Err(HostError::InvalidPayload);
                }
                let request_key = pseudonym(&self.scope_key, &request_id)?;
                (
                    interval(&observed_unix_ns, uncertainty_ns)?,
                    "request",
                    BTreeMap::from([
                        ("request_key".into(), request_key),
                        ("method".into(), method),
                        ("resource_type".into(), resource_type),
                        ("url".into(), redact_url(&url, &self.scope_key)?),
                    ]),
                    Some(request_id),
                    false,
                )
            }
            BrowserPayload::Response {
                observed_unix_ns,
                uncertainty_ns,
                request_id,
                status,
                encoded_body_bytes,
            } => {
                validate_token(&request_id)?;
                if !(100..=599).contains(&status) {
                    return Err(HostError::InvalidPayload);
                }
                let mut fields = BTreeMap::from([
                    ("request_key".into(), pseudonym(&self.scope_key, &request_id)?),
                    ("status".into(), status.to_string()),
                ]);
                if let Some(size) = encoded_body_bytes {
                    fields.insert("encoded_body_bytes".into(), size.to_string());
                }
                (
                    interval(&observed_unix_ns, uncertainty_ns)?,
                    "response",
                    fields,
                    Some(request_id),
                    false,
                )
            }
            BrowserPayload::UserAction { observed_unix_ns, uncertainty_ns, action } => (
                interval(&observed_unix_ns, uncertainty_ns)?,
                "user_action",
                BTreeMap::from([("action".into(), action.name().into())]),
                None,
                false,
            ),
            BrowserPayload::Gap { observed_unix_ns, uncertainty_ns, reason, dropped_count } => (
                interval(&observed_unix_ns, uncertainty_ns)?,
                "gap",
                BTreeMap::from([
                    ("reason".into(), reason.name().into()),
                    ("dropped_count".into(), dropped_count.to_string()),
                ]),
                None,
                false,
            ),
            BrowserPayload::Stop { observed_unix_ns, uncertainty_ns } => (
                interval(&observed_unix_ns, uncertainty_ns)?,
                "session_end",
                BTreeMap::from([("reason".into(), "user_stop".into())]),
                None,
                true,
            ),
        };
        if event == "request"
            && request_id.as_ref().is_some_and(|id| self.requests.contains_key(id))
        {
            return Err(HostError::DuplicateRequest);
        }
        if event == "response"
            && request_id.as_ref().is_some_and(|id| !self.requests.contains_key(id))
        {
            return Err(HostError::MissingRequest);
        }
        if self.last_time_ns.is_some_and(|last| time.latest_ns < last) {
            return Err(HostError::NonMonotonicTime);
        }
        if let Some(first) = self.first_time_ns {
            if time.latest_ns.saturating_sub(first) > MAX_SESSION_NS {
                return Err(HostError::LimitExceeded);
            }
        } else {
            self.first_time_ns = Some(time.earliest_ns);
        }
        self.last_time_ns = Some(time.latest_ns);
        fields.insert("event".into(), event.into());
        fields.insert("selected_tab_only".into(), "true".into());
        fields.insert("not_causal_evidence".into(), "true".into());
        let native_id = format!("browser://selected-tab/{}/{ordinal}", self.capture_session);
        let semantic_id =
            SemanticObservationId::derive("chrome-selected-tab", &self.capture_session, &native_id);
        let trust = if event == "user_action" {
            SourceTrust::UserAsserted
        } else {
            SourceTrust::SignedUntrusted
        };
        let observation = NativeObservation {
            semantic_id: semantic_id.clone(),
            materialization_id: MaterializationId(format!(
                "browser-materialization:{}:{ordinal}",
                self.capture_session
            )),
            lineage_id: LineageId(format!("browser-lineage:{}:{ordinal}", self.capture_session)),
            source_kind: "chrome-selected-tab".into(),
            capture_session: self.capture_session.clone(),
            native_id,
            observed_time: time,
            trust,
            fields,
        };
        if event == "request" {
            let request_id = request_id.expect("request identifier");
            self.requests.insert(request_id, semantic_id.clone());
        } else if event == "response" {
            let request_id = request_id.expect("response identifier");
            let from = self.requests.get(&request_id).ok_or(HostError::MissingRequest)?.clone();
            self.relations.push(EvidenceRelation::derive(
                from.clone(),
                semantic_id.clone(),
                RelationBasis::SharedAddressableKey,
                RelationProvenanceRecord {
                    class: RelationProvenance::DeterministicJoin,
                    rule_version: "browser-request-response/v1".into(),
                    inputs: vec![from.clone(), semantic_id.clone()],
                    supporting_evidence: vec![from, semantic_id.clone()],
                    counterevidence: vec![],
                    missing_evidence: vec![],
                    falsifier: None,
                    clock_uncertainty: Some(time),
                },
            )?);
            self.requests.remove(&request_id);
        }
        self.observations.push(observation);
        Ok(terminal)
    }

    fn publish(&self) -> Result<Published, HostError> {
        if self.observations.is_empty()
            || self
                .observations
                .last()
                .and_then(|item| item.fields.get("event"))
                .map(String::as_str)
                != Some("session_end")
        {
            return Err(HostError::IncompleteSession);
        }
        let mut kernel = EvidenceKernel::default();
        kernel.import_atomic(self.observations.clone(), self.relations.clone())?;
        let mut bundle = Vec::new();
        write_lossless(&mut bundle, &self.observations, &self.relations)?;
        let sha256 = format!("{:x}", Sha256::digest(&bundle));
        let inbox = inbox_directory()?;
        fs::create_dir_all(&inbox)?;
        fs::set_permissions(&inbox, fs::Permissions::from_mode(0o700))?;
        let file_name = format!("{}.glassbox", self.capture_session);
        let destination = inbox.join(&file_name);
        let temporary = inbox.join(format!(".{}.partial", self.capture_session));
        let mut output =
            OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temporary)?;
        if let Err(error) = output.write_all(&bundle).and_then(|_| output.sync_all()) {
            let _ = fs::remove_file(&temporary);
            return Err(error.into());
        }
        drop(output);
        if destination.exists() {
            let _ = fs::remove_file(&temporary);
            return Err(HostError::DestinationExists);
        }
        fs::rename(&temporary, &destination)?;
        Ok(Published {
            file_name,
            observations: self.observations.len(),
            relations: self.relations.len(),
            bundle_bytes: bundle.len(),
            bundle_sha256: sha256,
        })
    }
}

struct Published {
    file_name: String,
    observations: usize,
    relations: usize,
    bundle_bytes: usize,
    bundle_sha256: String,
}

fn main() {
    if run().is_err() {
        let _ = write_message(
            &mut io::stdout().lock(),
            &HostResponse::Rejected { code: "request_rejected" },
        );
        eprintln!("glassbox browser host: request rejected");
        std::process::exit(1);
    }
}

fn run() -> Result<(), HostError> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments != [format!("chrome-extension://{EXTENSION_ID}/")] {
        return Err(HostError::WrongOrigin);
    }
    let mut random = Zeroizing::new(vec![0_u8; 32]);
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    let policy = ProductionPolicy {
        host_name: HOST_NAME.into(),
        extension_id: EXTENSION_ID.into(),
        install_root: "/Applications/Glassbox Browser Adapter.app/Contents/Helpers".into(),
        expected_team_id: TEAM_ID.into(),
    };
    let mut broker = AttachmentBroker::new(policy, &random)?;
    let mut capture = Capture::new()?;
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut input = io::stdin().lock();
        loop {
            let message = read_message(&mut input);
            let terminal = message.is_err();
            if sender.send(message).is_err() || terminal {
                return;
            }
        }
    });
    let mut output = io::stdout().lock();
    loop {
        let message = match receiver.recv_timeout(WATCHDOG_POLL_INTERVAL) {
            Ok(message) => message?,
            Err(RecvTimeoutError::Timeout) => {
                if broker.watchdog(now_ms()?) {
                    return Err(HostError::WatchdogExpired);
                }
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => return Err(HostError::InvalidFrame),
        };
        match message {
            HostRequest::Attach { request } => {
                let challenge = broker.issue_challenge(request, now_ms()?)?;
                write_message(&mut output, &HostResponse::Challenge { challenge })?;
            }
            HostRequest::Exchange { challenge } => {
                let credential = broker.exchange_challenge(&challenge, now_ms()?)?;
                write_message(&mut output, &HostResponse::Credential { credential })?;
            }
            HostRequest::Frame { frame } => {
                let sequence = frame.sequence;
                let frame = broker.accept_frame(&serde_json::to_vec(&frame)?, now_ms()?)?;
                if capture.accept(&frame)? {
                    let published = capture.publish()?;
                    write_message(
                        &mut output,
                        &HostResponse::Completed {
                            schema_version: "glassbox-browser-evidence/v1",
                            file_name: published.file_name,
                            observations: published.observations,
                            relations: published.relations,
                            bundle_bytes: published.bundle_bytes,
                            bundle_sha256: published.bundle_sha256,
                        },
                    )?;
                    return Ok(());
                }
                write_message(&mut output, &HostResponse::Accepted { sequence })?;
            }
        }
    }
}

fn read_message<R: Read>(input: &mut R) -> Result<HostRequest, HostError> {
    let mut length = [0_u8; 4];
    input.read_exact(&mut length)?;
    let length = u32::from_le_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(HostError::InvalidFrame);
    }
    let mut payload = vec![0_u8; length];
    input.read_exact(&mut payload)?;
    serde_json::from_slice(&payload).map_err(|_| HostError::InvalidFrame)
}

fn write_message<W: Write>(output: &mut W, message: &HostResponse) -> Result<(), HostError> {
    let payload = serde_json::to_vec(message)?;
    if payload.len() > MAX_FRAME_BYTES {
        return Err(HostError::InvalidFrame);
    }
    output.write_all(&(payload.len() as u32).to_le_bytes())?;
    output.write_all(&payload)?;
    output.flush()?;
    Ok(())
}

fn interval(value: &str, uncertainty_ns: u64) -> Result<TimeInterval, HostError> {
    if uncertainty_ns > MAX_UNCERTAINTY_NS {
        return Err(HostError::InvalidPayload);
    }
    let center = value.parse::<i128>().map_err(|_| HostError::InvalidPayload)?;
    TimeInterval::new(
        center.saturating_sub(i128::from(uncertainty_ns)),
        center.saturating_add(i128::from(uncertainty_ns)),
    )
    .map_err(Into::into)
}

fn validate_token(value: &str) -> Result<(), HostError> {
    if !(1..=128).contains(&value.len())
        || !value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(HostError::InvalidPayload);
    }
    Ok(())
}

fn now_ms() -> Result<u64, HostError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| HostError::Clock)?
        .as_millis()
        .try_into()
        .map_err(|_| HostError::Clock)
}

fn inbox_directory() -> Result<PathBuf, HostError> {
    let home = std::env::var_os("HOME").ok_or(HostError::MissingHome)?;
    Ok(Path::new(&home).join("Library/Application Support/Glassbox Browser Adapter/Inbox"))
}

#[derive(Debug, Error)]
enum HostError {
    #[error("native messaging origin rejected")]
    WrongOrigin,
    #[error("native messaging frame rejected")]
    InvalidFrame,
    #[error("browser payload rejected")]
    InvalidPayload,
    #[error("browser capture limit exceeded")]
    LimitExceeded,
    #[error("response lacks an accepted request")]
    MissingRequest,
    #[error("request identifier was already pending")]
    DuplicateRequest,
    #[error("browser capture time moved backward")]
    NonMonotonicTime,
    #[error("authenticated browser session exceeded its idle watchdog")]
    WatchdogExpired,
    #[error("capture is incomplete")]
    IncompleteSession,
    #[error("destination already exists")]
    DestinationExists,
    #[error("home directory unavailable")]
    MissingHome,
    #[error("clock unavailable")]
    Clock,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Ipc(#[from] glassbox_browser_ipc::BrowserIpcError),
    #[error(transparent)]
    Privacy(#[from] glassbox_privacy::PrivacyError),
    #[error(transparent)]
    Contract(#[from] glassbox_contracts::ContractError),
    #[error(transparent)]
    Kernel(#[from] glassbox_kernel::KernelError),
    #[error(transparent)]
    Bundle(#[from] glassbox_evidence_bundle::BundleError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(payload: serde_json::Value, sequence: u64) -> BrowserFrame {
        BrowserFrame {
            protocol_version: 1,
            context: glassbox_browser_ipc::AttachmentContext {
                extension_id: EXTENSION_ID.into(),
                browser_attachment_id: "attachment_123456789".into(),
                selected_tab_id: 42,
                request_id: "attachment_request_123".into(),
                session_nonce: "session_nonce_123456".into(),
            },
            session_token: "ignored_in_capture_unit".into(),
            sequence,
            payload,
        }
    }

    #[test]
    fn strict_metadata_projection_redacts_urls_and_links_request_response() {
        let mut capture = Capture::new().unwrap();
        let now = "1720000000000000000";
        capture
            .accept(&frame(
                serde_json::json!({
                    "kind":"request", "observed_unix_ns":now, "uncertainty_ns":1000,
                    "request_id":"request_1", "method":"POST", "resource_type":"fetch",
                    "url":"https://user:pass@example.test/private/secret?token=seeded-secret&safe=1#fragment"
                }),
                1,
            ))
            .unwrap();
        capture
            .accept(&frame(
                serde_json::json!({
                    "kind":"response", "observed_unix_ns":now, "uncertainty_ns":1000,
                    "request_id":"request_1", "status":204, "encoded_body_bytes":0
                }),
                2,
            ))
            .unwrap();
        assert_eq!(capture.observations.len(), 2);
        assert_eq!(capture.relations.len(), 1);
        let encoded = serde_json::to_string(&capture.observations).unwrap();
        for secret in ["example.test", "seeded-secret", "user", "pass", "fragment", "request_1"] {
            assert!(!encoded.contains(secret));
        }
        assert!(encoded.contains("psn:"));
        assert_eq!(capture.observations[0].trust, SourceTrust::SignedUntrusted);
    }

    #[test]
    fn unknown_fields_unbounded_uncertainty_and_orphan_response_fail_closed() {
        let mut capture = Capture::new().unwrap();
        let unknown = frame(
            serde_json::json!({
                "kind":"navigation", "observed_unix_ns":"1720000000000000000",
                "uncertainty_ns":1, "url":"https://example.test/", "secret":"no"
            }),
            1,
        );
        assert!(capture.accept(&unknown).is_err());
        let unbounded = frame(
            serde_json::json!({
                "kind":"navigation", "observed_unix_ns":"1720000000000000000",
                "uncertainty_ns":MAX_UNCERTAINTY_NS + 1, "url":"https://example.test/"
            }),
            2,
        );
        assert!(capture.accept(&unbounded).is_err());
        let orphan = frame(
            serde_json::json!({
                "kind":"response", "observed_unix_ns":"1720000000000000000",
                "uncertainty_ns":1, "request_id":"missing", "status":200,
                "encoded_body_bytes":0
            }),
            3,
        );
        assert!(capture.accept(&orphan).is_err());
        assert!(capture.observations.is_empty());
    }

    #[test]
    fn request_ids_are_unique_pending_capabilities_and_responses_consume_them() {
        let mut capture = Capture::new().unwrap();
        let request = frame(
            serde_json::json!({
                "kind":"request", "observed_unix_ns":"1720000000000000000",
                "uncertainty_ns":1, "request_id":"request_1", "method":"GET",
                "resource_type":"document", "url":"https://example.test/"
            }),
            1,
        );
        capture.accept(&request).unwrap();
        assert!(matches!(capture.accept(&request), Err(HostError::DuplicateRequest)));
        assert_eq!(capture.observations.len(), 1);

        let response = frame(
            serde_json::json!({
                "kind":"response", "observed_unix_ns":"1720000000000000000",
                "uncertainty_ns":1, "request_id":"request_1", "status":200,
                "encoded_body_bytes":0
            }),
            2,
        );
        capture.accept(&response).unwrap();
        assert!(matches!(capture.accept(&response), Err(HostError::MissingRequest)));
        assert_eq!(capture.observations.len(), 2);
        assert_eq!(capture.relations.len(), 1);
    }

    #[test]
    fn capture_time_cannot_move_backward_or_bypass_the_session_bound() {
        let mut capture = Capture::new().unwrap();
        capture
            .accept(&frame(
                serde_json::json!({
                    "kind":"navigation", "observed_unix_ns":"1720000000000000000",
                    "uncertainty_ns":1, "url":"https://example.test/first"
                }),
                1,
            ))
            .unwrap();
        let backward = frame(
            serde_json::json!({
                "kind":"navigation", "observed_unix_ns":"1719999999999999000",
                "uncertainty_ns":1, "url":"https://example.test/backward"
            }),
            2,
        );
        assert!(matches!(capture.accept(&backward), Err(HostError::NonMonotonicTime)));
        let too_late = frame(
            serde_json::json!({
                "kind":"navigation",
                "observed_unix_ns":(1720000000000000000_i128 + MAX_SESSION_NS + 2).to_string(),
                "uncertainty_ns":1, "url":"https://example.test/late"
            }),
            3,
        );
        assert!(matches!(capture.accept(&too_late), Err(HostError::LimitExceeded)));
        assert_eq!(capture.observations.len(), 1);
    }
}
