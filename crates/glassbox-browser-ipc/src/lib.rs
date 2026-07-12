//! Authentication and lifecycle contract for the Chrome Native Messaging broker.
//!
//! This crate is intentionally transport-only. It contains no browser discovery,
//! socket client, storage, evidence interpretation, or inherited DTT dependency.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use thiserror::Error;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
pub const SESSION_TTL_MS: u64 = 5 * 60 * 1000;
pub const WATCHDOG_TIMEOUT_MS: u64 = 15_000;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionManifest {
    pub name: String,
    pub path: String,
    pub allowed_origins: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionPolicy {
    pub host_name: String,
    pub extension_id: String,
    pub install_root: String,
    pub expected_team_id: String,
}

impl ProductionPolicy {
    pub fn expected_origin(&self) -> String {
        format!("chrome-extension://{}/", self.extension_id)
    }

    pub fn validate_manifest(&self, manifest: &ProductionManifest) -> Result<(), BrowserIpcError> {
        if manifest.name != self.host_name {
            return Err(BrowserIpcError::WrongHostName);
        }
        let host_path = Path::new(&manifest.path);
        if !host_path.is_absolute() || !host_path.starts_with(Path::new(&self.install_root)) {
            return Err(BrowserIpcError::UnsafeHostPath);
        }
        if manifest.allowed_origins != [self.expected_origin()] {
            return Err(BrowserIpcError::WrongAllowedOrigins);
        }
        Ok(())
    }

    pub fn validate_signatures(
        &self,
        host_team_id: &str,
        app_team_id: &str,
    ) -> Result<(), BrowserIpcError> {
        if host_team_id != self.expected_team_id || app_team_id != self.expected_team_id {
            return Err(BrowserIpcError::SignatureMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentContext {
    pub extension_id: String,
    pub browser_attachment_id: String,
    pub selected_tab_id: u64,
    pub request_id: String,
    pub session_nonce: String,
}

impl AttachmentContext {
    fn validate(&self, policy: &ProductionPolicy) -> Result<(), BrowserIpcError> {
        if self.extension_id != policy.extension_id {
            return Err(BrowserIpcError::WrongExtension);
        }
        for token in [&self.browser_attachment_id, &self.request_id, &self.session_nonce] {
            if token.len() < 16
                || token.len() > 128
                || !token.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            {
                return Err(BrowserIpcError::InvalidIdentifier);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentRequest {
    pub protocol_version: u16,
    pub context: AttachmentContext,
    pub foreground_user_gesture: bool,
    pub visible_approval: bool,
    pub selected_tab_count: u8,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentChallenge {
    pub context: AttachmentContext,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub one_use_token: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionCredential {
    pub attachment_id: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub token: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserFrame {
    pub protocol_version: u16,
    pub context: AttachmentContext,
    pub session_token: String,
    pub sequence: u64,
    pub payload: serde_json::Value,
}

impl BrowserFrame {
    pub fn decode(bytes: &[u8]) -> Result<Self, BrowserIpcError> {
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(BrowserIpcError::FrameTooLarge(bytes.len()));
        }
        serde_json::from_slice(bytes).map_err(Into::into)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetachReason {
    UserStop,
    TabClosed,
    BrowserRestart,
    AppExit,
    WatchdogTimeout,
    Revoked,
}

#[derive(Clone, Debug)]
struct ActiveSession {
    context: AttachmentContext,
    credential: SessionCredential,
    last_sequence: Option<u64>,
    last_seen_ms: u64,
}

pub struct AttachmentBroker {
    policy: ProductionPolicy,
    signing_key: Zeroizing<Vec<u8>>,
    pending: HashMap<String, AttachmentChallenge>,
    consumed_challenges: HashSet<String>,
    active: Option<ActiveSession>,
    last_detach: Option<DetachReason>,
}

impl AttachmentBroker {
    pub fn new(policy: ProductionPolicy, signing_key: &[u8]) -> Result<Self, BrowserIpcError> {
        if signing_key.len() < 32 {
            return Err(BrowserIpcError::WeakSigningKey);
        }
        Ok(Self {
            policy,
            signing_key: Zeroizing::new(signing_key.to_vec()),
            pending: HashMap::new(),
            consumed_challenges: HashSet::new(),
            active: None,
            last_detach: None,
        })
    }

    pub fn issue_challenge(
        &mut self,
        request: AttachmentRequest,
        now_ms: u64,
    ) -> Result<AttachmentChallenge, BrowserIpcError> {
        if request.protocol_version != PROTOCOL_VERSION {
            return Err(BrowserIpcError::UnsupportedProtocol(request.protocol_version));
        }
        request.context.validate(&self.policy)?;
        if !request.foreground_user_gesture
            || !request.visible_approval
            || request.selected_tab_count != 1
        {
            return Err(BrowserIpcError::AttachmentNotApproved);
        }
        if self.active.is_some() || !self.pending.is_empty() {
            return Err(BrowserIpcError::ParallelAttachment);
        }
        let expires_at_ms = now_ms.checked_add(30_000).ok_or(BrowserIpcError::InvalidTime)?;
        let token = self.sign("challenge", &request.context, now_ms, expires_at_ms);
        let challenge = AttachmentChallenge {
            context: request.context,
            issued_at_ms: now_ms,
            expires_at_ms,
            one_use_token: token.clone(),
        };
        self.pending.insert(token, challenge.clone());
        Ok(challenge)
    }

    pub fn exchange_challenge(
        &mut self,
        challenge: &AttachmentChallenge,
        now_ms: u64,
    ) -> Result<SessionCredential, BrowserIpcError> {
        if self.consumed_challenges.contains(&challenge.one_use_token) {
            return Err(BrowserIpcError::Replay);
        }
        let expected = self
            .pending
            .remove(&challenge.one_use_token)
            .ok_or(BrowserIpcError::UnknownChallenge)?;
        if &expected != challenge || now_ms > challenge.expires_at_ms {
            return Err(BrowserIpcError::StaleCredential);
        }
        self.consumed_challenges.insert(challenge.one_use_token.clone());
        let expires_at_ms =
            now_ms.checked_add(SESSION_TTL_MS).ok_or(BrowserIpcError::InvalidTime)?;
        let token = self.sign("session", &challenge.context, now_ms, expires_at_ms);
        let credential = SessionCredential {
            attachment_id: challenge.context.browser_attachment_id.clone(),
            issued_at_ms: now_ms,
            expires_at_ms,
            token,
        };
        self.active = Some(ActiveSession {
            context: challenge.context.clone(),
            credential: credential.clone(),
            last_sequence: None,
            last_seen_ms: now_ms,
        });
        Ok(credential)
    }

    pub fn accept_frame(
        &mut self,
        bytes: &[u8],
        now_ms: u64,
    ) -> Result<BrowserFrame, BrowserIpcError> {
        let frame = BrowserFrame::decode(bytes)?;
        if frame.protocol_version != PROTOCOL_VERSION {
            return Err(BrowserIpcError::UnsupportedProtocol(frame.protocol_version));
        }
        let active = self.active.as_mut().ok_or(BrowserIpcError::Detached)?;
        if frame.context != active.context
            || !verify_token(
                &self.signing_key,
                "session",
                &frame.context,
                active.credential.issued_at_ms,
                active.credential.expires_at_ms,
                &frame.session_token,
            )
        {
            return Err(BrowserIpcError::CredentialMismatch);
        }
        if now_ms > active.credential.expires_at_ms {
            self.active = None;
            return Err(BrowserIpcError::StaleCredential);
        }
        if active.last_sequence.is_some_and(|last| frame.sequence <= last) {
            return Err(BrowserIpcError::Replay);
        }
        active.last_sequence = Some(frame.sequence);
        active.last_seen_ms = now_ms;
        Ok(frame)
    }

    pub fn watchdog(&mut self, now_ms: u64) -> bool {
        let timed_out = self
            .active
            .as_ref()
            .is_some_and(|active| now_ms.saturating_sub(active.last_seen_ms) > WATCHDOG_TIMEOUT_MS);
        if timed_out {
            self.detach(DetachReason::WatchdogTimeout);
        }
        timed_out
    }

    pub fn detach(&mut self, reason: DetachReason) {
        self.pending.clear();
        self.active = None;
        self.last_detach = Some(reason);
    }

    pub fn is_active(&self) -> bool {
        self.active.is_some()
    }
    pub fn last_detach_reason(&self) -> Option<DetachReason> {
        self.last_detach
    }

    fn sign(
        &self,
        domain: &str,
        context: &AttachmentContext,
        issued_at_ms: u64,
        expires_at_ms: u64,
    ) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.signing_key).expect("validated HMAC key");
        mac.update(domain.as_bytes());
        mac.update(&serde_json::to_vec(context).expect("serializable context"));
        mac.update(&issued_at_ms.to_be_bytes());
        mac.update(&expires_at_ms.to_be_bytes());
        hex::encode(mac.finalize().into_bytes())
    }
}

fn verify_token(
    key: &[u8],
    domain: &str,
    context: &AttachmentContext,
    issued_at_ms: u64,
    expires_at_ms: u64,
    encoded: &str,
) -> bool {
    let Ok(candidate) = hex::decode(encoded) else { return false };
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else { return false };
    mac.update(domain.as_bytes());
    mac.update(&serde_json::to_vec(context).expect("serializable context"));
    mac.update(&issued_at_ms.to_be_bytes());
    mac.update(&expires_at_ms.to_be_bytes());
    mac.verify_slice(&candidate).is_ok()
}

pub fn manifest_sha256(manifest: &ProductionManifest) -> String {
    hex::encode(Sha256::digest(serde_json::to_vec(manifest).expect("serializable manifest")))
}

#[derive(Debug, Error)]
pub enum BrowserIpcError {
    #[error("unsupported browser IPC protocol {0}")]
    UnsupportedProtocol(u16),
    #[error("frame is {0} bytes, exceeding the 1 MiB limit")]
    FrameTooLarge(usize),
    #[error("production host name does not match policy")]
    WrongHostName,
    #[error("native host path is not absolute and inside the installation root")]
    UnsafeHostPath,
    #[error("allowed origins must contain exactly the production extension origin")]
    WrongAllowedOrigins,
    #[error("host and app signatures do not match the expected team")]
    SignatureMismatch,
    #[error("extension identity does not match production policy")]
    WrongExtension,
    #[error("attachment identifier is invalid")]
    InvalidIdentifier,
    #[error(
        "attachment requires a foreground gesture, visible approval, and exactly one selected tab"
    )]
    AttachmentNotApproved,
    #[error("another attachment or challenge is already active")]
    ParallelAttachment,
    #[error("challenge is unknown or was cleared")]
    UnknownChallenge,
    #[error("credential has expired or was modified")]
    StaleCredential,
    #[error("credential or sequence was replayed")]
    Replay,
    #[error("frame does not bind to the active attachment credential")]
    CredentialMismatch,
    #[error("attachment is detached")]
    Detached,
    #[error("signing key must be at least 32 bytes")]
    WeakSigningKey,
    #[error("timestamp overflow")]
    InvalidTime,
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> ProductionPolicy {
        ProductionPolicy {
            host_name: "com.glassbox.browser".into(),
            extension_id: "abcdefghijklmnopabcdefghijklmnop".into(),
            install_root: "/Applications/Glassbox.app/Contents/Library/LoginItems".into(),
            expected_team_id: "TEAM123456".into(),
        }
    }
    fn context() -> AttachmentContext {
        AttachmentContext {
            extension_id: policy().extension_id,
            browser_attachment_id: "attach_1234567890".into(),
            selected_tab_id: 42,
            request_id: "request_123456789".into(),
            session_nonce: "nonce_12345678901".into(),
        }
    }
    fn request() -> AttachmentRequest {
        AttachmentRequest {
            protocol_version: 1,
            context: context(),
            foreground_user_gesture: true,
            visible_approval: true,
            selected_tab_count: 1,
        }
    }
    fn broker() -> AttachmentBroker {
        AttachmentBroker::new(policy(), &[7; 32]).unwrap()
    }

    #[test]
    fn manifest_and_signature_are_exact() {
        let p = policy();
        let manifest = ProductionManifest {
            name: p.host_name.clone(),
            path: format!("{}/GlassboxBrowserHost", p.install_root),
            allowed_origins: vec![p.expected_origin()],
        };
        p.validate_manifest(&manifest).unwrap();
        p.validate_signatures("TEAM123456", "TEAM123456").unwrap();
        let mut broad = manifest.clone();
        broad.allowed_origins.push("chrome-extension://evil/".into());
        assert!(matches!(p.validate_manifest(&broad), Err(BrowserIpcError::WrongAllowedOrigins)));
        assert!(matches!(
            p.validate_signatures("FAKE", "TEAM123456"),
            Err(BrowserIpcError::SignatureMismatch)
        ));
        let mut sibling = manifest;
        sibling.path = format!("{}-attacker/Host", p.install_root);
        assert!(matches!(p.validate_manifest(&sibling), Err(BrowserIpcError::UnsafeHostPath)));
    }

    #[test]
    fn approval_identity_and_parallel_attachment_fail_closed() {
        let mut b = broker();
        let mut wrong = request();
        wrong.context.extension_id = "wrongwrongwrongwrong".into();
        assert!(matches!(b.issue_challenge(wrong, 100), Err(BrowserIpcError::WrongExtension)));
        let mut silent = request();
        silent.visible_approval = false;
        assert!(matches!(
            b.issue_challenge(silent, 100),
            Err(BrowserIpcError::AttachmentNotApproved)
        ));
        b.issue_challenge(request(), 100).unwrap();
        assert!(matches!(
            b.issue_challenge(request(), 101),
            Err(BrowserIpcError::ParallelAttachment)
        ));
    }

    #[test]
    fn one_use_exchange_and_monotonic_frames_reject_replay() {
        let mut b = broker();
        let challenge = b.issue_challenge(request(), 100).unwrap();
        let credential = b.exchange_challenge(&challenge, 101).unwrap();
        assert!(matches!(b.exchange_challenge(&challenge, 102), Err(BrowserIpcError::Replay)));
        let frame = BrowserFrame {
            protocol_version: 1,
            context: context(),
            session_token: credential.token,
            sequence: 1,
            payload: serde_json::json!({"kind":"observation"}),
        };
        let bytes = serde_json::to_vec(&frame).unwrap();
        b.accept_frame(&bytes, 103).unwrap();
        assert!(matches!(b.accept_frame(&bytes, 104), Err(BrowserIpcError::Replay)));
    }

    #[test]
    fn lifecycle_detaches_without_automatic_reattachment() {
        for reason in [
            DetachReason::UserStop,
            DetachReason::TabClosed,
            DetachReason::BrowserRestart,
            DetachReason::AppExit,
            DetachReason::Revoked,
        ] {
            let mut b = broker();
            let challenge = b.issue_challenge(request(), 100).unwrap();
            b.exchange_challenge(&challenge, 101).unwrap();
            b.detach(reason);
            assert!(!b.is_active());
            assert_eq!(b.last_detach_reason(), Some(reason));
        }
        let mut b = broker();
        let challenge = b.issue_challenge(request(), 100).unwrap();
        b.exchange_challenge(&challenge, 101).unwrap();
        assert!(b.watchdog(101 + WATCHDOG_TIMEOUT_MS + 1));
        assert_eq!(b.last_detach_reason(), Some(DetachReason::WatchdogTimeout));
    }

    #[test]
    fn stale_oversized_and_replacement_frames_are_rejected() {
        assert!(matches!(
            BrowserFrame::decode(&vec![0; MAX_FRAME_BYTES + 1]),
            Err(BrowserIpcError::FrameTooLarge(_))
        ));
        let mut b = broker();
        let challenge = b.issue_challenge(request(), 100).unwrap();
        let credential = b.exchange_challenge(&challenge, 101).unwrap();
        let mut replacement = BrowserFrame {
            protocol_version: 1,
            context: context(),
            session_token: credential.token,
            sequence: 1,
            payload: serde_json::json!({}),
        };
        replacement.context.browser_attachment_id = "replacement_123456".into();
        assert!(matches!(
            b.accept_frame(&serde_json::to_vec(&replacement).unwrap(), 102),
            Err(BrowserIpcError::CredentialMismatch)
        ));
        let valid = BrowserFrame {
            protocol_version: 1,
            context: context(),
            session_token: replacement.session_token,
            sequence: 1,
            payload: serde_json::json!({}),
        };
        assert!(matches!(
            b.accept_frame(&serde_json::to_vec(&valid).unwrap(), 101 + SESSION_TTL_MS + 1),
            Err(BrowserIpcError::StaleCredential)
        ));
    }
}
