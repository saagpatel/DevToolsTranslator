//! Bounded authenticated ingress contract for ordinary live evidence brokers.
//!
//! Network listeners and platform samplers remain separate signed adapters. This
//! crate owns only session authentication, epochs, replay rules, quotas, and gaps.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

pub const PROTOCOL_VERSION: u16 = 1;
pub const ABSOLUTE_MAX_FRAME_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveSourcePolicy {
    pub max_frame_bytes: usize,
    pub max_events: u64,
    pub max_total_bytes: u64,
    pub max_events_per_second: u32,
}

impl LiveSourcePolicy {
    pub fn validate(&self) -> Result<(), LiveSourceError> {
        if self.max_frame_bytes == 0
            || self.max_frame_bytes > ABSOLUTE_MAX_FRAME_BYTES
            || self.max_events == 0
            || self.max_total_bytes == 0
            || self.max_events_per_second == 0
        {
            return Err(LiveSourceError::InvalidPolicy);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveFrame {
    pub protocol_version: u16,
    pub session_id: String,
    pub source_id: String,
    pub source_epoch: u64,
    pub sequence: u64,
    pub credential: String,
    pub captured_at_ms: u64,
    pub payload: serde_json::Value,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapReason {
    SequenceGap,
    Disconnected,
    QuotaExceeded,
    Revoked,
    EpochChanged,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GapReceipt {
    pub source_id: String,
    pub source_epoch: u64,
    pub after_sequence: Option<u64>,
    pub next_sequence: Option<u64>,
    pub reason: GapReason,
}

pub struct LiveSourceSession {
    session_id: String,
    source_id: String,
    source_epoch: u64,
    credential: Zeroizing<String>,
    policy: LiveSourcePolicy,
    active: bool,
    last_sequence: Option<u64>,
    accepted_events: u64,
    accepted_bytes: u64,
    rate_second: Option<u64>,
    rate_count: u32,
    gaps: Vec<GapReceipt>,
}

impl LiveSourceSession {
    pub fn new(
        session_id: String,
        source_id: String,
        source_epoch: u64,
        credential: String,
        policy: LiveSourcePolicy,
    ) -> Result<Self, LiveSourceError> {
        policy.validate()?;
        validate_id(&session_id)?;
        validate_id(&source_id)?;
        validate_credential(&credential)?;
        Ok(Self {
            session_id,
            source_id,
            source_epoch,
            credential: Zeroizing::new(credential),
            policy,
            active: true,
            last_sequence: None,
            accepted_events: 0,
            accepted_bytes: 0,
            rate_second: None,
            rate_count: 0,
            gaps: vec![],
        })
    }

    pub fn accept(
        &mut self,
        bytes: &[u8],
        received_at_ms: u64,
    ) -> Result<LiveFrame, LiveSourceError> {
        if !self.active {
            return Err(LiveSourceError::Detached);
        }
        if bytes.len() > self.policy.max_frame_bytes {
            // The frame is not authenticated yet, so it must not be allowed to
            // detach or mutate the legitimate source session.
            return Err(LiveSourceError::FrameTooLarge(bytes.len()));
        }
        let frame: LiveFrame = serde_json::from_slice(bytes)?;
        if frame.protocol_version != PROTOCOL_VERSION {
            return Err(LiveSourceError::UnsupportedProtocol(frame.protocol_version));
        }
        if frame.session_id != self.session_id || frame.source_id != self.source_id {
            return Err(LiveSourceError::WrongSource);
        }
        if frame.source_epoch != self.source_epoch {
            return Err(LiveSourceError::WrongEpoch {
                expected: self.source_epoch,
                received: frame.source_epoch,
            });
        }
        if !credential_matches(&self.credential, &frame.credential) {
            return Err(LiveSourceError::WrongCredential);
        }
        if self.last_sequence.is_some_and(|last| frame.sequence <= last) {
            return Err(LiveSourceError::Replay);
        }
        let next_events = self.accepted_events.saturating_add(1);
        let next_bytes = self.accepted_bytes.saturating_add(bytes.len() as u64);
        let second = received_at_ms / 1000;
        let next_rate =
            if self.rate_second == Some(second) { self.rate_count.saturating_add(1) } else { 1 };
        if next_events > self.policy.max_events
            || next_bytes > self.policy.max_total_bytes
            || next_rate > self.policy.max_events_per_second
        {
            return self.quota_failure();
        }
        let expected_sequence = self.last_sequence.map_or(0, |last| last.saturating_add(1));
        if frame.sequence > expected_sequence {
            self.gaps.push(GapReceipt {
                source_id: self.source_id.clone(),
                source_epoch: self.source_epoch,
                after_sequence: self.last_sequence,
                next_sequence: Some(frame.sequence),
                reason: GapReason::SequenceGap,
            });
        }
        self.last_sequence = Some(frame.sequence);
        self.accepted_events = next_events;
        self.accepted_bytes = next_bytes;
        if self.rate_second != Some(second) {
            self.rate_second = Some(second);
            self.rate_count = 0;
        }
        self.rate_count = self.rate_count.saturating_add(1);
        Ok(frame)
    }

    pub fn disconnect(&mut self, reason: GapReason) {
        self.active = false;
        self.gaps.push(GapReceipt {
            source_id: self.source_id.clone(),
            source_epoch: self.source_epoch,
            after_sequence: self.last_sequence,
            next_sequence: None,
            reason,
        });
    }

    pub fn reconnect(
        &mut self,
        new_epoch: u64,
        new_credential: String,
    ) -> Result<(), LiveSourceError> {
        if self.active || new_epoch <= self.source_epoch {
            return Err(LiveSourceError::UnsafeReconnect);
        }
        validate_credential(&new_credential)?;
        self.gaps.push(GapReceipt {
            source_id: self.source_id.clone(),
            source_epoch: self.source_epoch,
            after_sequence: self.last_sequence,
            next_sequence: None,
            reason: GapReason::EpochChanged,
        });
        self.source_epoch = new_epoch;
        self.credential = Zeroizing::new(new_credential);
        self.active = true;
        self.last_sequence = None;
        self.accepted_events = 0;
        self.accepted_bytes = 0;
        self.rate_second = None;
        self.rate_count = 0;
        Ok(())
    }

    pub fn gaps(&self) -> &[GapReceipt] {
        &self.gaps
    }
    pub fn is_active(&self) -> bool {
        self.active
    }

    fn quota_failure<T>(&mut self) -> Result<T, LiveSourceError> {
        self.disconnect(GapReason::QuotaExceeded);
        Err(LiveSourceError::QuotaExceeded)
    }
}

fn validate_id(value: &str) -> Result<(), LiveSourceError> {
    if value.len() < 8
        || value.len() > 128
        || !value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(LiveSourceError::InvalidIdentifier);
    }
    Ok(())
}

fn validate_credential(value: &str) -> Result<(), LiveSourceError> {
    if value.len() < 32 || value.len() > 256 || !value.is_ascii() {
        return Err(LiveSourceError::InvalidCredential);
    }
    Ok(())
}

fn credential_matches(expected: &str, candidate: &str) -> bool {
    let Ok(mut expected_mac) = HmacSha256::new_from_slice(expected.as_bytes()) else {
        return false;
    };
    expected_mac.update(b"glassbox-live-source-auth/v1");
    let expected_tag = expected_mac.finalize().into_bytes();
    let Ok(mut candidate_mac) = HmacSha256::new_from_slice(candidate.as_bytes()) else {
        return false;
    };
    candidate_mac.update(b"glassbox-live-source-auth/v1");
    candidate_mac.verify_slice(&expected_tag).is_ok()
}

#[derive(Debug, Error)]
pub enum LiveSourceError {
    #[error("live-source policy is zero or exceeds the absolute frame bound")]
    InvalidPolicy,
    #[error("session or source identifier is invalid")]
    InvalidIdentifier,
    #[error("credential must be a bounded ASCII secret of at least 32 bytes")]
    InvalidCredential,
    #[error("source is detached")]
    Detached,
    #[error("frame is {0} bytes, exceeding the session bound")]
    FrameTooLarge(usize),
    #[error("unsupported protocol {0}")]
    UnsupportedProtocol(u16),
    #[error("frame belongs to another session or source")]
    WrongSource,
    #[error("source epoch mismatch: expected {expected}, received {received}")]
    WrongEpoch { expected: u64, received: u64 },
    #[error("source credential mismatch")]
    WrongCredential,
    #[error("sequence replay or reordering rejected")]
    Replay,
    #[error("source quota exceeded; source detached and gap recorded")]
    QuotaExceeded,
    #[error("reconnect requires a detached source, fresh credential, and increasing epoch")]
    UnsafeReconnect,
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> LiveSourcePolicy {
        LiveSourcePolicy {
            max_frame_bytes: 4096,
            max_events: 3,
            max_total_bytes: 8192,
            max_events_per_second: 2,
        }
    }
    fn session() -> LiveSourceSession {
        LiveSourceSession::new(
            "session_12345678".into(),
            "source_12345678".into(),
            1,
            "a".repeat(32),
            policy(),
        )
        .unwrap()
    }
    fn frame(sequence: u64, epoch: u64, credential: &str) -> Vec<u8> {
        serde_json::to_vec(&LiveFrame {
            protocol_version: 1,
            session_id: "session_12345678".into(),
            source_id: "source_12345678".into(),
            source_epoch: epoch,
            sequence,
            credential: credential.into(),
            captured_at_ms: 1000,
            payload: serde_json::json!({"kind":"span"}),
        })
        .unwrap()
    }

    #[test]
    fn wrong_token_epoch_and_replay_fail_closed() {
        let mut s = session();
        assert!(matches!(
            s.accept(&frame(0, 1, &"b".repeat(32)), 1000),
            Err(LiveSourceError::WrongCredential)
        ));
        assert!(matches!(
            s.accept(&frame(0, 2, &"a".repeat(32)), 1000),
            Err(LiveSourceError::WrongEpoch { .. })
        ));
        s.accept(&frame(0, 1, &"a".repeat(32)), 1000).unwrap();
        assert!(matches!(
            s.accept(&frame(0, 1, &"a".repeat(32)), 1001),
            Err(LiveSourceError::Replay)
        ));
    }
    #[test]
    fn sequence_gaps_are_explicit() {
        let mut s = session();
        s.accept(&frame(2, 1, &"a".repeat(32)), 1000).unwrap();
        s.accept(&frame(5, 1, &"a".repeat(32)), 2000).unwrap();
        assert_eq!(s.gaps()[0].reason, GapReason::SequenceGap);
        assert_eq!(s.gaps()[0].after_sequence, None);
        assert_eq!(s.gaps()[0].next_sequence, Some(2));
        assert_eq!(s.gaps()[1].after_sequence, Some(2));
        assert_eq!(s.gaps()[1].next_sequence, Some(5));
    }
    #[test]
    fn rate_quota_detaches_and_records_gap() {
        let mut s = session();
        s.accept(&frame(0, 1, &"a".repeat(32)), 1000).unwrap();
        s.accept(&frame(1, 1, &"a".repeat(32)), 1001).unwrap();
        assert!(matches!(
            s.accept(&frame(2, 1, &"a".repeat(32)), 1002),
            Err(LiveSourceError::QuotaExceeded)
        ));
        assert!(!s.is_active());
        assert_eq!(s.gaps().last().unwrap().reason, GapReason::QuotaExceeded);
    }
    #[test]
    fn reconnect_requires_new_epoch_and_credential() {
        let mut s = session();
        s.disconnect(GapReason::Disconnected);
        assert!(matches!(s.reconnect(1, "b".repeat(32)), Err(LiveSourceError::UnsafeReconnect)));
        s.reconnect(2, "b".repeat(32)).unwrap();
        assert!(matches!(
            s.accept(&frame(0, 1, &"b".repeat(32)), 2000),
            Err(LiveSourceError::WrongEpoch { .. })
        ));
        s.accept(&frame(0, 2, &"b".repeat(32)), 2000).unwrap();
    }
    #[test]
    fn absolute_frame_limit_cannot_be_relaxed() {
        let mut p = policy();
        p.max_frame_bytes = ABSOLUTE_MAX_FRAME_BYTES + 1;
        assert!(matches!(p.validate(), Err(LiveSourceError::InvalidPolicy)));
    }

    #[test]
    fn unauthenticated_oversized_frame_cannot_detach_legitimate_source() {
        let mut s = session();
        assert!(matches!(
            s.accept(&vec![0; 4097], 1000),
            Err(LiveSourceError::FrameTooLarge(4097))
        ));
        assert!(s.is_active());
    }
}
