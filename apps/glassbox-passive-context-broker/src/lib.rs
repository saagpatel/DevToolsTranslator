//! Bounded parsing for explicitly requested, passive neighbor-table snapshots.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const MAX_SNAPSHOT_BYTES: usize = 256 * 1024;
pub const MAX_LINES: usize = 4096;
pub const MAX_LINE_BYTES: usize = 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NeighborState {
    Reachable,
    Incomplete,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PassiveNeighbor {
    pub native_locator: String,
    pub address: String,
    pub link_layer_id: Option<String>,
    pub interface: String,
    pub state: NeighborState,
    pub trust: String,
    pub role: String,
    pub limitations: Vec<String>,
    pub conflict: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub schema_version: String,
    pub source: String,
    pub active_probe_performed: bool,
    pub neighbors: Vec<PassiveNeighbor>,
}

pub fn parse_snapshot(input: &[u8]) -> Result<Snapshot, PassiveContextError> {
    if input.len() > MAX_SNAPSHOT_BYTES {
        return Err(PassiveContextError::SnapshotTooLarge);
    }
    let text = std::str::from_utf8(input).map_err(|_| PassiveContextError::InvalidUtf8)?;
    let mut neighbors = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if index >= MAX_LINES {
            return Err(PassiveContextError::TooManyLines);
        }
        if line.len() > MAX_LINE_BYTES {
            return Err(PassiveContextError::LineTooLarge);
        }
        if line.trim().is_empty() {
            continue;
        }
        neighbors.push(parse_line(line, index as u64 + 1)?);
    }
    mark_conflicts(&mut neighbors);
    Ok(Snapshot {
        schema_version: "glassbox-passive-context/v1".into(),
        source: "ordinary_neighbor_table".into(),
        active_probe_performed: false,
        neighbors,
    })
}

fn parse_line(line: &str, ordinal: u64) -> Result<PassiveNeighbor, PassiveContextError> {
    let open = line.find('(').ok_or(PassiveContextError::MalformedLine)?;
    let close = line[open + 1..]
        .find(')')
        .map(|value| value + open + 1)
        .ok_or(PassiveContextError::MalformedLine)?;
    let address = &line[open + 1..close];
    if !valid_address(address) {
        return Err(PassiveContextError::InvalidAddress);
    }
    let remainder = line[close + 1..].trim();
    let after_at = remainder.strip_prefix("at ").ok_or(PassiveContextError::MalformedLine)?;
    let (link, after_link) =
        after_at.split_once(" on ").ok_or(PassiveContextError::MalformedLine)?;
    let interface =
        after_link.split_ascii_whitespace().next().ok_or(PassiveContextError::MalformedLine)?;
    if !valid_interface(interface) {
        return Err(PassiveContextError::InvalidInterface);
    }
    let (link_layer_id, state) = if link == "(incomplete)" {
        (None, NeighborState::Incomplete)
    } else {
        if !valid_link_layer_id(link) {
            return Err(PassiveContextError::InvalidLinkLayerId);
        }
        (Some(link.to_ascii_lowercase()), NeighborState::Reachable)
    };
    Ok(PassiveNeighbor {
        native_locator: format!("neighbor-table://line/{ordinal}"),
        address: address.into(),
        link_layer_id,
        interface: interface.into(),
        state,
        trust: "untrusted_local_observation".into(),
        role: "logical_context_only".into(),
        limitations: vec![
            "not_physical_topology".into(),
            "not_device_ownership".into(),
            "not_packet_or_process_attribution".into(),
            "not_causal_evidence".into(),
        ],
        conflict: false,
    })
}

fn mark_conflicts(neighbors: &mut [PassiveNeighbor]) {
    let mut ids: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for neighbor in neighbors.iter() {
        if let Some(link) = neighbor.link_layer_id.as_deref() {
            ids.entry(neighbor.address.clone()).or_default().insert(link.into());
        }
    }
    let conflicts: BTreeSet<String> = ids
        .into_iter()
        .filter_map(|(address, values)| (values.len() > 1).then_some(address))
        .collect();
    for neighbor in neighbors {
        neighbor.conflict = conflicts.contains(neighbor.address.as_str());
    }
}

fn valid_address(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| byte.is_ascii_hexdigit() || matches!(byte, b'.' | b':' | b'%'))
}

fn valid_interface(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn valid_link_layer_id(value: &str) -> bool {
    let parts: Vec<_> = value.split(':').collect();
    parts.len() == 6
        && parts.iter().all(|part| {
            !part.is_empty() && part.len() <= 2 && part.bytes().all(|b| b.is_ascii_hexdigit())
        })
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PassiveContextError {
    #[error("snapshot exceeds 256 KiB")]
    SnapshotTooLarge,
    #[error("snapshot is not UTF-8")]
    InvalidUtf8,
    #[error("snapshot exceeds 4096 lines")]
    TooManyLines,
    #[error("snapshot line exceeds 1024 bytes")]
    LineTooLarge,
    #[error("malformed neighbor-table line")]
    MalformedLine,
    #[error("invalid neighbor address")]
    InvalidAddress,
    #[error("invalid interface name")]
    InvalidInterface,
    #[error("invalid link-layer identifier")]
    InvalidLinkLayerId,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_without_promoting_context_to_identity_or_cause() {
        let snapshot =
            parse_snapshot(b"? (192.0.2.4) at aa:bb:cc:dd:ee:f on en0 ifscope [ethernet]\n")
                .unwrap();
        let item = &snapshot.neighbors[0];
        assert!(!snapshot.active_probe_performed);
        assert_eq!(item.role, "logical_context_only");
        assert!(item.limitations.iter().any(|value| value == "not_causal_evidence"));
    }

    #[test]
    fn preserves_conflicting_neighbors_as_conflict() {
        let snapshot = parse_snapshot(
            b"? (192.0.2.4) at aa:bb:cc:dd:ee:1 on en0 ifscope [ethernet]\n? (192.0.2.4) at aa:bb:cc:dd:ee:2 on en0 ifscope [ethernet]\n",
        )
        .unwrap();
        assert_eq!(snapshot.neighbors.len(), 2);
        assert!(snapshot.neighbors.iter().all(|item| item.conflict));
    }

    #[test]
    fn malformed_and_oversized_input_fails_closed() {
        assert_eq!(parse_snapshot(b"host 192.0.2.1\n"), Err(PassiveContextError::MalformedLine));
        assert_eq!(
            parse_snapshot(&vec![b'x'; MAX_SNAPSHOT_BYTES + 1]),
            Err(PassiveContextError::SnapshotTooLarge)
        );
    }
}
