//! Bounded parser for Glassbox's native Apple unified-log projection.
//!
//! This does not parse Apple's private `.logarchive` container. A separately
//! sandboxed native adapter uses `OSLogStore` and emits this metadata-only,
//! terminal-digest-bound stream. Message text and string-valued process,
//! subsystem, category, sender, path, and signpost-name fields are absent by
//! construction.

use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::io::{BufRead, Read};
use thiserror::Error;

pub const SCHEMA_VERSION: &str = "glassbox-apple-log-projection/v1";
pub const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub const MAX_LINE_BYTES: usize = 64 * 1024;
pub const MAX_ENTRIES: u64 = 1_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    Log,
    Signpost,
    Activity,
    Loss,
    Unknown,
}

impl EntryKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Log => "log",
            Self::Signpost => "signpost",
            Self::Activity => "activity",
            Self::Loss => "loss",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Undefined,
    Debug,
    Info,
    Notice,
    Error,
    Fault,
}

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Undefined => "undefined",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Notice => "notice",
            Self::Error => "error",
            Self::Fault => "fault",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignpostType {
    Begin,
    End,
    Event,
}

impl SignpostType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Begin => "begin",
            Self::End => "end",
            Self::Event => "event",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppleLogRecord {
    pub source_artifact_sha256: String,
    pub ordinal: u64,
    pub timestamp_unix_ns: i128,
    pub entry_kind: EntryKind,
    pub level: LogLevel,
    pub process_id: u32,
    pub thread_id: u64,
    pub activity_id: u64,
    pub signpost_id: Option<u64>,
    pub signpost_type: Option<SignpostType>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionReceipt {
    pub source_artifact_sha256: String,
    pub records: u64,
    pub stream_sha256: String,
    pub bytes: u64,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum ProjectionLine {
    Header {
        schema_version: String,
        source_artifact_sha256: String,
    },
    Entry {
        ordinal: u64,
        timestamp_unix_ns: DecimalI128,
        entry_kind: EntryKind,
        level: LogLevel,
        process_id: u32,
        thread_id: u64,
        activity_id: u64,
        #[serde(default)]
        signpost_id: Option<u64>,
        #[serde(default)]
        signpost_type: Option<SignpostType>,
    },
    End {
        records: u64,
        stream_sha256: String,
    },
}

#[derive(Deserialize)]
#[serde(transparent)]
struct DecimalI128(String);

pub fn parse<R, F>(mut input: R, mut sink: F) -> Result<ProjectionReceipt, AppleLogImportError>
where
    R: BufRead,
    F: FnMut(AppleLogRecord) -> Result<(), AppleLogImportError>,
{
    let mut total_bytes = 0_u64;
    let mut line_number = 0_u64;
    let mut expected_ordinal = 1_u64;
    let mut source_artifact_sha256 = None;
    let mut digest = Sha256::new();
    let mut terminal = None;

    loop {
        let mut line = Vec::new();
        let bytes =
            Read::take(&mut input, (MAX_LINE_BYTES + 1) as u64).read_until(b'\n', &mut line)?;
        if bytes == 0 {
            break;
        }
        if bytes > MAX_LINE_BYTES {
            return Err(AppleLogImportError::LineTooLarge(bytes));
        }
        total_bytes = total_bytes
            .checked_add(bytes as u64)
            .ok_or(AppleLogImportError::FileTooLarge(u64::MAX))?;
        if total_bytes > MAX_FILE_BYTES {
            return Err(AppleLogImportError::FileTooLarge(total_bytes));
        }
        if terminal.is_some() {
            return Err(AppleLogImportError::TrailingData);
        }
        if line.last() != Some(&b'\n') {
            return Err(AppleLogImportError::UnterminatedLine(line_number + 1));
        }
        line.pop();
        if line.last() == Some(&b'\r') {
            return Err(AppleLogImportError::CarriageReturn(line_number + 1));
        }
        if line.is_empty() {
            return Err(AppleLogImportError::EmptyLine(line_number + 1));
        }
        line_number += 1;
        let parsed: ProjectionLine = serde_json::from_slice(&line)?;
        match parsed {
            ProjectionLine::Header { schema_version, source_artifact_sha256: source_hash } => {
                if line_number != 1 {
                    return Err(AppleLogImportError::HeaderOrder);
                }
                if schema_version != SCHEMA_VERSION {
                    return Err(AppleLogImportError::UnsupportedSchema(schema_version));
                }
                validate_sha256("source artifact", &source_hash)?;
                source_artifact_sha256 = Some(source_hash);
                digest.update(&line);
                digest.update(b"\n");
            }
            ProjectionLine::Entry {
                ordinal,
                timestamp_unix_ns,
                entry_kind,
                level,
                process_id,
                thread_id,
                activity_id,
                signpost_id,
                signpost_type,
            } => {
                if source_artifact_sha256.is_none() || line_number == 1 {
                    return Err(AppleLogImportError::HeaderOrder);
                }
                if ordinal != expected_ordinal {
                    return Err(AppleLogImportError::UnexpectedOrdinal {
                        expected: expected_ordinal,
                        actual: ordinal,
                    });
                }
                if ordinal > MAX_ENTRIES {
                    return Err(AppleLogImportError::TooManyEntries(ordinal));
                }
                if matches!(entry_kind, EntryKind::Signpost)
                    != (signpost_id.is_some() && signpost_type.is_some())
                {
                    return Err(AppleLogImportError::InvalidSignpostShape(ordinal));
                }
                let timestamp_unix_ns = timestamp_unix_ns
                    .0
                    .parse()
                    .map_err(|_| AppleLogImportError::InvalidTimestamp(ordinal))?;
                sink(AppleLogRecord {
                    source_artifact_sha256: source_artifact_sha256
                        .as_ref()
                        .expect("header presence was checked")
                        .clone(),
                    ordinal,
                    timestamp_unix_ns,
                    entry_kind,
                    level,
                    process_id,
                    thread_id,
                    activity_id,
                    signpost_id,
                    signpost_type,
                })?;
                expected_ordinal += 1;
                digest.update(&line);
                digest.update(b"\n");
            }
            ProjectionLine::End { records, stream_sha256 } => {
                if source_artifact_sha256.is_none() || line_number == 1 {
                    return Err(AppleLogImportError::HeaderOrder);
                }
                let actual_records = expected_ordinal - 1;
                if records != actual_records {
                    return Err(AppleLogImportError::RecordCount {
                        declared: records,
                        actual: actual_records,
                    });
                }
                validate_sha256("stream", &stream_sha256)?;
                let actual_digest = format!("{:x}", digest.clone().finalize());
                if stream_sha256 != actual_digest {
                    return Err(AppleLogImportError::DigestMismatch);
                }
                terminal = Some((records, stream_sha256));
            }
        }
    }
    let source_artifact_sha256 =
        source_artifact_sha256.ok_or(AppleLogImportError::MissingHeader)?;
    let (records, stream_sha256) = terminal.ok_or(AppleLogImportError::MissingEnd)?;
    Ok(ProjectionReceipt { source_artifact_sha256, records, stream_sha256, bytes: total_bytes })
}

fn validate_sha256(label: &'static str, value: &str) -> Result<(), AppleLogImportError> {
    if value.len() != 64
        || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AppleLogImportError::InvalidSha256(label));
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum AppleLogImportError {
    #[error("Apple log projection line is too large: {0} bytes")]
    LineTooLarge(usize),
    #[error("Apple log projection is too large: {0} bytes")]
    FileTooLarge(u64),
    #[error("Apple log projection line {0} is not newline terminated")]
    UnterminatedLine(u64),
    #[error("Apple log projection line {0} uses a carriage return")]
    CarriageReturn(u64),
    #[error("Apple log projection line {0} is empty")]
    EmptyLine(u64),
    #[error("Apple log projection header is missing or out of order")]
    HeaderOrder,
    #[error("Apple log projection header is missing")]
    MissingHeader,
    #[error("unsupported Apple log projection schema {0}")]
    UnsupportedSchema(String),
    #[error("invalid {0} SHA-256")]
    InvalidSha256(&'static str),
    #[error("unexpected Apple log entry ordinal: expected {expected}, got {actual}")]
    UnexpectedOrdinal { expected: u64, actual: u64 },
    #[error("Apple log projection contains too many entries: {0}")]
    TooManyEntries(u64),
    #[error("Apple log entry {0} has an invalid signpost shape")]
    InvalidSignpostShape(u64),
    #[error("Apple log entry {0} has an invalid timestamp")]
    InvalidTimestamp(u64),
    #[error("Apple log projection count mismatch: declared {declared}, parsed {actual}")]
    RecordCount { declared: u64, actual: u64 },
    #[error("Apple log projection stream digest does not match")]
    DigestMismatch,
    #[error("Apple log projection terminal record is missing")]
    MissingEnd,
    #[error("Apple log projection has trailing data")]
    TrailingData,
    #[error("Apple log projection sink rejected a record: {0}")]
    Sink(String),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn stream(entries: &[&str]) -> Vec<u8> {
        let header = concat!(
            "{\"type\":\"header\",\"schema_version\":\"glassbox-apple-log-projection/v1\",",
            "\"source_artifact_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}\n"
        );
        let mut bytes = header.as_bytes().to_vec();
        for entry in entries {
            bytes.extend_from_slice(entry.as_bytes());
            bytes.push(b'\n');
        }
        let digest = format!("{:x}", Sha256::digest(&bytes));
        bytes.extend_from_slice(
            format!(
                "{{\"type\":\"end\",\"records\":{},\"stream_sha256\":\"{}\"}}\n",
                entries.len(),
                digest
            )
            .as_bytes(),
        );
        bytes
    }

    #[test]
    fn accepts_complete_metadata_only_stream() {
        let entry = concat!(
            "{\"type\":\"entry\",\"ordinal\":1,\"timestamp_unix_ns\":\"1720000000000000000\",",
            "\"entry_kind\":\"signpost\",\"level\":\"notice\",\"process_id\":42,",
            "\"thread_id\":7,\"activity_id\":9,\"signpost_id\":11,\"signpost_type\":\"begin\"}"
        );
        let mut records = Vec::new();
        let receipt = parse(Cursor::new(stream(&[entry])), |record| {
            records.push(record);
            Ok(())
        })
        .unwrap();
        assert_eq!(receipt.records, 1);
        assert_eq!(records[0].entry_kind, EntryKind::Signpost);
        assert_eq!(records[0].signpost_id, Some(11));
    }

    #[test]
    fn rejects_truncation_corruption_unknown_fields_and_bad_shape() {
        let entry = concat!(
            "{\"type\":\"entry\",\"ordinal\":1,\"timestamp_unix_ns\":\"1\",",
            "\"entry_kind\":\"log\",\"level\":\"info\",\"process_id\":1,",
            "\"thread_id\":2,\"activity_id\":3}"
        );
        let valid = stream(&[entry]);
        assert!(matches!(
            parse(Cursor::new(&valid[..valid.len() - 2]), |_| Ok(())),
            Err(AppleLogImportError::UnterminatedLine(_)) | Err(AppleLogImportError::MissingEnd)
        ));
        let mut corrupt = valid.clone();
        let position = corrupt.iter().position(|byte| *byte == b'1').unwrap();
        corrupt[position] = b'2';
        assert!(parse(Cursor::new(corrupt), |_| Ok(())).is_err());
        let unknown =
            entry.replace("\"activity_id\":3", "\"activity_id\":3,\"message\":\"secret\"");
        assert!(matches!(
            parse(Cursor::new(stream(&[&unknown])), |_| Ok(())),
            Err(AppleLogImportError::Json(_))
        ));
        let invalid_signpost =
            entry.replace("\"entry_kind\":\"log\"", "\"entry_kind\":\"signpost\"");
        assert!(matches!(
            parse(Cursor::new(stream(&[&invalid_signpost])), |_| Ok(())),
            Err(AppleLogImportError::InvalidSignpostShape(1))
        ));
    }
}
