//! Streaming, fixed-member Glassbox Evidence Bundle.
//!
//! The container has no filenames to interpret and performs no extraction. It
//! consists of a versioned manifest followed by exactly two length-bounded,
//! hash-bound NDJSON members: native observations and evidence relations.

use glassbox_contracts::{EvidenceRelation, NativeObservation, SemanticObservationId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Read, Write};
use thiserror::Error;

const MAGIC: &[u8; 8] = b"GLSBX001";
pub const FORMAT_MAJOR: u16 = 1;
pub const FORMAT_MINOR: u16 = 1;
pub const PREVIOUS_FORMAT_MINOR: u16 = 0;
pub const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
pub const MAX_RECORD_BYTES: usize = 1024 * 1024;
pub const MAX_EXPANDED_BYTES: u64 = 16 * 1024 * 1024 * 1024;
pub const MAX_OBSERVATIONS: u64 = 10_000_000;
pub const MAX_RELATIONS: u64 = 20_000_000;
const MEMBER_HEADER_BYTES: usize = 1 + 8 + 8 + 32;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleManifest {
    pub schema_version: String,
    pub format_major: u16,
    pub format_minor: u16,
    pub authenticity: String,
    pub members: Vec<MemberManifest>,
    pub integrity_root_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derivation: Option<DerivationManifest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberManifest {
    pub kind: String,
    pub media_type: String,
    pub bytes: u64,
    pub records: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationManifest {
    pub source_bundle_sha256: String,
    pub redaction_policy_version: String,
    pub derivation_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BundleRecord {
    Manifest(BundleManifest),
    Observation(NativeObservation),
    Relation(EvidenceRelation),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundleReceipt {
    pub manifest: BundleManifest,
    pub total_bytes: u64,
}

#[derive(Clone, Copy)]
enum MemberKind {
    Observations = 1,
    Relations = 2,
}

impl MemberKind {
    fn name(self) -> &'static str {
        match self {
            Self::Observations => "observations.ndjson",
            Self::Relations => "relations.ndjson",
        }
    }

    fn media_type(self) -> &'static str {
        "application/x-ndjson"
    }

    fn limit(self) -> u64 {
        match self {
            Self::Observations => MAX_OBSERVATIONS,
            Self::Relations => MAX_RELATIONS,
        }
    }
}

pub fn write_lossless<W: Write>(
    mut output: W,
    observations: &[NativeObservation],
    relations: &[EvidenceRelation],
) -> Result<BundleReceipt, BundleError> {
    write_lossless_versioned(&mut output, observations, relations, FORMAT_MINOR)
}

fn write_lossless_versioned<W: Write>(
    mut output: W,
    observations: &[NativeObservation],
    relations: &[EvidenceRelation],
    minor: u16,
) -> Result<BundleReceipt, BundleError> {
    if !matches!(minor, PREVIOUS_FORMAT_MINOR | FORMAT_MINOR) {
        return Err(BundleError::UnsupportedMinor(minor));
    }
    let observation_member = measure_observations(observations)?;
    let relation_member = measure_relations(relations)?;
    let members = vec![observation_member, relation_member];
    validate_expanded_total(&members)?;
    let manifest = BundleManifest {
        schema_version: "glassbox-evidence-bundle/v1".into(),
        format_major: FORMAT_MAJOR,
        format_minor: minor,
        authenticity: "unsigned_local".into(),
        integrity_root_sha256: integrity_root(&members),
        members,
        derivation: None,
    };
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    if manifest_bytes.len() > MAX_MANIFEST_BYTES {
        return Err(BundleError::ManifestTooLarge(manifest_bytes.len()));
    }
    output.write_all(MAGIC)?;
    output.write_all(&FORMAT_MAJOR.to_be_bytes())?;
    output.write_all(&minor.to_be_bytes())?;
    output.write_all(&(manifest_bytes.len() as u32).to_be_bytes())?;
    output.write_all(&manifest_bytes)?;
    write_member_header(&mut output, MemberKind::Observations, &manifest.members[0])?;
    write_records(&mut output, observations)?;
    write_member_header(&mut output, MemberKind::Relations, &manifest.members[1])?;
    write_records(&mut output, relations)?;
    let total_bytes = 8_u64
        + 2
        + 2
        + 4
        + manifest_bytes.len() as u64
        + (2 * MEMBER_HEADER_BYTES) as u64
        + manifest.members.iter().map(|member| member.bytes).sum::<u64>();
    Ok(BundleReceipt { manifest, total_bytes })
}

pub fn read_bundle<R, F>(mut input: R, mut sink: F) -> Result<BundleReceipt, BundleError>
where
    R: Read,
    F: FnMut(BundleRecord) -> Result<(), BundleError>,
{
    let mut magic = [0_u8; 8];
    input.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(BundleError::InvalidMagic);
    }
    let major = read_u16(&mut input)?;
    let minor = read_u16(&mut input)?;
    validate_version(major, minor)?;
    let manifest_length = read_u32(&mut input)? as usize;
    if manifest_length == 0 || manifest_length > MAX_MANIFEST_BYTES {
        return Err(BundleError::ManifestTooLarge(manifest_length));
    }
    let mut manifest_bytes = vec![0_u8; manifest_length];
    input.read_exact(&mut manifest_bytes)?;
    let manifest: BundleManifest = serde_json::from_slice(&manifest_bytes)?;
    validate_manifest(&manifest, major, minor)?;
    sink(BundleRecord::Manifest(manifest.clone()))?;

    let mut total_bytes = 8_u64 + 2 + 2 + 4 + manifest_length as u64;
    for (index, kind) in [MemberKind::Observations, MemberKind::Relations].into_iter().enumerate() {
        let member = &manifest.members[index];
        read_and_validate_member_header(&mut input, kind, member)?;
        total_bytes = total_bytes
            .checked_add(MEMBER_HEADER_BYTES as u64)
            .and_then(|value| value.checked_add(member.bytes))
            .ok_or(BundleError::ExpandedTooLarge(u64::MAX))?;
        if total_bytes > MAX_EXPANDED_BYTES {
            return Err(BundleError::ExpandedTooLarge(total_bytes));
        }
        read_member_records(&mut input, kind, member, &mut sink)?;
    }
    let mut trailing = [0_u8; 1];
    if input.read(&mut trailing)? != 0 {
        return Err(BundleError::TrailingData);
    }
    Ok(BundleReceipt { manifest, total_bytes })
}

fn measure_observations(records: &[NativeObservation]) -> Result<MemberManifest, BundleError> {
    if records.len() as u64 > MAX_OBSERVATIONS {
        return Err(BundleError::TooManyRecords(MemberKind::Observations.name()));
    }
    for record in records {
        validate_observation(record)?;
    }
    measure_records(MemberKind::Observations, records)
}

fn measure_relations(records: &[EvidenceRelation]) -> Result<MemberManifest, BundleError> {
    if records.len() as u64 > MAX_RELATIONS {
        return Err(BundleError::TooManyRecords(MemberKind::Relations.name()));
    }
    for record in records {
        record.validate().map_err(|_| BundleError::InvalidRelation)?;
    }
    measure_records(MemberKind::Relations, records)
}

fn measure_records<T: Serialize>(
    kind: MemberKind,
    records: &[T],
) -> Result<MemberManifest, BundleError> {
    let mut hasher = Sha256::new();
    let mut bytes = 0_u64;
    for record in records {
        let encoded = serde_json::to_vec(record)?;
        if encoded.len() + 1 > MAX_RECORD_BYTES {
            return Err(BundleError::RecordTooLarge(encoded.len() + 1));
        }
        hasher.update(&encoded);
        hasher.update(b"\n");
        bytes = bytes
            .checked_add(encoded.len() as u64 + 1)
            .ok_or(BundleError::ExpandedTooLarge(u64::MAX))?;
    }
    Ok(MemberManifest {
        kind: kind.name().into(),
        media_type: kind.media_type().into(),
        bytes,
        records: records.len() as u64,
        sha256: hex::encode(hasher.finalize()),
    })
}

fn write_records<W: Write, T: Serialize>(output: &mut W, records: &[T]) -> Result<(), BundleError> {
    for record in records {
        serde_json::to_writer(&mut *output, record)?;
        output.write_all(b"\n")?;
    }
    Ok(())
}

fn write_member_header<W: Write>(
    output: &mut W,
    kind: MemberKind,
    member: &MemberManifest,
) -> Result<(), BundleError> {
    output.write_all(&[kind as u8])?;
    output.write_all(&member.bytes.to_be_bytes())?;
    output.write_all(&member.records.to_be_bytes())?;
    let digest = hex::decode(&member.sha256).map_err(|_| BundleError::InvalidDigest)?;
    if digest.len() != 32 {
        return Err(BundleError::InvalidDigest);
    }
    output.write_all(&digest)?;
    Ok(())
}

fn read_and_validate_member_header<R: Read>(
    input: &mut R,
    kind: MemberKind,
    member: &MemberManifest,
) -> Result<(), BundleError> {
    let mut encoded_kind = [0_u8; 1];
    input.read_exact(&mut encoded_kind)?;
    let bytes = read_u64(input)?;
    let records = read_u64(input)?;
    let mut digest = [0_u8; 32];
    input.read_exact(&mut digest)?;
    if encoded_kind[0] != kind as u8
        || bytes != member.bytes
        || records != member.records
        || hex::encode(digest) != member.sha256
    {
        return Err(BundleError::MemberHeaderMismatch(kind.name()));
    }
    if records > kind.limit() {
        return Err(BundleError::TooManyRecords(kind.name()));
    }
    Ok(())
}

fn read_member_records<R, F>(
    input: &mut R,
    kind: MemberKind,
    member: &MemberManifest,
    sink: &mut F,
) -> Result<(), BundleError>
where
    R: Read,
    F: FnMut(BundleRecord) -> Result<(), BundleError>,
{
    let take = (&mut *input).take(member.bytes);
    let mut reader = BufReader::new(take);
    let mut hasher = Sha256::new();
    let mut records = 0_u64;
    loop {
        let mut line = Vec::new();
        let bytes =
            Read::take(&mut reader, MAX_RECORD_BYTES as u64).read_until(b'\n', &mut line)?;
        if bytes == 0 {
            break;
        }
        if bytes == MAX_RECORD_BYTES && line.last() != Some(&b'\n') {
            return Err(BundleError::RecordTooLarge(bytes));
        }
        if line.last() != Some(&b'\n') {
            return Err(BundleError::TruncatedMember(kind.name()));
        }
        hasher.update(&line);
        line.pop();
        if line.is_empty() {
            return Err(BundleError::EmptyRecord(kind.name()));
        }
        records += 1;
        if records > kind.limit() {
            return Err(BundleError::TooManyRecords(kind.name()));
        }
        let record = match kind {
            MemberKind::Observations => {
                let observation: NativeObservation = serde_json::from_slice(&line)?;
                validate_observation(&observation)?;
                BundleRecord::Observation(observation)
            }
            MemberKind::Relations => {
                let relation: EvidenceRelation = serde_json::from_slice(&line)?;
                relation.validate().map_err(|_| BundleError::InvalidRelation)?;
                BundleRecord::Relation(relation)
            }
        };
        sink(record)?;
    }
    let take = reader.into_inner();
    if take.limit() != 0 {
        return Err(BundleError::TruncatedMember(kind.name()));
    }
    if records != member.records {
        return Err(BundleError::RecordCountMismatch(kind.name()));
    }
    if hex::encode(hasher.finalize()) != member.sha256 {
        return Err(BundleError::MemberHashMismatch(kind.name()));
    }
    Ok(())
}

fn validate_manifest(manifest: &BundleManifest, major: u16, minor: u16) -> Result<(), BundleError> {
    if manifest.schema_version != "glassbox-evidence-bundle/v1"
        || manifest.format_major != major
        || manifest.format_minor != minor
        || manifest.authenticity != "unsigned_local"
        || manifest.members.len() != 2
    {
        return Err(BundleError::InvalidManifest);
    }
    for (member, kind) in
        manifest.members.iter().zip([MemberKind::Observations, MemberKind::Relations])
    {
        if member.kind != kind.name()
            || member.media_type != kind.media_type()
            || member.records > kind.limit()
            || member.sha256.len() != 64
            || !member.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(BundleError::InvalidManifest);
        }
    }
    validate_expanded_total(&manifest.members)?;
    if integrity_root(&manifest.members) != manifest.integrity_root_sha256 {
        return Err(BundleError::IntegrityRootMismatch);
    }
    if minor == PREVIOUS_FORMAT_MINOR && manifest.derivation.is_some() {
        return Err(BundleError::InvalidManifest);
    }
    if let Some(derivation) = &manifest.derivation {
        for digest in [&derivation.source_bundle_sha256, &derivation.derivation_sha256] {
            if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(BundleError::InvalidDigest);
            }
        }
        if derivation.redaction_policy_version.is_empty()
            || derivation.redaction_policy_version.len() > 128
        {
            return Err(BundleError::InvalidManifest);
        }
    }
    Ok(())
}

fn validate_version(major: u16, minor: u16) -> Result<(), BundleError> {
    if major != FORMAT_MAJOR {
        return Err(BundleError::UnsupportedMajor(major));
    }
    if !matches!(minor, PREVIOUS_FORMAT_MINOR | FORMAT_MINOR) {
        return Err(BundleError::UnsupportedMinor(minor));
    }
    Ok(())
}

fn validate_expanded_total(members: &[MemberManifest]) -> Result<(), BundleError> {
    let total = members.iter().try_fold(0_u64, |total, member| {
        total.checked_add(member.bytes).ok_or(BundleError::ExpandedTooLarge(u64::MAX))
    })?;
    if total > MAX_EXPANDED_BYTES {
        return Err(BundleError::ExpandedTooLarge(total));
    }
    Ok(())
}

fn validate_observation(observation: &NativeObservation) -> Result<(), BundleError> {
    let expected = SemanticObservationId::derive(
        &observation.source_kind,
        &observation.capture_session,
        &observation.native_id,
    );
    if observation.semantic_id != expected {
        return Err(BundleError::SemanticIdentityMismatch);
    }
    if observation.observed_time.earliest_ns > observation.observed_time.latest_ns {
        return Err(BundleError::InvalidTimeInterval);
    }
    for value in [
        observation.source_kind.as_str(),
        observation.capture_session.as_str(),
        observation.native_id.as_str(),
        observation.materialization_id.0.as_str(),
        observation.lineage_id.0.as_str(),
    ] {
        if value.is_empty() || value.len() > MAX_RECORD_BYTES {
            return Err(BundleError::InvalidObservationField);
        }
    }
    if observation.fields.len() > 1024
        || observation
            .fields
            .iter()
            .any(|(key, value)| key.is_empty() || key.len() > 256 || value.len() > 64 * 1024)
    {
        return Err(BundleError::InvalidObservationField);
    }
    Ok(())
}

fn integrity_root(members: &[MemberManifest]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"glassbox-evidence-bundle-integrity/v1\0");
    for member in members {
        for value in
            [member.kind.as_bytes(), member.media_type.as_bytes(), member.sha256.as_bytes()]
        {
            hasher.update((value.len() as u64).to_be_bytes());
            hasher.update(value);
        }
        hasher.update(member.bytes.to_be_bytes());
        hasher.update(member.records.to_be_bytes());
    }
    hex::encode(hasher.finalize())
}

fn read_u16<R: Read>(input: &mut R) -> Result<u16, BundleError> {
    let mut bytes = [0_u8; 2];
    input.read_exact(&mut bytes)?;
    Ok(u16::from_be_bytes(bytes))
}

fn read_u32<R: Read>(input: &mut R) -> Result<u32, BundleError> {
    let mut bytes = [0_u8; 4];
    input.read_exact(&mut bytes)?;
    Ok(u32::from_be_bytes(bytes))
}

fn read_u64<R: Read>(input: &mut R) -> Result<u64, BundleError> {
    let mut bytes = [0_u8; 8];
    input.read_exact(&mut bytes)?;
    Ok(u64::from_be_bytes(bytes))
}

#[derive(Debug, Error)]
pub enum BundleError {
    #[error("Glassbox bundle magic is invalid")]
    InvalidMagic,
    #[error("unsupported Glassbox bundle major version {0}")]
    UnsupportedMajor(u16),
    #[error("unsupported Glassbox bundle minor version {0}")]
    UnsupportedMinor(u16),
    #[error("Glassbox bundle manifest is {0} bytes or empty")]
    ManifestTooLarge(usize),
    #[error("Glassbox bundle manifest is invalid")]
    InvalidManifest,
    #[error("Glassbox bundle digest is invalid")]
    InvalidDigest,
    #[error("Glassbox bundle integrity root does not match its members")]
    IntegrityRootMismatch,
    #[error("Glassbox bundle expanded size exceeds the limit: {0}")]
    ExpandedTooLarge(u64),
    #[error("Glassbox bundle member header does not match: {0}")]
    MemberHeaderMismatch(&'static str),
    #[error("Glassbox bundle member hash does not match: {0}")]
    MemberHashMismatch(&'static str),
    #[error("Glassbox bundle member is truncated: {0}")]
    TruncatedMember(&'static str),
    #[error("Glassbox bundle member has the wrong record count: {0}")]
    RecordCountMismatch(&'static str),
    #[error("Glassbox bundle member contains an empty record: {0}")]
    EmptyRecord(&'static str),
    #[error("Glassbox bundle contains too many records in {0}")]
    TooManyRecords(&'static str),
    #[error("Glassbox bundle record is too large: {0}")]
    RecordTooLarge(usize),
    #[error("Glassbox observation semantic identity does not match its native locator")]
    SemanticIdentityMismatch,
    #[error("Glassbox observation time interval is inverted")]
    InvalidTimeInterval,
    #[error("Glassbox observation contains an invalid bounded field")]
    InvalidObservationField,
    #[error("Glassbox evidence relation is invalid")]
    InvalidRelation,
    #[error("Glassbox bundle contains trailing data")]
    TrailingData,
    #[error("Glassbox bundle sink rejected a record: {0}")]
    Sink(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use glassbox_fixtures::gate1_fixture;
    use std::io::Cursor;

    #[test]
    fn lossless_round_trip_preserves_semantic_evidence_and_integrity() {
        let fixture = gate1_fixture();
        let mut encoded = Vec::new();
        let written =
            write_lossless(&mut encoded, &fixture.observations, &fixture.relations).unwrap();
        let mut decoded = Vec::new();
        let read = read_bundle(Cursor::new(&encoded), |record| {
            decoded.push(record);
            Ok(())
        })
        .unwrap();
        assert_eq!(written, read);
        assert_eq!(decoded.len(), 1 + fixture.observations.len() + fixture.relations.len());
        assert_eq!(written.manifest.authenticity, "unsigned_local");
    }

    #[test]
    fn reads_n_minus_one_minor_and_rejects_unknown_versions() {
        let fixture = gate1_fixture();
        let mut previous = Vec::new();
        write_lossless_versioned(
            &mut previous,
            &fixture.observations,
            &fixture.relations,
            PREVIOUS_FORMAT_MINOR,
        )
        .unwrap();
        assert!(read_bundle(Cursor::new(previous), |_| Ok(())).is_ok());

        let mut future = Vec::new();
        write_lossless(&mut future, &fixture.observations, &fixture.relations).unwrap();
        future[8..10].copy_from_slice(&2_u16.to_be_bytes());
        assert!(matches!(
            read_bundle(Cursor::new(future), |_| Ok(())),
            Err(BundleError::UnsupportedMajor(2))
        ));
    }

    #[test]
    fn corruption_truncation_and_trailing_data_fail_closed() {
        let fixture = gate1_fixture();
        let mut encoded = Vec::new();
        write_lossless(&mut encoded, &fixture.observations, &fixture.relations).unwrap();
        let mut corrupt = encoded.clone();
        let index = corrupt.len() - 2;
        corrupt[index] ^= 1;
        assert!(read_bundle(Cursor::new(corrupt), |_| Ok(())).is_err());
        assert!(read_bundle(Cursor::new(&encoded[..encoded.len() - 1]), |_| Ok(())).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(matches!(
            read_bundle(Cursor::new(trailing), |_| Ok(())),
            Err(BundleError::TrailingData)
        ));
    }
}
