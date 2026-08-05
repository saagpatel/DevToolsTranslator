//! Trusted validation and publication boundary for hostile-worker output.

use glassbox_import::{BatchAssembler, ImportContractError, StagedBatch};
use glassbox_kernel::{EvidenceKernel, KernelError};
use glassbox_storage_sqlite::{PublishResult, SqlCipherRepository, StorageError};
use thiserror::Error;

pub struct ImportCoordinator {
    repository: SqlCipherRepository,
}

impl ImportCoordinator {
    pub fn new(repository: SqlCipherRepository) -> Self {
        Self { repository }
    }

    pub fn publish_frames<'a, I>(
        &mut self,
        batch_id: &str,
        frames: I,
    ) -> Result<PublishResult, CoordinatorError>
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let mut assembler = BatchAssembler::default();
        for frame in frames {
            assembler.push(frame)?;
        }
        self.publish(batch_id, assembler.finish()?)
    }

    pub fn publish(
        &mut self,
        batch_id: &str,
        batch: StagedBatch,
    ) -> Result<PublishResult, CoordinatorError> {
        batch.validate()?;
        let mut validator = EvidenceKernel::default();
        validator.import_atomic(batch.observations.clone(), batch.relations.clone())?;
        self.repository
            .publish_atomic(batch_id, &batch.observations, &batch.relations)
            .map_err(Into::into)
    }

    pub fn repository(&self) -> &SqlCipherRepository {
        &self.repository
    }
}

#[derive(Debug, Error)]
pub enum CoordinatorError {
    #[error(transparent)]
    Contract(#[from] ImportContractError),
    #[error(transparent)]
    Kernel(#[from] KernelError),
    #[error(transparent)]
    Storage(#[from] StorageError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use glassbox_fixtures::gate1_fixture;
    use std::env;
    use std::io::Cursor;
    use std::path::Path;
    use std::process::Command;

    fn batch() -> StagedBatch {
        let fixture = gate1_fixture();
        StagedBatch {
            protocol_version: 1,
            source_format: "fixture-v1".into(),
            observations: fixture.observations,
            relations: fixture.relations,
        }
    }

    fn decode_worker_frames(mut encoded: &[u8]) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        while !encoded.is_empty() {
            let length = u32::from_be_bytes(encoded[..4].try_into().unwrap()) as usize;
            frames.push(encoded[4..4 + length].to_vec());
            encoded = &encoded[4 + length..];
        }
        frames
    }

    #[test]
    fn coordinator_validates_then_publishes_and_replays() {
        let temp = tempfile::tempdir().unwrap();
        let repository =
            SqlCipherRepository::create(&temp.path().join("store.sqlite3"), [11; 32]).unwrap();
        let mut coordinator = ImportCoordinator::new(repository);
        assert_eq!(coordinator.publish("batch-1", batch()).unwrap().inserted, 2);
        assert!(coordinator.publish("batch-1", batch()).unwrap().replayed);
        assert_eq!(coordinator.repository().observation_count().unwrap(), 2);
    }

    #[test]
    fn worker_frames_publish_only_after_complete_end_frame() {
        let observation = &batch().observations[0];
        let input = serde_json::to_vec(
            &serde_json::json!({"type":"observation","observation":observation}),
        )
        .unwrap();
        let mut encoded = Vec::new();
        glassbox_import_worker::translate(Cursor::new(input), &mut encoded, "fixture-v1").unwrap();
        let frames = decode_worker_frames(&encoded);
        let temp = tempfile::tempdir().unwrap();
        let repository =
            SqlCipherRepository::create(&temp.path().join("store.sqlite3"), [13; 32]).unwrap();
        let mut coordinator = ImportCoordinator::new(repository);
        let slices: Vec<&[u8]> = frames.iter().map(Vec::as_slice).collect();
        assert_eq!(coordinator.publish_frames("worker-batch", slices).unwrap().inserted, 1);
        assert_eq!(coordinator.repository().observation_count().unwrap(), 1);
    }

    #[test]
    fn interrupted_har_worker_stream_cannot_publish_but_complete_stream_can() {
        let har = include_str!("../../glassbox-fixtures/corpus/hostile-import/har/valid.har");
        let mut encoded = Vec::new();
        glassbox_import_worker::translate_har(
            Cursor::new(har),
            &mut encoded,
            "selected_har",
            "session_001",
        )
        .unwrap();
        for secret in [
            "seed-host.example",
            "seed-query",
            "seed-cookie",
            "seed-header",
            "seed-request-body",
            "seed-response-body",
            "203.0.113.9",
        ] {
            assert!(!String::from_utf8_lossy(&encoded).contains(secret));
        }

        let frames = decode_worker_frames(&encoded);
        assert_eq!(frames.len(), 3);
        let temp = tempfile::tempdir().unwrap();
        let repository =
            SqlCipherRepository::create(&temp.path().join("store.sqlite3"), [14; 32]).unwrap();
        let mut coordinator = ImportCoordinator::new(repository);

        let interrupted: Vec<&[u8]> = frames[..2].iter().map(Vec::as_slice).collect();
        assert!(coordinator.publish_frames("interrupted-har", interrupted).is_err());
        assert_eq!(coordinator.repository().observation_count().unwrap(), 0);

        let complete: Vec<&[u8]> = frames.iter().map(Vec::as_slice).collect();
        assert_eq!(coordinator.publish_frames("complete-har", complete).unwrap().inserted, 1);
        assert_eq!(coordinator.repository().observation_count().unwrap(), 1);
    }

    #[test]
    fn interrupted_otlp_worker_stream_cannot_publish_but_complete_stream_can() {
        let otlp =
            include_str!("../../glassbox-fixtures/corpus/hostile-import/otlp/valid-traces.jsonl");
        let mut encoded = Vec::new();
        glassbox_import_worker::translate_otlp(
            Cursor::new(otlp),
            &mut encoded,
            "selected_otlp",
            "session_001",
        )
        .unwrap();
        for secret in [
            "seed-resource",
            "seed-scope",
            "seed-root-span",
            "seed-child-span",
            "seed-host",
            "seed-query",
            "seed-event-secret",
            "seed-database-body",
            "seed-root-status",
            "seed-child-status",
        ] {
            assert!(!String::from_utf8_lossy(&encoded).contains(secret));
        }

        let frames = decode_worker_frames(&encoded);
        assert_eq!(frames.len(), 5);
        let temp = tempfile::tempdir().unwrap();
        let repository =
            SqlCipherRepository::create(&temp.path().join("store.sqlite3"), [15; 32]).unwrap();
        let mut coordinator = ImportCoordinator::new(repository);

        let interrupted: Vec<&[u8]> = frames[..4].iter().map(Vec::as_slice).collect();
        assert!(coordinator.publish_frames("interrupted-otlp", interrupted).is_err());
        assert_eq!(coordinator.repository().observation_count().unwrap(), 0);

        let complete: Vec<&[u8]> = frames.iter().map(Vec::as_slice).collect();
        let result = coordinator.publish_frames("complete-otlp", complete).unwrap();
        assert_eq!(result.inserted, 2);
        assert_eq!(coordinator.repository().observation_count().unwrap(), 2);
    }

    #[test]
    fn lossless_bundle_reimport_preserves_semantics_and_adds_materializations_atomically() {
        let fixture = gate1_fixture();
        let mut bundle = Vec::new();
        glassbox_evidence_bundle::write_lossless(
            &mut bundle,
            &fixture.observations,
            &fixture.relations,
        )
        .unwrap();
        let mut encoded = Vec::new();
        glassbox_import_worker::translate_bundle(
            Cursor::new(bundle),
            &mut encoded,
            "selected_bundle",
            "reimport_001",
        )
        .unwrap();
        let frames = decode_worker_frames(&encoded);
        assert_eq!(frames.len(), 5);

        let temp = tempfile::tempdir().unwrap();
        let repository =
            SqlCipherRepository::create(&temp.path().join("store.sqlite3"), [19; 32]).unwrap();
        let mut coordinator = ImportCoordinator::new(repository);
        let original = coordinator.publish("original", batch()).unwrap();
        assert_eq!(original.inserted, 2);
        assert_eq!(original.materializations_inserted, 2);

        let interrupted: Vec<&[u8]> = frames[..4].iter().map(Vec::as_slice).collect();
        assert!(coordinator.publish_frames("interrupted-bundle", interrupted).is_err());
        assert_eq!(coordinator.repository().observation_count().unwrap(), 2);
        assert_eq!(coordinator.repository().materialization_count().unwrap(), 2);

        let complete: Vec<&[u8]> = frames.iter().map(Vec::as_slice).collect();
        let reimported = coordinator.publish_frames("complete-bundle", complete).unwrap();
        assert_eq!(reimported.inserted, 0);
        assert_eq!(reimported.materializations_inserted, 2);
        assert!(!reimported.replayed);
        assert_eq!(coordinator.repository().observation_count().unwrap(), 2);
        assert_eq!(coordinator.repository().materialization_count().unwrap(), 4);
        for original in &fixture.observations {
            let materializations =
                coordinator.repository().materializations(&original.semantic_id).unwrap();
            assert_eq!(materializations.len(), 2);
            assert!(materializations.contains(original));
            assert!(materializations.iter().any(|item| {
                item.semantic_id == original.semantic_id
                    && item.materialization_id != original.materialization_id
                    && item.lineage_id != original.lineage_id
            }));
        }
    }

    #[test]
    fn incomplete_apple_log_projection_cannot_publish_but_complete_projection_can() {
        let projection =
            include_str!("../../glassbox-fixtures/corpus/hostile-import/apple-log/valid.ndjson");
        let mut encoded = Vec::new();
        glassbox_import_worker::translate_apple_log(
            Cursor::new(projection),
            &mut encoded,
            "apple_log_session_001",
        )
        .unwrap();
        let frames = decode_worker_frames(&encoded);
        assert_eq!(frames.len(), 4);
        for forbidden in ["message", "subsystem", "category", "process_name", "sender", "path"] {
            assert!(!String::from_utf8_lossy(&encoded).contains(forbidden));
        }

        let temp = tempfile::tempdir().unwrap();
        let repository =
            SqlCipherRepository::create(&temp.path().join("store.sqlite3"), [21; 32]).unwrap();
        let mut coordinator = ImportCoordinator::new(repository);
        let interrupted: Vec<&[u8]> = frames[..3].iter().map(Vec::as_slice).collect();
        assert!(coordinator.publish_frames("interrupted-apple-log", interrupted).is_err());
        assert_eq!(coordinator.repository().observation_count().unwrap(), 0);
        assert_eq!(coordinator.repository().materialization_count().unwrap(), 0);

        let complete: Vec<&[u8]> = frames.iter().map(Vec::as_slice).collect();
        let result = coordinator.publish_frames("complete-apple-log", complete).unwrap();
        assert_eq!(result.inserted, 2);
        assert_eq!(result.materializations_inserted, 2);
        assert_eq!(coordinator.repository().observation_count().unwrap(), 2);
        assert_eq!(coordinator.repository().materialization_count().unwrap(), 2);
    }

    #[test]
    fn forced_process_abort_before_commit_publishes_nothing() {
        if env::var_os("GLASSBOX_COORDINATOR_CRASH_CHILD").is_some() {
            let path = env::var_os("GLASSBOX_COORDINATOR_DB").unwrap();
            let mut repository = SqlCipherRepository::open(Path::new(&path), [12; 32]).unwrap();
            let batch = batch();
            let _ = repository.publish_atomic_with_test_hook(
                "crash-batch",
                &batch.observations,
                &batch.relations,
                || std::process::abort(),
            );
            unreachable!();
        }
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("store.sqlite3");
        drop(SqlCipherRepository::create(&path, [12; 32]).unwrap());
        let status = Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::forced_process_abort_before_commit_publishes_nothing",
                "--nocapture",
            ])
            .env("GLASSBOX_COORDINATOR_CRASH_CHILD", "1")
            .env("GLASSBOX_COORDINATOR_DB", &path)
            .status()
            .unwrap();
        assert!(!status.success());
        let repository = SqlCipherRepository::open(&path, [12; 32]).unwrap();
        assert_eq!(repository.observation_count().unwrap(), 0);
    }
}
