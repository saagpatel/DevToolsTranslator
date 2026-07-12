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
        let mut frames = Vec::new();
        let mut remaining = encoded.as_slice();
        while !remaining.is_empty() {
            let length = u32::from_be_bytes(remaining[..4].try_into().unwrap()) as usize;
            frames.push(remaining[4..4 + length].to_vec());
            remaining = &remaining[4 + length..];
        }
        let temp = tempfile::tempdir().unwrap();
        let repository =
            SqlCipherRepository::create(&temp.path().join("store.sqlite3"), [13; 32]).unwrap();
        let mut coordinator = ImportCoordinator::new(repository);
        let slices: Vec<&[u8]> = frames.iter().map(Vec::as_slice).collect();
        assert_eq!(coordinator.publish_frames("worker-batch", slices).unwrap().inserted, 1);
        assert_eq!(coordinator.repository().observation_count().unwrap(), 1);
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
