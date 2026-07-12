//! SQLCipher-backed per-investigation repository.

use glassbox_contracts::{EvidenceRelation, NativeObservation, SemanticObservationId};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const SCHEMA_VERSION: i64 = 1;

pub struct SqlCipherRepository {
    connection: Connection,
}

impl SqlCipherRepository {
    pub fn create(path: &Path, key: [u8; 32]) -> Result<Self, StorageError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
        let existed = path.exists();
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )?;
        if !existed {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        Self::configure(connection, key, true)
    }

    pub fn open(path: &Path, key: [u8; 32]) -> Result<Self, StorageError> {
        let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        Self::configure(connection, key, false)
    }

    fn configure(
        connection: Connection,
        key: [u8; 32],
        initialize: bool,
    ) -> Result<Self, StorageError> {
        let mut encoded = Zeroizing::new(hex::encode(key));
        connection.execute_batch(&format!("PRAGMA key = \"x'{}'\";", encoded.as_str()))?;
        encoded.zeroize();
        let cipher_version: String =
            connection.query_row("PRAGMA cipher_version", [], |row| row.get(0))?;
        if cipher_version.is_empty() {
            return Err(StorageError::CipherUnavailable);
        }
        connection.execute_batch(
            "PRAGMA foreign_keys=ON;
             PRAGMA temp_store=MEMORY;
             PRAGMA secure_delete=ON;
             PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;",
        )?;
        let temp_store_2: bool = connection
            .prepare("PRAGMA compile_options")?
            .query_map([], |row| row.get::<_, String>(0))?
            .filter_map(Result::ok)
            .any(|option| option == "TEMP_STORE=2");
        if !temp_store_2 {
            return Err(StorageError::UnsafeTempStore);
        }
        let mut repository = Self { connection };
        if initialize {
            repository.migrate()?;
        }
        repository.verify_schema()?;
        Ok(repository)
    }

    fn migrate(&mut self) -> Result<(), StorageError> {
        let tx = self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_meta(version INTEGER NOT NULL);
             INSERT INTO schema_meta(version) SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM schema_meta);
             CREATE TABLE IF NOT EXISTS observations(
               semantic_id TEXT PRIMARY KEY,
               payload_json BLOB NOT NULL
             ) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS relations(
               from_id TEXT NOT NULL REFERENCES observations(semantic_id),
               to_id TEXT NOT NULL REFERENCES observations(semantic_id),
               payload_json BLOB NOT NULL,
               PRIMARY KEY(from_id, to_id, payload_json)
             ) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS committed_batches(
               batch_id TEXT PRIMARY KEY
             ) WITHOUT ROWID;",
        )?;
        tx.commit()?;
        Ok(())
    }

    fn verify_schema(&self) -> Result<(), StorageError> {
        let version: i64 =
            self.connection.query_row("SELECT version FROM schema_meta", [], |row| row.get(0))?;
        if version != SCHEMA_VERSION {
            return Err(StorageError::UnsupportedSchema(version));
        }
        Ok(())
    }

    pub fn publish_atomic(
        &mut self,
        batch_id: &str,
        observations: &[NativeObservation],
        relations: &[EvidenceRelation],
    ) -> Result<PublishResult, StorageError> {
        self.publish_atomic_inner(batch_id, observations, relations, || {})
    }

    fn publish_atomic_inner<F: FnOnce()>(
        &mut self,
        batch_id: &str,
        observations: &[NativeObservation],
        relations: &[EvidenceRelation],
        before_commit: F,
    ) -> Result<PublishResult, StorageError> {
        let tx = self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if tx
            .query_row("SELECT 1 FROM committed_batches WHERE batch_id=?1", [batch_id], |_| Ok(()))
            .optional()?
            .is_some()
        {
            return Ok(PublishResult { inserted: 0, replayed: true });
        }
        let mut inserted = 0;
        for observation in observations {
            let semantic_id = observation.semantic_id.as_str();
            let payload = serde_json::to_vec(observation)?;
            let changed = tx.execute(
                "INSERT OR IGNORE INTO observations(semantic_id,payload_json) VALUES (?1,?2)",
                params![semantic_id, payload],
            )?;
            if changed == 1 {
                inserted += 1;
                continue;
            }
            let existing: Vec<u8> = tx.query_row(
                "SELECT payload_json FROM observations WHERE semantic_id=?1",
                [semantic_id],
                |row| row.get(0),
            )?;
            if existing != payload {
                return Err(StorageError::SemanticCollision(semantic_id.to_owned()));
            }
        }
        for relation in relations {
            tx.execute(
                "INSERT OR IGNORE INTO relations(from_id,to_id,payload_json) VALUES (?1,?2,?3)",
                params![
                    relation.from.as_str(),
                    relation.to.as_str(),
                    serde_json::to_vec(relation)?
                ],
            )?;
        }
        tx.execute("INSERT INTO committed_batches(batch_id) VALUES (?1)", [batch_id])?;
        before_commit();
        tx.commit()?;
        Ok(PublishResult { inserted, replayed: false })
    }

    #[cfg(feature = "test-hooks")]
    pub fn publish_atomic_with_test_hook<F: FnOnce()>(
        &mut self,
        batch_id: &str,
        observations: &[NativeObservation],
        relations: &[EvidenceRelation],
        before_commit: F,
    ) -> Result<PublishResult, StorageError> {
        self.publish_atomic_inner(batch_id, observations, relations, before_commit)
    }

    pub fn observation(
        &self,
        id: &SemanticObservationId,
    ) -> Result<Option<NativeObservation>, StorageError> {
        let payload: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT payload_json FROM observations WHERE semantic_id=?1",
                [id.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        payload.map(|bytes| serde_json::from_slice(&bytes).map_err(StorageError::from)).transpose()
    }

    pub fn observation_count(&self) -> Result<usize, StorageError> {
        let count: i64 =
            self.connection.query_row("SELECT count(*) FROM observations", [], |row| row.get(0))?;
        usize::try_from(count).map_err(|_| StorageError::InvalidCount(count))
    }

    /// Returns a stable, bounded keyset page. The cursor need not identify an existing row.
    pub fn observation_page_after(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<ObservationPage, StorageError> {
        if limit == 0 || limit > MAX_OBSERVATION_PAGE_SIZE {
            return Err(StorageError::InvalidPageSize(limit));
        }
        let cursor = after.unwrap_or("");
        let mut statement = self.connection.prepare(
            "SELECT semantic_id,payload_json FROM observations
             WHERE semantic_id > ?1 ORDER BY semantic_id LIMIT ?2",
        )?;
        let mut rows = statement.query(params![cursor, (limit + 1) as i64])?;
        let mut observations = Vec::with_capacity(limit);
        let mut has_more = false;
        while let Some(row) = rows.next()? {
            if observations.len() == limit {
                has_more = true;
                break;
            }
            let semantic_id: String = row.get(0)?;
            let payload: Vec<u8> = row.get(1)?;
            let observation: NativeObservation = serde_json::from_slice(&payload)?;
            if observation.semantic_id.as_str() != semantic_id {
                return Err(StorageError::StoredIdentityMismatch);
            }
            observations.push(observation);
        }
        let next_cursor = if has_more {
            observations.last().map(|item| item.semantic_id.as_str().to_owned())
        } else {
            None
        };
        Ok(ObservationPage { observations, next_cursor })
    }
}

pub const MAX_OBSERVATION_PAGE_SIZE: usize = 500;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationPage {
    pub observations: Vec<NativeObservation>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishResult {
    pub inserted: usize,
    pub replayed: bool,
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("SQLCipher is unavailable")]
    CipherUnavailable,
    #[error("SQLCipher was not compiled with TEMP_STORE=2")]
    UnsafeTempStore,
    #[error("unsupported schema version {0}")]
    UnsupportedSchema(i64),
    #[error("semantic identity collision for {0}")]
    SemanticCollision(String),
    #[error("invalid observation count {0}")]
    InvalidCount(i64),
    #[error("page size {0} is outside 1..=500")]
    InvalidPageSize(usize),
    #[error("stored semantic identity does not match its index key")]
    StoredIdentityMismatch,
    #[error(transparent)]
    Sql(#[from] rusqlite::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use glassbox_fixtures::gate1_fixture;

    #[test]
    fn encrypted_repository_is_atomic_immutable_and_idempotent() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("investigation/store.sqlite3");
        let fixture = gate1_fixture();
        let mut repository = SqlCipherRepository::create(&path, [7; 32]).unwrap();
        let first = repository
            .publish_atomic("batch-1", &fixture.observations, &fixture.relations)
            .unwrap();
        assert_eq!(first, PublishResult { inserted: 2, replayed: false });
        let replay = repository
            .publish_atomic("batch-1", &fixture.observations, &fixture.relations)
            .unwrap();
        assert_eq!(replay, PublishResult { inserted: 0, replayed: true });
        assert_eq!(repository.observation_count().unwrap(), 2);
        let page = repository.observation_page_after(None, 1).unwrap();
        assert_eq!(page.observations.len(), 1);
        assert!(page.next_cursor.is_some());
        let second_page =
            repository.observation_page_after(page.next_cursor.as_deref(), 1).unwrap();
        assert_eq!(second_page.observations.len(), 1);
        assert_ne!(page.observations[0].semantic_id, second_page.observations[0].semantic_id);
        assert!(matches!(
            repository.observation_page_after(None, 0),
            Err(StorageError::InvalidPageSize(0))
        ));
        assert_eq!(
            repository.observation(&fixture.observations[0].semantic_id).unwrap(),
            Some(fixture.observations[0].clone())
        );
        let mut conflict = fixture.observations[0].clone();
        conflict.native_id = "mutated".into();
        assert!(matches!(
            repository.publish_atomic("batch-2", &[conflict], &[]),
            Err(StorageError::SemanticCollision(_))
        ));
        assert_eq!(repository.observation_count().unwrap(), 2);
    }

    #[test]
    fn wrong_key_and_missing_key_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("store.sqlite3");
        drop(SqlCipherRepository::create(&path, [8; 32]).unwrap());
        assert!(SqlCipherRepository::open(&path, [9; 32]).is_err());
        assert!(Connection::open(path)
            .unwrap()
            .query_row("SELECT version FROM schema_meta", [], |row| row.get::<_, i64>(0))
            .is_err());
    }
}
