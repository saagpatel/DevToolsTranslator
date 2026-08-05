//! SQLCipher-backed per-investigation repository.

use glassbox_contracts::{EvidenceRelation, NativeObservation, SemanticObservationId};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const SCHEMA_VERSION: i64 = 2;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredMaterializationMarker {
    schema_version: u8,
}

const MATERIALIZATION_MARKER: StoredMaterializationMarker =
    StoredMaterializationMarker { schema_version: 1 };

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
        Self::configure(connection, key)
    }

    pub fn open(path: &Path, key: [u8; 32]) -> Result<Self, StorageError> {
        let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        Self::configure(connection, key)
    }

    fn configure(connection: Connection, key: [u8; 32]) -> Result<Self, StorageError> {
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
             PRAGMA wal_autocheckpoint=65536;
             PRAGMA cache_size=-65536;
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
        repository.migrate()?;
        repository.verify_schema()?;
        Ok(repository)
    }

    fn migrate(&mut self) -> Result<(), StorageError> {
        let tx = self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch("CREATE TABLE IF NOT EXISTS schema_meta(version INTEGER NOT NULL);")?;
        let version: Option<i64> =
            tx.query_row("SELECT version FROM schema_meta", [], |row| row.get(0)).optional()?;
        match version {
            None => {
                create_schema_v2(&tx)?;
                tx.execute("INSERT INTO schema_meta(version) VALUES (?1)", [SCHEMA_VERSION])?;
            }
            Some(1) => {
                tx.execute_batch(
                    "CREATE TABLE materializations(
                       semantic_id TEXT NOT NULL REFERENCES observations(semantic_id),
                       materialization_id TEXT NOT NULL,
                       lineage_id TEXT NOT NULL,
                       payload_json BLOB NOT NULL,
                       PRIMARY KEY(semantic_id, materialization_id, lineage_id)
                     ) WITHOUT ROWID;",
                )?;
                let payloads: Vec<Vec<u8>> = {
                    let mut statement = tx.prepare("SELECT payload_json FROM observations")?;
                    let payloads =
                        statement.query_map([], |row| row.get(0))?.collect::<Result<_, _>>()?;
                    payloads
                };
                for payload in payloads {
                    let observation: NativeObservation = serde_json::from_slice(&payload)?;
                    tx.execute(
                        "INSERT INTO materializations(
                           semantic_id,materialization_id,lineage_id,payload_json
                         ) VALUES (?1,?2,?3,?4)",
                        params![
                            observation.semantic_id.as_str(),
                            observation.materialization_id.0,
                            observation.lineage_id.0,
                            serde_json::to_vec(&MATERIALIZATION_MARKER)?
                        ],
                    )?;
                }
                tx.execute("UPDATE schema_meta SET version=?1", [SCHEMA_VERSION])?;
            }
            Some(SCHEMA_VERSION) => {}
            Some(other) => return Err(StorageError::UnsupportedSchema(other)),
        }
        tx.commit()?;
        Ok(())
    }

    fn verify_schema(&self) -> Result<(), StorageError> {
        let (rows, minimum, maximum): (i64, Option<i64>, Option<i64>) = self.connection.query_row(
            "SELECT count(*),min(version),max(version) FROM schema_meta",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        if rows != 1 || minimum != Some(SCHEMA_VERSION) || maximum != Some(SCHEMA_VERSION) {
            return Err(StorageError::InvalidSchemaMetadata);
        }
        let table_count: i64 = self.connection.query_row(
            "SELECT count(*) FROM sqlite_master
             WHERE type='table' AND name IN (
               'schema_meta','observations','materializations','relations','committed_batches'
             )",
            [],
            |row| row.get(0),
        )?;
        if table_count != 5 {
            return Err(StorageError::IncompleteSchema);
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
            return Ok(PublishResult { inserted: 0, materializations_inserted: 0, replayed: true });
        }
        let mut inserted = 0;
        let mut materializations_inserted = 0;
        {
            let mut insert_observation = tx.prepare_cached(
                "INSERT OR IGNORE INTO observations(semantic_id,payload_json) VALUES (?1,?2)",
            )?;
            let mut read_observation =
                tx.prepare_cached("SELECT payload_json FROM observations WHERE semantic_id=?1")?;
            let mut insert_materialization = tx.prepare_cached(
                "INSERT OR IGNORE INTO materializations(
                   semantic_id,materialization_id,lineage_id,payload_json
                 ) VALUES (?1,?2,?3,?4)",
            )?;
            let mut read_materialization = tx.prepare_cached(
                "SELECT payload_json FROM materializations
                 WHERE semantic_id=?1 AND materialization_id=?2 AND lineage_id=?3",
            )?;
            for observation in observations {
                let semantic_id = observation.semantic_id.as_str();
                let payload = serde_json::to_vec(observation)?;
                let materialization_payload = serde_json::to_vec(&MATERIALIZATION_MARKER)?;
                let changed = insert_observation.execute(params![semantic_id, payload])?;
                if changed == 1 {
                    inserted += 1;
                } else {
                    let existing: Vec<u8> =
                        read_observation.query_row([semantic_id], |row| row.get(0))?;
                    let existing: NativeObservation = serde_json::from_slice(&existing)?;
                    if !same_semantic_content(&existing, observation) {
                        return Err(StorageError::SemanticCollision(semantic_id.to_owned()));
                    }
                }
                let materialization_changed = insert_materialization.execute(params![
                    semantic_id,
                    observation.materialization_id.0,
                    observation.lineage_id.0,
                    materialization_payload
                ])?;
                materializations_inserted += materialization_changed;
                if materialization_changed == 0 {
                    let existing_materialization: Vec<u8> = read_materialization.query_row(
                        params![
                            semantic_id,
                            observation.materialization_id.0,
                            observation.lineage_id.0
                        ],
                        |row| row.get(0),
                    )?;
                    if !valid_materialization_payload(
                        &existing_materialization,
                        observation,
                        &observation.materialization_id.0,
                        &observation.lineage_id.0,
                    )? {
                        return Err(StorageError::MaterializationCollision {
                            semantic_id: semantic_id.to_owned(),
                            materialization_id: observation.materialization_id.0.clone(),
                            lineage_id: observation.lineage_id.0.clone(),
                        });
                    }
                }
            }
        }
        {
            let mut insert_relation = tx.prepare_cached(
                "INSERT OR IGNORE INTO relations(from_id,to_id,payload_json) VALUES (?1,?2,?3)",
            )?;
            for relation in relations {
                insert_relation.execute(params![
                    relation.from.as_str(),
                    relation.to.as_str(),
                    serde_json::to_vec(relation)?
                ])?;
            }
        }
        tx.execute("INSERT INTO committed_batches(batch_id) VALUES (?1)", [batch_id])?;
        before_commit();
        tx.commit()?;
        Ok(PublishResult { inserted, materializations_inserted, replayed: false })
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
        table_count(&self.connection, "observations")
    }

    pub fn materialization_count(&self) -> Result<usize, StorageError> {
        table_count(&self.connection, "materializations")
    }

    pub fn materializations(
        &self,
        id: &SemanticObservationId,
    ) -> Result<Vec<NativeObservation>, StorageError> {
        let canonical = self.observation(id)?.ok_or(StorageError::StoredIdentityMismatch)?;
        let mut statement = self.connection.prepare(
            "SELECT materialization_id,lineage_id,payload_json
             FROM materializations WHERE semantic_id=?1
             ORDER BY materialization_id,lineage_id",
        )?;
        let rows = statement.query_map([id.as_str()], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Vec<u8>>(2)?))
        })?;
        rows.map(|row| {
            let (materialization_id, lineage_id, payload) = row?;
            if !valid_materialization_payload(
                &payload,
                &canonical,
                &materialization_id,
                &lineage_id,
            )? {
                return Err(StorageError::StoredMaterializationIdentityMismatch);
            }
            let mut observation = canonical.clone();
            observation.materialization_id.0 = materialization_id;
            observation.lineage_id.0 = lineage_id;
            Ok(observation)
        })
        .collect()
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

fn create_schema_v2(tx: &rusqlite::Transaction<'_>) -> Result<(), rusqlite::Error> {
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS observations(
               semantic_id TEXT PRIMARY KEY,
               payload_json BLOB NOT NULL
             ) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS materializations(
               semantic_id TEXT NOT NULL REFERENCES observations(semantic_id),
               materialization_id TEXT NOT NULL,
               lineage_id TEXT NOT NULL,
               payload_json BLOB NOT NULL,
               PRIMARY KEY(semantic_id, materialization_id, lineage_id)
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
    )
}

fn same_semantic_content(left: &NativeObservation, right: &NativeObservation) -> bool {
    left.semantic_id == right.semantic_id
        && left.source_kind == right.source_kind
        && left.capture_session == right.capture_session
        && left.native_id == right.native_id
        && left.observed_time == right.observed_time
        && left.trust == right.trust
        && left.fields == right.fields
}

fn valid_materialization_payload(
    payload: &[u8],
    canonical: &NativeObservation,
    materialization_id: &str,
    lineage_id: &str,
) -> Result<bool, StorageError> {
    if let Ok(marker) = serde_json::from_slice::<StoredMaterializationMarker>(payload) {
        return Ok(marker.schema_version == MATERIALIZATION_MARKER.schema_version);
    }
    let legacy: NativeObservation = serde_json::from_slice(payload)?;
    Ok(same_semantic_content(&legacy, canonical)
        && legacy.materialization_id.0 == materialization_id
        && legacy.lineage_id.0 == lineage_id)
}

fn table_count(connection: &Connection, table: &str) -> Result<usize, StorageError> {
    let query = match table {
        "observations" => "SELECT count(*) FROM observations",
        "materializations" => "SELECT count(*) FROM materializations",
        _ => unreachable!("table_count is only used with fixed internal table names"),
    };
    let count: i64 = connection.query_row(query, [], |row| row.get(0))?;
    usize::try_from(count).map_err(|_| StorageError::InvalidCount(count))
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
    pub materializations_inserted: usize,
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
    #[error("schema metadata must contain exactly one supported version row")]
    InvalidSchemaMetadata,
    #[error("repository schema is missing one or more required tables")]
    IncompleteSchema,
    #[error("semantic identity collision for {0}")]
    SemanticCollision(String),
    #[error(
        "materialization identity collision for semantic {semantic_id}, materialization {materialization_id}, lineage {lineage_id}"
    )]
    MaterializationCollision { semantic_id: String, materialization_id: String, lineage_id: String },
    #[error("invalid observation count {0}")]
    InvalidCount(i64),
    #[error("page size {0} is outside 1..=500")]
    InvalidPageSize(usize),
    #[error("stored semantic identity does not match its index key")]
    StoredIdentityMismatch,
    #[error("stored materialization identity does not match its index key")]
    StoredMaterializationIdentityMismatch,
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
        assert_eq!(
            first,
            PublishResult { inserted: 2, materializations_inserted: 2, replayed: false }
        );
        let replay = repository
            .publish_atomic("batch-1", &fixture.observations, &fixture.relations)
            .unwrap();
        assert_eq!(
            replay,
            PublishResult { inserted: 0, materializations_inserted: 0, replayed: true }
        );
        assert_eq!(repository.observation_count().unwrap(), 2);
        assert_eq!(repository.materialization_count().unwrap(), 2);
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
    fn same_semantics_accept_new_materializations_without_overwriting_canonical_content() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("store.sqlite3");
        let fixture = gate1_fixture();
        let mut repository = SqlCipherRepository::create(&path, [17; 32]).unwrap();
        repository.publish_atomic("original", &fixture.observations, &fixture.relations).unwrap();

        let rematerialized: Vec<_> = fixture
            .observations
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, mut observation)| {
                observation.materialization_id.0 = format!("bundle-materialization-{index}");
                observation.lineage_id.0 = format!("bundle-lineage-{index}");
                observation
            })
            .collect();
        let result =
            repository.publish_atomic("reimport", &rematerialized, &fixture.relations).unwrap();

        assert_eq!(
            result,
            PublishResult { inserted: 0, materializations_inserted: 2, replayed: false }
        );
        assert_eq!(repository.observation_count().unwrap(), 2);
        assert_eq!(repository.materialization_count().unwrap(), 4);
        assert_eq!(
            repository.observation(&fixture.observations[0].semantic_id).unwrap(),
            Some(fixture.observations[0].clone())
        );
        let materializations =
            repository.materializations(&fixture.observations[0].semantic_id).unwrap();
        assert_eq!(materializations.len(), 2);
        assert!(materializations.contains(&fixture.observations[0]));
        assert!(materializations.contains(&rematerialized[0]));
    }

    #[test]
    fn version_one_repository_migrates_and_backfills_materializations_atomically() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("store.sqlite3");
        let key = [18; 32];
        let fixture = gate1_fixture();
        let connection = Connection::open(&path).unwrap();
        connection.execute_batch(&format!("PRAGMA key = \"x'{}'\";", hex::encode(key))).unwrap();
        connection
            .execute_batch(
                "PRAGMA foreign_keys=ON;
                 CREATE TABLE schema_meta(version INTEGER NOT NULL);
                 INSERT INTO schema_meta(version) VALUES (1);
                 CREATE TABLE observations(
                   semantic_id TEXT PRIMARY KEY,
                   payload_json BLOB NOT NULL
                 ) WITHOUT ROWID;
                 CREATE TABLE relations(
                   from_id TEXT NOT NULL REFERENCES observations(semantic_id),
                   to_id TEXT NOT NULL REFERENCES observations(semantic_id),
                   payload_json BLOB NOT NULL,
                   PRIMARY KEY(from_id, to_id, payload_json)
                 ) WITHOUT ROWID;
                 CREATE TABLE committed_batches(batch_id TEXT PRIMARY KEY) WITHOUT ROWID;",
            )
            .unwrap();
        for observation in &fixture.observations {
            connection
                .execute(
                    "INSERT INTO observations(semantic_id,payload_json) VALUES (?1,?2)",
                    params![
                        observation.semantic_id.as_str(),
                        serde_json::to_vec(observation).unwrap()
                    ],
                )
                .unwrap();
        }
        drop(connection);

        let repository = SqlCipherRepository::open(&path, key).unwrap();
        assert_eq!(repository.observation_count().unwrap(), 2);
        assert_eq!(repository.materialization_count().unwrap(), 2);
        assert_eq!(
            repository.materializations(&fixture.observations[0].semantic_id).unwrap(),
            vec![fixture.observations[0].clone()]
        );
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

    #[test]
    fn damaged_current_schema_is_rejected_instead_of_silently_recreated() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("store.sqlite3");
        let key = [20; 32];
        drop(SqlCipherRepository::create(&path, key).unwrap());
        let connection = Connection::open(&path).unwrap();
        connection.execute_batch(&format!("PRAGMA key = \"x'{}'\";", hex::encode(key))).unwrap();
        connection.execute_batch("DROP TABLE materializations;").unwrap();
        drop(connection);

        assert!(matches!(
            SqlCipherRepository::open(&path, key),
            Err(StorageError::IncompleteSchema)
        ));
    }
}
