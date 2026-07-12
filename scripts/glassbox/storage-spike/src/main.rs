use rusqlite::{Connection, OpenFlags};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::Instant;

const KEY: [u8; 32] = [0x42; 32];
const WRONG_KEY: [u8; 32] = [0x24; 32];
const SECRET: &str = "glassbox-seeded-secret-never-plaintext";

fn key_pragma(key: &[u8; 32]) -> String {
    format!("PRAGMA key = \"x'{}'\";", hex::encode(key))
}

fn open_keyed(path: &Path, key: &[u8; 32]) -> rusqlite::Result<Connection> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
    )?;
    conn.execute_batch(&key_pragma(key))?;
    Ok(conn)
}

fn contains(path: &Path, needle: &[u8]) -> bool {
    fs::read(path)
        .map(|bytes| bytes.windows(needle.len()).any(|window| window == needle))
        .unwrap_or(false)
}

fn sha256(path: &Path) -> Option<String> {
    fs::read(path).ok().map(|bytes| format!("{:x}", Sha256::digest(bytes)))
}

fn crash_child(path: &Path) -> ! {
    let mut conn = open_keyed(path, &KEY).expect("open crash fixture");
    let tx = conn.transaction().expect("begin crash transaction");
    tx.execute("INSERT INTO probe(value) VALUES (?1)", ["uncommitted-crash-secret"])
        .expect("insert crash fixture");
    std::process::abort();
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.get(1).map(String::as_str) == Some("--crash-child") {
        crash_child(Path::new(args.get(2).expect("database path")));
    }
    match run() {
        Ok(receipt) => {
            println!("{}", serde_json::to_string_pretty(&receipt).unwrap());
            ExitCode::SUCCESS
        }
        Err(error) => {
            println!("{}", json!({"technical_ok":false,"error":error}));
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<serde_json::Value, String> {
    let temp = tempfile::Builder::new()
        .prefix("glassbox-storage-spike-")
        .tempdir()
        .map_err(|e| e.to_string())?;
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))
        .map_err(|e| e.to_string())?;
    let path = temp.path().join("investigation.sqlite3");
    let mut conn = open_keyed(&path, &KEY).map_err(|e| e.to_string())?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    let cipher_version: String = conn
        .query_row("PRAGMA cipher_version", [], |row| row.get(0))
        .map_err(|e| format!("SQLCipher unavailable: {e}"))?;
    let compile_options: Vec<String> = conn
        .prepare("PRAGMA compile_options")
        .and_then(|mut stmt| stmt.query_map([], |row| row.get(0))?.collect())
        .map_err(|e| e.to_string())?;
    let temp_store_memory = compile_options.iter().any(|item| item == "TEMP_STORE=2");
    conn.execute_batch(
        "PRAGMA temp_store=MEMORY;
         PRAGMA secure_delete=ON;
         PRAGMA wal_autocheckpoint=0;
         PRAGMA journal_mode=WAL;
         CREATE TABLE probe(id INTEGER PRIMARY KEY, value TEXT NOT NULL);",
    )
    .map_err(|e| e.to_string())?;
    let start = Instant::now();
    {
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        for index in 0..10_000 {
            tx.execute("INSERT INTO probe(value) VALUES (?1)", [format!("{SECRET}-{index}")])
                .map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())?;
    }
    let insert_10k_ms = start.elapsed().as_millis();
    let wal = PathBuf::from(format!("{}-wal", path.display()));
    let shm = PathBuf::from(format!("{}-shm", path.display()));
    let plaintext_absent =
        [&path, &wal, &shm].iter().all(|item| !contains(item, SECRET.as_bytes()));
    let file_evidence = [&path, &wal, &shm]
        .iter()
        .map(|item| json!({"path_suffix":item.file_name().unwrap().to_string_lossy(),"exists":item.exists(),"sha256":sha256(item)}))
        .collect::<Vec<_>>();
    drop(conn);

    let reopened = open_keyed(&path, &KEY).map_err(|e| e.to_string())?;
    let correct_key_count: i64 = reopened
        .query_row("SELECT count(*) FROM probe", [], |row| row.get(0))
        .map_err(|e| e.to_string())?;
    drop(reopened);
    let wrong_key_rejected = open_keyed(&path, &WRONG_KEY)
        .and_then(|conn| {
            conn.query_row("SELECT count(*) FROM probe", [], |row| row.get::<_, i64>(0))
        })
        .is_err();
    let missing_key_rejected = Connection::open(&path)
        .and_then(|conn| {
            conn.query_row("SELECT count(*) FROM probe", [], |row| row.get::<_, i64>(0))
        })
        .is_err();

    let crash_status = Command::new(env::current_exe().map_err(|e| e.to_string())?)
        .arg("--crash-child")
        .arg(&path)
        .status()
        .map_err(|e| e.to_string())?;
    let recovered = open_keyed(&path, &KEY).map_err(|e| e.to_string())?;
    let crash_rows: i64 = recovered
        .query_row("SELECT count(*) FROM probe WHERE value='uncommitted-crash-secret'", [], |row| {
            row.get(0)
        })
        .map_err(|e| e.to_string())?;
    let integrity: String = recovered
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|e| e.to_string())?;

    let db_mode = fs::metadata(&path).map_err(|e| e.to_string())?.mode() & 0o777;
    let dir_mode = fs::metadata(temp.path()).map_err(|e| e.to_string())?.mode() & 0o777;
    let sandbox_expected = env::var_os("GLASSBOX_EXPECT_SANDBOX").is_some();
    let sandbox_home_write_denied = if sandbox_expected {
        let forbidden = PathBuf::from(
            env::var_os("GLASSBOX_FORBIDDEN_HOME")
                .or_else(|| env::var_os("HOME"))
                .ok_or("home path missing")?,
        )
        .join(format!(".glassbox-sandbox-deny-{}", std::process::id()));
        match fs::write(&forbidden, b"must be denied") {
            Ok(()) => {
                let _ = fs::remove_file(forbidden);
                false
            }
            Err(error) => error.kind() == std::io::ErrorKind::PermissionDenied,
        }
    } else {
        false
    };
    let technical_ok = temp_store_memory
        && plaintext_absent
        && correct_key_count == 10_000
        && wrong_key_rejected
        && missing_key_rejected
        && !crash_status.success()
        && crash_rows == 0
        && integrity == "ok"
        && db_mode == 0o600
        && dir_mode == 0o700
        && insert_10k_ms < 10_000;
    Ok(json!({
        "schema_version":"glassbox-storage-spike-technical/v1",
        "technical_ok":technical_ok,
        "candidate":"SQLCipher Community Edition via rusqlite bundled-sqlcipher-vendored-openssl",
        "cipher_version":cipher_version,
        "compile_temp_store_2":temp_store_memory,
        "journal_mode":"wal",
        "plaintext_absent_from_db_wal_shm":plaintext_absent,
        "correct_key_count":correct_key_count,
        "wrong_key_rejected":wrong_key_rejected,
        "missing_key_rejected":missing_key_rejected,
        "crash_process_failed":!crash_status.success(),
        "uncommitted_rows_after_crash":crash_rows,
        "integrity_check":integrity,
        "insert_10k_ms":insert_10k_ms,
        "database_mode":format!("{db_mode:o}"),
        "directory_mode":format!("{dir_mode:o}"),
        "sandbox_expected":sandbox_expected,
        "sandbox_home_write_denied":sandbox_home_write_denied,
        "files":file_evidence
    }))
}
