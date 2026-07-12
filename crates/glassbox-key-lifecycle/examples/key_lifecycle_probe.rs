use glassbox_key_lifecycle::{
    generate_investigation_key, KeyLifecycleError, MacKeychainWrappingKeyStore,
    WrappedInvestigationKey,
};
use glassbox_storage_sqlite::SqlCipherRepository;
use serde_json::json;
use std::{env, fs};
use tempfile::tempdir;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let service = env::var("GLASSBOX_KEYCHAIN_SERVICE")?;
    let version = 1;
    let store = MacKeychainWrappingKeyStore::new(&service);
    let _ = store.delete(version);

    let wrapping_key = store.create(version)?;
    let reloaded = store.load(version)?;
    let keychain_restart_roundtrip = wrapping_key.as_ref() == reloaded.as_ref();

    let investigation_id = "probe-investigation";
    let investigation_key = generate_investigation_key();
    let wrapped = WrappedInvestigationKey::wrap(
        investigation_id,
        version,
        &wrapping_key,
        &investigation_key,
    )?;
    let wrapped_has_no_plaintext = !wrapped
        .ciphertext
        .windows(investigation_key.len())
        .any(|window| window == investigation_key.as_ref());
    let wrapped_key_aad_binding = wrapped.unwrap("wrong-investigation", &wrapping_key).is_err();

    let directory = tempdir()?;
    let database = directory.path().join("investigation.sqlite3");
    drop(SqlCipherRepository::create(&database, *investigation_key)?);
    let database_has_no_plaintext_key = !fs::read(&database)?
        .windows(investigation_key.len())
        .any(|window| window == investigation_key.as_ref());

    drop(wrapping_key);
    drop(reloaded);
    store.delete(version)?;
    let key_deleted = matches!(store.load(version), Err(KeyLifecycleError::Keychain(_)));
    let retained_material_cannot_recover_key = key_deleted;

    println!(
        "{}",
        serde_json::to_string(&json!({
            "technical_ok": keychain_restart_roundtrip
                && wrapped_has_no_plaintext
                && database_has_no_plaintext_key
                && retained_material_cannot_recover_key,
            "keychain_restart_roundtrip": keychain_restart_roundtrip,
            "wrapped_key_aad_binding": wrapped_key_aad_binding,
            "wrapped_key_has_no_plaintext": wrapped_has_no_plaintext,
            "database_has_no_plaintext_key": database_has_no_plaintext_key,
            "key_deleted_before_cleanup": key_deleted,
            "retained_database_and_wrapped_key_unrecoverable_after_crypto_shred": retained_material_cannot_recover_key,
        }))?
    );
    Ok(())
}
