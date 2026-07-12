//! Per-investigation data-key wrapping and macOS Keychain lifecycle controls.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use security_framework::{
    access_control::{ProtectionMode, SecAccessControl},
    passwords::{
        delete_generic_password_options, generic_password, set_generic_password_options,
        PasswordOptions,
    },
};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

pub const KEY_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 12;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WrappedInvestigationKey {
    pub wrapping_key_version: u32,
    pub nonce: [u8; NONCE_BYTES],
    pub ciphertext: Vec<u8>,
}

impl WrappedInvestigationKey {
    pub fn wrap(
        investigation_id: &str,
        wrapping_key_version: u32,
        wrapping_key: &[u8; KEY_BYTES],
        investigation_key: &[u8; KEY_BYTES],
    ) -> Result<Self, KeyLifecycleError> {
        let cipher =
            Aes256Gcm::new_from_slice(wrapping_key).map_err(|_| KeyLifecycleError::Crypto)?;
        let mut nonce = [0_u8; NONCE_BYTES];
        rand::rng().fill_bytes(&mut nonce);
        let aad = associated_data(investigation_id, wrapping_key_version);
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: investigation_key, aad: &aad })
            .map_err(|_| KeyLifecycleError::Crypto)?;
        Ok(Self { wrapping_key_version, nonce, ciphertext })
    }

    pub fn unwrap(
        &self,
        investigation_id: &str,
        wrapping_key: &[u8; KEY_BYTES],
    ) -> Result<Zeroizing<[u8; KEY_BYTES]>, KeyLifecycleError> {
        let cipher =
            Aes256Gcm::new_from_slice(wrapping_key).map_err(|_| KeyLifecycleError::Crypto)?;
        let aad = associated_data(investigation_id, self.wrapping_key_version);
        let mut plaintext = cipher
            .decrypt(Nonce::from_slice(&self.nonce), Payload { msg: &self.ciphertext, aad: &aad })
            .map_err(|_| KeyLifecycleError::Authentication)?;
        if plaintext.len() != KEY_BYTES {
            plaintext.zeroize();
            return Err(KeyLifecycleError::InvalidKeyLength(plaintext.len()));
        }
        let mut key = [0_u8; KEY_BYTES];
        key.copy_from_slice(&plaintext);
        plaintext.zeroize();
        Ok(Zeroizing::new(key))
    }
}

pub struct MacKeychainWrappingKeyStore {
    service: String,
}

impl MacKeychainWrappingKeyStore {
    #[must_use]
    pub fn new(service: impl Into<String>) -> Self {
        Self { service: service.into() }
    }

    pub fn create(&self, version: u32) -> Result<Zeroizing<[u8; KEY_BYTES]>, KeyLifecycleError> {
        let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
        rand::rng().fill_bytes(key.as_mut());
        let options = self.options(version)?;
        set_generic_password_options(key.as_ref(), options)?;
        Ok(key)
    }

    pub fn load(&self, version: u32) -> Result<Zeroizing<[u8; KEY_BYTES]>, KeyLifecycleError> {
        let mut bytes = generic_password(self.options(version)?)?;
        if bytes.len() != KEY_BYTES {
            let len = bytes.len();
            bytes.zeroize();
            return Err(KeyLifecycleError::InvalidKeyLength(len));
        }
        let mut key = [0_u8; KEY_BYTES];
        key.copy_from_slice(&bytes);
        bytes.zeroize();
        Ok(Zeroizing::new(key))
    }

    pub fn delete(&self, version: u32) -> Result<(), KeyLifecycleError> {
        delete_generic_password_options(self.options(version)?)?;
        Ok(())
    }

    fn options(&self, version: u32) -> Result<PasswordOptions, KeyLifecycleError> {
        let mut options = PasswordOptions::new_generic_password(&self.service, &account(version));
        options.use_protected_keychain();
        options.set_access_synchronized(Some(false));
        options.set_access_control(SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            0,
        )?);
        options.set_label("Project Glassbox application wrapping key");
        options.set_description(
            "Non-synchronizing, versioned key used only to wrap investigation keys",
        );
        Ok(options)
    }
}

pub fn generate_investigation_key() -> Zeroizing<[u8; KEY_BYTES]> {
    let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
    rand::rng().fill_bytes(key.as_mut());
    key
}

fn account(version: u32) -> String {
    format!("application-wrapping-key-v{version}")
}

fn associated_data(investigation_id: &str, version: u32) -> Vec<u8> {
    format!("glassbox/investigation-key/v1\0{investigation_id}\0{version}").into_bytes()
}

#[derive(Debug, Error)]
pub enum KeyLifecycleError {
    #[error("keychain operation failed: {0}")]
    Keychain(#[from] security_framework::base::Error),
    #[error("invalid key length: {0}")]
    InvalidKeyLength(usize),
    #[error("key wrapping operation failed")]
    Crypto,
    #[error("wrapped key authentication failed")]
    Authentication,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_is_bound_to_investigation_and_version() {
        let wrapping_key = [7_u8; KEY_BYTES];
        let investigation_key = [9_u8; KEY_BYTES];
        let wrapped =
            WrappedInvestigationKey::wrap("inv-a", 3, &wrapping_key, &investigation_key).unwrap();
        assert_eq!(*wrapped.unwrap("inv-a", &wrapping_key).unwrap(), investigation_key);
        assert!(matches!(
            wrapped.unwrap("inv-b", &wrapping_key),
            Err(KeyLifecycleError::Authentication)
        ));
        assert!(!wrapped.ciphertext.windows(KEY_BYTES).any(|window| window == investigation_key));
    }

    #[test]
    fn wrong_wrapping_key_is_rejected() {
        let wrapped =
            WrappedInvestigationKey::wrap("inv", 1, &[1; KEY_BYTES], &[2; KEY_BYTES]).unwrap();
        assert!(matches!(
            wrapped.unwrap("inv", &[3; KEY_BYTES]),
            Err(KeyLifecycleError::Authentication)
        ));
    }
}
