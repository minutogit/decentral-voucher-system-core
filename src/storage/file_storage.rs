//! # src/storage/file_storage.rs
//!
//! Eine Implementierung des `Storage`-Traits, die Daten in mehreren verschlüsselten
//! Dateien im Dateisystem speichert.

use super::{AuthMethod, Storage, StorageError};
use crate::models::conflict::{FingerprintStore, ProofStore};
use crate::models::profile::{BundleMetadataStore, UserIdentity, UserProfile, VoucherStore};
use crate::services::crypto_utils;
use argon2::Argon2;
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};

// --- Interne Konstanten und Strukturen ---

const SALT_SIZE: usize = 16;
const KEY_SIZE: usize = 32;
const PROFILE_FILE_NAME: &str = "profile.enc";
const VOUCHER_STORE_FILE_NAME: &str = "vouchers.enc";
const BUNDLE_META_FILE_NAME: &str = "bundles.meta.enc";
const FINGERPRINT_STORE_FILE_NAME: &str = "fingerprints.enc";
const PROOF_STORE_FILE_NAME: &str = "proofs.enc";

/// Container für das verschlüsselte Nutzerprofil, inklusive Key-Wrapping-Informationen.
#[derive(Serialize, Deserialize)]
struct ProfileStorageContainer {
    password_kdf_salt: [u8; SALT_SIZE],
    password_wrapped_key_with_nonce: Vec<u8>,
    mnemonic_kdf_salt: [u8; SALT_SIZE],
    mnemonic_wrapped_key_with_nonce: Vec<u8>,
    encrypted_profile_payload: Vec<u8>,
}

/// Bündelt das Profil und den privaten Schlüssel für die Speicherung.
#[derive(Serialize, Deserialize, Clone)]
struct ProfilePayload {
    profile: UserProfile,
    signing_key_bytes: Vec<u8>,
}

/// Container für den verschlüsselten Gutschein-Store.
#[derive(Serialize, Deserialize)]
struct VoucherStorageContainer {
    encrypted_store_payload: Vec<u8>,
}

/// Container für die verschlüsselten Bundle-Metadaten.
#[derive(Serialize, Deserialize)]
struct BundleMetadataContainer {
    encrypted_store_payload: Vec<u8>,
}

/// Container für den verschlüsselten Fingerprint-Store.
#[derive(Serialize, Deserialize)]
struct FingerprintStorageContainer {
    encrypted_store_payload: Vec<u8>,
}

/// Container für den verschlüsselten Proof-Store.
#[derive(Serialize, Deserialize)]
struct ProofStorageContainer {
    encrypted_store_payload: Vec<u8>,
}

// --- FileStorage Implementierung ---

/// Eine Implementierung des `Storage`-Traits, die Daten in verschlüsselten Dateien speichert.
pub struct FileStorage {
    /// Der Pfad zum Verzeichnis, das die Wallet-Dateien enthält.
    wallet_directory: PathBuf,
}

impl FileStorage {
    /// Erstellt eine neue `FileStorage`-Instanz für ein bestimmtes Verzeichnis.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        FileStorage {
            wallet_directory: path.into(),
        }
    }
}

impl Storage for FileStorage {
    fn profile_exists(&self) -> bool {
        self.wallet_directory.join(PROFILE_FILE_NAME).exists()
    }

    fn load_wallet(
        &self,
        auth: &AuthMethod,
    ) -> Result<(UserProfile, VoucherStore, UserIdentity), StorageError> {
        let profile_path = self.wallet_directory.join(PROFILE_FILE_NAME);
        let store_path = self.wallet_directory.join(VOUCHER_STORE_FILE_NAME);

        if !profile_path.exists() {
            return Err(StorageError::NotFound);
        }

        let profile_container_bytes = fs::read(profile_path)?;
        let profile_container: ProfileStorageContainer =
            serde_json::from_slice(&profile_container_bytes)
                .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

        // Entschlüssle den Master-Dateischlüssel basierend auf der Authentifizierungsmethode.
        let file_key_bytes = get_file_key(auth, &profile_container)?;
        let file_key: [u8; KEY_SIZE] = file_key_bytes
            .try_into()
            .map_err(|_| StorageError::InvalidFormat("Invalid file key length".to_string()))?;

        // Entschlüssele den Payload, der Profil und privaten Schlüssel enthält.
        let payload_bytes = crypto_utils::decrypt_data(&file_key, &profile_container.encrypted_profile_payload)
            .map_err(|e| StorageError::InvalidFormat(format!("Failed to decrypt profile payload: {}", e)))?;
        let payload: ProfilePayload = serde_json::from_slice(&payload_bytes)
            .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

        // Lade den VoucherStore.
        let store = if store_path.exists() {
            let store_container_bytes = fs::read(store_path)?;
            let store_container: VoucherStorageContainer =
                serde_json::from_slice(&store_container_bytes)
                    .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;
            let store_bytes = crypto_utils::decrypt_data(&file_key, &store_container.encrypted_store_payload)
                .map_err(|e| StorageError::InvalidFormat(format!("Failed to decrypt store: {}", e)))?;
            serde_json::from_slice(&store_bytes)
                .map_err(|e| StorageError::InvalidFormat(e.to_string()))?
        } else {
            VoucherStore::default()
        };

        // Rekonstruiere die UserIdentity.
        let signing_key_bytes: &[u8; 32] = payload
            .signing_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| StorageError::InvalidFormat("Invalid signing key length in storage".to_string()))?;
        let signing_key = SigningKey::from_bytes(signing_key_bytes);
        let public_key = signing_key.verifying_key();

        let identity = UserIdentity {
            signing_key,
            public_key,
            user_id: payload.profile.user_id.clone(),
        };

        Ok((payload.profile, store, identity))
    }

    fn save_wallet(
        &mut self,
        profile: &UserProfile,
        store: &VoucherStore,
        identity: &UserIdentity,
        password: &str,
    ) -> Result<(), StorageError> {
        fs::create_dir_all(&self.wallet_directory)?;
        let profile_path = self.wallet_directory.join(PROFILE_FILE_NAME);
        let store_path = self.wallet_directory.join(VOUCHER_STORE_FILE_NAME);

        let file_key: [u8; KEY_SIZE];
        let profile_container: ProfileStorageContainer;

        let payload = ProfilePayload {
            profile: profile.clone(),
            signing_key_bytes: identity.signing_key.to_bytes().to_vec(),
        };

        if !profile_path.exists() {
            // Erstmaliges Speichern: Generiere alle Schlüssel und Salze.
            let mut new_file_key = [0u8; KEY_SIZE];
            OsRng.fill_bytes(&mut new_file_key);
            file_key = new_file_key;

            let mut pw_salt = [0u8; SALT_SIZE];
            OsRng.fill_bytes(&mut pw_salt);
            let password_key = derive_key_from_password(password, &pw_salt)?;
            let pw_wrapped_key = crypto_utils::encrypt_data(&password_key, &file_key)
                .map_err(|e| StorageError::Generic(e.to_string()))?;

            let mut mn_salt = [0u8; SALT_SIZE];
            OsRng.fill_bytes(&mut mn_salt);
            let mnemonic_key = derive_key_from_signing_key(&identity.signing_key, &mn_salt)?;
            let mn_wrapped_key = crypto_utils::encrypt_data(&mnemonic_key, &file_key)
                .map_err(|e| StorageError::Generic(e.to_string()))?;

            let profile_payload = crypto_utils::encrypt_data(&file_key, &serde_json::to_vec(&payload).unwrap())
                .map_err(|e| StorageError::Generic(e.to_string()))?;

            profile_container = ProfileStorageContainer {
                password_kdf_salt: pw_salt,
                password_wrapped_key_with_nonce: pw_wrapped_key,
                mnemonic_kdf_salt: mn_salt,
                mnemonic_wrapped_key_with_nonce: mn_wrapped_key,
                encrypted_profile_payload: profile_payload,
            };
        } else {
            // Aktualisieren eines bestehenden Wallets: Lade Container, entschlüssele Schlüssel und verschlüssele neuen Payload.
            let existing_container_bytes = fs::read(&profile_path)?;
            let mut existing_container: ProfileStorageContainer =
                serde_json::from_slice(&existing_container_bytes)
                    .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

            let password_key =
                derive_key_from_password(password, &existing_container.password_kdf_salt)?;
            let decrypted_file_key = crypto_utils::decrypt_data(
                &password_key,
                &existing_container.password_wrapped_key_with_nonce,
            )
                .map_err(|_| StorageError::AuthenticationFailed)?;

            file_key = decrypted_file_key
                .try_into()
                .map_err(|_| StorageError::InvalidFormat("Invalid file key".to_string()))?;

            existing_container.encrypted_profile_payload =
                crypto_utils::encrypt_data(&file_key, &serde_json::to_vec(&payload).unwrap())
                    .map_err(|e| StorageError::Generic(e.to_string()))?;
            profile_container = existing_container;
        }

        // Speichere den VoucherStore.
        let store_payload = crypto_utils::encrypt_data(&file_key, &serde_json::to_vec(store).unwrap())
            .map_err(|e| StorageError::Generic(e.to_string()))?;
        let store_container = VoucherStorageContainer {
            encrypted_store_payload: store_payload,
        };

        // Atomares Schreiben über temporäre Dateien.
        let profile_tmp_path = self.wallet_directory.join(format!("{}.tmp", PROFILE_FILE_NAME));
        let store_tmp_path = self.wallet_directory.join(format!("{}.tmp", VOUCHER_STORE_FILE_NAME));

        fs::write(&profile_tmp_path, serde_json::to_vec(&profile_container).unwrap())?;
        fs::write(&store_tmp_path, serde_json::to_vec(&store_container).unwrap())?;

        fs::rename(&profile_tmp_path, &profile_path)?;
        fs::rename(&store_tmp_path, &store_path)?;

        Ok(())
    }

    fn reset_password(
        &mut self,
        identity: &UserIdentity,
        new_password: &str,
    ) -> Result<(), StorageError> {
        let profile_path = self.wallet_directory.join(PROFILE_FILE_NAME);
        if !profile_path.exists() {
            return Err(StorageError::NotFound);
        }

        let container_bytes = fs::read(&profile_path)?;
        let mut container: ProfileStorageContainer = serde_json::from_slice(&container_bytes)
            .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

        let mnemonic_key = derive_key_from_signing_key(&identity.signing_key, &container.mnemonic_kdf_salt)?;
        let file_key = crypto_utils::decrypt_data(
            &mnemonic_key,
            &container.mnemonic_wrapped_key_with_nonce,
        )
            .map_err(|_| StorageError::AuthenticationFailed)?;

        let mut new_pw_salt = [0u8; SALT_SIZE];
        OsRng.fill_bytes(&mut new_pw_salt);
        let new_password_key = derive_key_from_password(new_password, &new_pw_salt)?;
        let new_pw_wrapped_key = crypto_utils::encrypt_data(&new_password_key, &file_key)
            .map_err(|e| StorageError::Generic(e.to_string()))?;

        container.password_kdf_salt = new_pw_salt;
        container.password_wrapped_key_with_nonce = new_pw_wrapped_key;

        let profile_tmp_path = self.wallet_directory.join(format!("{}.tmp", PROFILE_FILE_NAME));
        fs::write(&profile_tmp_path, serde_json::to_vec(&container).unwrap())?;
        fs::rename(&profile_tmp_path, &profile_path)?;

        Ok(())
    }

    fn load_fingerprints(&self, _user_id: &str, auth: &AuthMethod) -> Result<FingerprintStore, StorageError> {
        let profile_path = self.wallet_directory.join(PROFILE_FILE_NAME);
        let fingerprint_path = self.wallet_directory.join(FINGERPRINT_STORE_FILE_NAME);

        if !profile_path.exists() {
            return Err(StorageError::NotFound);
        }

        if !fingerprint_path.exists() {
            return Ok(FingerprintStore::default());
        }

        let profile_container_bytes = fs::read(&profile_path)?;
        let profile_container: ProfileStorageContainer =
            serde_json::from_slice(&profile_container_bytes)
                .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

        let file_key_bytes = get_file_key(auth, &profile_container)?;
        let file_key: [u8; KEY_SIZE] = file_key_bytes
            .try_into()
            .map_err(|_| StorageError::InvalidFormat("Invalid file key length".to_string()))?;

        let fingerprint_container_bytes = fs::read(fingerprint_path)?;
        let fingerprint_container: FingerprintStorageContainer =
            serde_json::from_slice(&fingerprint_container_bytes)
                .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

        let store_bytes = crypto_utils::decrypt_data(&file_key, &fingerprint_container.encrypted_store_payload)
            .map_err(|e| StorageError::InvalidFormat(format!("Failed to decrypt fingerprint store: {}", e)))?;

        serde_json::from_slice(&store_bytes)
            .map_err(|e| StorageError::InvalidFormat(e.to_string()))
    }

    fn save_fingerprints(
        &mut self,
        _user_id: &str,
        password: &str,
        fingerprint_store: &FingerprintStore,
    ) -> Result<(), StorageError> {
        let profile_path = self.wallet_directory.join(PROFILE_FILE_NAME);
        let fingerprint_path = self.wallet_directory.join(FINGERPRINT_STORE_FILE_NAME);

        if !profile_path.exists() {
            return Err(StorageError::NotFound);
        }

        let profile_container_bytes = fs::read(profile_path)?;
        let profile_container: ProfileStorageContainer =
            serde_json::from_slice(&profile_container_bytes)
                .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

        let password_key =
            derive_key_from_password(password, &profile_container.password_kdf_salt)?;
        let file_key_bytes = crypto_utils::decrypt_data(
            &password_key,
            &profile_container.password_wrapped_key_with_nonce,
        ).map_err(|_| StorageError::AuthenticationFailed)?;

        let file_key: [u8; KEY_SIZE] = file_key_bytes
            .try_into()
            .map_err(|_| StorageError::InvalidFormat("Invalid file key length".to_string()))?;

        let store_payload = crypto_utils::encrypt_data(&file_key, &serde_json::to_vec(fingerprint_store).unwrap())
            .map_err(|e| StorageError::Generic(e.to_string()))?;
        let store_container = FingerprintStorageContainer {
            encrypted_store_payload: store_payload,
        };

        let store_tmp_path = self.wallet_directory.join(format!("{}.tmp", FINGERPRINT_STORE_FILE_NAME));
        fs::write(&store_tmp_path, serde_json::to_vec(&store_container).unwrap())?;
        fs::rename(&store_tmp_path, &fingerprint_path)?;

        Ok(())
    }

    fn load_bundle_metadata(
        &self,
        _user_id: &str,
        auth: &AuthMethod,
    ) -> Result<BundleMetadataStore, StorageError> {
        let profile_path = self.wallet_directory.join(PROFILE_FILE_NAME);
        let meta_path = self.wallet_directory.join(BUNDLE_META_FILE_NAME);

        if !profile_path.exists() {
            return Err(StorageError::NotFound);
        }

        if !meta_path.exists() {
            return Ok(BundleMetadataStore::default());
        }

        let profile_container_bytes = fs::read(&profile_path)?;
        let profile_container: ProfileStorageContainer =
            serde_json::from_slice(&profile_container_bytes)
                .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

        let file_key_bytes = get_file_key(auth, &profile_container)?;
        let file_key: [u8; KEY_SIZE] = file_key_bytes
            .try_into()
            .map_err(|_| StorageError::InvalidFormat("Invalid file key length".to_string()))?;

        let meta_container_bytes = fs::read(meta_path)?;
        let meta_container: BundleMetadataContainer =
            serde_json::from_slice(&meta_container_bytes)
                .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

        let store_bytes = crypto_utils::decrypt_data(&file_key, &meta_container.encrypted_store_payload)
            .map_err(|e| StorageError::InvalidFormat(format!("Failed to decrypt bundle metadata: {}", e)))?;

        serde_json::from_slice(&store_bytes)
            .map_err(|e| StorageError::InvalidFormat(e.to_string()))
    }

    fn save_bundle_metadata(
        &mut self,
        _user_id: &str,
        password: &str,
        metadata: &BundleMetadataStore,
    ) -> Result<(), StorageError> {
        let profile_path = self.wallet_directory.join(PROFILE_FILE_NAME);
        let meta_path = self.wallet_directory.join(BUNDLE_META_FILE_NAME);

        if !profile_path.exists() {
            return Err(StorageError::NotFound);
        }

        let profile_container_bytes = fs::read(profile_path)?;
        let profile_container: ProfileStorageContainer =
            serde_json::from_slice(&profile_container_bytes)
                .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

        let password_key =
            derive_key_from_password(password, &profile_container.password_kdf_salt)?;
        let file_key_bytes = crypto_utils::decrypt_data(
            &password_key,
            &profile_container.password_wrapped_key_with_nonce,
        ).map_err(|_| StorageError::AuthenticationFailed)?;

        let file_key: [u8; KEY_SIZE] = file_key_bytes
            .try_into()
            .map_err(|_| StorageError::InvalidFormat("Invalid file key length".to_string()))?;

        let store_payload = crypto_utils::encrypt_data(&file_key, &serde_json::to_vec(metadata).unwrap())
            .map_err(|e| StorageError::Generic(e.to_string()))?;
        let store_container = BundleMetadataContainer {
            encrypted_store_payload: store_payload,
        };

        let store_tmp_path = self.wallet_directory.join(format!("{}.tmp", BUNDLE_META_FILE_NAME));
        fs::write(&store_tmp_path, serde_json::to_vec(&store_container).unwrap())?;
        fs::rename(&store_tmp_path, &meta_path)?;

        Ok(())
    }

    fn load_proofs(&self, _user_id: &str, auth: &AuthMethod) -> Result<ProofStore, StorageError> {
        let profile_path = self.wallet_directory.join(PROFILE_FILE_NAME);
        let proof_path = self.wallet_directory.join(PROOF_STORE_FILE_NAME);

        if !profile_path.exists() {
            return Err(StorageError::NotFound);
        }

        if !proof_path.exists() {
            return Ok(ProofStore::default());
        }

        let profile_container_bytes = fs::read(&profile_path)?;
        let profile_container: ProfileStorageContainer =
            serde_json::from_slice(&profile_container_bytes)
                .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

        let file_key_bytes = get_file_key(auth, &profile_container)?;
        let file_key: [u8; KEY_SIZE] = file_key_bytes
            .try_into()
            .map_err(|_| StorageError::InvalidFormat("Invalid file key length".to_string()))?;

        let proof_container_bytes = fs::read(proof_path)?;
        let proof_container: ProofStorageContainer =
            serde_json::from_slice(&proof_container_bytes)
                .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

        let store_bytes = crypto_utils::decrypt_data(&file_key, &proof_container.encrypted_store_payload)
            .map_err(|e| StorageError::InvalidFormat(format!("Failed to decrypt proof store: {}", e)))?;

        serde_json::from_slice(&store_bytes)
            .map_err(|e| StorageError::InvalidFormat(e.to_string()))
    }

    fn save_proofs(
        &mut self,
        _user_id: &str,
        password: &str,
        proof_store: &ProofStore,
    ) -> Result<(), StorageError> {
        let profile_path = self.wallet_directory.join(PROFILE_FILE_NAME);
        let proof_path = self.wallet_directory.join(PROOF_STORE_FILE_NAME);

        if !profile_path.exists() {
            return Err(StorageError::NotFound);
        }

        let profile_container_bytes = fs::read(profile_path)?;
        let profile_container: ProfileStorageContainer =
            serde_json::from_slice(&profile_container_bytes)
                .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

        let password_key =
            derive_key_from_password(password, &profile_container.password_kdf_salt)?;
        let file_key_bytes = crypto_utils::decrypt_data(
            &password_key,
            &profile_container.password_wrapped_key_with_nonce,
        ).map_err(|_| StorageError::AuthenticationFailed)?;

        let file_key: [u8; KEY_SIZE] = file_key_bytes
            .try_into()
            .map_err(|_| StorageError::InvalidFormat("Invalid file key length".to_string()))?;

        if proof_store.proofs.is_empty() {
            if proof_path.exists() {
                fs::remove_file(proof_path)?;
            }
            return Ok(());
        }

        let store_payload = crypto_utils::encrypt_data(&file_key, &serde_json::to_vec(proof_store).unwrap())
            .map_err(|e| StorageError::Generic(e.to_string()))?;
        let store_container = ProofStorageContainer {
            encrypted_store_payload: store_payload,
        };

        let store_tmp_path = self.wallet_directory.join(format!("{}.tmp", PROOF_STORE_FILE_NAME));
        fs::write(&store_tmp_path, serde_json::to_vec(&store_container).unwrap())?;
        fs::rename(&store_tmp_path, &proof_path)?;

        Ok(())
    }
}

// --- Private Hilfsfunktionen ---

/// Entschlüsselt den Master-Dateischlüssel (`file_key`) basierend auf der Authentifizierungsmethode.
fn get_file_key(
    auth: &AuthMethod,
    container: &ProfileStorageContainer,
) -> Result<Vec<u8>, StorageError> {
    match auth {
        AuthMethod::Password(password) => {
            let password_key =
                derive_key_from_password(password, &container.password_kdf_salt)?;
            crypto_utils::decrypt_data(
                &password_key,
                &container.password_wrapped_key_with_nonce,
            )
                .map_err(|_| StorageError::AuthenticationFailed)
        }
        AuthMethod::Mnemonic(mnemonic) => {
            let (_, signing_key) =
                crypto_utils::derive_ed25519_keypair(mnemonic, None)
                    .map_err(|e| StorageError::Generic(format!("Key derivation from mnemonic failed: {}", e)))?;
            let mnemonic_key =
                derive_key_from_signing_key(&signing_key, &container.mnemonic_kdf_salt)?;
            crypto_utils::decrypt_data(
                &mnemonic_key,
                &container.mnemonic_wrapped_key_with_nonce,
            )
                .map_err(|_| StorageError::AuthenticationFailed)
        }
        AuthMethod::RecoveryIdentity(identity) => {
            let mnemonic_key =
                derive_key_from_signing_key(&identity.signing_key, &container.mnemonic_kdf_salt)?;
            crypto_utils::decrypt_data(
                &mnemonic_key,
                &container.mnemonic_wrapped_key_with_nonce,
            )
                .map_err(|_| StorageError::AuthenticationFailed)
        }
    }
}

/// Leitet einen kryptographischen Schlüssel aus einem Passwort und Salt ab.
fn derive_key_from_password(
    password: &str,
    salt: &[u8; SALT_SIZE],
) -> Result<[u8; KEY_SIZE], StorageError> {
    let mut key = [0u8; KEY_SIZE];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| StorageError::Generic(format!("Password key derivation failed: {}", e)))?;
    Ok(key)
}

/// Leitet einen kryptographischen Schlüssel aus dem privaten Schlüssel der Identität ab.
fn derive_key_from_signing_key(
    signing_key: &SigningKey,
    salt: &[u8; SALT_SIZE],
) -> Result<[u8; KEY_SIZE], StorageError> {
    let mut key = [0u8; KEY_SIZE];
    Argon2::default()
        .hash_password_into(signing_key.to_bytes().as_ref(), salt, &mut key)
        .map_err(|e| StorageError::Generic(format!("Identity key derivation failed: {}", e)))?;
    Ok(key)
}