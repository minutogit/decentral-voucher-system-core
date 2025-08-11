//! # src/services/profile_manager.rs
//!
//! Enthält die Logik zur Verwaltung eines `UserProfile`, insbesondere für
//! die sichere Persistenz und den Austausch von Gutscheinen mittels des `secure_container_manager`.

use crate::error::VoucherCoreError;
use crate::models::profile::{TransactionBundle, TransactionDirection, UserIdentity, UserProfile};
use crate::models::secure_container::{PayloadType, SecureContainer};
use crate::models::voucher::Voucher;
use crate::services::crypto_utils::{
    self, create_user_id, get_hash, get_pubkey_from_user_id, sign_ed25519, verify_ed25519,
};
use crate::services::secure_container_manager::{
    create_secure_container, open_secure_container, ContainerManagerError,
};
use crate::services::utils::{get_current_timestamp, to_canonical_json};
use crate::services::voucher_validation::ValidationError;
use argon2::Argon2;
use ed25519_dalek::Signature;
use rand_core::{OsRng, RngCore};
use std::fs;

// Konstanten für die Persistenz
const SALT_SIZE: usize = 16;
const KEY_SIZE: usize = 32;

/// Definiert die Fehler, die im `profile_manager`-Modul auftreten können.
#[derive(Debug, thiserror::Error)]
pub enum ProfileManagerError {
    #[error("Failed to derive key from password using Argon2: {0}")]
    KeyDerivation(String),

    #[error("I/O Error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid profile file format or length.")]
    InvalidFileFormat,

    // Der `Serialization`-Fehler wird nicht mehr benötigt, da `VoucherCoreError`
    // bereits `serde_json::Error` verarbeiten kann.
    #[error("Sender ID in bundle did not match. Expected: {expected}, Found: {found}")]
    SenderIdMismatch { expected: String, found: String },

    #[error("The digital signature of the transaction bundle is invalid.")]
    InvalidBundleSignature,
}

/// Serialisiert und verschlüsselt ein `UserProfile`-Objekt und speichert es in einer Datei.
pub fn save_profile_encrypted(
    profile: &UserProfile,
    path: &std::path::Path,
    password: &str,
) -> Result<(), VoucherCoreError> {
    // Wir verwenden JSON für die Persistenz, da es robust ist.
    let serialized_profile = serde_json::to_vec(profile)?;

    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);

    let mut key = [0u8; KEY_SIZE];
    Argon2::default()
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .map_err(|e| ProfileManagerError::KeyDerivation(e.to_string()))?;

    let encrypted_data_with_nonce = crypto_utils::encrypt_data(&key, &serialized_profile)?;

    let mut final_data = Vec::with_capacity(SALT_SIZE + encrypted_data_with_nonce.len());
    final_data.extend_from_slice(&salt);
    final_data.extend_from_slice(&encrypted_data_with_nonce);

    fs::write(path, final_data).map_err(ProfileManagerError::from)?;

    Ok(())
}

/// Liest eine verschlüsselte Profildatei, entschlüsselt sie und deserialisiert sie zu einem `UserProfile`.
pub fn load_profile_encrypted(
    path: &std::path::Path,
    password: &str,
) -> Result<UserProfile, VoucherCoreError> {
    let encrypted_file_content = fs::read(path).map_err(ProfileManagerError::from)?;

    if encrypted_file_content.len() < SALT_SIZE {
        return Err(ProfileManagerError::InvalidFileFormat.into());
    }
    let (salt_bytes, encrypted_data_with_nonce) =
        encrypted_file_content.split_at(SALT_SIZE);

    let mut key = [0u8; KEY_SIZE];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt_bytes, &mut key)
        .map_err(|e| ProfileManagerError::KeyDerivation(e.to_string()))?;

    let decrypted_data = crypto_utils::decrypt_data(&key, encrypted_data_with_nonce)?;

    let profile: UserProfile = serde_json::from_slice(&decrypted_data)?;

    Ok(profile)
}

/// Erstellt ein neues Nutzerprofil samt Identität aus einer Mnemonic-Phrase.
pub fn create_profile_from_mnemonic(
    mnemonic_phrase: &str,
    user_prefix: Option<&str>,
) -> Result<(UserProfile, UserIdentity), VoucherCoreError> {
    let (public_key, signing_key) = crate::services::crypto_utils::derive_ed25519_keypair(mnemonic_phrase, None);
    let user_id =
        create_user_id(&public_key, user_prefix).map_err(|e| VoucherCoreError::Crypto(e.to_string()))?;

    let identity = UserIdentity {
        signing_key,
        public_key,
        user_id: user_id.clone(),
    };

    let profile = UserProfile {
        user_id,
        vouchers: Default::default(),
        bundle_history: Default::default(),
    };

    Ok((profile, identity))
}

/// Fügt einen Gutschein zu einem Profil hinzu.
pub fn add_voucher_to_profile(
    profile: &mut UserProfile,
    voucher: Voucher,
) -> Result<(), ProfileManagerError> {
    profile.vouchers.insert(voucher.voucher_id.clone(), voucher);
    Ok(())
}

/// Erstellt ein `TransactionBundle`, verpackt es in einen `SecureContainer` und serialisiert diesen.
pub fn create_and_encrypt_transaction_bundle(
    sender_profile: &mut UserProfile,
    sender_identity: &UserIdentity,
    vouchers: Vec<Voucher>,
    recipient_id: &str,
    notes: Option<String>,
) -> Result<Vec<u8>, VoucherCoreError> {
    // 1. Das innere Transaktionsbündel erstellen und signieren.
    let mut bundle = TransactionBundle {
        bundle_id: "".to_string(),
        sender_id: sender_identity.user_id.clone(),
        recipient_id: recipient_id.to_string(),
        vouchers: vouchers.clone(),
        timestamp: get_current_timestamp(),
        notes,
        sender_signature: "".to_string(),
    };

    let bundle_json_for_id = to_canonical_json(&bundle)?;
    bundle.bundle_id = get_hash(bundle_json_for_id);

    let signature = sign_ed25519(&sender_identity.signing_key, bundle.bundle_id.as_bytes());
    bundle.sender_signature = bs58::encode(signature.to_bytes()).into_string();
    let signed_bundle_bytes = serde_json::to_vec(&bundle)?;

    // 2. Das signierte Bündel als Payload in einen `SecureContainer` verpacken.
    let secure_container = create_secure_container(
        sender_identity,
        &[recipient_id.to_string()],
        &signed_bundle_bytes,
        PayloadType::TransactionBundle,
    )?;

    // 3. Den Container zum Transport serialisieren und das Sender-Profil aktualisieren.
    let container_bytes = serde_json::to_vec(&secure_container)?;

    let header = bundle.to_header(TransactionDirection::Sent);
    sender_profile
        .bundle_history
        .insert(header.bundle_id.clone(), header);

    for v in vouchers {
        sender_profile.vouchers.remove(&v.voucher_id);
    }

    Ok(container_bytes)
}

/// Verarbeitet einen serialisierten `SecureContainer`, der ein `TransactionBundle` enthält.
pub fn process_encrypted_transaction_bundle(
    recipient_profile: &mut UserProfile,
    recipient_identity: &UserIdentity,
    container_bytes: &[u8],
) -> Result<(), VoucherCoreError> {
    // 1. Den äußeren Container deserialisieren.
    let container: SecureContainer = serde_json::from_slice(container_bytes)?;

    // 2. Den Container mit der zentralen Funktion öffnen und entschlüsseln.
    // Diese Funktion übernimmt die Signaturprüfung des Containers.
    let (decrypted_bundle_bytes, payload_type) =
        open_secure_container(&container, recipient_identity)?;

    // 3. Sicherstellen, dass der Payload-Typ korrekt ist.
    if payload_type != PayloadType::TransactionBundle {
        return Err(VoucherCoreError::Container(ContainerManagerError::NotAnIntendedRecipient)); // Simplification
    }

    // 4. Das innere TransactionBundle deserialisieren und dessen eigene Signatur verifizieren.
    let bundle: TransactionBundle = serde_json::from_slice(&decrypted_bundle_bytes)?;
    let sender_pubkey_ed = get_pubkey_from_user_id(&bundle.sender_id)?;

    // Verifiziere die *innere* Signatur des Bündels selbst.
    let signature_bytes = bs58::decode(&bundle.sender_signature)
        .into_vec()
        .map_err(|e| {
            VoucherCoreError::Validation(ValidationError::SignatureDecodeError(e.to_string()))
        })?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|e| {
        VoucherCoreError::Validation(ValidationError::SignatureDecodeError(e.to_string()))
    })?;

    if !verify_ed25519(
        &sender_pubkey_ed,
        bundle.bundle_id.as_bytes(),
        &signature,
    ) {
        return Err(ProfileManagerError::InvalidBundleSignature.into());
    }

    // 5. Bei Erfolg: Gutscheine und Historie im Profil des Empfängers aktualisieren.
    for voucher in bundle.vouchers.clone() {
        add_voucher_to_profile(recipient_profile, voucher)?;
    }

    let header = bundle.to_header(TransactionDirection::Received);
    recipient_profile
        .bundle_history
        .insert(header.bundle_id.clone(), header);

    Ok(())
}