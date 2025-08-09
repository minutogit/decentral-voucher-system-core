//! # src/services/profile_manager.rs
//!
//! Enthält die Logik zur Verwaltung eines `UserProfile`, insbesondere für
//! die sichere Persistenz und den Austausch von Gutscheinen.

use crate::error::VoucherCoreError;
use crate::models::profile::{TransactionBundle, TransactionDirection, UserIdentity, UserProfile};
use crate::models::voucher::Voucher;
use crate::services::crypto_utils::{
    create_user_id, decrypt_data, ed25519_pub_to_x25519,
    ed25519_sk_to_x25519_sk, encrypt_data, get_hash, get_pubkey_from_user_id, sign_ed25519,
    verify_ed25519,
};
use crate::services::utils::{get_current_timestamp, to_canonical_json};
use crate::services::voucher_validation::ValidationError;
use argon2::Argon2;
use ed25519_dalek::Signature;
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use std::fs;
use std::path::Path;

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
    path: &Path,
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

    let encrypted_data_with_nonce = encrypt_data(&key, &serialized_profile)?;

    let mut final_data = Vec::with_capacity(SALT_SIZE + encrypted_data_with_nonce.len());
    final_data.extend_from_slice(&salt);
    final_data.extend_from_slice(&encrypted_data_with_nonce);

    fs::write(path, final_data).map_err(ProfileManagerError::from)?;

    Ok(())
}

/// Liest eine verschlüsselte Profildatei, entschlüsselt sie und deserialisiert sie zu einem `UserProfile`.
pub fn load_profile_encrypted(
    path: &Path,
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

    let decrypted_data = decrypt_data(&key, encrypted_data_with_nonce)?;

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

/// Erstellt, signiert und verschlüsselt ein Transaktionsbündel für einen Empfänger.
pub fn create_and_encrypt_transaction_bundle(
    sender_profile: &mut UserProfile,
    sender_identity: &UserIdentity,
    vouchers: Vec<Voucher>,
    recipient_id: &str,
    notes: Option<String>,
) -> Result<Vec<u8>, VoucherCoreError> {
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

    let recipient_pubkey_ed =
        get_pubkey_from_user_id(recipient_id).map_err(|e| VoucherCoreError::Crypto(e.to_string()))?;
    let recipient_pubkey_x = ed25519_pub_to_x25519(&recipient_pubkey_ed);
    let sender_secret_x = ed25519_sk_to_x25519_sk(&sender_identity.signing_key);

    let shared_secret = sender_secret_x.diffie_hellman(&recipient_pubkey_x);

    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut key = [0u8; 32];
    hkdf.expand(b"voucher-bundle-key", &mut key).unwrap();

    // Serialisiere das Bündel zu JSON für den Transport.
    let signed_bundle_bytes = serde_json::to_vec(&bundle)?;

    let encrypted_bundle = encrypt_data(&key, &signed_bundle_bytes)?;

    let header = bundle.to_header(TransactionDirection::Sent);
    sender_profile
        .bundle_history
        .insert(header.bundle_id.clone(), header);

    for v in vouchers {
        sender_profile.vouchers.remove(&v.voucher_id);
    }

    Ok(encrypted_bundle)
}

/// Entschlüsselt, verifiziert und verarbeitet ein empfangenes Transaktionsbündel.
pub fn process_encrypted_transaction_bundle(
    recipient_profile: &mut UserProfile,
    recipient_identity: &UserIdentity,
    encrypted_bundle: &[u8],
    sender_id: &str,
) -> Result<(), VoucherCoreError> {
    let sender_pubkey_ed =
        get_pubkey_from_user_id(sender_id).map_err(|e| VoucherCoreError::Crypto(e.to_string()))?;
    let sender_pubkey_x = ed25519_pub_to_x25519(&sender_pubkey_ed);
    let recipient_secret_x = ed25519_sk_to_x25519_sk(&recipient_identity.signing_key);

    let shared_secret = recipient_secret_x.diffie_hellman(&sender_pubkey_x);

    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut key = [0u8; 32];
    hkdf.expand(b"voucher-bundle-key", &mut key).unwrap();

    let decrypted_bundle_bytes = decrypt_data(&key, encrypted_bundle)?;

    // Deserialisiere das Bündel aus JSON.
    let bundle: TransactionBundle = serde_json::from_slice(&decrypted_bundle_bytes)?;

    if bundle.sender_id != sender_id {
        return Err(ProfileManagerError::SenderIdMismatch {
            expected: sender_id.to_string(),
            found: bundle.sender_id.clone(),
        }
            .into());
    }

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

    for voucher in bundle.vouchers.clone() {
        add_voucher_to_profile(recipient_profile, voucher)?;
    }

    let header = bundle.to_header(TransactionDirection::Received);
    recipient_profile
        .bundle_history
        .insert(header.bundle_id.clone(), header);

    Ok(())
}