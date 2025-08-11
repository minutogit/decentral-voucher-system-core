//! # src/services/secure_container_manager.rs
//!
//! Enthält die Kernlogik zur Erstellung, Verschlüsselung, Entschlüsselung und
//! Verifizierung des generischen `SecureContainer`.

use crate::error::VoucherCoreError;
use crate::models::profile::UserIdentity;
use crate::models::secure_container::{PayloadType, SecureContainer};
use crate::services::crypto_utils::{
    self, ed25519_pub_to_x25519, ed25519_sk_to_x25519_sk, get_hash, get_pubkey_from_user_id,
};
use crate::services::utils::to_canonical_json;
use crate::services::voucher_validation::ValidationError;
use ed25519_dalek::Signature;
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use std::collections::HashMap;

/// Definiert die Fehler, die im `secure_container_manager`-Modul auftreten können.
#[derive(Debug, thiserror::Error)]
pub enum ContainerManagerError {
    #[error("The current user is not in the list of recipients for this container.")]
    NotAnIntendedRecipient,
    #[error("The digital signature of the secure container is invalid.")]
    InvalidContainerSignature,
    #[error("Failed to derive key for key encryption: {0}")]
    KeyDerivationError(String),
}

/// Erstellt, verschlüsselt und signiert einen `SecureContainer` für mehrere Empfänger.
///
/// # Arguments
/// * `sender_identity` - Die Identität des Senders, inklusive seiner Schlüssel.
/// * `recipient_ids` - Eine Liste der User-IDs der Empfänger.
/// * `payload` - Die zu verschlüsselnden Rohdaten (z.B. ein serialisiertes JSON-Objekt).
/// * `payload_type` - Der Typ der Daten im Payload.
///
/// # Returns
/// Ein `Result`, das den vollständig konfigurierten `SecureContainer` oder einen `VoucherCoreError` enthält.
pub fn create_secure_container(
    sender_identity: &UserIdentity,
    recipient_ids: &[String],
    payload: &[u8],
    payload_type: PayloadType,
) -> Result<SecureContainer, VoucherCoreError> {
    // 1. Einen einmaligen, symmetrischen Schlüssel für den Payload generieren.
    let mut payload_key = [0u8; 32];
    OsRng.fill_bytes(&mut payload_key);

    // 2. Den Payload mit diesem symmetrischen Schlüssel verschlüsseln.
    let encrypted_payload = crypto_utils::encrypt_data(&payload_key, payload)?;

    // 3. Den symmetrischen `payload_key` für jeden Empfänger einzeln verschlüsseln.
    let mut recipient_key_map = HashMap::new();
    let sender_x25519_sk = ed25519_sk_to_x25519_sk(&sender_identity.signing_key);

    for recipient_id in recipient_ids {
        let recipient_pubkey_ed = get_pubkey_from_user_id(recipient_id)?;
        let recipient_pubkey_x = ed25519_pub_to_x25519(&recipient_pubkey_ed);

        // Statischen DH-Austausch durchführen, um ein Shared Secret zu erhalten.
        let shared_secret = sender_x25519_sk.diffie_hellman(&recipient_pubkey_x);

        // Einen Key-Encryption-Key (KEK) aus dem Shared Secret ableiten (Best Practice).
        let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut kek = [0u8; 32];
        hkdf.expand(b"secure-container-kek", &mut kek)
            .map_err(|e| ContainerManagerError::KeyDerivationError(e.to_string()))?;

        // Den `payload_key` mit dem KEK verschlüsseln.
        let encrypted_payload_key = crypto_utils::encrypt_data(&kek, &payload_key)?;
        recipient_key_map.insert(recipient_id.clone(), encrypted_payload_key);
    }

    // 4. Den Container zusammenbauen (vorerst ohne ID und Signatur).
    let mut container = SecureContainer {
        container_id: "".to_string(),
        sender_id: sender_identity.user_id.clone(),
        payload_type,
        encrypted_payload,
        recipient_key_map,
        sender_signature: "".to_string(),
    };

    // 5. Die `container_id` aus dem Hash des kanonischen Inhalts generieren.
    let container_json_for_id = to_canonical_json(&container)?;
    container.container_id = get_hash(container_json_for_id);

    // 6. Die `container_id` signieren und dem Container hinzufügen.
    let signature =
        crypto_utils::sign_ed25519(&sender_identity.signing_key, container.container_id.as_bytes());
    container.sender_signature = bs58::encode(signature.to_bytes()).into_string();

    Ok(container)
}

/// Öffnet, verifiziert und entschlüsselt einen `SecureContainer`.
///
/// # Arguments
/// * `container` - Der zu öffnende `SecureContainer`.
/// * `recipient_identity` - Die Identität des Empfängers (des aktuellen Nutzers).
///
/// # Returns
/// Ein `Result`, das ein Tupel aus den entschlüsselten Payload-Daten und dem `PayloadType`
/// oder einen `VoucherCoreError` enthält.
pub fn open_secure_container(
    container: &SecureContainer,
    recipient_identity: &UserIdentity,
) -> Result<(Vec<u8>, PayloadType), VoucherCoreError> {
    // 1. Authentizität des Containers durch Signaturprüfung sicherstellen.
    let sender_pubkey_ed = get_pubkey_from_user_id(&container.sender_id)?;
    let signature_bytes = bs58::decode(&container.sender_signature)
        .into_vec()
        .map_err(|e| ValidationError::SignatureDecodeError(e.to_string()))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|e| ValidationError::SignatureDecodeError(e.to_string()))?;

    if !crypto_utils::verify_ed25519(
        &sender_pubkey_ed,
        container.container_id.as_bytes(),
        &signature,
    ) {
        return Err(ContainerManagerError::InvalidContainerSignature.into());
    }

    // 2. Den für diesen Empfänger verschlüsselten Payload Key finden.
    let encrypted_payload_key = container
        .recipient_key_map
        .get(&recipient_identity.user_id)
        .ok_or(ContainerManagerError::NotAnIntendedRecipient)?;

    // 3. Shared Secret neu berechnen, um den Payload Key zu entschlüsseln.
    let recipient_x25519_sk = ed25519_sk_to_x25519_sk(&recipient_identity.signing_key);
    let sender_pubkey_x = ed25519_pub_to_x25519(&sender_pubkey_ed);
    let shared_secret = recipient_x25519_sk.diffie_hellman(&sender_pubkey_x);

    // Denselben KEK wie der Sender ableiten.
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut kek = [0u8; 32];
    hkdf.expand(b"secure-container-kek", &mut kek)
        .map_err(|e| ContainerManagerError::KeyDerivationError(e.to_string()))?;

    // 4. Den Payload Key entschlüsseln.
    let payload_key_bytes = crypto_utils::decrypt_data(&kek, encrypted_payload_key)?;
    let payload_key: [u8; 32] = payload_key_bytes
        .try_into()
        .map_err(|_| VoucherCoreError::Crypto("Decrypted payload key has incorrect length".to_string()))?;

    // 5. Den eigentlichen Payload entschlüsseln.
    let decrypted_payload = crypto_utils::decrypt_data(&payload_key, &container.encrypted_payload)?;

    Ok((decrypted_payload, container.payload_type.clone()))
}