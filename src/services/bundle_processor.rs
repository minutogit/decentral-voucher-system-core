//! # src/services/bundle_processor.rs
//!
//! Kapselt die Logik für das Erstellen, Verschlüsseln, Öffnen und Verifizieren
//! von Transaktionsbündeln (`TransactionBundle`) und ihren `SecureContainer`.
//! Dieses Modul ist zustandslos und operiert nur auf den ihm übergebenen Daten.

use ed25519_dalek::Signature;

use crate::error::VoucherCoreError;
use crate::models::conflict::TransactionFingerprint;
use crate::models::profile::{TransactionBundle, UserIdentity,};
use crate::models::secure_container::{PayloadType, SecureContainer};
use crate::services::crypto_utils::{get_hash, get_pubkey_from_user_id, sign_ed25519, verify_ed25519};
use crate::services::secure_container_manager::{create_secure_container, open_secure_container};
use crate::services::utils::{get_current_timestamp, to_canonical_json};
use crate::error::ValidationError;
use crate::models::voucher::Voucher;
use std::collections::HashMap;

/// Erstellt ein `TransactionBundle`, verpackt es in einen `SecureContainer` und serialisiert diesen.
/// Diese Funktion ist zustandslos und modifiziert kein Wallet.
///
/// # Returns
/// Ein Tupel, das die serialisierten Bytes des `SecureContainer` und das vollständig
/// erstellte `TransactionBundle` (inkl. ID und Signatur) enthält.
pub fn create_and_encrypt_bundle(
    identity: &UserIdentity,
    vouchers: Vec<Voucher>,
    recipient_id: &str,
    notes: Option<String>,
    forwarded_fingerprints: Vec<TransactionFingerprint>,
    fingerprint_depths: HashMap<String, u8>,
) -> Result<(Vec<u8>, TransactionBundle), VoucherCoreError> {
    let mut bundle = TransactionBundle {
        bundle_id: "".to_string(),
        sender_id: identity.user_id.clone(),
        recipient_id: recipient_id.to_string(),
        vouchers,
        timestamp: get_current_timestamp(),
        notes,
        sender_signature: "".to_string(),
        forwarded_fingerprints,
        fingerprint_depths,
    };

    let bundle_json_for_id = to_canonical_json(&bundle)?;
    bundle.bundle_id = get_hash(bundle_json_for_id);

    let signature = sign_ed25519(&identity.signing_key, bundle.bundle_id.as_bytes());
    bundle.sender_signature = bs58::encode(signature.to_bytes()).into_string();
    let signed_bundle_bytes = serde_json::to_vec(&bundle)?;

    let secure_container = create_secure_container(
        identity,
        &[recipient_id.to_string()],
        &signed_bundle_bytes,
        PayloadType::TransactionBundle,
    )?;

    let container_bytes = serde_json::to_vec(&secure_container)?;

    Ok((container_bytes, bundle))
}

/// Öffnet einen `SecureContainer`, validiert den Inhalt als `TransactionBundle` und
/// verifiziert dessen digitale Signatur.
/// Diese Funktion ist zustandslos und modifiziert kein Wallet.
///
/// # Returns
/// Das validierte `TransactionBundle`.
pub fn open_and_verify_bundle(
    identity: &UserIdentity,
    container_bytes: &[u8],
) -> Result<TransactionBundle, VoucherCoreError> {
    let container: SecureContainer = serde_json::from_slice(container_bytes)?;
    let (decrypted_bundle_bytes, payload_type) = open_secure_container(&container, identity)?;

    if payload_type != PayloadType::TransactionBundle {
        return Err(VoucherCoreError::InvalidPayloadType);
    }

    let bundle: TransactionBundle = serde_json::from_slice(&decrypted_bundle_bytes)?;
    verify_bundle_signature(&bundle)?;

    Ok(bundle)
}

/// Verifiziert die digitale Signatur eines `TransactionBundle`.
fn verify_bundle_signature(bundle: &TransactionBundle) -> Result<(), VoucherCoreError> {
    let sender_pubkey_ed = get_pubkey_from_user_id(&bundle.sender_id)?;
    let signature_bytes = bs58::decode(&bundle.sender_signature)
        .into_vec()
        .map_err(|e| ValidationError::SignatureDecodeError(e.to_string()))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|e| ValidationError::SignatureDecodeError(e.to_string()))?;

    if !verify_ed25519(&sender_pubkey_ed, bundle.bundle_id.as_bytes(), &signature) {
        return Err(ValidationError::InvalidBundleSignature.into());
    }

    Ok(())
}