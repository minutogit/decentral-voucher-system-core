//! # voucher_validation.rs
//!
//! Dieses Modul enthält die Logik zur Validierung eines `Voucher`-Objekts
//! gegen die Regeln eines `VoucherStandardDefinition`.

use crate::models::voucher::Voucher;
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use crate::services::crypto_utils::{
    get_hash, get_pubkey_from_user_id, verify_ed25519, GetPubkeyError,
};
use crate::services::utils::to_canonical_json;
use ed25519_dalek::Signature;
use serde_json::Value;
use std::fmt;

/// Definiert die verschiedenen Fehler, die während der Validierung auftreten können.
#[derive(Debug)]
pub enum ValidationError {
    /// Ein Feld, das im Standard als erforderlich markiert ist, fehlt im Gutschein.
    MissingRequiredField(String),
    /// Die Einheit des Nennwerts im Gutschein stimmt nicht mit dem Standard überein.
    IncorrectNominalValueUnit { expected: String, found: String },
    /// Die Teilbarkeitseigenschaft (`divisible`) im Gutschein stimmt nicht mit dem Standard überein.
    IncorrectDivisibility { expected: bool, found: bool },
    /// Die Signatur des Erstellers ist ungültig.
    InvalidCreatorSignature,
    /// Die User ID des Erstellers ist ungültig oder der Public Key kann nicht extrahiert werden.
    InvalidCreatorId(GetPubkeyError),
    /// Die Bürgenanforderungen des Standards werden nicht erfüllt.
    GuarantorRequirementsNotMet(String),
    /// Die voucher_id in einer Signatur stimmt nicht mit der des Gutscheins überein.
    MismatchedVoucherIdInSignature { expected: String, found: String },
    /// Die Signatur-ID ist ungültig, was auf manipulierte Signatur-Metadaten hindeutet.
    InvalidSignatureId(String),
    /// Eine Signatur eines Bürgen ist ungültig.
    InvalidGuarantorSignature(String),
    /// Eine Transaktionssignatur ist ungültig.
    InvalidTransactionSignature(String),
    /// Die User ID eines Senders in einer Transaktion ist ungültig.
    InvalidTransactionSenderId(String),
    /// Ein Fehler bei der JSON-Verarbeitung während der Validierung.
    Serialization(serde_json::Error),
    /// Ein Fehler bei der Dekodierung einer Signatur (z.B. Base58).
    SignatureDecodeError(String),
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::MissingRequiredField(path) => write!(f, "Required field is missing: {}", path),
            Self::IncorrectNominalValueUnit { expected, found } => {
                write!(f, "Incorrect nominal value unit. Expected: {}, Found: {}", expected, found)
            }
            Self::IncorrectDivisibility { expected, found } => {
                write!(f, "Incorrect divisibility. Expected: {}, Found: {}", expected, found)
            }
            Self::InvalidCreatorSignature => write!(f, "Creator signature is invalid"),
            Self::InvalidCreatorId(e) => write!(f, "Invalid creator ID: {}", e),
            Self::GuarantorRequirementsNotMet(reason) => write!(f, "Guarantor requirements not met: {}", reason),
            Self::MismatchedVoucherIdInSignature { expected, found } => write!(
                f,
                "Signature references wrong voucher. Expected ID: {}, Found ID: {}",
                expected, found
            ),
            Self::InvalidSignatureId(id) => write!(f, "The signature ID {} is invalid or data was tampered with", id),
            Self::InvalidGuarantorSignature(id) => write!(f, "Invalid signature for guarantor {}", id),
            Self::InvalidTransactionSignature(t_id) => write!(f, "Invalid signature for transaction {}", t_id),
            Self::InvalidTransactionSenderId(id) => write!(f, "Invalid sender ID in transaction: {}", id),
            Self::Serialization(e) => write!(f, "JSON serialization error during validation: {}", e),
            Self::SignatureDecodeError(e) => write!(f, "Failed to decode signature: {}", e),
        }
    }
}

impl std::error::Error for ValidationError {}

/// Hauptfunktion zur Validierung eines Gutscheins gegen seinen Standard.
///
/// # Arguments
/// * `voucher` - Eine Referenz auf den zu validierenden `Voucher`.
/// * `standard` - Eine Referenz auf die `VoucherStandardDefinition`, die die Regeln enthält.
///
/// # Returns
/// Ein leeres `Result::Ok(())` bei Erfolg oder ein `ValidationError` bei einem Fehler.
pub fn validate_voucher_against_standard(
    voucher: &Voucher,
    standard: &VoucherStandardDefinition,
) -> Result<(), ValidationError> {
    // Die Reihenfolge der Prüfungen ist wichtig für aussagekräftige Fehlermeldungen.
    // Zuerst logische und inhaltliche Konsistenz, dann die kryptographischen Prüfungen.
    verify_required_fields(voucher, standard)?;
    verify_consistency_with_standard(voucher, standard)?;
    verify_guarantor_requirements(voucher, standard)?;
    verify_transactions(voucher)?;
    verify_creator_signature(voucher)?; // Die kryptographische Gesamtprüfung zum Schluss.

    Ok(())
}

/// Überprüft, ob alle im Standard als erforderlich markierten Felder im Gutschein vorhanden sind.
fn verify_required_fields(voucher: &Voucher, standard: &VoucherStandardDefinition) -> Result<(), ValidationError> {
    let voucher_value = serde_json::to_value(voucher).map_err(ValidationError::Serialization)?;
    for path in &standard.validation.required_voucher_fields {
        let mut current_value = &voucher_value;
        for key in path.split('.') {
            current_value = current_value.get(key).unwrap_or(&Value::Null);
        }
        if current_value.is_null() {
            return Err(ValidationError::MissingRequiredField(path.clone()));
        }
    }
    Ok(())
}

/// Überprüft die Konsistenz der Gutscheindaten mit den Vorgaben des Standards.
fn verify_consistency_with_standard(voucher: &Voucher, standard: &VoucherStandardDefinition) -> Result<(), ValidationError> {
    // Überprüfe die Einheit des Nennwerts
    if voucher.nominal_value.unit != standard.template.nominal_value.unit {
        return Err(ValidationError::IncorrectNominalValueUnit {
            expected: standard.template.nominal_value.unit.clone(),
            found: voucher.nominal_value.unit.clone(),
        });
    }

    // Überprüfe die Teilbarkeit
    if voucher.divisible != standard.template.is_divisible {
        return Err(ValidationError::IncorrectDivisibility {
            expected: standard.template.is_divisible,
            found: voucher.divisible,
        });
    }

    // Weitere Konsistenzprüfungen (z.B. für collateral) können hier hinzugefügt werden.
    Ok(())
}

/// Verifiziert die Signatur des Erstellers.
fn verify_creator_signature(voucher: &Voucher) -> Result<(), ValidationError> {
    // 1. Extrahiere den Public Key aus der User ID des Erstellers.
    let public_key = get_pubkey_from_user_id(&voucher.creator.id)
        .map_err(ValidationError::InvalidCreatorId)?;

    // 2. Rekonstruiere die Daten, die signiert wurden.
    // Dafür erstellen wir eine Kopie des Gutscheins und leeren das Signaturfeld.
    let mut voucher_to_verify = voucher.clone();
    // Die Signatur des Erstellers deckt nur den initialen Zustand ab.
    // Später hinzugefügte Signaturen (Bürgen, etc.) müssen für die Prüfung entfernt werden.
    let signature_b58 = voucher_to_verify.creator.signature.clone();
    voucher_to_verify.creator.signature = "".to_string();
    // Die voucher_id selbst war auch Teil des Hashes, aber bei der Erstellung noch leer.
    // Daher muss sie für die Verifizierung ebenfalls geleert werden, um den ursprünglichen
    // Zustand exakt zu rekonstruieren.
    voucher_to_verify.voucher_id = "".to_string();
    voucher_to_verify.guarantor_signatures.clear();
    voucher_to_verify.additional_signatures.clear();

    let voucher_json =
        to_canonical_json(&voucher_to_verify).map_err(ValidationError::Serialization)?;
    let voucher_hash = get_hash(voucher_json);

    // 3. Dekodiere die Signatur aus dem Base58-Format.
    let signature_bytes = bs58::decode(signature_b58)
        .into_vec()
        .map_err(|e| ValidationError::SignatureDecodeError(e.to_string()))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|e| ValidationError::SignatureDecodeError(e.to_string()))?;


    // 4. Verifiziere die Signatur.
    if !verify_ed25519(&public_key, voucher_hash.as_bytes(), &signature) {
        return Err(ValidationError::InvalidCreatorSignature);
    }

    Ok(())
}

/// Verifiziert die Signaturen der Bürgen gegen die Anforderungen des Standards.
fn verify_guarantor_requirements(voucher: &Voucher, standard: &VoucherStandardDefinition) -> Result<(), ValidationError> {
    let required_count = standard.template.guarantor_info.needed_count as usize;
    let actual_count = voucher.guarantor_signatures.len();

    // 1. Prüfe die Anzahl der Bürgen
    if actual_count < required_count {
        return Err(ValidationError::GuarantorRequirementsNotMet(format!(
            "Expected at least {} guarantors, but found {}",
            required_count,
            actual_count
        )));
    }

    // 2. Prüfe jede vorhandene Bürgen-Signatur kryptographisch.
    // Jede Signatur ist jetzt ein in sich geschlossenes Objekt.
    for guarantor_signature in &voucher.guarantor_signatures {
        // 2.1. Stelle sicher, dass die Signatur zum richtigen Gutschein gehört.
        if guarantor_signature.voucher_id != voucher.voucher_id {
            return Err(ValidationError::MismatchedVoucherIdInSignature {
                expected: voucher.voucher_id.clone(),
                found: guarantor_signature.voucher_id.clone(),
            });
        }

        // 2.2. Rekonstruiere die Daten, die zur Erzeugung der `signature_id` gehasht wurden.
        let mut signature_to_verify = guarantor_signature.clone();
        let signature_b58 = signature_to_verify.signature;

        // Um die ID zu verifizieren, müssen wir exakt den Zustand hashen, der bei der Erstellung der ID vorlag.
        // Dabei waren sowohl die signature_id als auch die Signatur selbst noch nicht gesetzt.
        signature_to_verify.signature_id = "".to_string();
        signature_to_verify.signature = "".to_string();

        let calculated_signature_id_hash = get_hash(to_canonical_json(&signature_to_verify).map_err(ValidationError::Serialization)?);

        // 2.3. Verifiziere, dass die `signature_id` mit den Daten übereinstimmt.
        if calculated_signature_id_hash != guarantor_signature.signature_id {
            return Err(ValidationError::InvalidSignatureId(guarantor_signature.signature_id.clone()));
        }

        // 2.4. Verifiziere die digitale Signatur selbst. Sie signiert die `signature_id`.
        let public_key = get_pubkey_from_user_id(&guarantor_signature.guarantor_id)
            .map_err(|_| ValidationError::InvalidGuarantorSignature(guarantor_signature.guarantor_id.clone()))?;

        let signature_bytes = bs58::decode(signature_b58)
            .into_vec()
            .map_err(|e| ValidationError::SignatureDecodeError(e.to_string()))?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|e| ValidationError::SignatureDecodeError(e.to_string()))?;

        if !verify_ed25519(&public_key, guarantor_signature.signature_id.as_bytes(), &signature) {
            return Err(ValidationError::InvalidGuarantorSignature(
                guarantor_signature.guarantor_id.clone(),
            ));
        }
    }

    // 3. Prüfe geschlechtsspezifische Anforderungen, falls vorhanden
    if standard.validation.guarantor_rules.gender_specific {
        // Erstelle eine Kopie der benötigten Geschlechter, um gefundene zu entfernen.
        let mut needed_genders = standard.validation.guarantor_rules.genders_needed.to_vec();

        for guarantor_signature in &voucher.guarantor_signatures {
            // Finde das Geschlecht des aktuellen Bürgen in der Liste der benötigten
            if let Some(pos) = needed_genders.iter().position(|g| g == &guarantor_signature.gender) {
                // Wenn gefunden, entferne es, da diese Anforderung erfüllt ist.
                needed_genders.remove(pos);
            }
        }

        if !needed_genders.is_empty() {
            return Err(ValidationError::GuarantorRequirementsNotMet(format!(
                "Missing required genders: {:?}",
                needed_genders
            )));
        }
    }

    Ok(())
}

/// Verifiziert die Integrität und die Signaturen der Transaktionsliste.
fn verify_transactions(voucher: &Voucher) -> Result<(), ValidationError> {
    // TODO: Die vollständige Prüfung der Transaktionskette (z.B. Überprüfung von
    // previous_hash-Verkettungen und Double-Spending-Prävention auf Gutscheinebene)
    // muss implementiert werden, sobald die Transaktionsstruktur final definiert ist.

    for transaction in &voucher.transactions {
        // Rekonstruiere die signierten Daten für jede Transaktion
        let mut tx_to_verify = transaction.clone();
        let signature_b58 = tx_to_verify.sender_signature.clone();
        tx_to_verify.sender_signature = "".to_string();

        let tx_json =
            to_canonical_json(&tx_to_verify).map_err(ValidationError::Serialization)?;
        let tx_hash = get_hash(tx_json);

        // Extrahiere den Public Key des Senders
        let sender_pub_key = get_pubkey_from_user_id(&transaction.sender_id)
            .map_err(|_| ValidationError::InvalidTransactionSenderId(transaction.sender_id.clone()))?;

        // Dekodiere und verifiziere die Signatur
        let signature_bytes = bs58::decode(signature_b58)
            .into_vec()
            .map_err(|e| ValidationError::SignatureDecodeError(e.to_string()))?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|e| ValidationError::SignatureDecodeError(e.to_string()))?;

        if !verify_ed25519(&sender_pub_key, tx_hash.as_bytes(), &signature) {
            return Err(ValidationError::InvalidTransactionSignature(transaction.t_id.clone()));
        }
    }

    Ok(())
}