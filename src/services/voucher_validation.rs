//! # voucher_validation.rs
//!
//! Dieses Modul enthält die Logik zur Validierung eines `Voucher`-Objekts
//! gegen die Regeln eines `VoucherStandardDefinition`.

use crate::error::VoucherCoreError;
use crate::models::voucher::Voucher;
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use crate::services::crypto_utils::{
    get_hash, get_pubkey_from_user_id, verify_ed25519, GetPubkeyError,
};
use crate::services::utils::to_canonical_json;

use chrono::{DateTime, Utc};
use ed25519_dalek::Signature;
use rust_decimal::Decimal;
use serde_json::Value;
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

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
    /// Die Transaktionskette ist ungültig (z.B. falscher prev_hash oder Signatur).
    InvalidTransaction(String),
    /// Die User ID eines Senders in einer Transaktion ist ungültig.
    InvalidTransactionSenderId(String),
    /// Das Guthaben des Senders ist für eine Transaktion nicht ausreichend.
    InsufficientFunds,
    /// Bei einem Split stimmt die Summe aus gesendetem Betrag und Restbetrag nicht mit dem Wert vor dem Split überein.
    AmountMismatchOnSplit,
    /// Die im Gutschein gespeicherte Mindestgültigkeit stimmt nicht mit dem Standard überein.
    MismatchedMinimumValidity { expected: String, found: String },
    /// Die tatsächliche Gültigkeitsdauer des Gutscheins ist kürzer als vom Standard gefordert.
    ValidityDurationTooShort { required: String, actual: String },
    /// Ein Datum im Gutschein konnte nicht geparst werden.
    DateParseError(String),
    // Fehler bei der Konvertierung von Beträgen wird jetzt in VoucherCoreError behandelt.
    /// Ein Fehler bei der Dekodierung einer Signatur (z.B. Base58).
    SignatureDecodeError(String),
    /// Die Signatur eines Transaktionsbündels (`TransactionBundle`) ist ungültig.
    InvalidBundleSignature,
    /// Die digitale Signatur ist kryptographisch ungültig.
    InvalidSignature(String),
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::MissingRequiredField(path) => write!(f, "Required field is missing: {}", path),
            Self::IncorrectNominalValueUnit { expected, found } => write!(f, "Incorrect nominal value unit. Expected: {}, Found: {}", expected, found),
            Self::IncorrectDivisibility { expected, found } => write!(f, "Incorrect divisibility. Expected: {}, Found: {}", expected, found),
            Self::InvalidCreatorSignature => write!(f, "Creator signature is invalid"),
            Self::InvalidCreatorId(e) => write!(f, "Invalid creator ID: {}", e),
            Self::GuarantorRequirementsNotMet(reason) => write!(f, "Guarantor requirements not met: {}", reason),
            Self::MismatchedVoucherIdInSignature { expected, found } => write!(f, "Signature references wrong voucher. Expected ID: {}, Found ID: {}", expected, found),
            Self::InvalidSignatureId(id) => write!(f, "The signature ID {} is invalid or data was tampered with", id),
            Self::InvalidGuarantorSignature(id) => write!(f, "Invalid signature for guarantor {}", id),
            Self::InvalidTransaction(reason) => write!(f, "Invalid transaction: {}", reason),
            Self::InvalidTransactionSenderId(id) => write!(f, "Invalid sender ID in transaction: {}", id),
            Self::InsufficientFunds => write!(f, "Insufficient funds for transaction."),
            Self::AmountMismatchOnSplit => write!(f, "The sum of amount and sender_remaining_amount does not match the pre-split value."),
            Self::MismatchedMinimumValidity { expected, found } => write!(f, "Voucher's stored minimum validity rule ('{}') does not match standard's rule ('{}')", found, expected),
            Self::ValidityDurationTooShort { required, actual } => write!(f, "Actual voucher validity duration is too short. Required at least: {}, Actual: {}", required, actual),
            Self::DateParseError(e) => write!(f, "Failed to parse date: {}", e),
            Self::SignatureDecodeError(e) => write!(f, "Failed to decode signature: {}", e),
            Self::InvalidBundleSignature => write!(f, "The transaction bundle signature is invalid"),
            Self::InvalidSignature(signer_id) => write!(f, "Invalid digital signature for signer: {}", signer_id),
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
) -> Result<(), VoucherCoreError> {
    // Die Reihenfolge der Prüfungen ist wichtig für aussagekräftige Fehlermeldungen.
    // Zuerst logische und inhaltliche Konsistenz, dann die kryptographischen Prüfungen.
    verify_required_fields(voucher, standard)?;
    verify_consistency_with_standard(voucher, standard)?;
    verify_validity_duration(voucher, standard)?;
    verify_guarantor_requirements(voucher, standard)?;
    verify_additional_signatures(voucher)?; // NEUE PRÜFUNG HINZUGEFÜGT
    verify_transactions(voucher, standard)?; // WICHTIG: standard wird jetzt übergeben
    verify_creator_signature(voucher)?; // Die kryptographische Gesamtprüfung zum Schluss.

    Ok(())
}

/// Überprüft, ob alle im Standard als erforderlich markierten Felder im Gutschein vorhanden sind.
fn verify_required_fields(voucher: &Voucher, standard: &VoucherStandardDefinition) -> Result<(), VoucherCoreError> {
    let voucher_value = serde_json::to_value(voucher)?;
    for path in &standard.validation.required_voucher_fields {
        let mut current_value = &voucher_value;
        for key in path.split('.') {
            current_value = current_value.get(key).unwrap_or(&Value::Null);
        }
        if current_value.is_null() {
            return Err(ValidationError::MissingRequiredField(path.clone()).into());
        }
    }
    Ok(())
}

/// Überprüft die Konsistenz der Gutscheindaten mit den Vorgaben des Standards.
fn verify_consistency_with_standard(voucher: &Voucher, standard: &VoucherStandardDefinition) -> Result<(), VoucherCoreError> {
    // Überprüfe die Einheit des Nennwerts
    if voucher.nominal_value.unit != standard.template.fixed.nominal_value.unit {
        return Err(ValidationError::IncorrectNominalValueUnit {
            expected: standard.template.fixed.nominal_value.unit.clone(),
            found: voucher.nominal_value.unit.clone(),
        }.into());
    }

    // Überprüfe die Teilbarkeit
    if voucher.divisible != standard.template.fixed.is_divisible {
        return Err(ValidationError::IncorrectDivisibility {
            expected: standard.template.fixed.is_divisible,
            found: voucher.divisible,
        }.into());
    }

    // Weitere Konsistenzprüfungen (z.B. für collateral) können hier hinzugefügt werden.
    Ok(())
}

/// Verifiziert, dass die Gültigkeitsdauer des Gutscheins den Regeln des Standards entspricht.
fn verify_validity_duration(voucher: &Voucher, standard: &VoucherStandardDefinition) -> Result<(), VoucherCoreError> {
    let standard_min_duration = standard.validation.issuance_minimum_validity_duration.clone().unwrap_or_default();

    // 1. Prüfe, ob die im Gutschein gespeicherte Regel mit der aktuellen Regel des Standards übereinstimmt.
    //    Dies verhindert, dass ein Gutschein gegen eine veraltete/andere Standard-Version validiert wird.
    if voucher.standard_minimum_issuance_validity != standard_min_duration {
        return Err(ValidationError::MismatchedMinimumValidity {
            expected: standard_min_duration,
            found: voucher.standard_minimum_issuance_validity.clone(),
        }.into());
    }

    // Wenn keine Mindestdauer im Standard definiert ist, sind wir hier fertig.
    if standard_min_duration.is_empty() {
        return Ok(());
    }

    // 2. Parse die Daten aus dem Gutschein.
    let creation_dt = DateTime::parse_from_rfc3339(&voucher.creation_date)
        .map_err(|e| ValidationError::DateParseError(e.to_string()))?
        .with_timezone(&Utc);

    let valid_until_dt = DateTime::parse_from_rfc3339(&voucher.valid_until)
        .map_err(|e| ValidationError::DateParseError(e.to_string()))?
        .with_timezone(&Utc);

    // 3. Berechne das erforderliche Mindest-Gültigkeitsdatum.
    let required_valid_until = add_iso8601_duration_for_validation(creation_dt, &standard_min_duration)?;

    // 4. Vergleiche das tatsächliche Datum mit dem erforderlichen Datum.
    if valid_until_dt < required_valid_until {
        return Err(ValidationError::ValidityDurationTooShort {
            required: required_valid_until.to_rfc3339(),
            actual: valid_until_dt.to_rfc3339(),
        }.into());
    }

    Ok(())
}

/// Eine eigenständige Hilfsfunktion, die `add_iso8601_duration` aus dem `voucher_manager` spiegelt.
fn add_iso8601_duration_for_validation(start_date: DateTime<Utc>, duration_str: &str) -> Result<DateTime<Utc>, VoucherCoreError> {
    if !duration_str.starts_with('P') || duration_str.len() < 3 { return Err(ValidationError::DateParseError(format!("Invalid ISO 8601 duration format: {}", duration_str)).into()); }
    let (value_str, unit) = duration_str.split_at(duration_str.len() - 1);
    let value: u32 = value_str[1..].parse().map_err(|_| ValidationError::DateParseError(format!("Invalid number in duration: {}", duration_str)))?;
    match unit { "Y" => Ok(start_date + chrono::Duration::days(i64::from(value) * 365)), "M" => Ok(start_date + chrono::Duration::days(i64::from(value) * 30)), "D" => Ok(start_date + chrono::Duration::days(i64::from(value))), _ => Err(ValidationError::DateParseError(format!("Unsupported duration unit in: {}", duration_str)).into()), }
}

/// Verifiziert die Signatur des Erstellers.
fn verify_creator_signature(voucher: &Voucher) -> Result<(), VoucherCoreError> {
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
    voucher_to_verify.transactions.clear(); // Wichtig: Transaktionen müssen entfernt werden!
    voucher_to_verify.guarantor_signatures.clear();
    voucher_to_verify.additional_signatures.clear();

    let voucher_json = to_canonical_json(&voucher_to_verify)?;
    let voucher_hash = get_hash(voucher_json);

    // 3. Dekodiere die Signatur aus dem Base58-Format.
    let signature_bytes = bs58::decode(signature_b58)
        .into_vec()
        .map_err(|e| ValidationError::SignatureDecodeError(e.to_string()))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|e| ValidationError::SignatureDecodeError(e.to_string()))?;


    // 4. Verifiziere die Signatur.
    if !verify_ed25519(&public_key, voucher_hash.as_bytes(), &signature) {
        return Err(ValidationError::InvalidCreatorSignature.into());
    }

    Ok(())
}

/// Verifiziert die Signaturen der Bürgen gegen die Anforderungen des Standards.
fn verify_guarantor_requirements(voucher: &Voucher, standard: &VoucherStandardDefinition) -> Result<(), VoucherCoreError> {
    let required_count = standard.template.fixed.guarantor_info.needed_count as usize;
    let actual_count = voucher.guarantor_signatures.len();

    // 1. Prüfe die Anzahl der Bürgen
    if actual_count < required_count {
        return Err(ValidationError::GuarantorRequirementsNotMet(format!(
            "Expected at least {} guarantors, but found {}",
            required_count,
            actual_count
        )).into());
    }

    // 2. Prüfe jede vorhandene Bürgen-Signatur kryptographisch.
    // Jede Signatur ist jetzt ein in sich geschlossenes Objekt.
    for guarantor_signature in &voucher.guarantor_signatures {
        // 2.1. Stelle sicher, dass die Signatur zum richtigen Gutschein gehört.
        if guarantor_signature.voucher_id != voucher.voucher_id {
            return Err(ValidationError::MismatchedVoucherIdInSignature {
                expected: voucher.voucher_id.clone(),
                found: guarantor_signature.voucher_id.clone(),
            }.into());
        }

        // 2.2. Rekonstruiere die Daten, die zur Erzeugung der `signature_id` gehasht wurden.
        let mut signature_to_verify = guarantor_signature.clone();
        let signature_b58 = signature_to_verify.signature;

        // Um die ID zu verifizieren, müssen wir exakt den Zustand hashen, der bei der Erstellung der ID vorlag.
        // Dabei waren sowohl die signature_id als auch die Signatur selbst noch nicht gesetzt.
        signature_to_verify.signature_id = "".to_string();
        signature_to_verify.signature = "".to_string();

        let calculated_signature_id_hash = get_hash(to_canonical_json(&signature_to_verify)?);

        // 2.3. Verifiziere, dass die `signature_id` mit den Daten übereinstimmt.
        if calculated_signature_id_hash != guarantor_signature.signature_id {
            return Err(ValidationError::InvalidSignatureId(guarantor_signature.signature_id.clone()).into());
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
            ).into());
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
            )).into());
        }
    }

    Ok(())
}

/// Verifiziert die Integrität und kryptographische Gültigkeit aller zusätzlichen Signaturen.
/// Die Logik ist identisch zur Überprüfung der Bürgen-Signaturen.
fn verify_additional_signatures(voucher: &Voucher) -> Result<(), VoucherCoreError> {
    for signature_obj in &voucher.additional_signatures {
        // 1. Stelle sicher, dass die Signatur zum richtigen Gutschein gehört.
        if signature_obj.voucher_id != voucher.voucher_id {
            return Err(ValidationError::MismatchedVoucherIdInSignature {
                expected: voucher.voucher_id.clone(),
                found: signature_obj.voucher_id.clone(),
            }.into());
        }

        // 2. Rekonstruiere die Daten für die `signature_id` und verifiziere sie.
        let mut obj_to_verify = signature_obj.clone();
        let signature_b58 = obj_to_verify.signature;

        obj_to_verify.signature_id = "".to_string();
        obj_to_verify.signature = "".to_string();

        let calculated_id_hash = get_hash(to_canonical_json(&obj_to_verify)?);

        if calculated_id_hash != signature_obj.signature_id {
            return Err(ValidationError::InvalidSignatureId(signature_obj.signature_id.clone()).into());
        }

        // 3. Verifiziere die digitale Signatur selbst.
        let public_key = get_pubkey_from_user_id(&signature_obj.signer_id)
            .map_err(|_| ValidationError::InvalidGuarantorSignature(signature_obj.signer_id.clone()))?;

        let signature_bytes = bs58::decode(signature_b58)
            .into_vec()
            .map_err(|e| ValidationError::SignatureDecodeError(e.to_string()))?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|e| ValidationError::SignatureDecodeError(e.to_string()))?;

        if !verify_ed25519(&public_key, signature_obj.signature_id.as_bytes(), &signature) {
            return Err(ValidationError::InvalidGuarantorSignature(
                signature_obj.signer_id.clone(),
            ).into());
        }
    }
    Ok(())
}


/// Verifiziert die Integrität, Signaturen und Geschäftslogik der Transaktionsliste.
/// Dies ist eine zustandsbehaftete Prüfung, die Bilanzen über die Kette hinweg verfolgt.
fn verify_transactions(voucher: &Voucher, standard: &VoucherStandardDefinition) -> Result<(), VoucherCoreError> {
    // Ein Mapping von user_id zu ihrem aktuellen Guthaben.
    let mut balances: HashMap<String, Decimal> = HashMap::new();
    let decimal_places = standard.validation.amount_decimal_places as u32;

    for (i, transaction) in voucher.transactions.iter().enumerate() {
        // 1. Überprüfe die kryptographische Verkettung (`prev_hash`).
        let expected_prev_hash = if i == 0 {
            get_hash(&voucher.voucher_id)
        } else {
            let prev_transaction = &voucher.transactions[i - 1];
            get_hash(to_canonical_json(prev_transaction)?)
        };

        if transaction.prev_hash != expected_prev_hash {
            return Err(ValidationError::InvalidTransaction(format!(
                "Transaction {} has an invalid prev_hash.",
                transaction.t_id
            )).into());
        }

        // 2. Überprüfe die Integrität der `t_id` und die `sender_signature`.
        verify_transaction_integrity_and_signature(transaction)?;

        // 3. Geschäftslogik validieren (Guthaben, Splits etc.).
        let sender_id = &transaction.sender_id;
        let sender_balance = *balances.get(sender_id).unwrap_or(&Decimal::ZERO);
        
        // SICHERHEITSPATCH: Eine "init"-Transaktion ist nur als allererste Transaktion (i=0) gültig.
        if i > 0 && transaction.t_type == "init" {
            return Err(ValidationError::InvalidTransaction(format!(
                "Transaction {} has invalid type 'init' at a non-zero position.",
                transaction.t_id
            )).into());
        }

        let mut amount_sent = Decimal::from_str(&transaction.amount)?;
        amount_sent.set_scale(decimal_places)?;

        // SICHERHEITSPATCH: Transaktions- und Restbeträge müssen immer positiv sein.
        if amount_sent <= Decimal::ZERO {
            return Err(ValidationError::InvalidTransaction(
                "Transaction amount must be positive.".to_string()
            ).into());
        }

        // Geschäftslogik für die 'init' Transaktion.
        if i == 0 && transaction.t_type == "init" {
            // Die 'init' Transaktion setzt das Startguthaben für den Ersteller.
            balances.insert(sender_id.clone(), amount_sent);
        } else {
            // Geschäftslogik für alle nachfolgenden Transaktionen.
            // Unterscheidung zwischen Split und vollem Transfer anhand von sender_remaining_amount
            if let Some(remaining_str) = &transaction.sender_remaining_amount {
                // --- Fall 1: Dies ist eine SPLIT-Transaktion ---
                if !voucher.divisible {
                    return Err(ValidationError::InvalidTransaction("Voucher is not divisible.".to_string()).into());
                }
                if transaction.t_type != "split" {
                    return Err(ValidationError::InvalidTransaction("Transaction with remaining amount must be of type 'split'.".to_string()).into());
                }
                
                let mut remaining_amount = Decimal::from_str(remaining_str)?;
                remaining_amount.set_scale(decimal_places)?;

                if remaining_amount < Decimal::ZERO { // Restbetrag darf 0 sein, aber nicht negativ
                    return Err(ValidationError::InvalidTransaction(
                        "Sender remaining amount cannot be negative.".to_string()
                    ).into());
                }

                // Prüfe die Erhaltung des Wertes.
                // Toleranz für Rundungsfehler einbauen, falls nötig, aber exakter Vergleich ist besser.
                if amount_sent + remaining_amount != sender_balance{
                    return Err(ValidationError::AmountMismatchOnSplit.into());
                }

                // Aktualisiere Guthaben für Sender und Empfänger.
                balances.insert(sender_id.clone(), remaining_amount);
                *balances.entry(transaction.recipient_id.clone()).or_insert(Decimal::ZERO) += amount_sent;

            } else {
                // --- Fall 2: Dies ist ein VOLLER TRANSFER ---
                // Bei einem vollen Transfer muss der gesendete Betrag exakt dem Guthaben des Senders entsprechen.
                if amount_sent > sender_balance {
                     return Err(ValidationError::InsufficientFunds.into());
                }
                if amount_sent < sender_balance {
                    return Err(ValidationError::InvalidTransaction("Full transfer amount is less than the available sender balance.".to_string()).into());
                }
                *balances.entry(sender_id.clone()).or_insert(Decimal::ZERO) -= amount_sent;
                *balances.entry(transaction.recipient_id.clone()).or_insert(Decimal::ZERO) += amount_sent;
            }
        }
    }

    Ok(())
}

/// Hilfsfunktion zur Überprüfung der internen Integrität (t_id) und der Signatur einer einzelnen Transaktion.
fn verify_transaction_integrity_and_signature(transaction: &crate::models::voucher::Transaction) -> Result<(), VoucherCoreError> {
    // Überprüfe die t_id
    let mut tx_for_tid_calc = transaction.clone();
    tx_for_tid_calc.t_id = "".to_string();
    tx_for_tid_calc.sender_signature = "".to_string();
    let calculated_tid = get_hash(to_canonical_json(&tx_for_tid_calc)?);
    if transaction.t_id != calculated_tid {
        return Err(ValidationError::InvalidTransaction(format!(
            "Transaction ID {} does not match its content hash.",
            transaction.t_id
        )).into());
    }

    // Überprüfe die Signatur
    let signature_payload = serde_json::json!({
        "prev_hash": transaction.prev_hash,
        "sender_id": transaction.sender_id,
        "t_id": transaction.t_id,
        "t_time": transaction.t_time,
    });
    let signature_payload_hash = get_hash(to_canonical_json(&signature_payload)?);

    let sender_pub_key = get_pubkey_from_user_id(&transaction.sender_id).map_err(|_| {
        ValidationError::InvalidTransactionSenderId(transaction.sender_id.clone())
    })?;

    let signature_bytes = bs58::decode(&transaction.sender_signature)
        .into_vec()
        .map_err(|e| ValidationError::SignatureDecodeError(e.to_string()))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|e| ValidationError::SignatureDecodeError(e.to_string()))?;

    if !verify_ed25519(&sender_pub_key, signature_payload_hash.as_bytes(), &signature) {
        return Err(ValidationError::InvalidTransaction(format!("Invalid signature for transaction {}", transaction.t_id)).into());
    }

    Ok(())
}

/// Berechnet das aktuell verfügbare Guthaben für einen bestimmten Nutzer.
/// Diese Funktion ist öffentlich, damit der `voucher_manager` sie für Vorab-Prüfungen nutzen kann.
pub fn get_spendable_balance(
    voucher: &Voucher,
    user_id: &str,
    standard: &VoucherStandardDefinition,
) -> Result<Decimal, VoucherCoreError> {
    let _decimal_places = standard.validation.amount_decimal_places as u32;
    let mut balance = Decimal::ZERO;

    // Für die schnelle Guthabenprüfung eines bestimmten Nutzers ist nur die letzte Transaktion relevant.
    if let Some(last_tx) = voucher.transactions.last() {
        // Logik nach Ihrem Vorschlag:
        // 1. Prüfe zuerst, ob der User der Empfänger war. Dies deckt auch die `init`-Transaktion korrekt ab.
        if last_tx.recipient_id == user_id {
            balance = Decimal::from_str(&last_tx.amount)?;
        // 2. Wenn nicht, prüfe, ob der User der Sender war.
        } else if last_tx.sender_id == user_id {
            // Sein Guthaben ist der verbleibende Restbetrag (der bei 'None' oder einer vollen Übertragung 0 ist).
            let remaining_str = last_tx
                .sender_remaining_amount
                .as_deref()
                .unwrap_or("0");
            balance = Decimal::from_str(remaining_str)?;
        }
    }

    // KORREKTUR: Die Normalisierung der Skalierung hier ist fehlerhaft und die Ursache der Rechenfehler.
    // `rust_decimal` kann mit Werten unterschiedlicher Skalierung korrekt umgehen.
    // Die Zeile wird entfernt, um die rohen, korrekt geparsten Decimal-Werte zurückzugeben.
    // balance.set_scale(decimal_places)?;
    Ok(balance)
}