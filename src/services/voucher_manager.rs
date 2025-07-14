//! # voucher_manager.rs
//!
//! Dieses Modul stellt die Kernlogik für die Verwaltung von Gutscheinen bereit.
//! Es enthält Funktionen zum Erstellen, Serialisieren und Deserialisieren
//! von `Voucher`- und `VoucherStandardDefinition`-Strukturen.

use crate::models::voucher::{
    Voucher, Creator, NominalValue, Collateral, VoucherStandard, Transaction
};
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use crate::services::crypto_utils::{get_hash, sign_ed25519};
use crate::services::utils::{get_current_timestamp, get_timestamp};

use ed25519_dalek::SigningKey;
use serde_json;
use std::fmt;

/// Definiert die Fehler, die im `voucher_manager`-Modul auftreten können.
#[derive(Debug)]
pub enum VoucherManagerError {
    /// Fehler bei der Serialisierung oder Deserialisierung von JSON.
    Serialization(serde_json::Error),
    /// Ein allgemeiner Fehler mit einer Beschreibung.
    Generic(String),
}

// Implementiert die Konvertierung von serde_json::Error in unseren benutzerdefinierten Fehlertyp.
impl From<serde_json::Error> for VoucherManagerError {
    fn from(err: serde_json::Error) -> Self {
        VoucherManagerError::Serialization(err)
    }
}

// Ermöglicht die Anzeige des Fehlers als String.
impl fmt::Display for VoucherManagerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VoucherManagerError::Serialization(e) => write!(f, "Serialization Error: {}", e),
            VoucherManagerError::Generic(s) => write!(f, "Voucher Manager Error: {}", s),
        }
    }
}

impl std::error::Error for VoucherManagerError {}

/// Nimmt einen JSON-String entgegen und deserialisiert ihn in ein `Voucher`-Struct.
///
/// # Arguments
/// * `json_str` - Der JSON-String, der den Gutschein repräsentiert.
///
/// # Returns
/// Ein `Result`, das entweder das `Voucher`-Struct oder einen `VoucherManagerError` enthält.
pub fn from_json(json_str: &str) -> Result<Voucher, VoucherManagerError> {
    let voucher: Voucher = serde_json::from_str(json_str)?;
    Ok(voucher)
}

/// Serialisiert ein `Voucher`-Struct in einen formatierten JSON-String.
///
/// # Arguments
/// * `voucher` - Eine Referenz auf das zu serialisierende `Voucher`-Struct.
///
/// # Returns
/// Ein `Result`, das entweder den JSON-String oder einen `VoucherManagerError` enthält.
pub fn to_json(voucher: &Voucher) -> Result<String, VoucherManagerError> {
    let json_str = serde_json::to_string_pretty(voucher)?;
    Ok(json_str)
}

/// Nimmt einen JSON-String entgegen und deserialisiert ihn in ein `VoucherStandardDefinition`-Struct.
/// Diese Funktion wird verwendet, um die "Regelwerke" der Gutscheine zu laden.
///
/// # Arguments
/// * `json_str` - Der JSON-String, der die Gutschein-Standard-Definition repräsentiert.
///
/// # Returns
/// Ein `Result`, das entweder das `VoucherStandardDefinition`-Struct oder einen `VoucherManagerError` enthält.
pub fn load_standard_definition(json_str: &str) -> Result<VoucherStandardDefinition, VoucherManagerError> {
    let definition: VoucherStandardDefinition = serde_json::from_str(json_str)?;
    Ok(definition)
}

/// Eine Hilfsstruktur, die alle notwendigen Daten zur Erstellung eines neuen Gutscheins bündelt.
/// Dies vereinfacht die Signatur der `create_voucher` Funktion.
pub struct NewVoucherData {
    pub voucher_standard: VoucherStandard,
    pub description: String,
    pub divisible: bool,
    pub years_valid: i32,
    pub non_redeemable_test_voucher: bool,
    pub nominal_value: NominalValue,
    pub collateral: Collateral,
    // Creator-Daten ohne die finale Signatur
    pub creator: Creator,
    pub needed_guarantors: i64,
}

/// Erstellt ein neues, signiertes `Voucher`-Struct.
/// Diese Funktion orchestriert die Erzeugung von Zeitstempeln, Hashes und der initialen Signatur.
///
/// # Arguments
/// * `data` - Die `NewVoucherData`-Struktur mit allen erforderlichen Informationen.
/// * `creator_signing_key` - Der private Ed25519-Schlüssel des Erstellers zum Signieren.
///
/// # Returns
/// Ein `Result`, das entweder den vollständig erstellten `Voucher` oder einen `VoucherManagerError` enthält.
pub fn create_voucher(
    data: NewVoucherData,
    creator_signing_key: &SigningKey,
) -> Result<Voucher, VoucherManagerError> {
    let creation_date = get_current_timestamp();
    let valid_until = get_timestamp(data.years_valid, true);

    // 1. Erstelle die initiale "init" Transaktion.
    // Bei der Erstellung gehört der Gutschein vollständig dem Ersteller.
    let init_transaction = Transaction {
        t_id: "".to_string(), // Wird später basierend auf dem Inhalt gesetzt
        t_type: "init".to_string(),
        t_time: creation_date.clone(),
        sender_id: data.creator.id.clone(),
        recipient_id: data.creator.id.clone(),
        amount: data.nominal_value.amount.clone(),
        sender_remaining_amount: None,
        sender_signature: "".to_string(), // Wird ebenfalls später signiert
    };

    // 2. Baue ein vorläufiges Voucher-Objekt, das zur Generierung von ID und Signatur verwendet wird.
    // Die Felder für `voucher_id` und `signature` sind hier noch leer.
    let mut temp_voucher = Voucher {
        voucher_standard: data.voucher_standard,
        voucher_id: "".to_string(),
        description: data.description,
        divisible: data.divisible,
        creation_date: creation_date.clone(),
        valid_until,
        non_redeemable_test_voucher: data.non_redeemable_test_voucher,
        nominal_value: data.nominal_value,
        collateral: data.collateral,
        creator: data.creator, // Creator-Daten ohne Signatur
        guarantor_signatures: vec![],
        needed_guarantors: data.needed_guarantors,
        transactions: vec![init_transaction],
        additional_signatures: vec![],
    };

    // 3. Generiere die eindeutige voucher_id durch Hashing des vorläufigen Objekts.
    // Dies stellt sicher, dass die ID deterministisch aus dem Inhalt abgeleitet wird.
    let voucher_json_for_id = serde_json::to_string(&temp_voucher)?;
    let voucher_id = get_hash(voucher_json_for_id);
    temp_voucher.voucher_id = voucher_id.clone();

    // Update die initiale Transaktion mit einer eigenen ID
    let init_transaction_json_for_id = serde_json::to_string(&temp_voucher.transactions[0])?;
    let t_id = get_hash(init_transaction_json_for_id);
    temp_voucher.transactions[0].t_id = t_id;

    // 4. Signiere die initiale Transaktion
    let transaction_to_sign_json = serde_json::to_string(&temp_voucher.transactions[0])?;
    let transaction_signature_hash = get_hash(&transaction_to_sign_json);
    let transaction_signature = sign_ed25519(creator_signing_key, transaction_signature_hash.as_bytes());
    temp_voucher.transactions[0].sender_signature = bs58::encode(transaction_signature.to_bytes()).into_string();

    // 5. Generiere die finale Signatur des Erstellers für den gesamten Gutschein.
    // Die Signatur deckt alle initialen Daten, einschließlich der nun gesetzten voucher_id, ab.
    let voucher_json_for_signing = serde_json::to_string(&temp_voucher)?;
    let voucher_hash_to_sign = get_hash(voucher_json_for_signing);
    let creator_signature = sign_ed25519(creator_signing_key, voucher_hash_to_sign.as_bytes());

    // 6. Setze die finale Signatur in die Creator-Daten ein.
    temp_voucher.creator.signature = bs58::encode(creator_signature.to_bytes()).into_string();

    // 7. Gib den finalen, validen Gutschein zurück.
    Ok(temp_voucher)
}