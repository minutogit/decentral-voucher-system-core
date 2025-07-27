use crate::models::voucher::{
    Voucher, Creator, NominalValue, Collateral, VoucherStandard, Transaction
};
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use crate::services::crypto_utils::{get_hash, sign_ed25519};
use crate::services::utils::{get_current_timestamp, to_canonical_json};

use ed25519_dalek::SigningKey;
use toml::de::Error as TomlError;
use serde_json;
use chrono::{DateTime, Utc, Datelike, TimeZone};
use std::fmt;

// ... (Der Fehler-Enum und die Funktionen from_json, to_json, load_standard_definition bleiben unverändert) ...
// Definiert die Fehler, die im `voucher_manager`-Modul auftreten können.
#[derive(Debug)]
pub enum VoucherManagerError {
    /// Fehler bei der Serialisierung oder Deserialisierung von JSON.
    Serialization(serde_json::Error),
    /// Fehler beim Parsen von TOML.
    TomlDeserialization(TomlError),
    /// Ein allgemeiner Fehler mit einer Beschreibung.
    Generic(String),
    /// Die angegebene Gültigkeitsdauer erfüllt nicht die Mindestanforderungen des Standards.
    InvalidValidityDuration(String),
}

// Implementiert die Konvertierung von serde_json::Error in unseren benutzerdefinierten Fehlertyp.
impl From<serde_json::Error> for VoucherManagerError {
    fn from(err: serde_json::Error) -> Self {
        VoucherManagerError::Serialization(err)
    }
}

// Implementiert die Konvertierung von toml::de::Error in unseren benutzerdefinierten Fehlertyp.
impl From<TomlError> for VoucherManagerError {
    fn from(err: TomlError) -> Self {
        VoucherManagerError::TomlDeserialization(err)
    }
}
// Ermöglicht die Anzeige des Fehlers als String.
impl fmt::Display for VoucherManagerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VoucherManagerError::TomlDeserialization(e) => write!(f, "TOML Deserialization Error: {}", e),
            VoucherManagerError::Serialization(e) => write!(f, "Serialization Error: {}", e),
            VoucherManagerError::Generic(s) => write!(f, "Voucher Manager Error: {}", s),
            VoucherManagerError::InvalidValidityDuration(s) => write!(f, "Invalid validity duration: {}", s),
        }
    }
}

impl std::error::Error for VoucherManagerError {}

/// Nimmt einen JSON-String entgegen und deserialisiert ihn in ein `Voucher`-Struct.
pub fn from_json(json_str: &str) -> Result<Voucher, VoucherManagerError> {
    let voucher: Voucher = serde_json::from_str(json_str)?;
    Ok(voucher)
}

/// Serialisiert ein `Voucher`-Struct in einen formatierten JSON-String.
pub fn to_json(voucher: &Voucher) -> Result<String, VoucherManagerError> {
    let json_str = serde_json::to_string_pretty(voucher)?;
    Ok(json_str)
}

/// Nimmt einen TOML-String entgegen und deserialisiert ihn in ein `VoucherStandardDefinition`-Struct.
pub fn load_standard_definition(toml_str: &str) -> Result<VoucherStandardDefinition, VoucherManagerError> {
    let definition: VoucherStandardDefinition = toml::from_str(toml_str)?;
    Ok(definition)
}


// KORRIGIERTER BEREICH STARTET HIER

/// Eine Hilfsstruktur, die alle notwendigen Daten zur Erstellung eines neuen Gutscheins bündelt.
/// Dies vereinfacht die Signatur der `create_voucher` Funktion.
pub struct NewVoucherData {
    /// Eine vom Ersteller optional angegebene Gültigkeitsdauer im ISO 8601 Duration Format (z.B. "P1Y").
    pub validity_duration: Option<String>,
    pub non_redeemable_test_voucher: bool,
    pub nominal_value: NominalValue,
    pub collateral: Collateral,
    // Creator-Daten ohne die finale Signatur
    pub creator: Creator,
}

/// Erstellt ein neues, signiertes `Voucher`-Struct.
/// Diese Funktion orchestriert die Erzeugung von Zeitstempeln, Hashes und der initialen Signatur.
/// Sie übernimmt dabei die Regel-basierten Felder aus der `VoucherStandardDefinition`.
///
/// # Arguments
/// * `data` - Die `NewVoucherData`-Struktur mit allen für diesen Gutschein spezifischen Informationen.
/// * `standard_definition` - Die Definition des Standards, nach dem der Gutschein erstellt wird.
/// * `creator_signing_key` - Der private Ed25519-Schlüssel des Erstellers zum Signieren.
///
/// # Returns
/// Ein `Result`, das entweder den vollständig erstellten `Voucher` oder einen `VoucherManagerError` enthält.
pub fn create_voucher(
    data: NewVoucherData,
    standard_definition: &VoucherStandardDefinition, // WICHTIG: Dieser Parameter ist entscheidend!
    creator_signing_key: &SigningKey
) -> Result<Voucher, VoucherManagerError> {
    let creation_dt = Utc::now();
    let creation_date_str = creation_dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);

    // 1. Bestimme die zu verwendende Gültigkeitsdauer.
    let duration_str = data.validity_duration
        .as_deref()
        .or(standard_definition.template.default.default_validity_duration.as_deref())
        .ok_or_else(|| VoucherManagerError::Generic("No validity duration specified and no default found in standard.".to_string()))?;

    // 2. Berechne das `valid_until`-Datum.
    let mut valid_until_dt = add_iso8601_duration(creation_dt, duration_str)?;

    // 3. Wende die Rundungsregel an, falls im Standard definiert.
    if let Some(rounding_str) = &standard_definition.template.fixed.round_up_validity_to {
        valid_until_dt = round_up_date(valid_until_dt, rounding_str)?;
    }
    let valid_until_str = valid_until_dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);

    // 4. PRÜFUNG: Stelle sicher, dass die berechnete Dauer die Mindestanforderung erfüllt.
    if let Some(min_duration_str) = &standard_definition.validation.issuance_minimum_validity_duration {
        let min_duration_dt = add_iso8601_duration(creation_dt, min_duration_str)?;
        if valid_until_dt < min_duration_dt {
            return Err(VoucherManagerError::InvalidValidityDuration(format!(
                "Calculated validity ({}) is less than the required minimum ({}).",
                valid_until_dt.to_rfc3339(),
                min_duration_dt.to_rfc3339()
            )));
        }
    }

    // 5. Erstelle die initiale "init" Transaktion.
    // Der Betrag wird direkt aus den Eingabedaten (`data`) genommen.
    let init_transaction = Transaction {
        t_id: "".to_string(),
        t_type: "init".to_string(),
        t_time: creation_date_str.clone(),
        sender_id: data.creator.id.clone(),
        recipient_id: data.creator.id.clone(),
        amount: data.nominal_value.amount.clone(),
        sender_remaining_amount: None,
        sender_signature: "".to_string(),
    };

    let voucher_standard = VoucherStandard {
        name: standard_definition.metadata.name.clone(),
        uuid: standard_definition.metadata.uuid.clone(),
    };

    let mut final_nominal_value = data.nominal_value;
    final_nominal_value.unit = standard_definition.template.nominal_value.unit.clone();
    final_nominal_value.abbreviation = standard_definition.metadata.abbreviation.clone();

    let mut final_collateral = data.collateral;
    final_collateral.type_ = standard_definition.template.collateral.type_.clone();
    final_collateral.description = standard_definition.template.collateral.description.clone();
    final_collateral.redeem_condition = standard_definition.template.collateral.redeem_condition.clone();

    // 2. Baue ein vorläufiges Voucher-Objekt, das zur Generierung von ID und Signatur verwendet wird.
    // Die Beschreibung wird aus der Vorlage des Standards generiert und der Platzhalter {{amount}} ersetzt.
    let description_template = standard_definition.template.description.clone().unwrap_or_default();
    let final_description = description_template.replace("{{amount}}", &final_nominal_value.amount);

    let mut temp_voucher = Voucher {
        voucher_standard,
        voucher_id: "".to_string(),
        description: final_description,
        primary_redemption_type: standard_definition.template.primary_redemption_type.clone(),
        divisible: standard_definition.template.is_divisible,
        creation_date: creation_date.clone(),
        valid_until,
        non_redeemable_test_voucher: data.non_redeemable_test_voucher,
        nominal_value: final_nominal_value,
        collateral: final_collateral,
        creator: data.creator,
        guarantor_requirements_description: standard_definition
            .template.guarantor_info
            .description
            .clone(),
        guarantor_signatures: vec![],
        needed_guarantors: standard_definition.template.guarantor_info.needed_count,
        transactions: vec![init_transaction],
        additional_signatures: vec![],
    };

    // 3. Update die initiale Transaktion mit einer eigenen ID, BEVOR sie signiert wird.
    let init_transaction_json_for_id = to_canonical_json(&temp_voucher.transactions[0])?;
    let t_id = get_hash(init_transaction_json_for_id);
    temp_voucher.transactions[0].t_id = t_id;

    // 4. Signiere die initiale Transaktion
    let transaction_to_sign_json = to_canonical_json(&temp_voucher.transactions[0])?;
    let transaction_signature_hash = get_hash(transaction_to_sign_json);
    let transaction_signature = sign_ed25519(creator_signing_key, transaction_signature_hash.as_bytes());
    temp_voucher.transactions[0].sender_signature = bs58::encode(transaction_signature.to_bytes()).into_string();

    // 5. Generiere den finalen Hash für die voucher_id und die Signatur.
    // Dies geschieht NACHDEM alle initialen Daten (inkl. signierter Transaktion) final sind.
    let voucher_json_for_signing = to_canonical_json(&temp_voucher)?;
    let voucher_hash_to_sign = get_hash(voucher_json_for_signing);
    
    // Setze die finale voucher_id.
    temp_voucher.voucher_id = voucher_hash_to_sign.clone();

    // 6. Setze die finale Signatur in die Creator-Daten ein.
    let creator_signature = sign_ed25519(creator_signing_key, voucher_hash_to_sign.as_bytes());
    temp_voucher.creator.signature = bs58::encode(creator_signature.to_bytes()).into_string();

    // 7. Gib den finalen, validen Gutschein zurück.
    Ok(temp_voucher)
}