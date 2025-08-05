use crate::models::voucher::{
    Voucher, Creator, NominalValue, Collateral, VoucherStandard, Transaction
};
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use crate::services::crypto_utils::{get_hash, sign_ed25519};
use crate::services::utils::{get_current_timestamp, to_canonical_json};

use ed25519_dalek::SigningKey;
use toml::de::Error as TomlError;
use serde_json;
use chrono::{DateTime, Utc, Datelike, TimeZone, Timelike};
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
    standard_definition: &VoucherStandardDefinition,
    creator_signing_key: &SigningKey
) -> Result<Voucher, VoucherManagerError> {
    let creation_date_str = get_current_timestamp();
    let creation_dt = DateTime::parse_from_rfc3339(&creation_date_str).unwrap().with_timezone(&Utc);

    // 1. Bestimme die zu verwendende Gültigkeitsdauer.
    let duration_str = data.validity_duration
        .as_deref()
        .or(standard_definition.template.default.default_validity_duration.as_deref())
        .ok_or_else(|| VoucherManagerError::Generic("No validity duration specified and no default found in standard.".to_string()))?;

    // 2. Berechne das initiale `valid_until`-Datum.
    let initial_valid_until_dt = add_iso8601_duration(creation_dt, duration_str)?;

    // 3. PRÜFUNG: Stelle sicher, dass die Dauer die Mindestanforderung erfüllt, BEVOR gerundet wird.
    if let Some(min_duration_str) = &standard_definition.validation.issuance_minimum_validity_duration {
        let min_duration_dt = add_iso8601_duration(creation_dt, min_duration_str)?;
        if initial_valid_until_dt < min_duration_dt {
            return Err(VoucherManagerError::InvalidValidityDuration(format!(
                "Initial validity ({}) is less than the required minimum ({}).",
                initial_valid_until_dt.to_rfc3339(),
                min_duration_dt.to_rfc3339()
            )));
        }
    }

    // 4. Wende die Rundungsregel an, falls vorhanden, NACHDEM die Prüfung bestanden wurde.
    let final_valid_until_dt = if let Some(rounding_str) = &standard_definition.template.fixed.round_up_validity_to {
        round_up_date(initial_valid_until_dt, rounding_str)?
    } else {
        initial_valid_until_dt
    };
    let valid_until_str = final_valid_until_dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);

    let voucher_standard = VoucherStandard {
        name: standard_definition.metadata.name.clone(),
        uuid: standard_definition.metadata.uuid.clone(),
    };

    let mut final_nominal_value = data.nominal_value;
    final_nominal_value.unit = standard_definition.template.fixed.nominal_value.unit.clone();
    final_nominal_value.abbreviation = standard_definition.metadata.abbreviation.clone();

    let mut final_collateral = data.collateral;
    final_collateral.type_ = standard_definition.template.fixed.collateral.type_.clone();
    final_collateral.description = standard_definition.template.fixed.collateral.description.clone();
    final_collateral.redeem_condition = standard_definition.template.fixed.collateral.redeem_condition.clone();

    let description_template = standard_definition.template.fixed.description.clone().unwrap_or_default();
    let final_description = description_template.replace("{{amount}}", &final_nominal_value.amount);

    // Erstelle einen temporären Gutschein OHNE Transaktionen, um die voucher_id zu erzeugen.
    let mut temp_voucher = Voucher {
        voucher_standard,
        voucher_id: "".to_string(),
        description: final_description,
        primary_redemption_type: standard_definition.template.fixed.primary_redemption_type.clone(),
        divisible: standard_definition.template.fixed.is_divisible,
        creation_date: creation_date_str.clone(), // Klonen, um Ownership zu behalten
        valid_until: valid_until_str,
        standard_minimum_issuance_validity: standard_definition.validation.issuance_minimum_validity_duration.clone().unwrap_or_default(),
        non_redeemable_test_voucher: data.non_redeemable_test_voucher,
        nominal_value: final_nominal_value,
        collateral: final_collateral,
        creator: data.creator,
        guarantor_requirements_description: standard_definition
            .template.fixed.guarantor_info
            .description
            .clone(),
        guarantor_signatures: vec![],
        needed_guarantors: standard_definition.template.fixed.guarantor_info.needed_count,
        transactions: vec![], // Wichtig: Transaktionen sind hier leer!
        additional_signatures: vec![],
    };

    // Erzeuge den Hash für die voucher_id und die Signatur des Erstellers.
    let voucher_json_for_signing = to_canonical_json(&temp_voucher)?;
    let voucher_hash = get_hash(voucher_json_for_signing);
    
    // Setze die finale voucher_id und die Signatur des Erstellers.
    temp_voucher.voucher_id = voucher_hash.clone();
    let creator_signature = sign_ed25519(creator_signing_key, voucher_hash.as_bytes());
    temp_voucher.creator.signature = bs58::encode(creator_signature.to_bytes()).into_string();

    // JETZT: Erstelle und signiere die 'init' Transaktion, die sich auf die finale voucher_id bezieht.
    let mut init_transaction = Transaction {
        t_id: "".to_string(), // Wird im nächsten Schritt berechnet
        prev_hash: get_hash(&temp_voucher.voucher_id),
        t_type: "init".to_string(),
        t_time: creation_date_str.clone(),
        sender_id: temp_voucher.creator.id.clone(),
        recipient_id: temp_voucher.creator.id.clone(),
        amount: temp_voucher.nominal_value.amount.clone(),
        sender_remaining_amount: None,
        sender_signature: "".to_string(), // Wird im nächsten Schritt berechnet
    };

    // Berechne die t_id aus der Transaktion (ohne t_id und Signatur)
    let tx_json_for_id = to_canonical_json(&init_transaction)?;
    let final_t_id = get_hash(tx_json_for_id);
    init_transaction.t_id = final_t_id;

    // Erstelle die Daten für die Transaktionssignatur (JSON-Objekt)
    let signature_payload = serde_json::json!({
        "prev_hash": init_transaction.prev_hash,
        "sender_id": init_transaction.sender_id,
        "t_id": init_transaction.t_id,
        "t_time": init_transaction.t_time
    });
    let signature_payload_json = to_canonical_json(&signature_payload)?;
    let signature_hash = get_hash(signature_payload_json);

    // Signiere den Hash der Signatur-Daten
    let transaction_signature = sign_ed25519(creator_signing_key, signature_hash.as_bytes());
    init_transaction.sender_signature = bs58::encode(transaction_signature.to_bytes()).into_string();

    // Füge die finale, signierte Transaktion zum Gutschein hinzu.
    temp_voucher.transactions.push(init_transaction);

    Ok(temp_voucher)
}


/// Hilfsfunktion zum Parsen einer einfachen ISO 8601 Duration und Addieren zu einem Datum.
/// Unterstützt nur P...Y, P...M, P...D.
fn add_iso8601_duration(start_date: DateTime<Utc>, duration_str: &str) -> Result<DateTime<Utc>, VoucherManagerError> {
    if !duration_str.starts_with('P') || duration_str.len() < 3 {
        return Err(VoucherManagerError::Generic(format!("Invalid ISO 8601 duration format: {}", duration_str)));
    }

    let (value_str, unit) = duration_str.split_at(duration_str.len() - 1);
    let value: u32 = value_str[1..].parse().map_err(|_| VoucherManagerError::Generic(format!("Invalid number in duration: {}", duration_str)))?;

    match unit {
        "Y" => Ok(start_date + chrono::Duration::days(i64::from(value) * 365)), // Vereinfachung
        "M" => Ok(start_date + chrono::Duration::days(i64::from(value) * 30)), // Vereinfachung
        "D" => Ok(start_date + chrono::Duration::days(i64::from(value))),
        _ => Err(VoucherManagerError::Generic(format!("Unsupported duration unit in: {}", duration_str))),
    }
}

/// Hilfsfunktion, um ein Datum auf das Ende des Tages, Monats oder Jahres aufzurunden.
fn round_up_date(date: DateTime<Utc>, rounding_str: &str) -> Result<DateTime<Utc>, VoucherManagerError> {
    match rounding_str {
        "P1D" => { // Ende des Tages
            Ok(date.with_hour(23).unwrap()
                .with_minute(59).unwrap()
                .with_second(59).unwrap()
                .with_nanosecond(999_999_999).unwrap())
        }
        "P1M" => { // Ende des Monats
            let next_month = if date.month() == 12 { 1 } else { date.month() + 1 };
            let year = if date.month() == 12 { date.year() + 1 } else { date.year() };
            let first_of_next_month = Utc.with_ymd_and_hms(year, next_month, 1, 0, 0, 0).unwrap();
            Ok(first_of_next_month - chrono::Duration::nanoseconds(1))
        }
        "P1Y" => { // Ende des Jahres
            let first_of_next_year = Utc.with_ymd_and_hms(date.year() + 1, 1, 1, 0, 0, 0).unwrap();
            Ok(first_of_next_year - chrono::Duration::nanoseconds(1))
        }
        _ => Err(VoucherManagerError::Generic(format!("Unsupported rounding unit: {}", rounding_str))),
    }
}