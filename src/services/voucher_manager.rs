use crate::models::voucher::{
    Collateral, Creator, NominalValue, Transaction, Voucher, VoucherStandard,
};
use crate::error::VoucherCoreError;
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use crate::services::voucher_validation::get_spendable_balance;
use crate::services::{decimal_utils, standard_manager};
use crate::services::crypto_utils::{get_hash, sign_ed25519};
use crate::services::utils::{get_current_timestamp, to_canonical_json};

use chrono::{DateTime, Datelike, TimeZone, Timelike, Utc};
use rand::Rng;
use ed25519_dalek::SigningKey;
use rust_decimal::Decimal;
use std::str::FromStr;
use std::fmt;

// Definiert die Fehler, die im `voucher_manager`-Modul auftreten können.
#[derive(Debug)]
pub enum VoucherManagerError {
    /// Der Gutschein ist laut Standard nicht teilbar.
    VoucherNotDivisible,
    /// Das verfügbare Guthaben ist für die Transaktion nicht ausreichend.
    InsufficientFunds { available: Decimal, needed: Decimal },
    /// Der Betrag hat mehr Nachkommastellen als vom Standard erlaubt.
    AmountPrecisionExceeded {
        allowed: u32,
        found: u32,
    },
    /// Die angegebene Gültigkeitsdauer erfüllt nicht die Mindestanforderungen des Standards.
    InvalidValidityDuration(String),
    /// Ein allgemeiner Fehler mit einer Beschreibung.
    Generic(String),
    /// Ein Validierungsfehler aus dem Validierungsmodul ist aufgetreten.
    ValidationError(String),
}

impl fmt::Display for VoucherManagerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VoucherManagerError::VoucherNotDivisible => write!(f, "Voucher is not divisible according to its standard."),
            VoucherManagerError::InsufficientFunds { available, needed } => {
                write!(f, "Insufficient funds: Available: {}, Needed: {}", available, needed)
            }
            VoucherManagerError::AmountPrecisionExceeded { allowed, found } => {
                write!(f, "Amount precision exceeds standard limit. Allowed: {}, Found: {}", allowed, found)
            }
            VoucherManagerError::InvalidValidityDuration(s) => write!(f, "Invalid validity duration: {}", s),
            VoucherManagerError::Generic(s) => write!(f, "Voucher Manager Error: {}", s),
            VoucherManagerError::ValidationError(s) => write!(f, "Validation Error: {}", s),
        }
    }
}

impl std::error::Error for VoucherManagerError {}

/// Nimmt einen JSON-String entgegen und deserialisiert ihn in ein `Voucher`-Struct.
pub fn from_json(json_str: &str) -> Result<Voucher, VoucherCoreError> {
    let voucher: Voucher = serde_json::from_str(json_str)?;
    Ok(voucher)
}

/// Serialisiert ein `Voucher`-Struct in einen formatierten JSON-String.
pub fn to_json(voucher: &Voucher) -> Result<String, VoucherCoreError> {
    let json_str = serde_json::to_string_pretty(voucher)?;
    Ok(json_str)
}

/// Eine Hilfsstruktur, die alle notwendigen Daten zur Erstellung eines neuen Gutscheins bündelt.
#[derive(Default)]
pub struct NewVoucherData {
    pub validity_duration: Option<String>,
    pub non_redeemable_test_voucher: bool,
    pub nominal_value: NominalValue,
    pub collateral: Collateral,
    pub creator: Creator,
}

/// Erstellt ein neues, signiertes `Voucher`-Struct.
///
/// # Arguments
/// * `data` - Die `NewVoucherData`-Struktur mit allen für diesen Gutschein spezifischen Informationen.
/// * `verified_standard` - Die **bereits verifizierte** `VoucherStandardDefinition`.
/// * `standard_hash` - Der **Konsistenz-Hash** des verifizierten Standards.
/// * `creator_signing_key` - Der private Ed25519-Schlüssel des Erstellers zum Signieren.
/// * `lang_preference` - Der bevorzugte Sprachcode (z.B. "de") zur Auswahl des Beschreibungstextes.
///
/// # Returns
/// Ein `Result`, das entweder den vollständig erstellten `Voucher` oder einen `VoucherCoreError` enthält.
pub fn create_voucher(
    data: NewVoucherData,
    verified_standard: &VoucherStandardDefinition,
    standard_hash: &str,
    creator_signing_key: &SigningKey,
    lang_preference: &str,
) -> Result<Voucher, VoucherCoreError> {
    let creation_date_str = get_current_timestamp();
    let nonce_bytes = rand::thread_rng().gen::<[u8; 16]>();
    let nonce = bs58::encode(nonce_bytes).into_string();
    let creation_dt = DateTime::parse_from_rfc3339(&creation_date_str).unwrap().with_timezone(&Utc);

    let duration_str = data.validity_duration
        .as_deref()
        .or(verified_standard.template.default.default_validity_duration.as_deref())
        .ok_or_else(|| VoucherManagerError::Generic("No validity duration specified and no default found in standard.".to_string()))?;

    let initial_valid_until_dt = add_iso8601_duration(creation_dt, duration_str)?;

    if let Some(min_duration_str) = &verified_standard.validation.issuance_minimum_validity_duration {
        let min_duration_dt = add_iso8601_duration(creation_dt, min_duration_str)?;
        if initial_valid_until_dt < min_duration_dt {
            return Err(VoucherManagerError::InvalidValidityDuration(format!(
                "Initial validity ({}) is less than the required minimum ({}).",
                initial_valid_until_dt.to_rfc3339(),
                min_duration_dt.to_rfc3339()
            )).into());
        }
    }

    let final_valid_until_dt = if let Some(rounding_str) = &verified_standard.template.fixed.round_up_validity_to {
        round_up_date(initial_valid_until_dt, rounding_str)?
    } else {
        initial_valid_until_dt
    };
    let valid_until_str = final_valid_until_dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);

    let voucher_standard = VoucherStandard {
        name: verified_standard.metadata.name.clone(),
        uuid: verified_standard.metadata.uuid.clone(),
        standard_definition_hash: standard_hash.to_string(), // NEU: Hash einbetten
    };

    let mut final_nominal_value = data.nominal_value;
    final_nominal_value.unit = verified_standard.template.fixed.nominal_value.unit.clone();
    final_nominal_value.abbreviation = verified_standard.metadata.abbreviation.clone();

    let mut final_collateral = data.collateral;
    final_collateral.type_ = verified_standard.template.fixed.collateral.type_.clone();
    final_collateral.description = verified_standard.template.fixed.collateral.description.clone();
    final_collateral.redeem_condition = verified_standard.template.fixed.collateral.redeem_condition.clone();

    // NEU: Logik zur Auswahl des mehrsprachigen Beschreibungstextes
    let description_template = standard_manager::get_localized_text(
        &verified_standard.template.fixed.description,
        lang_preference
    ).unwrap_or(""); // Fallback auf leeren String, falls Liste leer ist

    let final_description = description_template.replace("{{amount}}", &final_nominal_value.amount);

    let mut temp_voucher = Voucher {
        voucher_standard,
        voucher_id: "".to_string(),
        voucher_nonce: nonce,
        description: final_description,
        primary_redemption_type: verified_standard.template.fixed.primary_redemption_type.clone(),
        divisible: verified_standard.template.fixed.is_divisible,
        creation_date: creation_date_str.clone(),
        valid_until: valid_until_str,
        standard_minimum_issuance_validity: verified_standard.validation.issuance_minimum_validity_duration.clone().unwrap_or_default(),
        non_redeemable_test_voucher: data.non_redeemable_test_voucher,
        nominal_value: final_nominal_value,
        collateral: final_collateral,
        creator: data.creator,
        guarantor_requirements_description: verified_standard.template.fixed.guarantor_info.description.clone(),
        footnote: verified_standard.template.fixed.footnote.clone().unwrap_or_default(),
        guarantor_signatures: vec![],
        needed_guarantors: verified_standard.template.fixed.guarantor_info.needed_count,
        transactions: vec![],
        additional_signatures: vec![],
    };

    let voucher_json_for_signing = to_canonical_json(&temp_voucher)?;
    let voucher_hash = get_hash(voucher_json_for_signing);

    temp_voucher.voucher_id = voucher_hash.clone();
    let creator_signature = sign_ed25519(creator_signing_key, voucher_hash.as_bytes());
    temp_voucher.creator.signature = bs58::encode(creator_signature.to_bytes()).into_string();

    let decimal_places = verified_standard.validation.amount_decimal_places as u32;
    let initial_amount = Decimal::from_str(&temp_voucher.nominal_value.amount)?;

    let mut init_transaction = Transaction {
        t_id: "".to_string(),
        prev_hash: get_hash(format!("{}{}", &temp_voucher.voucher_id, &temp_voucher.voucher_nonce)),
        t_type: "init".to_string(),
        t_time: creation_date_str.clone(),
        sender_id: temp_voucher.creator.id.clone(),
        recipient_id: temp_voucher.creator.id.clone(),
        amount: decimal_utils::format_for_storage(&initial_amount, decimal_places),
        sender_remaining_amount: None,
        sender_signature: "".to_string(),
    };

    let tx_json_for_id = to_canonical_json(&init_transaction)?;
    let final_t_id = get_hash(tx_json_for_id);
    init_transaction.t_id = final_t_id;

    let signature_payload = serde_json::json!({
        "prev_hash": init_transaction.prev_hash,
        "sender_id": init_transaction.sender_id,
        "t_id": init_transaction.t_id
    });
    let signature_payload_json = to_canonical_json(&signature_payload)?;
    let signature_hash = get_hash(signature_payload_json);

    let transaction_signature = sign_ed25519(creator_signing_key, signature_hash.as_bytes());
    init_transaction.sender_signature = bs58::encode(transaction_signature.to_bytes()).into_string();

    temp_voucher.transactions.push(init_transaction);

    Ok(temp_voucher)
}

/// Hilfsfunktion zum Parsen einer einfachen ISO 8601 Duration und Addieren zu einem Datum.
pub fn add_iso8601_duration(start_date: DateTime<Utc>, duration_str: &str) -> Result<DateTime<Utc>, VoucherManagerError> {
    if !duration_str.starts_with('P') || duration_str.len() < 3 {
        return Err(VoucherManagerError::Generic(format!("Invalid ISO 8601 duration format: {}", duration_str)));
    }
    let (value_str, unit) = duration_str.split_at(duration_str.len() - 1);
    let value: u32 = value_str[1..].parse().map_err(|_| VoucherManagerError::Generic(format!("Invalid number in duration: {}", duration_str)))?;
    match unit {
        "Y" => {
            let new_year = start_date.year() + value as i32;
            let new_date = start_date.with_year(new_year).unwrap_or_else(|| {
                Utc.with_ymd_and_hms(new_year, 2, 28, start_date.hour(), start_date.minute(), start_date.second()).unwrap()
            });
            Ok(new_date)
        }
        "M" => {
            let current_month0 = start_date.month0();
            let total_months0 = current_month0 + value;
            let new_year = start_date.year() + (total_months0 / 12) as i32;
            let new_month = (total_months0 % 12) + 1;
            let original_day = start_date.day();
            let days_in_target_month = Utc.with_ymd_and_hms(
                if new_month == 12 { new_year + 1 } else { new_year },
                if new_month == 12 { 1 } else { new_month + 1 },
                1, 0, 0, 0
            ).unwrap()
                .signed_duration_since(Utc.with_ymd_and_hms(new_year, new_month, 1, 0, 0, 0).unwrap())
                .num_days() as u32;
            let new_day = original_day.min(days_in_target_month);
            let new_date = Utc.with_ymd_and_hms(new_year, new_month, new_day, start_date.hour(), start_date.minute(), start_date.second())
                .unwrap()
                .with_nanosecond(start_date.nanosecond())
                .unwrap();
            Ok(new_date)
        }
        "D" => Ok(start_date + chrono::Duration::days(i64::from(value))),
        _ => Err(VoucherManagerError::Generic(format!("Unsupported duration unit in: {}", duration_str))),
    }
}

/// Hilfsfunktion, um ein Datum auf das Ende des Tages, Monats oder Jahres aufzurunden.
pub fn round_up_date(date: DateTime<Utc>, rounding_str: &str) -> Result<DateTime<Utc>, VoucherManagerError> {
    match rounding_str {
        "P1D" => Ok(date.with_hour(23).unwrap().with_minute(59).unwrap().with_second(59).unwrap().with_nanosecond(999_999_999).unwrap()),
        "P1M" => {
            let next_month = if date.month() == 12 { 1 } else { date.month() + 1 };
            let year = if date.month() == 12 { date.year() + 1 } else { date.year() };
            let first_of_next_month = Utc.with_ymd_and_hms(year, next_month, 1, 0, 0, 0).unwrap();
            Ok(first_of_next_month - chrono::Duration::nanoseconds(1))
        }
        "P1Y" => {
            let first_of_next_year = Utc.with_ymd_and_hms(date.year() + 1, 1, 1, 0, 0, 0).unwrap();
            Ok(first_of_next_year - chrono::Duration::nanoseconds(1))
        }
        _ => Err(VoucherManagerError::Generic(format!("Unsupported rounding unit: {}", rounding_str))),
    }
}

/// Erstellt eine neue Transaktion und hängt sie an eine Kopie des Gutscheins an.
pub fn create_transaction(
    voucher: &Voucher,
    standard: &VoucherStandardDefinition,
    sender_id: &str,
    sender_key: &SigningKey,
    recipient_id: &str,
    amount_to_send_str: &str,
) -> Result<Voucher, VoucherCoreError> {
    crate::services::voucher_validation::validate_voucher_against_standard(voucher, standard)?;
    let decimal_places = standard.validation.amount_decimal_places as u32;

    let spendable_balance = get_spendable_balance(voucher, sender_id, standard)?;
    let amount_to_send = Decimal::from_str(amount_to_send_str)?;
    decimal_utils::validate_precision(&amount_to_send, decimal_places)?;

    if amount_to_send <= Decimal::ZERO {
        return Err(VoucherManagerError::Generic("Transaction amount must be positive.".to_string()).into());
    }
    if amount_to_send > spendable_balance {
        return Err(VoucherManagerError::InsufficientFunds {
            available: spendable_balance,
            needed: amount_to_send,
        }.into());
    }

    let (t_type, sender_remaining_amount) = if amount_to_send < spendable_balance {
        if !voucher.divisible {
            return Err(VoucherManagerError::VoucherNotDivisible.into());
        }
        let remaining = spendable_balance - amount_to_send;
        ("split".to_string(), Some(decimal_utils::format_for_storage(&remaining, decimal_places)))
    } else {
        ("transfer".to_string(), None)
    };

    let prev_hash = get_hash(to_canonical_json(voucher.transactions.last().unwrap())?);
    let t_time = get_current_timestamp();

    let mut new_transaction = Transaction {
        t_id: "".to_string(),
        prev_hash,
        t_type,
        t_time,
        sender_id: sender_id.to_string(),
        recipient_id: recipient_id.to_string(),
        amount: decimal_utils::format_for_storage(&amount_to_send, decimal_places),
        sender_remaining_amount,
        sender_signature: "".to_string(),
    };

    let tx_json_for_id = to_canonical_json(&new_transaction)?;
    new_transaction.t_id = get_hash(tx_json_for_id);

    let signature_payload = serde_json::json!({
        "prev_hash": new_transaction.prev_hash,
        "sender_id": new_transaction.sender_id,
        "t_id": new_transaction.t_id
    });
    let signature_payload_hash = get_hash(to_canonical_json(&signature_payload)?);
    let signature = sign_ed25519(sender_key, signature_payload_hash.as_bytes());
    new_transaction.sender_signature = bs58::encode(signature.to_bytes()).into_string();

    let mut new_voucher = voucher.clone();
    new_voucher.transactions.push(new_transaction);

    // SICHERHEITSPATCH: Validiere den *neuen* Gutschein-Zustand, BEVOR er zurückgegeben wird.
    // Dies stellt sicher, dass keine Transaktion erstellt werden kann, die gegen die Regeln des Standards verstößt.
    crate::services::voucher_validation::validate_voucher_against_standard(&new_voucher, standard)?;


    Ok(new_voucher)
}