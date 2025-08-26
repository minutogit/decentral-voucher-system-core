use crate::models::voucher::{
    Collateral, Creator, NominalValue, Transaction, Voucher, VoucherStandard,
};
use crate::error::VoucherCoreError;
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use crate::services::voucher_validation::get_spendable_balance;
use crate::services::decimal_utils;
use crate::services::crypto_utils::{get_hash, sign_ed25519};
use crate::services::utils::{get_current_timestamp, to_canonical_json};

use chrono::{DateTime, Datelike, TimeZone, Timelike, Utc};
// use toml::de::Error as TomlError; // ungenutzt
use ed25519_dalek::SigningKey;
use rust_decimal::Decimal;
use std::str::FromStr;
use std::fmt;

// Definiert die Fehler, die im `voucher_manager`-Modul auftreten können.
#[derive(Debug)]
pub enum VoucherManagerError {
    // AmountConversion wird jetzt direkt in VoucherCoreError behandelt
    // TomlDeserialization(TomlError), // Wird jetzt direkt in VoucherCoreError behandelt
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
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
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

/// Nimmt einen TOML-String entgegen und deserialisiert ihn in ein `VoucherStandardDefinition`-Struct.
pub fn load_standard_definition(toml_str: &str) -> Result<VoucherStandardDefinition, VoucherCoreError> {
    let definition: VoucherStandardDefinition = toml::from_str(toml_str)?;
    Ok(definition)
}

/// Eine Hilfsstruktur, die alle notwendigen Daten zur Erstellung eines neuen Gutscheins bündelt.
/// Dies vereinfacht die Signatur der `create_voucher` Funktion.
#[derive(Default)]
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
) -> Result<Voucher, VoucherCoreError> {
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
            )).into());
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
        footnote: standard_definition.template.fixed.footnote.clone().unwrap_or_default(),
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
    let decimal_places = standard_definition.validation.amount_decimal_places as u32;
    let initial_amount = Decimal::from_str(&temp_voucher.nominal_value.amount)?;

    let mut init_transaction = Transaction {
        t_id: "".to_string(), // Wird im nächsten Schritt berechnet
        prev_hash: get_hash(&temp_voucher.voucher_id),
        t_type: "init".to_string(),
        t_time: creation_date_str.clone(),
        sender_id: temp_voucher.creator.id.clone(),
        recipient_id: temp_voucher.creator.id.clone(),
        amount: decimal_utils::format_for_storage(&initial_amount, decimal_places),
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
/// Unterstützt P...Y, P...M, P...D und behandelt Schaltjahre/Monatslängen korrekt.
pub fn add_iso8601_duration(start_date: DateTime<Utc>, duration_str: &str) -> Result<DateTime<Utc>, VoucherManagerError> {
    if !duration_str.starts_with('P') || duration_str.len() < 3 {
        return Err(VoucherManagerError::Generic(format!("Invalid ISO 8601 duration format: {}", duration_str)));
    }

    let (value_str, unit) = duration_str.split_at(duration_str.len() - 1);
    let value: u32 = value_str[1..].parse().map_err(|_| VoucherManagerError::Generic(format!("Invalid number in duration: {}", duration_str)))?;

    match unit {
        "Y" => {
            let new_year = start_date.year() + value as i32;
            // Versuche, das Datum im neuen Jahr zu erstellen. `with_year` behandelt die meisten Fälle.
            // Das Hauptproblem ist der 29. Februar in einem Schaltjahr, wenn das Zieljahr keines ist.
            // In diesem Fall gibt `with_year` `None` zurück.
            let new_date = start_date.with_year(new_year).unwrap_or_else(|| {
                // Wenn wir von einem 29. Februar in einem Nicht-Schaltjahr landen,
                // setzen wir das Datum auf den 28. Februar des Zieljahres.
                Utc.with_ymd_and_hms(new_year, 2, 28, start_date.hour(), start_date.minute(), start_date.second()).unwrap()
            });
            Ok(new_date)
        }
        "M" => {
            let current_month0 = start_date.month0(); // 0-indiziert für einfache Berechnung
            let total_months0 = current_month0 + value;
            
            let new_year = start_date.year() + (total_months0 / 12) as i32;
            let new_month = (total_months0 % 12) + 1;
            let original_day = start_date.day();

            // Ermittle den letzten Tag des Zielmonats, um ein Überlaufen zu verhindern
            // (z.B. 31. Januar + 1 Monat soll nicht der 31. Februar sein).
            let days_in_target_month = Utc.with_ymd_and_hms(
                    if new_month == 12 { new_year + 1 } else { new_year },
                    if new_month == 12 { 1 } else { new_month + 1 },
                    1, 0, 0, 0
                ).unwrap()
                .signed_duration_since(Utc.with_ymd_and_hms(new_year, new_month, 1, 0, 0, 0).unwrap())
                .num_days() as u32;

            let new_day = original_day.min(days_in_target_month);

            // KORREKTUR: Konstruiere das Datum sicher aus den Komponenten, anstatt das Originaldatum
            // schrittweise zu ändern, was bei ungültigen Zwischendaten (z.B. "31. Februar") zu einem Panic führt.
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

/// Erstellt eine neue Transaktion und hängt sie an eine Kopie des Gutscheins an.
///
/// Die Funktion ermittelt automatisch, ob es sich um einen **vollen Transfer** oder einen **Split** handelt,
/// basierend auf dem Vergleich des zu sendenden Betrags mit dem verfügbaren Guthaben.
/// - Bei einem **vollen Transfer** werden `t_type` und `sender_remaining_amount` weggelassen.
/// - Bei einem **Split** wird `t_type` auf "split" gesetzt und `sender_remaining_amount` enthält den Restbetrag.
///
/// # Arguments
/// * `voucher` - Der aktuelle Zustand des Gutscheins vor der Transaktion.
/// * `standard` - Die Definition des Standards, um Regeln wie `amount_decimal_places` zu prüfen.
/// * `sender_id` - Die ID des Nutzers, der die Transaktion durchführt.
/// * `sender_key` - Der Signierschlüssel des Senders.
/// * `recipient_id` - Die ID des Empfängers des Teilbetrags.
/// * `amount_to_send_str` - Der zu sendende Betrag als String.
///
/// # Returns
/// Ein `Result`, das entweder den neuen, aktualisierten `Voucher` oder einen `VoucherManagerError` enthält.
pub fn create_transaction(
    voucher: &Voucher,
    standard: &VoucherStandardDefinition,
    sender_id: &str,
    sender_key: &SigningKey,
    recipient_id: &str,
    amount_to_send_str: &str,
) -> Result<Voucher, VoucherCoreError> {
    // SICHERHEITSPATCH: Validiere den gesamten Gutschein-Zustand, bevor eine neue Transaktion erstellt wird.
    // Dies verhindert, dass auf einer manipulierten oder ungültigen Transaktionskette aufgebaut wird.
    crate::services::voucher_validation::validate_voucher_against_standard(voucher, standard)?;
    let decimal_places = standard.validation.amount_decimal_places as u32;
 
    // 1. Aktuell verfügbares Guthaben für den Sender berechnen.
    let spendable_balance = get_spendable_balance(voucher, sender_id, standard)?;

    // 2. Zu sendenden Betrag parsen und mit dem Guthaben vergleichen.
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

    // 3. Fallunterscheidung: Split oder voller Transfer?
    let (t_type, sender_remaining_amount) = if amount_to_send < spendable_balance {
        // Dies ist ein Split.
        if !voucher.divisible {
            return Err(VoucherManagerError::VoucherNotDivisible.into());
        }
        let remaining = spendable_balance - amount_to_send;
        ("split".to_string(), Some(decimal_utils::format_for_storage(&remaining, decimal_places)))
    } else {
        // Dies ist ein voller Transfer.
        ("".to_string(), None)
    };

    // 4. Neue Transaktion erstellen.
    let prev_hash = get_hash(to_canonical_json(voucher.transactions.last().unwrap())?);
    let t_time = get_current_timestamp();

    let mut new_transaction = Transaction {
        t_id: "".to_string(), // Wird später berechnet
        prev_hash,
        t_type,
        t_time,
        sender_id: sender_id.to_string(),
        recipient_id: recipient_id.to_string(),
        amount: decimal_utils::format_for_storage(&amount_to_send, decimal_places),
        sender_remaining_amount,
        sender_signature: "".to_string(), // Wird später berechnet
    };

    // 5. t_id und Signatur für die neue Transaktion generieren.
    let tx_json_for_id = to_canonical_json(&new_transaction)?;
    new_transaction.t_id = get_hash(tx_json_for_id);

    let signature_payload = serde_json::json!({
        "prev_hash": new_transaction.prev_hash,
        "sender_id": new_transaction.sender_id,
        "t_id": new_transaction.t_id,
        "t_time": new_transaction.t_time
    });
    let signature_payload_hash = get_hash(to_canonical_json(&signature_payload)?);
    let signature = sign_ed25519(sender_key, signature_payload_hash.as_bytes());
    new_transaction.sender_signature = bs58::encode(signature.to_bytes()).into_string();

    // 6. Neuen Gutschein-Zustand erstellen.
    let mut new_voucher = voucher.clone();
    new_voucher.transactions.push(new_transaction);

    Ok(new_voucher)
}
