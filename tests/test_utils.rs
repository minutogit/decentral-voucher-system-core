//! # tests/test_utils.rs
//!
//! Hilfsfunktionen für die Integrationstests, um Boilerplate-Code zu reduzieren.

use bip39::Language;
use std::fs;
use std::path::PathBuf;
use voucher_lib::models::{
    conflict::{FingerprintStore, ProofStore},
    profile::{BundleMetadataStore, UserIdentity, UserProfile, VoucherStore},
};
use voucher_lib::models::signature::DetachedSignature;
use voucher_lib::models::voucher::{Address, GuarantorSignature, Voucher};
use voucher_lib::models::voucher_standard_definition::VoucherStandardDefinition;
use voucher_lib::services::crypto_utils::{
    self,
    create_user_id, generate_ed25519_keypair_for_tests,
};
use voucher_lib::services::secure_container_manager;
use voucher_lib::services::signature_manager;
use voucher_lib::services::voucher_manager::{self, NewVoucherData};
use voucher_lib::wallet::Wallet;
use voucher_lib::{
    models::{
        profile::VoucherStatus,
        voucher::{Creator, NominalValue},
    },
    VoucherCoreError,
};

// --- Neue Hilfsfunktionen ---
#[allow(dead_code)]
/// Generiert eine neue, valide 12-Wort BIP39 Mnemonic-Phrase für Tests.
pub fn generate_valid_mnemonic() -> String {
    crypto_utils::generate_mnemonic(12, Language::English)
        .expect("Test mnemonic generation should not fail")
}

// --- Öffentliche Hilfsfunktionen für Integrationstests ---

/// Lädt eine Standard-Definition aus dem `voucher_standards`-Verzeichnis.
pub fn load_standard_definition(filename: &str) -> Result<VoucherStandardDefinition, anyhow::Error> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("voucher_standards");
    path.push(filename);
    let content = fs::read_to_string(path)?;
    let standard: VoucherStandardDefinition = toml::from_str(&content)?;
    Ok(standard)
}

/// Erstellt ein neues Test-Wallet aus einem deterministischen Seed.
#[allow(dead_code)]
pub fn create_test_wallet(
    seed_phrase_extra: &str,
) -> Result<(Wallet, UserIdentity), VoucherCoreError> {
    // Verwende die dedizierte Test-Funktion, die kein valides Mnemonic-Format benötigt.
    // Sie erzeugt deterministisch einen Schlüssel aus dem Seed-String.
    let (public_key, signing_key) =
        generate_ed25519_keypair_for_tests(Some(seed_phrase_extra));
    let user_id = create_user_id(&public_key, Some("test"))
        .map_err(|e| VoucherCoreError::Crypto(e.to_string()))?;

    let identity = UserIdentity {
        signing_key,
        public_key,
        user_id: user_id.clone(),
    };

    let profile = UserProfile { user_id };

    let wallet = Wallet {
        profile,
        voucher_store: VoucherStore::default(),
        bundle_meta_store: BundleMetadataStore::default(),
        fingerprint_store: FingerprintStore::default(),
        proof_store: ProofStore::default(),
    };

    Ok((wallet, identity))
}

/// Erstellt ein Test-Wallet und fügt sofort einen Gutschein mit dem angegebenen Betrag hinzu.
#[allow(dead_code)]
pub fn create_test_wallet_with_voucher(
    seed_phrase_extra: &str,
    amount: &str,
    standard: &VoucherStandardDefinition,
    with_valid_guarantors: bool,
) -> Result<(Wallet, UserIdentity, String), VoucherCoreError> {
    let (mut wallet, identity) = create_test_wallet(seed_phrase_extra)?;

    // Erstelle die Creator- und NominalValue-Strukturen, die für NewVoucherData benötigt werden.
    let creator_info = Creator {
        id: identity.user_id.clone(),
        first_name: "Test".to_string(),
        last_name: "User".to_string(),
        address: Address::default(),
        ..Default::default()
    };

    let nominal_value_info = NominalValue {
        amount: amount.to_string(),
        ..Default::default()
    };

    let new_voucher_data = NewVoucherData {
        creator: creator_info,
        nominal_value: nominal_value_info,
        ..Default::default()
    };

    let mut voucher = voucher_manager::create_voucher(
        new_voucher_data,
        standard,
        &identity.signing_key,
    )?;

    if with_valid_guarantors {
        let (_guarantor1_wallet, guarantor1_identity) = create_test_wallet("guarantor1")?;
        let (_guarantor2_wallet, guarantor2_identity) = create_test_wallet("guarantor2")?;

        let sig_data1 =
            create_guarantor_signature_data(&guarantor1_identity, "1", &voucher.voucher_id);
        let sig_data2 =
            create_guarantor_signature_data(&guarantor2_identity, "2", &voucher.voucher_id);

        let signed_sig1 = signature_manager::complete_and_sign_detached_signature(
            sig_data1,
            &voucher.voucher_id,
            &guarantor1_identity,
        )?;
        let signed_sig2 = signature_manager::complete_and_sign_detached_signature(
            sig_data2,
            &voucher.voucher_id,
            &guarantor2_identity,
        )?;

        if let DetachedSignature::Guarantor(s) = signed_sig1 {
            voucher.guarantor_signatures.push(s);
        }
        if let DetachedSignature::Guarantor(s) = signed_sig2 {
            voucher.guarantor_signatures.push(s);
        }
    }

    let local_id = Wallet::calculate_local_instance_id(&voucher, &identity.user_id)?;
    wallet
        .add_voucher_to_store(voucher, VoucherStatus::Active, &identity.user_id)?;

    Ok((wallet, identity, local_id))
}

/// Erstellt die Metadaten für eine Bürgen-Signatur.
/// Die eigentliche Signatur wird erst von der zu testenden Funktion hinzugefügt.
pub fn create_guarantor_signature_data(
    guarantor_identity: &UserIdentity,
    gender: &str,
    voucher_id: &str,
) -> DetachedSignature {
    let data = GuarantorSignature {
        guarantor_id: guarantor_identity.user_id.clone(),
        first_name: "Guarantor".to_string(),
        last_name: "Test".to_string(),
        gender: gender.to_string(),
        voucher_id: voucher_id.to_string(),
        signature_id: String::new(),
        signature: String::new(),
        signature_time: String::new(),
        organization: None,
        community: None,
        address: None,
        email: None,
        phone: None,
        coordinates: None,
        url: None,
    };
    DetachedSignature::Guarantor(data)
}

/// Eine Helferfunktion, um einen SecureContainer für Testzwecke zu öffnen.
pub fn debug_open_container(
    container_bytes: &[u8],
    recipient_identity: &UserIdentity,
) -> Result<(Voucher, String), VoucherCoreError> {
    let container: voucher_lib::models::secure_container::SecureContainer =
        serde_json::from_slice(container_bytes)?;
    let (payload, _) =
        secure_container_manager::open_secure_container(&container, recipient_identity)?;
    let voucher: Voucher = serde_json::from_slice(&payload)?;
    let sender_id = container.sender_id;
    Ok((voucher, sender_id))
}


// --- Bestehende interne Tests für die `utils`-Services ---

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Datelike, Timelike, Utc};
    use regex::Regex;
    use voucher_lib::services::utils::{get_current_timestamp, get_timestamp};

    // Helper function to parse the timestamp string and check basic format
    fn parse_and_validate_format(timestamp_str: &str) -> Result<DateTime<Utc>, String> {
        // Regex to validate the ISO 8601 format with microseconds and Z suffix
        // Example: 2023-10-27T10:30:55.123456Z
        let re = Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$").unwrap();
        if !re.is_match(timestamp_str) {
            return Err(format!("Timestamp '{}' does not match expected format YYYY-MM-DDTHH:MM:SS.ffffffZ", timestamp_str));
        }

        // Try parsing the timestamp
        DateTime::parse_from_rfc3339(timestamp_str)
            .map(|dt| dt.with_timezone(&Utc))
            .map_err(|e| format!("Failed to parse timestamp '{}': {}", timestamp_str, e))
    }

    #[test]
    fn test_get_current_timestamp_format() {
        let timestamp = get_current_timestamp();
        println!("Current Timestamp: {}", timestamp);
        assert!(parse_and_validate_format(&timestamp).is_ok());
    }

    #[test]
    fn test_get_timestamp_add_years() {
        let years_to_add = 2;
        let now = Utc::now();
        let expected_year = now.year() + years_to_add;

        let timestamp = get_timestamp(years_to_add, false);
        println!("Timestamp (+{} years): {}", years_to_add, timestamp);
        let parsed_dt = parse_and_validate_format(&timestamp).expect("Timestamp should be valid");

        assert_eq!(parsed_dt.year(), expected_year, "Year should be incremented correctly");
        // We can't easily assert the exact day/month/time due to potential leap year adjustments
        // and the exact moment Utc::now() is called, but we check the year.
    }

    #[test]
    fn test_get_timestamp_end_of_current_year() {
        let now = Utc::now();
        let current_year = now.year();

        let timestamp = get_timestamp(0, true);
        println!("Timestamp (End of Current Year {}): {}", current_year, timestamp);
        let parsed_dt = parse_and_validate_format(&timestamp).expect("Timestamp should be valid");

        assert_eq!(parsed_dt.year(), current_year, "Year should be the current year");
        assert_eq!(parsed_dt.month(), 12, "Month should be December");
        assert_eq!(parsed_dt.day(), 31, "Day should be 31st");
        assert_eq!(parsed_dt.hour(), 23, "Hour should be 23");
        assert_eq!(parsed_dt.minute(), 59, "Minute should be 59");
        assert_eq!(parsed_dt.second(), 59, "Second should be 59");
        // Check for 999_999 microseconds (which corresponds to 999_999_000 nanoseconds)
        assert_eq!(parsed_dt.nanosecond(), 999_999_000, "Nanoseconds should indicate the last microsecond");
    }

    #[test]
    fn test_get_timestamp_end_of_future_year() {
        let years_to_add = 3;
        let now = Utc::now();
        let expected_year = now.year() + years_to_add;

        let timestamp = get_timestamp(years_to_add, true);
        println!("Timestamp (End of Future Year {}): {}", expected_year, timestamp);
        let parsed_dt = parse_and_validate_format(&timestamp).expect("Timestamp should be valid");

        assert_eq!(parsed_dt.year(), expected_year, "Year should be the future year");
        assert_eq!(parsed_dt.month(), 12, "Month should be December");
        assert_eq!(parsed_dt.day(), 31, "Day should be 31st");
        assert_eq!(parsed_dt.hour(), 23, "Hour should be 23");
        assert_eq!(parsed_dt.minute(), 59, "Minute should be 59");
        assert_eq!(parsed_dt.second(), 59, "Second should be 59");
        assert_eq!(parsed_dt.nanosecond(), 999_999_000, "Nanoseconds should indicate the last microsecond");
    }

    // --- Tests related to Leap Year Logic ---
    // NOTE: Directly testing the internal leap year adjustment logic of `get_timestamp`
    // is difficult because it always starts from `Utc::now()`. We cannot easily force
    // it to start from Feb 29th without mocking the clock.
    // However, we can test the `end_of_year` flag in a leap year context and trust
    // that the underlying `chrono` library handles date calculations correctly,
    // including the fallback logic implemented in `get_timestamp`.

    #[test]
    fn test_get_timestamp_end_of_leap_year() {
        let now = Utc::now();
        let mut years_to_add = 0;
        // Find the next leap year relative to the current year
        loop {
            let target_year = now.year() + years_to_add;
            if chrono::NaiveDate::from_ymd_opt(target_year, 2, 29).is_some() {
                break; // Found a leap year
            }
            years_to_add += 1;
            if years_to_add > 4 {
                // Safety break
                panic!("Could not find a leap year within 4 years for testing");
            }
        }

        let leap_year = now.year() + years_to_add;
        println!("Testing end_of_year for leap year: {}", leap_year);

        let timestamp = get_timestamp(years_to_add, true);
        let parsed_dt = parse_and_validate_format(&timestamp).expect("Timestamp should be valid");

        assert_eq!(parsed_dt.year(), leap_year, "Year should be the target leap year");
        assert_eq!(parsed_dt.month(), 12, "Month should be December");
        assert_eq!(parsed_dt.day(), 31, "Day should be 31st");
        assert_eq!(parsed_dt.hour(), 23, "Hour should be 23");
        assert_eq!(parsed_dt.minute(), 59, "Minute should be 59");
        assert_eq!(parsed_dt.second(), 59, "Second should be 59");
        assert_eq!(parsed_dt.nanosecond(), 999_999_000, "Nanoseconds should indicate the last microsecond");
    }

    #[test]
    fn test_get_timestamp_add_years_crossing_leap_day() {
        // This test demonstrates adding years, but doesn't guarantee crossing Feb 29th
        // in a specific way due to starting from Utc::now().
        // It primarily verifies the year increment is correct, even if the target is a leap year.
        let now = Utc::now();
        let mut years_to_add = 0;
        // Find the next leap year relative to the current year
        loop {
            let target_year = now.year() + years_to_add;
            if chrono::NaiveDate::from_ymd_opt(target_year, 2, 29).is_some() {
                if years_to_add > 0 {
                    // Ensure we actually add years
                    break;
                }
            }
            years_to_add += 1;
            if years_to_add > 4 {
                // Safety break
                panic!("Could not find a future leap year within 4 years for testing");
            }
        }

        let target_leap_year = now.year() + years_to_add;
        println!("Testing add_years to reach leap year: {}", target_leap_year);

        let timestamp = get_timestamp(years_to_add, false);
        let parsed_dt = parse_and_validate_format(&timestamp).expect("Timestamp should be valid");

        assert_eq!(parsed_dt.year(), target_leap_year, "Year should be the target leap year");
        // Further assertions on day/month are unreliable without mocking time.
    }
}