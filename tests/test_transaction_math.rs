// tests/test_transaction_math.rs

//! # Integrationstest für die numerische Robustheit von Transaktionen
//!
//! Diese Test-Suite verifiziert die korrekte arithmetische Verarbeitung
//! von `Decimal`-Werten in der `create_transaction`-Funktion.
//!
//! ## Abgedeckte Szenarien:
//!
//! - **Ganzzahl-Transaktionen:** Korrekte Subtraktion und Skalierung.
//! - **Dezimal-Transaktionen:** Verarbeitung mit maximaler und geringerer Präzision.
//! - **Gemischte Transaktionen:** Korrekte Arithmetik bei Interaktionen zwischen
//!   ganzzahligen und dezimalen Guthaben.
//! - **Regelkonformität:** Sicherstellung, dass die `amount_decimal_places`-Regel
//!   des Standards korrekt angewendet wird (Skalierung und Validierung).
//! - **Fehlerfall:** Ablehnung von Transaktionen, deren Betrag die vom Standard
//!   erlaubte Präzision überschreitet.
//! - **Vollständiger Transfer:** Korrekte Erstellung einer Transaktion ohne Restbetrag,
//!   wenn das gesamte Guthaben überwiesen wird.

use voucher_lib::{
    create_transaction, create_voucher, crypto_utils, get_spendable_balance,
    load_standard_definition, validate_voucher_against_standard, Address, Collateral, Creator, NewVoucherData,
    NominalValue, VoucherCoreError, VoucherStandardDefinition,
};
use voucher_lib::services::voucher_manager::VoucherManagerError;
use ed25519_dalek::SigningKey;
use rust_decimal_macros::dec;

// --- HELPER-FUNKTIONEN (adaptiert aus test_voucher_lifecycle.rs) ---

/// Erstellt einen neuen Signierschlüssel und eine Creator-Struktur für Tests.
fn setup_creator(seed: Option<&str>, user_prefix: &str) -> (SigningKey, Creator, String) {
    let (public_key, signing_key) = crypto_utils::generate_ed25519_keypair_for_tests(seed);
    let user_id = crypto_utils::create_user_id(&public_key, Some(user_prefix)).unwrap();

    let creator = Creator {
        id: user_id.clone(),
        first_name: "Test".to_string(),
        last_name: "User".to_string(),
        address: Address {
            street: "Teststraße".to_string(),
            house_number: "1".to_string(),
            zip_code: "12345".to_string(),
            city: "Teststadt".to_string(),
            country: "DE".to_string(),
            full_address: "Teststraße 1, 12345 Teststadt, DE".to_string(),
        },
        organization: None,
        community: None,
        phone: None,
        email: Some("test@user.de".to_string()),
        url: None,
        gender: "1".to_string(),
        service_offer: None,
        needs: None,
        signature: "".to_string(), // Wird von create_voucher ausgefüllt
        coordinates: "0,0".to_string(),
    };
    (signing_key, creator, user_id)
}

/// Erstellt die Basisdaten für einen Test-Gutschein.
fn create_test_voucher_data(creator: Creator, amount: &str) -> NewVoucherData {
    NewVoucherData {
        validity_duration: Some("P3Y".to_string()),
        non_redeemable_test_voucher: true,
        nominal_value: NominalValue {
            unit: "".to_string(),
            amount: amount.to_string(),
            abbreviation: "".to_string(),
            description: "Test value".to_string(),
        },
        collateral: Collateral::default(),
        creator,
    }
}

// --- TESTFÄLLE ---

#[test]
fn test_chained_transaction_math_and_scaling() {
    // --- 1. SETUP ---
    let standard_toml = std::fs::read_to_string("voucher_standards/silver_standard.toml").unwrap();
    let standard: VoucherStandardDefinition = load_standard_definition(&standard_toml).unwrap();
    assert_eq!(
        standard.validation.amount_decimal_places, 4,
        "This test requires the silver standard with 4 decimal places."
    );

    // Erstelle Alice (Sender) und Bob (Empfänger)
    let (alice_key, alice_creator, alice_id) = setup_creator(Some("alice"), "al");
    let (bob_key, _, bob_id) = setup_creator(Some("bob"), "bo");

    // Erstelle einen initialen Gutschein für Alice mit dem Wert 100
    let voucher_data = create_test_voucher_data(alice_creator, "100");
    let mut current_voucher = create_voucher(voucher_data, &standard, &alice_key).unwrap();
    validate_voucher_against_standard(&current_voucher, &standard).unwrap();
    assert_eq!(
        get_spendable_balance(&current_voucher, &alice_id, &standard).unwrap(),
        dec!(100)
    );
    assert_eq!(
        get_spendable_balance(&current_voucher, &bob_id, &standard).unwrap(),
        dec!(0)
    );

    // --- 2. FALL: GANZZAHL-SPLIT VON GANZZAHL-GUTHABEN ---
    // Alice (100) sendet "40" an Bob.
    current_voucher = create_transaction(
        &current_voucher,
        &standard,
        &alice_id,
        &alice_key,
        &bob_id,
        "40",
    )
        .unwrap();

    validate_voucher_against_standard(&current_voucher, &standard).unwrap();
    assert_eq!(
        get_spendable_balance(&current_voucher, &alice_id, &standard).unwrap(),
        dec!(60)
    );
    assert_eq!(
        get_spendable_balance(&current_voucher, &bob_id, &standard).unwrap(),
        dec!(40)
    );
    let tx1 = current_voucher.transactions.last().unwrap();
    assert_eq!(tx1.amount, "40.0000"); // Korrekt skaliert
    assert_eq!(tx1.sender_remaining_amount, Some("60.0000".to_string()));

    // --- 3. FALL: DEZIMAL-SPLIT (MAX. PRÄZISION) VON GANZZAHL-GUTHABEN ---
    // Alice (60) sendet "10.1234" an Bob.
    current_voucher = create_transaction(
        &current_voucher,
        &standard,
        &alice_id,
        &alice_key,
        &bob_id,
        "10.1234",
    )
        .unwrap();
    validate_voucher_against_standard(&current_voucher, &standard).unwrap();
    assert_eq!(
        get_spendable_balance(&current_voucher, &alice_id, &standard).unwrap(),
        dec!(49.8766)
    );
    assert_eq!(
        get_spendable_balance(&current_voucher, &bob_id, &standard).unwrap(),
        dec!(10.1234) // Guthaben ist nur der Betrag der letzten Transaktion
    );

    // --- 4. FALL: GANZZAHL-SPLIT VON DEZIMAL-GUTHABEN ---
    // Alice (49.8766) sendet "9" an Bob.
    current_voucher = create_transaction(
        &current_voucher,
        &standard,
        &alice_id,
        &alice_key,
        &bob_id,
        "9",
    )
        .unwrap();
    validate_voucher_against_standard(&current_voucher, &standard).unwrap();
    assert_eq!(
        get_spendable_balance(&current_voucher, &alice_id, &standard).unwrap(),
        dec!(40.8766)
    );
    assert_eq!(
        get_spendable_balance(&current_voucher, &bob_id, &standard).unwrap(),
        dec!(9.0000) // Guthaben ist nur der Betrag der letzten Transaktion
    );
    let tx3 = current_voucher.transactions.last().unwrap();
    assert_eq!(tx3.amount, "9.0000"); // Korrekt skaliert

    // --- 5. FALL: SPLIT MIT WENIGER NACHKOMMASTELLEN ALS ERLAUBT ---
    // Alice (40.8766) sendet "0.87" (2 statt 4 Stellen) an Bob.
    current_voucher = create_transaction(
        &current_voucher,
        &standard,
        &alice_id,
        &alice_key,
        &bob_id,
        "0.87",
    )
        .unwrap();
    validate_voucher_against_standard(&current_voucher, &standard).unwrap();
    assert_eq!(
        get_spendable_balance(&current_voucher, &alice_id, &standard).unwrap(),
        dec!(40.0066)
    );
    assert_eq!(
        get_spendable_balance(&current_voucher, &bob_id, &standard).unwrap(),
        dec!(0.8700) // Guthaben ist nur der Betrag der letzten Transaktion
    );
    let tx4 = current_voucher.transactions.last().unwrap();
    assert_eq!(tx4.amount, "0.8700"); // Korrekt skaliert

    // --- 6. FALL: VOLLER TRANSFER DES RESTGUTHABENS ---
    // Alice (40.0066) sendet ihr komplettes Restguthaben "40.0066" an Bob.
    current_voucher = create_transaction(
        &current_voucher,
        &standard,
        &alice_id,
        &alice_key,
        &bob_id,
        "40.0066",
    )
        .unwrap();
    validate_voucher_against_standard(&current_voucher, &standard).unwrap();
    assert_eq!(
        get_spendable_balance(&current_voucher, &alice_id, &standard).unwrap(),
        dec!(0)
    );
    assert_eq!(
        get_spendable_balance(&current_voucher, &bob_id, &standard).unwrap(),
        dec!(40.0066) // Guthaben ist nur der Betrag der letzten Transaktion
    );
    let tx5 = current_voucher.transactions.last().unwrap();
    assert_eq!(tx5.t_type, ""); // Kein "split" mehr
    assert!(tx5.sender_remaining_amount.is_none());
    assert_eq!(tx5.amount, "40.0066");

    // --- 7. FALL: RÜCKTRANSAKTIONEN VON BOB AN ALICE ---
    // Bob (Guthaben: 40.0066) sendet "10" (Ganzzahl) zurück an Alice.
    current_voucher = create_transaction(
        &current_voucher,
        &standard,
        &bob_id,
        &bob_key,
        &alice_id,
        "10",
    )
    .unwrap();
    validate_voucher_against_standard(&current_voucher, &standard).unwrap();

    // Prüfe die Guthaben nach der ersten Rücktransaktion
    assert_eq!(
        get_spendable_balance(&current_voucher, &bob_id, &standard).unwrap(),
        dec!(30.0066) // Bobs Restguthaben
    );
    assert_eq!(
        get_spendable_balance(&current_voucher, &alice_id, &standard).unwrap(),
        dec!(10.0000) // Alice' neues Guthaben
    );

    // Bob (Guthaben: 30.0066) sendet "0.0066" (Dezimal) zurück an Alice.
    current_voucher = create_transaction(
        &current_voucher,
        &standard,
        &bob_id,
        &bob_key,
        &alice_id,
        "0.0066",
    )
    .unwrap();
    validate_voucher_against_standard(&current_voucher, &standard).unwrap();

    // Prüfe die Guthaben nach der zweiten Rücktransaktion
    assert_eq!(
        get_spendable_balance(&current_voucher, &bob_id, &standard).unwrap(),
        dec!(30.0000) // Bobs Restguthaben
    );
    assert_eq!(
        get_spendable_balance(&current_voucher, &alice_id, &standard).unwrap(),
        dec!(0.0066) // Alice' neues Guthaben
    );
}

#[test]
fn test_transaction_fails_on_excess_precision() {
    // --- SETUP ---
    let standard_toml = std::fs::read_to_string("voucher_standards/silver_standard.toml").unwrap();
    let standard: VoucherStandardDefinition = load_standard_definition(&standard_toml).unwrap();
    let (alice_key, alice_creator, alice_id) = setup_creator(Some("alice_prec"), "al");
    let (_, _, bob_id) = setup_creator(Some("bob_prec"), "bo");

    let voucher_data = create_test_voucher_data(alice_creator, "100");
    let voucher = create_voucher(voucher_data, &standard, &alice_key).unwrap();

    // --- AKTION & PRÜFUNG ---
    // Alice versucht, "0.12345" (5 Nachkommastellen) zu senden, erlaubt sind aber nur 4.
    let result = create_transaction(&voucher, &standard, &alice_id, &alice_key, &bob_id, "0.12345");

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        VoucherCoreError::Manager(VoucherManagerError::AmountPrecisionExceeded {
            allowed: 4,
            found: 5
        })
    ));
}