// cargo test --test test_voucher_lifecycle
//! # Integrationstests für den Gutschein-Lebenszyklus und die Sicherheit
//!
//! Diese Test-Suite deckt den gesamten Lebenszyklus eines `Voucher`-Objekts ab,
//! von der Erstellung bis zur vollständigen Validierung, und prüft kritische
//! Sicherheitsaspekte.
//!
//! ## Abgedeckte Szenarien:
//!
//! - **Vollständiger Lebenszyklus:**
//!   - Erstellung eines Gutscheins.
//!   - Validierung im initialen Zustand (erwarteter Fehlschlag wegen fehlender Bürgen).
//!   - Erstellung und Hinzufügen von korrekten, entkoppelten Bürgen-Signaturen.
//!   - Finale, erfolgreiche Validierung des vollständigen Gutscheins.
//! - **Serialisierung:**
//!   - Korrekte Umwandlung zwischen `Voucher`-Struct und JSON-String.
//! - **Validierungs-Fehlerfälle:**
//!   - Ungültige oder manipulierte Creator-Signatur.
//!   - Fehlende, im Standard definierte Felder.
//!   - Inkonsistente Daten (z.B. falsche Nennwert-Einheit).
//!   - Nichterfüllung von Bürgen-Anforderungen (Anzahl, Geschlecht).
//! - **Sicherheitsprüfungen:**
//!   - **Replay-Angriff:** Verhindert, dass eine Bürgen-Signatur von einem Gutschein
//!     für einen anderen wiederverwendet wird.
//!   - **Daten-Manipulation:** Stellt sicher, dass eine nachträgliche Änderung
//!     an den Metadaten einer Signatur erkannt wird.
//! - **Kanonische Serialisierung:**
//!   - Überprüfung der deterministischen und sortierten JSON-Ausgabe.
//!   - Toleranz gegenüber unbekannten Feldern für Vorwärtskompatibilität.

// Wir importieren die öffentlichen Typen, die in lib.rs re-exportiert wurden.
use voucher_lib::{
    create_transaction, create_voucher, crypto_utils, from_json, get_spendable_balance, load_standard_definition,
    to_canonical_json, to_json, validate_voucher_against_standard,
    Address, Collateral, Creator, GuarantorSignature, NewVoucherData, NominalValue, Transaction,
    Voucher, VoucherCoreError, VoucherStandardDefinition, Wallet,
};
// Importiere die spezifischen Fehlertypen direkt aus ihren Modulen für die `matches!`-Makros.
use voucher_lib::services::{
    voucher_manager::VoucherManagerError, voucher_validation::ValidationError,
};
use voucher_lib::archive::file_archive::FileVoucherArchive;
use voucher_lib::crypto_utils::get_hash;
use voucher_lib::models::conflict::FingerprintStore;
use voucher_lib::models::profile::{
    BundleMetadataStore, UserIdentity, UserProfile, VoucherStatus, VoucherStore,
};
use ed25519_dalek::SigningKey;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;

// --- HELPER-FUNKTIONEN UND TESTDATEN ---

/// Erstellt einen neuen Signierschlüssel und eine Creator-Struktur für Tests.
fn setup_creator() -> (SigningKey, Creator) {
    // Erzeuge ein zufälliges Schlüsselpaar für den Test. Für deterministische Tests
    // könnte hier ein Seed übergeben werden, z.B. Some("mein_test_seed").
    let (public_key, signing_key) = crypto_utils::generate_ed25519_keypair_for_tests(None);
    let user_id = crypto_utils::create_user_id(&public_key, Some("ts")).unwrap();

    let creator = Creator {
        id: user_id,
        first_name: "Max".to_string(),
        last_name: "Mustermann".to_string(),
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
        email: Some("max@test.de".to_string()),
        url: None,
        gender: "1".to_string(),
        service_offer: None,
        needs: None,
        signature: "".to_string(), // Wird von create_voucher ausgefüllt
        coordinates: "0,0".to_string(),
    };
    (signing_key, creator)
}

/// Erstellt die Basisdaten für einen Minuto-Gutschein.
fn create_minuto_voucher_data(creator: Creator) -> NewVoucherData {
    NewVoucherData {
        // Anstelle von `years_valid` wird nun die ISO 8601-Dauer verwendet.
        // Wir verwenden P4Y, da dies die neue Mindestanforderung von P3Y erfüllt.
        validity_duration: Some("P4Y".to_string()),
        non_redeemable_test_voucher: true,
        nominal_value: NominalValue {
            // Einheit und Abkürzung werden später vom Standard überschrieben.
            // Die Angabe hier ist nur ein Platzhalter.
            unit: "".to_string(),
            amount: "60".to_string(),
            abbreviation: "".to_string(),
            description: "Qualitative Leistung".to_string(),
        },
        collateral: Collateral {
            // Typ, Beschreibung und Einlösebedingung werden vom Standard überschrieben.
            type_: "".to_string(),
            unit: "".to_string(),
            amount: "".to_string(),
            abbreviation: "".to_string(),
            description: "".to_string(),
            redeem_condition: "".to_string(),
        },
        creator,
    }
}

/// Erstellt eine gültige, entkoppelte Bürgen-Signatur für einen gegebenen Gutschein.
fn create_guarantor_signature(
    voucher_id: &str,
    guarantor_id: String,
    guarantor_first_name: &str,
    guarantor_gender: &str,
    signing_key: &SigningKey,
) -> GuarantorSignature {
    // 1. Erstelle das Signatur-Objekt, aber lasse die finale Signatur und die ID leer.
    let mut signature_data = GuarantorSignature {
        voucher_id: voucher_id.to_string(),
        signature_id: "".to_string(), // Wird gleich berechnet
        guarantor_id,
        first_name: guarantor_first_name.to_string(),
        last_name: "Guarantor".to_string(),
        organization: None,
        community: Some("Test Community".to_string()),
        address: None,
        gender: guarantor_gender.to_string(),
        email: None,
        phone: None,
        coordinates: None,
        url: None,
        signature: "".to_string(), // Wird gleich berechnet
        signature_time: "2025-07-16T12:00:00Z".to_string(),
    };

    // 2. Erzeuge die signature_id durch Hashing der Metadaten.
    let signature_json_for_id = to_canonical_json(&signature_data).unwrap();
    let signature_id = crypto_utils::get_hash(signature_json_for_id);
    signature_data.signature_id = signature_id;

    // 3. Signiere die signature_id.
    let digital_signature =
        crypto_utils::sign_ed25519(signing_key, signature_data.signature_id.as_bytes());
    signature_data.signature = bs58::encode(digital_signature.to_bytes()).into_string();

    signature_data
}

#[test]
fn test_full_creation_and_validation_cycle() {
    // 1. Setup: Lade Standard und erstelle Creator
    let standard_toml = std::fs::read_to_string("voucher_standards/minuto_standard.toml").unwrap();
    let standard: VoucherStandardDefinition = load_standard_definition(&standard_toml).unwrap();
    let (signing_key, creator) = setup_creator();
    let voucher_data = create_minuto_voucher_data(creator);

    // 2. Erstellung
    let mut voucher = create_voucher(voucher_data, &standard, &signing_key).unwrap();
    assert!(!voucher.voucher_id.is_empty());
    assert!(!voucher.creator.signature.is_empty());
    // Prüfe die neuen Werte, die aus dem geänderten Standard kommen.
    assert_eq!(voucher.standard_minimum_issuance_validity, "P3Y");
    // Prüfe, ob das Gültigkeitsdatum korrekt auf das Jahresende gerundet wurde.
    assert!(voucher.valid_until.contains("-12-31T23:59:59"));
    let expected_description = "Ein Gutschein für Waren oder Dienstleistungen im Wert von 60 Minuten qualitativer Leistung.";
    assert_eq!(voucher.description, expected_description);

    // 3. Erste Validierung: Muss fehlschlagen, da Bürgen fehlen.
    let initial_validation_result = validate_voucher_against_standard(&voucher, &standard);
    assert!(matches!(
        initial_validation_result.unwrap_err(),
        VoucherCoreError::Validation(ValidationError::GuarantorRequirementsNotMet(_))
    ));

    // 4. Simulation des Bürgenprozesses nach neuer Logik
    let (g1_pub, g1_priv) = crypto_utils::generate_ed25519_keypair_for_tests(Some("g1"));
    let (g2_pub, g2_priv) = crypto_utils::generate_ed25519_keypair_for_tests(Some("g2"));
    let g1_id = crypto_utils::create_user_id(&g1_pub, Some("g1")).unwrap();
    let g2_id = crypto_utils::create_user_id(&g2_pub, Some("g2")).unwrap();

    let guarantor_sig_1 =
        create_guarantor_signature(&voucher.voucher_id, g1_id, "Hans", "1", &g1_priv);
    let guarantor_sig_2 =
        create_guarantor_signature(&voucher.voucher_id, g2_id, "Gabi", "2", &g2_priv);

    voucher.guarantor_signatures.push(guarantor_sig_1);
    voucher.guarantor_signatures.push(guarantor_sig_2);

    // 5. Finale Validierung (Positivfall mit Bürgen)
    let final_validation_result = validate_voucher_against_standard(&voucher, &standard);
    assert!(
        final_validation_result.is_ok(),
        "Final validation failed unexpectedly: {:?}",
        final_validation_result.err()
    );

    // 6. Finale Überprüfung des Guthabens mit der neuen Funktion
    let balance = get_spendable_balance(&voucher, &voucher.creator.id, &standard).unwrap();
    let expected_balance = Decimal::from_str_exact(voucher.nominal_value.amount.as_str()).unwrap();
    assert_eq!(
        balance, expected_balance,
        "Final balance check failed."
    );
}

#[test]
fn test_serialization_deserialization() {
    // 1. Erstelle einen Gutschein
    let standard_toml = std::fs::read_to_string("voucher_standards/minuto_standard.toml").unwrap();
    let standard: VoucherStandardDefinition = load_standard_definition(&standard_toml).unwrap();
    let (signing_key, creator) = setup_creator();
    let voucher_data = create_minuto_voucher_data(creator);
    let original_voucher = create_voucher(voucher_data, &standard, &signing_key).unwrap();

    // 2. Serialisiere zu JSON
    let json_string = to_json(&original_voucher).unwrap();

    // 3. Deserialisiere zurück
    let deserialized_voucher: Voucher = from_json(&json_string).unwrap();

    // 4. Vergleiche die Objekte
    assert_eq!(original_voucher, deserialized_voucher);
}

#[test]
fn test_validation_fails_on_invalid_signature() {
    // 1. Erstelle einen gültigen Gutschein
    let standard_toml = std::fs::read_to_string("voucher_standards/minuto_standard.toml").unwrap();
    let standard: VoucherStandardDefinition = load_standard_definition(&standard_toml).unwrap();
    let (signing_key, creator) = setup_creator();
    let voucher_data = create_minuto_voucher_data(creator);
    let mut voucher = create_voucher(voucher_data, &standard, &signing_key).unwrap();

    // Füge die benötigten Bürgen hinzu, um den Gutschein valide zu machen, BEVOR wir ihn manipulieren.
    // Ansonsten würde die Validierung bereits an den fehlenden Bürgen scheitern.
    let (g1_pub, g1_priv) = crypto_utils::generate_ed25519_keypair_for_tests(Some("g1_invalid_sig"));
    let (g2_pub, g2_priv) = crypto_utils::generate_ed25519_keypair_for_tests(Some("g2_invalid_sig"));
    let g1_id = crypto_utils::create_user_id(&g1_pub, Some("g1")).unwrap();
    let g2_id = crypto_utils::create_user_id(&g2_pub, Some("g2")).unwrap();
    let guarantor_sig_1 =
        create_guarantor_signature(&voucher.voucher_id, g1_id, "Guarantor1", "1", &g1_priv);
    let guarantor_sig_2 =
        create_guarantor_signature(&voucher.voucher_id, g2_id, "Guarantor2", "2", &g2_priv);
    voucher.guarantor_signatures.push(guarantor_sig_1);
    voucher.guarantor_signatures.push(guarantor_sig_2);
    assert!(validate_voucher_against_standard(&voucher, &standard).is_ok());

    // 2. Manipuliere die Signatur
    voucher.creator.signature = "invalid_signature_string_12345".to_string();

    // 3. Validierung sollte fehlschlagen
    let validation_result = validate_voucher_against_standard(&voucher, &standard);
    assert!(validation_result.is_err());
    // Wir erwarten einen Fehler beim Dekodieren der Signatur, da sie kein gültiges Base58 ist.
    assert!(matches!(
        validation_result.unwrap_err(),
        VoucherCoreError::Validation(ValidationError::SignatureDecodeError(_))
    ));
}

#[test]
fn test_validation_fails_on_missing_required_field() {
    // 1. Erstelle einen gültigen Gutschein
    let standard_toml = std::fs::read_to_string("voucher_standards/minuto_standard.toml").unwrap();
    let base_standard: VoucherStandardDefinition = load_standard_definition(&standard_toml).unwrap();
    let (signing_key, creator) = setup_creator();
    let voucher_data = create_minuto_voucher_data(creator);
    let voucher = create_voucher(voucher_data, &base_standard, &signing_key).unwrap();

    // 2. Lade einen manipulierten Standard, der ein zusätzliches Feld erfordert
    let standard_toml = std::fs::read_to_string("voucher_standards/minuto_standard.toml").unwrap();
    let mut standard: VoucherStandardDefinition = load_standard_definition(&standard_toml).unwrap();
    standard.validation
        .required_voucher_fields
        .push("creator.phone".to_string()); // creator.phone ist optional

    // 3. Validierung sollte fehlschlagen
    let validation_result = validate_voucher_against_standard(&voucher, &standard);
    assert!(validation_result.is_err());
    match validation_result.unwrap_err() {
        VoucherCoreError::Validation(ValidationError::MissingRequiredField(path)) => assert_eq!(path, "creator.phone"),
        _ => panic!("Expected MissingRequiredField error"),
    }
}

#[test]
fn test_validation_fails_on_inconsistent_unit() {
    let standard_toml = std::fs::read_to_string("voucher_standards/silver_standard.toml").unwrap();
    let standard: VoucherStandardDefinition = load_standard_definition(&standard_toml).unwrap();
    // Erstelle einen initial gültigen Gutschein nach dem Silber-Standard.
    let (signing_key, creator) = setup_creator();
    let voucher_data = create_minuto_voucher_data(creator);
    let mut voucher = create_voucher(voucher_data, &standard, &signing_key).unwrap();

    // Manipuliere die Einheit NACH der Erstellung, um einen inkonsistenten Zustand zu erzeugen.
    voucher.nominal_value.unit = "EUR".to_string();

    // Validierung sollte wegen der Einheit fehlschlagen
    let validation_result = validate_voucher_against_standard(&voucher, &standard);
    assert!(validation_result.is_err());
    match validation_result.unwrap_err() {
        VoucherCoreError::Validation(ValidationError::IncorrectNominalValueUnit { expected, found }) => {
            assert_eq!(expected, "Unzen");
            assert_eq!(found, "EUR");
        }
        e => panic!("Expected IncorrectNominalValueUnit error, but got {:?}", e),
    }
}

#[test]
fn test_validation_fails_on_guarantor_count() {
    let standard_toml = std::fs::read_to_string("voucher_standards/minuto_standard.toml").unwrap();
    let standard: VoucherStandardDefinition = load_standard_definition(&standard_toml).unwrap();
    let (signing_key, creator) = setup_creator();
    let voucher_data = create_minuto_voucher_data(creator);
    let mut voucher = create_voucher(voucher_data, &standard, &signing_key).unwrap();

    // Der erstellte Gutschein hat 0 Bürgen, der Standard erfordert aber 2
    voucher.guarantor_signatures.clear();

    let validation_result = validate_voucher_against_standard(&voucher, &standard);
    assert!(validation_result.is_err());
    match validation_result.unwrap_err() {
        VoucherCoreError::Validation(ValidationError::GuarantorRequirementsNotMet(_)) => {
            // Korrekter Fehlertyp
        }
        e => panic!("Expected GuarantorRequirementsNotMet error, but got {:?}", e),
    }
}

// --- NEUE TESTS FÜR KANONISCHE SERIALISIERUNG ---

#[test]
fn test_canonical_json_is_deterministic_and_sorted() {
    // 1. Erstelle zwei identische Datenstrukturen.
    // Wir rufen setup_creator nur einmal auf, um einen konsistenten Schlüssel zu erhalten.
    let standard_toml = std::fs::read_to_string("voucher_standards/minuto_standard.toml").unwrap();
    let standard: VoucherStandardDefinition = load_standard_definition(&standard_toml).unwrap();
    let (signing_key, creator) = setup_creator();
    let data1 = create_minuto_voucher_data(creator.clone());
    let data2 = create_minuto_voucher_data(creator);

    // 2. Erstelle zwei Gutscheine nacheinander.
    // Wir fügen eine winzige Pause ein, um sicherzustellen, dass die Zeitstempel
    // und somit die Hashes sich auf jeden Fall unterscheiden.
    let voucher1 = create_voucher(data1, &standard, &signing_key).unwrap();
    std::thread::sleep(std::time::Duration::from_micros(10));
    let voucher2 = create_voucher(data2, &standard, &signing_key).unwrap();

    // 3. Verifiziere, dass die Gutscheine NICHT identisch sind, da ihre Zeitstempel
    // und die daraus abgeleiteten Felder (IDs, Signaturen) sich unterscheiden müssen.
    assert_ne!(
        voucher1, voucher2,
        "Vouchers should be different due to unique timestamps"
    );
    assert_ne!(
        voucher1.voucher_id, voucher2.voucher_id,
        "Voucher IDs should be different"
    );

    // 4. Teste die kanonische Serialisierung an einem statischen Teil des Gutscheins.
    // Das Ergebnis muss immer alphabetisch sortierte Schlüssel haben,
    // z.B. "abbreviation" vor "amount".
    let canonical_json = to_canonical_json(&voucher1.nominal_value).unwrap();

    // Erzeuge den Erwartungswert dynamisch aus dem geladenen Standard,
    // anstatt einen hartkodierten String zu verwenden.
    let expected_json = format!(
        r#"{{"abbreviation":"{}","amount":"60","description":"Qualitative Leistung","unit":"{}"}}"#,
        standard.metadata.abbreviation, standard.template.fixed.nominal_value.unit
    );
    assert_eq!(canonical_json, expected_json);
    println!("Canonical Nominal Value: {}", canonical_json);
}

#[test]
fn test_validation_succeeds_with_extra_fields_in_json() {
    // 1. Erstelle einen VOLLSTÄNDIG gültigen Gutschein, inklusive der benötigten Bürgen.
    let (signing_key, creator) = setup_creator();
    let standard_toml = std::fs::read_to_string("voucher_standards/minuto_standard.toml").unwrap();
    let standard: VoucherStandardDefinition = load_standard_definition(&standard_toml).unwrap();
    let voucher_data = create_minuto_voucher_data(creator);
    let mut valid_voucher = create_voucher(voucher_data, &standard, &signing_key).unwrap();

    // Füge die für den Minuto-Standard erforderlichen Bürgen hinzu.
    let (g1_pub, g1_priv) = crypto_utils::generate_ed25519_keypair_for_tests(Some("g1_extra"));
    let (g2_pub, g2_priv) = crypto_utils::generate_ed25519_keypair_for_tests(Some("g2_extra"));
    let g1_id = crypto_utils::create_user_id(&g1_pub, Some("g1")).unwrap();
    let g2_id = crypto_utils::create_user_id(&g2_pub, Some("g2")).unwrap();

    let guarantor_sig_1 =
        create_guarantor_signature(&valid_voucher.voucher_id, g1_id, "Guarantor1", "1", &g1_priv);
    let guarantor_sig_2 =
        create_guarantor_signature(&valid_voucher.voucher_id, g2_id, "Guarantor2", "2", &g2_priv);
    valid_voucher.guarantor_signatures.push(guarantor_sig_1);
    valid_voucher.guarantor_signatures.push(guarantor_sig_2);

    // Stelle sicher, dass der Gutschein jetzt gültig ist, bevor wir ihn modifizieren.
    assert!(validate_voucher_against_standard(&valid_voucher, &standard).is_ok());

    let mut voucher_as_value: serde_json::Value = serde_json::to_value(&valid_voucher).unwrap();

    // 2. Füge ein unbekanntes Feld zum JSON-Objekt hinzu.
    // Dies simuliert einen Gutschein, der von einer neueren Software-Version erstellt wurde.
    voucher_as_value
        .as_object_mut()
        .unwrap()
        .insert("unknown_future_field".to_string(), serde_json::json!("some_data"));

    // Füge auch ein unbekanntes Feld in ein verschachteltes Objekt ein.
    voucher_as_value
        .get_mut("creator")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(
            "creator_metadata".to_string(),
            serde_json::json!({"rating": 5}),
        );

    let json_with_extra_fields = serde_json::to_string(&voucher_as_value).unwrap();

    // 3. Deserialisiere diesen JSON-String. `serde` sollte die unbekannten Felder ignorieren.
    let deserialized_voucher: Voucher = from_json(&json_with_extra_fields).unwrap();

    // 4. Der deserialisierte Gutschein sollte exakt dem Original entsprechen, da die
    // zusätzlichen Felder verworfen wurden.
    assert_eq!(valid_voucher, deserialized_voucher);

    // 5. Die Validierung muss erfolgreich sein. Die `verify_creator_signature`-Funktion
    // wird intern die kanonische Form des `deserialized_voucher` (ohne die extra Felder)
    // berechnen, und diese muss mit der ursprünglichen Signatur übereinstimmen.
    let validation_result = validate_voucher_against_standard(&deserialized_voucher, &standard);

    assert!(
        validation_result.is_ok(),
        "Validation failed unexpectedly with extra fields: {:?}",
        validation_result.err()
    );
}

// --- NEUE TESTS FÜR SPLIT-TRANSAKTIONEN ---

#[test]
fn test_split_transaction_cycle_and_balance_check() {
    // 1. Setup: Silber-Standard, da er teilbar ist und keine Bürgen benötigt.
    let standard_toml = std::fs::read_to_string("voucher_standards/silver_standard.toml").unwrap();
    let standard: VoucherStandardDefinition = load_standard_definition(&standard_toml).unwrap();
    assert!(standard.template.fixed.is_divisible);

    // 2. Erstelle Sender und Empfänger
    let (sender_key, sender_creator) = setup_creator();
    let sender_id = sender_creator.id.clone();

    let (recipient_pub, _recipient_key) =
        crypto_utils::generate_ed25519_keypair_for_tests(Some("recipient"));
    let recipient_id = crypto_utils::create_user_id(&recipient_pub, Some("rc")).unwrap();

    // 3. Erstelle einen Gutschein mit dem Wert 100.0000
    let mut voucher_data = create_minuto_voucher_data(sender_creator);
    voucher_data.nominal_value.amount = "100.0000".to_string();
    let initial_voucher = create_voucher(voucher_data, &standard, &sender_key).unwrap();

    // 4. Überprüfe den initialen Zustand und das Guthaben
    assert!(validate_voucher_against_standard(&initial_voucher, &standard).is_ok());
    let initial_balance = get_spendable_balance(&initial_voucher, &sender_id, &standard).unwrap();
    assert_eq!(initial_balance, dec!(100.0000));

    // 5. Führe eine Split-Transaktion durch: Sende 30.5000 an den Empfänger
    let split_amount = "30.5000";
    let voucher_after_split = create_transaction(
        &initial_voucher,
        &standard,
        &sender_id,
        &sender_key,
        &recipient_id,
        split_amount,
    )
    .unwrap();

    // 6. Validiere den Gutschein nach dem Split
    let validation_result = validate_voucher_against_standard(&voucher_after_split, &standard);
    assert!(
        validation_result.is_ok(),
        "Validation after split failed: {:?}",
        validation_result.err()
    );
    assert_eq!(voucher_after_split.transactions.len(), 2);
    assert_eq!(
        voucher_after_split.transactions.last().unwrap().t_type,
        "split"
    );

    // 7. Überprüfe die Guthaben beider Parteien
    let sender_balance_after_split =
        get_spendable_balance(&voucher_after_split, &sender_id, &standard).unwrap();
    let recipient_balance_after_split =
        get_spendable_balance(&voucher_after_split, &recipient_id, &standard).unwrap();

    assert_eq!(sender_balance_after_split, dec!(69.5000)); // 100.0000 - 30.5000
    assert_eq!(recipient_balance_after_split, dec!(30.5000));
}

#[test]
fn test_split_fails_on_insufficient_funds() {
    // Setup wie oben
    let standard_toml = std::fs::read_to_string("voucher_standards/silver_standard.toml").unwrap();
    let standard: VoucherStandardDefinition = load_standard_definition(&standard_toml).unwrap();
    let (sender_key, sender_creator) = setup_creator();
    let sender_id = sender_creator.id.clone();
    let (recipient_pub, _) = crypto_utils::generate_ed25519_keypair_for_tests(Some("recipient2"));
    let recipient_id = crypto_utils::create_user_id(&recipient_pub, Some("rc")).unwrap();

    let mut voucher_data = create_minuto_voucher_data(sender_creator);
    voucher_data.nominal_value.amount = "50.0".to_string(); // Initialwert 50
    let initial_voucher = create_voucher(voucher_data, &standard, &sender_key).unwrap();

    // Versuche, 50.1 zu senden (mehr als vorhanden)
    let split_result = create_transaction(
        &initial_voucher,
        &standard,
        &sender_id,
        &sender_key,
        &recipient_id,
        "50.1",
    );

    assert!(matches!(
        split_result.unwrap_err(),
        VoucherCoreError::Manager(VoucherManagerError::InsufficientFunds { .. })
    ));
}

#[test]
fn test_split_fails_on_non_divisible_voucher() {
    let mut standard_toml =
        std::fs::read_to_string("voucher_standards/silver_standard.toml").unwrap();
    // Manipuliere den Standard, um ihn nicht-teilbar zu machen
    standard_toml = standard_toml.replace("is_divisible = true", "is_divisible = false");
    let standard: VoucherStandardDefinition = load_standard_definition(&standard_toml).unwrap();
    assert!(!standard.template.fixed.is_divisible);

    let (sender_key, sender_creator) = setup_creator();
    let sender_id = sender_creator.id.clone();
    let (recipient_pub, _) = crypto_utils::generate_ed25519_keypair_for_tests(Some("recipient3"));
    let recipient_id = crypto_utils::create_user_id(&recipient_pub, Some("rc")).unwrap();

    // Passe die Testdaten an den Silver-Standard an (4 Dezimalstellen), um Konsistenz zu gewährleisten.
    let mut voucher_data = create_minuto_voucher_data(sender_creator);
    voucher_data.nominal_value.amount = "60.0000".to_string();
    let initial_voucher = create_voucher(voucher_data, &standard, &sender_key).unwrap();

    let split_result = create_transaction(
        &initial_voucher,
        &standard,
        &sender_id,
        &sender_key,
        &recipient_id,
        "10.0",
    );

    assert!(matches!(
        split_result.unwrap_err(),
        VoucherCoreError::Manager(VoucherManagerError::VoucherNotDivisible)
    ));
}

#[test]
fn test_validity_duration_rules() {
    // 1. Setup
    let standard_toml = std::fs::read_to_string("voucher_standards/minuto_standard.toml").unwrap();
    let standard: VoucherStandardDefinition = load_standard_definition(&standard_toml).unwrap();
    let (signing_key, creator) = setup_creator();

    // 2. Testfall: Versuch, einen Gutschein mit zu kurzer Gültigkeit zu erstellen.
    // Der Minuto-Standard erfordert jetzt P3Y. Wir versuchen es mit P2Y.
    let mut short_duration_data = create_minuto_voucher_data(creator.clone());
    short_duration_data.validity_duration = Some("P2Y".to_string());
    let creation_result = create_voucher(short_duration_data, &standard, &signing_key);

    assert!(
        matches!(
            creation_result.unwrap_err(),
            VoucherCoreError::Manager(VoucherManagerError::InvalidValidityDuration(_))
        ),
        "Creation should fail with InvalidValidityDuration error"
    );

    // 3. Testfall: Erstelle einen gültigen Gutschein und manipuliere dann sein Gültigkeitsdatum.
    let valid_data = create_minuto_voucher_data(creator.clone());
    let mut voucher = create_voucher(valid_data, &standard, &signing_key).unwrap();

    // Mache ihn mit Bürgen vollständig gültig, um die Datumsprüfung zu isolieren.
    let (g1_pub, g1_priv) = crypto_utils::generate_ed25519_keypair_for_tests(Some("g1_validity"));
    let (g2_pub, g2_priv) = crypto_utils::generate_ed25519_keypair_for_tests(Some("g2_validity"));
    let g1_id = crypto_utils::create_user_id(&g1_pub, Some("g1")).unwrap();
    let g2_id = crypto_utils::create_user_id(&g2_pub, Some("g2")).unwrap();
    voucher.guarantor_signatures.push(create_guarantor_signature(&voucher.voucher_id, g1_id, "G1", "1", &g1_priv));
    voucher.guarantor_signatures.push(create_guarantor_signature(&voucher.voucher_id, g2_id, "G2", "2", &g2_priv));
    assert!(validate_voucher_against_standard(&voucher, &standard).is_ok());

    // Manipuliere das Datum
    let creation_dt = chrono::DateTime::parse_from_rfc3339(&voucher.creation_date).unwrap();
    let tampered_until_dt = creation_dt + chrono::Duration::days(10); // weniger als 90
    voucher.valid_until = tampered_until_dt.to_rfc3339();

    let validation_result = validate_voucher_against_standard(&voucher, &standard);
    assert!(matches!(
        validation_result.unwrap_err(),
        VoucherCoreError::Validation(ValidationError::ValidityDurationTooShort { .. })
    ));

    // 4. Testfall: Nicht übereinstimmende Mindestgültigkeitsregel zwischen Gutschein und Standard
    let mut voucher2 = create_voucher(create_minuto_voucher_data(creator.clone()), &standard, &signing_key).unwrap();
    // Manipuliere die im Gutschein gespeicherte Regel
    voucher2.standard_minimum_issuance_validity = "P1Y".to_string(); // Standard erwartet P3Y
    let validation_result2 = validate_voucher_against_standard(&voucher2, &standard);
    assert!(matches!(
        validation_result2.unwrap_err(),
        VoucherCoreError::Validation(ValidationError::MismatchedMinimumValidity { .. })
    ));
}

// --- NEUE SICHERHEITSTESTS ---

#[test]
fn test_validation_fails_on_replayed_guarantor_signature() {
    // 1. Erstelle zwei verschiedene Gutscheine
    let standard_toml = std::fs::read_to_string("voucher_standards/minuto_standard.toml").unwrap();
    let standard: VoucherStandardDefinition = load_standard_definition(&standard_toml).unwrap();
    let (creator1_key, creator1) = setup_creator();
    let voucher_a =
        create_voucher(create_minuto_voucher_data(creator1), &standard, &creator1_key).unwrap();

    let (creator2_key, creator2) = setup_creator();
    let mut voucher_b = create_voucher(
        create_minuto_voucher_data(creator2),
        &standard,
        &creator2_key,
    )
        .unwrap();
    assert_ne!(voucher_a.voucher_id, voucher_b.voucher_id);

    // 2. Erstelle eine gültige Bürgschaft für Gutschein A
    let (g1_pub, g1_priv) = crypto_utils::generate_ed25519_keypair_for_tests(Some("g_replay"));
    let g1_id = crypto_utils::create_user_id(&g1_pub, Some("g1")).unwrap();
    let valid_signature_for_a =
        create_guarantor_signature(&voucher_a.voucher_id, g1_id, "Replay", "1", &g1_priv);

    // 3. Versuche, die Signatur von A an B anzuhängen (Replay-Angriff)
    // (Wir benötigen eine zweite "Dummy"-Signatur, um die Anforderung von 2 Bürgen zu erfüllen)
    let (g2_pub, g2_priv) = crypto_utils::generate_ed25519_keypair_for_tests(Some("g_dummy"));
    let g2_id = crypto_utils::create_user_id(&g2_pub, Some("g2")).unwrap();
    let dummy_signature_for_b =
        create_guarantor_signature(&voucher_b.voucher_id, g2_id, "Dummy", "2", &g2_priv);

    voucher_b.guarantor_signatures.push(valid_signature_for_a); // Falsche Signatur
    voucher_b.guarantor_signatures.push(dummy_signature_for_b); // Korrekte Signatur

    // 4. Validierung von B muss fehlschlagen, weil die erste Signatur die falsche voucher_id referenziert.
    let validation_result = validate_voucher_against_standard(&voucher_b, &standard);
    assert!(validation_result.is_err());
    match validation_result.unwrap_err() {
        VoucherCoreError::Validation(ValidationError::MismatchedVoucherIdInSignature { expected, found }) => {
            assert_eq!(expected, voucher_b.voucher_id);
            assert_eq!(found, voucher_a.voucher_id);
        }
        e => panic!("Expected MismatchedVoucherIdInSignature error, but got {:?}", e),
    }
}

#[test]
fn test_validation_fails_on_tampered_guarantor_signature() {
    // 1. Erstelle einen vollständig gültigen Gutschein
    let standard_toml = std::fs::read_to_string("voucher_standards/minuto_standard.toml").unwrap();
    let standard: VoucherStandardDefinition = load_standard_definition(&standard_toml).unwrap();
    let (signing_key, creator) = setup_creator();
    let mut voucher =
        create_voucher(create_minuto_voucher_data(creator), &standard, &signing_key).unwrap();

    let (g1_pub, g1_priv) = crypto_utils::generate_ed25519_keypair_for_tests(Some("g1_tamper"));
    let (g2_pub, g2_priv) = crypto_utils::generate_ed25519_keypair_for_tests(Some("g2_tamper"));
    let g1_id = crypto_utils::create_user_id(&g1_pub, Some("g1")).unwrap();
    let g2_id = crypto_utils::create_user_id(&g2_pub, Some("g2")).unwrap();

    let sig1 = create_guarantor_signature(&voucher.voucher_id, g1_id, "Original", "1", &g1_priv);
    let sig2 =
        create_guarantor_signature(&voucher.voucher_id, g2_id, "Untampered", "2", &g2_priv);
    voucher.guarantor_signatures.push(sig1);
    voucher.guarantor_signatures.push(sig2);
    assert!(validate_voucher_against_standard(&voucher, &standard).is_ok());

    // 2. Manipuliere die Metadaten der ersten Signatur, NACHDEM sie erstellt wurde.
    let original_signature_id = voucher.guarantor_signatures[0].signature_id.clone();
    voucher.guarantor_signatures[0].first_name = "Tampered".to_string();

    // 3. Die Validierung muss nun fehlschlagen, da der Hash der Daten nicht mehr zur signature_id passt.
    let validation_result = validate_voucher_against_standard(&voucher, &standard);
    assert!(matches!(validation_result.unwrap_err(), VoucherCoreError::Validation(ValidationError::InvalidSignatureId(id)) if id == original_signature_id));
}

#[test]
fn test_double_spend_detection_logic() {
    // 1. Setup: Silber-Standard, ein Ersteller (Alice) und zwei Empfänger (Bob, Frank).
    let standard_toml = std::fs::read_to_string("voucher_standards/silver_standard.toml").unwrap();
    let standard: VoucherStandardDefinition = load_standard_definition(&standard_toml).unwrap();

    let (alice_key, alice_creator) = setup_creator();
    let alice_id = alice_creator.id.clone();

    let (bob_pub, _) = crypto_utils::generate_ed25519_keypair_for_tests(Some("bob"));
    let bob_id = crypto_utils::create_user_id(&bob_pub, Some("rc")).unwrap();

    let (frank_pub, _) = crypto_utils::generate_ed25519_keypair_for_tests(Some("frank"));
    let frank_id = crypto_utils::create_user_id(&frank_pub, Some("fr")).unwrap();

    // 2. Alice erstellt einen Gutschein mit dem Wert 100.
    let mut voucher_data = create_minuto_voucher_data(alice_creator);
    voucher_data.nominal_value.amount = "100".to_string();
    let initial_voucher = create_voucher(voucher_data, &standard, &alice_key).unwrap();
    assert!(validate_voucher_against_standard(&initial_voucher, &standard).is_ok());

    // 3. Alice führt eine erste, legitime Transaktion durch: Sie sendet 40 an Bob.
    let voucher_after_split = create_transaction(
        &initial_voucher, &standard, &alice_id, &alice_key, &bob_id, "40"
    ).unwrap();
    assert!(validate_voucher_against_standard(&voucher_after_split, &standard).is_ok());

    // 4. Alice betrügt: Sie nimmt den Zustand VOR der Transaktion an Bob (`initial_voucher`)
    //    und versucht, ihr ursprüngliches Guthaben von 100 erneut auszugeben, indem sie 60 an Frank sendet.
    let fraudulent_voucher = create_transaction(
        &initial_voucher, &standard, &alice_id, &alice_key, &frank_id, "60"
    ).unwrap();
    assert!(validate_voucher_against_standard(&fraudulent_voucher, &standard).is_ok());

    // 5. Verifizierung des Double Spends:
    //    Beide Gutscheine sind für sich genommen gültig, aber die zweite Transaktion in beiden
    //    basiert auf demselben Vorgänger (der `init`-Transaktion).
    let tx_to_bob = &voucher_after_split.transactions[1];
    let fraudulent_tx_to_frank = &fraudulent_voucher.transactions[1];

    // Der Beweis: Gleicher `prev_hash` und `sender_id`, aber unterschiedliche `t_id`.
    // Dies ist der Fingerabdruck, den ein Layer-2-System erkennen würde.
    assert_eq!(tx_to_bob.prev_hash, fraudulent_tx_to_frank.prev_hash, "prev_hash values must be identical to prove the double spend");
    assert_eq!(tx_to_bob.sender_id, fraudulent_tx_to_frank.sender_id, "Sender IDs must be identical");
    assert_ne!(tx_to_bob.t_id, fraudulent_tx_to_frank.t_id, "Transaction IDs must be different");

    println!("Double Spend Test: OK. prev_hash für beide Transaktionen ist: {}", tx_to_bob.prev_hash);
}

// --- Hilfsfunktionen für den Transfer-Test, um private Logik der Wallet-Fassade zu simulieren ---

/// Berechnet das Guthaben eines bestimmten Nutzers nach einer spezifischen Transaktionshistorie.
fn get_balance_at_transaction(
    history: &[Transaction],
    user_id: &str,
    initial_amount: &str,
) -> Decimal {
    let mut current_balance = Decimal::ZERO;
    let total_amount = Decimal::from_str_exact(initial_amount).unwrap_or_default();

    for tx in history {
        let tx_amount = Decimal::from_str_exact(&tx.amount).unwrap_or_default();
        if tx.recipient_id == user_id {
            if tx.t_type == "init" {
                current_balance = total_amount;
            } else {
                current_balance += tx_amount;
            }
        } else if tx.sender_id == user_id {
            if let Some(remaining_str) = &tx.sender_remaining_amount {
                if let Ok(remaining_amount) = Decimal::from_str_exact(remaining_str) {
                    current_balance = remaining_amount;
                } else {
                    current_balance = Decimal::ZERO;
                }
            } else {
                current_balance = Decimal::ZERO;
            }
        }
    }
    current_balance
}

/// Berechnet eine deterministische, lokale ID für eine Gutschein-Instanz.
fn calculate_local_instance_id(voucher: &Voucher, profile_owner_id: &str) -> String {
    let mut defining_transaction_id: Option<String> = None;

    for i in (0..voucher.transactions.len()).rev() {
        let history_slice = &voucher.transactions[..=i];
        let balance =
            get_balance_at_transaction(history_slice, profile_owner_id, &voucher.nominal_value.amount);

        if balance > Decimal::ZERO {
            defining_transaction_id = Some(voucher.transactions[i].t_id.clone());
            break;
        }
    }

    let t_id = defining_transaction_id.expect("Voucher must be owned by the user.");
    let combined_string = format!("{}{}{}", voucher.voucher_id, t_id, profile_owner_id);
    get_hash(combined_string)
}

#[test]
fn test_secure_voucher_transfer_via_encrypted_bundle() {
    // --- 1. SETUP ---
    let standard_toml = std::fs::read_to_string("voucher_standards/silver_standard.toml").unwrap();
    let standard: VoucherStandardDefinition = load_standard_definition(&standard_toml).unwrap();

    let (alice_pub, alice_key) =
        crypto_utils::generate_ed25519_keypair_for_tests(Some("alice_secure_transfer"));
    let alice_user_id = crypto_utils::create_user_id(&alice_pub, Some("al")).unwrap();
    let alice_identity = UserIdentity {
        signing_key: alice_key.clone(),
        public_key: alice_pub,
        user_id: alice_user_id.clone(),
    };
    let mut alice_wallet = Wallet {
        profile: UserProfile { user_id: alice_user_id },
        voucher_store: VoucherStore::default(),
        bundle_meta_store: BundleMetadataStore::default(),
        fingerprint_store: FingerprintStore::default(),
        proof_store: Default::default(),
    };

    let (bob_pub, bob_key) =
        crypto_utils::generate_ed25519_keypair_for_tests(Some("bob_secure_transfer"));
    let bob_user_id = crypto_utils::create_user_id(&bob_pub, Some("bo")).unwrap();
    let bob_identity = UserIdentity { signing_key: bob_key, public_key: bob_pub, user_id: bob_user_id.clone() };
    let mut bob_wallet = Wallet {
        profile: UserProfile { user_id: bob_user_id },
        voucher_store: VoucherStore::default(),
        bundle_meta_store: BundleMetadataStore::default(),
        fingerprint_store: FingerprintStore::default(),
        proof_store: Default::default(),
    };

    // --- 2. VOUCHER CREATION by Alice ---
    let alice_creator = Creator {
        id: alice_identity.user_id.clone(),
        first_name: "Alice".to_string(),
        // Restliche Felder für den Test gekürzt
        ..setup_creator().1
    };

    let voucher_data = NewVoucherData {
        validity_duration: Some("P3Y".to_string()),
        non_redeemable_test_voucher: false,
        nominal_value: NominalValue { amount: "500".to_string(), ..create_minuto_voucher_data(alice_creator.clone()).nominal_value },
        collateral: Collateral::default(),
        creator: alice_creator,
    };

    let voucher = create_voucher(voucher_data, &standard, &alice_key).unwrap();
    let local_id = calculate_local_instance_id(&voucher, &alice_identity.user_id);
    
    // Alice adds the new voucher to her wallet's store
    alice_wallet.voucher_store.vouchers.insert(local_id.clone(), (voucher, VoucherStatus::Active));
    assert!(alice_wallet.voucher_store.vouchers.contains_key(&local_id));

    // --- 3. SECURE TRANSFER from Alice to Bob ---
    // Anstatt die Transaktion manuell zu erstellen und zu bündeln, verwenden wir die
    // öffentliche `create_transfer`-Methode, die die Zustandsverwaltung (Archivierung) korrekt durchführt.
    let (encrypted_bundle_for_bob, _) = alice_wallet.create_transfer(
        &alice_identity,
        &standard,
        &local_id,
        &bob_identity.user_id,
        "500", // Sende den vollen Betrag
        Some("Here is the voucher I promised!".to_string()),
        None::<&FileVoucherArchive>,
    ).unwrap();

    // Der Gutschein wird nicht entfernt, sondern archiviert. Wir prüfen den Status.
    let (_, status) = alice_wallet.voucher_store.vouchers.get(&local_id).expect("Voucher should still be in wallet");
    assert_eq!(*status, VoucherStatus::Archived, "Voucher status should be Archived after sending.");
    assert_eq!(
        alice_wallet.bundle_meta_store.history.len(),
        1,
        "Alice's bundle history should contain one entry."
    );

    // --- 4. RECEIPT AND PROCESSING by Bob ---
    bob_wallet
        .process_encrypted_transaction_bundle(&bob_identity, &encrypted_bundle_for_bob, None::<&FileVoucherArchive>)
        .unwrap();

    // --- 5. VERIFICATION ---
    assert_eq!(bob_wallet.voucher_store.vouchers.len(), 1, "Bob's wallet should now have one voucher.");
    assert_eq!(
        bob_wallet.bundle_meta_store.history.len(),
        1,
        "Bob's bundle history should contain one entry."
    );

    // Berechne die lokale ID für Bobs Instanz des Gutscheins.
    let (received_voucher, _) = bob_wallet.voucher_store.vouchers.values().next().unwrap();
    let bob_local_id = calculate_local_instance_id(received_voucher, &bob_identity.user_id);
    assert!(bob_wallet.voucher_store.vouchers.contains_key(&bob_local_id), "Voucher with correct local ID should be in Bob's wallet.");

    // Füge die finale Überprüfung hinzu, ob der empfangene Gutschein auch wirklich gültig ist.
    assert!(validate_voucher_against_standard(received_voucher, &standard).is_ok(), "Received voucher must be valid.");
    println!("SUCCESS: Voucher was securely transferred from Alice to Bob via an encrypted bundle.");
}
