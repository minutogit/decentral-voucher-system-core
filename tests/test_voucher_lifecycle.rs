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
mod test_utils;

use voucher_lib::{
    create_transaction, create_voucher, crypto_utils, from_json, get_spendable_balance,
    to_canonical_json, to_json, validate_voucher_against_standard, Collateral, Creator,
    GuarantorSignature, NewVoucherData, NominalValue, Transaction, Voucher, VoucherCoreError
};
use voucher_lib::services::crypto_utils::get_hash;
use voucher_lib::services::{
    voucher_manager::VoucherManagerError, voucher_validation::ValidationError,
};
use ed25519_dalek::SigningKey;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use test_utils::{setup_in_memory_wallet, ACTORS, MINUTO_STANDARD, SILVER_STANDARD};

// --- HELPER-FUNKTIONEN UND TESTDATEN ---

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
    // Wir übergeben den ganzen Gutschein, um Zugriff auf das Erstellungsdatum zu haben.
    voucher: &Voucher,
    guarantor_id: String,
    guarantor_first_name: &str,
    guarantor_gender: &str,
    signing_key: &SigningKey,
) -> GuarantorSignature {
    // Erzeuge einen Zeitstempel, der garantiert NACH der Erstellung des Gutscheins liegt.
    let creation_dt = chrono::DateTime::parse_from_rfc3339(&voucher.creation_date)
        .unwrap()
        .with_timezone(&chrono::Utc);
    let signature_dt = creation_dt + chrono::Duration::days(1);
    let signature_time_str = signature_dt.to_rfc3339();

    // 1. Erstelle das Signatur-Objekt, aber lasse die finale Signatur und die ID leer.
    let mut signature_data = GuarantorSignature {
        voucher_id: voucher.voucher_id.clone(),
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
        signature_time: signature_time_str,
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
    let identity = &ACTORS.issuer;
    let creator = Creator { id: identity.user_id.clone(), ..Default::default() };
    let voucher_data = create_minuto_voucher_data(creator);

    // NEU: Den Standard und seinen Hash aus dem Tupel extrahieren.
    let (minuto_standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    // 2. Erstellung
    let mut voucher = create_voucher(voucher_data, minuto_standard, standard_hash, &identity.signing_key, "en").unwrap();
    assert!(!voucher.voucher_id.is_empty());
    assert!(!voucher.creator.signature.is_empty());
    // Prüfe die neuen Werte, die aus dem geänderten Standard kommen.
    assert_eq!(voucher.standard_minimum_issuance_validity, "P3Y");
    // Prüfe, ob das Gültigkeitsdatum korrekt auf das Jahresende gerundet wurde.
    assert!(voucher.valid_until.contains("-12-31T23:59:59"));
    let expected_description = "A voucher for goods or services worth 60 minutes of quality performance.";
    assert_eq!(voucher.description, expected_description);

    // 3. Erste Validierung: Muss fehlschlagen, da Bürgen fehlen.
    let initial_validation_result = validate_voucher_against_standard(&voucher, minuto_standard);
    assert!(matches!(
        initial_validation_result.unwrap_err(),
        VoucherCoreError::Validation(ValidationError::GuarantorRequirementsNotMet(_))
    ));

    // 4. Simulation des Bürgenprozesses nach neuer Logik
    let g1 = &ACTORS.guarantor1;
    let g2 = &ACTORS.guarantor2;
    let guarantor_sig_1 = create_guarantor_signature(&voucher, g1.user_id.clone(), "Hans", "1", &g1.signing_key);
    let guarantor_sig_2 = create_guarantor_signature(&voucher, g2.user_id.clone(), "Gabi", "2", &g2.signing_key);

    voucher.guarantor_signatures.push(guarantor_sig_1);
    voucher.guarantor_signatures.push(guarantor_sig_2);

    // 5. Finale Validierung (Positivfall mit Bürgen)
    let final_validation_result = validate_voucher_against_standard(&voucher, minuto_standard);
    assert!(
        final_validation_result.is_ok(),
        "Final validation failed unexpectedly: {:?}",
        final_validation_result.err()
    );

    // 6. Finale Überprüfung des Guthabens mit der neuen Funktion
    let balance = get_spendable_balance(&voucher, &voucher.creator.id, minuto_standard).unwrap();
    let expected_balance = Decimal::from_str_exact(voucher.nominal_value.amount.as_str()).unwrap();
    assert_eq!(
        balance, expected_balance,
        "Final balance check failed."
    );
}

#[test]
fn test_serialization_deserialization() {
    // 1. Erstelle einen Gutschein
    let identity = &ACTORS.issuer;
    let creator = Creator { id: identity.user_id.clone(), ..Default::default() };
    let voucher_data = create_minuto_voucher_data(creator);

    let (minuto_standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    let original_voucher = create_voucher(voucher_data, minuto_standard, standard_hash, &identity.signing_key, "en").unwrap();

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
    let identity = &ACTORS.issuer;
    let creator = Creator { id: identity.user_id.clone(), ..Default::default() };
    let voucher_data = create_minuto_voucher_data(creator);

    let (minuto_standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    let mut voucher = create_voucher(voucher_data, minuto_standard, standard_hash, &identity.signing_key, "en").unwrap();

    // Füge die benötigten Bürgen hinzu, um den Gutschein valide zu machen, BEVOR wir ihn manipulieren.
    // Ansonsten würde die Validierung bereits an den fehlenden Bürgen scheitern.
    let g1 = &ACTORS.guarantor1;
    let g2 = &ACTORS.guarantor2;
    let guarantor_sig_1 = create_guarantor_signature(&voucher, g1.user_id.clone(), "Guarantor1", "1", &g1.signing_key);
    let guarantor_sig_2 = create_guarantor_signature(&voucher, g2.user_id.clone(), "Guarantor2", "2", &g2.signing_key);
    voucher.guarantor_signatures.push(guarantor_sig_1);
    voucher.guarantor_signatures.push(guarantor_sig_2);
    assert!(validate_voucher_against_standard(&voucher, minuto_standard).is_ok());

    // 2. Manipuliere die Signatur
    voucher.creator.signature = "invalid_signature_string_12345".to_string();

    // 3. Validierung sollte fehlschlagen
    let validation_result = validate_voucher_against_standard(&voucher, minuto_standard);
    assert!(validation_result.is_err());
    // Wir erwarten einen Fehler beim Dekodieren der Signatur, da sie kein gültiges Base58 ist.
    assert!(matches!(
        validation_result.unwrap_err(),
        VoucherCoreError::Validation(ValidationError::SignatureDecodeError(_))
    ));
}

#[test]
fn test_validation_fails_on_missing_required_field() {
    let identity = &ACTORS.issuer;
    let creator = Creator { id: identity.user_id.clone(), ..Default::default() }; 
    let voucher_data = create_minuto_voucher_data(creator);

    let (minuto_standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    let voucher = create_voucher(voucher_data, minuto_standard, standard_hash, &identity.signing_key, "en").unwrap();

    // 2. Lade einen manipulierten Standard, der ein zusätzliches Feld erfordert
    let mut standard = minuto_standard.clone();
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
    // Erstelle einen initial gültigen Gutschein nach dem Silber-Standard.
    let identity = &ACTORS.issuer;
    let creator = Creator { id: identity.user_id.clone(), ..Default::default() };
    let voucher_data = create_minuto_voucher_data(creator);

    let (silver_standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);

    let mut voucher = create_voucher(voucher_data, silver_standard, standard_hash, &identity.signing_key, "en").unwrap();

    // Manipuliere die Einheit NACH der Erstellung, um einen inkonsistenten Zustand zu erzeugen.
    voucher.nominal_value.unit = "EUR".to_string();

    // Validierung sollte wegen der Einheit fehlschlagen
    let validation_result = validate_voucher_against_standard(&voucher, silver_standard);
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
    let identity = &ACTORS.issuer;
    let creator = Creator { id: identity.user_id.clone(), ..Default::default() };
    let voucher_data = create_minuto_voucher_data(creator);

    let (minuto_standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    let mut voucher = create_voucher(voucher_data, minuto_standard, standard_hash, &identity.signing_key, "en").unwrap();

    // Der erstellte Gutschein hat 0 Bürgen, der Standard erfordert aber 2
    voucher.guarantor_signatures.clear();

    let validation_result = validate_voucher_against_standard(&voucher, minuto_standard);
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
    let identity = &ACTORS.issuer;
    let creator = Creator { id: identity.user_id.clone(), ..Default::default() };
    let data1 = create_minuto_voucher_data(creator.clone());
    let data2 = create_minuto_voucher_data(creator);

    let (minuto_standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    // 2. Erstelle zwei Gutscheine nacheinander.
    // Wir fügen eine winzige Pause ein, um sicherzustellen, dass die Zeitstempel
    // und somit die Hashes sich auf jeden Fall unterscheiden.
    let voucher1 = create_voucher(data1, minuto_standard, standard_hash, &identity.signing_key, "en").unwrap();
    std::thread::sleep(std::time::Duration::from_micros(10));
    let voucher2 = create_voucher(data2, minuto_standard, standard_hash, &identity.signing_key, "en").unwrap();

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
        MINUTO_STANDARD.0.metadata.abbreviation, MINUTO_STANDARD.0.template.fixed.nominal_value.unit
    );
    assert_eq!(canonical_json, expected_json);
    println!("Canonical Nominal Value: {}", canonical_json);
}

#[test]
fn test_validation_succeeds_with_extra_fields_in_json() {
    // 1. Erstelle einen VOLLSTÄNDIG gültigen Gutschein, inklusive der benötigten Bürgen.
    let identity = &ACTORS.issuer;
    let creator = Creator { id: identity.user_id.clone(), ..Default::default() };
    let voucher_data = create_minuto_voucher_data(creator);

    let (minuto_standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    let mut valid_voucher = create_voucher(voucher_data, minuto_standard, standard_hash, &identity.signing_key, "en").unwrap();

    // Füge die für den Minuto-Standard erforderlichen Bürgen hinzu.
    let g1 = &ACTORS.guarantor1;
    let g2 = &ACTORS.guarantor2;

    let guarantor_sig_1 = create_guarantor_signature(&valid_voucher, g1.user_id.clone(), "Guarantor1", "1", &g1.signing_key);
    let guarantor_sig_2 = create_guarantor_signature(&valid_voucher, g2.user_id.clone(), "Guarantor2", "2", &g2.signing_key);
    valid_voucher.guarantor_signatures.push(guarantor_sig_1);
    valid_voucher.guarantor_signatures.push(guarantor_sig_2);

    // Stelle sicher, dass der Gutschein jetzt gültig ist, bevor wir ihn modifizieren.
    assert!(validate_voucher_against_standard(&valid_voucher, minuto_standard).is_ok());

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
    let validation_result = validate_voucher_against_standard(&deserialized_voucher, minuto_standard);

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
    let (silver_standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
    assert!(silver_standard.template.fixed.is_divisible);

    // 2. Erstelle Sender und Empfänger
    let sender = &ACTORS.alice;
    let recipient = &ACTORS.bob;
    let sender_creator = Creator { id: sender.user_id.clone(), ..Default::default() };

    // 3. Erstelle einen Gutschein mit dem Wert 100.0000
    let mut voucher_data = create_minuto_voucher_data(sender_creator);
    voucher_data.nominal_value.amount = "100.0000".to_string();

    let initial_voucher = create_voucher(voucher_data, silver_standard, standard_hash, &sender.signing_key, "en").unwrap();

    // 4. Überprüfe den initialen Zustand und das Guthaben
    assert!(validate_voucher_against_standard(&initial_voucher, silver_standard).is_ok());
    let initial_balance = get_spendable_balance(&initial_voucher, &sender.user_id, silver_standard).unwrap();
    assert_eq!(initial_balance, dec!(100.0000));

    // 5. Führe eine Split-Transaktion durch: Sende 30.5000 an den Empfänger
    let split_amount = "30.5000";
    let voucher_after_split = create_transaction(
        &initial_voucher,
        &SILVER_STANDARD.0,
        &sender.user_id,
        &sender.signing_key,
        &recipient.user_id,
        split_amount,
    )
    .unwrap();

    // 6. Validiere den Gutschein nach dem Split
    let validation_result = validate_voucher_against_standard(&voucher_after_split, silver_standard);
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
        get_spendable_balance(&voucher_after_split, &sender.user_id, silver_standard).unwrap();
    let recipient_balance_after_split =
        get_spendable_balance(&voucher_after_split, &recipient.user_id, silver_standard).unwrap();

    assert_eq!(sender_balance_after_split, dec!(69.5000)); // 100.0000 - 30.5000
    assert_eq!(recipient_balance_after_split, dec!(30.5000));
}

#[test]
fn test_split_fails_on_insufficient_funds() {
    // Setup wie oben
    let sender = &ACTORS.alice;
    let recipient = &ACTORS.bob;
    let sender_creator = Creator { id: sender.user_id.clone(), ..Default::default() };

    let mut voucher_data = create_minuto_voucher_data(sender_creator);
    voucher_data.nominal_value.amount = "50.0".to_string(); // Initialwert 50

    let (silver_standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);

    let initial_voucher = create_voucher(voucher_data, silver_standard, standard_hash, &sender.signing_key, "en").unwrap();

    // Versuche, 50.1 zu senden (mehr als vorhanden)
    let split_result = create_transaction(
        &initial_voucher,
        silver_standard,
        &sender.user_id,
        &sender.signing_key,
        &recipient.user_id,
        "50.1",
    );

    assert!(matches!(
        split_result.unwrap_err(),
        VoucherCoreError::Manager(VoucherManagerError::InsufficientFunds { .. })
    ));
}

#[test]
fn test_split_fails_on_non_divisible_voucher() {
    // Manipuliere den Standard, um ihn nicht-teilbar zu machen
    let (mut standard, _) = (SILVER_STANDARD.0.clone(), SILVER_STANDARD.1.clone());
    standard.template.fixed.is_divisible = false;
    assert!(!standard.template.fixed.is_divisible);

    // Da der Standard manipuliert wurde, muss der Konsistenz-Hash neu berechnet werden.
    let mut standard_to_hash = standard.clone();
    standard_to_hash.signature = None;
    let new_hash = get_hash(to_canonical_json(&standard_to_hash).unwrap());

    let sender = &ACTORS.alice;
    let recipient = &ACTORS.bob;
    let sender_creator = Creator { id: sender.user_id.clone(), ..Default::default() };

    let mut voucher_data = create_minuto_voucher_data(sender_creator);
    voucher_data.nominal_value.amount = "60.0000".to_string();

    let initial_voucher = create_voucher(voucher_data, &standard, &new_hash, &sender.signing_key, "en").unwrap();

    let split_result = create_transaction(
        &initial_voucher,
        &standard,
        &sender.user_id,
        &sender.signing_key,
        &recipient.user_id,
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
    let identity = &ACTORS.issuer;
    let creator = Creator { id: identity.user_id.clone(), ..Default::default() };

    // 2. Testfall: Versuch, einen Gutschein mit zu kurzer Gültigkeit zu erstellen.
    // Der Minuto-Standard erfordert P3Y. Wir versuchen es mit P2Y.
    let mut short_duration_data = create_minuto_voucher_data(creator.clone());
    let (minuto_standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    short_duration_data.validity_duration = Some("P2Y".to_string());
    let creation_result = create_voucher(short_duration_data, minuto_standard, standard_hash, &identity.signing_key, "en");

    assert!(
        matches!(
            creation_result.unwrap_err(),
            VoucherCoreError::Manager(VoucherManagerError::InvalidValidityDuration(_))
        ),
        "Creation should fail with InvalidValidityDuration error"
    );

    // 3. Testfall: Erstelle einen gültigen Gutschein und manipuliere dann sein Gültigkeitsdatum.
    let valid_data = create_minuto_voucher_data(creator.clone());
    let mut voucher = create_voucher(valid_data, minuto_standard, standard_hash, &identity.signing_key, "en").unwrap();

    // Mache ihn mit Bürgen vollständig gültig, um die Datumsprüfung zu isolieren.
    let g1 = &ACTORS.guarantor1;
    let g2 = &ACTORS.guarantor2;
    voucher.guarantor_signatures.push(create_guarantor_signature(&voucher, g1.user_id.clone(), "G1", "1", &g1.signing_key));
    voucher.guarantor_signatures.push(create_guarantor_signature(&voucher, g2.user_id.clone(), "G2", "2", &g2.signing_key));
    assert!(validate_voucher_against_standard(&voucher, minuto_standard).is_ok());

    // Manipuliere das Datum
    let creation_dt = chrono::DateTime::parse_from_rfc3339(&voucher.creation_date).unwrap();
    let tampered_until_dt = creation_dt + chrono::Duration::days(10); // weniger als 90
    voucher.valid_until = tampered_until_dt.to_rfc3339();

    let validation_result = validate_voucher_against_standard(&voucher, minuto_standard);
    assert!(matches!(
        validation_result.unwrap_err(),
        VoucherCoreError::Validation(ValidationError::ValidityDurationTooShort { .. })
    ));

    // 4. Testfall: Nicht übereinstimmende Mindestgültigkeitsregel zwischen Gutschein und Standard
    let mut voucher2 = create_voucher(create_minuto_voucher_data(creator.clone()), minuto_standard, standard_hash, &identity.signing_key, "en").unwrap();
    // Manipuliere die im Gutschein gespeicherte Regel
    voucher2.standard_minimum_issuance_validity = "P1Y".to_string(); // Standard erwartet P3Y
    let validation_result2 = validate_voucher_against_standard(&voucher2, minuto_standard);
    assert!(matches!(
        validation_result2.unwrap_err(),
        VoucherCoreError::Validation(ValidationError::MismatchedMinimumValidity { .. })
    ));
}

// --- NEUE SICHERHEITSTESTS ---

#[test]
fn test_validation_fails_on_replayed_guarantor_signature() {
    // 1. Erstelle zwei verschiedene Gutscheine
    let creator1_identity = &ACTORS.alice;
    let creator1 = Creator { id: creator1_identity.user_id.clone(), ..Default::default() };
    let (minuto_standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    let voucher_a =
        create_voucher(create_minuto_voucher_data(creator1), minuto_standard, standard_hash, &creator1_identity.signing_key, "en").unwrap();

    let creator2_identity = &ACTORS.bob;
    let creator2 = Creator { id: creator2_identity.user_id.clone(), ..Default::default() };
    let mut voucher_b = create_voucher(create_minuto_voucher_data(creator2), minuto_standard, standard_hash, &creator2_identity.signing_key, "en").unwrap();
    assert_ne!(voucher_a.voucher_id, voucher_b.voucher_id);

    // 2. Erstelle eine gültige Bürgschaft für Gutschein A
    let g1 = &ACTORS.guarantor1;
    let valid_signature_for_a = create_guarantor_signature(&voucher_a, g1.user_id.clone(), "Replay", "1", &g1.signing_key);

    // 3. Versuche, die Signatur von A an B anzuhängen (Replay-Angriff)
    // (Wir benötigen eine zweite "Dummy"-Signatur, um die Anforderung von 2 Bürgen zu erfüllen)
    let g2 = &ACTORS.guarantor2;
    let dummy_signature_for_b =
        create_guarantor_signature(&voucher_b, g2.user_id.clone(), "Dummy", "2", &g2.signing_key);

    voucher_b.guarantor_signatures.push(valid_signature_for_a); // Falsche Signatur
    voucher_b.guarantor_signatures.push(dummy_signature_for_b); // Korrekte Signatur

    // 4. Validierung von B muss fehlschlagen, weil die erste Signatur die falsche voucher_id referenziert.
    let validation_result = validate_voucher_against_standard(&voucher_b, minuto_standard);
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
    let identity = &ACTORS.issuer;
    let creator = Creator { id: identity.user_id.clone(), ..Default::default() };
    let (minuto_standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    let mut voucher =
        create_voucher(create_minuto_voucher_data(creator), minuto_standard, standard_hash, &identity.signing_key, "en").unwrap();

    let g1 = &ACTORS.guarantor1;
    let g2 = &ACTORS.guarantor2;

    let sig1 = create_guarantor_signature(&voucher, g1.user_id.clone(), "Original", "1", &g1.signing_key);
    let sig2 = create_guarantor_signature(&voucher, g2.user_id.clone(), "Untampered", "2", &g2.signing_key);
    voucher.guarantor_signatures.push(sig1);
    voucher.guarantor_signatures.push(sig2);
    assert!(validate_voucher_against_standard(&voucher, minuto_standard).is_ok());

    // 2. Manipuliere die Metadaten der ersten Signatur, NACHDEM sie erstellt wurde.
    let original_signature_id = voucher.guarantor_signatures[0].signature_id.clone();
    voucher.guarantor_signatures[0].first_name = "Tampered".to_string();

    // 3. Die Validierung muss nun fehlschlagen, da der Hash der Daten nicht mehr zur signature_id passt.
    let validation_result = validate_voucher_against_standard(&voucher, minuto_standard);
    assert!(matches!(validation_result.unwrap_err(), VoucherCoreError::Validation(ValidationError::InvalidSignatureId(id)) if id == original_signature_id));
}

#[test]
fn test_double_spend_detection_logic() {
    // 1. Setup: Silber-Standard, ein Ersteller (Alice) und zwei Empfänger (Bob, Frank).
    let alice = &ACTORS.alice;
    let bob = &ACTORS.bob;
    let frank = &ACTORS.charlie; // Use charlie as Frank
    let alice_creator = Creator { id: alice.user_id.clone(), ..Default::default() };

    // 2. Alice erstellt einen Gutschein mit dem Wert 100.
    let mut voucher_data = create_minuto_voucher_data(alice_creator);
    voucher_data.nominal_value.amount = "100".to_string();

    let (silver_standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);

    let initial_voucher = create_voucher(voucher_data, silver_standard, standard_hash, &alice.signing_key, "en").unwrap();
    assert!(validate_voucher_against_standard(&initial_voucher, silver_standard).is_ok());

    // 3. Alice führt eine erste, legitime Transaktion durch: Sie sendet 40 an Bob.
    let voucher_after_split = create_transaction(
        &initial_voucher, silver_standard, &alice.user_id, &alice.signing_key, &bob.user_id, "40"
    ).unwrap();
    // NEU: Verbessertes Assert, das den Fehler im Detail ausgibt.
    let validation_result_1 = validate_voucher_against_standard(&voucher_after_split, silver_standard);
    assert!(
        validation_result_1.is_ok(),
        "Validation of the first legitimate transaction failed unexpectedly: {:?}",
        validation_result_1.err()
    );

    // 4. Alice betrügt: Sie nimmt den Zustand VOR der Transaktion an Bob (`initial_voucher`)
    //    und versucht, ihr ursprüngliches Guthaben von 100 erneut auszugeben, indem sie 60 an Frank sendet.
    let fraudulent_voucher = create_transaction(
        &initial_voucher, silver_standard, &alice.user_id, &alice.signing_key, &frank.user_id, "60"
    ).unwrap();
    // NEU: Verbessertes Assert auch für den zweiten Gutschein.
    let validation_result_2 = validate_voucher_against_standard(&fraudulent_voucher, silver_standard);
    assert!(validation_result_2.is_ok(), "Validation of the fraudulent (but individually valid) transaction failed unexpectedly: {:?}", validation_result_2.err());

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

use voucher_lib::models::profile::VoucherStatus;
#[test]
fn test_secure_voucher_transfer_via_encrypted_bundle() {
    // --- 1. SETUP ---
    let alice_identity = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(alice_identity);
    let bob_identity = &ACTORS.bob;
    let mut bob_wallet = setup_in_memory_wallet(bob_identity);

    // --- 2. VOUCHER CREATION by Alice ---
    let alice_creator = Creator {
        id: alice_identity.user_id.clone(),
        first_name: "Alice".to_string(),
        // Restliche Felder für den Test gekürzt
        ..Default::default()
    };

    let voucher_data = NewVoucherData {
        validity_duration: Some("P3Y".to_string()),
        non_redeemable_test_voucher: false,
        nominal_value: NominalValue { amount: "500".to_string(), ..create_minuto_voucher_data(alice_creator.clone()).nominal_value },
        collateral: Collateral::default(),
        creator: alice_creator,
    };

    let (silver_standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);

    let voucher = create_voucher(voucher_data, silver_standard, standard_hash, &alice_identity.signing_key, "en").unwrap();
    let local_id = calculate_local_instance_id(&voucher, &alice_identity.user_id);
    
    // Alice adds the new voucher to her wallet's store
    alice_wallet.voucher_store.vouchers.insert(local_id.clone(), (voucher, VoucherStatus::Active));
    assert!(alice_wallet.voucher_store.vouchers.contains_key(&local_id));

    // --- 3. SECURE TRANSFER from Alice to Bob ---
    // Anstatt die Transaktion manuell zu erstellen und zu bündeln, verwenden wir die
    // öffentliche `create_transfer`-Methode, die die Zustandsverwaltung (Archivierung) korrekt durchführt.
    let (encrypted_bundle_for_bob, _) = alice_wallet.create_transfer(
        &alice_identity,
        &SILVER_STANDARD.0,
        &local_id,
        &bob_identity.user_id,
        "500", // Sende den vollen Betrag
        Some("Here is the voucher I promised!".to_string()),
        None::<&dyn voucher_lib::archive::VoucherArchive>,
    ).unwrap();

    // NACH ÄNDERUNG: Die alte Instanz wird gelöscht. Es sollte nur noch eine neue, archivierte Instanz im Wallet sein.
    assert_eq!(alice_wallet.voucher_store.vouchers.len(), 1, "Alice's wallet should contain exactly one (archived) voucher instance.");
    let (_, status) = alice_wallet.voucher_store.vouchers.values().next().unwrap();
    assert_eq!(*status, VoucherStatus::Archived, "The remaining voucher's status should be Archived after sending.");
    assert_eq!(
        alice_wallet.bundle_meta_store.history.len(),
        1,
        "Alice's bundle history should contain one entry."
    );

    // --- 4. RECEIPT AND PROCESSING by Bob ---
    bob_wallet
        .process_encrypted_transaction_bundle(&bob_identity, &encrypted_bundle_for_bob, None::<&dyn voucher_lib::archive::VoucherArchive>)
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
    // KORREKTUR: Verwende ein assert!, das im Fehlerfall die genaue ValidationError ausgibt.
    let final_validation_result = validate_voucher_against_standard(received_voucher, silver_standard);
    assert!(
        final_validation_result.is_ok(),
        "Validation of the received voucher failed: {:?}",
        final_validation_result.err()
    );
    println!("SUCCESS: Voucher was securely transferred from Alice to Bob via an encrypted bundle.");
}
