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
    create_voucher, crypto_utils, from_json, load_standard_definition, to_canonical_json, to_json,
    validate_voucher_against_standard, Address, Collateral, Creator, GuarantorSignature,
    NewVoucherData, NominalValue, ValidationError, Voucher, VoucherStandard, VoucherStandardDefinition,
};
use ed25519_dalek::SigningKey;

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
        voucher_standard: VoucherStandard {
            name: "Minuto-Gutschein".to_string(),
            uuid: "MINUTO-V1-XXXX-YYYY".to_string(),
        },
        description: "Ein Test-Minuto".to_string(),
        divisible: true,
        years_valid: 1,
        non_redeemable_test_voucher: true,
        nominal_value: NominalValue {
            unit: "Minuten".to_string(),
            amount: "60".to_string(),
            abbreviation: "m".to_string(),
            description: "Qualitative Leistung".to_string(),
        },
        collateral: Collateral {
            type_: "Community-Besicherung".to_string(),
            unit: "".to_string(),
            amount: "".to_string(),
            abbreviation: "".to_string(),
            description: "Besichert durch das Vertrauen der Community.".to_string(),
            redeem_condition: "Keine direkte physische Einlösung.".to_string(),
        },
        creator,
        needed_guarantors: 2,
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
    let standard_json =
        std::fs::read_to_string("voucher_standards/minuto_standard.json").unwrap();
    let standard: VoucherStandardDefinition = load_standard_definition(&standard_json).unwrap();
    let (signing_key, creator) = setup_creator();
    let voucher_data = create_minuto_voucher_data(creator);

    // 2. Erstellung
    let mut voucher = create_voucher(voucher_data, &signing_key).unwrap();
    assert!(!voucher.voucher_id.is_empty());
    assert!(!voucher.creator.signature.is_empty());

    // 3. Erste Validierung: Muss fehlschlagen, da Bürgen fehlen.
    let initial_validation_result = validate_voucher_against_standard(&voucher, &standard);
    assert!(matches!(
        initial_validation_result.unwrap_err(),
        ValidationError::GuarantorRequirementsNotMet(_)
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
}

#[test]
fn test_serialization_deserialization() {
    // 1. Erstelle einen Gutschein
    let (signing_key, creator) = setup_creator();
    let voucher_data = create_minuto_voucher_data(creator);
    let original_voucher = create_voucher(voucher_data, &signing_key).unwrap();

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
    let standard_json =
        std::fs::read_to_string("voucher_standards/minuto_standard.json").unwrap();
    let standard: VoucherStandardDefinition = load_standard_definition(&standard_json).unwrap();
    let (signing_key, creator) = setup_creator();
    let voucher_data = create_minuto_voucher_data(creator);
    let mut voucher = create_voucher(voucher_data, &signing_key).unwrap();

    // 2. Manipuliere die Signatur
    voucher.creator.signature = "invalid_signature_string_12345".to_string();

    // 3. Validierung sollte fehlschlagen
    let validation_result = validate_voucher_against_standard(&voucher, &standard);
    assert!(validation_result.is_err());
    // Wir erwarten einen Fehler beim Dekodieren der Signatur, da sie kein gültiges Base58 ist.
    assert!(matches!(
        validation_result.unwrap_err(),
        ValidationError::SignatureDecodeError(_)
    ));
}

#[test]
fn test_validation_fails_on_missing_required_field() {
    // 1. Erstelle einen gültigen Gutschein
    let (signing_key, creator) = setup_creator();
    let voucher_data = create_minuto_voucher_data(creator);
    let voucher = create_voucher(voucher_data, &signing_key).unwrap();

    // 2. Lade einen manipulierten Standard, der ein zusätzliches Feld erfordert
    let standard_json =
        std::fs::read_to_string("voucher_standards/minuto_standard.json").unwrap();
    let mut standard: VoucherStandardDefinition = load_standard_definition(&standard_json).unwrap();
    standard
        .required_voucher_fields
        .push("creator.phone".to_string()); // creator.phone ist optional

    // 3. Validierung sollte fehlschlagen
    let validation_result = validate_voucher_against_standard(&voucher, &standard);
    assert!(validation_result.is_err());
    match validation_result.unwrap_err() {
        ValidationError::MissingRequiredField(path) => assert_eq!(path, "creator.phone"),
        _ => panic!("Expected MissingRequiredField error"),
    }
}

#[test]
fn test_validation_fails_on_inconsistent_unit() {
    let standard_json =
        std::fs::read_to_string("voucher_standards/silver_standard.json").unwrap();
    let standard: VoucherStandardDefinition = load_standard_definition(&standard_json).unwrap();
    let (signing_key, creator) = setup_creator();
    let mut voucher_data = create_minuto_voucher_data(creator);
    voucher_data.nominal_value.unit = "EUR".to_string(); // Falsche Einheit für Silber-Standard

    let voucher = create_voucher(voucher_data, &signing_key).unwrap();

    // Validierung sollte wegen der Einheit fehlschlagen
    let validation_result = validate_voucher_against_standard(&voucher, &standard);
    assert!(validation_result.is_err());
    match validation_result.unwrap_err() {
        ValidationError::IncorrectNominalValueUnit { expected, found } => {
            assert_eq!(expected, "Unzen");
            assert_eq!(found, "EUR");
        }
        e => panic!("Expected IncorrectNominalValueUnit error, but got {:?}", e),
    }
}

#[test]
fn test_validation_fails_on_guarantor_count() {
    let standard_json =
        std::fs::read_to_string("voucher_standards/minuto_standard.json").unwrap();
    let standard: VoucherStandardDefinition = load_standard_definition(&standard_json).unwrap();
    let (signing_key, creator) = setup_creator();
    let voucher_data = create_minuto_voucher_data(creator);
    let mut voucher = create_voucher(voucher_data, &signing_key).unwrap();

    // Der erstellte Gutschein hat 0 Bürgen, der Standard erfordert aber 2
    voucher.guarantor_signatures.clear();

    let validation_result = validate_voucher_against_standard(&voucher, &standard);
    assert!(validation_result.is_err());
    match validation_result.unwrap_err() {
        ValidationError::GuarantorRequirementsNotMet(_) => {
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
    let (signing_key, creator) = setup_creator();
    let data1 = create_minuto_voucher_data(creator.clone());
    let data2 = create_minuto_voucher_data(creator);

    // 2. Erstelle zwei Gutscheine nacheinander.
    let voucher1 = create_voucher(data1, &signing_key).unwrap();
    let voucher2 = create_voucher(data2, &signing_key).unwrap();

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
    // z.B. "abbreviation" vor "amount", "amount" vor "description" etc.
    // Dies bestätigt den "sorted" Aspekt des Testnamens.
    let canonical_json = to_canonical_json(&voucher1.nominal_value).unwrap();
    let expected_start =
        r#"{"abbreviation":"m","amount":"60","description":"Qualitative Leistung","unit":"Minuten"}"#;
    assert_eq!(canonical_json, expected_start);
    println!("Canonical Nominal Value: {}", canonical_json);
}

#[test]
fn test_validation_succeeds_with_extra_fields_in_json() {
    // 1. Erstelle einen VOLLSTÄNDIG gültigen Gutschein, inklusive der benötigten Bürgen.
    let (signing_key, creator) = setup_creator();
    let voucher_data = create_minuto_voucher_data(creator);
    let mut valid_voucher = create_voucher(voucher_data, &signing_key).unwrap();
    let standard_json =
        std::fs::read_to_string("voucher_standards/minuto_standard.json").unwrap();
    let standard: VoucherStandardDefinition = load_standard_definition(&standard_json).unwrap();

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

// --- NEUE SICHERHEITSTESTS ---

#[test]
fn test_validation_fails_on_replayed_guarantor_signature() {
    // 1. Erstelle zwei verschiedene Gutscheine
    let standard_json =
        std::fs::read_to_string("voucher_standards/minuto_standard.json").unwrap();
    let standard: VoucherStandardDefinition = load_standard_definition(&standard_json).unwrap();
    let (creator1_key, creator1) = setup_creator();
    let voucher_a = create_voucher(create_minuto_voucher_data(creator1), &creator1_key).unwrap();

    let (creator2_key, creator2) = setup_creator();
    let mut voucher_b = create_voucher(create_minuto_voucher_data(creator2), &creator2_key).unwrap();
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
        ValidationError::MismatchedVoucherIdInSignature { expected, found } => {
            assert_eq!(expected, voucher_b.voucher_id);
            assert_eq!(found, voucher_a.voucher_id);
        }
        e => panic!("Expected MismatchedVoucherIdInSignature error, but got {:?}", e),
    }
}

#[test]
fn test_validation_fails_on_tampered_guarantor_signature() {
    // 1. Erstelle einen vollständig gültigen Gutschein
    let standard_json =
        std::fs::read_to_string("voucher_standards/minuto_standard.json").unwrap();
    let standard: VoucherStandardDefinition = load_standard_definition(&standard_json).unwrap();
    let (signing_key, creator) = setup_creator();
    let mut voucher = create_voucher(create_minuto_voucher_data(creator), &signing_key).unwrap();

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
    assert!(matches!(validation_result.unwrap_err(), ValidationError::InvalidSignatureId(id) if id == original_signature_id));
}