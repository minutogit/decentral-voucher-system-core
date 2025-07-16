//! # Integrationstests für den gesamten Gutschein-Lebenszyklus

// Wir importieren die öffentlichen Typen, die in lib.rs re-exportiert wurden.
use voucher_lib::{
    create_voucher, crypto_utils, from_json, load_standard_definition, to_json, GuarantorSignature,
    validate_voucher_against_standard, Address, Collateral, Creator, NewVoucherData,
    NominalValue, ValidationError, Voucher, VoucherStandard, VoucherStandardDefinition, to_canonical_json,
};
use ed25519_dalek::SigningKey;

// --- HELPER-FUNKTIONEN UND TESTDATEN ---

// Definiert einen Minuto-Standard für Tests. Beachte die ISO 5218 Codes für `genders_needed`.
const MINUTO_STANDARD_JSON: &str = r#"{
  "name": "Minuto-Gutschein",
  "uuid": "MINUTO-V1-XXXX-YYYY",
  "description": "Ein Gutschein für Waren oder Dienstleistungen im Wert von X Minuten qualitativer Leistung, besichert durch eine Gemeinschaft.",
  "nominal_value_unit": "Minuten",
  "is_divisible": true,
  "primary_redemption_type": "goods_or_services",
  "guarantor_requirements": {
    "needed_count": 2,
    "gender_specific": true,
    "genders_needed": ["1", "2"],
    "description": "Ein männlicher und ein weiblicher Bürge sind erforderlich."
  },
  "collateral": {
    "type": "Community-Besicherung",
    "description": "Besichert durch das Vertrauen und die Leistung der Minuto-Community.",
    "redeem_condition": "Keine direkte physische Einlösung."
  },
  "required_voucher_fields": [
    "voucher_id",
    "creation_date",
    "creator.signature",
    "guarantor_signatures"
  ],
  "allowed_transaction_types": ["init", "split", "redeem"]
}"#;

const SILVER_STANDARD_JSON: &str = r#"{
  "name": "Silber-Umlauf-Gutschein",
  "uuid": "SILVER-PAYMENT-V1-XXXX-YYYY",
  "description": "Dieser Gutschein dient als Zahlungsmittel für Waren oder Dienstleistungen im Wert von X Unzen Silber.",
  "nominal_value_unit": "Unzen",
  "is_divisible": true,
  "primary_redemption_type": "goods_or_services",
  "guarantor_requirements": {
    "needed_count": 0,
    "gender_specific": false,
    "genders_needed": [],
    "description": "Keine Bürgen erforderlich."
  },
  "collateral": {
    "type": "Physisches Edelmetall",
    "unit": "Unzen",
    "amount": "entspricht dem Nennwert des Gutscheins",
    "description": "Der Gutschein ist durch die entsprechende Menge an physischem Silber besichert.",
    "redeem_condition": "Nur in Notfällen einlösbar."
  },
  "required_voucher_fields": [
    "voucher_id",
    "creation_date",
    "creator.signature"
  ],
  "allowed_transaction_types": ["init", "split", "redeem"]
}"#;

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


#[test]
fn test_full_creation_and_validation_cycle() {
    // 1. Setup: Lade Standard und erstelle Creator
    let standard: VoucherStandardDefinition =
        load_standard_definition(MINUTO_STANDARD_JSON).unwrap();
    let (signing_key, creator) = setup_creator();
    let voucher_data = create_minuto_voucher_data(creator);

    // 2. Erstellung
    let mut voucher = create_voucher(voucher_data, &signing_key).unwrap();
    assert!(!voucher.voucher_id.is_empty());
    assert!(!voucher.creator.signature.is_empty());
 
    // 3. Simulation des Bürgenprozesses
    // Wir erzeugen echte Schlüsselpaare und Signaturen für zwei Bürgen.
    // Annahme: Die Bürgen signieren den Hash der `voucher_id`.
    let (g1_pub, g1_priv) = crypto_utils::generate_ed25519_keypair_for_tests(Some("g1"));
    let (g2_pub, g2_priv) = crypto_utils::generate_ed25519_keypair_for_tests(Some("g2"));
    let g1_id = crypto_utils::create_user_id(&g1_pub, Some("g1")).unwrap();
    let g2_id = crypto_utils::create_user_id(&g2_pub, Some("g2")).unwrap();
 
    let message_to_sign = crypto_utils::get_hash(&voucher.voucher_id);
    let g1_signature = crypto_utils::sign_ed25519(&g1_priv, message_to_sign.as_bytes());
    let g2_signature = crypto_utils::sign_ed25519(&g2_priv, message_to_sign.as_bytes());
 
    voucher.guarantor_signatures.push(GuarantorSignature {
        guarantor_id: g1_id,
        first_name: "Hans".to_string(),
        last_name: "Guarantor".to_string(),
        organization: None,
        community: Some("Test Community".to_string()),
        address: None,
        gender: "1".to_string(), // Männlich
        email: None,
        phone: None,
        coordinates: None,
        url: None,
        signature: bs58::encode(g1_signature.to_bytes()).into_string(),
        signature_time: "2025-07-15T10:00:00Z".to_string(),
    });
    voucher.guarantor_signatures.push(GuarantorSignature {
        guarantor_id: g2_id,
        first_name: "Gabi".to_string(),
        last_name: "Guarantor".to_string(),
        organization: None,
        community: Some("Test Community".to_string()),
        address: None,
        gender: "2".to_string(), // Weiblich
        email: None,
        phone: None,
        coordinates: None,
        url: None,
        signature: bs58::encode(g2_signature.to_bytes()).into_string(),
        signature_time: "2025-07-15T10:01:00Z".to_string(),
    });
 
    // 4. Validierung (Positivfall mit Bürgen)
    let validation_result = validate_voucher_against_standard(&voucher, &standard);
    assert!(
        validation_result.is_ok(),
        "Validation failed unexpectedly: {:?}",
        validation_result.err()
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
    let standard: VoucherStandardDefinition =
        load_standard_definition(MINUTO_STANDARD_JSON).unwrap();
    let (signing_key, creator) = setup_creator();
    let voucher_data = create_minuto_voucher_data(creator);
    let mut voucher = create_voucher(voucher_data, &signing_key).unwrap();

    // 2. Manipuliere die Signatur
    voucher.creator.signature = "invalid_signature_string_12345".to_string();

    // 3. Validierung sollte fehlschlagen
    let validation_result = validate_voucher_against_standard(&voucher, &standard);
    assert!(validation_result.is_err());
    // Wir erwarten einen Fehler beim Dekodieren der Signatur, da sie kein gültiges Base58 ist.
    assert!(matches!(validation_result.unwrap_err(), ValidationError::SignatureDecodeError(_)));
}


#[test]
fn test_validation_fails_on_missing_required_field() {
    // 1. Erstelle einen gültigen Gutschein
    let (signing_key, creator) = setup_creator();
    let voucher_data = create_minuto_voucher_data(creator);
    let voucher = create_voucher(voucher_data, &signing_key).unwrap();

    // 2. Lade einen manipulierten Standard, der ein zusätzliches Feld erfordert
    let mut standard: VoucherStandardDefinition =
        load_standard_definition(MINUTO_STANDARD_JSON).unwrap();
    standard.required_voucher_fields.push("creator.phone".to_string()); // creator.phone ist optional

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
    let standard: VoucherStandardDefinition =
        load_standard_definition(SILVER_STANDARD_JSON).unwrap();
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
    let standard: VoucherStandardDefinition =
        load_standard_definition(MINUTO_STANDARD_JSON).unwrap(); // Erfordert 2 Bürgen
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
    assert_ne!(voucher1, voucher2, "Vouchers should be different due to unique timestamps");
    assert_ne!(voucher1.voucher_id, voucher2.voucher_id, "Voucher IDs should be different");

    // 4. Teste die kanonische Serialisierung an einem statischen Teil des Gutscheins.
    // Das Ergebnis muss immer alphabetisch sortierte Schlüssel haben,
    // z.B. "abbreviation" vor "amount", "amount" vor "description" etc.
    // Dies bestätigt den "sorted" Aspekt des Testnamens.
    let canonical_json = to_canonical_json(&voucher1.nominal_value).unwrap();
    let expected_start = r#"{"abbreviation":"m","amount":"60","description":"Qualitative Leistung","unit":"Minuten"}"#;
    assert_eq!(canonical_json, expected_start);
    println!("Canonical Nominal Value: {}", canonical_json);
}

#[test]
fn test_validation_succeeds_with_extra_fields_in_json() {
    // 1. Erstelle einen VOLLSTÄNDIG gültigen Gutschein, inklusive der benötigten Bürgen.
    let (signing_key, creator) = setup_creator();
    let voucher_data = create_minuto_voucher_data(creator);
    let mut valid_voucher = create_voucher(voucher_data, &signing_key).unwrap();
    let standard: VoucherStandardDefinition =
        load_standard_definition(MINUTO_STANDARD_JSON).unwrap();

    // Füge die für den Minuto-Standard erforderlichen Bürgen hinzu.
    let (g1_pub, g1_priv) = crypto_utils::generate_ed25519_keypair_for_tests(Some("g1_extra"));
    let (g2_pub, g2_priv) = crypto_utils::generate_ed25519_keypair_for_tests(Some("g2_extra"));
    let g1_id = crypto_utils::create_user_id(&g1_pub, Some("g1")).unwrap();
    let g2_id = crypto_utils::create_user_id(&g2_pub, Some("g2")).unwrap();

    let message_to_sign = crypto_utils::get_hash(&valid_voucher.voucher_id);
    let g1_signature = crypto_utils::sign_ed25519(&g1_priv, message_to_sign.as_bytes());
    let g2_signature = crypto_utils::sign_ed25519(&g2_priv, message_to_sign.as_bytes());

    valid_voucher.guarantor_signatures.push(GuarantorSignature {
        guarantor_id: g1_id,
        first_name: "Guarantor1".to_string(),
        last_name: "Test".to_string(),
        organization: None,
        community: None,
        address: None,
        gender: "1".to_string(), // Männlich
        email: None,
        phone: None,
        coordinates: None,
        url: None,
        signature: bs58::encode(g1_signature.to_bytes()).into_string(),
        signature_time: "2025-07-16T11:00:00Z".to_string(),
    });
    valid_voucher.guarantor_signatures.push(GuarantorSignature {
        guarantor_id: g2_id,
        first_name: "Guarantor2".to_string(),
        last_name: "Test".to_string(),
        organization: None,
        community: None,
        address: None,
        gender: "2".to_string(), // Weiblich
        email: None,
        phone: None,
        coordinates: None,
        url: None,
        signature: bs58::encode(g2_signature.to_bytes()).into_string(),
        signature_time: "2025-07-16T11:01:00Z".to_string(),
    });
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
        .insert("creator_metadata".to_string(), serde_json::json!({"rating": 5}));

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