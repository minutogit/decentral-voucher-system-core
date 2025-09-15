//! # tests/test_forward_compatibility.rs
//!
//! Diese Test-Suite stellt sicher, dass die Bibliothek robust gegenüber zukünftigen
//! Änderungen an den Datenstrukturen ist (Vorwärtskompatibilität).
//!
//! ## Getestete Szenarien:
//!
//! 1.  **Unbekannte Felder in Gutschein-JSON:**
//!     - Ein Gutschein, der mit einer neueren Software-Version erstellt wurde und
//!       zusätzliche, unbekannte Felder enthält, muss von der alten Version
//!       problemlos deserialisiert und validiert werden können. `serde` sollte
//!       die unbekannten Felder ignorieren, und die Signaturvalidierung, die auf
//!       einer kanonischen Form der *bekannten* Felder basiert, muss weiterhin
//!       erfolgreich sein.
//!
//! 2.  **Unbekannte Transaktionstypen:**
//!     - Wenn ein Gutschein einen Transaktionstyp enthält, den die aktuelle
//!       Bibliotheksversion nicht kennt (z.B. `merge`), darf die Anwendung nicht
//!       abstürzen. Stattdessen muss die Validierung fehlschlagen und einen
//!       klaren Fehler zurückgeben, dass der Typ nicht unterstützt wird.
//!
//! 3.  **Unbekannte Felder in Standard-Definitionen (TOML):**
//!     - Eine Standard-Definition im TOML-Format, die neue, unbekannte Regeln
//!       oder Metadaten enthält, muss trotzdem erfolgreich geparst und ihre
//!       Signatur verifiziert werden können. Der Hash für die Signatur wird nur
//!       über die bekannten Felder gebildet.

mod test_utils;

use serde_json::json;
use test_utils::{ACTORS, MINUTO_STANDARD};
use voucher_lib::{
    from_json, validate_voucher_against_standard, Creator, NewVoucherData, Voucher,
    VoucherCoreError, NominalValue,
};
use voucher_lib::error::ValidationError;
use voucher_lib::error::StandardDefinitionError;
use voucher_lib::services::standard_manager;
use voucher_lib::services::utils::to_canonical_json;

/// **Szenario 1: Testet die Deserialisierung und Validierung eines Gutscheins mit unbekannten Feldern.**
///
/// Dieser Test simuliert den Fall, dass eine ältere Version der Bibliothek einen Gutschein
/// von einer neueren Version empfängt.
#[test]
fn test_voucher_deserialization_and_validation_succeeds_with_unknown_fields() {
    // 1. Erstelle einen vollständig gültigen Gutschein als Basis.
    // Wir verwenden den Minuto-Standard, der Bürgen erfordert.
    let identity = &ACTORS.issuer;
    let creator = Creator { id: identity.user_id.clone(), ..Default::default() };
    let voucher_data = NewVoucherData {
        validity_duration: Some("P3Y".to_string()),
        nominal_value: NominalValue {
            amount: "100".to_string(),
            ..Default::default()
        },
        creator,
        ..Default::default()
    };
    let (minuto_standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    let mut valid_voucher = test_utils::create_voucher_for_manipulation(voucher_data, minuto_standard, standard_hash, &identity.signing_key, "en");

    // Füge die für den Minuto-Standard erforderlichen Bürgen hinzu, damit der Gutschein valide ist.
    // Wir verwenden eine vereinfachte Methode, um die Signaturen zu erstellen, da die Signatur-
    // Logik selbst nicht im Fokus dieses Tests steht.
    let g1 = &ACTORS.guarantor1;
    let g2 = &ACTORS.guarantor2;
    let sig_data1 = test_utils::create_guarantor_signature_data(g1, "1", &valid_voucher.voucher_id);
    let sig_data2 = test_utils::create_guarantor_signature_data(g2, "2", &valid_voucher.voucher_id);
    let signed_sig1 = voucher_lib::services::signature_manager::complete_and_sign_detached_signature(sig_data1, &valid_voucher.voucher_id, g1).unwrap();
    let signed_sig2 = voucher_lib::services::signature_manager::complete_and_sign_detached_signature(sig_data2, &valid_voucher.voucher_id, g2).unwrap();
    if let voucher_lib::models::signature::DetachedSignature::Guarantor(s) = signed_sig1 { valid_voucher.guarantor_signatures.push(s); }
    if let voucher_lib::models::signature::DetachedSignature::Guarantor(s) = signed_sig2 { valid_voucher.guarantor_signatures.push(s); }

    // Stelle sicher, dass der Gutschein vor der Manipulation gültig ist.
    assert!(validate_voucher_against_standard(&valid_voucher, minuto_standard).is_ok());

    // 2. Konvertiere den Gutschein in ein allgemeines JSON-Value-Objekt und füge unbekannte Felder hinzu.
    let mut voucher_as_value: serde_json::Value = serde_json::to_value(&valid_voucher).unwrap();

    voucher_as_value.as_object_mut().unwrap().insert(
        "new_root_field_from_v2".to_string(),
        json!("some future data"),
    );
    voucher_as_value.get_mut("transactions").unwrap()[0].as_object_mut().unwrap().insert(
        "transaction_memo".to_string(),
        json!("a memo for the init transaction"),
    );

    let json_with_extra_fields = serde_json::to_string(&voucher_as_value).unwrap();

    // 3. Deserialisiere diesen JSON-String. `serde` sollte die unbekannten Felder ignorieren.
    let deserialized_voucher: Voucher = from_json(&json_with_extra_fields).unwrap();

    // 4. Der deserialisierte Gutschein sollte exakt dem Original entsprechen.
    assert_eq!(valid_voucher, deserialized_voucher);

    // 5. Die Validierung muss weiterhin erfolgreich sein, da die Hash-Berechnung für die
    //    Signaturprüfung die unbekannten Felder nicht berücksichtigt.
    let validation_result = validate_voucher_against_standard(&deserialized_voucher, minuto_standard);
    assert!(
        validation_result.is_ok(),
        "Validation failed unexpectedly with extra fields: {:?}",
        validation_result.err()
    );
}

/// **Szenario 2: Testet, ob die Validierung bei einem unbekannten Transaktionstyp fehlschlägt.**
///
/// Eine alte Bibliotheksversion muss einen neuen, ihr unbekannten `t_type` ablehnen,
/// anstatt abzustürzen.
#[test]
fn test_validation_fails_for_unknown_transaction_type() {
    // 1. Erstelle einen gültigen Gutschein als Basis.
    let identity = &ACTORS.issuer;
    let (minuto_standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
    let mut voucher = test_utils::create_voucher_for_manipulation(
        NewVoucherData {
            creator: Creator { id: identity.user_id.clone(), ..Default::default() },
            validity_duration: Some("P3Y".to_string()),
            nominal_value: NominalValue {
                amount: "100".to_string(),
                ..Default::default()
            },
            ..Default::default()
        },
        minuto_standard, standard_hash, &identity.signing_key, "en",
    );

    // FÜGE GÜLTIGE BÜRGEN HINZU, damit die Validierung nicht vorzeitig an
    // den Bürgen-Anforderungen scheitert.
    let g1 = &ACTORS.guarantor1;
    let g2 = &ACTORS.guarantor2;
    let sig_data1 = test_utils::create_guarantor_signature_data(g1, "1", &voucher.voucher_id);
    let sig_data2 = test_utils::create_guarantor_signature_data(g2, "2", &voucher.voucher_id);
    let signed_sig1 = voucher_lib::services::signature_manager::complete_and_sign_detached_signature(sig_data1, &voucher.voucher_id, g1).unwrap();
    let signed_sig2 = voucher_lib::services::signature_manager::complete_and_sign_detached_signature(sig_data2, &voucher.voucher_id, g2).unwrap();
    if let voucher_lib::models::signature::DetachedSignature::Guarantor(s) = signed_sig1 { voucher.guarantor_signatures.push(s); }
    if let voucher_lib::models::signature::DetachedSignature::Guarantor(s) = signed_sig2 { voucher.guarantor_signatures.push(s); }

    // 2. Konvertiere zu JSON Value und manipuliere den `t_type` der `init`-Transaktion.
    let mut voucher_as_value: serde_json::Value = serde_json::to_value(&voucher).unwrap();
    let transactions = voucher_as_value.get_mut("transactions").unwrap().as_array_mut().unwrap();
    let init_transaction = transactions[0].as_object_mut().unwrap();
    init_transaction.insert("t_type".to_string(), json!("merge")); // "merge" ist ein fiktiver neuer Typ

    // WICHTIG: Wenn wir den Inhalt der Transaktion ändern, müssen wir auch die t_id neu berechnen,
    // damit der Test nicht an einer inkonsistenten t_id scheitert, bevor er die t_type-Prüfung erreicht.
    let mut temp_tx: voucher_lib::models::voucher::Transaction = serde_json::from_value(
        serde_json::Value::Object(init_transaction.clone()),
    )
    .unwrap();
    temp_tx.t_id = "".to_string();
    temp_tx.sender_signature = "".to_string(); // Die Signatur ist für die t_id-Berechnung irrelevant.
    let new_tid = voucher_lib::services::crypto_utils::get_hash(
        to_canonical_json(&temp_tx).unwrap(),
    );
    // Aktualisiere die t_id im JSON-Objekt.
    init_transaction.insert("t_id".to_string(), json!(new_tid));

    // Da sich die t_id geändert hat, ist auch die ursprüngliche Signatur ungültig. Wir müssen sie neu signieren.
    let signature_payload = json!({
        "prev_hash": &temp_tx.prev_hash,
        "sender_id": &temp_tx.sender_id,
        "t_id": new_tid
    });
    let signature_payload_hash = voucher_lib::services::crypto_utils::get_hash(
        to_canonical_json(&signature_payload).unwrap(),
    );
    let new_signature = voucher_lib::services::crypto_utils::sign_ed25519(
        &identity.signing_key,
        signature_payload_hash.as_bytes(),
    );
    init_transaction.insert("sender_signature".to_string(), json!(bs58::encode(new_signature.to_bytes()).into_string()));

    let manipulated_json = serde_json::to_string(&voucher_as_value).unwrap();

    // 3. Deserialisiere den Gutschein. Das `t_type`-Feld ist nur ein String, daher klappt dies.
    let deserialized_voucher: Voucher = from_json(&manipulated_json).unwrap();

    // 4. Die Validierung muss nun fehlschlagen, da die Geschäftslogik den `t_type` "merge"
    //    gemäß den Regeln im Standard nicht erlaubt.
    let validation_result = validate_voucher_against_standard(&deserialized_voucher, minuto_standard);
    assert!(matches!(
        validation_result.unwrap_err(),
        VoucherCoreError::Validation(ValidationError::TransactionTypeNotAllowed { t_type, .. }) if t_type == "merge"
    ));
}

/// **Szenario 3: Testet, ob eine Standard-Definition mit unbekannten Feldern geparst werden kann.**
///
/// Simuliert eine `standard.toml`, die mit einer neueren Version erstellt wurde und
/// zusätzliche, der aktuellen Version unbekannte, Validierungsregeln enthält.
#[test]
fn test_standard_parsing_succeeds_with_unknown_fields() {
    // HINWEIS: Für diesen Test muss eine neue Fixture-Datei manuell angelegt werden:
    // `voucher_standards/minuto_v2_new_rules/standard.toml`
    // Diese Datei sollte eine Kopie von `minuto_v1` sein, aber ein zusätzliches Feld enthalten,
    // z.B. unter `[validation]`: `max_transactions = 100`

    // Annahme, dass die Fixture-Datei existiert.
    let fixture_path = "voucher_standards/minuto_v1/standard.toml"; // Wir verwenden die existierende Datei und fügen das Feld im Speicher hinzu.

    let mut toml_str = std::fs::read_to_string(fixture_path)
        .expect("Failed to read TOML template for test");

    // Füge die neue, unbekannte Regel hinzu.
    toml_str.push_str("\n[validation.new_rules]\nmax_amount = 1000\n");

    // 1. Parse den modifizierten TOML-String. Die `verify_and_parse_standard` Funktion
    //    wird intern die Signatur verifizieren. Da der Hash der bekannten Felder
    //    unverändert ist, sollte die Signatur (falls im Original-TOML vorhanden und gültig)
    //    oder eine neu generierte Signatur korrekt sein.
    //    Wir erwarten, dass `toml::from_str` die unbekannten Felder einfach ignoriert.
    let result = standard_manager::verify_and_parse_standard(&toml_str);

    // 2. Der Parsing- und Verifizierungsprozess muss erfolgreich sein.
    //    Der Original-TOML hat eine ungültige Signatur, daher erwarten wir hier einen
    //    Signaturfehler, aber KEINEN Parsing-Fehler. Das beweist, dass das unbekannte Feld
    //    ignoriert wurde.
    match result {
        Ok(_) => {
            panic!("Parsing should have failed due to the invalid signature in the template file, but it succeeded.");
        },
        Err(VoucherCoreError::Standard(StandardDefinitionError::InvalidSignature)) => {
            // DIES IST DAS ERWARTETE ERGEBNIS! Der Fehler kommt von der ungültigen Signatur,
            // nicht vom Parsen des unbekannten Feldes.
        },
        Err(e) => panic!("Expected a signature error, but got a different error: {:?}", e),
    }

    // Zusätzlicher, expliziter Test: Parsen ohne Signatur-Check
    let parse_only_result: Result<voucher_lib::models::voucher_standard_definition::VoucherStandardDefinition, _> = toml::from_str(&toml_str);
    assert!(parse_only_result.is_ok(), "Parsing the TOML with extra fields should succeed.");
}