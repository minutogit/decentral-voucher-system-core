//! # Erweiterte Integrationstests für Validierung und Angriffsvektoren
//!
//! Diese Test-Suite prüft gezielt Randfälle, logische Inkonsistenzen und
//! potenzielle Angriffsvektoren, die in der `voucher_validation`-Logik
//! abgefangen werden müssen.
//!
//! ## Abgedeckte Szenarien:
//!
//! - **Gutschein-Stammdaten:**
//!   - Validierung gegen einen falschen Standard (UUID-Mismatch).
//!   - Logisch ungültige Zeitstempel (`valid_until` vor `creation_date`).
//!   - Fehlformatierte Betrags-Strings.
//! - **Ersteller-Signatur:**
//!   - Verwendung einer gültigen Signatur von einem fremden Schlüssel.
//!   - Verwendung eines fehlerhaften Signatur-Formats.
//! - **Bürgen-Signaturen:**
//!   - Doppeltes Hinzufügen desselben Bürgen (Duplicate Attack).
//!   - Der Ersteller versucht, für sich selbst zu bürgen.
//!   - Zeitlich ungültige Bürgschaft (Signatur vor Gutschein-Erstellung).
//! - **Transaktionskette:**
//!   - Verletzung der chronologischen Reihenfolge von Transaktionen.
//!   - Inkonsistente Logik bei Split-Transaktionen (`t_type` vs. `sender_remaining_amount`).

// Wir importieren die öffentlichen Typen, die in lib.rs re-exportiert wurden.
use voucher_lib::{
    create_transaction, create_voucher, crypto_utils, to_canonical_json,
    validate_voucher_against_standard, Creator, GuarantorSignature, NewVoucherData, NominalValue,
    Transaction, UserIdentity, VoucherCoreError,
};
// Importiere die spezifischen Fehlertypen direkt aus ihren Modulen für die `matches!`-Makros.
use voucher_lib::services::voucher_validation::ValidationError;

use ed25519_dalek::SigningKey;
mod test_utils;
use test_utils::{ACTORS, MINUTO_STANDARD, SILVER_STANDARD};

/// Erstellt eine gültige, entkoppelte Bürgen-Signatur für einen gegebenen Gutschein.
fn create_guarantor_signature(
    voucher_id: &str,
    guarantor_id: String,
    guarantor_first_name: &str,
    guarantor_gender: &str,
    signing_key: &SigningKey,
    signature_time: &str,
) -> GuarantorSignature {
    let mut signature_data = GuarantorSignature {
        voucher_id: voucher_id.to_string(),
        signature_id: "".to_string(),
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
        signature: "".to_string(),
        signature_time: signature_time.to_string(),
    };
    let signature_json_for_id = to_canonical_json(&signature_data).unwrap();
    let signature_id = crypto_utils::get_hash(signature_json_for_id);
    signature_data.signature_id = signature_id;
    let digital_signature =
        crypto_utils::sign_ed25519(signing_key, signature_data.signature_id.as_bytes());
    signature_data.signature = bs58::encode(digital_signature.to_bytes()).into_string();
    signature_data
}

/// Helper zum Neuberechnen von t_id und Signatur einer manipulierten Transaktion.
/// Isoliert den zu testenden Fehler von Signatur- oder ID-Fehlern.
fn resign_transaction(
    mut tx: Transaction,
    signer_key: &SigningKey,
) -> Transaction {
    tx.t_id = "".to_string();
    tx.sender_signature = "".to_string();
    tx.t_id = crypto_utils::get_hash(to_canonical_json(&tx).unwrap());
    let payload = serde_json::json!({
        "prev_hash": tx.prev_hash,
        "sender_id": tx.sender_id,
        "t_id": tx.t_id
    });
    let signature_hash = crypto_utils::get_hash(to_canonical_json(&payload).unwrap());
    tx.sender_signature = bs58::encode(
        crypto_utils::sign_ed25519(signer_key, signature_hash.as_bytes()).to_bytes(),
    )
        .into_string();
    tx
}


// --- NEUE, ERWEITERTE TESTS ---

#[test]
fn test_validation_fails_on_standard_uuid_mismatch() {
    let minuto_standard = &MINUTO_STANDARD;
    let silver_standard = &SILVER_STANDARD;

    // 1. Erstelle einen Gutschein nach dem Minuto-Standard.
    let creator_identity = &ACTORS.alice;
    let voucher_data = NewVoucherData {
        creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
        nominal_value: NominalValue { amount: "60".to_string(), ..Default::default() },
        ..Default::default()
    };
    let voucher =
        create_voucher(voucher_data, minuto_standard, &creator_identity.signing_key).unwrap();
 
    assert_eq!(
        voucher.voucher_standard.uuid,
        minuto_standard.metadata.uuid
    );
    assert_ne!(
        voucher.voucher_standard.uuid,
        silver_standard.metadata.uuid
    );

    // 2. Versuche, diesen Minuto-Gutschein gegen den Silber-Standard zu validieren.
    let validation_result = validate_voucher_against_standard(&voucher, silver_standard);

    // SICHERHEITSLÜCKE: Die aktuelle Implementierung von `validate_voucher_against_standard`
    // prüft nicht, ob der Gutschein und der Standard zusammengehören. Dies ist eine kritische
    // Schwachstelle. Der Test ist so geschrieben, dass er fehlschlägt, bis diese Prüfung
    // hinzugefügt wird und einen spezifischen Fehler zurückgibt.
    // Ein Angreifer könnte sonst Regeln umgehen, indem er einen Gutschein gegen einen
    // schwächeren Standard validiert.
    assert!(matches!(
        validation_result.unwrap_err(),
        VoucherCoreError::Validation(ValidationError::StandardUuidMismatch { .. })
    ));
}

#[test]
fn test_validation_fails_on_invalid_date_logic() {
    let standard = &MINUTO_STANDARD;
    let creator_identity = &ACTORS.alice;
    let voucher_data = NewVoucherData {
        creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
        nominal_value: NominalValue { amount: "60".to_string(), ..Default::default() },
        ..Default::default()
    };
    let mut voucher =
        create_voucher(voucher_data, standard, &creator_identity.signing_key).unwrap();

    // Manipuliere die Daten so, dass das Gültigkeitsdatum vor dem Erstellungsdatum liegt.
    voucher.valid_until = "2020-01-01T00:00:00Z".to_string();

    // Da wir den Inhalt geändert haben, müssen wir die Signatur neu erstellen,
    // um die Datumslogik isoliert zu testen.
    let mut voucher_to_sign = voucher.clone();
    voucher_to_sign.creator.signature = "".to_string();
    voucher_to_sign.voucher_id = "".to_string();
    voucher_to_sign.transactions.clear();
    let hash = crypto_utils::get_hash(to_canonical_json(&voucher_to_sign).unwrap());
    let new_sig = crypto_utils::sign_ed25519(&creator_identity.signing_key, hash.as_bytes());
    voucher.creator.signature = bs58::encode(new_sig.to_bytes()).into_string();

    let validation_result = validate_voucher_against_standard(&voucher, standard);

    // HINWEIS: Die aktuelle Validierung prüft dies nicht. Der Test wird fehlschlagen,
    // bis eine Prüfung der Datumslogik (`valid_until` >= `creation_date`) implementiert ist.
    assert!(
        matches!(
            validation_result.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::InvalidDateLogic(_))
        ),
    );
}

#[test]
fn test_validation_fails_on_malformed_amount_string() {
    let standard = &SILVER_STANDARD;
    let creator_identity = &ACTORS.alice;
    let voucher_data = NewVoucherData {
        creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
        nominal_value: NominalValue { amount: "60".to_string(), ..Default::default() },
        ..Default::default()
    };
    let mut voucher =
        create_voucher(voucher_data, standard, &creator_identity.signing_key).unwrap();

    // Manipuliere den Betrag in der `init`-Transaktion zu einem ungültigen Wert.
    voucher.transactions[0].amount = "not-a-number".to_string();

    // Da dies die Transaktion ungültig macht, müssen wir `t_id` und Signatur neu berechnen.
    let tx = voucher.transactions[0].clone();
    voucher.transactions[0] = resign_transaction(tx, &creator_identity.signing_key);

    let validation_result = validate_voucher_against_standard(&voucher, standard);
    assert!(
        matches!(
            validation_result.unwrap_err(),
            VoucherCoreError::AmountConversion(_)
        ),
        "Validation should fail with a DecimalConversionError."
    );
}

#[test]
fn test_validation_fails_on_foreign_key_signature() {
    let standard = &MINUTO_STANDARD;

    let creator_identity = &ACTORS.alice; // The real creator
    let imposter_identity = &ACTORS.hacker; // The one signing

    // 1. Erstelle Gutschein-Daten im Namen des echten Erstellers.
    let voucher_data = NewVoucherData {
        creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
        nominal_value: NominalValue { amount: "60".to_string(), ..Default::default() },
        ..Default::default()
    };

    // 2. ABER: Signiere den Gutschein mit dem Schlüssel des Hochstaplers.
    // `create_voucher` bettet die korrekten Ersteller-Daten aus `voucher_data` ein,
    // aber nutzt den falschen Schlüssel für die Signatur. Das ist genau das Testszenario.
    let mut voucher_with_wrong_sig =
        create_voucher(voucher_data, standard, &imposter_identity.signing_key).unwrap();

    // 3. FÜGE GÜLTIGE BÜRGEN HINZU. Andernfalls schlägt die Validierung bereits an den
    // fehlenden Bürgen fehl, bevor die Ersteller-Signatur geprüft wird.
    let guarantor1 = &ACTORS.guarantor1;
    let guarantor2 = &ACTORS.guarantor2;

    // Zeitstempel muss nach der Erstellung des Gutscheins liegen.
    let signature_time = "2026-01-01T00:00:00Z";
    assert!(signature_time > voucher_with_wrong_sig.creation_date.as_str());
    // Passe die Geschlechter an die Anforderungen des Minuto-Standards an ("1" und "2")
    let sig1 = create_guarantor_signature(
        &voucher_with_wrong_sig.voucher_id, guarantor1.user_id.clone(), "G1", "1",
        &guarantor1.signing_key, signature_time,
    );
    let sig2 = create_guarantor_signature(
        &voucher_with_wrong_sig.voucher_id, guarantor2.user_id.clone(), "G2", "2",
        &guarantor2.signing_key, signature_time,
    );
    voucher_with_wrong_sig.guarantor_signatures.push(sig1);
    voucher_with_wrong_sig.guarantor_signatures.push(sig2);

    // 4. Die Validierung muss fehlschlagen, da die Signatur nicht zum Public Key in `creator.id` passt.
    let validation_result =
        validate_voucher_against_standard(&voucher_with_wrong_sig, &standard);

    // DEBUG-Ausgabe
    if let Err(e) = &validation_result {
        println!("\nDEBUG foreign_key_signature: Validation failed as expected. Error: {:?}", e);
    }

    assert!(
        matches!(
            validation_result.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::InvalidCreatorSignature { .. })
        ),
        "Validation should fail due to signature from a foreign key."
    );
}

#[test]
fn test_validation_fails_on_duplicate_guarantor() {
    let standard = &MINUTO_STANDARD;
    let creator_identity = &ACTORS.alice;
    let voucher_data = NewVoucherData {
        creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
        nominal_value: NominalValue { amount: "60".to_string(), ..Default::default() },
        ..Default::default()
    };
    let mut voucher =
        create_voucher(voucher_data, standard, &creator_identity.signing_key).unwrap();

    let guarantor1 = &ACTORS.guarantor1;
    let guarantor2 = &ACTORS.guarantor2;

    let sig1 = create_guarantor_signature(
        &voucher.voucher_id,
        guarantor1.user_id.clone(),
        "Hans",
        "1",
        &guarantor1.signing_key,
        "2026-08-01T10:00:00Z",
    );
    let sig2 = create_guarantor_signature(
        &voucher.voucher_id, guarantor2.user_id.clone(), "Gabi", "2",
        &guarantor2.signing_key, "2026-08-01T10:00:00Z",
    );

    // Füge sig1, sig2 und dann nochmal sig1 hinzu. Die Liste ist [sig1, sig2, sig1].
    // Dies erfüllt die Anzahl- und Geschlechter-Anforderungen, enthält aber ein Duplikat.
    voucher.guarantor_signatures.push(sig1.clone());
    voucher.guarantor_signatures.push(sig2);
    voucher.guarantor_signatures.push(sig1);

    let validation_result = validate_voucher_against_standard(&voucher, standard);

    // SICHERHEITSLÜCKE: Die aktuelle Validierung prüft nicht auf eindeutige Bürgen.
    // Ein Angreifer könnte mit nur einem Bürgen die Anforderung von `needed_guarantors` erfüllen.
    // Der Test erwartet einen neuen, spezifischen Fehler.
    assert!(
        matches!(
            validation_result.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::DuplicateGuarantor(_))
        ),
    );
}

#[test]
fn test_validation_fails_on_invalid_guarantor_signature_time() {
    let standard = &MINUTO_STANDARD;
    let creator_identity = &ACTORS.alice;
    let voucher_data = NewVoucherData {
        creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
        nominal_value: NominalValue { amount: "60".to_string(), ..Default::default() },
        ..Default::default()
    };
    let mut voucher =
        create_voucher(voucher_data, standard, &creator_identity.signing_key).unwrap();

    let guarantor1 = &ACTORS.guarantor1;

    // Signaturzeit ist VOR der Erstellung des Gutscheins.
    let invalid_time = "2020-01-01T00:00:00Z";
    assert!(invalid_time < voucher.creation_date.as_str());

    let sig = create_guarantor_signature(
        &voucher.voucher_id,
        guarantor1.user_id.clone(),
        "Zeitreiser",
        "1",
        &guarantor1.signing_key,
        invalid_time,
    );

    // FÜGE EINEN ZWEITEN, GÜLTIGEN BÜRGEN HINZU, um die Anforderung an die Anzahl zu erfüllen.
    let guarantor2 = &ACTORS.guarantor2;
    let valid_sig = create_guarantor_signature(&voucher.voucher_id, guarantor2.user_id.clone(),
        "Gabi", "2", &guarantor2.signing_key, "2026-01-01T00:00:00Z");

    voucher.guarantor_signatures.push(sig);
    voucher.guarantor_signatures.push(valid_sig);

    let validation_result = validate_voucher_against_standard(&voucher, standard);

    // HINWEIS: Die aktuelle Implementierung prüft die Chronologie der Bürgen-Signatur nicht.
    // Der Test wird fehlschlagen, bis diese logische Prüfung implementiert ist.
    assert!(
        matches!(
            validation_result.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::InvalidTimeOrder(_))
        ),
    );
}

#[test]
fn test_validation_fails_on_transaction_time_order() {
    let standard = &SILVER_STANDARD;
    let sender = &ACTORS.sender;
    let recipient = &ACTORS.recipient1;

    // KORREKTUR: Verwende das korrekte Betragsformat für den Silber-Standard (4 Dezimalstellen).
    let voucher_data = NewVoucherData {
        creator: Creator { id: sender.user_id.clone(), ..Default::default() },
        nominal_value: NominalValue { amount: "60.0000".to_string(), ..Default::default() },
        ..Default::default()
    };
    let initial_voucher = create_voucher(voucher_data, standard, &sender.signing_key).unwrap();

    let voucher_after_split_result = create_transaction(
        &initial_voucher, standard, &sender.user_id, &sender.signing_key, &recipient.user_id, "10",
    );

    // DEBUG-Ausgabe für den create_transaction-Aufruf
    if let Err(e) = &voucher_after_split_result {
        println!("\nDEBUG transaction_time_order: create_transaction failed with: {:?}", e);
    }
    let mut voucher_after_split = voucher_after_split_result.unwrap();

    // Manipuliere den Zeitstempel der zweiten Transaktion, sodass er vor der ersten liegt.
    let first_tx_time = voucher_after_split.transactions[0].t_time.clone();
    let invalid_second_time = "2020-01-01T00:00:00Z";
    assert!(invalid_second_time < first_tx_time.as_str());
    voucher_after_split.transactions[1].t_time = invalid_second_time.to_string();

    // Re-signiere die manipulierte Transaktion, um den Zeit-Check zu isolieren.
    let tx = voucher_after_split.transactions[1].clone();
    voucher_after_split.transactions[1] = resign_transaction(tx, &sender.signing_key);


    let validation_result = validate_voucher_against_standard(&voucher_after_split, standard);

    // DEBUG-Ausgabe
    if let Err(e) = &validation_result {
        println!("\nDEBUG transaction_time_order: Final validation failed as expected. Error: {:?}", e);
    }

    // HINWEIS: Die aktuelle `verify_transactions` prüft die chronologische Reihenfolge nicht.
    // Der Test wird fehlschlagen, bis diese Prüfung hinzugefügt wird.
    assert!(
        matches!(
            validation_result.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::InvalidTimeOrder(_))
        ),
        "Validation should fail with a dedicated 'InvalidTransactionTimeOrder' error."
    );
}

// --- NEUE TESTS FÜR DIE `INIT`-TRANSAKTION ---

#[test]
fn test_validation_fails_on_init_tx_with_wrong_prev_hash() {
    let standard = &SILVER_STANDARD;
    let creator_identity = &ACTORS.alice;
    let voucher_data = NewVoucherData {
        creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
        nominal_value: NominalValue { amount: "60".to_string(), ..Default::default() },
        ..Default::default()
    };
    let mut voucher =
        create_voucher(voucher_data, standard, &creator_identity.signing_key).unwrap();

    // 1. Manipuliere den prev_hash der init-Transaktion.
    voucher.transactions[0].prev_hash = "intentionally_wrong_prev_hash".to_string();

    // 2. Re-signiere die Transaktion, um den Fehler auf den prev_hash zu isolieren.
    let tx = voucher.transactions[0].clone();
    voucher.transactions[0] = resign_transaction(tx, &creator_identity.signing_key);

    // 3. Die Validierung muss fehlschlagen.
    let validation_result = validate_voucher_against_standard(&voucher, standard);
    assert!(
        matches!(
            validation_result.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::InvalidTransaction(_))
        ),
        "Validation should fail due to incorrect prev_hash in init transaction."
    );
}

#[test]
fn test_validation_fails_on_init_tx_with_wrong_amount() {
    let standard = &SILVER_STANDARD;
    let creator_identity = &ACTORS.alice;
    let voucher_data = NewVoucherData {
        creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
        nominal_value: NominalValue { amount: "60".to_string(), ..Default::default() },
        ..Default::default()
    };
    let mut voucher =
        create_voucher(voucher_data, standard, &creator_identity.signing_key).unwrap();

    // 1. Manipuliere den Betrag der init-Transaktion.
    // Er sollte dem Nennwert des Gutscheins (60) entsprechen.
    voucher.transactions[0].amount = "999".to_string(); // Absichtlich falscher Betrag

    // 2. Re-signiere die Transaktion, um den Fehler zu isolieren.
    let tx = voucher.transactions[0].clone();
    voucher.transactions[0] = resign_transaction(tx, &creator_identity.signing_key);

    // 3. Die Validierung sollte fehlschlagen.
    // HINWEIS: Dies deckt eine Lücke in der aktuellen Validierungslogik auf.
    // Dieser Test wird fehlschlagen, bis `verify_transactions` prüft, ob der
    // Betrag der init-Transaktion dem Nennwert entspricht.
    let validation_result = validate_voucher_against_standard(&voucher, standard);
    assert!(
        matches!(
            validation_result.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::InitAmountMismatch { .. })
        ),
        "Validation should fail because init transaction amount does not match nominal value."
    );
}

#[test]
fn test_validation_fails_on_init_tx_with_wrong_recipient() {
    let standard = &SILVER_STANDARD;
    let creator_identity = &ACTORS.alice;
    let imposter_identity = &ACTORS.hacker;

    let voucher_data = NewVoucherData {
        creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
        nominal_value: NominalValue { amount: "60".to_string(), ..Default::default() },
        ..Default::default()
    };
    let mut voucher =
        create_voucher(voucher_data, standard, &creator_identity.signing_key).unwrap();

    // 1. Manipuliere den Empfänger. Sender und Empfänger müssen der Ersteller sein.
    assert_eq!(voucher.transactions[0].sender_id, creator_identity.user_id);
    voucher.transactions[0].recipient_id = imposter_identity.user_id.clone();

    // 2. Re-signiere die Transaktion.
    let tx = voucher.transactions[0].clone();
    voucher.transactions[0] = resign_transaction(tx, &creator_identity.signing_key);

    // 3. Die Validierung sollte fehlschlagen.
    // HINWEIS: Dies deckt ebenfalls eine Lücke in der Validierungslogik auf.
    let validation_result = validate_voucher_against_standard(&voucher, standard);
    assert!(
        matches!(
            validation_result.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::InitPartyMismatch { .. })
        ),
        "Validation should fail because recipient of init tx is not the creator."
    );
}

#[test]
fn test_validation_fails_on_tampered_transaction_id() {
    let standard = &SILVER_STANDARD;
    let creator_identity = &ACTORS.alice;
    let voucher_data = NewVoucherData {
        creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
        nominal_value: NominalValue { amount: "60".to_string(), ..Default::default() },
        ..Default::default()
    };
    let mut voucher = create_voucher(voucher_data, standard, &creator_identity.signing_key).unwrap();

    // Manipuliere die t_id, ohne die Signatur neu zu berechnen.
    voucher.transactions[0].t_id = "this-is-a-tampered-id".to_string();

    let validation_result = validate_voucher_against_standard(&voucher, standard);
    assert!(
        matches!(
            validation_result.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::MismatchedTransactionId { .. })
        ),
        "Validation should fail because the t_id does not match its content hash."
    );
}

// --- NEUE TESTS FÜR ANGRIFFSVEKTOREN AUF TRANSAKTIONEN ---

/// Bereitet einen Gutschein mit einer validen ersten Transaktion für die folgenden Tests vor.
fn setup_voucher_with_one_tx() -> (
    &'static voucher_lib::VoucherStandardDefinition,
    &'static UserIdentity,
    &'static UserIdentity,
    voucher_lib::Voucher,
) {
    let standard = &SILVER_STANDARD;
    let creator = &ACTORS.alice;
    let recipient = &ACTORS.bob;

    let voucher_data = NewVoucherData {
        creator: Creator { id: creator.user_id.clone(), ..Default::default() },
        nominal_value: NominalValue { amount: "100.0000".to_string(), ..Default::default() },
        ..Default::default()
    };
    let initial_voucher = create_voucher(voucher_data, standard, &creator.signing_key).unwrap();

    // Erstelle eine valide Split-Transaktion. Creator -> Recipient
    // Creator hat danach 60.0000, Recipient hat 40.0000
    let voucher_after_tx1 = create_transaction(
        &initial_voucher, standard, &creator.user_id, &creator.signing_key,
        &recipient.user_id, "40.0000",
    )
    .unwrap();

    (standard, creator, recipient, voucher_after_tx1)
}

#[test]
fn test_tx_fails_on_split_if_not_divisible() {
    let (standard, creator, recipient, voucher) = setup_voucher_with_one_tx();

    // Manipuliere den Standard, sodass der Gutschein nicht teilbar ist.
    let mut standard_clone = standard.clone();
    standard_clone.template.fixed.is_divisible = false;

    // Die Validierung innerhalb von `create_transaction` sollte fehlschlagen,
    // da `voucher.divisible` (true) nicht mit `standard.is_divisible` (false) übereinstimmt.
    let tx_result = create_transaction(&voucher, &standard_clone, &creator.user_id, &creator.signing_key, &recipient.user_id, "10.0000");

    assert!(matches!(
        tx_result.unwrap_err(),
        VoucherCoreError::Validation(ValidationError::IncorrectDivisibility { .. })
    ));
}

#[test]
fn test_tx_fails_on_negative_amount() {
    let (standard, _, recipient, mut voucher) = setup_voucher_with_one_tx();
    let last_valid_tx = voucher.transactions.last().unwrap();
    let prev_hash = crypto_utils::get_hash(to_canonical_json(last_valid_tx).unwrap());

    let tx2 = Transaction {
        t_id: "".to_string(),
        prev_hash,
        t_type: "".to_string(),
        t_time: voucher_lib::services::utils::get_current_timestamp(),
        sender_id: recipient.user_id.clone(),
        recipient_id: "ts1...some_other_person".to_string(),
        amount: "-10.0000".to_string(), // Negativer Betrag
        sender_remaining_amount: None,
        sender_signature: "".to_string(),
    };
    let signed_tx2 = resign_transaction(tx2, &recipient.signing_key);
    voucher.transactions.push(signed_tx2);

    let result = validate_voucher_against_standard(&voucher, &standard);
    assert!(matches!(
        result.unwrap_err(),
        VoucherCoreError::Validation(ValidationError::NegativeOrZeroAmount { .. })
    ));
}

#[test]
fn test_tx_fails_on_wrong_prev_hash_in_chain() {
    let (standard, _, recipient, mut voucher) = setup_voucher_with_one_tx();

    let tx2 = Transaction {
        t_id: "".to_string(),
        prev_hash: "intentionally-wrong-hash".to_string(),
        t_type: "".to_string(),
        t_time: voucher_lib::services::utils::get_current_timestamp(),
        sender_id: recipient.user_id.clone(),
        recipient_id: "ts1...some_other_person".to_string(),
        amount: "10.0000".to_string(),
        sender_remaining_amount: None,
        sender_signature: "".to_string(),
    };
    let signed_tx2 = resign_transaction(tx2, &recipient.signing_key);
    voucher.transactions.push(signed_tx2);

    let result = validate_voucher_against_standard(&voucher, &standard);
    assert!(matches!(
        result.unwrap_err(),
        VoucherCoreError::Validation(ValidationError::InvalidTransaction(_))
    ));
}

#[test]
fn test_tx_fails_on_insufficient_funds() {
    let (standard, _, recipient, mut voucher) = setup_voucher_with_one_tx();
    let last_valid_tx = voucher.transactions.last().unwrap();
    let prev_hash = crypto_utils::get_hash(to_canonical_json(last_valid_tx).unwrap());

    // Empfänger hat 40.0000, versucht aber 50.0000 als vollen Transfer zu senden.
    let tx2 = Transaction {
        t_id: "".to_string(),
        prev_hash,
        t_type: "".to_string(),
        t_time: voucher_lib::services::utils::get_current_timestamp(),
        sender_id: recipient.user_id.clone(),
        recipient_id: "ts1...some_other_person".to_string(),
        amount: "50.0000".to_string(),
        sender_remaining_amount: None, // Voller Transfer
        sender_signature: "".to_string(),
    };
    let signed_tx2 = resign_transaction(tx2, &recipient.signing_key);
    voucher.transactions.push(signed_tx2);

    let result = validate_voucher_against_standard(&voucher, &standard);
    assert!(matches!(
        result.unwrap_err(),
        VoucherCoreError::Validation(ValidationError::FullTransferAmountMismatch { .. })
    ));
}

#[test]
fn test_tx_fails_on_subsequent_init_transaction() {
    let (standard, _, recipient, mut voucher) = setup_voucher_with_one_tx();
    let last_valid_tx = voucher.transactions.last().unwrap();
    let prev_hash = crypto_utils::get_hash(to_canonical_json(last_valid_tx).unwrap());

    let tx2 = Transaction {
        t_id: "".to_string(),
        prev_hash,
        t_type: "init".to_string(), // Eine zweite init-Transaktion
        t_time: voucher_lib::services::utils::get_current_timestamp(),
        sender_id: recipient.user_id.clone(),
        recipient_id: "ts1...some_other_person".to_string(),
        amount: "10.0000".to_string(),
        sender_remaining_amount: None,
        sender_signature: "".to_string(),
    };
    let signed_tx2 = resign_transaction(tx2, &recipient.signing_key);
    voucher.transactions.push(signed_tx2);

    let result = validate_voucher_against_standard(&voucher, &standard);
    assert!(matches!(
        result.unwrap_err(),
        VoucherCoreError::Validation(ValidationError::InvalidTransaction(_))
    ));
}

#[test]
fn test_tx_fails_on_send_to_self_after_init() {
    let (standard, _, recipient, mut voucher) = setup_voucher_with_one_tx();
    let last_valid_tx = voucher.transactions.last().unwrap();
    let prev_hash = crypto_utils::get_hash(to_canonical_json(last_valid_tx).unwrap());

    let tx2 = Transaction {
        t_id: "".to_string(),
        prev_hash,
        t_type: "".to_string(),
        t_time: voucher_lib::services::utils::get_current_timestamp(),
        sender_id: recipient.user_id.clone(),
        recipient_id: recipient.user_id.clone(), // Sendet an sich selbst
        amount: "10.0000".to_string(),
        sender_remaining_amount: None,
        sender_signature: "".to_string(),
    };
    let signed_tx2 = resign_transaction(tx2, &recipient.signing_key);
    voucher.transactions.push(signed_tx2);

    let result = validate_voucher_against_standard(&voucher, &standard);
    assert!(matches!(
        result.unwrap_err(),
        VoucherCoreError::Validation(ValidationError::InvalidTransaction(_))
    ));
}

#[test]
fn test_tx_fails_on_tampered_content_vs_tid() {
    let (standard, _, _, mut voucher) = setup_voucher_with_one_tx();

    // Manipuliere einen Wert, aber berechne weder t_id noch Signatur neu.
    voucher.transactions[1].amount = "99.9999".to_string();

    let result = validate_voucher_against_standard(&voucher, &standard);
    assert!(matches!(
        result.unwrap_err(),
        VoucherCoreError::Validation(ValidationError::MismatchedTransactionId{..})
    ));
}

#[test]
fn test_tx_fails_on_zero_amount() {
    let (standard, _, recipient, mut voucher) = setup_voucher_with_one_tx();
    let last_valid_tx = voucher.transactions.last().unwrap();
    let prev_hash = crypto_utils::get_hash(to_canonical_json(last_valid_tx).unwrap());

    let tx2 = Transaction {
        t_id: "".to_string(),
        prev_hash,
        t_type: "".to_string(),
        t_time: voucher_lib::services::utils::get_current_timestamp(),
        sender_id: recipient.user_id.clone(),
        recipient_id: "ts1...some_other_person".to_string(),
        amount: "0.0000".to_string(), // Null-Betrag
        sender_remaining_amount: None,
        sender_signature: "".to_string(),
    };
    let signed_tx2 = resign_transaction(tx2, &recipient.signing_key);
    voucher.transactions.push(signed_tx2);

    let result = validate_voucher_against_standard(&voucher, &standard);
    assert!(matches!(
        result.unwrap_err(),
        VoucherCoreError::Validation(ValidationError::NegativeOrZeroAmount{..})
    ));
}

#[test]
fn test_guarantor_sig_fails_on_mismatched_voucher_id() {
    let standard = &MINUTO_STANDARD;
    let creator_identity = &ACTORS.alice;
    let voucher_data = NewVoucherData {
        creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
        nominal_value: NominalValue { amount: "60".to_string(), ..Default::default() },
        ..Default::default()
    };
    let mut voucher =
        create_voucher(voucher_data, standard, &creator_identity.signing_key).unwrap();

    let guarantor1 = &ACTORS.guarantor1;
    let guarantor2 = &ACTORS.guarantor2;

    // Erstelle eine valide Signatur
    let mut sig1 = create_guarantor_signature(
        &voucher.voucher_id, guarantor1.user_id.clone(), "G1", "1", &guarantor1.signing_key,
        "2026-08-01T10:00:00Z",
    );
    // Manipuliere die voucher_id NACH der Erstellung
    sig1.voucher_id = "this-is-the-wrong-voucher-id".to_string();

    let sig2 = create_guarantor_signature(
        &voucher.voucher_id, guarantor2.user_id.clone(), "G2", "2", &guarantor2.signing_key,
        "2026-08-01T10:00:00Z",
    );

    voucher.guarantor_signatures.push(sig1);
    voucher.guarantor_signatures.push(sig2);

    let validation_result = validate_voucher_against_standard(&voucher, standard);
    assert!(matches!(
        validation_result.unwrap_err(),
        VoucherCoreError::Validation(ValidationError::MismatchedVoucherIdInSignature { .. })
    ));
}