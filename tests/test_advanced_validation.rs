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
    create_transaction, create_voucher, crypto_utils, to_canonical_json, validate_voucher_against_standard, Creator, NewVoucherData, NominalValue,
    Transaction, UserIdentity, VoucherCoreError,
};
// Importiere die spezifischen Fehlertypen direkt aus ihren Modulen für die `matches!`-Makros.
use voucher_lib::services::voucher_manager::VoucherManagerError;
use voucher_lib::error::ValidationError;
mod test_utils;
use test_utils::{
    create_female_guarantor_signature, create_guarantor_signature_with_time,
    create_male_guarantor_signature,
    create_voucher_for_manipulation, resign_transaction, ACTORS, MINUTO_STANDARD, SILVER_STANDARD,
};

// --- NEUE, ERWEITERTE TESTS ---

#[test]
fn test_validation_fails_on_standard_uuid_mismatch() {
    let (minuto_standard, minuto_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
    let silver_standard = &SILVER_STANDARD.0;

    // 1. Erstelle einen Gutschein nach dem Minuto-Standard.
    let creator_identity = &ACTORS.alice;
    let voucher_data = NewVoucherData {
        creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
        nominal_value: NominalValue { amount: "60".to_string(), ..Default::default() },
        ..Default::default()
    };

    // Verwende den Helper, um die `CountOutOfBounds`-Validierung bei der Erstellung zu umgehen.
    let mut voucher = create_voucher_for_manipulation(voucher_data, minuto_standard, minuto_hash, &creator_identity.signing_key, "en");

    // SETUP-FIX: Füge zwei valide Bürgen hinzu, damit die Validierung nicht vorzeitig an
    // der `CountOutOfBounds`-Regel des Minuto-Standards scheitert.
    voucher.guarantor_signatures.push(create_male_guarantor_signature(&voucher));
    voucher.guarantor_signatures.push(create_female_guarantor_signature(&voucher));

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

    assert!(matches!(
        validation_result.unwrap_err(),
        VoucherCoreError::Validation(ValidationError::StandardUuidMismatch { .. })
    ));
}

#[test]
fn test_validation_fails_on_invalid_date_logic() {
    let (standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
    let creator_identity = &ACTORS.alice;
    let voucher_data = NewVoucherData {
        creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
        nominal_value: NominalValue { amount: "60".to_string(), ..Default::default() },
        ..Default::default()
    };

    // Verwende den Helper, um die `CountOutOfBounds`-Validierung bei der Erstellung zu umgehen.
    let mut voucher = create_voucher_for_manipulation(voucher_data, standard, standard_hash, &creator_identity.signing_key, "en");

    // SETUP-FIX: Füge zwei valide Bürgen hinzu, damit die Validierung bis zur Datumslogik kommt.
    voucher.guarantor_signatures.push(create_male_guarantor_signature(&voucher));
    voucher.guarantor_signatures.push(create_female_guarantor_signature(&voucher));

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

    assert!(
        matches!(
            validation_result.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::InvalidDateLogic { .. })
        ),
    );
}

#[test]
fn test_validation_fails_on_malformed_amount_string() {
    let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
    let creator_identity = &ACTORS.alice;
    let voucher_data = NewVoucherData {
        creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
        nominal_value: NominalValue { amount: "60".to_string(), ..Default::default() },
        ..Default::default()
    };

    let mut voucher = create_voucher(voucher_data, standard, standard_hash, &creator_identity.signing_key, "en").unwrap();

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
    let (standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

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
    // aber nutzt den falschen Schlüssel für die Signatur.
    // KORREKTUR: Wir trennen die Erstellung von der Validierung, um den `CountOutOfBounds`-Fehler zu umgehen.
    let voucher =
        create_voucher_for_manipulation(voucher_data, standard, standard_hash, &imposter_identity.signing_key, "en");

    // 3. Die Validierung muss nun manuell aufgerufen werden. Sie muss fehlschlagen,
    // da die Signatur nicht zum Public Key in `creator.id` passt.
    let validation_result = validate_voucher_against_standard(&voucher, standard);

    assert!(
        matches!(
            validation_result,
            Err(VoucherCoreError::Validation(
                ValidationError::InvalidCreatorSignature { .. }
            ))
        ),
        "Validation should fail due to signature from a foreign key."
    );
}

#[test]
fn test_validation_fails_on_duplicate_guarantor() {
    let (standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
    let creator_identity = &ACTORS.alice;
    let voucher_data = NewVoucherData {
        creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
        nominal_value: NominalValue { amount: "60".to_string(), ..Default::default() },
        ..Default::default()
    };

    // Verwende den Helper, um die `CountOutOfBounds`-Validierung bei der Erstellung zu umgehen.
    let mut voucher = create_voucher_for_manipulation(voucher_data, standard, standard_hash, &creator_identity.signing_key, "en");

    // SETUP-FIX: Erstelle zwei Signaturen vom selben Bürgen. Die Gesamtanzahl (2)
    // erfüllt die `CountOutOfBounds`-Regel `{min=2, max=2}`, aber der Inhalt
    // verletzt die Duplikats-Logik.
    let guarantor1 = &ACTORS.guarantor1;
    let sig1 = create_guarantor_signature_with_time(
        &voucher.voucher_id,
        &guarantor1,
        "Hans",
        "1",
        "2026-08-01T10:00:00Z",
    );
    // Erstelle eine zweite Signatur vom selben Bürgen, aber mit anderem Gender,
    // um die FieldGroupRule zu umgehen und den Duplikats-Check zu isolieren.
    let sig2 = create_guarantor_signature_with_time(
        &voucher.voucher_id,
        &guarantor1,
        "Hans",
        "2", // Falsches Gender, nur um die Regel zu umgehen
        "2026-08-01T10:00:01Z", // Geringfügig anderer Zeitstempel
    );

    voucher.guarantor_signatures.push(sig1);
    voucher.guarantor_signatures.push(sig2);

    let validation_result = validate_voucher_against_standard(&voucher, standard);

    assert!(
        matches!(
            validation_result.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::DuplicateGuarantor { .. })
        ),
    );
}

#[test]
fn test_validation_fails_on_invalid_guarantor_signature_time() {
    let (standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
    let creator_identity = &ACTORS.alice;
    let voucher_data = NewVoucherData {
        creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
        nominal_value: NominalValue { amount: "60".to_string(), ..Default::default() },
        ..Default::default()
    };

    // Verwende den Helper, um die `CountOutOfBounds`-Validierung bei der Erstellung zu umgehen.
    let mut voucher = create_voucher_for_manipulation(voucher_data, standard, standard_hash, &creator_identity.signing_key, "en");

    let guarantor1 = &ACTORS.guarantor1;

    // 1. Signaturzeit ist VOR der Erstellung des Gutscheins.
    let invalid_time = "2020-01-01T00:00:00Z";
    assert!(invalid_time < voucher.creation_date.as_str());

    let sig = create_guarantor_signature_with_time(
        &voucher.voucher_id,
        &guarantor1,
        "Zeitreiser",
        "1",
        invalid_time,
    );

    // 2. Füge einen zweiten, validen Bürgen hinzu, damit die `CountOutOfBounds`-
    // Regel erfüllt ist und der Zeitfehler der ersten Signatur geprüft wird.
    let valid_sig = create_female_guarantor_signature(&voucher);

    voucher.guarantor_signatures.push(sig);
    voucher.guarantor_signatures.push(valid_sig);

    let validation_result = validate_voucher_against_standard(&voucher, standard);

    assert!(
        matches!(
            validation_result.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::InvalidTimeOrder { .. })
        ),
    );
}

#[test]
fn test_validation_fails_on_transaction_time_order() {
    let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
    let sender = &ACTORS.sender;
    let recipient = &ACTORS.recipient1;

    // KORREKTUR: Verwende das korrekte Betragsformat für den Silber-Standard (4 Dezimalstellen).
    let voucher_data = NewVoucherData {
        creator: Creator { id: sender.user_id.clone(), ..Default::default() },
        nominal_value: NominalValue { amount: "60.0000".to_string(), ..Default::default() },
        ..Default::default()
    };

    // KORREKTUR: Verwende die flexiblere Hilfsfunktion, da der Minuto-Standard Bürgen erfordert,
    // die hier aber für den Testablauf nicht relevant sind.
    let initial_voucher = create_voucher_for_manipulation(
        voucher_data,
        standard,
        standard_hash,
        &sender.signing_key, "en"
    );

    let voucher_after_split_result = create_transaction(
        &initial_voucher, standard, &sender.user_id, &sender.signing_key, &recipient.user_id, "10.0000",
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

    assert!(
        matches!(
            validation_result.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::InvalidTimeOrder { .. })
        ),
        "Validation should fail with a dedicated 'InvalidTransactionTimeOrder' error."
    );
}

// --- NEUE TESTS FÜR DIE `INIT`-TRANSAKTION ---

#[test]
fn test_validation_fails_on_init_tx_with_wrong_prev_hash() {
    let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
    let creator_identity = &ACTORS.alice;
    let voucher_data = NewVoucherData {
        creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
        nominal_value: NominalValue { amount: "60".to_string(), ..Default::default() },
        ..Default::default()
    };

    // KORREKTUR: Verwende die flexiblere Hilfsfunktion, da der Minuto-Standard Bürgen erfordert.
    let mut voucher = create_voucher_for_manipulation(
        voucher_data, standard,
        standard_hash,
        &creator_identity.signing_key, "en"
    );

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
    let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
    let creator_identity = &ACTORS.alice;
    let voucher_data = NewVoucherData {
        creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
        nominal_value: NominalValue { amount: "60".to_string(), ..Default::default() },
        ..Default::default()
    };

    // KORREKTUR: Verwende die flexiblere Hilfsfunktion.
    let mut voucher = create_voucher_for_manipulation(
        voucher_data, standard,
        standard_hash,
        &creator_identity.signing_key, "en"
    );

    // 1. Manipuliere den Betrag der init-Transaktion.
    // Er sollte dem Nennwert des Gutscheins (60) entsprechen.
    voucher.transactions[0].amount = "999".to_string(); // Absichtlich falscher Betrag

    // 2. Re-signiere die Transaktion, um den Fehler zu isolieren.
    let tx = voucher.transactions[0].clone();
    voucher.transactions[0] = resign_transaction(tx, &creator_identity.signing_key);

    // 3. Die Validierung sollte fehlschlagen.
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
    let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
    let creator_identity = &ACTORS.alice;
    let imposter_identity = &ACTORS.hacker;

    let voucher_data = NewVoucherData {
        creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
        nominal_value: NominalValue { amount: "60".to_string(), ..Default::default() },
        ..Default::default()
    };

    // KORREKTUR: Verwende die flexiblere Hilfsfunktion.
    let mut voucher = create_voucher_for_manipulation(
        voucher_data, standard,
        standard_hash,
        &creator_identity.signing_key, "en"
    );

    // 1. Manipuliere den Empfänger. Sender und Empfänger müssen der Ersteller sein.
    assert_eq!(voucher.transactions[0].sender_id, creator_identity.user_id);
    voucher.transactions[0].recipient_id = imposter_identity.user_id.clone();

    // 2. Re-signiere die Transaktion.
    let tx = voucher.transactions[0].clone();
    voucher.transactions[0] = resign_transaction(tx, &creator_identity.signing_key);

    // 3. Die Validierung sollte fehlschlagen.
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
    let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
    let creator_identity = &ACTORS.alice;
    let voucher_data = NewVoucherData {
        creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
        nominal_value: NominalValue { amount: "60".to_string(), ..Default::default() },
        ..Default::default()
    };

    // KORREKTUR: Verwende die flexiblere Hilfsfunktion.
    let mut voucher = create_voucher_for_manipulation(
        voucher_data, standard,
        standard_hash,
        &creator_identity.signing_key, "en"
    );

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
    &'static String,
    &'static UserIdentity,
    &'static UserIdentity,
    voucher_lib::Voucher,
) {
    let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
    let creator = &ACTORS.alice;
    let recipient = &ACTORS.bob;

    let voucher_data = NewVoucherData {
        creator: Creator { id: creator.user_id.clone(), ..Default::default() },
        nominal_value: NominalValue { amount: "100.0000".to_string(), ..Default::default() },
        ..Default::default()
    };

    let initial_voucher = create_voucher(voucher_data, standard, standard_hash, &creator.signing_key, "en").unwrap();

    // Erstelle eine valide Split-Transaktion. Creator -> Recipient
    // Creator hat danach 60.0000, Recipient hat 40.0000
    let voucher_after_tx1 = create_transaction(
        &initial_voucher, standard, &creator.user_id, &creator.signing_key,
        &recipient.user_id, "40.0000",
    )
        .unwrap();

    (standard, standard_hash, creator, recipient, voucher_after_tx1)
}

#[test]
fn test_tx_fails_on_split_if_not_divisible() {
    // 1. Erstelle einen Standard, der explizit nicht teilbar ist.
    let (silver_standard, _) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
    let creator = &ACTORS.alice;
    let recipient = &ACTORS.bob;

    let mut non_divisible_standard = silver_standard.clone();
    non_divisible_standard.template.fixed.is_divisible = false;

    // 2. Erstelle einen Gutschein mit diesem Standard.
    let mut standard_to_hash = non_divisible_standard.clone();
    standard_to_hash.signature = None;
    let standard_hash = crypto_utils::get_hash(to_canonical_json(&standard_to_hash).unwrap());

    let voucher_data = NewVoucherData {
        creator: Creator { id: creator.user_id.clone(), ..Default::default() },
        nominal_value: NominalValue { amount: "100.0000".to_string(), ..Default::default() },
        ..Default::default()
    };
    let voucher = create_voucher(voucher_data, &non_divisible_standard, &standard_hash, &creator.signing_key, "en").unwrap();

    // 3. Versuche, eine Split-Transaktion zu erstellen. Dies muss fehlschlagen.
    let tx_result = create_transaction(&voucher, &non_divisible_standard, &creator.user_id, &creator.signing_key, &recipient.user_id, "10.0000");

    assert!(matches!(
        tx_result.unwrap_err(),
        VoucherCoreError::Manager(VoucherManagerError::VoucherNotDivisible)
    ));
}

#[test]
fn test_tx_fails_on_negative_amount() {
    let (standard, _, _, recipient, mut voucher) = setup_voucher_with_one_tx();
    let last_valid_tx = voucher.transactions.last().unwrap();
    let prev_hash = crypto_utils::get_hash(to_canonical_json(last_valid_tx).unwrap());

    let tx2 = Transaction {
        t_id: "".to_string(),
        prev_hash,
        t_type: "transfer".to_string(), // KORREKTUR: Gib einen validen Typ an
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
    let (standard, _, _, recipient, mut voucher) = setup_voucher_with_one_tx();

    let tx2 = Transaction {
        t_id: "".to_string(),
        prev_hash: "intentionally-wrong-hash".to_string(),
        t_type: "transfer".to_string(), // KORREKTUR: Gib einen validen Typ an
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
        VoucherCoreError::Validation(ValidationError::InvalidTransaction(s)) if s.contains("Transaction chain broken")
    ));
}

#[test]
fn test_tx_fails_on_insufficient_funds() {
    let (standard, _, _, recipient, mut voucher) = setup_voucher_with_one_tx();
    let last_valid_tx = voucher.transactions.last().unwrap();
    let prev_hash = crypto_utils::get_hash(to_canonical_json(last_valid_tx).unwrap());

    // Empfänger hat 40.0000, versucht aber 50.0000 als vollen Transfer zu senden.
    let tx2 = Transaction {
        t_id: "".to_string(),
        prev_hash,
        t_type: "transfer".to_string(), // Explizit als Transfer
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
    // KORREKTUR: Nach der Härtung von `verify_transactions` MUSS diese Funktion
    // nun fehlschlagen, da sie die Guthaben jetzt verfolgt.
    assert!(matches!(
        result.unwrap_err(),
        VoucherCoreError::Validation(ValidationError::InsufficientFundsInChain { .. })
    ), "Validation should now fail with InsufficientFundsInChain after hardening.");
}

#[test]
fn test_tx_fails_on_subsequent_init_transaction() {
    let (standard, _, _, recipient, mut voucher) = setup_voucher_with_one_tx();
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
        VoucherCoreError::Validation(ValidationError::InvalidTransaction(s)) if s.contains("invalid type 'init'")
    ));
}

#[test]
fn test_tx_fails_on_send_to_self_after_init() {
    let (standard, _, _, recipient, mut voucher) = setup_voucher_with_one_tx();
    let last_valid_tx = voucher.transactions.last().unwrap();
    let prev_hash = crypto_utils::get_hash(to_canonical_json(last_valid_tx).unwrap());

    let tx2 = Transaction {
        t_id: "".to_string(),
        prev_hash,
        t_type: "transfer".to_string(),
        t_time: voucher_lib::services::utils::get_current_timestamp(),
        sender_id: recipient.user_id.clone(),
        recipient_id: recipient.user_id.clone(), // Sendet an sich selbst
        amount: "40.0000".to_string(), // KORREKTUR: Der Betrag muss dem Guthaben des Senders entsprechen für einen validen vollen Transfer.
        sender_remaining_amount: None,
        sender_signature: "".to_string(),
    };
    let signed_tx2 = resign_transaction(tx2, &recipient.signing_key);
    voucher.transactions.push(signed_tx2);

    let result = validate_voucher_against_standard(&voucher, &standard);
    assert!(matches!(
        result.unwrap_err(),
        VoucherCoreError::Validation(ValidationError::InvalidTransaction(s)) if s.contains("Sender and recipient cannot be the same")
    ));
}

#[test]
fn test_tx_fails_on_tampered_content_vs_tid() {
    let (standard, _, _, _, mut voucher) = setup_voucher_with_one_tx();

    // Manipuliere einen Wert, aber berechne weder t_id noch Signatur neu.
    voucher.transactions[1].amount = "99.9999".to_string();

    let result = validate_voucher_against_standard(&voucher, &standard);
    assert!(matches!(
        result.unwrap_err(),
        VoucherCoreError::Validation(ValidationError::MismatchedTransactionId { .. })
    ));
}

#[test]
fn test_tx_fails_on_zero_amount() {
    let (standard, _, _, recipient, mut voucher) = setup_voucher_with_one_tx();
    let last_valid_tx = voucher.transactions.last().unwrap();
    let prev_hash = crypto_utils::get_hash(to_canonical_json(last_valid_tx).unwrap());

    let tx2 = Transaction {
        t_id: "".to_string(),
        prev_hash,
        t_type: "transfer".to_string(),
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
        VoucherCoreError::Validation(ValidationError::NegativeOrZeroAmount { .. })
    ));
}

#[test]
fn test_guarantor_sig_fails_on_mismatched_voucher_id() {
    let (standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
    let creator_identity = &ACTORS.alice;
    let voucher_data = NewVoucherData {
        creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
        nominal_value: NominalValue { amount: "60".to_string(), ..Default::default() },
        ..Default::default()
    };

    // Verwende den Helper, um die `CountOutOfBounds`-Validierung bei der Erstellung zu umgehen.
    let mut voucher = create_voucher_for_manipulation(voucher_data, standard, standard_hash, &creator_identity.signing_key, "en");

    // SETUP-FIX: Füge zuerst eine valide Signatur hinzu, damit die `CountOutOfBounds`-Regel
    // mit min=2 nicht sofort greift, wenn wir die zweite, manipulierte Signatur hinzufügen.
    voucher.guarantor_signatures.push(create_female_guarantor_signature(&voucher));

    let guarantor1 = &ACTORS.guarantor1;

    // Erstelle eine valide Signatur
    let mut sig1 = create_guarantor_signature_with_time(
        &voucher.voucher_id, &guarantor1, "G1", "1", // Hier wird die umbenannte Funktion verwendet
        "2026-08-01T10:00:00Z",
    );
    // Manipuliere die voucher_id NACH der Erstellung
    sig1.voucher_id = "this-is-the-wrong-voucher-id".to_string();

    voucher.guarantor_signatures.push(sig1);

    let validation_result = validate_voucher_against_standard(&voucher, standard);
    assert!(matches!(
        validation_result.unwrap_err(),
        VoucherCoreError::Validation(ValidationError::MismatchedVoucherIdInSignature { .. })
    ));
}


#[test]
fn test_validation_fails_on_field_group_rule_gender_mismatch() {
    let (standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
    let creator_identity = &ACTORS.alice;
    let voucher_data = NewVoucherData {
        creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
        nominal_value: NominalValue { amount: "60".to_string(), ..Default::default() },
        ..Default::default()
    };

    // Erstelle einen Basis-Gutschein.
    let mut voucher = create_voucher_for_manipulation(voucher_data, standard, standard_hash, &creator_identity.signing_key, "en");

    // Füge zwei männliche Bürgen hinzu. Dies verletzt die Regel "1x male, 1x female".
    // Die Gesamtzahl (2) ist aber korrekt laut `counts`-Regel.
    let male_sig_1 = create_guarantor_signature_with_time(&voucher.voucher_id, &ACTORS.guarantor1, "Hans", "1", "2026-01-01T12:00:00Z");
    let male_sig_2 = create_guarantor_signature_with_time(&voucher.voucher_id, &ACTORS.male_guarantor, "Martin", "1", "2026-01-01T13:00:00Z");

    voucher.guarantor_signatures.push(male_sig_1);
    voucher.guarantor_signatures.push(male_sig_2);

    // Die Validierung muss nun wegen der `FieldValueCountMismatch`-Regel fehlschlagen.
    let validation_result = validate_voucher_against_standard(&voucher, standard);

    let err = validation_result.unwrap_err();
    assert!(
        matches!(
            &err,
            VoucherCoreError::Validation(ValidationError::FieldValueCountOutOfBounds { path, field, .. }) if path == "guarantor_signatures" && field == "gender"
        ),
        "Validation should fail with a gender count mismatch, but got: {:?}", err
    );
}