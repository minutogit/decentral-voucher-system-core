//! # tests/test_voucher_integrity.rs
//!
//! Integrationstests, die die fundamentale strukturelle und logische Konsistenz
//! eines vollstaendigen `Voucher`-Objekts verifizieren. Der Fokus liegt hier auf
//! der korrekten Anwendung von Geschaeftsregeln und der Datenintegritaet,
//! nicht auf boeswilligen Angriffen.

// Wir importieren die oeffentlichen Typen, die in lib.rs re-exportiert wurden.
use voucher_lib::{
    create_transaction, create_voucher, crypto_utils, to_canonical_json, validate_voucher_against_standard, Creator, NewVoucherData, NominalValue,
    Transaction, VoucherCoreError,
};
use voucher_lib::error::ValidationError;
mod test_utils;
use test_utils::{
    create_female_guarantor_signature, create_guarantor_signature_with_time,
    create_male_guarantor_signature,
    create_voucher_for_manipulation, resign_transaction, ACTORS, MINUTO_STANDARD, SILVER_STANDARD,
};
use voucher_lib::services::voucher_manager::VoucherManagerError;

// --- Tests zur grundlegenden Struktur und Logik (verschoben aus advanced_validation) ---

#[test]
fn test_validation_fails_on_standard_uuid_mismatch() {
    let (minuto_standard, minuto_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
    let silver_standard = &SILVER_STANDARD.0;

    let creator_identity = &ACTORS.alice;
    let voucher_data = NewVoucherData {
        creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
        nominal_value: NominalValue { amount: "60".to_string(), ..Default::default() },
        validity_duration: Some("P1Y".to_string()),
        ..Default::default()
    };

    let mut voucher = create_voucher_for_manipulation(voucher_data, minuto_standard, minuto_hash, &creator_identity.signing_key, "en");
    voucher.guarantor_signatures.push(create_male_guarantor_signature(&voucher));
    voucher.guarantor_signatures.push(create_female_guarantor_signature(&voucher));

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
        validity_duration: Some("P1Y".to_string()),
        ..Default::default()
    };

    let mut voucher = create_voucher_for_manipulation(voucher_data, standard, standard_hash, &creator_identity.signing_key, "en");
    voucher.guarantor_signatures.push(create_male_guarantor_signature(&voucher));
    voucher.guarantor_signatures.push(create_female_guarantor_signature(&voucher));

    voucher.valid_until = "2020-01-01T00:00:00Z".to_string();

    let mut voucher_to_sign = voucher.clone();
    voucher_to_sign.creator.signature = "".to_string();
    voucher_to_sign.voucher_id = "".to_string();
    voucher_to_sign.transactions.clear();
    voucher_to_sign.guarantor_signatures.clear();
    voucher_to_sign.additional_signatures.clear();
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
        validity_duration: Some("P1Y".to_string()),
        ..Default::default()
    };
    let mut voucher = create_voucher(voucher_data, standard, standard_hash, &creator_identity.signing_key, "en").unwrap();
    voucher.transactions[0].amount = "not-a-number".to_string();
    let tx = voucher.transactions[0].clone();
    voucher.transactions[0] = resign_transaction(tx, &creator_identity.signing_key);
    let validation_result = validate_voucher_against_standard(&voucher, standard);
    assert!(
        matches!(
            validation_result.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::InvalidAmountFormat { .. })
        ),
        "Validation should fail with a DecimalConversionError."
    );
}

#[test]
fn test_validation_fails_on_transaction_time_order() {
    let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
    let sender = &ACTORS.sender;
    let recipient = &ACTORS.recipient1;
    let voucher_data = NewVoucherData {
        creator: Creator { id: sender.user_id.clone(), ..Default::default() },
        nominal_value: NominalValue { amount: "60.0000".to_string(), ..Default::default() },
        validity_duration: Some("P1Y".to_string()),
        ..Default::default()
    };
    let initial_voucher = create_voucher_for_manipulation(voucher_data, standard, standard_hash, &sender.signing_key, "en");
    let mut voucher_after_split = create_transaction(&initial_voucher, standard, &sender.user_id, &sender.signing_key, &recipient.user_id, "10.0000").unwrap();

    let _first_tx_time = voucher_after_split.transactions[0].t_time.clone();
    let invalid_second_time = "2020-01-01T00:00:00Z";
    voucher_after_split.transactions[1].t_time = invalid_second_time.to_string();
    let tx = voucher_after_split.transactions[1].clone();
    voucher_after_split.transactions[1] = resign_transaction(tx, &sender.signing_key);

    let validation_result = validate_voucher_against_standard(&voucher_after_split, standard);
    assert!(
        matches!(
            validation_result.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::InvalidTimeOrder { .. })
        )
    );
}


#[test]
fn test_validation_fails_on_init_tx_with_wrong_prev_hash() {
    let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
    let creator_identity = &ACTORS.alice;
    let voucher_data = NewVoucherData {
        creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
        nominal_value: NominalValue { amount: "60".to_string(), ..Default::default() },
        validity_duration: Some("P1Y".to_string()),
        ..Default::default()
    };
    let mut voucher = create_voucher_for_manipulation(voucher_data, standard, standard_hash, &creator_identity.signing_key, "en");
    voucher.transactions[0].prev_hash = "intentionally_wrong_prev_hash".to_string();
    let tx = voucher.transactions[0].clone();
    voucher.transactions[0] = resign_transaction(tx, &creator_identity.signing_key);
    let validation_result = validate_voucher_against_standard(&voucher, standard);
    assert!(
        matches!(
            validation_result.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::InvalidTransaction(_))
        )
    );
}

#[test]
fn test_validation_fails_on_init_tx_with_wrong_amount() {
    let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
    let creator_identity = &ACTORS.alice;
    let voucher_data = NewVoucherData {
        creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
        nominal_value: NominalValue { amount: "60".to_string(), ..Default::default() },
        validity_duration: Some("P1Y".to_string()),
        ..Default::default()
    };
    let mut voucher = create_voucher_for_manipulation(voucher_data, standard, standard_hash, &creator_identity.signing_key, "en");
    voucher.transactions[0].amount = "999".to_string();
    let tx = voucher.transactions[0].clone();
    voucher.transactions[0] = resign_transaction(tx, &creator_identity.signing_key);
    let validation_result = validate_voucher_against_standard(&voucher, standard);
    assert!(
        matches!(
            validation_result.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::InitAmountMismatch { .. })
        )
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
        validity_duration: Some("P1Y".to_string()),
        ..Default::default()
    };
    let mut voucher = create_voucher_for_manipulation(voucher_data, standard, standard_hash, &creator_identity.signing_key, "en");
    voucher.transactions[0].recipient_id = imposter_identity.user_id.clone();
    let tx = voucher.transactions[0].clone();
    voucher.transactions[0] = resign_transaction(tx, &creator_identity.signing_key);
    let validation_result = validate_voucher_against_standard(&voucher, standard);
    assert!(
        matches!(
            validation_result.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::InitPartyMismatch { .. })
        )
    );
}

#[test]
fn test_tx_fails_on_split_if_not_divisible() {
    let (silver_standard, _) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
    let creator = &ACTORS.alice;
    let recipient = &ACTORS.bob;
    let mut non_divisible_standard = silver_standard.clone();
    non_divisible_standard.template.fixed.is_divisible = false;
    let mut standard_to_hash = non_divisible_standard.clone();
    standard_to_hash.signature = None;
    let standard_hash = crypto_utils::get_hash(to_canonical_json(&standard_to_hash).unwrap());
    let voucher_data = NewVoucherData {
        creator: Creator { id: creator.user_id.clone(), ..Default::default() },
        nominal_value: NominalValue { amount: "100.0000".to_string(), ..Default::default() },
        validity_duration: Some("P1Y".to_string()),
        ..Default::default()
    };
    let voucher = create_voucher(voucher_data, &non_divisible_standard, &standard_hash, &creator.signing_key, "en").unwrap();
    let tx_result = create_transaction(&voucher, &non_divisible_standard, &creator.user_id, &creator.signing_key, &recipient.user_id, "10.0000");
    assert!(matches!(
        tx_result.unwrap_err(),
        VoucherCoreError::Manager(VoucherManagerError::VoucherNotDivisible)
    ));
}

#[test]
fn test_tx_fails_on_zero_amount() {
    let (standard, _, _, recipient, mut voucher) = test_utils::setup_voucher_with_one_tx();
    let last_valid_tx = voucher.transactions.last().unwrap();
    let prev_hash = crypto_utils::get_hash(to_canonical_json(last_valid_tx).unwrap());
    let tx2 = Transaction {
        t_id: "".to_string(), prev_hash, t_type: "transfer".to_string(),
        t_time: voucher_lib::services::utils::get_current_timestamp(),
        sender_id: recipient.user_id.clone(),
        recipient_id: "ts1...some_other_person".to_string(),
        amount: "0.0000".to_string(), sender_remaining_amount: None, sender_signature: "".to_string(),
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
fn test_tx_fails_on_negative_amount() {
    let (standard, _, _, recipient, mut voucher) = test_utils::setup_voucher_with_one_tx();
    let last_valid_tx = voucher.transactions.last().unwrap();
    let prev_hash = crypto_utils::get_hash(to_canonical_json(last_valid_tx).unwrap());
    let tx2 = Transaction {
        t_id: "".to_string(), prev_hash, t_type: "transfer".to_string(),
        t_time: voucher_lib::services::utils::get_current_timestamp(),
        sender_id: recipient.user_id.clone(),
        recipient_id: "ts1...some_other_person".to_string(),
        amount: "-10.0000".to_string(), sender_remaining_amount: None, sender_signature: "".to_string(),
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
        validity_duration: Some("P4Y".to_string()), // KORREKTUR: Minuto-Standard erfordert >= P3Y
        ..Default::default()
    };
    let mut voucher = create_voucher_for_manipulation(voucher_data, standard, standard_hash, &creator_identity.signing_key, "en");
    voucher.guarantor_signatures.push(create_female_guarantor_signature(&voucher));
    let mut sig1 = create_guarantor_signature_with_time(&voucher.voucher_id, &ACTORS.guarantor1, "G1", "1", "2026-08-01T10:00:00Z");
    // Manipuliere die voucher_id, um den Testfall zu erstellen.
    sig1.voucher_id = "this-is-the-wrong-voucher-id".to_string();

    // KORREKTUR: Die Signatur muss neu berechnet werden, nachdem die Daten manipuliert wurden.
    // Andernfalls würde die `InvalidSignatureId`-Prüfung vor der `MismatchedVoucherId`-Prüfung fehlschlagen.
    let mut data_for_id_hash = sig1.clone();
    data_for_id_hash.signature_id = "".to_string();
    data_for_id_hash.signature = "".to_string();
    sig1.signature_id = crypto_utils::get_hash(to_canonical_json(&data_for_id_hash).unwrap());
    let new_digital_signature = crypto_utils::sign_ed25519(&ACTORS.guarantor1.signing_key, sig1.signature_id.as_bytes());
    sig1.signature = bs58::encode(new_digital_signature.to_bytes()).into_string();

    voucher.guarantor_signatures.push(sig1);

    let validation_result = validate_voucher_against_standard(&voucher, standard);
    if let Err(e) = &validation_result {
        println!("[DEBUG] test_guarantor_sig_fails_on_mismatched_voucher_id: Error returned: {:?}", e);
    }
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
        validity_duration: Some("P4Y".to_string()), // KORREKTUR: Minuto-Standard erfordert >= P3Y
        ..Default::default()
    };
    let mut voucher = create_voucher_for_manipulation(voucher_data, standard, standard_hash, &creator_identity.signing_key, "en");
    let male_sig_1 = create_guarantor_signature_with_time(&voucher.voucher_id, &ACTORS.guarantor1, "Hans", "1", "2026-01-01T12:00:00Z");
    let male_sig_2 = create_guarantor_signature_with_time(&voucher.voucher_id, &ACTORS.male_guarantor, "Martin", "1", "2026-01-01T13:00:00Z");
    voucher.guarantor_signatures.push(male_sig_1);
    voucher.guarantor_signatures.push(male_sig_2);
    let validation_result = validate_voucher_against_standard(&voucher, standard);
    if let Err(e) = &validation_result {
        println!("[DEBUG] test_validation_fails_on_field_group_rule_gender_mismatch: Error returned: {:?}", e);
    }
    assert!(
        matches!(
            validation_result.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::FieldValueCountOutOfBounds { .. })
        )
    );
}

// ===================================================================================
// NEUE TESTS FÜR GESCHÄFTSREGELN UND LOGISCHE KONSISTENZ (Plan-Umsetzung)
// ===================================================================================

#[cfg(test)]
mod behavior_and_integrity_rules {
    use super::*;
    use test_utils::{generate_signed_standard_toml, create_guarantor_signature_with_time};
    use voucher_lib::services::standard_manager::verify_and_parse_standard;

    fn load_toml_standard(path: &str) -> (voucher_lib::VoucherStandardDefinition, String) {
        let toml_str = generate_signed_standard_toml(path);
        verify_and_parse_standard(&toml_str).unwrap()
    }

    #[test]
    fn test_behavior_fails_on_validity_too_short() {
        let (standard, standard_hash) = load_toml_standard("tests/test_data/standards/standard_behavior_rules.toml");
        let creator_identity = &ACTORS.alice;
        let voucher_data = NewVoucherData {
            creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
            validity_duration: Some("P2Y".to_string()), // Valide Start-Dauer > 1Y
            nominal_value: NominalValue { amount: "100".to_string(), ..Default::default() },
            ..Default::default()
        };

        // Dieser Standard erfordert min. 1 Jahr Gültigkeit. Wir erstellen einen Gutschein,
        // der manuell auf eine kürzere Gültigkeit gesetzt wird.
        let mut voucher = create_voucher_for_manipulation(voucher_data, &standard, &standard_hash, &creator_identity.signing_key, "en");
        
        // Setze das Datum auf nur 6 Monate in die Zukunft.
        let creation_dt = chrono::DateTime::parse_from_rfc3339(&voucher.creation_date).unwrap();
        let short_validity_dt = creation_dt + chrono::Months::new(6);
        voucher.valid_until = short_validity_dt.to_rfc3339();

        // Creator-Signatur muss neu berechnet werden, da `valid_until` Teil der signierten Daten ist.
        let mut voucher_to_sign = voucher.clone();
        voucher_to_sign.creator.signature = "".to_string();
        voucher_to_sign.voucher_id = "".to_string();
        voucher_to_sign.transactions.clear();
        voucher_to_sign.guarantor_signatures.clear();
        voucher_to_sign.additional_signatures.clear();
        let hash = crypto_utils::get_hash(to_canonical_json(&voucher_to_sign).unwrap());
        let new_sig = crypto_utils::sign_ed25519(&creator_identity.signing_key, hash.as_bytes());
        voucher.creator.signature = bs58::encode(new_sig.to_bytes()).into_string();

        let result = validate_voucher_against_standard(&voucher, &standard);
        assert!(matches!(
            result.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::ValidityDurationTooShort)
        ));
    }

    #[test]
    fn test_behavior_fails_on_invalid_decimal_places() {
        let (standard, standard_hash) = load_toml_standard("tests/test_data/standards/standard_behavior_rules.toml"); // max_places = 2
        let creator_identity = &ACTORS.alice;
        
        // Fall 1: Der Nennwert hat zu viele Nachkommastellen
        let voucher_data = NewVoucherData {
            creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
            validity_duration: Some("P1Y".to_string()),
            nominal_value: NominalValue { amount: "100.123".to_string(), ..Default::default() },
            ..Default::default()
        };
        let voucher_bad_nominal = create_voucher_for_manipulation(voucher_data, &standard, &standard_hash, &creator_identity.signing_key, "en");
        let result1 = validate_voucher_against_standard(&voucher_bad_nominal, &standard);
        assert!(matches!(
            result1.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::InvalidAmountPrecision { path, max_places: 2, found: 3 }) if path == "nominal_value.amount"
        ));

        // Fall 2: Eine Transaktion hat zu viele Nachkommastellen
        let mut voucher = create_voucher(NewVoucherData {
            creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
            validity_duration: Some("P1Y".to_string()),
            nominal_value: NominalValue { amount: "100.00".to_string(), ..Default::default() },
            ..Default::default()
        }, &standard, &standard_hash, &creator_identity.signing_key, "en").unwrap();

        voucher.transactions[0].amount = "100.123".to_string(); // Manipuliere init-Transaktion
        let tx = voucher.transactions[0].clone();
        voucher.transactions[0] = resign_transaction(tx, &creator_identity.signing_key);
        
        let result2 = validate_voucher_against_standard(&voucher, &standard);
        assert!(matches!(
            result2.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::InvalidAmountPrecision { path, max_places: 2, found: 3 }) if path == "transactions[0].amount"
        ));
    }

    #[test]
    fn test_fails_on_conflicting_count_and_group_rules() {
        let (standard, standard_hash) = load_toml_standard("tests/test_data/standards/standard_conflicting_rules.toml");
        let creator_identity = &ACTORS.alice;
        let voucher_data = NewVoucherData {
            creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
            validity_duration: Some("P1Y".to_string()),
            nominal_value: NominalValue { amount: "100".to_string(), ..Default::default() },
            ..Default::default()
        };
        let base_voucher = create_voucher_for_manipulation(voucher_data, &standard, &standard_hash, &creator_identity.signing_key, "en");

        // Fall 1: Erfülle die `field_group_rules` (4 Bürgen), verletze aber die `counts`-Regel (max 3)
        let mut voucher1 = base_voucher.clone();
        voucher1.guarantor_signatures = vec![
            create_guarantor_signature_with_time(&voucher1.voucher_id, &ACTORS.guarantor1, "G1", "A", "2026-01-01T12:00:00Z"),
            create_guarantor_signature_with_time(&voucher1.voucher_id, &ACTORS.guarantor2, "G2", "A", "2026-01-01T13:00:00Z"),
            create_guarantor_signature_with_time(&voucher1.voucher_id, &ACTORS.male_guarantor, "G3", "B", "2026-01-01T14:00:00Z"),
            create_guarantor_signature_with_time(&voucher1.voucher_id, &ACTORS.female_guarantor, "G4", "B", "2026-01-01T15:00:00Z"),
        ];

        let result1 = validate_voucher_against_standard(&voucher1, &standard);
        assert!(matches!(
            result1.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::CountOutOfBounds { field, min: 3, max: 3, found: 4 }) if field == "guarantor_signatures"
        ), "Should fail because of count mismatch before checking group rules");

        // Fall 2: Erfülle die `counts`-Regel (3 Bürgen), verletze aber die `field_group_rules` (braucht 2x "B")
        let mut voucher2 = base_voucher.clone();
        voucher2.guarantor_signatures = vec![
            create_guarantor_signature_with_time(&voucher2.voucher_id, &ACTORS.guarantor1, "G1", "A", "2026-01-01T12:00:00Z"),
            create_guarantor_signature_with_time(&voucher2.voucher_id, &ACTORS.guarantor2, "G2", "A", "2026-01-01T13:00:00Z"),
            create_guarantor_signature_with_time(&voucher2.voucher_id, &ACTORS.male_guarantor, "G3", "B", "2026-01-01T14:00:00Z"),
        ];

        let result2 = validate_voucher_against_standard(&voucher2, &standard);
        assert!(matches!(
            result2.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::FieldValueCountOutOfBounds { value, min: 2, max: 2, found: 1, .. }) if value == "B"
        ), "Should fail because of group rule value count mismatch");
    }
    
    #[test]
    fn test_fails_on_full_transfer_amount_mismatch() {
        let (standard, _, _, recipient, mut voucher) = test_utils::setup_voucher_with_one_tx();
        // Nach dem Setup hat `recipient` (Bob) ein Guthaben von 40.0000.

        let last_valid_tx = voucher.transactions.last().unwrap();
        let prev_hash = crypto_utils::get_hash(to_canonical_json(last_valid_tx).unwrap());

        // Erstelle eine Transaktion vom Typ "transfer", aber mit einem Betrag, der
        // NICHT dem vollen Guthaben entspricht. Dies ist ein logischer Fehler.
        let invalid_transfer_tx = Transaction {
            t_id: "".to_string(),
            prev_hash,
            t_type: "transfer".to_string(), // Explizit voller Transfer
            t_time: voucher_lib::services::utils::get_current_timestamp(),
            sender_id: recipient.user_id.clone(),
            recipient_id: ACTORS.charlie.user_id.clone(),
            amount: "10.0000".to_string(), // Weniger als das volle Guthaben von 40
            sender_remaining_amount: None, // Korrekt für einen Transfer
            sender_signature: "".to_string(),
        };

        let signed_tx = resign_transaction(invalid_transfer_tx, &recipient.signing_key);
        voucher.transactions.push(signed_tx);

        let result = validate_voucher_against_standard(&voucher, &standard);
        assert!(matches!(
            result.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::FullTransferAmountMismatch { .. })
        ));
    }
}
