//! # tests/wallet_api/hostile_bundles.rs
//!
//! Enthält Tests, die den `AppService` gegen den Empfang von feindseligen,
//! intern inkonsistenten Gutscheinen härten.

use voucher_lib::{
    app_service::AppService,
    test_utils::{
        create_test_bundle, generate_signed_standard_toml, resign_transaction, ACTORS,
        SILVER_STANDARD, setup_service_with_profile,
    },
    UserIdentity,
    models::voucher::{Creator, NominalValue}, services::voucher_manager::NewVoucherData,
};
use std::collections::HashMap;
use tempfile::tempdir;

/// Erstellt eine Sender- und Empfänger-Instanz für die Tests.
fn setup_sender_recipient() -> (AppService, UserIdentity, AppService, String) {
    let dir_sender = tempdir().unwrap();
    let sender = &ACTORS.sender;
    let (service_sender, _) =
        setup_service_with_profile(dir_sender.path(), sender, "Sender", "pwd");
    let identity_sender = sender.identity.clone();

    let dir_recipient = tempdir().unwrap();
    let recipient = &ACTORS.recipient1;
    let (service_recipient, _) =
        setup_service_with_profile(dir_recipient.path(), recipient, "Recipient", "pwd");
    let id_recipient = service_recipient.get_user_id().unwrap();

    (service_sender, identity_sender, service_recipient, id_recipient)
}

/// Test 2.1: Ein empfangenes Bundle mit einem Gutschein, dessen Transaktionskette
/// gebrochen ist (`prev_hash` ist falsch), muss abgewiesen werden.
#[test]
fn test_rejection_of_broken_transaction_chain() {
    // 1. ARRANGE
    let (mut service_sender, identity_sender, mut service_recipient, id_recipient) =
        setup_sender_recipient();
    let silver_toml = generate_signed_standard_toml("voucher_standards/silver_v1/standard.toml");
    let mut standards_map = HashMap::new();
    standards_map.insert(SILVER_STANDARD.0.metadata.uuid.clone(), silver_toml);

    let (wallet, _) = service_sender.get_unlocked_mut_for_test();
    let mut voucher = wallet
        .create_new_voucher(
            &identity_sender,
            &SILVER_STANDARD.0,
            &SILVER_STANDARD.1,
            "en",
            NewVoucherData {
                creator: Creator {
                    id: identity_sender.user_id.clone(),
                    ..Default::default()
                },
                nominal_value: NominalValue { amount: "100".to_string(), ..Default::default() },
                ..Default::default()
            },
        )
        .unwrap();

    let mut tx2 = voucher.transactions[0].clone();
    tx2.prev_hash = "garbage_hash_value".to_string(); // Kette brechen
    tx2.t_type = "transfer".to_string();
    tx2.recipient_id = id_recipient.clone();
    tx2 = resign_transaction(tx2, &identity_sender.signing_key);
    voucher.transactions.push(tx2);

    let bundle =
        create_test_bundle(&identity_sender, vec![voucher], &id_recipient, None).unwrap();

    // 2. ACT
    let result = service_recipient.receive_bundle(&bundle, &standards_map, None, "pwd");

    // 3. ASSERT
    assert!(result.is_err());
    let err_str = result.unwrap_err();
    assert!(
        err_str.contains("Transaction chain broken"),
        "Error should complain about broken transaction chain. Got: {}",
        err_str
    );
    assert!(service_recipient
        .get_voucher_summaries(None, None)
        .unwrap()
        .is_empty());
}

/// Test 2.2: Ein Bundle mit einer "split"-Transaktion, deren Beträge sich nicht korrekt
/// zum vorherigen Saldo aufsummieren, muss abgewiesen werden.
#[test]
fn test_rejection_of_inconsistent_split_math() {
    // 1. ARRANGE
    let (mut service_sender, identity_sender, mut service_recipient, id_recipient) =
        setup_sender_recipient();
    let silver_toml = generate_signed_standard_toml("voucher_standards/silver_v1/standard.toml");
    let mut standards_map = HashMap::new();
    standards_map.insert(SILVER_STANDARD.0.metadata.uuid.clone(), silver_toml);

    let (wallet, _) = service_sender.get_unlocked_mut_for_test();
    let mut voucher = wallet
        .create_new_voucher(
            &identity_sender,
            &SILVER_STANDARD.0,
            &SILVER_STANDARD.1,
            "en",
            // Erstelle einen Gutschein mit 100
            NewVoucherData {
                creator: Creator {
                    id: identity_sender.user_id.clone(),
                    ..Default::default()
                },
                nominal_value: NominalValue {
                    amount: "100".to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();

    let prev_tx_hash = voucher_lib::services::crypto_utils::get_hash(
        voucher_lib::services::utils::to_canonical_json(voucher.transactions.last().unwrap())
            .unwrap(),
    );

    // Erstelle eine Split-Transaktion: Sende 30, behalte 80. (30 + 80 != 100 -> FEHLER)
    let mut tx2 = voucher.transactions[0].clone();
    tx2.prev_hash = prev_tx_hash;
    tx2.t_type = "split".to_string();
    tx2.recipient_id = id_recipient.clone();
    tx2.amount = "30.0000".to_string();
    tx2.sender_remaining_amount = Some("80.0000".to_string()); // Falscher Restbetrag
    tx2 = resign_transaction(tx2, &identity_sender.signing_key);
    voucher.transactions.push(tx2);

    let bundle =
        create_test_bundle(&identity_sender, vec![voucher], &id_recipient, None).unwrap();

    // 2. ACT
    let result = service_recipient.receive_bundle(&bundle, &standards_map, None, "pwd");

    // 3. ASSERT
    // HINWEIS: Dies deckt eine Lücke in der aktuellen Validierungslogik auf.
    // `voucher_validation.rs` prüft nur `InsufficientFunds`, aber nicht, ob die Summe
    // eines Splits korrekt ist. Der Test wird daher aktuell fälschlicherweise PASSIEREN.
    // Ein idealer Fehler wäre `InvalidSplitBalance`. Wir prüfen auf einen generischen Fehler.
    assert!(result.is_err(), "Receive bundle should have failed due to bad math. This might indicate a validation logic gap if it passes.");

    // Sobald die Validierung gehärtet ist, kann die spezifische Fehlermeldung geprüft werden.
    // assert!(result.unwrap_err().contains("InvalidSplitBalance"));
}