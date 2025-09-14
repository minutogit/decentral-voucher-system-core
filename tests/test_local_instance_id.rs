// tests/test_local_instance_id.rs

use voucher_lib::models::voucher::{
    Address, Collateral, Creator, NominalValue, Transaction, Voucher, VoucherStandard,
};
use voucher_lib::services::crypto_utils::get_hash;
use voucher_lib::services::utils::get_current_timestamp;
use voucher_lib::wallet::Wallet;
use voucher_lib::VoucherCoreError;
mod test_utils;
use test_utils::ACTORS;

/// Hilfsfunktion, um einen einfachen Test-Gutschein zu erstellen.
/// Initialisiert alle Felder manuell, um die fehlende `Default`-Implementierung zu umgehen.
fn create_base_voucher(creator_id: &str, amount: &str) -> Voucher {
    let voucher = Voucher {
        voucher_standard: VoucherStandard {
            name: "Test Standard".to_string(),
            uuid: "uuid-test".to_string(),
            standard_definition_hash: "dummy-hash-for-test".to_string(),
        },
        voucher_id: "voucher-123".to_string(),
        voucher_nonce: "test-nonce".to_string(),
        description: "A test voucher".to_string(),
        primary_redemption_type: "SERVICE".to_string(),
        divisible: true,
        creation_date: get_current_timestamp(),
        valid_until: get_current_timestamp(),
        standard_minimum_issuance_validity: "P1Y".to_string(),
        non_redeemable_test_voucher: true,
        nominal_value: NominalValue {
            unit: "Minutes".to_string(),
            amount: amount.to_string(),
            abbreviation: "m".to_string(),
            description: "Test".to_string(),
        },
        collateral: Collateral {
            type_: "".to_string(),
            unit: "".to_string(),
            amount: "".to_string(),
            abbreviation: "".to_string(),
            description: "".to_string(),
            redeem_condition: "".to_string(),
        },
        creator: Creator {
            id: creator_id.to_string(),
            first_name: "Test".to_string(),
            last_name: "Creator".to_string(),
            address: Address::default(), // Address leitet Default ab und kann so verwendet werden
            organization: None,
            community: None,
            phone: None,
            email: None,
            url: None,
            gender: "9".to_string(),
            service_offer: None,
            needs: None,
            signature: "".to_string(),
            coordinates: "0,0".to_string(),
        },
        guarantor_requirements_description: "".to_string(),
        footnote: "".to_string(),
        guarantor_signatures: vec![],
        needed_guarantors: 0,
        transactions: vec![], // Wird im nächsten Schritt gefüllt
        additional_signatures: vec![],
    };

    let mut voucher = voucher;
    let init_transaction = Transaction {
        t_id: "t-init-abc".to_string(),
        prev_hash: get_hash(format!("{}{}", &voucher.voucher_id, &voucher.voucher_nonce)),
        t_type: "init".to_string(),
        t_time: get_current_timestamp(),
        sender_id: creator_id.to_string(),
        recipient_id: creator_id.to_string(),
        amount: amount.to_string(),
        sender_remaining_amount: None,
        sender_signature: "sig-init".to_string(),
    };
    voucher.transactions.push(init_transaction);
    voucher
}

/// Testet, ob die `local_instance_id` für den ursprünglichen Ersteller
/// korrekt auf Basis der `init`-Transaktion berechnet wird.
#[test]
fn test_local_id_for_initial_creator() {
    let creator = &ACTORS.alice;
    let voucher = create_base_voucher(&creator.user_id, "100");

    let result = Wallet::calculate_local_instance_id(&voucher, &creator.user_id);
    assert!(result.is_ok());
    let local_id = result.unwrap();

    let expected_combined_string =
        format!("{}{}{}", voucher.voucher_id, "t-init-abc", &creator.user_id);
    let expected_hash = get_hash(expected_combined_string);

    assert_eq!(local_id, expected_hash);
}

/// Testet, ob die `local_instance_id` für einen Empfänger nach einem
/// vollständigen Transfer korrekt auf Basis der Transfer-Transaktion berechnet wird.
#[test]
fn test_local_id_after_full_transfer() {
    let creator = &ACTORS.alice;
    let recipient = &ACTORS.bob;
    let mut voucher = create_base_voucher(&creator.user_id, "100");

    let transfer_tx = Transaction {
        t_id: "t-transfer-def".to_string(),
        prev_hash: get_hash("..."),
        t_type: "".to_string(), // Voller Transfer
        t_time: get_current_timestamp(),
        sender_id: creator.user_id.clone(),
        recipient_id: recipient.user_id.clone(),
        amount: "100".to_string(),
        sender_remaining_amount: None, // Kein Restbetrag
        sender_signature: "sig-transfer".to_string(),
    };
    voucher.transactions.push(transfer_tx);

    // ID für den neuen Besitzer (Empfänger)
    let result_recipient = Wallet::calculate_local_instance_id(&voucher, &recipient.user_id);
    assert!(result_recipient.is_ok());
    let local_id_recipient = result_recipient.unwrap();

    let expected_combined_string =
        format!("{}{}{}", voucher.voucher_id, "t-transfer-def", &recipient.user_id);
    let expected_hash = get_hash(expected_combined_string);

    assert_eq!(local_id_recipient, expected_hash);

    // ID für den ursprünglichen Besitzer (jetzt archiviert)
    // NACH ÄNDERUNG: Die ID muss nun auf der Transfer-Transaktion basieren, da der Creator dort der Sender war.
    let result_creator = Wallet::calculate_local_instance_id(&voucher, &creator.user_id);
    assert!(result_creator.is_ok());
    let creators_archived_id = result_creator.unwrap();
    let expected_archived_string = format!("{}{}{}", voucher.voucher_id, "t-transfer-def", &creator.user_id);
    assert_eq!(creators_archived_id, get_hash(expected_archived_string), "Die archivierte ID des Erstellers sollte auf der Transfer-Transaktion basieren.");
}

/// Testet die `local_instance_id` für Sender und Empfänger nach einer Teilung (Split).
/// Beide IDs müssen auf der Split-Transaktion basieren.
#[test]
fn test_local_id_after_split() {
    let sender = &ACTORS.sender;
    let recipient = &ACTORS.recipient1;
    let mut voucher = create_base_voucher(&sender.user_id, "100");

    let split_tx = Transaction {
        t_id: "t-split-ghi".to_string(),
        prev_hash: get_hash("..."),
        t_type: "split".to_string(),
        t_time: get_current_timestamp(),
        sender_id: sender.user_id.clone(),
        recipient_id: recipient.user_id.clone(),
        amount: "40".to_string(),
        sender_remaining_amount: Some("60".to_string()),
        sender_signature: "sig-split".to_string(),
    };
    voucher.transactions.push(split_tx);

    // ID für den Sender (hat noch Restguthaben)
    let result_sender = Wallet::calculate_local_instance_id(&voucher, &sender.user_id);
    assert!(result_sender.is_ok());
    let local_id_sender = result_sender.unwrap();
    let expected_combined_sender =
        format!("{}{}{}", voucher.voucher_id, "t-split-ghi", &sender.user_id);
    assert_eq!(local_id_sender, get_hash(expected_combined_sender));

    // ID für den Empfänger des Teilbetrags
    let result_recipient = Wallet::calculate_local_instance_id(&voucher, &recipient.user_id);
    assert!(result_recipient.is_ok());
    let local_id_recipient = result_recipient.unwrap();
    let expected_combined_recipient =
        format!("{}{}{}", voucher.voucher_id, "t-split-ghi", &recipient.user_id);
    assert_eq!(local_id_recipient, get_hash(expected_combined_recipient));
}

/// Testet, ob die Funktion korrekt einen Fehler zurückgibt, wenn der
/// angegebene Nutzer den Gutschein nie besessen hat.
#[test]
fn test_local_id_for_non_owner() {
    let creator = &ACTORS.alice;
    let non_owner = &ACTORS.hacker;
    let voucher = create_base_voucher(&creator.user_id, "100");

    let result = Wallet::calculate_local_instance_id(&voucher, &non_owner.user_id);
    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), VoucherCoreError::Generic(msg) if msg.contains("never owned"))
    );
}

/// **NEUER TEST:** Stellt sicher, dass sich die `local_instance_id` ändert, wenn ein Gutschein
/// erst weggeschickt und dann wieder zurückempfangen wird.
#[test]
fn test_local_id_changes_on_round_trip() {
    let alice = &ACTORS.alice;
    let bob = &ACTORS.bob;
    let mut voucher = create_base_voucher(&alice.user_id, "100");

    // 1. Alice's initialer Zustand
    let initial_alice_id = Wallet::calculate_local_instance_id(&voucher, &alice.user_id)
        .expect("Alice should own the voucher initially");
    assert!(!initial_alice_id.is_empty());

    // 2. Alice sendet den Gutschein an Bob
    let tx_to_bob = Transaction {
        t_id: "t-alice-to-bob".to_string(),
        prev_hash: get_hash("..."),
        t_type: "".to_string(),
        t_time: get_current_timestamp(),
        sender_id: alice.user_id.clone(),
        recipient_id: bob.user_id.clone(),
        amount: "100".to_string(),
        sender_remaining_amount: None,
        sender_signature: "sig-to-bob".to_string(),
    };
    voucher.transactions.push(tx_to_bob);

    // 3. Überprüfen: Bob besitzt ihn jetzt, Alice nicht mehr
    let _bobs_id = Wallet::calculate_local_instance_id(&voucher, &bob.user_id)
        .expect("Bob should now own the voucher");
    let alice_result_after_send = Wallet::calculate_local_instance_id(&voucher, &alice.user_id);
    // NACH ÄNDERUNG: Alice's Aufruf muss erfolgreich sein und eine NEUE ID zurückgeben, die
    // auf der Transaktion basiert, bei der sie die Senderin war.
    assert!(alice_result_after_send.is_ok());
    let alice_archived_id = alice_result_after_send.unwrap();
    assert_ne!(initial_alice_id, alice_archived_id, "Alice's archived ID should NOT be her initial ID.");
    let expected_archived_string = format!("{}{}{}", voucher.voucher_id, "t-alice-to-bob", &alice.user_id);
    assert_eq!(alice_archived_id, get_hash(expected_archived_string), "Alice's archived ID should be based on the transaction to Bob.");

    // 4. Bob sendet den Gutschein zurück an Alice
    let tx_to_alice = Transaction {
        t_id: "t-bob-to-alice".to_string(),
        prev_hash: get_hash("..."),
        t_type: "".to_string(),
        t_time: get_current_timestamp(),
        sender_id: bob.user_id.clone(),
        recipient_id: alice.user_id.clone(),
        amount: "100".to_string(),
        sender_remaining_amount: None,
        sender_signature: "sig-to-alice".to_string(),
    };
    voucher.transactions.push(tx_to_alice);

    // 5. Finale Überprüfung: Alice besitzt ihn wieder, aber mit einer NEUEN ID. Bob besitzt ihn nicht mehr.
    let final_alice_id = Wallet::calculate_local_instance_id(&voucher, &alice.user_id)
        .expect("Alice should own the voucher again");
    let bob_result_after_send = Wallet::calculate_local_instance_id(&voucher, &bob.user_id);
    // NACH ÄNDERUNG: Bob's Aufruf muss erfolgreich sein und seine ID aus der Transaktion zu ihm zurückgeben.
    assert!(bob_result_after_send.is_ok());

    // Die wichtigste Prüfung: Die neue ID von Alice muss sich von ihrer ursprünglichen ID unterscheiden.
    assert_ne!(
        initial_alice_id, final_alice_id,
        "Alice's local instance ID should be different after receiving the voucher back."
    );

    // Die neue ID muss auf der letzten Transaktion basieren.
    let expected_final_string =
        format!("{}{}{}", voucher.voucher_id, "t-bob-to-alice", &alice.user_id);
    assert_eq!(final_alice_id, get_hash(expected_final_string));
}