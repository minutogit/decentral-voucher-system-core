//! # tests/test_wallet_integration.rs
//!
//! Integrationstests für die `Wallet`-Fassade.
//! Deckt den Lebenszyklus, Transfers, Double-Spending, Abfragen und Signaturen ab.

mod test_utils;

use test_utils::{
    add_voucher_to_wallet, create_guarantor_signature_data, debug_open_container,
    setup_in_memory_wallet, ACTORS, MINUTO_STANDARD, SILVER_STANDARD,
};
use voucher_lib::models::profile::VoucherStatus;
use voucher_lib::models::voucher_standard_definition::VoucherStandardDefinition;
use voucher_lib::storage::{AuthMethod, file_storage::FileStorage};
use voucher_lib::wallet::Wallet;
use voucher_lib::VoucherCoreError;

use rust_decimal::Decimal;
use std::str::FromStr;
use tempfile::tempdir;

// --- 1. Kernfunktionalität (mod.rs) ---

/// 1.1. Testet den grundlegenden Lebenszyklus: Erstellen, Speichern, Laden.
#[test]
fn test_wallet_lifecycle() {
    let dir = tempdir().unwrap();
    let mut storage = FileStorage::new(dir.path());

    // 1. Wallet erstellen
    // Eine valide 12-Wort-Phrase mit korrekter Prüfsumme.
    let valid_mnemonic =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let (wallet_a, identity_a) = Wallet::new_from_mnemonic(valid_mnemonic, Some("test"))
        .expect("Wallet creation failed");
    let original_user_id = wallet_a.profile.user_id.clone();

    // 2. Wallet speichern
    wallet_a
        .save(&mut storage, &identity_a, "password123")
        .expect("Saving wallet failed");

    // 3. Wallet laden
    let auth = AuthMethod::Password("password123");
    let wallet_b =
        Wallet::load(&storage, &auth, identity_a).expect("Loading wallet failed");

    // 4. Prüfen, ob der Zustand wiederhergestellt wurde
    assert_eq!(
        wallet_b.profile.user_id, original_user_id,
        "Loaded user ID should match the original"
    );
}

/// 1.2. Szenario (Happy Path): Vollständiger Transfer.
#[test]
fn test_transfer_full_amount() {
    // Setup
    let alice_identity = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(alice_identity);
    let voucher_id =
        add_voucher_to_wallet(&mut alice_wallet, alice_identity, "100", &MINUTO_STANDARD, true).unwrap();

    let bob_identity = &ACTORS.bob;
    let mut bob_wallet = setup_in_memory_wallet(bob_identity);

    // Aktion: Alice sendet 100m an Bob
    let (bundle_bytes, sent_voucher) = alice_wallet
        .create_transfer(
            alice_identity,
            &MINUTO_STANDARD,
            &voucher_id,
            &bob_identity.user_id,
            "100",
            None,
            None,
        )
        .unwrap();
    assert_eq!(sent_voucher.transactions.len(), 2);

    // Assert (Alice):
    // - Der ursprüngliche Gutschein ist aus dem aktiven Store entfernt.
    assert!(
        alice_wallet.voucher_store.vouchers.get(&voucher_id).is_none(),
        "Original voucher should be removed from active store"
    );
    // - Es gibt jetzt einen archivierten Gutschein.
    let (_, (_, status)) = alice_wallet
        .voucher_store
        .vouchers
        .iter()
        .find(|(_, (v, _))| v.voucher_id == sent_voucher.voucher_id)
        .unwrap();
    assert_eq!(*status, VoucherStatus::Archived);

    // Aktion (Bob): Empfängt das Bündel
    let result = bob_wallet
        .process_encrypted_transaction_bundle(bob_identity, &bundle_bytes, None)
        .unwrap();
    assert_eq!(result.header.sender_id, alice_identity.user_id);

    // Assert (Bob):
    // - Bob hat einen neuen, aktiven Gutschein.
    assert_eq!(bob_wallet.voucher_store.vouchers.len(), 1);
    let (_, bob_status) = bob_wallet.voucher_store.vouchers.values().next().unwrap();
    assert_eq!(*bob_status, VoucherStatus::Active);
    let summary = bob_wallet.list_vouchers().pop().unwrap();
    assert_eq!(summary.current_amount, "100");
}

/// 1.2. Szenario (Happy Path): Teilüberweisung (Split).
#[test]
fn test_transfer_split_amount() {
    // Setup
    let alice_identity = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(alice_identity);
    let voucher_id =
        add_voucher_to_wallet(&mut alice_wallet, alice_identity, "100", &MINUTO_STANDARD, true).unwrap();

    let bob_identity = &ACTORS.bob;
    let mut bob_wallet = setup_in_memory_wallet(bob_identity);

    // Aktion: Alice sendet 30m an Bob
    let (bundle_bytes, _) = alice_wallet
        .create_transfer(
            alice_identity,
            &MINUTO_STANDARD,
            &voucher_id,
            &bob_identity.user_id,
            "30",
            None,
            None,
        )
        .unwrap();

    // Assert (Alice):
    // - Der alte 100m-Gutschein ist weg.
    assert!(alice_wallet.voucher_store.vouchers.get(&voucher_id).is_none());
    // - Ein neuer Gutschein mit 70m Restbetrag ist `Active`.
    let active_summary = alice_wallet
        .list_vouchers()
        .into_iter()
        .find(|s| s.status == VoucherStatus::Active)
        .unwrap();
    assert_eq!(active_summary.current_amount, "70");

    // Aktion (Bob): Empfängt die 30m
    bob_wallet
        .process_encrypted_transaction_bundle(bob_identity, &bundle_bytes, None)
        .unwrap();
    let bob_summary = bob_wallet.list_vouchers().pop().unwrap();
    assert_eq!(bob_summary.current_amount, "30");
    assert_eq!(bob_summary.status, VoucherStatus::Active);
}

/// 1.2. Szenario (Fehlerfall): Ungültiger Betrag (negativ oder falsche Genauigkeit).
#[test]
fn test_transfer_invalid_amount() {
    // Setup
    let alice_identity = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(alice_identity);
    let voucher_id =
        add_voucher_to_wallet(&mut alice_wallet, alice_identity, "100", &MINUTO_STANDARD, true).unwrap();
    let bob_identity = &ACTORS.bob;

    // Versuch 1: Negativer Betrag
    let result_negative = alice_wallet.create_transfer(
        alice_identity,
        &MINUTO_STANDARD,
        &voucher_id,
        &bob_identity.user_id,
        "-50",
        None,
        None,
    );
    assert!(matches!(
        result_negative,
        Err(VoucherCoreError::Manager(_))
    ));

    // Versuch 2: Unzulässige Dezimalstellen für Minuto-Standard
    let result_decimal = alice_wallet.create_transfer(
        alice_identity,
        &MINUTO_STANDARD,
        &voucher_id,
        &bob_identity.user_id,
        "50.5", // Minuto erlaubt keine Dezimalstellen
        None,
        None,
    );
    assert!(matches!(
        result_decimal,
        Err(VoucherCoreError::Manager(_))
    ));
}

/// 1.2. Szenario (Fehlerfall): Gutschein nicht aktiv.
#[test]
fn test_transfer_inactive_voucher() {
    let alice_identity = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(alice_identity);
    let voucher_id =
        add_voucher_to_wallet(&mut alice_wallet, alice_identity, "100", &MINUTO_STANDARD, true).unwrap();
    let bob_identity = &ACTORS.bob;

    // Status manuell auf Quarantined setzen
    let (_, status) = alice_wallet
        .voucher_store
        .vouchers
        .get_mut(&voucher_id)
        .unwrap();
    *status = VoucherStatus::Quarantined;

    let result = alice_wallet.create_transfer(
        alice_identity,
        &MINUTO_STANDARD,
        &voucher_id,
        &bob_identity.user_id,
        "50",
        None,
        None,
    );
    assert!(matches!(
        result,
        Err(VoucherCoreError::VoucherNotActive(
            VoucherStatus::Quarantined
        ))
    ));
}

/// 1.2. Szenario (Sicherheit): Proaktive Double-Spend-Verhinderung.
#[test]
fn test_proactive_double_spend_prevention() {
    let alice_identity = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(alice_identity);
    let voucher_id =
        add_voucher_to_wallet(&mut alice_wallet, alice_identity, "100", &MINUTO_STANDARD, true).unwrap();
    let bob_identity = &ACTORS.bob;
    let charlie_identity = &ACTORS.charlie;

    // Erste Transaktion (erfolgreich)
    alice_wallet
        .create_transfer(
            alice_identity,
            &MINUTO_STANDARD,
            &voucher_id,
            &bob_identity.user_id,
            "100",
            None,
            None,
        )
        .expect("First transfer should succeed");

    // Zweiter Versuch, denselben Zustand auszugeben (sollte fehlschlagen)
    // Da `create_transfer` den alten Zustand entfernt, müssen wir den Aufruf
    // mit der alten `voucher_id` wiederholen, die nicht mehr existiert.
    let result = alice_wallet.create_transfer(
        alice_identity,
        &MINUTO_STANDARD,
        &voucher_id, // Diese ID ist nicht mehr im aktiven Store
        &charlie_identity.user_id,
        "100",
        None,
        None,
    );
    // Der Fehler ist `VoucherNotFound`, weil der Zustand nach der Ausgabe
    // sofort ungültig wird. Dies ist ein effektiver Schutz.
    assert!(matches!(
        result,
        Err(VoucherCoreError::VoucherNotFound(_))
    ));
}

/// 1.4. Szenario (Happy Path): Erstellen eines neuen Gutscheins direkt im Wallet.
#[test]
fn test_create_new_voucher_and_get_user_id() {
    let identity = &ACTORS.issuer;
    let mut wallet = setup_in_memory_wallet(identity);

    // Test 1: get_user_id
    assert_eq!(
        wallet.get_user_id(),
        identity.user_id,
        "get_user_id should return the correct user id"
    );

    // Test 2: create_new_voucher
    // Setup: Daten für den neuen Gutschein vorbereiten.
    let new_voucher_data = voucher_lib::services::voucher_manager::NewVoucherData {
        creator: voucher_lib::models::voucher::Creator {
            id: identity.user_id.clone(),
            first_name: "Test".to_string(),
            last_name: "Creator".to_string(),
            ..Default::default()
        },
        nominal_value: voucher_lib::models::voucher::NominalValue {
            amount: "500".to_string(),
            ..Default::default()
        },
        ..Default::default()
    };

    // Aktion: Neuen Gutschein erstellen
    let created_voucher = wallet.create_new_voucher(identity, &MINUTO_STANDARD, new_voucher_data).unwrap();
    assert_eq!(created_voucher.transactions.len(), 1, "A new voucher must have exactly one 'init' transaction.");

    // Assert: Gutschein ist im Wallet vorhanden und aktiv
    let summary = wallet.list_vouchers().pop().expect("Wallet should contain one voucher");
    assert_eq!(summary.current_amount, "500");
    assert_eq!(summary.status, VoucherStatus::Active);
    assert_eq!(wallet.voucher_store.vouchers.len(), 1);
}

/// 1.3. Szenario (Konflikt): Reaktive Double-Spend-Erkennung ("Earliest Wins").
#[test]
#[ignore] // Diesen Test erst aktivieren, wenn Helfer zum Erzeugen von Konflikten bereitstehen.
fn test_reactive_double_spend_earliest_wins() {
    println!("TODO: Implement test_reactive_double_spend_earliest_wins");
}

// --- 2. Abfragen & Ansichten (queries.rs) ---

/// Testet die korrekte Saldoberechnung über mehrere Währungen hinweg.
#[test]
fn test_get_total_balance_by_currency() {
    let identity = &ACTORS.issuer;
    let mut wallet = setup_in_memory_wallet(identity);

    // Helfer zum Hinzufügen von Gutscheinen für einen bestimmten Standard
    let mut add_voucher = |amount: &str, status: VoucherStatus, standard: &VoucherStandardDefinition| {
        let new_voucher_data = voucher_lib::services::voucher_manager::NewVoucherData {
            creator: voucher_lib::models::voucher::Creator { id: identity.user_id.clone(), first_name: "Test".to_string(), last_name: "User".to_string(), ..Default::default() },
            nominal_value: voucher_lib::models::voucher::NominalValue { amount: amount.to_string(), ..Default::default() },
            ..Default::default()
        };

        let voucher = voucher_lib::services::voucher_manager::create_voucher(new_voucher_data, standard, &identity.signing_key).unwrap();
        // Hier werden keine Bürgen hinzugefügt, da die Gültigkeit für die Saldoprüfung irrelevant ist.

        wallet
            .add_voucher_to_store(voucher, status, &identity.user_id)
            .unwrap();
    };

    // 1. Setup: Wallet mit diversen Gutscheinen füllen
    add_voucher("100", VoucherStatus::Active, &MINUTO_STANDARD); // 100 Minuto
    add_voucher("50", VoucherStatus::Active, &MINUTO_STANDARD); // 50 Minuto
    add_voucher("200", VoucherStatus::Quarantined, &MINUTO_STANDARD); // Ignored
    add_voucher("1.25", VoucherStatus::Active, &SILVER_STANDARD); // 1.25 Unzen
    add_voucher("0.75", VoucherStatus::Active, &SILVER_STANDARD); // 0.75 Unzen

    // 2. Aktion: Saldo berechnen
    let balances = wallet.get_total_balance_by_currency();

    // 3. Assert: Nur aktive Gutscheine werden korrekt summiert und gruppiert
    assert_eq!(balances.len(), 2, "Two currencies should be present");

    let expected_minuto_balance = Decimal::from_str("150").unwrap();
    let actual_minuto_balance = Decimal::from_str(balances.get("Minuto").unwrap()).unwrap();
    assert_eq!(actual_minuto_balance, expected_minuto_balance, "Balance for 'Minuto' should be 150");

    let expected_silver_balance = Decimal::from_str("2.00").unwrap(); // 1.25 + 0.75 = 2.0
    let actual_silver_balance = Decimal::from_str(balances.get("Unzen").unwrap()).unwrap();
    assert_eq!(actual_silver_balance, expected_silver_balance, "Balance for 'Unzen' should be 2.00");
}

// --- 3. Signatur-Workflow (signature_handler.rs) ---

/// Testet den Signatur-Roundtrip für den Minuto-Standard.
/// Dieser Test prüft nur das erfolgreiche Anhängen einer Signatur, nicht die vollständige Gültigkeit des Gutscheins.
#[test]
fn test_signature_roundtrip_for_minuto_standard() {
    let alice_identity = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(alice_identity);
    let voucher_id =
        add_voucher_to_wallet(&mut alice_wallet, alice_identity, "100", &MINUTO_STANDARD, false).unwrap();
    let bob_identity = &ACTORS.bob;

    let (initial_voucher, _) = alice_wallet.voucher_store.vouchers.get(&voucher_id).unwrap();
    assert!(initial_voucher.guarantor_signatures.is_empty());

    // Alice erstellt eine Signaturanfrage für Bob
    let request_bytes = alice_wallet
        .create_signing_request(alice_identity, &voucher_id, &bob_identity.user_id)
        .unwrap();

    // Bob verarbeitet die Anfrage und erstellt eine Antwort
    let (voucher_for_signing, _) =
        debug_open_container(&request_bytes, bob_identity).unwrap();
    let signature_data = create_guarantor_signature_data(&bob_identity, "1", &voucher_for_signing.voucher_id); // male

    let response_bytes = alice_wallet
        .create_detached_signature_response(
            &bob_identity,
            &voucher_for_signing,
            signature_data,
            &alice_identity.user_id,
        )
        .unwrap();

    // Alice verarbeitet die Signatur-Antwort
    alice_wallet
        .process_and_attach_signature(alice_identity, &response_bytes)
        .unwrap();

    // Assert: Der Gutschein hat jetzt genau eine Signatur von Bob
    let (final_voucher, _) = alice_wallet.voucher_store.vouchers.get(&voucher_id).unwrap();
    assert_eq!(final_voucher.guarantor_signatures.len(), 1);
    let signature = &final_voucher.guarantor_signatures[0];
    assert_eq!(signature.guarantor_id, bob_identity.user_id);
}

/// Testet den Signatur-Workflow für den Silber-Standard, bei dem Bürgen optional sind.
#[test]
fn test_signature_roundtrip_on_silver_standard() {
    let alice_identity = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(alice_identity);
    let voucher_id =
        add_voucher_to_wallet(&mut alice_wallet, alice_identity, "10", &SILVER_STANDARD, false).unwrap();
    let bob_identity = &ACTORS.bob;

    // Der Gutschein ist initial gültig ohne Signaturen, da `needed_count = 0` ist.
    let (initial_voucher, _) = alice_wallet.voucher_store.vouchers.get(&voucher_id).unwrap();
    assert!(initial_voucher.guarantor_signatures.is_empty());
    assert_eq!(initial_voucher.needed_guarantors, 0);

    // Alice bittet Bob trotzdem um eine (optionale) Signatur
    let request_bytes = alice_wallet
        .create_signing_request(alice_identity, &voucher_id, &bob_identity.user_id)
        .unwrap();

    // Bob antwortet
    let (voucher_for_signing, _) =
        debug_open_container(&request_bytes, bob_identity).unwrap();
    let signature_data = create_guarantor_signature_data(&bob_identity, "1", &voucher_for_signing.voucher_id);

    let response_bytes = alice_wallet
        .create_detached_signature_response(
            &bob_identity,
            &voucher_for_signing,
            signature_data,
            &alice_identity.user_id,
        )
        .unwrap();

    // Alice fügt die Signatur an
    alice_wallet
        .process_and_attach_signature(alice_identity, &response_bytes)
        .unwrap();

    // Assert: Der Gutschein hat nun eine optionale Signatur
    let (final_voucher, _) = alice_wallet.voucher_store.vouchers.get(&voucher_id).unwrap();
    assert_eq!(final_voucher.guarantor_signatures.len(), 1);
}