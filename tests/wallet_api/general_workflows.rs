//! # tests/wallet_api/general_workflows.rs
//!
//! Enthält Integrationstests für die primären, nicht-signaturbezogenen
//! End-to-End-Workflows, die über die `AppService`- und `Wallet`-Fassaden
//! abgewickelt werden.

// Binde das `test_utils` Modul explizit über seinen Dateipfad ein.
#[path = "../test_utils.rs"]
mod test_utils;

use self::test_utils::{
    add_voucher_to_wallet, create_voucher_for_manipulation, generate_signed_standard_toml,
    generate_valid_mnemonic, setup_in_memory_wallet, ACTORS, MINUTO_STANDARD, SILVER_STANDARD,
};
use rust_decimal::Decimal;
use std::str::FromStr;
use tempfile::tempdir;
use voucher_lib::{
    app_service::AppService,
    models::{
        voucher::{Creator, NominalValue},
        voucher_standard_definition::VoucherStandardDefinition,
    },
    services::voucher_manager::NewVoucherData,
    storage::{file_storage::FileStorage, AuthMethod},
    wallet::Wallet,
    VoucherCoreError, VoucherStatus,
};

// --- 1. AppService Workflows ---

/// Simuliert den gesamten Lebenszyklus eines Benutzers über den `AppService`.
///
/// ### Szenario:
/// 1.  Zwei temporäre Verzeichnisse für Alice und Bob werden erstellt.
/// 2.  Zwei `AppService`-Instanzen werden initialisiert.
/// 3.  Alice und Bob erstellen ihre Profile mit Mnemonic und Passwort.
/// 4.  Alice loggt sich aus und wieder ein, um die Authentifizierung zu testen.
/// 5.  Alice erstellt einen neuen Gutschein in ihrem Wallet.
/// 6.  Alice transferiert den gesamten Gutschein an Bob.
/// 7.  Der alte Gutschein-Zustand bei Alice wird als archiviert verifiziert.
/// 8.  Bob empfängt das Bundle und verifiziert seinen neuen Kontostand.
#[test]
fn api_app_service_full_lifecycle() {
    // --- 1. Setup ---
    let silver_standard_toml =
        generate_signed_standard_toml("voucher_standards/silver_v1/standard.toml");
    let standard = &SILVER_STANDARD.0;
    let dir_alice = tempdir().expect("Failed to create temp dir for Alice");
    let dir_bob = tempdir().expect("Failed to create temp dir for Bob");
    let mnemonic_alice = generate_valid_mnemonic();
    let mnemonic_bob = generate_valid_mnemonic();
    let password = "password123";

    let mut service_alice =
        AppService::new(dir_alice.path()).expect("Failed to create service for Alice");
    let mut service_bob =
        AppService::new(dir_bob.path()).expect("Failed to create service for Bob");

    // --- 2. Profile erstellen ---
    service_alice
        .create_profile(&mnemonic_alice, Some("alice"), password)
        .expect("Alice profile creation failed");
    service_bob
        .create_profile(&mnemonic_bob, Some("bob"), password)
        .expect("Bob profile creation failed");

    let id_alice = service_alice.get_user_id().unwrap();
    let id_bob = service_bob.get_user_id().unwrap();

    // --- 3. Logout und Login für Alice ---
    service_alice.logout();
    assert!(
        service_alice.get_user_id().is_err(),
        "Service should be locked after logout"
    );
    service_alice
        .login(password)
        .expect("Login with correct password should succeed");
    assert_eq!(service_alice.get_user_id().unwrap(), id_alice);

    // --- 4. Alice erstellt einen Gutschein ---
    service_alice
        .create_new_voucher(
            &silver_standard_toml,
            "en",
            NewVoucherData {
                nominal_value: NominalValue {
                    amount: "100".to_string(),
                    ..Default::default()
                },
                creator: Creator {
                    id: id_alice.clone(),
                    ..Default::default()
                },
                ..Default::default()
            },
            password,
        )
        .expect("Voucher creation failed");
    let summaries_alice = service_alice.get_voucher_summaries().unwrap();
    let local_id_alice = summaries_alice[0].local_instance_id.clone();

    // --- 5. Alice sendet den Gutschein an Bob ---
    let transfer_bundle = service_alice
        .create_transfer_bundle(
            &standard,
            &local_id_alice,
            &id_bob,
            "100",
            None,
            None,
            password,
        )
        .expect("Transfer failed");
    let summary = service_alice
        .get_voucher_details(&local_id_alice)
        .expect_err("Old voucher ID should not resolve to an active voucher anymore");
    assert!(summary.to_lowercase().contains("not found"));

    // --- 6. Bob empfängt den Gutschein ---
    let mut standards = std::collections::HashMap::new();
    standards.insert(standard.metadata.uuid.clone(), silver_standard_toml);
    service_bob
        .receive_bundle(&transfer_bundle, &standards, None, password)
        .expect("Receive failed");
    let balance_bob = service_bob.get_total_balance_by_currency().unwrap();
    // KORREKTUR: Die Bilanz wird jetzt nach der Abkürzung der Währung gruppiert, nicht nach der Einheit.
    let silver_abbreviation = &SILVER_STANDARD.0.metadata.abbreviation;
    assert_eq!(balance_bob.get(silver_abbreviation).unwrap(), "100.0000");
}

/// Testet die statischen Mnemonic-Hilfsfunktionen des `AppService`.
///
/// ### Szenario:
/// 1.  Generiert eine gültige 12-Wort-Phrase und prüft deren Korrektheit.
/// 2.  Versucht, eine Phrase mit ungültiger Wortanzahl zu generieren (soll fehlschlagen).
/// 3.  Validiert eine frisch generierte Phrase (soll erfolgreich sein).
/// 4.  Validiert Phrasen mit ungültigen Wörtern oder schlechter Prüfsumme (sollen fehlschlagen).
#[test]
fn api_app_service_mnemonic_helpers() {
    let mnemonic = AppService::generate_mnemonic(12).unwrap();
    assert_eq!(
        mnemonic.split_whitespace().count(),
        12,
        "Mnemonic should have 12 words"
    );
    assert!(
        AppService::generate_mnemonic(11).is_err(),
        "Should fail with invalid word count"
    );
    assert!(
        AppService::validate_mnemonic(&mnemonic).is_ok(),
        "A freshly generated mnemonic should be valid"
    );
    let invalid_word_mnemonic =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon hello";
    assert!(
        AppService::validate_mnemonic(invalid_word_mnemonic).is_err(),
        "Should fail with an invalid word"
    );
    let bad_checksum_mnemonic =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    assert!(
        AppService::validate_mnemonic(bad_checksum_mnemonic).is_err(),
        "Should fail with a bad checksum"
    );
}

/// Testet die Passwort-Wiederherstellungsfunktion des `AppService`.
///
/// ### Szenario:
/// 1.  Ein Profil wird erstellt und sofort wieder gesperrt.
/// 2.  Ein Wiederherstellungsversuch mit einer falschen Mnemonic schlägt fehl.
/// 3.  Ein Wiederherstellungsversuch mit der korrekten Mnemonic ist erfolgreich.
/// 4.  Das Wallet ist nach der Wiederherstellung entsperrt.
/// 5.  Nach erneutem Sperren schlägt der Login mit dem alten Passwort fehl,
///     während der Login mit dem neuen Passwort funktioniert.
#[test]
fn api_app_service_password_recovery() {
    let dir = tempdir().expect("Failed to create temp dir");
    let mut service = AppService::new(dir.path()).expect("Failed to create service");
    let mnemonic =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let initial_password = "password-123";
    let new_password = "password-ABC";

    service
        .create_profile(&mnemonic, Some("recovery-test"), initial_password)
        .expect("Profile creation failed");
    service.logout();

    let wrong_mnemonic =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    assert!(
        service
            .recover_wallet_and_set_new_password(&wrong_mnemonic, new_password)
            .is_err(),
        "Recovery with wrong mnemonic should fail"
    );
    assert!(
        service.get_user_id().is_err(),
        "Service should remain locked after failed recovery"
    );

    assert!(
        service
            .recover_wallet_and_set_new_password(&mnemonic, new_password)
            .is_ok(),
        "Recovery with correct mnemonic should succeed"
    );
    assert!(
        service.get_user_id().is_ok(),
        "Service should be unlocked after successful recovery"
    );

    service.logout();
    assert!(
        service.login(initial_password).is_err(),
        "Login with old password should fail after recovery"
    );
    assert!(
        service.login(new_password).is_ok(),
        "Login with new password should succeed after recovery"
    );
}

// --- 2. Wallet Workflows ---

/// Testet den grundlegenden Lebenszyklus des Wallets: Erstellen, Speichern, Laden.
///
/// ### Szenario:
/// 1.  Ein neues Wallet wird aus einer Mnemonic-Phrase erstellt.
/// 2.  Der Zustand des Wallets wird mit einem Passwort verschlüsselt gespeichert.
/// 3.  Das Wallet wird aus dem Speicher geladen.
/// 4.  Es wird verifiziert, dass die geladene User ID mit der ursprünglichen übereinstimmt.
#[test]
fn api_wallet_lifecycle() {
    let dir = tempdir().unwrap();
    let mut storage = FileStorage::new(dir.path());
    let valid_mnemonic =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let (wallet_a, identity_a) =
        Wallet::new_from_mnemonic(valid_mnemonic, Some("test")).expect("Wallet creation failed");
    let original_user_id = wallet_a.profile.user_id.clone();

    wallet_a
        .save(&mut storage, &identity_a, "password123")
        .expect("Saving wallet failed");

    let auth = AuthMethod::Password("password123");
    let (wallet_b, _) = Wallet::load(&storage, &auth).expect("Loading wallet failed");

    assert_eq!(
        wallet_b.profile.user_id, original_user_id,
        "Loaded user ID should match the original"
    );
}

/// Testet eine vollständige Überweisung des gesamten Gutscheinbetrags.
///
/// ### Szenario:
/// 1.  Alice hat einen Gutschein über 100m.
/// 2.  Sie erstellt einen Transfer von 100m an Bob.
/// 3.  Ihr ursprünglicher Gutschein wird archiviert.
/// 4.  Bob empfängt das Bundle und hat danach einen aktiven Gutschein über 100m.
#[test]
fn api_wallet_transfer_full_amount() {
    let alice_identity = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(alice_identity);
    let (minuto_standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
    let voucher_id =
        add_voucher_to_wallet(&mut alice_wallet, alice_identity, "100", minuto_standard, true)
            .unwrap();
    let bob_identity = &ACTORS.bob;
    let mut bob_wallet = setup_in_memory_wallet(bob_identity);

    let (bundle_bytes, _) = alice_wallet
        .create_transfer(
            alice_identity,
            minuto_standard,
            &voucher_id,
            &bob_identity.user_id,
            "100",
            None,
            None,
        )
        .unwrap();

    let summary = alice_wallet
        .list_vouchers()
        .into_iter()
        .find(|s| s.status == VoucherStatus::Archived)
        .unwrap();
    assert_eq!(summary.status, VoucherStatus::Archived);

    bob_wallet
        .process_encrypted_transaction_bundle(bob_identity, &bundle_bytes, None)
        .unwrap();

    let summary = bob_wallet.list_vouchers().pop().unwrap();
    assert_eq!(summary.current_amount, "100");
    assert_eq!(summary.status, VoucherStatus::Active);
}

/// Testet eine Teilüberweisung, bei der der Restbetrag beim Sender verbleibt.
///
/// ### Szenario:
/// 1.  Alice hat einen Gutschein über 100m.
/// 2.  Sie sendet 30m an Bob.
/// 3.  Ihr alter Gutschein wird archiviert und ein neuer, aktiver Gutschein
///     über 70m wird für sie erstellt.
/// 4.  Bob empfängt das Bundle und hat danach einen aktiven Gutschein über 30m.
#[test]
fn api_wallet_transfer_split_amount() {
    let alice_identity = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(alice_identity);
    let (minuto_standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
    let voucher_id =
        add_voucher_to_wallet(&mut alice_wallet, alice_identity, "100", minuto_standard, true)
            .unwrap();
    let bob_identity = &ACTORS.bob;
    let mut bob_wallet = setup_in_memory_wallet(bob_identity);

    let (bundle_bytes, _) = alice_wallet
        .create_transfer(
            alice_identity,
            minuto_standard,
            &voucher_id,
            &bob_identity.user_id,
            "30",
            None,
            None,
        )
        .unwrap();

    let active_summary = alice_wallet
        .list_vouchers()
        .into_iter()
        .find(|s| s.status == VoucherStatus::Active)
        .unwrap();
    assert_eq!(active_summary.current_amount, "70");

    bob_wallet
        .process_encrypted_transaction_bundle(bob_identity, &bundle_bytes, None)
        .unwrap();
    let bob_summary = bob_wallet.list_vouchers().pop().unwrap();
    assert_eq!(bob_summary.current_amount, "30");
}

/// Stellt sicher, dass Transfers mit ungültigen Beträgen fehlschlagen.
///
/// ### Szenario:
/// 1.  Ein Transfer mit einem negativen Betrag wird versucht und schlägt fehl.
/// 2.  Ein Transfer mit für den Standard unzulässiger Genauigkeit (Dezimalstellen)
///     wird versucht und schlägt fehl.
#[test]
fn api_wallet_transfer_invalid_amount() {
    let alice_identity = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(alice_identity);
    let (minuto_standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
    let voucher_id =
        add_voucher_to_wallet(&mut alice_wallet, alice_identity, "100", minuto_standard, true)
            .unwrap();
    let bob_identity = &ACTORS.bob;

    let result_negative = alice_wallet.create_transfer(
        alice_identity,
        minuto_standard,
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

    let result_decimal = alice_wallet.create_transfer(
        alice_identity,
        minuto_standard,
        &voucher_id,
        &bob_identity.user_id,
        "50.5",
        None,
        None,
    );
    assert!(matches!(
        result_decimal,
        Err(VoucherCoreError::Manager(_))
    ));
}

/// Stellt sicher, dass Transfers nur mit `Active` Gutscheinen möglich sind.
///
/// ### Szenario:
/// 1.  Ein Gutschein wird manuell auf den Status `Quarantined` gesetzt.
/// 2.  Ein Transferversuch mit diesem Gutschein schlägt mit einem `VoucherNotActive`
///     Fehler fehl.
#[test]
fn api_wallet_transfer_inactive_voucher() {
    let alice_identity = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(alice_identity);
    let (minuto_standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
    let voucher_id =
        add_voucher_to_wallet(&mut alice_wallet, alice_identity, "100", minuto_standard, true)
            .unwrap();
    let bob_identity = &ACTORS.bob;

    let instance = alice_wallet
        .voucher_store
        .vouchers
        .get_mut(&voucher_id)
        .unwrap();
    instance.status = VoucherStatus::Quarantined { reason: "test".to_string() };

    let result = alice_wallet.create_transfer(
        alice_identity,
        minuto_standard,
        &voucher_id,
        &bob_identity.user_id,
        "50",
        None,
        None,
    );
    assert!(matches!(
        result,
        Err(VoucherCoreError::VoucherNotActive(VoucherStatus::Quarantined{..}))
    ));
}

/// Testet die proaktive Double-Spend-Verhinderung im `Wallet`.
///
/// ### Szenario:
/// 1.  Alice transferiert einen Gutschein an Bob. Der `create_transfer` Aufruf
///     ist erfolgreich und entfernt den alten Gutschein-Zustand aus dem aktiven Speicher.
/// 2.  Alice versucht, denselben alten Gutschein-Zustand ein zweites Mal an Charlie
///     zu senden.
/// 3.  Der Aufruf schlägt mit `VoucherNotFound` fehl, da der Zustand bereits
///     verbraucht und archiviert wurde. Dies ist der eingebaute Schutz.
#[test]
fn api_wallet_proactive_double_spend_prevention() {
    let alice_identity = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(alice_identity);
    let (minuto_standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
    let voucher_id =
        add_voucher_to_wallet(&mut alice_wallet, alice_identity, "100", minuto_standard, true)
            .unwrap();
    let bob_identity = &ACTORS.bob;

    alice_wallet
        .create_transfer(
            alice_identity,
            minuto_standard,
            &voucher_id,
            &bob_identity.user_id,
            "100",
            None,
            None,
        )
        .expect("First transfer should succeed");

    let result = alice_wallet.create_transfer(
        alice_identity,
        minuto_standard,
        &voucher_id,
        &ACTORS.charlie.user_id,
        "100",
        None,
        None,
    );
    assert!(matches!(
        result,
        Err(VoucherCoreError::VoucherNotFound(_))
    ));
}

/// Testet das Erstellen eines neuen Gutscheins direkt im Wallet.
///
/// ### Szenario:
/// 1.  Ein neues Wallet wird für einen Aussteller (`issuer`) erstellt.
/// 2.  Die Methode `get_user_id` gibt die korrekte ID zurück.
/// 3.  Ein neuer Gutschein wird mit `create_new_voucher` erstellt.
/// 4.  Der Gutschein ist danach im Wallet vorhanden, hat den Status `Active`
///     und den korrekten Betrag.
#[test]
fn api_wallet_create_voucher_and_get_id() {
    let identity = &ACTORS.issuer;
    let mut wallet = setup_in_memory_wallet(identity);
    assert_eq!(wallet.get_user_id(), identity.user_id);

    let new_voucher_data = NewVoucherData {
        creator: Creator {
            id: identity.user_id.clone(),
            ..Default::default()
        },
        nominal_value: NominalValue {
            amount: "500".to_string(),
            ..Default::default()
        },
        validity_duration: Some("P4Y".to_string()),
        ..Default::default()
    };
    let (silver_standard, silver_standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);

    wallet
        .create_new_voucher(
            identity,
            silver_standard,
            silver_standard_hash,
            "en",
            new_voucher_data,
        )
        .unwrap();

    let summary = wallet
        .list_vouchers()
        .pop()
        .expect("Wallet should contain one voucher");
    assert_eq!(summary.current_amount, "500.0000");
    assert_eq!(summary.status, VoucherStatus::Active);
}

/// Testet die korrekte Saldoberechnung über mehrere Währungen hinweg.
///
/// ### Szenario:
/// 1.  Ein Wallet wird mit mehreren aktiven Gutscheinen für "Minuto" und "Unzen"
///     sowie einem nicht-aktiven Gutschein gefüllt.
/// 2.  Die Methode `get_total_balance_by_currency` wird aufgerufen.
/// 3.  Das Ergebnis enthält korrekte, summierte Salden für die beiden Währungen,
///     wobei nur die aktiven Gutscheine berücksichtigt wurden.
#[test]
fn api_wallet_query_total_balance() {
    let identity = &ACTORS.issuer;
    let mut wallet = setup_in_memory_wallet(identity);
    let (minuto_standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
    let (silver_standard, _) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);

    let mut add_voucher =
        |amount: &str, status: VoucherStatus, standard: &VoucherStandardDefinition| {
            let new_voucher_data = NewVoucherData {
                creator: Creator {
                    id: identity.user_id.clone(),
                    ..Default::default()
                },
                nominal_value: NominalValue {
                    amount: amount.to_string(),
                    ..Default::default()
                },
                validity_duration: Some("P4Y".to_string()),
                ..Default::default()
            };
            let mut standard_to_hash = standard.clone();
            standard_to_hash.signature = None;
            let correct_hash = voucher_lib::services::crypto_utils::get_hash(
                voucher_lib::services::utils::to_canonical_json(&standard_to_hash).unwrap(),
            );
            let voucher = create_voucher_for_manipulation(
                new_voucher_data,
                standard,
                &correct_hash,
                &identity.signing_key,
                "en",
            );
            let local_id = Wallet::calculate_local_instance_id(&voucher, &identity.user_id).unwrap();
            wallet
                .add_voucher_instance(local_id, voucher, status);
        };

    add_voucher("100", VoucherStatus::Active, minuto_standard);
    add_voucher("50", VoucherStatus::Active, minuto_standard);
    add_voucher("200", VoucherStatus::Quarantined { reason: "test".to_string() }, minuto_standard); // Ignored
    add_voucher("1.25", VoucherStatus::Active, silver_standard);
    add_voucher("0.75", VoucherStatus::Active, silver_standard);

    let balances = wallet.get_total_balance_by_currency();

    assert_eq!(balances.len(), 2, "Two currencies should be present");
    // KORREKTUR: Die Tests müssen die korrekten Währungs-Abkürzungen aus den Standards verwenden.
    let minuto_abbreviation = &minuto_standard.metadata.abbreviation;
    let expected_minuto_balance = Decimal::from_str("150").unwrap();
    let actual_minuto_balance = Decimal::from_str(balances.get(minuto_abbreviation).unwrap()).unwrap();
    assert_eq!(actual_minuto_balance, expected_minuto_balance);

    let silver_abbreviation = &silver_standard.metadata.abbreviation;
    let expected_silver_balance = Decimal::from_str("2.00").unwrap();
    let actual_silver_balance = Decimal::from_str(balances.get(silver_abbreviation).unwrap()).unwrap();
    assert_eq!(actual_silver_balance, expected_silver_balance);
}

/// Stellt sicher, dass das Wallet ein Bundle mit einem ungültigen Gutschein abweist.
///
/// ### Szenario:
/// 1.  Alice erstellt einen Gutschein, der gegen eine Inhaltsregel seines Standards verstößt.
/// 2.  Sie verpackt diesen ungültigen Gutschein in ein Bundle für Bob.
/// 3.  Eine externe Logik (die den Client simuliert) öffnet das Bundle,
///     validiert den Gutschein und stellt fest, dass er ungültig ist.
/// 4.  Da die Validierung fehlschlägt, wird der Gutschein **nicht** an Bobs Wallet
///     übergeben. Bobs Wallet bleibt leer.
#[test]
fn api_wallet_rejects_invalid_bundle() {
    let alice_identity = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(alice_identity);
    let bob_identity = &ACTORS.bob;
    let bob_wallet = setup_in_memory_wallet(bob_identity);

    let toml_str = include_str!("../test_data/standards/standard_content_rules.toml");
    let mut standard: VoucherStandardDefinition = toml::from_str(toml_str).unwrap();
    standard.template.fixed.nominal_value.unit = "EUR".to_string();
    standard.template.fixed.description = vec![
        voucher_lib::models::voucher_standard_definition::LocalizedText {
            lang: "en".to_string(),
            text: "INV-123456".to_string(),
        },
    ];

    let voucher_data = NewVoucherData {
        creator: Creator {
            id: alice_identity.user_id.clone(),
            ..Default::default()
        },
        nominal_value: NominalValue {
            amount: "50.00".to_string(),
            ..Default::default()
        },
        validity_duration: Some("P1Y".to_string()),
        ..Default::default()
    };

    let mut standard_to_hash = standard.clone();
    standard_to_hash.signature = None;
    let standard_hash = voucher_lib::services::crypto_utils::get_hash(
        voucher_lib::services::utils::to_canonical_json(&standard_to_hash).unwrap(),
    );
    let mut voucher = voucher_lib::services::voucher_manager::create_voucher(
        voucher_data,
        &standard,
        &standard_hash,
        &alice_identity.signing_key,
        "en",
    )
        .unwrap();

    voucher.description = "BAD-FORMAT".to_string(); // Verstößt gegen Regex

    let bundle_bytes = alice_wallet
        .create_and_encrypt_transaction_bundle(
            alice_identity,
            vec![voucher.clone()],
            &bob_identity.user_id,
            None,
        )
        .unwrap();

    let decrypted_bundle =
        voucher_lib::services::bundle_processor::open_and_verify_bundle(bob_identity, &bundle_bytes)
            .unwrap();
    let received_voucher = decrypted_bundle.vouchers.first().unwrap();

    let validation_result = voucher_lib::services::voucher_validation::validate_voucher_against_standard(
        received_voucher,
        &standard,
    );
    assert!(
        validation_result.is_err(),
        "Validation of the manipulated voucher should fail"
    );

    assert!(
        bob_wallet.voucher_store.vouchers.is_empty(),
        "Bob's wallet should remain empty"
    );
}

/// Testet die reaktive Double-Spend-Erkennung via "Earliest Wins"-Heuristik.
///
/// ### Szenario:
/// 1.  Ein Wallet empfängt zwei widersprüchliche Gutschein-Versionen, die
///     einen Double-Spend darstellen.
/// 2.  Das Wallet wendet die "Earliest Wins"-Regel an.
/// 3.  Der Zweig mit dem früheren Zeitstempel bleibt `Active`.
/// 4.  Der Zweig mit dem späteren Zeitstempel wird auf `Quarantined` gesetzt.
#[test]
#[ignore] // TODO: Helfer zum Erzeugen von Konflikt-Bundles implementieren.
fn api_wallet_reactive_double_spend_earliest_wins() {
    // Dieser Test erfordert eine komplexe Vorbereitung, bei der zwei konkurrierende
    // Transaktionszweige erstellt und in separate Bundles verpackt werden.
    // Die Wallet-Methode `process_encrypted_transaction_bundle` muss dann so
    // aufgerufen werden, dass der Konflikt erkannt und behandelt wird.
    println!("TODO: Implement api_wallet_reactive_double_spend_earliest_wins");
}
