//! # tests/test_app_service.rs
//!
//! Integrationstest für die `AppService`-Fassade.
//! Dieser Test simuliert einen vollständigen End-to-End-Benutzer-Workflow
//! und einen Signatur-Roundtrip, inspiriert von `test_wallet_integration.rs`.

use tempfile::tempdir;
use voucher_lib::app_service::AppService;
use voucher_lib::models::profile::VoucherStatus;
use voucher_lib::models::voucher::{Creator, NominalValue};
use voucher_lib::services::voucher_manager::NewVoucherData;

// Die `test_utils` werden für Helferfunktionen wie `load_standard_definition` benötigt.
mod test_utils;
use test_utils::{
    create_guarantor_signature_data, debug_open_container, generate_valid_mnemonic,
    load_standard_definition,
};

/// Testet den vollständigen Lebenszyklus von Profilerstellung, Login,
/// Voucher-Erstellung und Transfer zwischen zwei Benutzern.
#[test]
fn test_app_service_full_lifecycle() {
    // --- 1. Setup ---
    let standard =
        load_standard_definition("silver_standard.toml").expect("Failed to load standard");
    let dir_alice = tempdir().expect("Failed to create temp dir for Alice");
    let dir_bob = tempdir().expect("Failed to create temp dir for Bob");

    // Mnemonics werden nun dynamisch mit dem neuen Helfer generiert.
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
    assert!(id_alice.starts_with("alice@did:key:"));
    assert!(id_bob.starts_with("bob@did:key:"));

    // --- 3. Logout und Login für Alice ---
    service_alice.logout();
    assert!(
        service_alice.get_user_id().is_err(),
        "Service should be locked after logout"
    );
    assert!(
        service_alice.login("wrongpassword").is_err(),
        "Login with wrong password should fail"
    );
    service_alice
        .login(password)
        .expect("Login with correct password should succeed");
    assert_eq!(service_alice.get_user_id().unwrap(), id_alice);

    // --- 4. Alice erstellt einen Gutschein ---
    let voucher_data = NewVoucherData {
        nominal_value: NominalValue {
            amount: "100".to_string(),
            ..Default::default()
        },
        creator: Creator {
            id: id_alice.clone(),
            ..Default::default()
        },
        ..Default::default()
    };
    service_alice
        .create_new_voucher(&standard, voucher_data, password)
        .expect("Voucher creation failed");

    let balance_alice = service_alice.get_total_balance_by_currency().unwrap();
    assert_eq!(balance_alice.get("Unzen").unwrap(), "100.0000");
    let summaries_alice = service_alice.get_voucher_summaries().unwrap();
    let local_id_alice = summaries_alice[0].local_instance_id.clone();

    // --- 5. Alice sendet den Gutschein an Bob ---
    let transfer_bundle = service_alice
        .create_transfer_bundle(
            &standard,
            &local_id_alice,
            &id_bob,
            "100",
            Some("Für dich, Bob!".to_string()),
            None,
            password,
        )
        .expect("Transfer failed");

    let summary = service_alice
        .get_voucher_details(&local_id_alice)
        .expect_err("Old voucher ID should not resolve to an active voucher anymore");
    // Mache den Assert robuster: Prüfe nur, ob "not found" im Fehlertext vorkommt,
    // unabhängig von Groß-/Kleinschreibung oder exaktem Wortlaut.
    assert!(summary.to_lowercase().contains("not found"));

    // --- 6. Bob empfängt den Gutschein ---
    service_bob
        .receive_bundle(&transfer_bundle, None, password)
        .expect("Receive failed");

    let balance_bob = service_bob.get_total_balance_by_currency().unwrap();
    assert_eq!(balance_bob.get("Unzen").unwrap(), "100.0000");
    assert_eq!(service_bob.get_voucher_summaries().unwrap()[0].status, VoucherStatus::Active);
}

/// Testet die statischen Mnemonic-Hilfsfunktionen des AppService.
#[test]
fn test_app_service_mnemonic_helpers() {
    // --- 1. Test der Generierung ---
    // Erfolgreiche Generierung mit gültiger Wortanzahl
    let mnemonic_result = AppService::generate_mnemonic(12);
    assert!(mnemonic_result.is_ok(), "Should generate a 12-word mnemonic");
    let mnemonic = mnemonic_result.unwrap();
    assert_eq!(mnemonic.split_whitespace().count(), 12, "Mnemonic should have 12 words");

    // Fehlgeschlagene Generierung mit ungültiger Wortanzahl
    let invalid_result = AppService::generate_mnemonic(11);
    assert!(invalid_result.is_err(), "Should fail with invalid word count");

    // --- 2. Test der Validierung ---
    // Erfolgreiche Validierung einer frisch generierten Mnemonic
    let validation_result = AppService::validate_mnemonic(&mnemonic);
    assert!(validation_result.is_ok(), "A freshly generated mnemonic should be valid");

    // Fehlgeschlagene Validierung mit ungültigem Wort
    let invalid_word_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon hello";
    assert!(AppService::validate_mnemonic(invalid_word_mnemonic).is_err(), "Should fail with an invalid word");

    // Fehlgeschlagene Validierung mit schlechter Prüfsumme
    let bad_checksum_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    assert!(AppService::validate_mnemonic(bad_checksum_mnemonic).is_err(), "Should fail with a bad checksum");
}
/// Testet den Signatur-Workflow über die AppService-Fassade.
#[test]
fn test_app_service_signature_roundtrip() {
    let standard =
        load_standard_definition("minuto_standard.toml").expect("Failed to load standard");
    let dir_creator = tempdir().unwrap();
    let dir_guarantor = tempdir().unwrap();
    let password = "sig-password";

    let mnemonic_creator = generate_valid_mnemonic();
    let mnemonic_guarantor = generate_valid_mnemonic();

    // Setup Creator
    let mut service_creator = AppService::new(dir_creator.path()).unwrap();
    service_creator
        .create_profile(&mnemonic_creator, Some("creator"), password)
        .unwrap();

    // Setup Guarantor
    let mut service_guarantor = AppService::new(dir_guarantor.path()).unwrap();
    service_guarantor
        .create_profile(&mnemonic_guarantor, Some("guarantor"), password)
        .unwrap();
    let id_guarantor = service_guarantor.get_user_id().unwrap();

    let voucher = service_creator
        .create_new_voucher(
            &standard,
            NewVoucherData {
                nominal_value: NominalValue {
                    amount: "50".to_string(),
                    ..Default::default()
                },
                creator: Creator { id: service_creator.get_user_id().unwrap(), ..Default::default() },
                ..Default::default()
            },
            password,
        )
        .unwrap();
    let local_id = service_creator.get_voucher_summaries().unwrap()[0].local_instance_id.clone();
    assert!(voucher.guarantor_signatures.is_empty());

    // 1. Creator erstellt eine Signaturanfrage
    let request_bytes = service_creator
        .create_signing_request_bundle(&local_id, &id_guarantor)
        .unwrap();

    // 2. Guarantor empfängt, signiert und antwortet
    let (voucher_to_sign, sender_id) = {
        service_guarantor.login(password).unwrap();
        let guarantor_identity = service_guarantor.get_unlocked_mut_for_test().1;
        debug_open_container(&request_bytes, guarantor_identity).unwrap()
    };

    let signature_data =
        create_guarantor_signature_data(service_guarantor.get_unlocked_mut_for_test().1, "1", &voucher_to_sign.voucher_id);

    let response_bytes = service_guarantor
        .create_detached_signature_response_bundle(&voucher_to_sign, signature_data, &sender_id)
        .unwrap();

    // 3. Creator empfängt die Signatur
    service_creator
        .process_and_attach_signature(&response_bytes, password)
        .unwrap();

    let details = service_creator.get_voucher_details(&local_id).unwrap();
    assert_eq!(details.voucher.guarantor_signatures.len(), 1);
    assert_eq!(details.voucher.guarantor_signatures[0].guarantor_id, id_guarantor);
}

/// Testet die Passwort-Wiederherstellungsfunktion des AppService.
///
/// Dieses Szenario deckt ab:
/// 1. Fehlschlag bei Verwendung einer falschen Mnemonic-Phrase.
/// 2. Erfolg bei Verwendung der korrekten Mnemonic-Phrase.
/// 3. Verifizierung, dass das alte Passwort ungültig und das neue Passwort gültig ist.
#[test]
fn test_app_service_password_recovery() {
    // 1. Setup
    let dir = tempdir().expect("Failed to create temp dir");
    let mut service = AppService::new(dir.path()).expect("Failed to create service");
    // Verwende eine statische, bekannte Mnemonic, um die Test-Utils als Fehlerquelle auszuschließen.
    let mnemonic =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let initial_password = "password-123";
    let new_password = "password-ABC";

    // Erstelle ein Profil und sperre es sofort wieder.
    service
        .create_profile(&mnemonic, Some("recovery-test"), initial_password)
        .expect("Profile creation failed");
    service.logout();
    assert!(
        service.get_user_id().is_err(),
        "Service should be locked initially"
    );

    // 2. Testfall: Fehlgeschlagene Wiederherstellung (falsche Mnemonic)
    // Eine Mnemonic mit einer falschen Prüfsumme.
    let wrong_mnemonic =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    let recovery_result_fail =
        service.recover_wallet_and_set_new_password(&wrong_mnemonic, new_password);
    assert!(
        recovery_result_fail.is_err(),
        "Recovery with wrong mnemonic should fail"
    );
    assert!(
        service.get_user_id().is_err(),
        "Service should remain locked after failed recovery"
    );

    // 3. Testfall: Erfolgreiche Wiederherstellung
    let recovery_result_ok = service.recover_wallet_and_set_new_password(&mnemonic, new_password);
    assert!(
        recovery_result_ok.is_ok(),
        "Recovery with correct mnemonic should succeed"
    );
    assert!(
        service.get_user_id().is_ok(),
        "Service should be unlocked after successful recovery"
    );

    // Erneut sperren, um den Login zu testen.
    service.logout();

    // 4. Verifizierung
    assert!(
        service.login(initial_password).is_err(),
        "Login with old password should fail after recovery"
    );
    assert!(
        service.login(new_password).is_ok(),
        "Login with new password should succeed after recovery"
    );
}