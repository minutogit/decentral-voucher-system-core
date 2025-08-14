//! tests/test_profile_management.rs
//!
//! Enthält Integrationstests für das refaktorierte Profil- und VoucherStore-Management,
//! inklusive der Passwort-Wiederherstellungslogik und Randbedingungen.

use bip39::Language;
use voucher_lib::error::VoucherCoreError;
use voucher_lib::models::profile::{UserIdentity, UserProfile, VoucherStore};
use voucher_lib::models::voucher::{Collateral, Creator, NominalValue, Voucher};
use voucher_lib::models::voucher_standard_definition::VoucherStandardDefinition;
use voucher_lib::services::{
    crypto_utils,
    profile_manager::{self, ProfileManagerError},
    voucher_manager,
};
use std::fs;
use tempfile::tempdir;

/// Hilfsfunktion, um eine Standard-Definition aus dem TOML-String zu laden.
fn load_test_standard() -> VoucherStandardDefinition {
    let toml_str = include_str!("../voucher_standards/minuto_standard.toml");
    voucher_manager::load_standard_definition(toml_str).expect("Failed to load standard definition")
}

/// Hilfsfunktion, um eine neue, zufällige Test-Identität zu erstellen.
fn create_new_random_identity(prefix: &str) -> (UserProfile, VoucherStore, UserIdentity) {
    let mnemonic = crypto_utils::generate_mnemonic(12, Language::English).unwrap();
    profile_manager::create_profile_from_mnemonic(&mnemonic, Some(prefix))
        .expect("Failed to create profile")
}

/// Hilfsfunktion, um einen einfachen Test-Gutschein zu erstellen.
fn create_test_voucher(identity: &UserIdentity, standard: &VoucherStandardDefinition) -> Voucher {
    let new_voucher_data = voucher_manager::NewVoucherData {
        validity_duration: None,
        non_redeemable_test_voucher: false,
        nominal_value: NominalValue {
            unit: "".to_string(),
            amount: "100".to_string(),
            abbreviation: "".to_string(),
            description: "Test description".to_string(),
        },
        collateral: Collateral {
            type_: "".to_string(),
            unit: "".to_string(),
            amount: "".to_string(),
            abbreviation: "".to_string(),
            description: "".to_string(),
            redeem_condition: "".to_string(),
        },
        creator: Creator { // Manuell alle benötigten Felder initialisieren
            id: identity.user_id.clone(),
            first_name: "Test".to_string(),
            last_name: "User".to_string(),
            address: Default::default(), // Address implementiert Default
            organization: None,
            community: None,
            phone: None,
            email: None,
            url: None,
            gender: "9".to_string(), // 9 = Not applicable
            service_offer: None,
            needs: None,
            signature: "".to_string(), // Wird von create_voucher ausgefüllt
            coordinates: "0,0".to_string(),
        },
    };
    voucher_manager::create_voucher(new_voucher_data, standard, &identity.signing_key)
        .expect("Voucher creation failed")
}

#[test]
fn test_profile_creation_save_and_load() {
    // 1. Setup
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let password = "strongpassword123";
    let (profile, store, identity) = create_new_random_identity("al");

    // 2. Speichern
    profile_manager::save_profile_and_store_encrypted(&profile, &store, temp_dir.path(), password, &identity)
        .expect("Failed to save profile and store");

    // 3. Laden und Verifizieren
    let (loaded_profile, loaded_store) =
        profile_manager::load_profile_and_store_encrypted(temp_dir.path(), password)
            .expect("Failed to load profile and store");
    assert_eq!(profile.user_id, loaded_profile.user_id);
    assert!(loaded_store.vouchers.is_empty());

    // 4. Fehlerfall: Falsches Passwort
    let result = profile_manager::load_profile_and_store_encrypted(temp_dir.path(), "wrongpassword");
    assert!(matches!(result, Err(VoucherCoreError::Profile(ProfileManagerError::AuthenticationFailed))));
}

#[test]
fn test_password_recovery_and_reset_with_data() {
    // 1. Setup: Erstelle ein Profil mit einem Gutschein.
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let initial_password = "my-secret-password";
    let (profile, mut store, identity) = create_new_random_identity("re");
    let standard = load_test_standard();
    let voucher = create_test_voucher(&identity, &standard);
    let voucher_id = voucher.voucher_id.clone();

    profile_manager::add_voucher_to_store(&mut store, voucher, &identity.user_id)
        .expect("Failed to add voucher");
    assert_eq!(store.vouchers.len(), 1);

    profile_manager::save_profile_and_store_encrypted(&profile, &store, temp_dir.path(), initial_password, &identity)
        .expect("Initial save failed");

    // 2. Wiederherstellung mit der Mnemonic-Phrase (Identität).
    let (recovered_profile, recovered_store) =
        profile_manager::load_profile_for_recovery(temp_dir.path(), &identity)
            .expect("Recovery with correct identity should succeed");

    // Überprüfe, ob die wiederhergestellten Daten (inkl. Gutschein) korrekt sind.
    assert_eq!(profile.user_id, recovered_profile.user_id);
    assert_eq!(recovered_store.vouchers.len(), 1, "Voucher should be present after recovery");
    assert!(recovered_store.vouchers.values().any(|v| v.voucher_id == voucher_id));

    // 3. Passwort zurücksetzen.
    let new_password = "my-new-strong-password-456";
    profile_manager::reset_password(temp_dir.path(), &identity, new_password)
        .expect("Password reset should succeed");

    // 4. Verifizierung nach dem Reset.
    // Login mit altem Passwort muss fehlschlagen.
    assert!(matches!(
        profile_manager::load_profile_and_store_encrypted(temp_dir.path(), initial_password),
        Err(VoucherCoreError::Profile(ProfileManagerError::AuthenticationFailed))
    ));

    // Login mit neuem Passwort muss erfolgreich sein und die Daten müssen intakt sein.
    let (final_profile, final_store) =
        profile_manager::load_profile_and_store_encrypted(temp_dir.path(), new_password)
            .expect("Login with new password should succeed");

    assert_eq!(profile.user_id, final_profile.user_id);
    assert_eq!(final_store.vouchers.len(), 1, "Voucher should still be present after reset");
    assert!(final_store.vouchers.values().any(|v| v.voucher_id == voucher_id));

    // 5. Fehlerfall: Wiederherstellung mit der falschen Identität.
    let (_imposter_profile, _imposter_store, imposter_identity) = create_new_random_identity("im");
    assert!(matches!(
        profile_manager::load_profile_for_recovery(temp_dir.path(), &imposter_identity),
        Err(VoucherCoreError::Profile(ProfileManagerError::AuthenticationFailed))
    ));
}

#[test]
fn test_load_with_missing_voucher_store() {
    let temp_dir = tempdir().unwrap();
    let password = "password123";
    let (profile, store, identity) = create_new_random_identity("ms");
    profile_manager::save_profile_and_store_encrypted(&profile, &store, temp_dir.path(), password, &identity).unwrap();

    // Lösche die Gutschein-Datei
    fs::remove_file(temp_dir.path().join("vouchers.enc")).unwrap();

    // Das Laden sollte trotzdem erfolgreich sein und einen leeren Store zurückgeben
    let (loaded_profile, loaded_store) =
        profile_manager::load_profile_and_store_encrypted(temp_dir.path(), password)
            .expect("Loading with missing voucher store should succeed");

    assert_eq!(profile.user_id, loaded_profile.user_id);
    assert!(loaded_store.vouchers.is_empty(), "Voucher store should be empty by default");
}

#[test]
fn test_load_from_corrupted_profile_file() {
    let temp_dir = tempdir().unwrap();
    let password = "password123";
    let (profile, store, identity) = create_new_random_identity("cr");
    profile_manager::save_profile_and_store_encrypted(&profile, &store, temp_dir.path(), password, &identity).unwrap();

    // Beschädige die Profil-Datei
    let profile_path = temp_dir.path().join("profile.enc");
    let mut contents = fs::read(&profile_path).unwrap();
    contents.truncate(contents.len() / 2); // Schneide die Hälfte ab
    fs::write(&profile_path, contents).unwrap();

    // Das Laden sollte mit einem Deserialisierungs- oder Formatfehler fehlschlagen
    let result = profile_manager::load_profile_and_store_encrypted(temp_dir.path(), password);
    assert!(matches!(result, Err(VoucherCoreError::Json(_))), "Expected a JSON parsing error");
}

#[test]
fn test_empty_password_handling() {
    let temp_dir = tempdir().unwrap();
    let empty_password = "";
    let (profile, store, identity) = create_new_random_identity("ep");

    // Speichern mit leerem Passwort sollte funktionieren
    profile_manager::save_profile_and_store_encrypted(&profile, &store, temp_dir.path(), empty_password, &identity)
        .expect("Saving with empty password should succeed");

    // Laden mit leerem Passwort sollte funktionieren
    let (loaded_profile, _) =
        profile_manager::load_profile_and_store_encrypted(temp_dir.path(), empty_password)
            .expect("Loading with empty password should succeed");
    assert_eq!(profile.user_id, loaded_profile.user_id);

    // Laden mit einem falschen, nicht-leeren Passwort sollte fehlschlagen
    let result = profile_manager::load_profile_and_store_encrypted(temp_dir.path(), "a-real-password");
    assert!(matches!(
        result,
        Err(VoucherCoreError::Profile(ProfileManagerError::AuthenticationFailed))
    ));
}

#[test]
fn test_add_voucher_and_transaction_flow() {
    // 1. Setup: Zwei User (Alice und Bob) und eine Standard-Definition
    let temp_dir_alice = tempdir().unwrap();
    let password_alice = "password_alice";

    let (mut alice_profile, mut alice_store, alice_identity) = create_new_random_identity("al");
    let (mut bob_profile, mut bob_store, bob_identity) = create_new_random_identity("bo");

    let standard = load_test_standard();
    let voucher = create_test_voucher(&alice_identity, &standard);

    // 3. Gutschein zu Alice' Store hinzufügen und speichern
    profile_manager::add_voucher_to_store(&mut alice_store, voucher.clone(), &alice_identity.user_id)
        .expect("Failed to add voucher to store");
    assert_eq!(alice_store.vouchers.len(), 1);

    profile_manager::save_profile_and_store_encrypted(&alice_profile, &alice_store, temp_dir_alice.path(), password_alice, &alice_identity).unwrap();

    // 4. Alice erstellt eine Transaktion, um den Gutschein an Bob zu senden.
    let voucher_for_bob = voucher_manager::create_split_transaction(
        &voucher,
        &standard,
        &alice_identity.user_id,
        &alice_identity.signing_key,
        &bob_identity.user_id,
        &voucher.nominal_value.amount, // Voller Betrag
    ).expect("Failed to create split transaction for Bob");

    // 5. Alice sendet den NEUEN Gutschein an Bob
    let container_bytes = profile_manager::create_and_encrypt_transaction_bundle(
        &mut alice_profile,
        &mut alice_store,
        &alice_identity,
        vec![voucher_for_bob],
        &bob_identity.user_id,
        Some("Here is your voucher!".to_string()),
    ).expect("Failed to create transaction bundle");

    assert_eq!(alice_store.vouchers.len(), 0, "Alice's store should be empty after sending");
    assert_eq!(alice_profile.bundle_history.len(), 1, "Alice should have 1 entry in her history");

    // 6. Bob empfängt das Bündel
    profile_manager::process_encrypted_transaction_bundle(
        &mut bob_profile,
        &mut bob_store,
        &bob_identity,
        &container_bytes,
    ).expect("Failed to process transaction bundle");

    assert_eq!(bob_store.vouchers.len(), 1, "Bob's store should now have 1 voucher");
    assert_eq!(bob_profile.bundle_history.len(), 1, "Bob should have 1 entry in his history");
}