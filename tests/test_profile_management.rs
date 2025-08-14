//! tests/test_profile_management.rs
//!
//! Enthält Integrationstests für das refaktorierte Profil- und VoucherStore-Management.
use bip39::Language;
use voucher_lib::error::VoucherCoreError;
use voucher_lib::models::profile::{UserIdentity, UserProfile, VoucherStore};
use voucher_lib::models::voucher::{Collateral, Creator, NominalValue};
use voucher_lib::models::voucher_standard_definition::VoucherStandardDefinition;
use voucher_lib::services::{
    crypto_utils,
    profile_manager,
    voucher_manager,
};
use tempfile::tempdir;

/// Hilfsfunktion, um eine Standard-Definition aus dem TOML-String zu laden.
fn load_test_standard() -> VoucherStandardDefinition {
    let toml_str = include_str!("../voucher_standards/minuto_standard.toml");
    voucher_manager::load_standard_definition(toml_str).expect("Failed to load standard definition")
}

/// Hilfsfunktion, um eine neue, zufällige Test-Identität zu erstellen.
/// Generiert bei jedem Aufruf eine neue Mnemonic-Phrase.
fn create_new_random_identity(prefix: &str) -> (UserProfile, VoucherStore, UserIdentity) {
    let mnemonic = crypto_utils::generate_mnemonic(12, Language::English).unwrap();
    profile_manager::create_profile_from_mnemonic(&mnemonic, Some(prefix))
        .expect("Failed to create profile")
}

#[test]
fn test_profile_creation_save_and_load() {
    // 1. Setup
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let password = "strongpassword123";
    let (profile, store, _identity) = create_new_random_identity("al");

    assert!(profile.bundle_history.is_empty(), "Initial history should be empty");
    assert!(store.vouchers.is_empty(), "Initial store should be empty");

    // 2. Speichern
    profile_manager::save_profile_and_store_encrypted(&profile, &store, temp_dir.path(), password)
        .expect("Failed to save profile and store");

    // Überprüfen, ob beide Dateien erstellt wurden
    assert!(temp_dir.path().join("profile.enc").exists());
    assert!(temp_dir.path().join("vouchers.enc").exists());

    // 3. Laden
    let (loaded_profile, loaded_store) =
        profile_manager::load_profile_and_store_encrypted(temp_dir.path(), password)
            .expect("Failed to load profile and store");

    // 4. Verifizieren
    assert_eq!(profile.user_id, loaded_profile.user_id);
    assert!(loaded_profile.bundle_history.is_empty());
    assert!(loaded_store.vouchers.is_empty());

    // 5. Fehlerfall: Falsches Passwort
    let result = profile_manager::load_profile_and_store_encrypted(temp_dir.path(), "wrongpassword");
    assert!(matches!(result, Err(VoucherCoreError::SymmetricEncryption(_))));
}

#[test]
fn test_add_voucher_and_transaction_flow() {
    // 1. Setup: Zwei User (Alice und Bob) und eine Standard-Definition
    let _temp_dir_alice = tempdir().unwrap();
    let temp_dir_bob = tempdir().unwrap();
    let password = "password123";

    let (mut alice_profile, mut alice_store, alice_identity) = create_new_random_identity("al");
    let (mut bob_profile, mut bob_store, bob_identity) = create_new_random_identity("bo");

    let standard = load_test_standard();

    // 2. Alice erstellt einen Gutschein für sich selbst
    let new_voucher_data = voucher_manager::NewVoucherData {
        validity_duration: None, // Standardwert aus TOML verwenden
        non_redeemable_test_voucher: false,
        nominal_value: NominalValue {
            unit: "".to_string(), // Wird vom Standard überschrieben
            amount: "100".to_string(),
            abbreviation: "".to_string(), // Wird vom Standard überschrieben
            description: "Test description".to_string(),
        },
        collateral: Collateral { // Dummy-Werte, da Minuto keine Besicherung hat
            type_: "".to_string(), unit: "".to_string(), amount: "".to_string(),
            abbreviation: "".to_string(), description: "".to_string(), redeem_condition: "".to_string(),
        },
        creator: Creator { // Dummy-Daten für den Creator
            id: alice_identity.user_id.clone(),
            first_name: "Alice".to_string(), last_name: "Wonderland".to_string(),
            address: Default::default(), organization: None, community: None, phone: None,
            email: None, url: None, gender: "2".to_string(), service_offer: None,
            needs: None, signature: "".to_string(), coordinates: "0,0".to_string(),
        },
    };
    let voucher = voucher_manager::create_voucher(new_voucher_data, &standard, &alice_identity.signing_key)
        .expect("Voucher creation failed");

    // 3. Gutschein zu Alice' Store hinzufügen
    profile_manager::add_voucher_to_store(&mut alice_store, voucher.clone(), &alice_identity.user_id)
        .expect("Failed to add voucher to store");

    assert_eq!(alice_store.vouchers.len(), 1);

    // 4. Alice erstellt eine Transaktion, um den Gutschein an Bob zu senden.
    // Dies erzeugt eine neue Version des Gutscheins mit der zusätzlichen Transaktion.
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
        &mut alice_store, // Dieser Parameter wurde für das Refactoring hinzugefügt
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

    // 7. Persistenz überprüfen
    profile_manager::save_profile_and_store_encrypted(&bob_profile, &bob_store, temp_dir_bob.path(), password).unwrap();
    let (_loaded_bob_profile, loaded_bob_store) = profile_manager::load_profile_and_store_encrypted(temp_dir_bob.path(), password).unwrap();
    assert_eq!(loaded_bob_store.vouchers.len(), 1, "Loaded Bob's store should still contain the voucher");
}