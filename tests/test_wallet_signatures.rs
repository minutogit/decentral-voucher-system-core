//! # tests/test_wallet_signatures.rs
//!
//! Integrationstests für den vollständigen Signatur-Workflow, der über die
//! `Wallet`-Fassade gesteuert wird.

use voucher_lib::{
    self,
    VoucherCoreError,
    models::{
        profile::{UserIdentity, VoucherStatus},
        secure_container::PayloadType,
        signature::DetachedSignature,
        voucher::{GuarantorSignature, Voucher},
    },
    services::{
        secure_container_manager::{self, ContainerManagerError},
        voucher_manager::{self},
        voucher_validation,
    },
    Wallet,
};
use bip39::Language;
use std::fs;
use std::path::PathBuf;
use tempfile::tempdir;

/// Eine Hilfsfunktion, die ein neues Wallet und eine UserIdentity für Tests erstellt.
fn setup_test_wallet(
    mnemonic_phrase: &str,
    prefix: &str,
) -> (Wallet, UserIdentity) {
    Wallet::new_from_mnemonic(mnemonic_phrase, Some(prefix)).unwrap()
}

/// Eine Hilfsfunktion, um eine gültige Mnemonic-Phrase als String zu erzeugen.
fn generate_mnemonic_str() -> String {
    voucher_lib::services::crypto_utils::generate_mnemonic(12, Language::English).unwrap()
}

/// Eine Hilfsfunktion, die einen Standard-Gutschein für Alice erstellt und in ihr Wallet legt.
fn setup_voucher_for_alice(
    alice_wallet: &mut Wallet,
    alice_identity: &UserIdentity,
    standard_toml: &str,
) -> (Voucher, voucher_lib::VoucherStandardDefinition, String) {
    let standard = voucher_manager::load_standard_definition(standard_toml).unwrap();
    let creator_data = voucher_lib::Creator {
        id: alice_identity.user_id.clone(),
        first_name: "Alice".to_string(),
        last_name: "Wonderland".to_string(),
        ..Default::default()
    };
    let voucher_data = voucher_lib::NewVoucherData {
        validity_duration: Some("P3Y".to_string()),
        non_redeemable_test_voucher: true,
        nominal_value: voucher_lib::NominalValue {
            amount: "60".to_string(), // Setze einen expliziten, gültigen Betrag
            ..Default::default()
        },
        collateral: Default::default(),
        creator: creator_data,
    };
    let voucher =
        voucher_manager::create_voucher(voucher_data, &standard, &alice_identity.signing_key)
            .unwrap();
    let local_id =
        Wallet::calculate_local_instance_id(&voucher, &alice_identity.user_id).unwrap();
    alice_wallet
        .voucher_store
        .vouchers
        .insert(local_id.clone(), (voucher.clone(), VoucherStatus::Active));
    (voucher, standard, local_id)
}

#[test]
fn test_full_signature_workflow_via_wallet() {
    // --- 1. SETUP ---
    let (mut alice_wallet, alice_identity) = setup_test_wallet(&generate_mnemonic_str(), "al");
    let (bob_wallet, bob_identity) = setup_test_wallet(&generate_mnemonic_str(), "bo");
    let temp_dir = tempdir().expect("Failed to create temporary directory");
    let standard_toml = std::fs::read_to_string("voucher_standards/minuto_standard.toml").unwrap();

    // --- 2. VOUCHER CREATION ---
    let (voucher, standard, local_id) =
        setup_voucher_for_alice(&mut alice_wallet, &alice_identity, &standard_toml);
    let voucher_id = voucher.voucher_id;

    // Erste Validierung: Muss fehlschlagen, da Bürgen fehlen.
    let (voucher_in_store, _) = alice_wallet.voucher_store.vouchers.get(&local_id).unwrap();
    assert!(voucher_validation::validate_voucher_against_standard(voucher_in_store, &standard)
        .is_err());

    // --- 3. SIGNING REQUEST (Alice -> Bob) ---
    let request_container_bytes = alice_wallet
        .create_signing_request(&alice_identity, &local_id, &bob_identity.user_id)
        .unwrap();
    let request_file_path: PathBuf = temp_dir.path().join("request_to_bob.secure");
    fs::write(&request_file_path, request_container_bytes).expect("Failed to write request file");

    // --- 4. PROCESS REQUEST & CREATE RESPONSE (Bob) ---
    let received_request_bytes = fs::read(&request_file_path).expect("Failed to read request file");
    let container: voucher_lib::models::secure_container::SecureContainer =
        serde_json::from_slice(&received_request_bytes).unwrap();
    let (decrypted_payload, payload_type) = secure_container_manager::open_secure_container(
        &container,
        &bob_identity,
    )
        .unwrap();
    assert_eq!(payload_type, PayloadType::VoucherForSigning);

    let voucher_from_alice: Voucher = serde_json::from_slice(&decrypted_payload).unwrap();
    assert_eq!(voucher_from_alice.voucher_id, voucher_id);

    let guarantor_metadata = GuarantorSignature {
        voucher_id: voucher_id.clone(),
        first_name: "Bob".to_string(),
        last_name: "Builder".to_string(),
        gender: "1".to_string(),
        ..Default::default()
    };
    let response_container_bytes = bob_wallet
        .create_detached_signature_response(
            &bob_identity,
            &voucher_from_alice,
            DetachedSignature::Guarantor(guarantor_metadata),
            &alice_identity.user_id,
        )
        .unwrap();
    let response_file_path: PathBuf = temp_dir.path().join("response_to_alice.secure");
    fs::write(&response_file_path, response_container_bytes).expect("Failed to write response file");

    // --- 5. PROCESS RESPONSE & ATTACH SIGNATURE (Alice) ---
    let received_response_bytes = fs::read(&response_file_path).expect("Failed to read response file");
    alice_wallet
        .process_and_attach_signature(&alice_identity, &received_response_bytes)
        .unwrap();

    // --- 6. FINAL VERIFICATION ---
    let (voucher_with_sig, _) = alice_wallet.voucher_store.vouchers.get(&local_id).unwrap();
    assert_eq!(voucher_with_sig.guarantor_signatures.len(), 1);
    assert_eq!(
        voucher_with_sig.guarantor_signatures[0].guarantor_id,
        bob_identity.user_id
    );
    assert!(
        matches!(voucher_validation::validate_voucher_against_standard(voucher_with_sig, &standard).unwrap_err(),
        VoucherCoreError::Validation(voucher_lib::services::voucher_validation::ValidationError::GuarantorRequirementsNotMet(_)))
    );

    println!("SUCCESS: Realistic signature workflow test completed.");
}

#[test]
fn test_workflow_fails_if_opened_by_wrong_recipient() {
    // 1. Setup: Alice, Bob (der eigentliche Empfänger) und Eve (die versucht abzufangen).
    let (mut alice_wallet, alice_identity) = setup_test_wallet(&generate_mnemonic_str(), "al");
    let (_, bob_identity) = setup_test_wallet(&generate_mnemonic_str(), "bo");
    let (_, eve_identity) = setup_test_wallet(&generate_mnemonic_str(), "ev");
    let standard_toml = std::fs::read_to_string("voucher_standards/minuto_standard.toml").unwrap();
    let (_, _, local_id) =
        setup_voucher_for_alice(&mut alice_wallet, &alice_identity, &standard_toml);

    // 2. Alice erstellt eine Signaturanfrage, die NUR für Bob bestimmt ist.
    let request_bytes = alice_wallet
        .create_signing_request(&alice_identity, &local_id, &bob_identity.user_id)
        .unwrap();

    // 3. Eve versucht, den Container zu öffnen.
    let container: voucher_lib::models::secure_container::SecureContainer =
        serde_json::from_slice(&request_bytes).unwrap();
    let result = secure_container_manager::open_secure_container(&container, &eve_identity);

    // 4. Verifizierung: Der Vorgang muss fehlschlagen, da Eve nicht die Empfängerin ist.
    assert!(matches!(
        result.unwrap_err(),
        VoucherCoreError::Container(ContainerManagerError::NotAnIntendedRecipient)
    ));
    println!("SUCCESS: Wrong recipient 'Eve' was correctly blocked from opening the container.");
}

#[test]
fn test_workflow_fails_with_tampered_container() {
    // 1. Setup: Alice und Bob.
    let (mut alice_wallet, alice_identity) = setup_test_wallet(&generate_mnemonic_str(), "al");
    let (bob_wallet, bob_identity) = setup_test_wallet(&generate_mnemonic_str(), "bo");
    let standard_toml = std::fs::read_to_string("voucher_standards/minuto_standard.toml").unwrap();
    let (voucher, _, _) =
        setup_voucher_for_alice(&mut alice_wallet, &alice_identity, &standard_toml);

    // 2. Alice sendet Anfrage, Bob erstellt eine GÜLTIGE Antwort.
    let guarantor_metadata = GuarantorSignature {
        voucher_id: voucher.voucher_id.clone(),
        ..Default::default()
    };
    let response_bytes = bob_wallet
        .create_detached_signature_response(
            &bob_identity,
            &voucher,
            DetachedSignature::Guarantor(guarantor_metadata),
            &alice_identity.user_id,
        )
        .unwrap();

    // 3. Manipulation: Ein Angreifer verändert ein Byte im verschlüsselten Payload.
    let mut container: voucher_lib::models::secure_container::SecureContainer =
        serde_json::from_slice(&response_bytes).unwrap();
    if !container.encrypted_payload.is_empty() {
        container.encrypted_payload[10] ^= 0xff; // Flip some bits
    }
    let tampered_bytes = serde_json::to_vec(&container).unwrap();

    // 4. Alice versucht, die manipulierte Antwort zu verarbeiten.
    let result =
        alice_wallet.process_and_attach_signature(&alice_identity, &tampered_bytes);

    // 5. Verifizierung: Die Verarbeitung muss aufgrund des Authentifizierungsfehlers bei der Entschlüsselung fehlschlagen.
    assert!(matches!(
        result.unwrap_err(),
        VoucherCoreError::SymmetricEncryption(_)
    ));
    println!("SUCCESS: Tampered container was correctly rejected.");
}

#[test]
fn test_workflow_fails_with_mismatched_voucher_id() {
    // 1. Setup: Alice erstellt zwei verschiedene Gutscheine (A und B).
    let (mut alice_wallet, alice_identity) = setup_test_wallet(&generate_mnemonic_str(), "al");
    let (bob_wallet, bob_identity) = setup_test_wallet(&generate_mnemonic_str(), "bo");
    let standard_toml = std::fs::read_to_string("voucher_standards/minuto_standard.toml").unwrap();
    let (_voucher_a, standard, _) =
        setup_voucher_for_alice(&mut alice_wallet, &alice_identity, &standard_toml);

    // Erstelle Gutschein B, aber füge ihn NICHT zu Alices Wallet hinzu.
    // So stellen wir sicher, dass er in ihrem Wallet nicht gefunden werden kann.
    let creator_data_b = voucher_lib::Creator {
        id: alice_identity.user_id.clone(), ..Default::default()
    };
    let voucher_data_b = voucher_lib::NewVoucherData {
        creator: creator_data_b,
        validity_duration: Some("P3Y".to_string()),
        nominal_value: voucher_lib::NominalValue {
            amount: "120".to_string(), // Setze einen expliziten, gültigen Betrag
            ..Default::default()
        },
        ..Default::default()
    };
    let voucher_b =
        voucher_manager::create_voucher(voucher_data_b, &standard, &alice_identity.signing_key).unwrap();

    // 2. Bob erhält (korrekt) Gutschein A zur Signierung, entscheidet sich aber, die ID von B in seine Signatur zu schreiben.
    let guarantor_metadata = GuarantorSignature {
        voucher_id: voucher_b.voucher_id.clone(), // Falsche ID!
        ..Default::default()
    };

    // 3. Bob erstellt die Antwort. Wir verwenden Gutschein B als Kontext, um die Signatur dafür zu erstellen.
    let response_bytes = bob_wallet
        .create_detached_signature_response(
            &bob_identity,
            &voucher_b,
            DetachedSignature::Guarantor(guarantor_metadata),
            &alice_identity.user_id,
        )
        .unwrap();

    // 4. Alice versucht, diese Signatur zu verarbeiten.
    let result =
        alice_wallet.process_and_attach_signature(&alice_identity, &response_bytes);

    // 5. Verifizierung: Der Prozess muss fehlschlagen, weil das Wallet den Gutschein B (auf den sich die Signatur bezieht) nicht kennt.
    assert!(matches!(result.unwrap_err(), VoucherCoreError::VoucherNotFound(_)));
    println!("SUCCESS: Signature with mismatched voucher ID was correctly rejected.");
}

#[test]
fn test_workflow_fails_with_wrong_payload_type() {
    // 1. Setup: Alice
    let (mut alice_wallet, alice_identity) = setup_test_wallet(&generate_mnemonic_str(), "al");
    let standard_toml = std::fs::read_to_string("voucher_standards/minuto_standard.toml").unwrap();
    let (_, _, local_id) =
        setup_voucher_for_alice(&mut alice_wallet, &alice_identity, &standard_toml);

    // 2. Alice erstellt einen Container vom Typ `VoucherForSigning`.
    let request_container_bytes = alice_wallet
        .create_signing_request(&alice_identity, &local_id, &alice_identity.user_id)
        .unwrap();

    // 3. Alice versucht, diesen Container fälschlicherweise als Signatur-Antwort (die `DetachedSignature` erwartet) zu verarbeiten.
    let result =
        alice_wallet.process_and_attach_signature(&alice_identity, &request_container_bytes);

    // 4. Verifizierung: Die Funktion muss mit einem `InvalidPayloadType` Fehler ablehnen.
    assert!(matches!(result.unwrap_err(), VoucherCoreError::InvalidPayloadType));
    println!("SUCCESS: Container with wrong payload type was correctly rejected.");
}