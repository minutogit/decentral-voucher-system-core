//! # tests/test_secure_container.rs
//!
//! Integrationstests für den `secure_container_manager`.
//! Diese Tests überprüfen die Kernfunktionalität des `SecureContainer`,
//! insbesondere die Multi-Empfänger-Verschlüsselung und die Fehlerbehandlung.

use voucher_lib::{
    crypto_utils,
    models::{
        profile::UserIdentity,
        secure_container::PayloadType,
    },
    services::secure_container_manager::{create_secure_container, open_secure_container, ContainerManagerError},
    VoucherCoreError,
};

/// Erstellt eine Test-Identität für einen Benutzer.
fn setup_test_identity(name: &str, prefix: &str) -> UserIdentity {
    let (public_key, signing_key) = crypto_utils::generate_ed25519_keypair_for_tests(Some(name));
    let user_id = crypto_utils::create_user_id(&public_key, Some(prefix)).unwrap();
    UserIdentity {
        signing_key,
        public_key,
        user_id,
    }
}

#[test]
fn test_multi_recipient_secure_container() {
    // --- 1. SETUP ---
    // Erstelle einen Sender (Alice) und drei weitere Personen.
    // Bob und Carol werden die legitimen Empfänger sein.
    // Dave ist ein unbefugter Dritter.
    let alice_identity = setup_test_identity("alice", "al");
    let bob_identity = setup_test_identity("bob", "bo");
    let carol_identity = setup_test_identity("carol", "ca");
    let dave_identity = setup_test_identity("dave", "da");

    // --- 2. CONTAINER CREATION ---
    // Alice erstellt eine geheime Nachricht für Bob und Carol.
    let secret_payload = b"This is a secret message for Bob and Carol!";
    let recipient_ids = vec![bob_identity.user_id.clone(), carol_identity.user_id.clone()];

    let container = create_secure_container(
        &alice_identity,
        &recipient_ids,
        secret_payload,
        PayloadType::Generic("test_message".to_string()),
    )
        .unwrap();

    // --- 3. VERIFICATION BY RECIPIENTS ---

    // Bob versucht, den Container zu öffnen.
    let (bob_payload, bob_payload_type) =
        open_secure_container(&container, &bob_identity).unwrap();
    assert_eq!(bob_payload, secret_payload);
    assert_eq!(bob_payload_type, PayloadType::Generic("test_message".to_string()));
    println!("SUCCESS: Bob successfully opened the container.");

    // Carol versucht, denselben Container zu öffnen.
    let (carol_payload, carol_payload_type) =
        open_secure_container(&container, &carol_identity).unwrap();
    assert_eq!(carol_payload, secret_payload);
    assert_eq!(carol_payload_type, bob_payload_type);
    println!("SUCCESS: Carol successfully opened the container.");

    // --- 4. VERIFICATION FAILURE BY UNAUTHORIZED USER ---

    // Dave versucht, den Container zu öffnen. Dies muss fehlschlagen.
    let dave_result = open_secure_container(&container, &dave_identity);
    assert!(dave_result.is_err());

    // Überprüfe, ob der Fehler der richtige ist.
    match dave_result.unwrap_err() {
        VoucherCoreError::Container(ContainerManagerError::NotAnIntendedRecipient) => {
            // Korrekter Fehlertyp
            println!("SUCCESS: Dave was correctly denied access.");
        }
        e => panic!("Dave's access should be denied with NotAnIntendedRecipient error, but got {:?}", e),
    }
}