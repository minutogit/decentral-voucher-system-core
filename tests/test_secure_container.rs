//! # tests/test_secure_container.rs
//!
//! Integrationstests für den `secure_container_manager`.
//! Diese Tests überprüfen die Kernfunktionalität des `SecureContainer`,
//! insbesondere die Multi-Empfänger-Verschlüsselung und die Fehlerbehandlung.

use voucher_lib::models::secure_container::PayloadType;
use voucher_lib::services::secure_container_manager::{
    create_secure_container, open_secure_container, ContainerManagerError,
};
use voucher_lib::VoucherCoreError;
mod test_utils;
use test_utils::ACTORS;

#[test]
fn test_multi_recipient_secure_container() {
    // --- 1. SETUP ---
    // Erstelle einen Sender (Alice) und drei weitere Personen.
    // Bob und Carol werden die legitimen Empfänger sein.
    // Dave ist ein unbefugter Dritter.
    let alice_identity = &ACTORS.alice;
    let bob_identity = &ACTORS.bob;
    let carol_identity = &ACTORS.charlie; // Charlie represents Carol
    let david_identity = &ACTORS.david;

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

    // David versucht, den Container zu öffnen. Dies muss fehlschlagen.
    let david_result = open_secure_container(&container, david_identity);
    assert!(david_result.is_err());

    // Überprüfe, ob der Fehler der richtige ist.
    match david_result.unwrap_err() {
        VoucherCoreError::Container(ContainerManagerError::NotAnIntendedRecipient) => {
            // Korrekter Fehlertyp
            println!("SUCCESS: Dave was correctly denied access.");
        }
        e => panic!("Dave's access should be denied with NotAnIntendedRecipient error, but got {:?}", e),
    }
}