//! # tests/wallet_api/signature_workflows.rs
//!
//! Enthält Integrationstests speziell für die Signatur-Workflows,
//! die über die `AppService`- und `Wallet`-Fassaden gesteuert werden.
//! Dies umfasst das Anfordern, Erstellen und Anhängen von Signaturen.

// Binde das `test_utils` Modul explizit über seinen Dateipfad ein.

use voucher_lib::test_utils;

use voucher_lib::test_utils::{
    create_additional_signature_data, create_voucher_for_manipulation, debug_open_container,
    generate_signed_standard_toml, generate_valid_mnemonic, setup_in_memory_wallet, ACTORS,
    add_voucher_to_wallet, MINUTO_STANDARD, SILVER_STANDARD,
};
use std::{fs, path::PathBuf};
use tempfile::tempdir;
use voucher_lib::{
    app_service::AppService,
    error::ValidationError,
    models::{
        secure_container::SecureContainer,
        signature::DetachedSignature,
        voucher::{Creator, GuarantorSignature, NominalValue, Voucher},
    },
    services::{
        secure_container_manager::{self, ContainerManagerError},
        voucher_manager::NewVoucherData,
        voucher_validation,
    },
    UserIdentity, VoucherCoreError, Wallet, VoucherStatus, VoucherInstance,
};

/// Hilfsfunktion, um einen Standard-Gutschein für Tests zu erstellen und
/// direkt in das Wallet einer Testperson zu legen.
fn setup_voucher_for_alice(
    alice_wallet: &mut Wallet,
    alice_identity: &UserIdentity,
) -> (Voucher, String) {
    let voucher_data = NewVoucherData {
        validity_duration: Some("P3Y".to_string()),
        non_redeemable_test_voucher: true,
        creator: Creator {
            id: alice_identity.user_id.clone(),
            ..Default::default()
        },
        ..Default::default()
    };
    let (standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
    let voucher = create_voucher_for_manipulation(
        voucher_data,
        standard,
        standard_hash,
        &alice_identity.signing_key,
        "en",
    );
    let local_id =
        Wallet::calculate_local_instance_id(&voucher, &alice_identity.user_id).unwrap();
    alice_wallet
        .voucher_store
        .vouchers
        .insert(local_id.clone(), VoucherInstance {
            voucher: voucher.clone(),
            status: VoucherStatus::Active,
            local_instance_id: local_id.clone(),
        });
    (voucher, local_id)
}

// --- 1. Wallet Signature Workflows ---

/// Testet den vollständigen Signatur-Workflow über die `Wallet`-Fassade.
///
/// ### Szenario:
/// 1.  Alice erstellt einen Gutschein, der laut Standard Bürgen benötigt.
///     Die initiale Validierung schlägt daher fehl.
/// 2.  Alice erstellt eine Signaturanfrage (`SecureContainer`) und sendet sie an Bob.
/// 3.  Bob empfängt die Anfrage, öffnet den Container, extrahiert den Gutschein,
///     erstellt seine Bürgen-Signatur und sendet diese in einer Antwort zurück.
/// 4.  Alice empfängt Bobs Antwort, verarbeitet sie und fügt die Signatur
///     an ihren Gutschein an.
/// 5.  Die finale Verifizierung zeigt, dass der Gutschein nun eine Signatur hat,
///     aber die Validierung immer noch fehlschlägt, weil die *Anzahl* der
///     benötigten Bürgen nicht erfüllt ist.
#[test]
fn api_wallet_full_signature_workflow() {
    let alice_identity = &ACTORS.alice;
    let bob_identity = &ACTORS.bob;
    let mut alice_wallet = setup_in_memory_wallet(alice_identity);
    let bob_wallet = setup_in_memory_wallet(bob_identity);
    let temp_dir = tempdir().expect("Failed to create temporary directory");

    let (voucher, local_id) = setup_voucher_for_alice(&mut alice_wallet, alice_identity);
    let (minuto_standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
    assert!(voucher_validation::validate_voucher_against_standard(&voucher, minuto_standard)
        .is_err());

    let request_container_bytes = alice_wallet
        .create_signing_request(alice_identity, &local_id, &bob_identity.user_id)
        .unwrap();
    let request_file_path: PathBuf = temp_dir.path().join("request.secure");
    fs::write(&request_file_path, request_container_bytes).unwrap();

    let received_request_bytes = fs::read(&request_file_path).unwrap();
    let container: SecureContainer = serde_json::from_slice(&received_request_bytes).unwrap();
    let (decrypted_payload, _) =
        secure_container_manager::open_secure_container(&container, bob_identity).unwrap();
    let voucher_from_alice: Voucher = serde_json::from_slice(&decrypted_payload).unwrap();

    let guarantor_metadata = GuarantorSignature {
        voucher_id: voucher_from_alice.voucher_id.clone(),
        ..Default::default()
    };
    let response_container_bytes = bob_wallet
        .create_detached_signature_response(
            bob_identity,
            &voucher_from_alice,
            DetachedSignature::Guarantor(guarantor_metadata),
            &alice_identity.user_id,
        )
        .unwrap();
    let response_file_path: PathBuf = temp_dir.path().join("response.secure");
    fs::write(&response_file_path, response_container_bytes).unwrap();

    let received_response_bytes = fs::read(&response_file_path).unwrap();
    alice_wallet
        .process_and_attach_signature(alice_identity, &received_response_bytes)
        .unwrap();

    let instance = alice_wallet.voucher_store.vouchers.get(&local_id).unwrap();
    assert_eq!(instance.voucher.guarantor_signatures.len(), 1);
    assert_eq!(
        instance.voucher.guarantor_signatures[0].guarantor_id,
        bob_identity.user_id
    );
    assert!(matches!(
        voucher_validation::validate_voucher_against_standard(&instance.voucher, minuto_standard)
            .unwrap_err(),
        VoucherCoreError::Validation(ValidationError::CountOutOfBounds { .. })
    ));
}

/// Stellt sicher, dass ein `SecureContainer` nicht von einem falschen Empfänger geöffnet werden kann.
///
/// ### Szenario:
/// 1.  Alice erstellt eine Signaturanfrage, die explizit an Bob adressiert ist.
/// 2.  Eve (eine dritte Partei) fängt die Anfrage ab und versucht, sie zu öffnen.
/// 3.  Der Versuch schlägt mit `NotAnIntendedRecipient` fehl.
#[test]
fn api_wallet_signature_fail_wrong_recipient() {
    let alice_identity = &ACTORS.alice;
    let bob_identity = &ACTORS.bob;
    let eve_identity = &ACTORS.hacker;
    let mut alice_wallet = setup_in_memory_wallet(alice_identity);
    let (_, local_id) = setup_voucher_for_alice(&mut alice_wallet, alice_identity);

    let request_bytes = alice_wallet
        .create_signing_request(alice_identity, &local_id, &bob_identity.user_id)
        .unwrap();

    let container: SecureContainer = serde_json::from_slice(&request_bytes).unwrap();
    let result = secure_container_manager::open_secure_container(&container, eve_identity);

    assert!(matches!(
        result.unwrap_err(),
        VoucherCoreError::Container(ContainerManagerError::NotAnIntendedRecipient)
    ));
}

/// Stellt sicher, dass ein manipulierter `SecureContainer` abgewiesen wird.
///
/// ### Szenario:
/// 1.  Bob erstellt eine gültige Signatur-Antwort für Alice.
/// 2.  Ein Angreifer manipuliert ein Byte im verschlüsselten Payload des Containers.
/// 3.  Alice versucht, die manipulierte Antwort zu verarbeiten.
/// 4.  Der Prozess schlägt fehl, weil die Entschlüsselung aufgrund des
///     Authentifizierungsfehlers (AEAD) fehlschlägt.
#[test]
fn api_wallet_signature_fail_tampered_container() {
    let alice_identity = &ACTORS.alice;
    let bob_identity = &ACTORS.bob;
    let mut alice_wallet = setup_in_memory_wallet(alice_identity);
    let bob_wallet = setup_in_memory_wallet(bob_identity);
    let (voucher, _) = setup_voucher_for_alice(&mut alice_wallet, alice_identity);

    let guarantor_metadata = GuarantorSignature {
        voucher_id: voucher.voucher_id.clone(),
        ..Default::default()
    };
    let response_bytes = bob_wallet
        .create_detached_signature_response(
            bob_identity,
            &voucher,
            DetachedSignature::Guarantor(guarantor_metadata),
            &alice_identity.user_id,
        )
        .unwrap();

    let mut container: SecureContainer = serde_json::from_slice(&response_bytes).unwrap();
    if !container.encrypted_payload.is_empty() {
        container.encrypted_payload[10] ^= 0xff; // Flip some bits
    }
    let tampered_bytes = serde_json::to_vec(&container).unwrap();

    let result = alice_wallet.process_and_attach_signature(alice_identity, &tampered_bytes);

    assert!(matches!(
        result.unwrap_err(),
        VoucherCoreError::SymmetricEncryption(_)
    ));
}

/// Stellt sicher, dass eine Signatur für einen unbekannten Gutschein abgewiesen wird.
///
/// ### Szenario:
/// 1.  Alice hat Gutschein A in ihrem Wallet. Sie hat auch Gutschein B erstellt,
///     ihn aber nicht in ihr Wallet gelegt.
/// 2.  Bob soll Gutschein A signieren, erstellt aber fälschlicherweise eine Signatur,
///     die sich auf die ID von Gutschein B bezieht.
/// 3.  Alice versucht, diese Signatur zu verarbeiten.
/// 4.  Der Prozess schlägt mit `VoucherNotFound` fehl, da ihr Wallet den Gutschein
///     mit der ID von B nicht kennt, an den die Signatur angehängt werden soll.
#[test]
fn api_wallet_signature_fail_mismatched_voucher_id() {
    let alice_identity = &ACTORS.alice;
    let bob_identity = &ACTORS.bob;
    let mut alice_wallet = setup_in_memory_wallet(alice_identity);
    let bob_wallet = setup_in_memory_wallet(bob_identity);
    let (_voucher_a, _) = setup_voucher_for_alice(&mut alice_wallet, alice_identity);

    let voucher_data_b = NewVoucherData {
        creator: Creator {
            id: alice_identity.user_id.clone(),
            ..Default::default()
        },
        nominal_value: NominalValue {
            amount: "120".to_string(),
            ..Default::default()
        },
        validity_duration: Some("P3Y".to_string()),
        ..Default::default()
    };
    let (minuto_standard, minuto_standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
    let voucher_b = create_voucher_for_manipulation(
        voucher_data_b,
        minuto_standard,
        minuto_standard_hash,
        &alice_identity.signing_key,
        "en",
    );

    let guarantor_metadata = GuarantorSignature {
        voucher_id: voucher_b.voucher_id.clone(), // Falsche ID!
        ..Default::default()
    };
    let response_bytes = bob_wallet
        .create_detached_signature_response(
            bob_identity,
            &voucher_b,
            DetachedSignature::Guarantor(guarantor_metadata),
            &alice_identity.user_id,
        )
        .unwrap();

    let result = alice_wallet.process_and_attach_signature(alice_identity, &response_bytes);

    assert!(matches!(
        result.unwrap_err(),
        VoucherCoreError::VoucherNotFound(_)
    ));
}

/// Stellt sicher, dass die Verarbeitung fehlschlägt, wenn der Payload-Typ nicht erwartet wird.
///
/// ### Szenario:
/// 1.  Alice erstellt einen Container vom Typ `VoucherForSigning`.
/// 2.  Sie versucht, diesen Container mit der Funktion `process_and_attach_signature`
///     zu verarbeiten, die einen Payload vom Typ `DetachedSignature` erwartet.
/// 3.  Der Prozess schlägt mit `InvalidPayloadType` fehl.
#[test]
fn api_wallet_signature_fail_wrong_payload_type() {
    let alice_identity = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(alice_identity);
    let (_, local_id) = setup_voucher_for_alice(&mut alice_wallet, alice_identity);

    let request_container_bytes = alice_wallet
        .create_signing_request(alice_identity, &local_id, &alice_identity.user_id)
        .unwrap();

    let result =
        alice_wallet.process_and_attach_signature(alice_identity, &request_container_bytes);

    assert!(matches!(
        result.unwrap_err(),
        VoucherCoreError::InvalidPayloadType
    ));
}

// --- 2. AppService Signature Workflows ---

/// Testet den vollständigen Signatur-Workflow über die `AppService`-Fassade.
///
/// ### Szenario:
/// 1.  Zwei `AppService`-Instanzen für einen Ersteller und einen Bürgen werden eingerichtet.
/// 2.  Der Ersteller legt einen Gutschein an.
/// 3.  Der Ersteller fordert eine Signatur vom Bürgen an.
/// 4.  Der Bürge empfängt die Anfrage, erstellt eine `AdditionalSignature`
///     (passend zum Silber-Standard) und sendet sie zurück.
/// 5.  Der Ersteller empfängt die Antwort und fügt die Signatur erfolgreich an.
/// 6.  Die Details des Gutscheins zeigen die neue Signatur an.
#[test]
fn api_app_service_full_signature_workflow() {
    let silver_standard_toml =
        generate_signed_standard_toml("voucher_standards/silver_v1/standard.toml");
    let dir_creator = tempdir().unwrap();
    let dir_guarantor = tempdir().unwrap();
    let password = "sig-password";

    let mut service_creator = AppService::new(dir_creator.path()).unwrap();
    service_creator
        .create_profile(&generate_valid_mnemonic(), None, Some("creator"), password)
        .unwrap();

    let mut service_guarantor = AppService::new(dir_guarantor.path()).unwrap();
    service_guarantor
        .create_profile(&generate_valid_mnemonic(), None, Some("guarantor"), password)
        .unwrap();
    let id_guarantor = service_guarantor.get_user_id().unwrap();

    service_creator
        .create_new_voucher(
            &silver_standard_toml,
            "en",
            NewVoucherData {
                creator: Creator {
                    id: service_creator.get_user_id().unwrap(),
                    ..Default::default()
                },
                nominal_value: NominalValue {
                    amount: "50".to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
            password,
        )
        .unwrap();
    let local_id = service_creator.get_voucher_summaries().unwrap()[0]
        .local_instance_id
        .clone();

    let request_bytes = service_creator
        .create_signing_request_bundle(&local_id, &id_guarantor)
        .unwrap();

    let (voucher_to_sign, sender_id) = {
        service_guarantor.login(password).unwrap();
        let guarantor_identity = service_guarantor.get_unlocked_mut_for_test().1;
        debug_open_container(&request_bytes, guarantor_identity).unwrap()
    };

    let signature_data = create_additional_signature_data(
        service_guarantor.get_unlocked_mut_for_test().1,
        &voucher_to_sign.voucher_id,
        "Verified by external party.",
    );

    let response_bytes = service_guarantor
        .create_detached_signature_response_bundle(&voucher_to_sign, signature_data, &sender_id)
        .unwrap();

    service_creator
        .process_and_attach_signature(&response_bytes, &silver_standard_toml, password)
        .unwrap();

    let details = service_creator.get_voucher_details(&local_id).unwrap();
    assert_eq!(details.voucher.additional_signatures.len(), 1);
    assert_eq!(
        details.voucher.additional_signatures[0].signer_id,
        id_guarantor
    );
}

/// Testet den Signatur-Roundtrip für einen Standard, der Signaturen erfordert (Minuto).
///
/// ### Szenario:
/// 1.  Alice erstellt einen Minuto-Gutschein, der ohne Bürgen ungültig ist.
/// 2.  Sie fordert eine Signatur von Bob an.
/// 3.  Bob empfängt die Anfrage, erstellt eine `GuarantorSignature` und sendet
///     diese in einer verschlüsselten Antwort zurück.
/// 4.  Alice empfängt die Antwort und fügt die Signatur an ihren Gutschein an.
/// 5.  Der Gutschein hat danach eine Signatur von Bob.
#[test]
fn api_wallet_signature_roundtrip_minuto_required() {
    let alice_identity = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(alice_identity);
    let bob_identity = &ACTORS.bob;
    let bob_wallet = setup_in_memory_wallet(bob_identity); // Bobs Wallet für die Antwort
    let (minuto_standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    // Erstelle einen Minuto-Gutschein, der noch Bürgen braucht. `false` = nicht valide erstellen.
    let voucher_id =
        add_voucher_to_wallet(&mut alice_wallet, alice_identity, "100", minuto_standard, false)
            .unwrap();

    // Alice erstellt eine Signaturanfrage für Bob
    let request_bytes = alice_wallet
        .create_signing_request(alice_identity, &voucher_id, &bob_identity.user_id)
        .unwrap();

    // Bob verarbeitet die Anfrage und erstellt eine Antwort
    let (voucher_for_signing, _) =
        debug_open_container(&request_bytes, bob_identity).unwrap();

    // Bob erstellt seine Signatur-Daten (als Enum)
    let mut signature_data_enum =
        test_utils::create_guarantor_signature_data(bob_identity, "1", &voucher_for_signing.voucher_id);
    // Wir modifizieren die innere Struktur via Pattern Matching
    if let DetachedSignature::Guarantor(guarantor_struct) = &mut signature_data_enum {
        guarantor_struct.first_name = "Bob".to_string();
        guarantor_struct.last_name = "Builder".to_string();
    }

    // Bob erstellt die verschlüsselte Antwort mit der Signatur
    let response_bytes = bob_wallet
        .create_detached_signature_response(bob_identity, &voucher_for_signing, signature_data_enum, &alice_identity.user_id)
        .unwrap();

    // Alice verarbeitet die Signatur-Antwort
    alice_wallet
        .process_and_attach_signature(alice_identity, &response_bytes)
        .unwrap();

    // Assert: Der Gutschein hat jetzt genau eine Signatur von Bob
    let final_instance = alice_wallet.voucher_store.vouchers.get(&voucher_id).unwrap();
    assert_eq!(final_instance.voucher.guarantor_signatures.len(), 1);
    assert_eq!(
        final_instance.voucher.guarantor_signatures[0].guarantor_id,
        bob_identity.user_id
    );
}

/// Testet den vollständigen Bürgen-Workflow über die `AppService`-Fassade,
/// insbesondere den Statusübergang von `Incomplete` zu `Active`.
///
/// ### Szenario:
/// 1.  Ein Ersteller und zwei Bürgen werden als separate `AppService`-Instanzen initialisiert.
/// 2.  Der Ersteller erstellt einen neuen Gutschein nach dem Minuto-Standard, der
///     zwei Bürgen erfordert.
/// 3.  **Assertion 1:** Der Gutschein hat initial den Status `Incomplete`.
/// 4.  Der Ersteller fordert Signaturen von beiden Bürgen an und fügt diese nacheinander an.
/// 5.  **Assertion 2:** Nach dem Anfügen der ersten Signatur ist der Status immer
///     noch `Incomplete`, aber mit einer aktualisierten Begründung.
/// 6.  **Assertion 3:** Nach dem Anfügen der zweiten (und letzten benötigten) Signatur
///     wechselt der Status des Gutscheins zu `Active`.
#[test]
fn test_full_guarantor_workflow_via_app_service() {
    // --- 1. Setup: Drei separate Benutzer simulieren ---
    let dir_creator = tempdir().expect("Failed to create temp dir for creator");
    let dir_g1 = tempdir().expect("Failed to create temp dir for guarantor1");
    let dir_g2 = tempdir().expect("Failed to create temp dir for guarantor2");
    let password = "password123";

    let minuto_standard_toml =
        generate_signed_standard_toml("voucher_standards/minuto_v1/standard.toml");

    // Creator Service
    let mut service_creator =
        AppService::new(dir_creator.path()).expect("Failed to create creator service");
    service_creator
        .create_profile(&generate_valid_mnemonic(), None, Some("creator"), password)
        .expect("Creator profile creation failed");
    let creator_id = service_creator.get_user_id().unwrap();

    // Guarantor 1 Service
    let mut service_g1 = AppService::new(dir_g1.path()).expect("Failed to create g1 service");
    service_g1
        .create_profile(&generate_valid_mnemonic(), None, Some("g1"), password)
        .expect("G1 profile creation failed");
    let g1_id = service_g1.get_user_id().unwrap();

    // Guarantor 2 Service
    let mut service_g2 = AppService::new(dir_g2.path()).expect("Failed to create g2 service");
    service_g2
        .create_profile(&generate_valid_mnemonic(), None, Some("g2"), password)
        .expect("G2 profile creation failed");
    let g2_id = service_g2.get_user_id().unwrap();

    // --- 2. Schritt 1: Erstellung des unvollständigen Gutscheins ---
    service_creator
        .create_new_voucher(
            &minuto_standard_toml,
            "en",
            NewVoucherData {
                creator: Creator {
                    id: creator_id,
                    ..Default::default()
                },
                nominal_value: NominalValue {
                    amount: "60".to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
            password,
        )
        .expect("Voucher creation failed");

    let summary = service_creator.get_voucher_summaries().unwrap().pop().unwrap();
    let local_id = summary.local_instance_id;

    // --- 3. Assertion 1: Status ist `Incomplete` ---
    let details_before = service_creator
        .get_voucher_details(&local_id)
        .expect("Should find voucher details");
    assert!(matches!(details_before.status, VoucherStatus::Incomplete { .. }));

    // --- 4. Schritt 2: Simulieren des Signaturprozesses ---

    // --- Signatur von Bürge 1 ---
    let _request_bundle_1 = service_creator
        .create_signing_request_bundle(&local_id, &g1_id)
        .expect("Failed to create signing request for G1");
    let signature_data_1 = DetachedSignature::Guarantor(GuarantorSignature {
        voucher_id: details_before.voucher.voucher_id.clone(),
        gender: "1".to_string(),
        ..Default::default()
    });
    let response_bundle_1 = service_g1
        .create_detached_signature_response_bundle(
            &details_before.voucher,
            signature_data_1,
            &service_creator.get_user_id().unwrap(),
        )
        .expect("Failed to create signature response from G1");
    service_creator
        .process_and_attach_signature(&response_bundle_1, &minuto_standard_toml, password)
        .expect("Failed to attach G1's signature");
    let details_mid = service_creator.get_voucher_details(&local_id).unwrap();
    assert!(matches!(details_mid.status, VoucherStatus::Incomplete { .. }));

    // --- Signatur von Bürge 2 ---
    let _request_bundle_2 = service_creator
        .create_signing_request_bundle(&local_id, &g2_id)
        .expect("Failed to create signing request for G2");
    let signature_data_2 = DetachedSignature::Guarantor(GuarantorSignature {
        voucher_id: details_mid.voucher.voucher_id.clone(),
        gender: "2".to_string(),
        ..Default::default()
    });
    let response_bundle_2 = service_g2
        .create_detached_signature_response_bundle(
            &details_mid.voucher,
            signature_data_2,
            &service_creator.get_user_id().unwrap(),
        )
        .expect("Failed to create signature response from G2");
    service_creator
        .process_and_attach_signature(&response_bundle_2, &minuto_standard_toml, password)
        .expect("Failed to attach G2's signature");

    // --- 5. Assertion 3: Überprüfung des finalen `Active`-Zustands ---
    let details_after = service_creator.get_voucher_details(&local_id).unwrap();
    assert_eq!(
        details_after.status,
        VoucherStatus::Active,
        "Final voucher status should be Active"
    );
}

/// Testet den Signatur-Roundtrip für einen Standard mit optionalen Signaturen (Silber).
///
/// ### Szenario:
/// 1.  Alice erstellt einen Silber-Gutschein, der initial gültig ist, da `needed_guarantors = 0`.
/// 2.  Sie fordert trotzdem eine optionale Signatur von Bob an.
/// 3.  Bob empfängt und beantwortet die Anfrage.
/// 4.  Alice fügt die optionale Signatur erfolgreich an.
/// 5.  Der Gutschein hat danach eine Signatur, obwohl sie nicht erforderlich war.
#[test]
fn api_wallet_signature_roundtrip_silver_optional() {
    let alice_identity = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(alice_identity);
    let bob_identity = &ACTORS.bob;
    let bob_wallet = setup_in_memory_wallet(bob_identity);
    let (silver_standard, _) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);

    let voucher_id =
        add_voucher_to_wallet(&mut alice_wallet, alice_identity, "10", silver_standard, false)
            .unwrap();

    let request_bytes = alice_wallet
        .create_signing_request(alice_identity, &voucher_id, &bob_identity.user_id)
        .unwrap();

    let (voucher_for_signing, _) = debug_open_container(&request_bytes, bob_identity).unwrap();

    let mut signature_data_enum =
        test_utils::create_guarantor_signature_data(bob_identity, "1", &voucher_for_signing.voucher_id);
    if let DetachedSignature::Guarantor(guarantor_struct) = &mut signature_data_enum {
        guarantor_struct.first_name = "Bob".to_string();
        guarantor_struct.last_name = "Builder".to_string();
    }
    let response_bytes = bob_wallet
        .create_detached_signature_response(
            bob_identity,
            &voucher_for_signing,
            signature_data_enum,
            &alice_identity.user_id,
        )
        .unwrap();

    alice_wallet
        .process_and_attach_signature(alice_identity, &response_bytes)
        .unwrap();

    let final_instance = alice_wallet.voucher_store.vouchers.get(&voucher_id).unwrap();
    assert_eq!(final_instance.voucher.guarantor_signatures.len(), 1);
}