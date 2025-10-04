//! # tests/wallet_api/transactionality.rs
//!
//! Enthält Integrationstests, die sicherstellen, dass alle zustandsändernden
//! Operationen des `AppService` atomar sind. Eine Operation muss entweder
//! vollständig erfolgreich sein (inklusive Speicherung) oder den In-Memory-Zustand
//! so hinterlassen, als wäre sie nie ausgeführt worden.

use std::collections::HashMap;
use tempfile::tempdir;

use voucher_lib::{
    models::{
        conflict::{ProofOfDoubleSpend, ResolutionEndorsement},
        secure_container::SecureContainer,
        voucher::{Creator, NominalValue},
    },
    services::{crypto_utils, voucher_manager::NewVoucherData},
    test_utils::{generate_signed_standard_toml, resign_transaction, ACTORS, SILVER_STANDARD},
    VoucherStatus,
};
use voucher_lib::test_utils;
use chrono::{Duration, Utc};

/// Lokale Test-Hilfsfunktion, um einen mock `ProofOfDoubleSpend` zu erzeugen.
/// HINWEIS: Aus `state_management.rs` kopiert, um Importprobleme zu vermeiden.
fn create_mock_proof_of_double_spend(
    offender_id: &str,
    victim_id: &str,
    resolutions: Option<Vec<ResolutionEndorsement>>,
    verdict: Option<voucher_lib::models::conflict::Layer2Verdict>,
) -> ProofOfDoubleSpend {
    ProofOfDoubleSpend {
        proof_id: crypto_utils::get_hash(offender_id),
        offender_id: offender_id.to_string(),
        conflicting_transactions: vec![],
        reporter_id: victim_id.to_string(),
        resolutions,
        layer2_verdict: verdict,
        fork_point_prev_hash: "dummy_hash".to_string(),
        voucher_valid_until: (Utc::now() + Duration::days(365)).to_rfc3339(),
        report_timestamp: Utc::now().to_rfc3339(),
        reporter_signature: "dummy_sig".to_string(),
    }
}

/// Test 7.1: Stellt sicher, dass `create_transfer_bundle` bei einem Speicherfehler
/// den In-Memory-Zustand des Wallets nicht verändert.
#[test]
fn test_transfer_bundle_is_transactional_on_save_failure() {
    // 1. ARRANGE: Wallet mit einem aktiven Gutschein über 100 Einheiten vorbereiten.
    let dir = tempdir().unwrap();
    let correct_password = "correct_password";
    let wrong_password = "wrong_password";
    let test_user = &ACTORS.test_user;
    let (mut service, _) = test_utils::setup_service_with_profile(dir.path(), test_user, "Test User", correct_password);

    let silver_toml = generate_signed_standard_toml("voucher_standards/silver_v1/standard.toml");
    let user_id = service.get_user_id().unwrap();

    service
        .create_new_voucher(
            &silver_toml,
            "en",
            NewVoucherData {
                creator: Creator { id: user_id, ..Default::default() },
                nominal_value: NominalValue { amount: "100".to_string(), ..Default::default() },
                ..Default::default()
            },
            correct_password,
        )
        .unwrap();

    let summary_before = service.get_voucher_summaries(None, None).unwrap();
    let voucher_to_split_id = summary_before[0].local_instance_id.clone();

    // 2. ACT: Versuche, einen Transfer mit falschem Passwort zu erstellen.
    let (silver_standard, _) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
    let result = service.create_transfer_bundle(
        silver_standard,
        &voucher_to_split_id,
        "bob-recipient-id", // Kann ein Dummy sein, da die Operation fehlschlägt
        "40",
        None,
        None,
        wrong_password, // Falsches Passwort, um Speicherfehler auszulösen
    );

    // 3. ASSERT: Operation ist fehlgeschlagen und der Zustand ist unverändert.
    assert!(
        result.is_err(),
        "Operation should fail due to wrong password"
    );
    // HINWEIS: Wir prüfen nicht mehr den genauen Fehlertext, da dieser vom internen Ablauf abhängt.
    // Wichtig ist nur, DASS ein Fehler auftritt und der Zustand danach korrekt ist.

    // HINWEIS: Dieser Test schlägt weiterhin fehl, weil er einen echten Bug aufdeckt.
    // Die `create_transfer_bundle` Operation ist nicht atomar. Der Zustand im Speicher
    // wird verändert (der 100er Gutschein wird durch einen 60er ersetzt), aber nach dem
    // Speicherfehler nicht zurückgerollt. Die folgende Assertion würde also fehlschlagen.
    let summaries_after = service.get_voucher_summaries(None, None).unwrap();
    assert_eq!(
        summaries_after.len(),
        1,
        "Wallet should contain exactly one voucher instance after failed transfer"
    );

    assert_eq!(
        summaries_after[0].current_amount, "100.0000",
        "Voucher amount should be rolled back to 100"
    );
}

/// Test 7.2: Stellt sicher, dass `receive_bundle` bei einem Speicherfehler
/// den neuen Gutschein nicht im In-Memory-Zustand des Wallets belässt.
#[test]
fn test_receive_bundle_is_transactional_on_save_failure() {
    // 1. ARRANGE: Ein leeres Empfänger-Wallet und ein gültiges Bundle vorbereiten.
    let dir_sender = tempdir().unwrap();
    let sender = &ACTORS.sender;
    let dir_recipient = tempdir().unwrap();
    let recipient = &ACTORS.recipient1;
    let correct_password = "correct_password";
    let wrong_password = "wrong_password";
    let (mut service_sender, _) = test_utils::setup_service_with_profile(dir_sender.path(), sender, "Sender", "pwd");
    let (mut service_recipient, _) = test_utils::setup_service_with_profile(dir_recipient.path(), recipient, "Recipient", correct_password);

    let silver_toml = generate_signed_standard_toml("voucher_standards/silver_v1/standard.toml");
    let (silver_standard, _) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
    let id_sender = service_sender.get_user_id().unwrap();
    let id_recipient = service_recipient.get_user_id().unwrap();

    // FIX: Explizite Voucher-Daten anstelle von Default::default() verwenden, um Panic zu vermeiden.
    service_sender
        .create_new_voucher(
            &silver_toml,
            "en",
            NewVoucherData {
                creator: Creator { id: id_sender, ..Default::default() },
                nominal_value: NominalValue { amount: "100".to_string(), ..Default::default() },
                ..Default::default()
            },
            "pwd",
        )
        .unwrap();
    let voucher_id = service_sender.get_voucher_summaries(None, None).unwrap()[0]
        .local_instance_id
        .clone();
    let bundle = service_sender
        .create_transfer_bundle(
            silver_standard,
            &voucher_id,
            &id_recipient,
            "100",
            None,
            None,
            "pwd",
        )
        .unwrap();

    let mut standards_map = HashMap::new();
    standards_map.insert(silver_standard.metadata.uuid.clone(), silver_toml);

    // 2. ACT: Versuche, das Bundle mit falschem Passwort zu empfangen.
    let result = service_recipient.receive_bundle(
        &bundle,
        &standards_map,
        None,
        wrong_password, // Falsches Passwort
    );

    // 3. ASSERT: Operation ist fehlgeschlagen und Wallet ist immer noch leer.
    assert!(result.is_err(), "Receive operation should fail");
    let summaries_after = service_recipient
        .get_voucher_summaries(None, None)
        .unwrap();
    assert!(
        summaries_after.is_empty(),
        "Recipient's wallet should remain empty after a failed receive"
    );
}

/// Test 7.3: Stellt sicher, dass `process_and_attach_signature` bei einem Speicherfehler
/// den Gutscheinzustand (Status, Signaturanzahl) nicht in-memory verändert.
#[test]
fn test_attach_signature_is_transactional_on_save_failure() {
    // 1. ARRANGE: Wallet mit einem Gutschein (Silber-Standard, benötigt keine Bürgen) vorbereiten.
    let dir_creator = tempdir().unwrap();
    let correct_password = "correct_password";
    let wrong_password = "wrong_password";
    let creator = &ACTORS.alice;
    let (mut service_creator, _) = test_utils::setup_service_with_profile(dir_creator.path(), creator, "Creator", correct_password);
    let id_creator = service_creator.get_user_id().unwrap();

    let silver_toml = generate_signed_standard_toml("voucher_standards/silver_v1/standard.toml");
    let (silver_standard, _) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
    let mut standards_map = HashMap::new();
    standards_map.insert(silver_standard.metadata.uuid.clone(), silver_toml.clone());

    let signer = &ACTORS.guarantor1;
    let (mut service_signer, _) = test_utils::setup_service_with_profile(tempdir().unwrap().path(), signer, "Signer", "pwd");
    let id_signer = service_signer.get_user_id().unwrap();


    // Gutschein erstellen -> Status: Active (da keine Bürgen erforderlich)
    // FIX: Explizite Voucher-Daten anstelle von Default::default() verwenden, um Panic zu vermeiden.
    service_creator
        .create_new_voucher(
            &silver_toml,
            "en",
            NewVoucherData {
                creator: Creator {
                    id: id_creator.clone(),
                    first_name: "Test".to_string(),
                    last_name: "Creator".to_string(),
                    ..Default::default() },
                nominal_value: NominalValue { amount: "100".to_string(), unit: silver_standard.template.fixed.nominal_value.unit.clone(), ..Default::default() },
                validity_duration: Some("P1Y".to_string()),
                ..Default::default()
            },
            correct_password,
        ).unwrap();

    let local_id = service_creator.get_voucher_summaries(None, None).unwrap()[0].local_instance_id.clone();
    let details_before = service_creator.get_voucher_details(&local_id).unwrap();
    assert_eq!(details_before.voucher.guarantor_signatures.len(), 0);
    assert!(matches!(
        details_before.status, // Der Gutschein sollte Active sein
        VoucherStatus::Active
    ));

    // 1. Signatur von externem Unterzeichner vorbereiten (Additional Signature)
    let bundle_req = service_creator
        .create_signing_request_bundle(
            &local_id,
            &id_signer,
        )
        .unwrap();

    let (_, signer_identity_ref) = service_signer.get_unlocked_mut_for_test();
    let signer_identity = signer_identity_ref.clone();
    let request_container: SecureContainer = serde_json::from_slice(&bundle_req).unwrap();
    let (payload, _) = voucher_lib::services::secure_container_manager::open_secure_container(&request_container, &signer_identity).unwrap();
    let voucher_from_request: voucher_lib::models::voucher::Voucher = serde_json::from_slice(&payload).unwrap();

    // FIX: Argumente in der korrekten Reihenfolge übergeben (voucher_id, description).
    // 1. Signatur von externem Unterzeichner erstellen.
    let sig_data1 = voucher_lib::test_utils::create_additional_signature_data(
        &signer_identity, &voucher_from_request.voucher_id, "First validation",
    );

    // 3. Bürge erstellt das Antwort-Bundle.
    // Signer erstellt das Antwort-Bundle.
    // FIX: Das 3. Argument ist die Empfänger-ID der Antwort, nicht das Passwort.
    let detached_sig1 = service_signer
        .create_detached_signature_response_bundle(&voucher_from_request, sig_data1, &id_creator)
        .unwrap();
    
    // FIX: Das 2. Argument ist der Standard-TOML, nicht die local_id.
    service_creator
        .process_and_attach_signature(&detached_sig1, &silver_toml, correct_password)
        .expect("First signature attachment failed. The utility logic should now be correct.");

    let details_mid = service_creator.get_voucher_details(&local_id).unwrap();
        assert_eq!(
        details_mid.voucher.additional_signatures.len(),
        1,
        "Should have 1 additional signature after first attachment"
    );
    assert!(matches!(
        details_mid.status,
        VoucherStatus::Active
    ));

    // 2. Zweite Signatur von externem Unterzeichner vorbereiten
    let bundle_req2 = service_creator
        .create_signing_request_bundle(
            &local_id,
            &id_signer, // Erneut dieselbe ID, was in der Praxis zu einem Fehler führen könnte, aber hier nur das Rollback testet
        )
        .unwrap();

    let (_, signer_identity_ref2) = service_signer.get_unlocked_mut_for_test();
    let signer_identity2 = signer_identity_ref2.clone();
    let request_container2: SecureContainer = serde_json::from_slice(&bundle_req2).unwrap();
    let (payload2, _) = voucher_lib::services::secure_container_manager::open_secure_container(&request_container2, &signer_identity2).unwrap();
    let voucher_from_request2: voucher_lib::models::voucher::Voucher = serde_json::from_slice(&payload2).unwrap();

    // 2. Zweite Signatur erstellen.
    let sig_data2 = voucher_lib::test_utils::create_additional_signature_data(
        &signer_identity2, &voucher_from_request2.voucher_id, "Second validation",
    );

    let detached_sig2 = service_signer
        .create_detached_signature_response_bundle(&voucher_from_request2, sig_data2, &id_creator)
        .unwrap();

    // 2. ACT: Versuche, die zweite Signatur mit falschem Passwort hinzuzufügen.
    let result =
        service_creator.process_and_attach_signature(&detached_sig2, &silver_toml, wrong_password);

    // 3. ASSERT: Operation schlägt fehl, Zustand bleibt unverändert.
    assert!(result.is_err(), "Signature attachment should fail");

    let details_after = service_creator.get_voucher_details(&local_id).unwrap();
    assert_eq!(
        details_after.voucher.additional_signatures.len(),
        1,
        "Additional signature count should remain 1 after failed attachment"
    );
    assert!(
        matches!(details_after.status, VoucherStatus::Active), // Muss Active bleiben
        "Status should remain Active after failed attachment"
    );
}

/// Test 7.4: Stellt sicher, dass `import_resolution_endorsement` bei einem Speicherfehler
/// den In-Memory-Konfliktbeweis nicht verändert.
#[test]
fn test_import_endorsement_is_transactional_on_save_failure() {
    // 1. ARRANGE: Wallet mit einem ungelösten Konfliktbeweis vorbereiten.
    let dir_reporter = tempdir().unwrap();
    let correct_password = "correct_password";
    let wrong_password = "wrong_password";
    let reporter = &ACTORS.reporter;
    let dir_victim = tempdir().unwrap();
    let victim = &ACTORS.victim;
    let (mut service_reporter, _) = test_utils::setup_service_with_profile(dir_reporter.path(), reporter, "Reporter", correct_password);
    let (mut service_victim, _) = test_utils::setup_service_with_profile(dir_victim.path(), victim, "Victim", "pwd");
    let id_victim = service_victim.get_user_id().unwrap();

    // Beweis manuell hinzufügen und durch eine andere Operation speichern
    let proof = create_mock_proof_of_double_spend("offender-xyz", &id_victim, None, None);
    let proof_id = proof.proof_id.clone();
    {
        let (wallet, _identity) = service_reporter.get_unlocked_mut_for_test();
        wallet
            .proof_store
            .proofs
            .insert(proof.proof_id.clone(), proof);
    }
    // FIX: `wallet.save` ist nicht direkt nutzbar. Führe eine andere `AppService`-Aktion
    // aus, um den Zustand (inklusive des manuell hinzugefügten Beweises) zu speichern.
    service_reporter.save_encrypted_data("dummy", b"data", correct_password).unwrap();

    let conflicts_before = service_reporter.list_conflicts().unwrap();
    assert!(!conflicts_before[0].is_resolved, "Conflict should initially be unresolved");

    // Gültige Beilegung vom Opfer erstellen lassen
    let (wallet_victim, _) = service_victim.get_unlocked_mut_for_test();
    let proof_for_victim = create_mock_proof_of_double_spend("offender-xyz", &id_victim, None, None);
    wallet_victim
        .proof_store
        .proofs
        .insert(proof_for_victim.proof_id.clone(), proof_for_victim);
    let endorsement = service_victim
        .create_resolution_endorsement(&proof_id, Some("We settled this.".to_string()))
        .unwrap();

    // 2. ACT: Versuche, die Beilegung mit falschem Passwort zu importieren.
    let result =
        service_reporter.import_resolution_endorsement(endorsement, wrong_password);

    // 3. ASSERT: Operation schlägt fehl, Konflikt bleibt ungelöst.
    assert!(result.is_err(), "Endorsement import should fail");

    let conflicts_after = service_reporter.list_conflicts().unwrap();
    assert_eq!(conflicts_after.len(), 1);
    assert!(
        !conflicts_after[0].is_resolved,
        "Conflict should remain unresolved after failed import"
    );

    let proof_details = service_reporter.get_proof_of_double_spend(&proof_id).unwrap();
    assert!(
        proof_details.resolutions.is_none() || proof_details.resolutions.as_ref().unwrap().is_empty(),
        "Proof should have no endorsements after failed import"
    );
}

/// Test 7.5: Stellt sicher, dass `receive_bundle` bei einem Konflikt und
/// anschließendem Speicherfehler den Zustand komplett zurücksetzt.
#[test]
fn test_receive_bundle_is_transactional_on_conflict_and_save_failure() {
    // 1. ARRANGE: David empfängt einen Gutschein (Pfad A). Ein zweiter,
    // konfliktreicher Gutschein (Pfad B) wird vorbereitet.
    let dir_alice = tempdir().unwrap();
    let dir_david = tempdir().unwrap();
    let alice = &ACTORS.alice;
    let correct_password = "correct_password";
    let wrong_password = "wrong_password";
    let david = &ACTORS.david;
    let (mut service_alice, _) = test_utils::setup_service_with_profile(dir_alice.path(), alice, "Alice", "pwd");
    let (mut service_david, _) = test_utils::setup_service_with_profile(dir_david.path(), david, "David", correct_password);
    let id_david = service_david.get_user_id().unwrap();

    let silver_toml = generate_signed_standard_toml("voucher_standards/silver_v1/standard.toml");
    let mut standards_map = HashMap::new();
    standards_map.insert(SILVER_STANDARD.0.metadata.uuid.clone(), silver_toml.clone());

    // FIX: Explizite Voucher-Daten anstelle von Default::default() verwenden, um Panic zu vermeiden.
    let id_alice = service_alice.get_user_id().unwrap();
    let identity_alice = alice.identity.clone();
    let voucher_v1 = service_alice.create_new_voucher(
        &silver_toml,
        "en",
        NewVoucherData {
            creator: Creator { id: id_alice.clone(), ..Default::default() },
            nominal_value: NominalValue { amount: "100".to_string(), ..Default::default() },
            ..Default::default()
        },
        "pwd"
    ).unwrap();

    // Zwei konkurrierende Transaktionen aus V1 erstellen
    let prev_tx = voucher_v1.transactions.last().unwrap();
    let prev_tx_hash = voucher_lib::services::crypto_utils::get_hash(
        voucher_lib::services::utils::to_canonical_json(prev_tx).unwrap(),
    );
    // FIX: Zeitstempel müssen garantiert nach der Erstellung des Gutscheins liegen.
    let prev_tx_time = chrono::DateTime::parse_from_rfc3339(&prev_tx.t_time)
        .unwrap()
        .with_timezone(&Utc);
    let time_a = (prev_tx_time + Duration::seconds(1)).to_rfc3339();
    let time_b = (prev_tx_time + Duration::seconds(2)).to_rfc3339();

    // Pfad A (wird zuerst erfolgreich empfangen)
    let mut tx_a = voucher_lib::models::voucher::Transaction {
        prev_hash: prev_tx_hash.clone(), t_type: "transfer".to_string(), t_time: time_a,
        sender_id: id_alice.clone(), recipient_id: id_david.clone(), amount: "100".to_string(), ..Default::default()
    };
    tx_a = resign_transaction(tx_a, &identity_alice.signing_key);
    let mut voucher_path_a = voucher_v1.clone();
    voucher_path_a.transactions.push(tx_a);
    let bundle_a = voucher_lib::test_utils::create_test_bundle(&identity_alice, vec![voucher_path_a], &id_david, None).unwrap();

    // Pfad B (löst den Konflikt aus)
    let mut tx_b = voucher_lib::models::voucher::Transaction {
        prev_hash: prev_tx_hash, t_type: "transfer".to_string(), t_time: time_b,
        sender_id: id_alice.clone(), recipient_id: id_david.clone(), amount: "100".to_string(), ..Default::default()
    };
    tx_b = resign_transaction(tx_b, &identity_alice.signing_key);
    let mut voucher_path_b = voucher_v1.clone();
    voucher_path_b.transactions.push(tx_b);
    let bundle_b = voucher_lib::test_utils::create_test_bundle(&identity_alice, vec![voucher_path_b], &id_david, None).unwrap();

    // David empfängt Pfad A erfolgreich
    service_david.receive_bundle(&bundle_a, &standards_map, None, correct_password).unwrap();
    assert_eq!(service_david.get_voucher_summaries(None, None).unwrap().len(), 1);
    assert!(service_david.list_conflicts().unwrap().is_empty());

    // 2. ACT: David versucht, das konfliktreiche Bundle B mit falschem Passwort zu empfangen.
    let result = service_david.receive_bundle(&bundle_b, &standards_map, None, wrong_password);

    // 3. ASSERT: Operation schlägt fehl, Zustand wird komplett zurückgesetzt.
    assert!(result.is_err(), "Receive should fail on conflict + save error");

    let summaries_after = service_david.get_voucher_summaries(None, None).unwrap();
    assert_eq!(summaries_after.len(), 1, "Should only contain the original voucher from path A");
    assert_eq!(summaries_after[0].status, VoucherStatus::Active, "Original voucher should remain active");

    let conflicts_after = service_david.list_conflicts().unwrap();
    assert!(conflicts_after.is_empty(), "No conflict proof should be left in memory after failed operation");
}