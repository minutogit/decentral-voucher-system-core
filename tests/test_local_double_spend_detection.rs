//! # tests/test_local_double_spend_detection.rs
//!
//! Umfassende Test-Suite für die lokale Double-Spending-Erkennung.
//!
//! Diese Datei enthält:
//! 1.  **Unit-Tests:** Überprüfen die Kernkomponenten der Fingerprint-Verwaltung
//!     in Isolation (Generierung, Austausch, Konflikterkennung, Aufräumen).
//! 2.  **Integrationstest:** Simuliert ein vollständiges End-to-End-Szenario,
//!     bei dem ein Betrug begangen und vom System korrekt erkannt und behandelt wird.

use std::fs;
use std::path::Path;
use voucher_lib::models::fingerprint::TransactionFingerprint;
use voucher_lib::models::profile::{UserIdentity, VoucherStatus};
use voucher_lib::models::voucher::{Address, Collateral, Creator, NominalValue, Voucher};
use voucher_lib::services::crypto_utils::{create_user_id, get_hash};
use voucher_lib::services::utils::get_current_timestamp;
use voucher_lib::services::voucher_manager::{self, NewVoucherData};
use voucher_lib::storage::AuthMethod;
use voucher_lib::FileStorage;
use voucher_lib::wallet::Wallet;

// ===================================================================================
// HILFSFUNKTIONEN
// ===================================================================================

/// Erstellt eine `UserIdentity` aus einer Mnemonic-Phrase.
fn identity_from_mnemonic(mnemonic: &str) -> UserIdentity {
    let (public_key, signing_key) =
        voucher_lib::services::crypto_utils::derive_ed25519_keypair(mnemonic, None);
    let user_id = create_user_id(&public_key, Some("te")).unwrap();
    UserIdentity {
        signing_key,
        public_key,
        user_id,
    }
}

/// Initialisiert einen neuen Akteur mit Wallet und Speicher.
fn setup_actor(
    name: &str,
    storage_dir: &Path,
) -> (Wallet, UserIdentity) {
    let mnemonic = voucher_lib::services::crypto_utils::generate_mnemonic(12, Default::default()).unwrap();
    let mut storage = FileStorage::new(storage_dir.join(name));
    let password = "password123";

    let identity = identity_from_mnemonic(&mnemonic);
    let (wallet, _) = Wallet::new_from_mnemonic(&mnemonic, Some("te")).unwrap();
    wallet.save(&mut storage, &identity, password).unwrap();

    let auth = AuthMethod::Password(password);
    let loaded_wallet = Wallet::load(&storage, &auth, identity_from_mnemonic(&mnemonic)).unwrap();

    (loaded_wallet, identity_from_mnemonic(&mnemonic))
}

/// Extrahiert den einzigen Gutschein aus dem Wallet eines Akteurs.
fn get_voucher_from_wallet(wallet: &Wallet) -> Voucher {
    assert_eq!(wallet.voucher_store.vouchers.len(), 1, "Expected exactly one voucher in the wallet");
    wallet.voucher_store.vouchers.values().next().unwrap().0.clone()
}

/// Lädt die Standard-Definition.
fn load_test_standard() -> voucher_lib::models::voucher_standard_definition::VoucherStandardDefinition {
    let standard_toml = fs::read_to_string("voucher_standards/silver_standard.toml").unwrap();
    voucher_manager::load_standard_definition(&standard_toml).unwrap()
}

/// Erstellt einen leeren Fingerprint für Testzwecke.
fn new_dummy_fingerprint(t_id: &str) -> TransactionFingerprint {
    TransactionFingerprint {
        prvhash_senderid_hash: "".to_string(),
        t_id: t_id.to_string(),
        t_time: get_current_timestamp(),
        sender_signature: "".to_string(),
        valid_until: "2099-12-31T23:59:59.999999Z".to_string(),
    }
}

/// Erstellt leere `NewVoucherData` für Testzwecke.
fn new_test_voucher_data(creator_id: String) -> NewVoucherData {
    NewVoucherData {
        validity_duration: Some("P5Y".to_string()),
        non_redeemable_test_voucher: false,
        nominal_value: NominalValue {
            amount: "100".to_string(),
            unit: String::new(),
            abbreviation: String::new(),
            description: String::new(),
        },
        collateral: Collateral::default(),
        creator: Creator {
            id: creator_id,
            first_name: String::new(),
            last_name: String::new(),
            address: Address::default(),
            organization: Some(String::new()),
            community: Some(String::new()),
            phone: Some(String::new()),
            email: Some(String::new()),
            url: Some(String::new()),
            gender: String::new(),
            service_offer: Some(String::new()),
            needs: Some(String::new()),
            signature: String::new(),
            coordinates: String::new(),
        },
    }
}

// ===================================================================================
// UNIT-TESTS ("VORTESTS")
// ===================================================================================

#[test]
fn test_fingerprint_generation() {
    let temp_dir = tempfile::tempdir().unwrap();
    let (mut wallet, identity) = setup_actor("test_user", temp_dir.path());
    let standard = load_test_standard();

    // Erstelle einen Gutschein mit 2 Transaktionen (init + transfer)
    let voucher_data = new_test_voucher_data(identity.user_id.clone());
    let mut voucher = voucher_manager::create_voucher(voucher_data, &standard, &identity.signing_key).unwrap();
    voucher = voucher_manager::create_transaction(&voucher, &standard, &identity.user_id, &identity.signing_key, "recipient_id", "50").unwrap();
    wallet.add_voucher_to_store(voucher.clone(), VoucherStatus::Active, &identity.user_id).unwrap();

    // Aktion
    wallet.scan_and_update_own_fingerprints().unwrap();

    // Assertions
    assert_eq!(wallet.fingerprint_store.own_fingerprints.values().map(|v| v.len()).sum::<usize>(), 2, "Es sollten Fingerprints für 2 Transaktionen existieren.");

    let tx1 = &voucher.transactions[0];
    let expected_hash1 = get_hash(format!("{}{}", tx1.prev_hash, tx1.sender_id));
    assert!(wallet.fingerprint_store.own_fingerprints.contains_key(&expected_hash1), "Fingerprint für die init-Transaktion fehlt.");
    assert_eq!(wallet.fingerprint_store.own_fingerprints.get(&expected_hash1).unwrap()[0].valid_until, voucher.valid_until);
}

#[test]
fn test_fingerprint_exchange() {
    let temp_dir = tempfile::tempdir().unwrap();
    let (mut sender_wallet, _) = setup_actor("sender", temp_dir.path());
    let (mut receiver_wallet, _) = setup_actor("receiver", temp_dir.path());

    // Setup: Erzeuge Fingerprints im Sender-Wallet
    let mut fp1 = new_dummy_fingerprint("t1");
    fp1.prvhash_senderid_hash = "hash1".to_string();
    sender_wallet.fingerprint_store.own_fingerprints.insert("hash1".to_string(), vec![fp1]);

    // Aktion
    let exported_data = sender_wallet.export_own_fingerprints().unwrap();
    let import_count1 = receiver_wallet.import_foreign_fingerprints(&exported_data).unwrap();
    let import_count2 = receiver_wallet.import_foreign_fingerprints(&exported_data).unwrap();

    // Assertions
    assert_eq!(import_count1, 1, "Der erste Import sollte einen neuen Fingerprint hinzufügen.");
    assert_eq!(import_count2, 0, "Der zweite Import sollte keinen neuen Fingerprint hinzufügen.");
    assert!(receiver_wallet.fingerprint_store.own_fingerprints.is_empty(), "Die eigenen Fingerprints des Empfängers sollten leer sein.");
    assert_eq!(receiver_wallet.fingerprint_store.foreign_fingerprints.len(), 1, "Die fremden Fingerprints des Empfängers sollten einen Eintrag enthalten.");
}

#[test]
fn test_conflict_classification() {
    let temp_dir = tempfile::tempdir().unwrap();
    let (mut wallet, _) = setup_actor("test_user", temp_dir.path());

    let conflict_hash = "shared_hash".to_string();
    let fp1 = new_dummy_fingerprint("t_id_1");
    let fp2 = new_dummy_fingerprint("t_id_2");

    // Fall A: Verifizierbarer Konflikt
    wallet.fingerprint_store.own_fingerprints.insert(conflict_hash.clone(), vec![fp1.clone()]);
    wallet.fingerprint_store.foreign_fingerprints.insert(conflict_hash.clone(), vec![fp2.clone()]);

    let result_a = wallet.check_for_double_spend();
    assert_eq!(result_a.verifiable_conflicts.len(), 1, "Fall A: Ein verifizierbarer Konflikt muss erkannt werden.");
    assert!(result_a.unverifiable_warnings.is_empty(), "Fall A: Es sollte keine unverifizierbaren Warnungen geben.");

    // Fall B: Nicht verifizierbarer Konflikt
    wallet.fingerprint_store.own_fingerprints.clear();
    wallet.fingerprint_store.foreign_fingerprints.insert(conflict_hash.clone(), vec![fp1, fp2]);

    let result_b = wallet.check_for_double_spend();
    assert_eq!(result_b.unverifiable_warnings.len(), 1, "Fall B: Eine unverifizierbare Warnung muss erkannt werden.");
    assert!(result_b.verifiable_conflicts.is_empty(), "Fall B: Es sollte keine verifizierbaren Konflikte geben.");
}

#[test]
fn test_cleanup_expired_fingerprints() {
    let temp_dir = tempfile::tempdir().unwrap();
    let (mut wallet, _) = setup_actor("test_user", temp_dir.path());

    let mut expired_fp = new_dummy_fingerprint("t1");
    expired_fp.valid_until = "2020-01-01T00:00:00Z".to_string();
    let valid_fp = new_dummy_fingerprint("t2");

    wallet.fingerprint_store.own_fingerprints.insert("expired".to_string(), vec![expired_fp]);
    wallet.fingerprint_store.own_fingerprints.insert("valid".to_string(), vec![valid_fp]);

    // Aktion
    wallet.cleanup_expired_fingerprints();

    // Assertions
    assert!(!wallet.fingerprint_store.own_fingerprints.contains_key("expired"), "Der abgelaufene Fingerprint sollte entfernt werden.");
    assert!(wallet.fingerprint_store.own_fingerprints.contains_key("valid"), "Der gültige Fingerprint sollte erhalten bleiben.");
    assert_eq!(wallet.fingerprint_store.own_fingerprints.len(), 1);
}

// ===================================================================================
// INTEGRATIONSTEST
// ===================================================================================

#[test]
fn test_local_double_spend_detection_lifecycle() {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_path = temp_dir.path();
    let standard = load_test_standard();

    // ### Akt 1: Initialisierung & Erster Transfer ###
    println!("--- Akt 1: Alice erstellt einen Gutschein und sendet ihn an Bob ---");

    let (mut alice_wallet, alice_identity) = setup_actor("alice", storage_path);
    let (mut bob_wallet, bob_identity) = setup_actor("bob", storage_path);

    let voucher_data = new_test_voucher_data(alice_identity.user_id.clone());
    let initial_voucher = voucher_manager::create_voucher(voucher_data, &standard, &alice_identity.signing_key).unwrap();
    alice_wallet.add_voucher_to_store(initial_voucher.clone(), VoucherStatus::Active, &alice_identity.user_id).unwrap();

    let voucher_for_bob = voucher_manager::create_transaction(
        &initial_voucher,
        &standard,
        &alice_identity.user_id,
        &alice_identity.signing_key,
        &bob_identity.user_id,
        "100",
    ).unwrap();

    let bundle_to_bob = alice_wallet.create_and_encrypt_transaction_bundle(&alice_identity, vec![voucher_for_bob], &bob_identity.user_id, None).unwrap();
    bob_wallet.process_encrypted_transaction_bundle(&bob_identity, &bundle_to_bob).unwrap();

    assert_eq!(alice_wallet.voucher_store.vouchers.len(), 1, "Alices Wallet muss den gesendeten Gutschein als 'Archived' behalten.");
    let (_, status) = alice_wallet.voucher_store.vouchers.values().next().unwrap();
    assert_eq!(*status, VoucherStatus::Archived, "Der Status von Alices Gutschein muss 'Archived' sein.");
    assert_eq!(bob_wallet.voucher_store.vouchers.values().next().unwrap().1, VoucherStatus::Active);

    // ### Akt 2: Der Double Spend ###
    println!("--- Akt 2: Bob begeht einen Double Spend an Charlie und David ---");

    let (mut charlie_wallet, charlie_identity) = setup_actor("charlie", storage_path);
    let (mut david_wallet, david_identity) = setup_actor("david", storage_path);
    let voucher_from_bob = get_voucher_from_wallet(&bob_wallet);

    let voucher_for_charlie = voucher_manager::create_transaction(&voucher_from_bob, &standard, &bob_identity.user_id, &bob_identity.signing_key, &charlie_identity.user_id, "100").unwrap();
    let voucher_for_david = voucher_manager::create_transaction(&voucher_from_bob, &standard, &bob_identity.user_id, &bob_identity.signing_key, &david_identity.user_id, "100").unwrap();

    let bundle_to_charlie = bob_wallet.create_and_encrypt_transaction_bundle(&bob_identity, vec![voucher_for_charlie.clone()], &charlie_identity.user_id, None).unwrap();
    charlie_wallet.process_encrypted_transaction_bundle(&charlie_identity, &bundle_to_charlie).unwrap();

    bob_wallet.add_voucher_to_store(voucher_from_bob, VoucherStatus::Active, &bob_identity.user_id).unwrap();
    let bundle_to_david = bob_wallet.create_and_encrypt_transaction_bundle(&bob_identity, vec![voucher_for_david.clone()], &david_identity.user_id, None).unwrap();
    david_wallet.process_encrypted_transaction_bundle(&david_identity, &bundle_to_david).unwrap();

    assert_eq!(charlie_wallet.voucher_store.vouchers.len(), 1);
    assert_eq!(david_wallet.voucher_store.vouchers.len(), 1);

    // ### Akt 3: Die Rückkehr (Teil 1) ###
    println!("--- Akt 3: Charlie sendet seine Version zurück an Alice ---");

    let voucher_from_charlie_to_alice = voucher_manager::create_transaction(
        &voucher_for_charlie, &standard, &charlie_identity.user_id, &charlie_identity.signing_key, &alice_identity.user_id, "100"
    ).unwrap();
    let bundle_to_alice_1 = charlie_wallet.create_and_encrypt_transaction_bundle(&charlie_identity, vec![voucher_from_charlie_to_alice], &alice_identity.user_id, None).unwrap();

    println!("\n[Debug Test] Alices Wallet VOR dem Empfang von Charlie:");
    for (id, (voucher, status)) in &alice_wallet.voucher_store.vouchers {
        println!("  -> Vorhanden: ID={}, Status={:?}, Tx-Anzahl={}", id, status, voucher.transactions.len());
    }
    println!("[Debug Test] Verarbeite jetzt Bündel von Charlie...");

    let result1 = alice_wallet.process_encrypted_transaction_bundle(&alice_identity, &bundle_to_alice_1).unwrap();
    assert_eq!(alice_wallet.voucher_store.vouchers.len(), 2, "Alice muss jetzt einen 'Archived' und einen 'Active' Gutschein haben.");
    assert!(result1.check_result.verifiable_conflicts.is_empty(), "Nach dem ersten zurückerhaltenen Gutschein darf es noch keinen Konflikt geben.");

    // ### Akt 4: Die Aufdeckung ###
    println!("--- Akt 4: David sendet seine widersprüchliche Version an Alice. Der Betrug wird aufgedeckt. ---");

    let (active_local_id, _) = alice_wallet.voucher_store.vouchers.iter()
        .find(|(_, (_, status))| *status == VoucherStatus::Active)
        .expect("Alice sollte einen aktiven Gutschein haben.").clone();
    let active_local_id_clone = active_local_id.clone();

    let voucher_from_david_to_alice = voucher_manager::create_transaction(
        &voucher_for_david, &standard, &david_identity.user_id, &david_identity.signing_key, &alice_identity.user_id, "100"
    ).unwrap();
    let bundle_to_alice_2 = david_wallet.create_and_encrypt_transaction_bundle(&david_identity, vec![voucher_from_david_to_alice], &alice_identity.user_id, None).unwrap();

    let result2 = alice_wallet.process_encrypted_transaction_bundle(&alice_identity, &bundle_to_alice_2).unwrap();

    // Assertions
    assert_eq!(result2.check_result.verifiable_conflicts.len(), 1, "Ein verifizierbarer Konflikt MUSS erkannt worden sein.");

    let (_final_voucher, final_status) = alice_wallet.voucher_store.vouchers.get(&active_local_id_clone).unwrap();
    assert_eq!(*final_status, VoucherStatus::Quarantined, "Der ursprünglich von Charlie erhaltene Gutschein MUSS jetzt unter Quarantäne stehen!");

    assert_eq!(alice_wallet.voucher_store.vouchers.len(), 3, "Alices Wallet sollte am Ende drei Instanzen des Gutscheins enthalten.");

    let quarantined_voucher = alice_wallet.voucher_store.vouchers.get(&active_local_id_clone).unwrap().0.clone();
    let transfer_attempt = alice_wallet.create_and_encrypt_transaction_bundle(&alice_identity, vec![quarantined_voucher], &bob_identity.user_id, None);
    assert!(transfer_attempt.is_err(), "Die Verwendung eines unter Quarantäne stehenden Gutscheins muss fehlschlagen.");

    println!("Test erfolgreich: Double Spend wurde erkannt und der kompromittierte Gutschein gesperrt.");
}