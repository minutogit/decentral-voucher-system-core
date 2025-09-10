//! # tests/test_local_double_spend_detection.rs
//!
//! Umfassende Test-Suite für die lokale Double-Spending-Erkennung.
//!
//! Diese Datei enthält:
//! 1.  **Unit-Tests:** Überprüfen die Kernkomponenten der Fingerprint-Verwaltung
//!     in Isolation (Generierung, Austausch, Konflikterkennung, Aufräumen).
//! 2.  **Integrationstest:** Simuliert ein vollständiges End-to-End-Szenario,
//!     bei dem ein Betrug begangen und vom System korrekt erkannt und behandelt wird.

mod test_utils;

use voucher_lib::archive::file_archive::FileVoucherArchive;
use chrono::{DateTime, Datelike, NaiveDate, SecondsFormat};
use std::path::Path;
use test_utils::{setup_in_memory_wallet, ACTORS, SILVER_STANDARD};
use voucher_lib::models::conflict::TransactionFingerprint; 
use voucher_lib::{UserIdentity, VoucherStatus};
use voucher_lib::models::voucher::{Address, Collateral, Creator, NominalValue, Voucher};
use voucher_lib::services::crypto_utils::{get_hash};
use voucher_lib::services::voucher_manager::{self, NewVoucherData};
use voucher_lib::wallet::Wallet;

// ===================================================================================
// HILFSFUNKTIONEN
// ===================================================================================

/// Erstellt für einen Test ein frisches, leeres Wallet für eine vordefinierte Identität.
/// Stellt die Test-Isolation durch separates Speichern sicher.
fn setup_test_wallet(identity: &UserIdentity, _name: &str, _storage_dir: &Path) -> Wallet {
    setup_in_memory_wallet(identity)
}

/// Extrahiert den einzigen Gutschein aus dem Wallet eines Akteurs.
fn get_voucher_from_wallet(wallet: &Wallet) -> Voucher {
    assert_eq!(wallet.voucher_store.vouchers.len(), 1, "Expected exactly one voucher in the wallet");
    wallet.voucher_store.vouchers.values().next().unwrap().0.clone()
}

/// Erstellt einen leeren Fingerprint für Testzwecke.
fn new_dummy_fingerprint(t_id: &str) -> TransactionFingerprint {
    TransactionFingerprint {
        prvhash_senderid_hash: "".to_string(),
        t_id: t_id.to_string(),
        encrypted_timestamp: 0,
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
    let _temp_dir = tempfile::tempdir().unwrap();
    let identity = &ACTORS.test_user;
    let mut wallet = setup_in_memory_wallet(identity);

    // Erstelle einen Gutschein mit 2 Transaktionen (init + transfer)
    let voucher_data = new_test_voucher_data(identity.user_id.clone());
    // create_voucher erwartet den &SigningKey, nicht die ganze Identity.
    let mut voucher = voucher_manager::create_voucher(voucher_data, &SILVER_STANDARD, &identity.signing_key).unwrap();
    voucher = voucher_manager::create_transaction(&voucher, &SILVER_STANDARD, &identity.user_id, &identity.signing_key, "recipient_id", "50").unwrap();
    wallet.add_voucher_to_store(voucher.clone(), VoucherStatus::Active, &identity.user_id).unwrap();

    // Aktion
    wallet.scan_and_update_own_fingerprints().unwrap();

    // Assertions
    assert_eq!(wallet.fingerprint_store.own_fingerprints.values().map(|v| v.len()).sum::<usize>(), 2, "Es sollten Fingerprints für 2 Transaktionen existieren.");

    let tx1 = &voucher.transactions[0];
    let expected_hash1 = get_hash(format!("{}{}", tx1.prev_hash, tx1.sender_id));
    assert!(wallet.fingerprint_store.own_fingerprints.contains_key(&expected_hash1), "Fingerprint für die init-Transaktion fehlt.");

    // Berechne den erwarteten, auf das Monatsende gerundeten `valid_until`-Wert.
    let expected_rounded_valid_until = {
        let parsed_date = DateTime::parse_from_rfc3339(&voucher.valid_until).unwrap();
        let year = parsed_date.year();
        let month = parsed_date.month();
        let first_of_next_month = if month == 12 {
            NaiveDate::from_ymd_opt(year + 1, 1, 1).unwrap()
        } else {
            NaiveDate::from_ymd_opt(year, month + 1, 1).unwrap()
        };
        let last_day_of_month = first_of_next_month.pred_opt().unwrap();
        let end_of_month_dt = last_day_of_month.and_hms_micro_opt(23, 59, 59, 999999).unwrap().and_utc();
        end_of_month_dt.to_rfc3339_opts(SecondsFormat::Micros, true)
    };

    assert_eq!(wallet.fingerprint_store.own_fingerprints.get(&expected_hash1).unwrap()[0].valid_until, expected_rounded_valid_until, "Der valid_until-Wert im Fingerprint muss dem auf das Monatsende gerundeten Wert entsprechen.");
}

#[test]
fn test_fingerprint_exchange() {
    let mut sender_wallet = setup_in_memory_wallet(&ACTORS.sender);
    let mut receiver_wallet = setup_in_memory_wallet(&ACTORS.recipient1);

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
    let mut wallet = setup_in_memory_wallet(&ACTORS.test_user);

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
    let mut wallet = setup_in_memory_wallet(&ACTORS.test_user);

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
// PROACTIVE PREVENTION TEST
// ===================================================================================

#[test]
fn test_proactive_double_spend_prevention_in_wallet() {
    // ### Setup ###
    // Erstellt einen Sender und zwei potenzielle Empfänger.
    let _temp_dir = tempfile::tempdir().unwrap();

    let sender_identity = &ACTORS.sender;
    let mut sender_wallet = setup_in_memory_wallet(sender_identity);
    let recipient1_identity = &ACTORS.recipient1;
    let recipient2_identity = &ACTORS.recipient2;

    // Sender erhält einen initialen Gutschein.
    let voucher_data = new_test_voucher_data(sender_identity.user_id.clone());
    let initial_voucher = voucher_manager::create_voucher(voucher_data, &SILVER_STANDARD, &sender_identity.signing_key).unwrap();
    // Wir klonen den Gutschein hier, damit die 'initial_voucher'-Variable für den späteren Test gültig bleibt.
    sender_wallet.add_voucher_to_store(initial_voucher.clone(), VoucherStatus::Active, &sender_identity.user_id).unwrap();
    let initial_local_id = sender_wallet.voucher_store.vouchers.keys().next().unwrap().clone();

    // ### Akt 1: Legitime Transaktion ###
    // Sender sendet den Gutschein an Empfänger 1.
    // Dies sollte erfolgreich sein und den Fingerprint der Transaktion im Wallet des Senders speichern.
    let transfer1_result = sender_wallet.create_transfer(
        sender_identity,
        &SILVER_STANDARD,
        &initial_local_id,
        &recipient1_identity.user_id,
        "100",
        None,
        None,
    );
    assert!(transfer1_result.is_ok(), "Die erste Transaktion sollte erfolgreich sein.");
    assert_eq!(sender_wallet.fingerprint_store.own_fingerprints.len(), 1, "Ein Fingerprint sollte nach der ersten Transaktion existieren.");

    // ### Akt 2: Manuelle Manipulation für einen Betrugsversuch ###
    // Wir simulieren, dass der Sender versucht, denselben ursprünglichen Gutschein-Zustand erneut auszugeben.
    // Da create_transfer die ursprüngliche Instanz (`initial_local_id`) entfernt hat, fügen wir sie manuell
    // wieder hinzu. Dies ahmt einen Angreifer nach, der einen alten Wallet-Zustand wiederherstellt. 
    sender_wallet.add_voucher_to_store(initial_voucher, VoucherStatus::Active, &sender_identity.user_id).unwrap();

    // ### Akt 3: Der blockierte Double-Spend-Versuch ###
    // Sender versucht, den wiederhergestellten, ursprünglichen Gutschein an Empfänger 2 zu senden.
    // Dies MUSS fehlschlagen, weil `create_transfer` den existierenden Fingerprint aus der ersten Transaktion erkennt.
    let transfer2_result = sender_wallet.create_transfer(
        sender_identity,
        &SILVER_STANDARD,
        &initial_local_id, // Wichtig: Dieselbe lokale ID wird wiederverwendet
        &recipient2_identity.user_id,
        "100",
        None,
        None,
    );

    assert!(transfer2_result.is_err(), "Die zweite Transaktion von demselben Zustand aus muss fehlschlagen.");
    matches!(transfer2_result.err().unwrap(), voucher_lib::VoucherCoreError::DoubleSpendAttemptBlocked);
}

// ===================================================================================
// INTEGRATIONSTEST
// ===================================================================================

#[test]
fn test_local_double_spend_detection_lifecycle() {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_path = temp_dir.path();
    let archive = FileVoucherArchive::new(storage_path.join("archive"));

    // ### Akt 1: Initialisierung & Erster Transfer ###
    println!("--- Akt 1: Alice erstellt einen Gutschein und sendet ihn an Bob ---");

    let alice_identity = &ACTORS.alice;
    let bob_identity = &ACTORS.bob;
    let mut alice_wallet = setup_test_wallet(alice_identity, "alice", storage_path);
    let mut bob_wallet = setup_test_wallet(bob_identity, "bob", storage_path);

    let voucher_data = new_test_voucher_data(alice_identity.user_id.clone());
    let initial_voucher = voucher_manager::create_voucher(voucher_data, &SILVER_STANDARD, &alice_identity.signing_key).unwrap();
    alice_wallet.add_voucher_to_store(initial_voucher, VoucherStatus::Active, &alice_identity.user_id).unwrap();

    // Alice verwendet die neue, korrekte Methode, um den Gutschein an Bob zu senden.
    // Wir klonen die ID, um den immutable borrow auf alice_wallet sofort zu beenden.
    let alice_initial_local_id = alice_wallet.voucher_store.vouchers.keys().next().unwrap().clone();
    let (bundle_to_bob, _) = alice_wallet.create_transfer(
        alice_identity,
        &SILVER_STANDARD,
        &alice_initial_local_id,
        &bob_identity.user_id,
        "100",
        None,
        Some(&archive),
    ).unwrap();
    bob_wallet.process_encrypted_transaction_bundle(bob_identity, &bundle_to_bob, Some(&archive)).unwrap();

    assert_eq!(alice_wallet.voucher_store.vouchers.len(), 1, "Alices Wallet muss den gesendeten Gutschein als 'Archived' behalten.");
    let (_, status) = alice_wallet.voucher_store.vouchers.values().next().unwrap();
    assert_eq!(*status, VoucherStatus::Archived, "Der Status von Alices Gutschein muss 'Archived' sein.");
    assert_eq!(bob_wallet.voucher_store.vouchers.values().next().unwrap().1, VoucherStatus::Active);

    // ### Akt 2: Der Double Spend ###
    println!("--- Akt 2: Bob begeht einen Double Spend an Charlie und David ---");

    let charlie_identity = &ACTORS.charlie;
    let david_identity = &ACTORS.david;
    let mut charlie_wallet = setup_test_wallet(charlie_identity, "charlie", storage_path);
    let mut david_wallet = setup_test_wallet(david_identity, "david", storage_path);
    let voucher_from_bob = get_voucher_from_wallet(&bob_wallet);

    // Bob agiert böswillig. Er umgeht die Schutzmechanismen seines Wallets (create_transfer würde das blockieren)
    // und erstellt manuell zwei widersprüchliche Transaktionen aus demselben Zustand.
    // Wichtig: Wir fügen eine kleine Verzögerung ein, um sicherzustellen, dass die Zeitstempel
    // der betrügerischen Transaktionen deterministisch unterscheidbar sind.
    let voucher_for_charlie = voucher_manager::create_transaction(&voucher_from_bob, &SILVER_STANDARD, &bob_identity.user_id, &bob_identity.signing_key, &charlie_identity.user_id, "100").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(10));
    let voucher_for_david = voucher_manager::create_transaction(&voucher_from_bob, &SILVER_STANDARD, &bob_identity.user_id, &bob_identity.signing_key, &david_identity.user_id, "100").unwrap();

    // Wir merken uns die IDs der beiden widersprüchlichen Transaktionen.
    let winning_tx_id = voucher_for_charlie.transactions.last().unwrap().t_id.clone();
    let losing_tx_id = voucher_for_david.transactions.last().unwrap().t_id.clone();

    // Er verpackt und sendet die erste betrügerische Version an Charlie. Hierfür nutzt er die alte Methode.
    let bundle_to_charlie = bob_wallet.create_and_encrypt_transaction_bundle(bob_identity, vec![voucher_for_charlie.clone()], &charlie_identity.user_id, None).unwrap();
    charlie_wallet.process_encrypted_transaction_bundle(charlie_identity, &bundle_to_charlie, Some(&archive)).unwrap();

    // Um den zweiten Betrug zu ermöglichen, setzt er den Zustand seines Wallets künstlich zurück.
    bob_wallet.add_voucher_to_store(voucher_from_bob, VoucherStatus::Active, &bob_identity.user_id).unwrap();
    let bundle_to_david = bob_wallet.create_and_encrypt_transaction_bundle(bob_identity, vec![voucher_for_david.clone()], &david_identity.user_id, None).unwrap();
    david_wallet.process_encrypted_transaction_bundle(david_identity, &bundle_to_david, Some(&archive)).unwrap();

    assert_eq!(charlie_wallet.voucher_store.vouchers.len(), 1);
    assert_eq!(david_wallet.voucher_store.vouchers.len(), 1);

    // ### Akt 3: Die Rückkehr (Teil 1) ###
    println!("--- Akt 3: Charlie sendet seine Version zurück an Alice ---");

    // Charlie handelt legitim und verwendet die korrekte `create_transfer` Methode.
    // Wir klonen die ID, um den immutable borrow auf charlie_wallet sofort zu beenden.
    let charlie_local_id = charlie_wallet.voucher_store.vouchers.keys().next().unwrap().clone();
    let (bundle_to_alice_1, _) = charlie_wallet.create_transfer(
        charlie_identity,
        &SILVER_STANDARD,
        &charlie_local_id,
        &alice_identity.user_id,
        "100",
        None,
        Some(&archive)
    ).unwrap();

    println!("\n[Debug Test] Alices Wallet VOR dem Empfang von Charlie:");
    for (id, (voucher, status)) in &alice_wallet.voucher_store.vouchers {
        println!("  -> Vorhanden: ID={}, Status={:?}, Tx-Anzahl={}", id, status, voucher.transactions.len());
    }
    println!("[Debug Test] Verarbeite jetzt Bündel von Charlie...");

    let result1 = alice_wallet
        .process_encrypted_transaction_bundle(alice_identity, &bundle_to_alice_1, Some(&archive))
        .unwrap();
    assert_eq!(alice_wallet.voucher_store.vouchers.len(), 2, "Alice muss jetzt einen 'Archived' und einen 'Active' Gutschein haben.");
    assert!(result1.check_result.verifiable_conflicts.is_empty(), "Nach dem ersten zurückerhaltenen Gutschein darf es noch keinen Konflikt geben.");

    // ### Akt 4: Die Aufdeckung ###
    println!("--- Akt 4: David sendet seine widersprüchliche Version an Alice. Der Betrug wird aufgedeckt. ---");

    // David handelt ebenfalls legitim (aus seiner Sicht) und verwendet `create_transfer`.
    // Wir klonen die ID, um den immutable borrow auf david_wallet sofort zu beenden.
    let david_local_id = david_wallet.voucher_store.vouchers.keys().next().unwrap().clone();
    let (bundle_to_alice_2, _) = david_wallet.create_transfer(
        david_identity,
        &SILVER_STANDARD,
        &david_local_id,
        &alice_identity.user_id,
        "100",
        None,
        Some(&archive)
    ).unwrap();

    let result2 = alice_wallet
        .process_encrypted_transaction_bundle(alice_identity, &bundle_to_alice_2, Some(&archive))
        .unwrap();

    // Assertions
    assert_eq!(result2.check_result.verifiable_conflicts.len(), 1, "Ein verifizierbarer Konflikt MUSS erkannt worden sein.");
    assert_eq!(alice_wallet.voucher_store.vouchers.len(), 3, "Alices Wallet sollte am Ende drei Instanzen des Gutscheins enthalten.");

    // ### Akt 5: Überprüfung der intelligenten Konfliktlösung ###
    println!("--- Akt 5: Überprüfe, ob die korrekte Gutschein-Instanz aktiv geblieben ist ---");

    let mut winner_status: Option<VoucherStatus> = None;
    let mut loser_status: Option<VoucherStatus> = None;
    let mut loser_local_id: Option<String> = None;

    // Finde die beiden konkurrierenden Gutschein-Instanzen in Alices Wallet und prüfe ihren Status.
    // Wir müssen die gesamte Transaktionskette durchsuchen, nicht nur die letzte Transaktion.
    for (local_id, (voucher, status)) in &alice_wallet.voucher_store.vouchers {
        // Prüfe, ob die Gewinner-Transaktion Teil der Historie dieses Gutscheins ist.
        if voucher.transactions.iter().any(|tx| tx.t_id == winning_tx_id) {
            winner_status = Some(status.clone());
        }
        // Prüfe, ob die Verlierer-Transaktion Teil der Historie dieses Gutscheins ist.
        if voucher.transactions.iter().any(|tx| tx.t_id == losing_tx_id) {
            loser_status = Some(status.clone());
            loser_local_id = Some(local_id.clone());
        }
    }

    assert_eq!(winner_status, Some(VoucherStatus::Active), "Die 'Gewinner'-Instanz (von Charlie, weil früher) muss aktiv bleiben.");
    assert_eq!(loser_status, Some(VoucherStatus::Quarantined), "Die 'Verlierer'-Instanz (von David, weil später) muss unter Quarantäne gestellt werden.");

    // Der Versuch, den unter Quarantäne stehenden Gutschein (die 'Verlierer'-Instanz) auszugeben, muss fehlschlagen.
    let transfer_attempt = alice_wallet.create_transfer(
        alice_identity,
        &SILVER_STANDARD,
        &loser_local_id.unwrap(),
        &bob_identity.user_id,
        "100", None, // notes
        Some(&archive) // archive
    );
    assert!(transfer_attempt.is_err(), "Die Verwendung eines unter Quarantäne stehenden Gutscheins via create_transfer muss fehlschlagen.");

    println!("Test erfolgreich: Double Spend wurde erkannt, und die 'Der Früheste gewinnt'-Regel wurde korrekt angewendet.");
}
