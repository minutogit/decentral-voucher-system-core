//! # tests/wallet_api/state_management.rs
//!
//! Enthält Integrationstests für komplexes State-Management und die
//! Handhabung von Konflikten wie Double-Spending.

use voucher_lib::test_utils::{
    create_test_bundle, generate_signed_standard_toml, generate_valid_mnemonic, resign_transaction,
    ACTORS, SILVER_STANDARD,
};
use voucher_lib::models::voucher::Transaction;
use voucher_lib::services::utils;
use voucher_lib::{
    app_service::AppService,
    models::voucher::{Creator, NominalValue},
    services::{crypto_utils, voucher_manager::NewVoucherData},
    VoucherStatus,
};

use chrono::DateTime;
use chrono::{Duration, Utc};
use std::collections::HashMap;
use tempfile::tempdir;

/// Test 1.1: Testet die reaktive Double-Spend-Erkennung via "Earliest Wins"-Heuristik.
///
/// ### Szenario:
/// 1.  Alice erstellt einen Gutschein (Zustand V1).
/// 2.  Sie erzeugt zwei widersprüchliche Transaktionen aus V1:
///     - TX_A (früherer Zeitstempel): Sendet den vollen Betrag an Bob -> V2_BOB.
///     - TX_B (späterer Zeitstempel): Sendet den vollen Betrag an Charlie -> V2_CHARLIE.
/// 3.  Ein neues Wallet für David wird erstellt.
/// 4.  David empfängt zuerst das Bundle mit V2_CHARLIE (spätere Transaktion). Der Gutschein
///     wird als `Active` hinzugefügt.
/// 5.  David empfängt danach das Bundle mit V2_BOB (frühere Transaktion). Dies löst die
///     Konflikterkennung aus.
///
/// ### Erwartetes Ergebnis:
/// -   Das Wallet erkennt den Konflikt.
/// -   Die "Earliest Wins"-Heuristik wird angewendet.
/// -   Der Gutschein von Bob (basierend auf TX_A) wird auf `Active` gesetzt.
/// -   Der Gutschein von Charlie (basierend auf TX_B) wird auf `Quarantined` gesetzt.
#[test]
fn api_wallet_reactive_double_spend_earliest_wins() {
    // --- 1. Setup ---
    let dir_alice = tempdir().unwrap();
    let mut service_alice = AppService::new(dir_alice.path()).unwrap();
    // Manually derive Alice's identity to sign conflicting transactions outside the AppService flow
    let m_alice =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    service_alice.create_profile(&m_alice, Some("alice"), "pwd").unwrap();
    let (pk_alice, sk_alice) = crypto_utils::derive_ed25519_keypair(m_alice, None).unwrap();
    let id_alice = service_alice.get_user_id().unwrap();
    let identity_alice = voucher_lib::UserIdentity {
        signing_key: sk_alice,
        public_key: pk_alice,
        user_id: id_alice.clone(),
    };

    let dir_david = tempdir().unwrap();
    let mut service_david = AppService::new(dir_david.path()).unwrap();
    let m_david = generate_valid_mnemonic();
    service_david.create_profile(&m_david, Some("david"), "pwd").unwrap();
    let id_david = service_david.get_user_id().unwrap();

    // KORREKTUR: Die Transaktionen müssen an David gehen, damit sein Wallet sie verarbeiten kann.
    // Bob und Charlie sind hier nur konzeptionelle Namen für die beiden Konfliktpfade.
    let silver_standard_toml =
        generate_signed_standard_toml("voucher_standards/silver_v1/standard.toml");
    let (standard, _) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
    let mut standards_map = HashMap::new();
    standards_map.insert(standard.metadata.uuid.clone(), silver_standard_toml.clone());

    // --- 2. Alice erstellt einen Gutschein (V1) ---
    let voucher_v1 = service_alice
        .create_new_voucher(
            &silver_standard_toml,
            "en",
            NewVoucherData {
                nominal_value: NominalValue { amount: "100".to_string(), ..Default::default() },
                creator: Creator { id: id_alice.clone(), ..Default::default() },
                ..Default::default()
            },
            "pwd",
        )
        .unwrap();

    // --- 3. Alice erzeugt zwei konkurrierende Transaktionen ---
    let prev_tx = voucher_v1.transactions.last().unwrap();
    // KORREKTUR: Zeitstempel müssen garantiert nach der vorherigen Transaktion liegen.
    let prev_tx_time = DateTime::parse_from_rfc3339(&prev_tx.t_time)
        .unwrap()
        .with_timezone(&Utc);
    let time_a = (prev_tx_time + Duration::seconds(1)).to_rfc3339();
    let time_b = (prev_tx_time + Duration::seconds(2)).to_rfc3339();

    // KORREKTUR: Der prev_hash muss der Hash der *gesamten* vorherigen Transaktion sein.
    let prev_tx_hash = crypto_utils::get_hash(utils::to_canonical_json(prev_tx).unwrap());

    // TX_A -> Bob (früher)
    let mut tx_a = Transaction {
        prev_hash: prev_tx_hash.clone(),
        t_type: "transfer".to_string(),
        t_time: time_a,
        sender_id: id_alice.clone(),
        recipient_id: id_david.clone(),
        amount: "100".to_string(),
        ..Default::default()
    };
    tx_a = resign_transaction(tx_a, &identity_alice.signing_key);
    let mut voucher_v2_bob = voucher_v1.clone();
    voucher_v2_bob.transactions.push(tx_a);

    // TX_B -> Charlie (später)
    let mut tx_b = Transaction {
        prev_hash: prev_tx_hash,
        t_type: "transfer".to_string(),
        t_time: time_b,
        sender_id: id_alice.clone(),
        recipient_id: id_david.clone(),
        amount: "100".to_string(),
        ..Default::default()
    };
    tx_b = resign_transaction(tx_b, &identity_alice.signing_key);
    let mut voucher_v2_charlie = voucher_v1.clone();
    voucher_v2_charlie.transactions.push(tx_b);

    let bundle_bob = create_test_bundle(&identity_alice, vec![voucher_v2_bob], &id_david, None).unwrap();
    let bundle_charlie =
        create_test_bundle(&identity_alice, vec![voucher_v2_charlie], &id_david, None)
        .unwrap();

    // --- 4. David empfängt zuerst das spätere Bundle (Charlie) ---
    service_david
        .receive_bundle(&bundle_charlie, &standards_map, None, "pwd")
        .unwrap();
    let summaries_before = service_david.get_voucher_summaries().unwrap();
    assert_eq!(summaries_before.len(), 1);
    assert_eq!(summaries_before[0].status, VoucherStatus::Active);
    let charlie_instance_id = summaries_before[0].local_instance_id.clone();

    // --- 5. David empfängt das frühere Bundle (Bob), was den Konflikt auslöst ---
    println!("\n[Debug] Wallet-Zustand VOR dem zweiten Empfang (Konflikt-Auslöser):");
    dbg!(service_david.get_voucher_summaries().unwrap());
    service_david
        .receive_bundle(&bundle_bob, &standards_map, None, "pwd")
        .unwrap();

    println!("\n[Debug] Wallet-Zustand NACH dem zweiten Empfang:");
    let summaries_after = service_david.get_voucher_summaries().unwrap();
    dbg!(&summaries_after);

    // --- 6. Assertions ---
    let summaries_after = service_david.get_voucher_summaries().unwrap();
    assert_eq!(summaries_after.len(), 2, "Wallet should now contain two instances");

    let summary_charlie = service_david
        .get_voucher_details(&charlie_instance_id)
        .unwrap();

    println!("\n[Debug] Überprüfe den Status des 'späteren' Gutscheins (sollte Quarantined sein):");
    dbg!(&summary_charlie);
    assert!(
        matches!(summary_charlie.status, VoucherStatus::Quarantined { .. }),
        "Charlie's later voucher should be quarantined"
    );

    let bob_instance_id = summaries_after
        .iter()
        .find(|s| s.local_instance_id != charlie_instance_id)
        .unwrap()
        .local_instance_id
        .clone();
    let summary_bob = service_david.get_voucher_details(&bob_instance_id).unwrap();
    assert_eq!(
        summary_bob.status,
        VoucherStatus::Active,
        "Bob's earlier voucher should be active"
    );
}

/// Test 2.1: Stellt sicher, dass der gesamte Zustand eines Wallets verlustfrei
/// gespeichert und wiederhergestellt werden kann.
///
/// ### Szenario:
/// 1.  Ein Wallet (`service_a`) wird erstellt und in einen komplexen Zustand versetzt:
///     - Mehrere aktive und archivierte Gutscheine.
///     - Metadaten von gesendeten und empfangenen Bundles.
/// 2.  Der Zustand wird durch die `AppService`-Operationen automatisch gespeichert.
/// 3.  Eine neue `AppService`-Instanz (`service_b`) wird für dasselbe Verzeichnis erstellt.
/// 4.  `service_b` wird entsperrt.
///
/// ### Erwartetes Ergebnis:
/// -   Der Zustand von `service_b` nach dem Laden ist identisch mit dem von `service_a`.
/// -   Abfragen wie `get_voucher_summaries` und `get_total_balance_by_currency`
///     liefern exakt dieselben Ergebnisse.
#[test]
fn api_wallet_save_and_load_fidelity() {
    // HINWEIS ZUR GETESTETEN LOGIK:
    // Dieser Test verifiziert das beabsichtigte Verhalten des Wallets bei Transfers:
    // 1. TEILTRANSFER (SPLIT): Wenn nur ein Teilbetrag eines Gutscheins gesendet wird,
    //    wird die alte Instanz durch eine neue mit dem Restguthaben ersetzt. Es findet
    //    KEINE Archivierung statt. Dies verhindert, dass gültige Gutscheine mit Restguthaben
    //    fälschlicherweise archiviert werden und spart Speicherplatz.
    // 2. VOLLSTÄNDIGER TRANSFER: Nur wenn der GESAMTE Betrag eines Gutscheins gesendet wird,
    //    wird die Instanz als "Archived" markiert, da sie vollständig verbraucht ist.

    // --- 1. Setup ---
    let dir = tempdir().unwrap();
    let mnemonic = generate_valid_mnemonic();
    let password = "a-very-secure-password";
    let silver_toml = generate_signed_standard_toml("voucher_standards/silver_v1/standard.toml");
    let (silver_standard, _) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
    let mut standards_map = HashMap::new();
    standards_map.insert(silver_standard.metadata.uuid.clone(), silver_toml.clone());

    // --- 2. Wallet A in komplexen Zustand versetzen ---
    {
        let mut service_a = AppService::new(dir.path()).unwrap();
        service_a.create_profile(&mnemonic, Some("fidelity-test"), password).unwrap();
        let id_a = service_a.get_user_id().unwrap();

        // Aktive Gutscheine erstellen
        service_a
            .create_new_voucher(
                &silver_toml,
                "en",
                // KORREKTUR: Testdaten explizit machen, um Mehrdeutigkeiten zu vermeiden.
                // Wir geben die `NominalValue` vollständig an, wie sie im Standard erwartet wird.
                NewVoucherData {
                    creator: Creator { id: id_a.clone(), ..Default::default() },
                    nominal_value: NominalValue {
                        unit: "Unzen".to_string(),
                        amount: "10".to_string(),
                        abbreviation: "oz Ag".to_string(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                password,
            )
            .unwrap();

        // --- Schritt A: Teiltransfer (Split) ---
        // Wir senden 3 von 10 Unzen. Die 10-Unzen-Instanz wird durch eine 7-Unzen-Instanz ersetzt.
        let summary = service_a.get_voucher_summaries().unwrap();
        let silver_voucher_id_10oz = summary
            .iter()
            .find(|s| s.current_amount == "10.0000" && s.status == VoucherStatus::Active)
            .expect("Silver voucher summary not found")
            .local_instance_id
            .clone();
        service_a.create_transfer_bundle(silver_standard, &silver_voucher_id_10oz, &ACTORS.bob.user_id, "3", None, None, password).unwrap();

        // Bundle-Metadaten durch Empfang erzeugen
        let transfer_back_bundle = {
            let mut service_bob = AppService::new(tempdir().unwrap().path()).unwrap();
            service_bob.create_profile(&generate_valid_mnemonic(), Some("bob"), "pwd").unwrap();
            let id_bob = service_bob.get_user_id().unwrap();
            service_bob
                .create_new_voucher(
                    &silver_toml,
                    "en",
                    NewVoucherData {
                        creator: Creator { id: id_bob, ..Default::default() },
                        nominal_value: NominalValue { amount: "1".to_string(), ..Default::default() },
                        ..Default::default()
                    },
                    "pwd",
                )
                .unwrap();
            let local_id = service_bob.get_voucher_summaries().unwrap()[0].local_instance_id.clone();
            service_bob.create_transfer_bundle(silver_standard, &local_id, &id_a, "1", None, None, "pwd").unwrap()
        };
        service_a.receive_bundle(&transfer_back_bundle, &standards_map, None, password).unwrap();

        // --- Schritt B: Vollständiger Transfer ---
        // Nun senden wir die verbleibenden 7 Unzen, um die Archivierungslogik zu testen.
        let summary_before_full_transfer = service_a.get_voucher_summaries().unwrap();
        let silver_voucher_id_7oz = summary_before_full_transfer
            .iter()
            .find(|s| s.current_amount == "7.0000" && s.status == VoucherStatus::Active)
            .expect("7oz silver voucher for full transfer not found")
            .local_instance_id
            .clone();
        service_a.create_transfer_bundle(
            silver_standard,
            &silver_voucher_id_7oz,
            &ACTORS.charlie.user_id, "7", None, None,
            password
        ).unwrap();
    } // service_a geht out of scope, Wallet wird aus dem Speicher entfernt

    // --- 3. Wallet B aus demselben Verzeichnis laden ---
    let mut service_b = AppService::new(dir.path()).unwrap();
    service_b.login(password).expect("Login for service_b should succeed");

    // --- 4. Assertions ---
    let summaries = service_b.get_voucher_summaries().unwrap();

    println!("\n[Debug] Finale Gutschein-Zusammenfassungen vor der Längen-Assertion:");
    dbg!(&summaries);

    // ERWARTETER ZUSTAND:
    // - 1x Silber-Gutschein (1 Unze), der empfangen wurde -> Active
    // - 1x Silber-Gutschein (7 Unzen), der vollständig gesendet wurde -> Archived
    // Insgesamt also 2 Instanzen.
    assert_eq!(summaries.len(), 2, "Should have 2 voucher instances (1 active, 1 archived)");

    let archived_count = summaries.iter().filter(|s| s.status == VoucherStatus::Archived).count();
    let active_count = summaries.iter().filter(|s| s.status == VoucherStatus::Active).count();
    assert_eq!(active_count, 1, "Incorrect number of active vouchers found");
    assert_eq!(archived_count, 1, "Incorrect number of archived vouchers found");

    let balances = service_b.get_total_balance_by_currency().unwrap();

    // --- HINZUGEFÜGTER DEBUG-PRINT ---
    // Dieser Print zeigt den exakten Inhalt der `balances`-Map.
    // Erwartete Ausgabe: {"Oz": "1.0000"}
    println!("\n[Debug] Inhalt der Salden-Map:");
    dbg!(&balances);

    // ERWARTETE BILANZ:
    // 10 (start) - 3 (gesendet) + 1 (empfangen) - 7 (gesendet) = 1
    // KORREKTUR: Der Test muss auf die korrekte Einheit "Oz" prüfen, die aus dem Standard geladen wird.
    assert_eq!(balances.get("Oz").unwrap(), "1.0000", "Silver balance mismatch");
    assert!(balances.get("m").is_none(), "Minuto balance should not exist as it was never created");
}