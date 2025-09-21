//! # src/wallet/tests.rs
//! Enthält die Modul-Tests für die `Wallet`-Struktur. Diese Datei ist
//! bewusst von `mod.rs` getrennt, um die Lesbarkeit zu verbessern.
use crate::{
    test_utils::{
        self, add_voucher_to_wallet, create_voucher_for_manipulation, setup_in_memory_wallet,
        ACTORS, MINUTO_STANDARD,
    },
    VoucherCoreError, VoucherStatus,
};
use chrono::{Duration, Utc};

/// Bündelt die Tests zur Validierung der `local_instance_id`-Logik.
mod local_instance_id_logic {
    // Importiert die benötigten Typen vom Crate-Anfang. Das ist robuster.
    use crate::{Wallet, VoucherCoreError};
    // Holt die Test-Helfer und die nur hier benötigte `create_transaction` Funktion
    use crate::services::voucher_manager::create_transaction;
    use crate::test_utils::{self, ACTORS};

    /// **Test 1: Grundlagen - Korrekte ID nach Split und Eindeutigkeit**
    ///
    /// Prüft, dass nach einer Split-Transaktion beide Parteien (Sender mit
    /// Restbetrag und Empfänger) unterschiedliche, aber korrekt abgeleitete
    /// lokale IDs erhalten, die beide auf derselben letzten Transaktion basieren.
    #[test]
    fn test_correct_id_after_split_and_uniqueness() {
        // --- Setup ---
        // Erstellt einen Gutschein von Alice (100) und eine Transaktion,
        // bei der sie 40 an Bob sendet.
        let (_, _, alice, bob, voucher_after_split) = test_utils::setup_voucher_with_one_tx();
        let split_tx = voucher_after_split.transactions.last().unwrap();

        // --- Aktion ---
        let alice_local_id =
            Wallet::calculate_local_instance_id(&voucher_after_split, &alice.user_id).unwrap();
        let bob_local_id =
            Wallet::calculate_local_instance_id(&voucher_after_split, &bob.user_id).unwrap();

        // --- Erwartetes Ergebnis ---
        let expected_alice_id = crate::services::crypto_utils::get_hash(format!(
            "{}{}{}",
            voucher_after_split.voucher_id, split_tx.t_id, alice.user_id
        ));
        let expected_bob_id = crate::services::crypto_utils::get_hash(format!(
            "{}{}{}",
            voucher_after_split.voucher_id, split_tx.t_id, bob.user_id
        ));

        // 1 & 2: IDs müssen auf der `split`-Transaktion basieren.
        assert_eq!(alice_local_id, expected_alice_id);
        assert_eq!(bob_local_id, expected_bob_id);

        // 3: Die IDs müssen unterschiedlich sein, da der `owner_id` Teil des Hashes ist.
        assert_ne!(alice_local_id, bob_local_id);
    }

    /// **Test 2: Pfadabhängigkeit - Korrekte ID in einer langen Transaktionskette**
    ///
    /// Stellt sicher, dass immer die _letzte_ relevante Transaktion für die ID-Berechnung
    /// herangezogen wird.
    #[test]
    fn test_path_dependency_long_chain() {
        // --- Setup ---
        // Alice (100) -> Bob (40)
        let (standard, _, _, bob, voucher_after_tx1) = test_utils::setup_voucher_with_one_tx();
        let charlie = &ACTORS.charlie;

        // Bob (40) -> Charlie (40) - Voller Transfer
        let voucher_after_tx2 = create_transaction(
            &voucher_after_tx1, standard, &bob.user_id, &bob.signing_key, &charlie.user_id, "40.0000",
        )
            .unwrap();
        let final_tx = voucher_after_tx2.transactions.last().unwrap();
 
        // --- Aktion ---
        let charlie_local_id =
            Wallet::calculate_local_instance_id(&voucher_after_tx2, &charlie.user_id).unwrap();

        // --- Erwartetes Ergebnis ---
        let expected_charlie_id = crate::services::crypto_utils::get_hash(format!(
            "{}{}{}",
            voucher_after_tx2.voucher_id, final_tx.t_id, charlie.user_id
        ));
        assert_eq!(charlie_local_id, expected_charlie_id);
    }

    /// **Test 3: Pfadabhängigkeit - "Bounce Back"-Szenario**
    ///
    /// Prüft, ob die ID korrekt ist, wenn ein Gutschein zum vorherigen Besitzer zurückkehrt.
    #[test]
    fn test_path_dependency_bounce_back() {
        // --- Setup ---
        // Alice (100) -> Bob (40)
        let (standard, _, alice, bob, voucher_after_tx1) = test_utils::setup_voucher_with_one_tx();

        // Bob (40) -> Alice (40) - Sendet den Betrag zurück
        let voucher_after_tx2 = create_transaction(
            &voucher_after_tx1, standard, &bob.user_id, &bob.signing_key, &alice.user_id, "40.0000",
        )
            .unwrap();
        let final_tx = voucher_after_tx2.transactions.last().unwrap();
 
        // --- Aktion ---
        let alice_final_local_id =
            Wallet::calculate_local_instance_id(&voucher_after_tx2, &alice.user_id).unwrap();

        // --- Erwartetes Ergebnis ---
        // Die ID muss auf der letzten Transaktion (Bob -> Alice) basieren.
        let expected_alice_id = crate::services::crypto_utils::get_hash(format!(
            "{}{}{}",
            voucher_after_tx2.voucher_id, final_tx.t_id, alice.user_id
        ));
        assert_eq!(alice_final_local_id, expected_alice_id);
    }

    /// **Test 4: Korrekte ID für archivierte Zustände**
    ///
    /// Stellt sicher, dass die ID-Berechnung auch für einen Sender korrekt ist,
    /// nachdem dieser seinen gesamten Betrag transferiert hat (Saldo = 0).
    #[test]
    fn test_correct_id_for_archived_state() {
        // --- Setup ---
        let (standard, _, alice, bob, initial_voucher) = test_utils::setup_voucher_with_one_tx();
        // Alice hat noch 60. Sie sendet diese 60 komplett an Bob.
        let voucher_after_full_transfer = create_transaction(
            &initial_voucher, standard, &alice.user_id, &alice.signing_key, &bob.user_id, "60.0000",
        )
            .unwrap();
        let final_tx = voucher_after_full_transfer.transactions.last().unwrap();

        // --- Aktion ---
        // Berechne die ID für Alice, deren Guthaben nun 0 ist (archivierter Zustand).
        let alice_archived_id =
            Wallet::calculate_local_instance_id(&voucher_after_full_transfer, &alice.user_id)
                .unwrap();

        // --- Erwartetes Ergebnis ---
        // Die ID muss auf der letzten Transaktion basieren, an der Alice beteiligt war.
        let expected_alice_id = crate::services::crypto_utils::get_hash(format!(
            "{}{}{}",
            voucher_after_full_transfer.voucher_id, final_tx.t_id, alice.user_id
        ));
        assert_eq!(alice_archived_id, expected_alice_id);
    }

    /// **Test 5: Fehlerfall - Kein Besitz**
    ///
    /// Prüft die korrekte Fehlerbehandlung, wenn eine ID für einen Benutzer
    /// berechnet werden soll, der nie im Besitz des Gutscheins war.
    #[test]
    fn test_error_when_user_has_no_balance_or_history() {
        // --- Setup ---
        // Alice (100) -> Bob (40). Charlie war nie beteiligt.
        let (_, _, _, _, voucher) = test_utils::setup_voucher_with_one_tx();
        let charlie = &ACTORS.charlie;

        // --- Aktion ---
        let result = Wallet::calculate_local_instance_id(&voucher, &charlie.user_id);

        // DEBUG: Gib das Ergebnis aus, um zu sehen, was tatsächlich zurückkommt.
        println!("Debug: Das Ergebnis für Charlie ist: {:?}", &result);

        // --- Erwartetes Ergebnis ---
        assert!(result.is_err(), "Function should return an error for a non-owner.");
        assert!(matches!(
            result.unwrap_err(),
            VoucherCoreError::VoucherOwnershipNotFound(_)
        ));
    }
}

/// Bündelt Tests zur Überprüfung des korrekten Verhaltens von Gutscheinen
/// in verschiedenen Zuständen (z.B. unter Quarantäne).
mod instance_state_behavior {
    use super::*;

    /// **Test 1.2: Verhalten von Quarantined-Gutscheinen**
    ///
    /// Stellt sicher, dass Operationen, die einen aktiven Gutschein erfordern,
    /// für einen unter Quarantäne gestellten Gutschein fehlschlagen.
    ///
    /// ### Szenario:
    /// 1.  Ein Gutschein wird erstellt und manuell auf `Quarantined` gesetzt.
    /// 2.  Ein Transfer-Versuch wird gestartet.
    /// 3.  Ein Versuch, eine Signaturanfrage zu erstellen, wird gestartet.
    ///
    /// ### Erwartetes Ergebnis:
    /// -   `create_transfer` schlägt mit `VoucherCoreError::VoucherNotActive` fehl.
    /// -   `create_signing_request` schlägt mit `VoucherCoreError::VoucherNotReadyForSigning` fehl.
    #[test]
    fn test_quarantined_voucher_behavior() {
        // --- Setup ---
        let alice = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(alice);
        let (standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
        let local_id = add_voucher_to_wallet(&mut wallet, alice, "100", standard, true).unwrap();

        // Instanz manuell auf Quarantined setzen
        let instance = wallet.voucher_store.vouchers.get_mut(&local_id).unwrap();
        instance.status = VoucherStatus::Quarantined {
            reason: "Test".to_string(),
        };

        // --- Aktion & Assertions ---

        // 1. Test create_transfer
        let transfer_result = wallet.create_transfer(
            alice,
            standard,
            &local_id,
            &ACTORS.bob.user_id,
            "50",
            None,
            None,
        );
        assert!(
            matches!(transfer_result, Err(VoucherCoreError::VoucherNotActive(VoucherStatus::Quarantined { .. }))),
            "create_transfer should fail for a quarantined voucher"
        );

        // 2. Test create_signing_request
        let signing_request_result = wallet.create_signing_request(
            alice,
            &local_id,
            &ACTORS.guarantor1.user_id,
            None,
        );
        assert!(
            matches!(signing_request_result, Err(VoucherCoreError::VoucherNotReadyForSigning(VoucherStatus::Quarantined { .. }))),
            "create_signing_request should fail for a quarantined voucher"
        );
    }
}

/// Bündelt Tests für Wartungsfunktionen wie die Speicherbereinigung.
mod maintenance_logic {
    use super::*;

    /// **Test 3.1: Korrektes Löschen abgelaufener, archivierter Instanzen**
    ///
    /// Verifiziert, dass `cleanup_storage` nur die archivierten Instanzen entfernt,
    /// deren Gültigkeit plus Gnadenfrist abgelaufen ist.
    ///
    /// ### Szenario:
    /// 1.  Ein Wallet wird mit zwei archivierten Gutscheinen gefüllt:
    ///     - Gutschein A: `valid_until` vor 3 Jahren.
    ///     - Gutschein B: `valid_until` vor 6 Monaten.
    /// 2.  Die Funktion `cleanup_storage` wird mit einer Gnadenfrist von 1 Jahr aufgerufen.
    ///
    /// ### Erwartetes Ergebnis:
    /// -   Gutschein A wird entfernt, da `valid_until` + 1 Jahr < heute.
    /// -   Gutschein B verbleibt im Speicher, da `valid_until` + 1 Jahr > heute.
    #[test]
    fn test_cleanup_of_expired_archived_instances() {
        // --- Setup ---
        let user = &ACTORS.test_user;
        let mut wallet = setup_in_memory_wallet(user);
        let (standard, hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

        // Gutschein A (abgelaufen)
        let mut voucher_a =
            create_voucher_for_manipulation(Default::default(), standard, hash, &user.signing_key, "en");
        voucher_a.valid_until = (Utc::now() - Duration::days(365 * 3)).to_rfc3339();
        let id_a = wallet.add_voucher_instance_for_test(voucher_a, VoucherStatus::Archived);

        // Gutschein B (noch in Gnadenfrist)
        let mut voucher_b =
            create_voucher_for_manipulation(Default::default(), standard, hash, &user.signing_key, "en");
        voucher_b.valid_until = (Utc::now() - Duration::days(180)).to_rfc3339();
        let id_b = wallet.add_voucher_instance_for_test(voucher_b, VoucherStatus::Archived);

        // --- Aktion ---
        wallet.cleanup_storage(1).unwrap(); // Gnadenfrist von 1 Jahr

        // --- Assertions ---
        assert!(!wallet.voucher_store.vouchers.contains_key(&id_a), "Expired voucher A should have been removed");
        assert!(wallet.voucher_store.vouchers.contains_key(&id_b), "Voucher B within grace period should remain");
    }
}
