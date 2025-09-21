//! # src/wallet/tests.rs
//! Enthält die Modul-Tests für die `Wallet`-Struktur. Diese Datei ist
//! bewusst von `mod.rs` getrennt, um die Lesbarkeit zu verbessern.

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