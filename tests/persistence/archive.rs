//! # tests/persistence/archive.rs
//!
//! Testet die Funktionalität des `VoucherArchive`-Traits und der `FileVoucherArchive`-Implementierung.
//! Ursprünglich in `tests/test_archive.rs`.

use voucher_lib::{
    archive::file_archive::FileVoucherArchive, models::profile::UserProfile,
    models::voucher::{Creator, NominalValue}, services::voucher_manager, wallet::Wallet, VoucherStatus
};
use std::fs;
use tempfile::tempdir;

// Lade die Test-Hilfsfunktionen aus dem übergeordneten Verzeichnis.

use voucher_lib::test_utils::{ACTORS, SILVER_STANDARD};

// --- Haupttest ---

#[test]
fn test_voucher_archiving_on_full_spend() {
    // 1. SETUP
    // Verwende die vordefinierten Test-Akteure aus `test_utils`.
    let alice_identity = &ACTORS.alice;
    let bob_identity = &ACTORS.bob;

    let mut alice_wallet = Wallet {
        profile: UserProfile { user_id: alice_identity.user_id.clone() },
        voucher_store: Default::default(),
        bundle_meta_store: Default::default(),
        fingerprint_store: Default::default(),
        proof_store: Default::default(),
    };

    // Erstelle Alices Archiv im temporären Verzeichnis.
    let temp_dir = tempdir().unwrap();
    let archive = FileVoucherArchive::new(temp_dir.path());
    // Verwende den vordefinierten, zur Laufzeit signierten Standard.
    let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);

    // Alice erstellt einen Gutschein und fügt ihn ihrem Wallet hinzu.
    let voucher = {
        let creator_data = Creator {
            id: alice_identity.user_id.clone(),
            // Fülle nur die nötigsten Felder für diesen Test.
            ..Default::default()
        };
        let nominal_value = NominalValue {
            amount: "100.0000".to_string(), // KORREKTUR: Vier Dezimalstellen für den Silber-Standard
            unit: "".to_string(),
            abbreviation: "".to_string(),
            description: "".to_string(),
        };
        let voucher_data = voucher_manager::NewVoucherData {
            nominal_value,
            creator: creator_data,
            ..Default::default()
        };

        voucher_manager::create_voucher(voucher_data, standard, standard_hash, &alice_identity.signing_key, "en")
            .unwrap()
    };

    let voucher_id = voucher.voucher_id.clone();
    let local_id =
        Wallet::calculate_local_instance_id(&voucher, &alice_identity.user_id).unwrap();
    alice_wallet
        .add_voucher_instance(local_id.clone(), voucher.clone(), VoucherStatus::Active);

    // 2. AKTION
    // Alice sendet ihr GESAMTES Guthaben ("100") an Bob und übergibt dabei ihr Archiv.
    let (_bundle_bytes, transferred_voucher_state) = alice_wallet
        .create_transfer(
            &alice_identity,
            &standard,
            &local_id,
            &bob_identity.user_id,
            "100.0000", // KORREKTUR: Betrag muss ebenfalls das korrekte Format haben.
            None,
            Some(&archive), // Das Archiv-Backend wird übergeben.
        )
        .expect("Transfer with archive should succeed.");

    // 3. VERIFIZIERUNG
    // Prüfe, ob das Archiv-System die korrekte Datei im korrekten Unterverzeichnis angelegt hat.
    let last_tx = transferred_voucher_state.transactions.last().unwrap();
    let expected_file_path = temp_dir
        .path()
        .join(&voucher_id)
        .join(format!("{}.json", &last_tx.t_id));

    assert!(expected_file_path.exists(), "Archive file was not created.");

    // Lade den Inhalt der archivierten Datei und vergleiche ihn.
    let archived_content = fs::read(expected_file_path).unwrap();
    let archived_voucher: voucher_lib::models::voucher::Voucher =
        serde_json::from_slice(&archived_content).unwrap();

    // Der archivierte Gutschein muss exakt dem Zustand entsprechen, den die `create_transfer`-Funktion zurückgegeben hat.
    assert_eq!(archived_voucher, transferred_voucher_state);
}