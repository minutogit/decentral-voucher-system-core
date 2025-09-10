//! # tests/test_archive.rs
//!
//! Testet die Funktionalität des `VoucherArchive`-Traits und der `FileVoucherArchive`-Implementierung.

use voucher_lib::{
    archive::file_archive::FileVoucherArchive,
    UserIdentity,
    models::{
        profile::{UserProfile},
        voucher::{Address, Creator, NominalValue},
        voucher_standard_definition::VoucherStandardDefinition,
    },
    services::{
        crypto_utils,
        voucher_manager::{self, NewVoucherData},
    },
    wallet::Wallet,
};
use std::fs;
use tempfile::tempdir;

// --- Hilfsfunktionen (könnten in ein gemeinsames Test-Modul ausgelagert werden) ---

fn setup_identity(seed: &str) -> UserIdentity {
    let (public_key, signing_key) =
        crypto_utils::generate_ed25519_keypair_for_tests(Some(seed));
    let user_id = crypto_utils::create_user_id(&public_key, Some("ar")).unwrap();
    UserIdentity {
        signing_key,
        public_key,
        user_id,
    }
}

fn load_test_standard() -> VoucherStandardDefinition {
    let toml_str = fs::read_to_string("voucher_standards/silver_standard.toml").unwrap();
    voucher_manager::load_standard_definition(&toml_str).expect("Failed to load standard")
}

// --- Haupttest ---

#[test]
fn test_voucher_archiving_on_full_spend() {
    // 1. SETUP
    // Erstelle Alice (Senderin) und Bob (Empfänger).
    let alice_identity = setup_identity("alice_archive_test");
    let bob_identity = setup_identity("bob_archive_test");

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
    let standard = load_test_standard();

    // Alice erstellt einen Gutschein und fügt ihn ihrem Wallet hinzu.
    let voucher = {
        let creator_data = Creator {
            id: alice_identity.user_id.clone(),
            first_name: "Alice".to_string(),
            last_name: "Test".to_string(),
            signature: "".to_string(),
            address: Address::default(),
            organization: None,
            community: None,
            phone: None,
            email: None,
            url: None,
            gender: "9".to_string(),
            service_offer: None,
            needs: None,
            coordinates: "0,0".to_string(),
        };
        let nominal_value = NominalValue {
            amount: "100.0000".to_string(), // KORREKTUR: Vier Dezimalstellen für den Silber-Standard
            unit: "".to_string(),
            abbreviation: "".to_string(),
            description: "".to_string(),
        };
        let voucher_data = NewVoucherData {
            validity_duration: Some("P3Y".to_string()),
            non_redeemable_test_voucher: false,
            nominal_value,
            creator: creator_data,
            collateral: Default::default(),
        };
        voucher_manager::create_voucher(voucher_data, &standard, &alice_identity.signing_key)
            .unwrap()
    };

    let voucher_id = voucher.voucher_id.clone();
    let local_id =
        Wallet::calculate_local_instance_id(&voucher, &alice_identity.user_id).unwrap();
    alice_wallet
        .add_voucher_to_store(voucher.clone(), voucher_lib::models::profile::VoucherStatus::Active, &alice_identity.user_id)
        .unwrap();

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