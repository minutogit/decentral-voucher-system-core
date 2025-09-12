//! tests/test_file_storage.rs
//!
//! Enthält Integrationstests für das refaktorierte Profil- und VoucherStore-Management,
//! inklusive der Passwort-Wiederherstellungslogik und Randbedingungen.
use std::fs;
use tempfile::tempdir;
use voucher_lib::models::profile::{
    VoucherStatus,
};
use voucher_lib::{UserIdentity};
use voucher_lib::models::voucher::{Creator, NominalValue, Voucher};
use voucher_lib::services::voucher_manager::NewVoucherData;
use voucher_lib::services::voucher_manager;
use voucher_lib::error::VoucherCoreError;
use voucher_lib::{AuthMethod, FileStorage, Storage, StorageError, Wallet};
mod test_utils;
use test_utils::{add_voucher_to_wallet, setup_in_memory_wallet, ACTORS, MINUTO_STANDARD, SILVER_STANDARD};

// --- Hilfsfunktionen ---
fn create_test_voucher(identity: &UserIdentity) -> Voucher {
    let new_voucher_data = NewVoucherData {
        creator: Creator {
            id: identity.user_id.clone(),
            first_name: "Test".to_string(),
            last_name: "User".to_string(),
            address: Default::default(),
            organization: None,
            community: None,
            phone: None,
            email: None,
            url: None,
            gender: "9".to_string(),
            service_offer: None,
            needs: None,
            signature: "".to_string(),
            coordinates: "0,0".to_string(),
        },
        nominal_value: NominalValue { amount: "100".to_string(), ..Default::default() },
        ..Default::default()
    };
    voucher_manager::create_voucher(new_voucher_data, &MINUTO_STANDARD, &identity.signing_key)
        .expect("Voucher creation failed")
}

// --- Tests ---

#[test]
fn test_wallet_creation_save_and_load() {
    // 1. Setup
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let mut storage = FileStorage::new(temp_dir.path());
    let password = "strongpassword123";
    let identity = &ACTORS.alice;
    let wallet = setup_in_memory_wallet(identity);

    // 2. Speichern
    wallet.save(&mut storage, identity, password).expect("Failed to save wallet");

    // 3. Laden und Verifizieren
    let (loaded_wallet, loaded_identity) =
        Wallet::load(&storage, &AuthMethod::Password(password)).expect("Failed to load wallet");
    assert_eq!(wallet.profile.user_id, loaded_wallet.profile.user_id);
    assert_eq!(identity.user_id, loaded_identity.user_id);
    assert!(loaded_wallet.voucher_store.vouchers.is_empty());

    // 4. Fehlerfall: Falsches Passwort
    let result = Wallet::load(&storage, &AuthMethod::Password("wrongpassword"));
    assert!(matches!(result, Err(VoucherCoreError::Storage(StorageError::AuthenticationFailed))));
}

#[test]
fn test_password_recovery_and_reset_with_data() {
    // 1. Setup: Erstelle ein Profil mit einem Gutschein.
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let mut storage = FileStorage::new(temp_dir.path());
    let initial_password = "my-secret-password";
    let identity = &ACTORS.test_user;
    let mut wallet = setup_in_memory_wallet(identity);
    let voucher = create_test_voucher(identity);
    let local_id = Wallet::calculate_local_instance_id(&voucher, &identity.user_id).unwrap();

    wallet
        .add_voucher_to_store(voucher, VoucherStatus::Active, &identity.user_id)
        .unwrap();
    assert_eq!(wallet.voucher_store.vouchers.len(), 1);

    wallet.save(&mut storage, identity, initial_password).expect("Initial save failed");

    // 2. Wiederherstellung mit der Mnemonic-Phrase (Identität).
    // Erzeuge eine Identität für die Referenz (borrow) und eine zweite für die Wertübergabe (move).
    let (recovered_wallet, recovered_identity) =
        Wallet::load(&storage, &AuthMethod::RecoveryIdentity(identity))
            .expect("Recovery with correct identity should succeed");

    // Überprüfe, ob die wiederhergestellten Daten (inkl. Gutschein) korrekt sind.
    assert_eq!(wallet.profile.user_id, recovered_wallet.profile.user_id);
    assert_eq!(identity.user_id, recovered_identity.user_id);
    assert_eq!(recovered_wallet.voucher_store.vouchers.len(), 1, "Voucher should be present after recovery");
    assert!(recovered_wallet.voucher_store.vouchers.contains_key(&local_id));

    // 3. Passwort zurücksetzen.
    let new_password = "my-new-strong-password-456";
    storage
        .reset_password(identity, new_password)
        .expect("Password reset should succeed");

    // 4. Verifizierung nach dem Reset.
    // Login mit altem Passwort muss fehlschlagen.
    let result = Wallet::load(&storage, &AuthMethod::Password(initial_password));
    assert!(matches!(result, Err(VoucherCoreError::Storage(StorageError::AuthenticationFailed))));

    // Login mit neuem Passwort muss erfolgreich sein und die Daten müssen intakt sein.
    let (final_wallet, _) = Wallet::load(&storage, &AuthMethod::Password(new_password))
        .expect("Login with new password should succeed");

    assert_eq!(wallet.profile.user_id, final_wallet.profile.user_id);
    assert_eq!(final_wallet.voucher_store.vouchers.len(), 1, "Voucher should still be present after reset");
    assert!(final_wallet.voucher_store.vouchers.contains_key(&local_id));

    // 5. Fehlerfall: Wiederherstellung mit der falschen Identität.
    let imposter_identity = &ACTORS.hacker;
    let result = Wallet::load(&storage, &AuthMethod::RecoveryIdentity(imposter_identity));
    assert!(matches!(result, Err(VoucherCoreError::Storage(StorageError::AuthenticationFailed))));
}

#[test]
fn test_load_with_missing_voucher_store() {
    let temp_dir = tempdir().unwrap();
    let mut storage = FileStorage::new(temp_dir.path());
    let password = "password123";
    let identity = &ACTORS.test_user;
    let wallet = setup_in_memory_wallet(identity);
    wallet.save(&mut storage, identity, password).unwrap();

    // Lösche die Gutschein-Datei
    fs::remove_file(temp_dir.path().join("vouchers.enc")).unwrap();

    // Das Laden sollte trotzdem erfolgreich sein und einen leeren Store zurückgeben
    let (loaded_wallet, _) = Wallet::load(&storage, &AuthMethod::Password(password))
        .expect("Loading with missing voucher store should succeed");

    assert_eq!(wallet.profile.user_id, loaded_wallet.profile.user_id);
    assert!(loaded_wallet.voucher_store.vouchers.is_empty(), "Voucher store should be empty by default");
}

#[test]
fn test_load_from_corrupted_profile_file() {
    let temp_dir = tempdir().unwrap();
    let mut storage = FileStorage::new(temp_dir.path());
    let password = "password123";
    let identity = &ACTORS.victim;
    let wallet = setup_in_memory_wallet(identity);
    wallet.save(&mut storage, identity, password).unwrap();

    // Beschädige die Profil-Datei
    let profile_path = temp_dir.path().join("profile.enc");
    let mut contents = fs::read(&profile_path).unwrap();
    contents.truncate(contents.len() / 2); // Schneide die Hälfte ab
    fs::write(&profile_path, contents).unwrap();

    // Das Laden sollte mit einem Deserialisierungs- oder Formatfehler fehlschlagen
    let result = Wallet::load(&storage, &AuthMethod::Password(password));
    assert!(matches!(result, Err(VoucherCoreError::Storage(StorageError::InvalidFormat(_)))));
}

#[test]
fn test_empty_password_handling() {
    let temp_dir = tempdir().unwrap();
    let mut storage = FileStorage::new(temp_dir.path());
    let empty_password = "";
    let identity = &ACTORS.test_user;
    let wallet = setup_in_memory_wallet(identity);

    // Speichern mit leerem Passwort sollte funktionieren
    wallet.save(&mut storage, identity, empty_password).expect("Saving with empty password should succeed");

    // Laden mit leerem Passwort sollte funktionieren
    let (loaded_wallet, _) = Wallet::load(&storage, &AuthMethod::Password(empty_password))
        .expect("Loading with empty password should succeed");
    assert_eq!(wallet.profile.user_id, loaded_wallet.profile.user_id);

    // Laden mit einem falschen, nicht-leeren Passwort sollte fehlschlagen
    let result = Wallet::load(&storage, &AuthMethod::Password("a-real-password"));
    assert!(matches!(result, Err(VoucherCoreError::Storage(StorageError::AuthenticationFailed))));
}

#[test]
fn test_save_and_load_with_bundle_history() {
    // 1. Setup
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let mut storage = FileStorage::new(temp_dir.path());
    let password = "strongpassword123";

    // Erstelle Sender (Alice) und Empfänger (Bob)
    let alice_identity = &ACTORS.alice;
    let bob_identity = &ACTORS.bob;
    let mut alice_wallet = setup_in_memory_wallet(alice_identity);

    // Alice erstellt einen Gutschein und fügt ihn ihrem Wallet hinzu
    let local_id =
        add_voucher_to_wallet(&mut alice_wallet, alice_identity, "100", &SILVER_STANDARD, false)
            .unwrap();

    // 2. Aktion: Führe eine Transaktion durch, um Bundle-Metadaten zu erzeugen.
    let _ = alice_wallet
        .create_transfer(
            alice_identity,
            &SILVER_STANDARD,
            &local_id,
            &bob_identity.user_id,
            "100", // Sende den vollen Betrag
            Some("Test transfer".to_string()),
            None::<&dyn voucher_lib::archive::VoucherArchive>,
        )
        .expect("Transfer failed");

    // Überprüfe den Zustand vor dem Speichern
    assert_eq!(alice_wallet.bundle_meta_store.history.len(), 1);
    let original_bundle_id = alice_wallet
        .bundle_meta_store
        .history
        .keys()
        .next()
        .unwrap()
        .clone();

    // 3. Speichern
    alice_wallet
        .save(&mut storage, alice_identity, password)
        .expect("Failed to save wallet with history");

    // Überprüfe, ob die neue Metadaten-Datei erstellt wurde
    assert!(temp_dir.path().join("bundles.meta.enc").exists());

    // 4. Laden und Verifizieren
    let (loaded_wallet, _) = Wallet::load(&storage, &AuthMethod::Password(password))
        .expect("Failed to load wallet");

    // **Die entscheidende Prüfung:** Wurde die Historie korrekt geladen?
    assert_eq!(
        loaded_wallet.bundle_meta_store.history.len(),
        1,
        "Bundle history should have been loaded from bundles.meta.enc"
    );
    assert!(loaded_wallet
        .bundle_meta_store
        .history
        .contains_key(&original_bundle_id));
    assert_eq!(
        loaded_wallet.profile.user_id,
        alice_wallet.profile.user_id
    );
}