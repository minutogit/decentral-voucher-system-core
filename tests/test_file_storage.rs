//! tests/test_file_storage.rs
//!
//! Enthält Integrationstests für das refaktorierte Profil- und VoucherStore-Management,
//! inklusive der Passwort-Wiederherstellungslogik und Randbedingungen.

use rust_decimal::Decimal;
use voucher_lib::error::VoucherCoreError;
use voucher_lib::models::profile::{UserIdentity, UserProfile, VoucherStore};
use voucher_lib::models::voucher::{Collateral, Creator, NominalValue, Transaction, Voucher};
use voucher_lib::models::voucher_standard_definition::VoucherStandardDefinition;
use voucher_lib::services::{crypto_utils, voucher_manager};
use voucher_lib::{crypto_utils::get_hash, AuthMethod, FileStorage, StorageError, Wallet};
use std::fs;
use tempfile::tempdir;

// --- Hilfsfunktionen ---

/// Erstellt eine deterministische Test-Identität und ein leeres Wallet.
/// Durch die Verwendung eines Seeds wird sichergestellt, dass bei jedem Testlauf dieselben Schlüssel generiert werden.
fn create_new_wallet_and_identity(prefix: &str, seed: &str) -> (Wallet, UserIdentity) {
    let (public_key, signing_key) = crypto_utils::generate_ed25519_keypair_for_tests(Some(seed));
    let user_id = crypto_utils::create_user_id(&public_key, Some(prefix)).unwrap();
    let identity = UserIdentity {
        signing_key,
        public_key,
        user_id: user_id.clone(),
    };
    let wallet = Wallet {
        profile: UserProfile {
            user_id,
            bundle_history: Default::default(),
        },
        store: VoucherStore::default(),
    };
    (wallet, identity)
}

/// Hilfsfunktion, um eine Standard-Definition aus dem TOML-String zu laden.
fn load_test_standard() -> VoucherStandardDefinition {
    let toml_str = include_str!("../voucher_standards/minuto_standard.toml");
    voucher_manager::load_standard_definition(toml_str).expect("Failed to load standard definition")
}

/// Fügt einen Gutschein zum Store einer Wallet hinzu. Simuliert den Anwendungsfall,
/// dass ein Ersteller seinen eigenen Gutschein zum Wallet hinzufügt.
fn add_voucher_to_wallet(wallet: &mut Wallet, voucher: Voucher, owner_id: &str) {
    let local_id = calculate_local_instance_id(&voucher, owner_id);
    wallet.store.vouchers.insert(local_id, voucher);
}

/// Hilfsfunktion, um einen einfachen Test-Gutschein zu erstellen.
fn create_test_voucher(identity: &UserIdentity, standard: &VoucherStandardDefinition) -> Voucher {
    let new_voucher_data = voucher_manager::NewVoucherData {
        validity_duration: None,
        non_redeemable_test_voucher: false,
        nominal_value: NominalValue {
            unit: "".to_string(),
            amount: "100".to_string(),
            abbreviation: "".to_string(),
            description: "Test description".to_string(),
        },
        collateral: Collateral::default(),
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
    };
    voucher_manager::create_voucher(new_voucher_data, standard, &identity.signing_key)
        .expect("Voucher creation failed")
}

// --- Tests ---

#[test]
fn test_wallet_creation_save_and_load() {
    // 1. Setup
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let mut storage = FileStorage::new(temp_dir.path());
    let password = "strongpassword123";
    let (wallet, identity) = create_new_wallet_and_identity("al", "save_load_seed");

    // 2. Speichern
    wallet.save(&mut storage, &identity, password).expect("Failed to save wallet");

    // 3. Laden und Verifizieren
    // Rekonstruiere die Identität mit demselben Seed, um den Ladevorgang zu authentifizieren.
    let (_, identity_for_load) = create_new_wallet_and_identity("al", "save_load_seed");
    let loaded_wallet = Wallet::load(&storage, &AuthMethod::Password(password), identity_for_load)
        .expect("Failed to load wallet");
    assert_eq!(wallet.profile.user_id, loaded_wallet.profile.user_id);
    assert!(loaded_wallet.store.vouchers.is_empty());

    // 4. Fehlerfall: Falsches Passwort
    let (_, identity_for_fail) = create_new_wallet_and_identity("al", "save_load_seed");
    let result = Wallet::load(&storage, &AuthMethod::Password("wrongpassword"), identity_for_fail);
    assert!(matches!(result, Err(VoucherCoreError::Storage(StorageError::AuthenticationFailed))));
}

#[test]
fn test_password_recovery_and_reset_with_data() {
    // 1. Setup: Erstelle ein Profil mit einem Gutschein.
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let mut storage = FileStorage::new(temp_dir.path());
    let initial_password = "my-secret-password";
    let (mut wallet, identity) = create_new_wallet_and_identity("re", "recovery_seed");
    let standard = load_test_standard();
    let voucher = create_test_voucher(&identity, &standard);
    let local_id = calculate_local_instance_id(&voucher, &identity.user_id);

    add_voucher_to_wallet(&mut wallet, voucher, &identity.user_id);
    assert_eq!(wallet.store.vouchers.len(), 1);

    wallet.save(&mut storage, &identity, initial_password).expect("Initial save failed");

    // 2. Wiederherstellung mit der Mnemonic-Phrase (Identität).
    // Erzeuge eine Identität für die Referenz (borrow) und eine zweite für die Wertübergabe (move).
    let (_, recovery_identity) = create_new_wallet_and_identity("re", "recovery_seed");
    let recovered_wallet = Wallet::load(
        &storage,
        &AuthMethod::RecoveryIdentity(&recovery_identity),
        create_new_wallet_and_identity("re", "recovery_seed").1,
    )
        .expect("Recovery with correct identity should succeed");

    // Überprüfe, ob die wiederhergestellten Daten (inkl. Gutschein) korrekt sind.
    assert_eq!(wallet.profile.user_id, recovered_wallet.profile.user_id);
    assert_eq!(recovered_wallet.store.vouchers.len(), 1, "Voucher should be present after recovery");
    assert!(recovered_wallet.store.vouchers.contains_key(&local_id));

    // 3. Passwort zurücksetzen.
    let new_password = "my-new-strong-password-456";
    let (_, reset_identity) = create_new_wallet_and_identity("re", "recovery_seed");
    Wallet::reset_password(&mut storage, &reset_identity, new_password)
        .expect("Password reset should succeed");

    // 4. Verifizierung nach dem Reset.
    // Login mit altem Passwort muss fehlschlagen.
    let (_, identity_for_fail) = create_new_wallet_and_identity("re", "recovery_seed");
    let result = Wallet::load(&storage, &AuthMethod::Password(initial_password), identity_for_fail);
    assert!(matches!(result, Err(VoucherCoreError::Storage(StorageError::AuthenticationFailed))));

    // Login mit neuem Passwort muss erfolgreich sein und die Daten müssen intakt sein.
    let (_, identity_for_success) = create_new_wallet_and_identity("re", "recovery_seed");
    let final_wallet = Wallet::load(&storage, &AuthMethod::Password(new_password), identity_for_success)
        .expect("Login with new password should succeed");

    assert_eq!(wallet.profile.user_id, final_wallet.profile.user_id);
    assert_eq!(final_wallet.store.vouchers.len(), 1, "Voucher should still be present after reset");
    assert!(final_wallet.store.vouchers.contains_key(&local_id));

    // 5. Fehlerfall: Wiederherstellung mit der falschen Identität.
    let (_imposter_wallet, imposter_identity) = create_new_wallet_and_identity("im", "imposter_seed");
    let result = Wallet::load(
        &storage,
        &AuthMethod::RecoveryIdentity(&imposter_identity),
        create_new_wallet_and_identity("im", "imposter_seed").1,
    );
    assert!(matches!(result, Err(VoucherCoreError::Storage(StorageError::AuthenticationFailed))));
}

#[test]
fn test_load_with_missing_voucher_store() {
    let temp_dir = tempdir().unwrap();
    let mut storage = FileStorage::new(temp_dir.path());
    let password = "password123";
    let (wallet, identity) = create_new_wallet_and_identity("ms", "missing_store_seed");
    wallet.save(&mut storage, &identity, password).unwrap();

    // Lösche die Gutschein-Datei
    fs::remove_file(temp_dir.path().join("vouchers.enc")).unwrap();

    // Das Laden sollte trotzdem erfolgreich sein und einen leeren Store zurückgeben
    let (_, identity_for_load) = create_new_wallet_and_identity("ms", "missing_store_seed");
    let loaded_wallet = Wallet::load(&storage, &AuthMethod::Password(password), identity_for_load)
        .expect("Loading with missing voucher store should succeed");

    assert_eq!(wallet.profile.user_id, loaded_wallet.profile.user_id);
    assert!(loaded_wallet.store.vouchers.is_empty(), "Voucher store should be empty by default");
}

#[test]
fn test_load_from_corrupted_profile_file() {
    let temp_dir = tempdir().unwrap();
    let mut storage = FileStorage::new(temp_dir.path());
    let password = "password123";
    let (wallet, identity) = create_new_wallet_and_identity("cr", "corrupt_seed");
    wallet.save(&mut storage, &identity, password).unwrap();

    // Beschädige die Profil-Datei
    let profile_path = temp_dir.path().join("profile.enc");
    let mut contents = fs::read(&profile_path).unwrap();
    contents.truncate(contents.len() / 2); // Schneide die Hälfte ab
    fs::write(&profile_path, contents).unwrap();

    // Das Laden sollte mit einem Deserialisierungs- oder Formatfehler fehlschlagen
    let (_, identity_for_load) = create_new_wallet_and_identity("cr", "corrupt_seed");
    let result = Wallet::load(&storage, &AuthMethod::Password(password), identity_for_load);
    assert!(matches!(result, Err(VoucherCoreError::Storage(StorageError::InvalidFormat(_)))));
}

#[test]
fn test_empty_password_handling() {
    let temp_dir = tempdir().unwrap();
    let mut storage = FileStorage::new(temp_dir.path());
    let empty_password = "";
    let (wallet, identity) = create_new_wallet_and_identity("ep", "empty_pass_seed");

    // Speichern mit leerem Passwort sollte funktionieren
    wallet.save(&mut storage, &identity, empty_password).expect("Saving with empty password should succeed");

    // Laden mit leerem Passwort sollte funktionieren
    let (_, identity_for_load) = create_new_wallet_and_identity("ep", "empty_pass_seed");
    let loaded_wallet = Wallet::load(&storage, &AuthMethod::Password(empty_password), identity_for_load)
        .expect("Loading with empty password should succeed");
    assert_eq!(wallet.profile.user_id, loaded_wallet.profile.user_id);

    // Laden mit einem falschen, nicht-leeren Passwort sollte fehlschlagen
    let (_, identity_for_fail) = create_new_wallet_and_identity("ep", "empty_pass_seed");
    let result = Wallet::load(
        &storage,
        &AuthMethod::Password("a-real-password"),
        identity_for_fail,
    );
    assert!(matches!(result, Err(VoucherCoreError::Storage(StorageError::AuthenticationFailed))));
}

// --- Hilfsfunktionen zur Berechnung der lokalen Instanz-ID im Testkontext ---

fn get_balance_at_transaction(
    history: &[Transaction],
    user_id: &str,
    initial_amount: &str,
) -> Decimal {
    let mut current_balance = Decimal::ZERO;
    let total_amount = Decimal::from_str_exact(initial_amount).unwrap_or_default();

    for tx in history {
        let tx_amount = Decimal::from_str_exact(&tx.amount).unwrap_or_default();
        if tx.recipient_id == user_id {
            if tx.t_type == "init" {
                current_balance = total_amount;
            } else {
                current_balance += tx_amount;
            }
        } else if tx.sender_id == user_id {
            if let Some(remaining_str) = &tx.sender_remaining_amount {
                if let Ok(remaining_amount) = Decimal::from_str_exact(remaining_str) {
                    current_balance = remaining_amount;
                } else {
                    current_balance = Decimal::ZERO;
                }
            } else {
                current_balance = Decimal::ZERO;
            }
        }
    }
    current_balance
}

fn calculate_local_instance_id(voucher: &Voucher, profile_owner_id: &str) -> String {
    let mut defining_transaction_id: Option<String> = None;

    for i in (0..voucher.transactions.len()).rev() {
        let history_slice = &voucher.transactions[..=i];
        let balance =
            get_balance_at_transaction(history_slice, profile_owner_id, &voucher.nominal_value.amount);

        if balance > Decimal::ZERO {
            defining_transaction_id = Some(voucher.transactions[i].t_id.clone());
            break;
        }
    }

    let t_id = defining_transaction_id.expect("Voucher must be owned by the user.");
    let combined_string = format!("{}{}{}", voucher.voucher_id, t_id, profile_owner_id);
    get_hash(combined_string)
}