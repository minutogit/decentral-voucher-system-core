//! # src/services/profile_manager.rs
//!
//! Enthält die Logik zur Verwaltung eines `UserProfile`, insbesondere für
//! die sichere Persistenz und den Austausch von Gutscheinen mittels des `secure_container_manager`.

use crate::error::VoucherCoreError;
use crate::models::profile::{TransactionBundle, TransactionDirection, UserIdentity, UserProfile, VoucherStore};
use crate::models::secure_container::{PayloadType, SecureContainer};
use crate::models::voucher::Voucher;
use crate::services::crypto_utils::{
    self, create_user_id, get_hash, get_pubkey_from_user_id, sign_ed25519, verify_ed25519,
};
use crate::services::secure_container_manager::{
    create_secure_container, open_secure_container, ContainerManagerError,
};
use crate::services::utils::{get_current_timestamp, to_canonical_json};
use crate::services::voucher_validation::ValidationError;
use argon2::Argon2;
use ed25519_dalek::Signature;
use rand_core::{OsRng, RngCore};
use rust_decimal::Decimal;
use serde::{de::DeserializeOwned, Serialize};
use std::{fs, path::Path};

// Konstanten für die Persistenz
const SALT_SIZE: usize = 16;
const KEY_SIZE: usize = 32;
const PROFILE_FILE_NAME: &str = "profile.enc";
const VOUCHER_STORE_FILE_NAME: &str = "vouchers.enc";

/// Definiert die Fehler, die im `profile_manager`-Modul auftreten können.
#[derive(Debug, thiserror::Error)]
pub enum ProfileManagerError {
    #[error("Failed to derive key from password using Argon2: {0}")]
    KeyDerivation(String),

    #[error("I/O Error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid profile file format or length.")]
    InvalidFileFormat,

    // Der `Serialization`-Fehler wird nicht mehr benötigt, da `VoucherCoreError`
    // bereits `serde_json::Error` verarbeiten kann.
    #[error("Sender ID in bundle did not match. Expected: {expected}, Found: {found}")]
    SenderIdMismatch { expected: String, found: String },

    #[error("The digital signature of the transaction bundle is invalid.")]
    InvalidBundleSignature,

    #[error("Invalid internal voucher state: {0}")]
    InvalidVoucherState(String),
}

/// Private Hilfsfunktion zum Verschlüsseln und Schreiben von Daten in eine Datei.
/// Leitet einen Schlüssel von einem Passwort ab, verschlüsselt die Daten und schreibt
/// das Salt zusammen mit den verschlüsselten Daten.
fn encrypt_to_file<T: Serialize>(
    data: &T,
    path: &Path,
    password: &str,
) -> Result<(), VoucherCoreError> {
    let serialized_data = serde_json::to_vec(data)?;
    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);

    let mut key = [0u8; KEY_SIZE];
    Argon2::default()
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .map_err(|e| ProfileManagerError::KeyDerivation(e.to_string()))?;

    let encrypted_data_with_nonce = crypto_utils::encrypt_data(&key, &serialized_data)?;

    let mut final_data = Vec::with_capacity(SALT_SIZE + encrypted_data_with_nonce.len());
    final_data.extend_from_slice(&salt);
    final_data.extend_from_slice(&encrypted_data_with_nonce);

    fs::write(path, final_data).map_err(ProfileManagerError::from)?;
    Ok(())
}

/// Private Hilfsfunktion zum Lesen und Entschlüsseln von Daten aus einer Datei.
fn decrypt_from_file<T: DeserializeOwned>(
    path: &Path,
    password: &str,
) -> Result<T, VoucherCoreError> {
    let encrypted_file_content = fs::read(path).map_err(ProfileManagerError::from)?;
    if encrypted_file_content.len() < SALT_SIZE {
        return Err(ProfileManagerError::InvalidFileFormat.into());
    }
    let (salt_bytes, encrypted_data_with_nonce) = encrypted_file_content.split_at(SALT_SIZE);

    let mut key = [0u8; KEY_SIZE];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt_bytes, &mut key)
        .map_err(|e| ProfileManagerError::KeyDerivation(e.to_string()))?;
    let decrypted_data = crypto_utils::decrypt_data(&key, encrypted_data_with_nonce)?;
    let deserialized: T = serde_json::from_slice(&decrypted_data)?;
    Ok(deserialized)
}

/// Speichert das `UserProfile` und den `VoucherStore` sicher in zwei getrennten,
/// verschlüsselten Dateien. Der Vorgang ist atomar gestaltet, um Datenverlust zu vermeiden.
///
/// # Arguments
/// * `profile` - Das zu speichernde Nutzerprofil.
/// * `store` - Der zu speichernde Gutschein-Store.
/// * `path_dir` - Das Verzeichnis, in dem die Dateien gespeichert werden.
/// * `password` - Das Passwort zur Verschlüsselung.
pub fn save_profile_and_store_encrypted(
    profile: &UserProfile,
    store: &VoucherStore,
    path_dir: &Path,
    password: &str,
) -> Result<(), VoucherCoreError> {
    // Temporäre Dateinamen verwenden, um Atomarität zu gewährleisten.
    let profile_tmp_path = path_dir.join(format!("{}.tmp", PROFILE_FILE_NAME));
    let store_tmp_path = path_dir.join(format!("{}.tmp", VOUCHER_STORE_FILE_NAME));

    // Schritt 1: In temporäre Dateien schreiben.
    encrypt_to_file(profile, &profile_tmp_path, password)?;
    encrypt_to_file(store, &store_tmp_path, password)?;

    // Schritt 2: Temporäre Dateien atomar umbenennen. Dies geschieht nur, wenn beide
    // Schreibvorgänge erfolgreich waren.
    let final_profile_path = path_dir.join(PROFILE_FILE_NAME);
    let final_store_path = path_dir.join(VOUCHER_STORE_FILE_NAME);
    fs::rename(&profile_tmp_path, final_profile_path)?;
    fs::rename(&store_tmp_path, final_store_path)?;

    Ok(())
}

/// Lädt und entschlüsselt das `UserProfile` und den `VoucherStore` aus ihrem
/// jeweiligen Speicherort.
///
/// # Arguments
/// * `path_dir` - Das Verzeichnis, aus dem die Dateien geladen werden.
/// * `password` - Das Passwort zur Entschlüsselung.
///
/// # Returns
/// Ein Tupel, das das `UserProfile` und den `VoucherStore` enthält.
/// Wenn die `vouchers.enc` Datei nicht existiert (z.B. bei einem neuen Profil),
/// wird ein leerer `VoucherStore` zurückgegeben.
pub fn load_profile_and_store_encrypted(
    path_dir: &Path,
    password: &str,
) -> Result<(UserProfile, VoucherStore), VoucherCoreError> {
    let profile_path = path_dir.join(PROFILE_FILE_NAME);
    let store_path = path_dir.join(VOUCHER_STORE_FILE_NAME);

    // Lade immer das Profil.
    let profile: UserProfile = decrypt_from_file(&profile_path, password)?;

    // Lade den VoucherStore nur, wenn er existiert, ansonsten erstelle einen leeren.
    let store = if store_path.exists() {
        decrypt_from_file(&store_path, password)?
    } else {
        VoucherStore::default()
    };
    Ok((profile, store))
}

/// Erstellt ein neues Nutzerprofil samt Identität aus einer Mnemonic-Phrase.
pub fn create_profile_from_mnemonic(
    mnemonic_phrase: &str,
    user_prefix: Option<&str>,
) -> Result<(UserProfile, VoucherStore, UserIdentity), VoucherCoreError> {
    let (public_key, signing_key) = crate::services::crypto_utils::derive_ed25519_keypair(mnemonic_phrase, None);
    let user_id =
        create_user_id(&public_key, user_prefix).map_err(|e| VoucherCoreError::Crypto(e.to_string()))?;

    let identity = UserIdentity {
        signing_key,
        public_key,
        user_id: user_id.clone(),
    };

    let profile = UserProfile {
        user_id,
        bundle_history: Default::default(),
    };

    let store = VoucherStore::default();

    Ok((profile, store, identity))
}

/// Fügt einen Gutschein zum `VoucherStore` hinzu und verwendet dabei die korrekte lokale Instanz-ID.
pub fn add_voucher_to_store(
    store: &mut VoucherStore,
    voucher: Voucher,
    profile_owner_id: &str,
) -> Result<(), VoucherCoreError> {
    let local_id = calculate_local_instance_id(&voucher, profile_owner_id)?;
    store.vouchers.insert(local_id, voucher);
    Ok(())
}

/// Berechnet das Guthaben eines bestimmten Nutzers nach einer spezifischen Transaktionshistorie.
/// Diese private Helper-Funktion ist das Kernstück zur Ermittlung des Guthabens zu einem beliebigen
/// Zeitpunkt in der Vergangenheit.
///
/// # Arguments
/// * `history` - Ein Slice der `Transaction`-Liste, die analysiert werden soll.
/// * `user_id` - Die ID des Nutzers, dessen Guthaben berechnet wird.
/// * `initial_amount` - Der ursprüngliche Nennwert des Gutscheins als String.
///
/// # Returns
/// Das berechnete Guthaben als `Decimal`. Gibt `Decimal::ZERO` zurück bei Fehlern.
fn get_balance_at_transaction(
    history: &[crate::models::voucher::Transaction],
    user_id: &str,
    initial_amount: &str,
) -> Decimal {
    let mut current_balance = Decimal::ZERO;
    let total_amount = Decimal::from_str_exact(initial_amount).unwrap_or_default();

    for tx in history {
        let tx_amount = Decimal::from_str_exact(&tx.amount).unwrap_or_default();

        // Fall 1: Der Nutzer ist der Empfänger der Transaktion.
        if tx.recipient_id == user_id {
            if tx.t_type == "init" {
                current_balance = total_amount;
            } else {
                current_balance += tx_amount;
            }
        }
        // Fall 2: Der Nutzer ist der Sender der Transaktion.
        else if tx.sender_id == user_id {
            // Bei einem "split" wird das Guthaben auf den expliziten Restbetrag gesetzt.
            if let Some(remaining_str) = &tx.sender_remaining_amount {
                if let Ok(remaining_amount) = Decimal::from_str_exact(remaining_str) {
                    current_balance = remaining_amount;
                } else {
                    current_balance = Decimal::ZERO; // Fehlerfall
                }
            } else {
                // Bei jeder anderen Transaktion (voller Transfer, Einlösung) wird das Guthaben auf 0 gesetzt.
                current_balance = Decimal::ZERO;
            }
        }
    }
    current_balance
}

/// Berechnet eine deterministische, lokale ID für eine Gutschein-Instanz.
/// Diese ID ist entscheidend, um zwischen aktiven und archivierten Gutscheinen zu unterscheiden.
/// Sie basiert auf dem letzten Zustand, in dem der Profilinhaber ein Guthaben auf dem Gutschein hielt.
///
/// # Logic
/// 1. Iteriert rückwärts durch die Transaktionshistorie des Gutscheins.
/// 2. Findet die erste Transaktion, nach der der `profile_owner_id` ein Guthaben > 0 besaß.
///    Diese wird zur "definierenden Transaktion".
/// 3. Erzeugt einen Hash aus `voucher_id`, der `t_id` der definierenden Transaktion und der `profile_owner_id`.
///
/// # Arguments
/// * `voucher` - Der Gutschein, für den die ID berechnet werden soll.
/// * `profile_owner_id` - Die ID des Profilinhabers.
///
/// # Returns
/// Ein `Result`, das entweder die `local_voucher_instance_id` als `String` oder einen `ProfileManagerError` enthält.
fn calculate_local_instance_id(
    voucher: &Voucher,
    profile_owner_id: &str,
) -> Result<String, ProfileManagerError> {
    let mut defining_transaction_id: Option<String> = None;

    // Iteriere rückwärts durch die Indizes der Transaktionen.
    for i in (0..voucher.transactions.len()).rev() {
        let history_slice = &voucher.transactions[..=i];
        let balance = get_balance_at_transaction(
            history_slice,
            profile_owner_id,
            &voucher.nominal_value.amount,
        );

        if balance > Decimal::ZERO {
            defining_transaction_id = Some(voucher.transactions[i].t_id.clone());
            break;
        }
    }

    match defining_transaction_id {
        Some(t_id) => {
            let combined_string =
                format!("{}{}{}", voucher.voucher_id, t_id, profile_owner_id);
            Ok(get_hash(combined_string))
        }
        None => Err(ProfileManagerError::InvalidVoucherState(
            "Voucher instance never owned by profile holder.".to_string(),
        )),
    }
}

/// Erstellt ein `TransactionBundle`, verpackt es in einen `SecureContainer` und serialisiert diesen.
pub fn create_and_encrypt_transaction_bundle(
    sender_profile: &mut UserProfile,
    sender_store: &mut VoucherStore,
    sender_identity: &UserIdentity,
    vouchers: Vec<Voucher>,
    recipient_id: &str,
    notes: Option<String>,
) -> Result<Vec<u8>, VoucherCoreError> {
    // 1. Das innere Transaktionsbündel erstellen und signieren.
    let mut bundle = TransactionBundle {
        bundle_id: "".to_string(),
        sender_id: sender_identity.user_id.clone(),
        recipient_id: recipient_id.to_string(),
        vouchers: vouchers.clone(),
        timestamp: get_current_timestamp(),
        notes,
        sender_signature: "".to_string(),
    };

    let bundle_json_for_id = to_canonical_json(&bundle)?;
    bundle.bundle_id = get_hash(bundle_json_for_id);

    let signature = sign_ed25519(&sender_identity.signing_key, bundle.bundle_id.as_bytes());
    bundle.sender_signature = bs58::encode(signature.to_bytes()).into_string();
    let signed_bundle_bytes = serde_json::to_vec(&bundle)?;

    // 2. Das signierte Bündel als Payload in einen `SecureContainer` verpacken.
    let secure_container = create_secure_container(
        sender_identity,
        &[recipient_id.to_string()],
        &signed_bundle_bytes,
        PayloadType::TransactionBundle,
    )?;

    // 3. Den Container zum Transport serialisieren und das Sender-Profil aktualisieren.
    let container_bytes = serde_json::to_vec(&secure_container)?;

    let header = bundle.to_header(TransactionDirection::Sent);
    sender_profile
        .bundle_history
        .insert(header.bundle_id.clone(), header);

    for voucher in vouchers {
        let local_id = calculate_local_instance_id(&voucher, &sender_identity.user_id)?;
        sender_store.vouchers.remove(&local_id);
    }

    Ok(container_bytes)
}

/// Verarbeitet einen serialisierten `SecureContainer`, der ein `TransactionBundle` enthält.
pub fn process_encrypted_transaction_bundle(
    recipient_profile: &mut UserProfile,
    recipient_store: &mut VoucherStore,
    recipient_identity: &UserIdentity,
    container_bytes: &[u8],
) -> Result<(), VoucherCoreError> {
    // 1. Den äußeren Container deserialisieren.
    let container: SecureContainer = serde_json::from_slice(container_bytes)?;

    // 2. Den Container mit der zentralen Funktion öffnen und entschlüsseln.
    // Diese Funktion übernimmt die Signaturprüfung des Containers.
    let (decrypted_bundle_bytes, payload_type) =
        open_secure_container(&container, recipient_identity)?;

    // 3. Sicherstellen, dass der Payload-Typ korrekt ist.
    if payload_type != PayloadType::TransactionBundle {
        return Err(VoucherCoreError::Container(ContainerManagerError::NotAnIntendedRecipient)); // Simplification
    }

    // 4. Das innere TransactionBundle deserialisieren und dessen eigene Signatur verifizieren.
    let bundle: TransactionBundle = serde_json::from_slice(&decrypted_bundle_bytes)?;
    let sender_pubkey_ed = get_pubkey_from_user_id(&bundle.sender_id)?;

    // Verifiziere die *innere* Signatur des Bündels selbst.
    let signature_bytes = bs58::decode(&bundle.sender_signature)
        .into_vec()
        .map_err(|e| {
            VoucherCoreError::Validation(ValidationError::SignatureDecodeError(e.to_string()))
        })?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|e| {
        VoucherCoreError::Validation(ValidationError::SignatureDecodeError(e.to_string()))
    })?;

    if !verify_ed25519(
        &sender_pubkey_ed,
        bundle.bundle_id.as_bytes(),
        &signature,
    ) {
        return Err(ProfileManagerError::InvalidBundleSignature.into());
    }

    // 5. Bei Erfolg: Gutscheine und Historie im Profil des Empfängers aktualisieren.
    for voucher in bundle.vouchers.clone() {
        add_voucher_to_store(recipient_store, voucher, &recipient_identity.user_id)?;
    }

    let header = bundle.to_header(TransactionDirection::Received);
    recipient_profile
        .bundle_history
        .insert(header.bundle_id.clone(), header);

    Ok(())
}