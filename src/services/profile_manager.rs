//! # src/services/profile_manager.rs
//!
//! Enthält die Logik zur Verwaltung eines `UserProfile`, insbesondere für
//! die sichere Persistenz (Verschlüsselung, Laden, Speichern) und den
//! Austausch von Gutscheinen. Implementiert eine Passwort-Wiederherstellung
//! über die aus der Mnemonic-Phrase abgeleitete User-Identität.

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
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

// Konstanten für die Persistenz
const SALT_SIZE: usize = 16;
const KEY_SIZE: usize = 32;
const PROFILE_FILE_NAME: &str = "profile.enc";
const VOUCHER_STORE_FILE_NAME: &str = "vouchers.enc";

/// Container für das verschlüsselte Nutzerprofil, inklusive Key-Wrapping-Informationen.
/// Diese Struktur wird nach `profile.enc` serialisiert.
#[derive(Serialize, Deserialize)]
struct ProfileStorageContainer {
    /// Salt für die Ableitung des Verschlüsselungsschlüssels aus dem Passwort des Nutzers.
    password_kdf_salt: [u8; SALT_SIZE],
    /// Der Master-Dateischlüssel, verschlüsselt (gewrappt) mit dem vom Passwort abgeleiteten Schlüssel.
    password_wrapped_key_with_nonce: Vec<u8>,

    /// Salt für die Ableitung des Verschlüsselungsschlüssels aus der Identität des Nutzers (Mnemonic).
    mnemonic_kdf_salt: [u8; SALT_SIZE],
    /// Der Master-Dateischlüssel, verschlüsselt (gewrappt) mit dem von der Identität abgeleiteten Schlüssel.
    mnemonic_wrapped_key_with_nonce: Vec<u8>,

    /// Die verschlüsselte `UserProfile`-Nutzlast.
    encrypted_profile_payload: Vec<u8>,
}

/// Container für den verschlüsselten Gutschein-Store.
/// Diese Struktur wird nach `vouchers.enc` serialisiert.
#[derive(Serialize, Deserialize)]
struct VoucherStorageContainer {
    /// Die verschlüsselte `VoucherStore`-Nutzlast.
    encrypted_store_payload: Vec<u8>,
}

/// Definiert die Fehler, die im `profile_manager`-Modul auftreten können.
#[derive(Debug, thiserror::Error)]
pub enum ProfileManagerError {
    #[error("Failed to derive key from password using Argon2: {0}")]
    KeyDerivation(String),

    #[error("I/O Error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid profile file format or length.")]
    InvalidFileFormat,

    #[error("Authentication failed. Invalid password or recovery identity.")]
    AuthenticationFailed,

    #[error("Sender ID in bundle did not match. Expected: {expected}, Found: {found}")]
    SenderIdMismatch { expected: String, found: String },

    #[error("The digital signature of the transaction bundle is invalid.")]
    InvalidBundleSignature,

    #[error("Invalid internal voucher state: {0}")]
    InvalidVoucherState(String),
}

/// Private Hilfsfunktion, die einen Verschlüsselungsschlüssel vom Passwort des Nutzers ableitet.
fn derive_key_from_password(
    password: &str,
    salt: &[u8; SALT_SIZE],
) -> Result<[u8; KEY_SIZE], ProfileManagerError> {
    let mut key = [0u8; KEY_SIZE];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| ProfileManagerError::KeyDerivation(e.to_string()))?;
    Ok(key)
}

/// Private Hilfsfunktion, die einen Verschlüsselungsschlüssel von der Identität des Nutzers ableitet.
/// Dies ist der "Master"-Wiederherstellungspfad.
fn derive_key_from_identity(
    identity: &UserIdentity,
    salt: &[u8; SALT_SIZE],
) -> Result<[u8; KEY_SIZE], ProfileManagerError> {
    let mut key = [0u8; KEY_SIZE];
    // Die Bytes des Signierschlüssels dienen als deterministisches Geheimnis.
    Argon2::default()
        .hash_password_into(identity.signing_key.to_bytes().as_ref(), salt, &mut key)
        .map_err(|e| ProfileManagerError::KeyDerivation(e.to_string()))?;
    Ok(key)
}

/// Speichert das `UserProfile` und den `VoucherStore` sicher in zwei getrennten,
/// verschlüsselten Dateien. Implementiert eine "Zwei-Schloss"-Mechanik für Passwort und Wiederherstellung.
///
/// # Arguments
/// * `profile` - Das zu speichernde Nutzerprofil.
/// * `store` - Der zu speichernde Gutschein-Store.
/// * `path_dir` - Das Verzeichnis, in dem die Dateien gespeichert werden.
/// * `password` - Das Passwort zur Verschlüsselung (Alltagszugriff).
/// * `identity` - Die Identität des Nutzers, zur Erstellung des Wiederherstellungs-Schlosses.
pub fn save_profile_and_store_encrypted(
    profile: &UserProfile,
    store: &VoucherStore,
    path_dir: &Path,
    password: &str,
    identity: &UserIdentity,
) -> Result<(), VoucherCoreError> {
    let profile_path = path_dir.join(PROFILE_FILE_NAME);
    let store_path = path_dir.join(VOUCHER_STORE_FILE_NAME);

    let file_key: [u8; KEY_SIZE];
    let profile_container: ProfileStorageContainer;

    if !profile_path.exists() {
        // Erster Speicher-Vorgang: Generiere einen neuen Master-Dateischlüssel und beide Schlösser.
        let mut new_file_key = [0u8; KEY_SIZE];
        OsRng.fill_bytes(&mut new_file_key);
        file_key = new_file_key;

        // Schloss 1: Passwort-basiert
        let mut pw_salt = [0u8; SALT_SIZE];
        OsRng.fill_bytes(&mut pw_salt);
        let password_key = derive_key_from_password(password, &pw_salt)?;
        let pw_wrapped_key = crypto_utils::encrypt_data(&password_key, &file_key)?;

        // Schloss 2: Mnemonic/Identitäts-basiert
        let mut mn_salt = [0u8; SALT_SIZE];
        OsRng.fill_bytes(&mut mn_salt);
        let mnemonic_key = derive_key_from_identity(identity, &mn_salt)?;
        let mn_wrapped_key = crypto_utils::encrypt_data(&mnemonic_key, &file_key)?;

        let profile_payload = crypto_utils::encrypt_data(&file_key, &serde_json::to_vec(profile)?)?;

        profile_container = ProfileStorageContainer {
            password_kdf_salt: pw_salt,
            password_wrapped_key_with_nonce: pw_wrapped_key,
            mnemonic_kdf_salt: mn_salt,
            mnemonic_wrapped_key_with_nonce: mn_wrapped_key,
            encrypted_profile_payload: profile_payload,
        };
    } else {
        // Folgender Speicher-Vorgang: Lade existierende Schlüssel, entschlüssele FileKey und verschlüssele neue Daten.
        let existing_container_bytes = fs::read(&profile_path).map_err(ProfileManagerError::from)?;
        let mut existing_container: ProfileStorageContainer =
            serde_json::from_slice(&existing_container_bytes)?;

        let password_key =
            derive_key_from_password(password, &existing_container.password_kdf_salt)?;
        let decrypted_file_key = crypto_utils::decrypt_data(
            &password_key,
            &existing_container.password_wrapped_key_with_nonce,
        )
            .map_err(|_| ProfileManagerError::AuthenticationFailed)?;

        file_key = decrypted_file_key
            .try_into()
            .map_err(|_| ProfileManagerError::InvalidFileFormat)?;

        // Verschlüssele nur die neuen Profildaten. Die Schlüssel bleiben gleich.
        existing_container.encrypted_profile_payload =
            crypto_utils::encrypt_data(&file_key, &serde_json::to_vec(profile)?)?;
        profile_container = existing_container;
    }

    // Erstelle den Voucher-Container mit den verschlüsselten Store-Daten.
    let store_payload = crypto_utils::encrypt_data(&file_key, &serde_json::to_vec(store)?)?;
    let store_container = VoucherStorageContainer {
        encrypted_store_payload: store_payload,
    };

    // Schreibe beide Container atomar auf die Festplatte.
    let profile_tmp_path = path_dir.join(format!("{}.tmp", PROFILE_FILE_NAME));
    let store_tmp_path = path_dir.join(format!("{}.tmp", VOUCHER_STORE_FILE_NAME));

    fs::write(&profile_tmp_path, serde_json::to_vec(&profile_container)?)?;
    fs::write(&store_tmp_path, serde_json::to_vec(&store_container)?)?;

    fs::rename(&profile_tmp_path, &profile_path)?;
    fs::rename(&store_tmp_path, &store_path)?;

    Ok(())
}

/// Lädt und entschlüsselt das `UserProfile` und den `VoucherStore` mittels Passwort.
///
/// # Arguments
/// * `path_dir` - Das Verzeichnis, aus dem die Dateien geladen werden.
/// * `password` - Das Passwort zur Entschlüsselung.
pub fn load_profile_and_store_encrypted(
    path_dir: &Path,
    password: &str,
) -> Result<(UserProfile, VoucherStore), VoucherCoreError> {
    let profile_path = path_dir.join(PROFILE_FILE_NAME);
    let store_path = path_dir.join(VOUCHER_STORE_FILE_NAME);

    // 1. Lade den Profil-Container
    let profile_container_bytes = fs::read(profile_path).map_err(ProfileManagerError::from)?;
    let profile_container: ProfileStorageContainer =
        serde_json::from_slice(&profile_container_bytes)?;

    // 2. Leite den Schlüssel vom Passwort ab und entschlüssele den FileKey
    let password_key = derive_key_from_password(password, &profile_container.password_kdf_salt)?;
    let file_key_bytes = crypto_utils::decrypt_data(
        &password_key,
        &profile_container.password_wrapped_key_with_nonce,
    )
        .map_err(|_| ProfileManagerError::AuthenticationFailed)?;
    let file_key: [u8; KEY_SIZE] = file_key_bytes
        .try_into()
        .map_err(|_| ProfileManagerError::InvalidFileFormat)?;

    // 3. Entschlüssele die Profil-Nutzlast
    let profile_bytes =
        crypto_utils::decrypt_data(&file_key, &profile_container.encrypted_profile_payload)?;
    let profile: UserProfile = serde_json::from_slice(&profile_bytes)?;

    // 4. Lade und entschlüssele den VoucherStore (falls vorhanden)
    let store = if store_path.exists() {
        let store_container_bytes = fs::read(store_path).map_err(ProfileManagerError::from)?;
        let store_container: VoucherStorageContainer =
            serde_json::from_slice(&store_container_bytes)?;
        let store_bytes =
            crypto_utils::decrypt_data(&file_key, &store_container.encrypted_store_payload)?;
        serde_json::from_slice(&store_bytes)?
    } else {
        VoucherStore::default()
    };

    Ok((profile, store))
}

/// Stellt den Zugriff auf das Profil über die Identität (Mnemonic) wieder her.
/// Diese Funktion wird verwendet, wenn der Benutzer sein Passwort vergessen hat.
///
/// # Arguments
/// * `path_dir` - Das Verzeichnis, in dem sich die Profildateien befinden.
/// * `identity` - Die `UserIdentity`, abgeleitet aus der Mnemonic-Phrase des Benutzers.
///
/// # Returns
/// Ein Tupel, das das wiederhergestellte `UserProfile` und den `VoucherStore` enthält.
pub fn load_profile_for_recovery(
    path_dir: &Path,
    identity: &UserIdentity,
) -> Result<(UserProfile, VoucherStore), VoucherCoreError> {
    let profile_path = path_dir.join(PROFILE_FILE_NAME);
    let store_path = path_dir.join(VOUCHER_STORE_FILE_NAME);

    // 1. Lade den Profil-Container
    let profile_container_bytes = fs::read(profile_path).map_err(ProfileManagerError::from)?;
    let profile_container: ProfileStorageContainer =
        serde_json::from_slice(&profile_container_bytes)?;

    // 2. Leite den Schlüssel von der Identität ab und entschlüssele den FileKey
    let mnemonic_key = derive_key_from_identity(identity, &profile_container.mnemonic_kdf_salt)?;
    let file_key_bytes = crypto_utils::decrypt_data(
        &mnemonic_key,
        &profile_container.mnemonic_wrapped_key_with_nonce,
    )
        .map_err(|_| ProfileManagerError::AuthenticationFailed)?; // Sollte nicht passieren, es sei denn die Identität ist falsch
    let file_key: [u8; KEY_SIZE] = file_key_bytes
        .try_into()
        .map_err(|_| ProfileManagerError::InvalidFileFormat)?;

    // 3. Entschlüssele die Profil-Nutzlast
    let profile_bytes =
        crypto_utils::decrypt_data(&file_key, &profile_container.encrypted_profile_payload)?;
    let profile: UserProfile = serde_json::from_slice(&profile_bytes)?;

    // 4. Lade und entschlüssle den VoucherStore
    let store = if store_path.exists() {
        let store_container_bytes = fs::read(store_path).map_err(ProfileManagerError::from)?;
        let store_container: VoucherStorageContainer =
            serde_json::from_slice(&store_container_bytes)?;
        let store_bytes =
            crypto_utils::decrypt_data(&file_key, &store_container.encrypted_store_payload)?;
        serde_json::from_slice(&store_bytes)?
    } else {
        VoucherStore::default()
    };

    Ok((profile, store))
}

/// Setzt das Passwort für den Profilzugriff zurück.
/// Diese Funktion wird nach einer erfolgreichen Wiederherstellung mit der Mnemonic-Phrase aufgerufen.
/// Sie erstellt ein neues "Passwort-Schloss" für den existierenden Dateischlüssel.
///
/// # Arguments
/// * `path_dir` - Das Verzeichnis der Profildateien.
/// * `identity` - Die Identität des Nutzers, um den Dateischlüssel zu entschlüsseln.
/// * `new_password` - Das neue Passwort, das festgelegt werden soll.
pub fn reset_password(
    path_dir: &Path,
    identity: &UserIdentity,
    new_password: &str,
) -> Result<(), VoucherCoreError> {
    let profile_path = path_dir.join(PROFILE_FILE_NAME);

    // Lade den existierenden Container
    let container_bytes = fs::read(&profile_path).map_err(ProfileManagerError::from)?;
    let mut container: ProfileStorageContainer = serde_json::from_slice(&container_bytes)?;

    // Entschlüssele den FileKey mit dem Wiederherstellungsschlüssel (Mnemonic)
    let mnemonic_key = derive_key_from_identity(identity, &container.mnemonic_kdf_salt)?;
    let file_key = crypto_utils::decrypt_data(
        &mnemonic_key,
        &container.mnemonic_wrapped_key_with_nonce,
    )
        .map_err(|_| ProfileManagerError::AuthenticationFailed)?;

    // Erstelle ein neues Passwort-Schloss
    let mut new_pw_salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut new_pw_salt);
    let new_password_key = derive_key_from_password(new_password, &new_pw_salt)?;
    let new_pw_wrapped_key = crypto_utils::encrypt_data(&new_password_key, &file_key)?;

    // Aktualisiere den Container mit dem neuen Schloss
    container.password_kdf_salt = new_pw_salt;
    container.password_wrapped_key_with_nonce = new_pw_wrapped_key;

    // Schreibe den aktualisierten Container atomar zurück
    let profile_tmp_path = path_dir.join(format!("{}.tmp", PROFILE_FILE_NAME));
    fs::write(&profile_tmp_path, serde_json::to_vec(&container)?)?;
    fs::rename(&profile_tmp_path, &profile_path)?;

    Ok(())
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