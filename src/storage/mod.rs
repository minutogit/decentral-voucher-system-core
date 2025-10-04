//! # src/storage/mod.rs
//!
//! Definiert die Abstraktion für die persistente Speicherung von Wallet-Daten.
//! Dies ermöglicht es, die Kernlogik von der konkreten Speichermethode zu entkoppeln.

use crate::models::conflict::{KnownFingerprints, OwnFingerprints, ProofStore};
use crate::models::profile::{BundleMetadataStore, UserIdentity, UserProfile, VoucherStore};
pub mod file_storage;
use thiserror::Error;

/// Ein generischer Fehler-Typ für alle Speicheroperationen.
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Authentication failed: Invalid password or recovery identity.")]
    AuthenticationFailed,

    #[error("Data not found for the given identifier.")]
    NotFound,

    #[error("Data is corrupted or has an invalid format: {0}")]
    InvalidFormat(String),

    #[error("Underlying I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("An unexpected error occurred: {0}")]
    Generic(String),
}

/// Definiert die Authentifizierungsmethode für den Zugriff auf den Speicher.
pub enum AuthMethod<'a> {
    /// Authentifizierung mittels eines Passworts.
    Password(&'a str),
    /// Authentifizierung mittels einer Mnemonic-Phrase (für die Wiederherstellung).
    Mnemonic(&'a str, Option<&'a str>),
    /// Authentifizierung mittels der kryptographischen Identität (für die Wiederherstellung).
    RecoveryIdentity(&'a UserIdentity),
}

impl<'a> AuthMethod<'a> {
    /// Extrahiert das Passwort als `&str`, wenn die Methode `Password` ist.
    pub fn get_password(&self) -> Result<&'a str, StorageError> {
        match self {
            AuthMethod::Password(p) => Ok(p),
            _ => Err(StorageError::Generic("Password not available for this auth method".to_string())),
        }
    }
}

/// Die Schnittstelle für persistente Speicherung.
/// Jede Methode ist eine atomare Operation für ein komplettes Wallet.
pub trait Storage {
    /// Lädt und entschlüsselt das Kern-Wallet (Profil und VoucherStore).
    fn load_wallet(
        &self,
        auth: &AuthMethod,
    ) -> Result<(UserProfile, VoucherStore, UserIdentity), StorageError>;

    /// Speichert und verschlüsselt das Kern-Wallet (Profil und VoucherStore).
    /// Muss auch die `UserIdentity` erhalten, um beim ersten Speichern den Wiederherstellungs-Schlüssel zu erstellen.
    fn save_wallet(
        &mut self,
        profile: &UserProfile,
        store: &VoucherStore,
        identity: &UserIdentity,
        password: &str,
    ) -> Result<(), StorageError>;

    /// Setzt das Passwort zurück, indem es das Passwort-Schloss mit dem Wiederherstellungs-Schlüssel neu erstellt.
    fn reset_password(
        &mut self,
        identity: &UserIdentity,
        new_password: &str,
    ) -> Result<(), StorageError>;

    /// Prüft, ob bereits ein Profil am Speicherort existiert.
    fn profile_exists(&self) -> bool;

    /// Lädt und entschlüsselt den `KnownFingerprints`-Store.
    fn load_known_fingerprints(&self, user_id: &str, auth: &AuthMethod) -> Result<KnownFingerprints, StorageError>;

    /// Speichert und verschlüsselt den `KnownFingerprints`-Store.
    fn save_known_fingerprints(
        &mut self,
        user_id: &str,
        password: &str,
        fingerprints: &KnownFingerprints,
    ) -> Result<(), StorageError>;

    /// Lädt und entschlüsselt den kritischen `OwnFingerprints`-Store.
    fn load_own_fingerprints(&self, user_id: &str, auth: &AuthMethod) -> Result<OwnFingerprints, StorageError>;

    /// Speichert und verschlüsselt den kritischen `OwnFingerprints`-Store.
    fn save_own_fingerprints(
        &mut self,
        user_id: &str,
        password: &str,
        fingerprints: &OwnFingerprints,
    ) -> Result<(), StorageError>;

    /// Lädt und entschlüsselt die Metadaten der Transaktionsbündel.
    fn load_bundle_metadata(
        &self,
        user_id: &str,
        auth: &AuthMethod,
    ) -> Result<BundleMetadataStore, StorageError>;

    /// Speichert und verschlüsselt die Metadaten der Transaktionsbündel.
    fn save_bundle_metadata(
        &mut self,
        user_id: &str,
        password: &str,
        metadata: &BundleMetadataStore,
    ) -> Result<(), StorageError>;


    /// Lädt und entschlüsselt den ProofStore.
    fn load_proofs(&self, user_id: &str, auth: &AuthMethod) -> Result<ProofStore, StorageError>;

    /// Speichert und verschlüsselt den ProofStore.
    fn save_proofs(
        &mut self,
        user_id: &str,
        password: &str,
        proof_store: &ProofStore,
    ) -> Result<(), StorageError>;

    /// Speichert einen beliebigen, benannten Datenblock verschlüsselt.
    ///
    /// Diese Funktion ermöglicht es der Anwendung, eigene Daten sicher im Kontext des
    /// Wallets zu speichern, ohne eigene Schlüssel verwalten zu müssen.
    ///
    /// # Arguments
    /// * `user_id` - Die ID des Benutzers, dem die Daten zugeordnet sind.
    /// * `password` - Das Passwort zum Ableiten des Verschlüsselungsschlüssels.
    /// * `name` - Ein eindeutiger Name für den Datenblock (z.B. "app_settings").
    /// * `data` - Die zu verschlüsselnden Rohdaten.
    fn save_arbitrary_data(&mut self, user_id: &str, password: &str, name: &str, data: &[u8]) -> Result<(), StorageError>;

    /// Lädt einen beliebigen, benannten und verschlüsselten Datenblock.
    ///
    /// # Arguments
    /// * `user_id` - Die ID des Benutzers, dem die Daten zugeordnet sind.
    /// * `auth` - Die Authentifizierungsmethode zum Entschlüsseln.
    /// * `name` - Der Name des zu ladenden Datenblocks.
    fn load_arbitrary_data(&self, user_id: &str, auth: &AuthMethod, name: &str) -> Result<Vec<u8>, StorageError>;
}