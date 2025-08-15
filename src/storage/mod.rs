//! # src/storage/mod.rs
//!
//! Definiert die Abstraktion für die persistente Speicherung von Wallet-Daten.
//! Dies ermöglicht es, die Kernlogik von der konkreten Speichermethode zu entkoppeln.

use crate::models::profile::{UserIdentity, UserProfile, VoucherStore};
use crate::models::fingerprint::FingerprintStore;
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
    /// Lädt und entschlüsselt das Profil und den VoucherStore.
    fn load(&self, auth: &AuthMethod) -> Result<(UserProfile, VoucherStore), StorageError>;

    /// Speichert und verschlüsselt das Profil und den VoucherStore.
    /// Muss auch die `UserIdentity` erhalten, um beim ersten Speichern den Wiederherstellungs-Schlüssel zu erstellen.
    fn save(
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

    /// Lädt und entschlüsselt den FingerprintStore.
    fn load_fingerprints(&self, user_id: &str, auth: &AuthMethod) -> Result<FingerprintStore, StorageError>;

    /// Speichert und verschlüsselt den FingerprintStore.
    fn save_fingerprints(
        &mut self,
        user_id: &str,
        password: &str,
        fingerprint_store: &FingerprintStore,
    ) -> Result<(), StorageError>;
}