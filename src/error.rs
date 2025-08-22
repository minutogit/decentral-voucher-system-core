//! # src/error.rs
//!
//! Definiert den zentralen Fehlertyp für die gesamte voucher_core-Bibliothek.
//! Verwendet `thiserror` zur einfachen Erstellung von aussagekräftigen Fehlern
//! und zur automatischen Konvertierung von untergeordneten Fehlertypen.

use thiserror::Error;
use crate::{
    services::{
        crypto_utils::{GetPubkeyError, SymmetricEncryptionError},
        // ContainerManagerError wird wieder benötigt
        secure_container_manager::ContainerManagerError,
        voucher_manager::VoucherManagerError, 
    },
    storage::StorageError,
};
use crate::models::profile::VoucherStatus;

/// Der zentrale Fehlertyp für alle Operationen in der `voucher_core`-Bibliothek.
///
/// Dieser Enum fasst Fehler aus allen Modulen (Manager, Validierung, Crypto, Serialisierung)
/// an einem Ort zusammen und bildet die einheitliche Fehler-API der Bibliothek.
#[derive(Error, Debug)]
pub enum VoucherCoreError {
    /// Ein Fehler, der während der Gutschein-Validierung aufgetreten ist.
    /// Kapselt den spezifischeren `ValidationError`-Typ.
    #[error("Validation Error: {0}")]
    Validation(#[from] crate::services::voucher_validation::ValidationError),

    /// Ein Fehler, der während der Gutschein-Verwaltung (Erstellung, Transaktionen) aufgetreten ist.
    /// Kapselt den spezifischeren `VoucherManagerError`-Typ.
    #[error("Voucher Manager Error: {0}")]
    Manager(#[from] VoucherManagerError),

    /// Ein Fehler, der während einer Speicheroperation (Laden, Speichern) aufgetreten ist.
    #[error("Storage Error: {0}")]
    Storage(#[from] StorageError),

    /// Ein Fehler, der bei der Verarbeitung eines `SecureContainer` auftrat.
    #[error("Secure Container Error: {0}")]
    Container(#[from] ContainerManagerError),

    /// Ein Fehler, der während einer Archiv-Operation aufgetreten ist.
    #[error("Archive error: {0}")]
    Archive(#[from] crate::archive::ArchiveError),

    /// Ein Fehler bei der Verarbeitung von JSON (Serialisierung oder Deserialisierung).
    #[error("JSON Processing Error: {0}")]
    Json(#[from] serde_json::Error),

    /// Ein Fehler bei der Deserialisierung von TOML (z.B. beim Laden einer Standard-Definition).
    #[error("TOML Deserialization Error: {0}")]
    Toml(#[from] toml::de::Error),

    /// Ein Fehler bei der Konvertierung oder Berechnung von Beträgen.
    #[error("Amount Conversion Error: {0}")]
    AmountConversion(#[from] rust_decimal::Error),

    /// Ein Fehler bei der symmetrischen Ver- oder Entschlüsselung.
    /// Kapselt den spezifischen `SymmetricEncryptionError`-Typ.
    #[error("Symmetric Encryption Error: {0}")]
    SymmetricEncryption(#[from] SymmetricEncryptionError),

    /// Ein Fehler bei der Verarbeitung einer User ID oder eines Public Keys.
    #[error("User ID or Key Error: {0}")]
    KeyOrId(#[from] GetPubkeyError),

    /// Ein Platzhalter für allgemeine kryptographische Fehler, die nicht von anderen Typen abgedeckt werden.
    #[error("Cryptography error: {0}")]
    Crypto(String),

    /// Ein Fehler bei I/O-Operationen (z.B. beim zukünftigen Speichern/Laden von Profilen).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Ein allgemeiner Fehler, der für verschiedene Zwecke verwendet werden kann.
    #[error("Generic error: {0}")]
    Generic(String),

    /// Der im `SecureContainer` gefundene Payload-Typ entspricht nicht dem erwarteten Typ.
    #[error("Invalid payload type in secure container.")]
    InvalidPayloadType,

    /// Es wurde versucht, eine Aktion mit einem Gutschein durchzuführen, der unter Quarantäne steht.
    #[error("Action aborted: The voucher is quarantined due to a detected double-spend conflict.")]
    VoucherInQuarantine,

    /// Eine Funktion oder ein Codepfad ist noch nicht implementiert.
    #[error("Feature not implemented yet: {0}")]
    NotImplemented(String),

    /// Der angeforderte Gutschein wurde im Wallet-Speicher nicht gefunden.
    #[error("Voucher with local instance ID '{0}' not found in wallet.")]
    VoucherNotFound(String),

    /// Es wurde versucht, eine Aktion mit einem Gutschein durchzuführen, der nicht den Status 'Active' hat.
    #[error("Action requires an active voucher, but its status is {0:?}.")]
    VoucherNotActive(VoucherStatus),

    /// Die proaktive, lokale Prüfung hat einen versuchten Double Spend verhindert.
    #[error("Double spend attempt blocked: A transaction has already been issued from this voucher state.")]
    DoubleSpendAttemptBlocked,

    /// Ein Fehler bei der Base58-Dekodierung.
    #[error("Base58 decode error: {0}")]
    Bs58Decode(#[from] bs58::decode::Error),

    /// Ein Fehler in der ed25519-Kryptographiebibliothek.
    #[error("Ed25519 crypto error: {0}")]
    Ed25519(#[from] ed25519_dalek::ed25519::Error),

    /// Die Daten in einer Signatur (z.B. voucher_id) stimmen nicht mit dem Kontext überein.
    #[error("Mismatched signature data: {0}")]
    MismatchedSignatureData(String),
}