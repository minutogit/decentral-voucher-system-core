//! # src/error.rs
//!
//! Definiert den zentralen Fehlertyp für die gesamte voucher_core-Bibliothek.
//! Verwendet `thiserror` zur einfachen Erstellung von aussagekräftigen Fehlern
//! und zur automatischen Konvertierung von untergeordneten Fehlertypen.

use thiserror::Error;

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
    Manager(#[from] crate::services::voucher_manager::VoucherManagerError),

    /// Ein Fehler bei der Verarbeitung von JSON (Serialisierung oder Deserialisierung).
    #[error("JSON Processing Error: {0}")]
    Json(#[from] serde_json::Error),

    /// Ein Fehler bei der Deserialisierung von TOML (z.B. beim Laden einer Standard-Definition).
    #[error("TOML Deserialization Error: {0}")]
    Toml(#[from] toml::de::Error),

    /// Ein Fehler bei der Konvertierung oder Berechnung von Beträgen.
    #[error("Amount Conversion Error: {0}")]
    AmountConversion(#[from] rust_decimal::Error),

    /// Ein Platzhalter für allgemeine kryptographische Fehler, die nicht von anderen Typen abgedeckt werden.
    #[error("Cryptography error: {0}")]
    Crypto(String),

    /// Ein Fehler bei I/O-Operationen (z.B. beim zukünftigen Speichern/Laden von Profilen).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}