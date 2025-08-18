//! # src/archive/mod.rs
//!
//! Definiert die Abstraktion für ein persistentes Archiv von Gutschein-Zuständen.
//! Dies ermöglicht es, jeden historischen Zustand eines Gutscheins zu speichern und
//! später für Vergleiche (z.B. zur Double-Spend-Analyse) abzurufen.

use crate::models::voucher::{Transaction, Voucher};
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use thiserror::Error;

pub mod file_archive;

/// Ein generischer Fehler-Typ für alle Archiv-Operationen.
#[derive(Debug, Error)]
pub enum ArchiveError {
    #[error("Voucher state not found for the given identifier.")]
    NotFound,

    #[error("Underlying I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Data could not be (de)serialized: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("An unexpected error occurred: {0}")]
    Generic(String),
}

/// Die Schnittstelle für ein persistentes Gutschein-Archiv.
/// Im Gegensatz zum `Storage`-Trait, das den *aktuellen* Wallet-Zustand verwaltet,
/// dient das `VoucherArchive` dazu, *jeden jemals gesehenen* Zustand eines Gutscheins
/// zu speichern, um eine lückenlose Historie für forensische Analysen zu schaffen.
pub trait VoucherArchive {
    /// Prüft, ob der Gutschein für den `owner_id` kein Guthaben mehr aufweist,
    /// und speichert ihn in diesem Fall im Archiv.
    ///
    /// # Arguments
    /// * `voucher` - Der zu prüfende und ggf. zu archivierende Gutschein.
    /// * `owner_id` - Die ID des Nutzers, dessen Guthaben geprüft werden soll.
    /// * `standard` - Die Standard-Definition, die für die Guthaben-Berechnung benötigt wird.
    ///
    /// # Returns
    /// `Ok(true)`, wenn der Gutschein archiviert wurde, `Ok(false)`, wenn noch Guthaben vorhanden war.
    fn archive_voucher(
        &self,
        voucher: &Voucher,
        owner_id: &str,
        standard: &VoucherStandardDefinition,
    ) -> Result<bool, ArchiveError>;

    /// Ruft einen archivierten Gutschein anhand seiner ID ab.
    fn get_archived_voucher(&self, voucher_id: &str) -> Result<Voucher, ArchiveError>;

    /// Findet einen Gutschein und die darin enthaltene Transaktion anhand der Transaktions-ID.
    ///
    /// Diese Methode durchsucht das gesamte Archiv.
    fn find_transaction_by_id(
        &self,
        t_id: &str,
    ) -> Result<Option<(Voucher, Transaction)>, ArchiveError>;

    /// Findet einen Gutschein anhand einer enthaltenen Transaktions-ID.
    fn find_voucher_by_tx_id(&self, t_id: &str) -> Result<Option<Voucher>, ArchiveError>;
}