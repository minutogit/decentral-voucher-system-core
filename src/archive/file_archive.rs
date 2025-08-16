//! # src/archive/file_archive.rs
//!
//! Eine Implementierung des `VoucherArchive`-Traits, die jeden Gutschein-Zustand
//! als separate JSON-Datei in einer strukturierten Verzeichnishierarchie speichert.

use super::{ArchiveError, VoucherArchive};
use crate::models::voucher::Voucher;
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use crate::services::utils::to_canonical_json;
use crate::services::voucher_validation::get_spendable_balance;
use rust_decimal::Decimal;
use std::{fs, path::PathBuf};

/// Eine Implementierung des `VoucherArchive`-Traits, die auf dem Dateisystem basiert.
///
/// Die Struktur ist: `base_path/voucher_id/transaction_id.json`
pub struct FileVoucherArchive {
    archive_directory: PathBuf,
}

impl FileVoucherArchive {
    /// Erstellt eine neue `FileVoucherArchive`-Instanz für ein bestimmtes Basisverzeichnis.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        FileVoucherArchive {
            archive_directory: path.into(),
        }
    }
}

impl VoucherArchive for FileVoucherArchive {
    fn archive_voucher(
        &self,
        voucher: &Voucher,
        owner_id: &str,
        standard: &VoucherStandardDefinition,
    ) -> Result<bool, ArchiveError> {
        let balance = get_spendable_balance(voucher, owner_id, standard)
            .map_err(|e| ArchiveError::Generic(e.to_string()))?;

        // Nur archivieren, wenn kein Guthaben mehr vorhanden ist.
        if balance > Decimal::ZERO {
            return Ok(false);
        }

        // Speichere den Gutschein als eine einzelne Datei.
        let file_path = self.archive_directory.join(format!("{}.json", &voucher.voucher_id));
        if file_path.exists() {
            return Ok(true); // Bereits archiviert.
        }

        fs::create_dir_all(&self.archive_directory)?;
        let json_content = to_canonical_json(voucher)?;

        // Atomares Schreiben
        let temp_file_path = self
            .archive_directory
            .join(format!("{}.json.tmp", &voucher.voucher_id));
        fs::write(&temp_file_path, json_content)?;
        fs::rename(&temp_file_path, &file_path)?;

        Ok(true)
    }

    fn get_archived_voucher(&self, voucher_id: &str) -> Result<Voucher, ArchiveError> {
        let file_path = self.archive_directory.join(format!("{}.json", voucher_id));

        if !file_path.exists() {
            return Err(ArchiveError::NotFound);
        }

        let file_content = fs::read(file_path)?;
        let voucher: Voucher = serde_json::from_slice(&file_content)?;
        Ok(voucher)
    }
}