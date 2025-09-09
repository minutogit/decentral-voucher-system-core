//! # src/wallet/conflict_handler.rs
//!
//! Enthält die Implementierung der `Wallet`-Methoden, die für die
//! Double-Spend-Erkennung und -Verwaltung zuständig sind.

use super::{DoubleSpendCheckResult, Wallet};
use crate::error::VoucherCoreError;
use crate::services::conflict_manager;

/// Methoden zur Verwaltung des Fingerprint-Speichers und der Double-Spending-Logik.
impl Wallet {
    /// Durchsucht alle eigenen Gutscheine und aktualisiert den `own_fingerprints`-Store.
    pub fn scan_and_update_own_fingerprints(&mut self) -> Result<(), VoucherCoreError> {
        conflict_manager::scan_and_update_own_fingerprints(
            &self.voucher_store,
            &mut self.fingerprint_store,
        )
    }

    /// Führt eine vollständige Double-Spend-Prüfung durch.
    pub fn check_for_double_spend(&self) -> DoubleSpendCheckResult {
        conflict_manager::check_for_double_spend(&self.fingerprint_store)
    }

    /// Entfernt alle abgelaufenen Fingerprints aus dem Speicher.
    pub fn cleanup_expired_fingerprints(&mut self) {
        conflict_manager::cleanup_expired_fingerprints(&mut self.fingerprint_store);
    }

    /// Serialisiert die eigenen Fingerprints für den Export.
    pub fn export_own_fingerprints(&self) -> Result<Vec<u8>, VoucherCoreError> {
        conflict_manager::export_own_fingerprints(&self.fingerprint_store)
    }

    /// Importiert und merged fremde Fingerprints in den Speicher.
    pub fn import_foreign_fingerprints(
        &mut self,
        data: &[u8],
    ) -> Result<usize, VoucherCoreError> {
        conflict_manager::import_foreign_fingerprints(&mut self.fingerprint_store, data)
    }
}