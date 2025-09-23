//! # src/app_service/queries.rs
//!
//! Enthält alle reinen Lese-Operationen (Queries) des `AppService`.

use super::{AppState, AppService};
use crate::wallet::{VoucherDetails, VoucherSummary, Wallet};
use std::collections::HashMap;

impl AppService {
    // --- Datenabfragen (Queries) ---

    /// Eine private Hilfsfunktion für den Nur-Lese-Zugriff auf das Wallet.
    /// Stellt sicher, dass das Wallet entsperrt ist, bevor eine Operation ausgeführt wird.
    ///
    /// Diese Funktion ist `pub(super)`, damit sie von allen Handlern innerhalb
    /// des `app_service`-Moduls verwendet werden kann.
    pub(super) fn get_wallet(&self) -> Result<&Wallet, String> {
        match &self.state {
            AppState::Unlocked { wallet, .. } => Ok(wallet),
            AppState::Locked => Err("Wallet is locked.".to_string()),
        }
    }

    /// Gibt eine Liste von Zusammenfassungen aller Gutscheine im Wallet zurück.
    ///
    /// # Returns
    /// Ein `Vec<VoucherSummary>` mit den wichtigsten Daten jedes Gutscheins.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet gesperrt (`Locked`) ist.
    pub fn get_voucher_summaries(&self) -> Result<Vec<VoucherSummary>, String> {
        Ok(self.get_wallet()?.list_vouchers())
    }

    /// Aggregiert die Guthaben aller aktiven Gutscheine, gruppiert nach Währung.
    ///
    /// # Returns
    /// Eine `HashMap`, die von der Währungseinheit (z.B. "Minuten") auf den Gesamtbetrag abbildet.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet gesperrt (`Locked`) ist.
    pub fn get_total_balance_by_currency(&self) -> Result<HashMap<String, String>, String> {
        Ok(self.get_wallet()?.get_total_balance_by_currency())
    }

    /// Ruft eine detaillierte Ansicht für einen einzelnen Gutschein ab.
    ///
    /// # Arguments
    /// * `local_id` - Die lokale, eindeutige ID der Gutschein-Instanz im Wallet.
    ///
    /// # Returns
    /// Die `VoucherDetails`-Struktur mit dem vollständigen Gutschein-Objekt.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet gesperrt ist oder keine Gutschein-Instanz mit dieser ID existiert.
    pub fn get_voucher_details(&self, local_id: &str) -> Result<VoucherDetails, String> {
        self.get_wallet()?
            .get_voucher_details(local_id)
            .map_err(|e| e.to_string())
    }

    /// Gibt die User-ID des Wallet-Inhabers zurück.
    ///
    /// # Returns
    /// Die `did:key`-basierte User-ID als String.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet gesperrt (`Locked`) ist.
    pub fn get_user_id(&self) -> Result<String, String> {
        Ok(self.get_wallet()?.get_user_id().to_string())
    }
}
