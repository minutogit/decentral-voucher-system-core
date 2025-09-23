//! # src/app_service/conflict_handler.rs
//!
//! Enthält alle `AppService`-Funktionen, die sich auf das Management von
//! Double-Spend-Konflikten beziehen.

use super::{AppState, AppService};
use crate::models::conflict::{ProofOfDoubleSpend, ResolutionEndorsement};
use crate::wallet::ProofOfDoubleSpendSummary;

impl AppService {
    // --- Konflikt-Management ---

    /// Gibt eine Liste von Zusammenfassungen aller bekannten Double-Spend-Konflikte zurück.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet gesperrt (`Locked`) ist.
    pub fn list_conflicts(&self) -> Result<Vec<ProofOfDoubleSpendSummary>, String> {
        Ok(self.get_wallet()?.list_conflicts())
    }

    /// Ruft einen vollständigen `ProofOfDoubleSpend` anhand seiner ID ab.
    ///
    /// Ideal, um die Details eines Konflikts anzuzeigen oder ihn für den
    /// manuellen Austausch zu exportieren.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet gesperrt ist oder kein Beweis mit dieser ID existiert.
    pub fn get_proof_of_double_spend(&self, proof_id: &str) -> Result<ProofOfDoubleSpend, String> {
        self.get_wallet()?
            .get_proof_of_double_spend(proof_id)
            .map_err(|e| e.to_string())
    }

    /// Erstellt eine signierte Beilegungserklärung (`ResolutionEndorsement`) für einen Konflikt.
    ///
    /// Diese Operation verändert den Wallet-Zustand nicht. Sie erzeugt ein
    /// signiertes Objekt, das an andere Parteien gesendet werden kann, um zu
    /// signalisieren, dass der Konflikt aus Sicht des Wallet-Inhabers (des Opfers)
    /// gelöst wurde.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet gesperrt ist oder der referenzierte Beweis nicht existiert.
    pub fn create_resolution_endorsement(
        &self,
        proof_id: &str,
        notes: Option<String>,
    ) -> Result<ResolutionEndorsement, String> {
        match &self.state {
            AppState::Unlocked { wallet, identity } => wallet
                .create_resolution_endorsement(identity, proof_id, notes)
                .map_err(|e| e.to_string()),
            AppState::Locked => Err("Wallet is locked.".to_string()),
        }
    }
}