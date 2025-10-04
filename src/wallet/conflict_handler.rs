//! # src/wallet/conflict_handler.rs
//!
//! Enthält die Implementierung der `Wallet`-Methoden, die für die
//! Double-Spend-Erkennung und -Verwaltung zuständig sind.

use super::{DoubleSpendCheckResult, Wallet};
use crate::models::{
    conflict::{ProofOfDoubleSpend, ResolutionEndorsement},
    profile::UserIdentity,
};
use crate::error::VoucherCoreError;
use crate::services::conflict_manager;
use crate::wallet::ProofOfDoubleSpendSummary;

/// Methoden zur Verwaltung des Fingerprint-Speichers und der Double-Spending-Logik.
impl Wallet {
    /// Durchsucht alle eigenen Gutscheine und aktualisiert den `own_fingerprints`-Store.
    /// WICHTIG: Diese Funktion bewahrt die bereits importierten `foreign_fingerprints`.
    pub fn scan_and_rebuild_fingerprints(&mut self) -> Result<(), VoucherCoreError> {
        let (own, mut known) = conflict_manager::scan_and_rebuild_fingerprints(
            &self.voucher_store,
            &self.profile.user_id,
        )?;
        // Bewahre die existierenden `foreign_fingerprints`, da diese nicht aus dem
        // lokalen `voucher_store` rekonstruiert werden können.
        known.foreign_fingerprints = std::mem::take(&mut self.known_fingerprints.foreign_fingerprints);
        self.own_fingerprints = own;
        self.known_fingerprints = known;
        Ok(())
    }

    /// Führt eine vollständige Double-Spend-Prüfung durch.
    pub fn check_for_double_spend(&self) -> DoubleSpendCheckResult {
        conflict_manager::check_for_double_spend(
            &self.own_fingerprints,
            &self.known_fingerprints,
        )
    }

    /// Entfernt alle abgelaufenen Fingerprints aus dem Speicher.
    pub fn cleanup_expired_fingerprints(&mut self) {
        conflict_manager::cleanup_known_fingerprints(&mut self.known_fingerprints)
    }

    /// Serialisiert die eigenen Fingerprints für den Export.
    pub fn export_own_fingerprints(&self) -> Result<Vec<u8>, VoucherCoreError> {
        conflict_manager::export_own_fingerprints(&self.own_fingerprints)
    }

    /// Importiert und merged fremde Fingerprints in den Speicher.
    pub fn import_foreign_fingerprints(
        &mut self,
        data: &[u8],
    ) -> Result<usize, VoucherCoreError> {
        conflict_manager::import_foreign_fingerprints(&mut self.known_fingerprints, data)
    }

    /// Gibt eine Liste von Zusammenfassungen aller bekannten Double-Spend-Konflikte zurück.
    ///
    /// Diese Methode iteriert durch den `proof_store` und erstellt für jeden
    /// `ProofOfDoubleSpend` eine vereinfachte `ProofOfDoubleSpendSummary`.
    /// Der Status (`is_resolved`, `has_l2_verdict`) wird dabei dynamisch ermittelt.
    pub fn list_conflicts(&self) -> Vec<ProofOfDoubleSpendSummary> {
        self.proof_store
            .proofs
            .values()
            .map(|proof| ProofOfDoubleSpendSummary {
                proof_id: proof.proof_id.clone(),
                offender_id: proof.offender_id.clone(),
                fork_point_prev_hash: proof.fork_point_prev_hash.clone(),
                report_timestamp: proof.report_timestamp.clone(),
                is_resolved: proof.resolutions.as_ref().map_or(false, |v| !v.is_empty()),
                has_l2_verdict: proof.layer2_verdict.is_some(),
            })
            .collect()
    }

    /// Ruft einen vollständigen `ProofOfDoubleSpend` anhand seiner ID ab.
    ///
    /// # Arguments
    /// * `proof_id` - Die deterministische ID des zu suchenden Beweises.
    pub fn get_proof_of_double_spend(
        &self,
        proof_id: &str,
    ) -> Result<ProofOfDoubleSpend, VoucherCoreError> {
        self.proof_store
            .proofs
            .get(proof_id)
            .cloned()
            .ok_or_else(|| {
                VoucherCoreError::Generic(format!("Proof with ID '{}' not found.", proof_id))
            })
    }

    /// Erstellt eine signierte Beilegungserklärung (`ResolutionEndorsement`) für einen Konflikt.
    ///
    /// Diese Methode verändert den Wallet-Zustand nicht, sondern erzeugt nur das
    /// signierte Objekt, das dann an andere Parteien gesendet werden kann.
    ///
    /// # Arguments
    /// * `identity` - Die Identität des Wallet-Besitzers (des Opfers), der die Beilegung signiert.
    /// * `proof_id` - Die ID des Konflikts, der beigelegt wird.
    /// * `notes` - Eine optionale, menschenlesbare Notiz.
    pub fn create_resolution_endorsement(
        &self,
        identity: &UserIdentity,
        proof_id: &str,
        notes: Option<String>,
    ) -> Result<ResolutionEndorsement, VoucherCoreError> {
        // Sicherstellen, dass der Beweis existiert, bevor eine Beilegung erstellt wird.
        if !self.proof_store.proofs.contains_key(proof_id) {
            return Err(VoucherCoreError::Generic(format!("Cannot create endorsement: Proof with ID '{}' not found.", proof_id)));
        }
        conflict_manager::create_and_sign_resolution_endorsement(proof_id, identity, notes)
    }

    /// Fügt eine (extern erhaltene) Beilegungserklärung zu einem bestehenden Konfliktbeweis hinzu.
    pub fn add_resolution_endorsement(
        &mut self,
        endorsement: ResolutionEndorsement,
    ) -> Result<(), VoucherCoreError> {
        let proof = self.proof_store.proofs.get_mut(&endorsement.proof_id).ok_or_else(|| VoucherCoreError::Generic(format!("Cannot add endorsement: Proof with ID '{}' not found.", endorsement.proof_id)))?;
        let resolutions = proof.resolutions.get_or_insert_with(Vec::new);
        if !resolutions.iter().any(|e| e.endorsement_id == endorsement.endorsement_id) {
            resolutions.push(endorsement);
        }
        Ok(())
    }
}