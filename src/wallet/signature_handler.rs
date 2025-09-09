//! # src/wallet/signature_handler.rs
//!
//! Enthält die Implementierung der `Wallet`-Methoden, die für den
//! Signatur-Workflow zuständig sind (Anfragen, Erstellen, Verarbeiten).

use super::Wallet;
use crate::error::VoucherCoreError;
use crate::models::profile::{UserIdentity, VoucherStatus};
use crate::models::secure_container::{PayloadType, SecureContainer};
use crate::models::signature::DetachedSignature;
use crate::models::voucher::Voucher;
use crate::services::utils::to_canonical_json;

/// Methoden für den Signatur-Workflow.
impl Wallet {
    /// Erstellt einen `SecureContainer`, um einen Gutschein zur Unterzeichnung zu versenden.
    ///
    /// Diese Funktion verändert den Wallet-Zustand nicht. Sie dient nur dazu, eine
    /// Anfrage zu verpacken.
    ///
    /// # Arguments
    /// * `identity` - Die Identität des anfragenden Gutschein-Besitzers.
    /// * `local_instance_id` - Die ID des Gutscheins im lokalen `voucher_store`.
    /// * `recipient_id` - Die User ID des potenziellen Unterzeichners.
    ///
    /// # Returns
    /// Die serialisierten Bytes des `SecureContainer`.
    pub fn create_signing_request(
        &self,
        identity: &UserIdentity,
        local_instance_id: &str,
        recipient_id: &str,
    ) -> Result<Vec<u8>, VoucherCoreError> {
        let (voucher, _) = self
            .voucher_store
            .vouchers
            .get(local_instance_id)
            .ok_or(VoucherCoreError::VoucherNotFound(
                local_instance_id.to_string(),
            ))?;

        let payload = to_canonical_json(voucher)?;

        let container = crate::services::secure_container_manager::create_secure_container(
            identity,
            &[recipient_id.to_string()],
            payload.as_bytes(),
            PayloadType::VoucherForSigning,
        )?;

        Ok(serde_json::to_vec(&container)?)
    }

    /// Erstellt eine `DetachedSignature` für einen Gutschein und verpackt sie in einem
    /// `SecureContainer` für den Rückversand.
    ///
    /// # Arguments
    /// * `identity` - Die Identität des Unterzeichners.
    /// * `voucher_to_sign` - Der Gutschein, der unterzeichnet werden soll (vom Client validiert).
    /// * `signature_data` - Die vom Client vorbereiteten Metadaten der Signatur.
    /// * `original_sender_id` - Die User ID des ursprünglichen Anfragers (Empfänger der Antwort).
    ///
    /// # Returns
    /// Die serialisierten Bytes des `SecureContainer` mit der Signatur.
    pub fn create_detached_signature_response(
        &self,
        identity: &UserIdentity,
        voucher_to_sign: &Voucher,
        signature_data: DetachedSignature,
        original_sender_id: &str,
    ) -> Result<Vec<u8>, VoucherCoreError> {
        let signed_signature =
            crate::services::signature_manager::complete_and_sign_detached_signature(
                signature_data,
                &voucher_to_sign.voucher_id,
                identity,
            )?;

        let payload = to_canonical_json(&signed_signature)?;

        let container = crate::services::secure_container_manager::create_secure_container(
            identity,
            &[original_sender_id.to_string()],
            payload.as_bytes(),
            PayloadType::DetachedSignature,
        )?;

        Ok(serde_json::to_vec(&container)?)
    }

    /// Verarbeitet einen `SecureContainer`, der eine `DetachedSignature` enthält,
    /// und fügt diese dem entsprechenden lokalen Gutschein hinzu.
    ///
    /// # Arguments
    /// * `identity` - Die Identität des Empfängers.
    /// * `container_bytes` - Die empfangenen Container-Daten.
    ///
    /// # Returns
    /// Ein `Result`, das bei Erfolg leer ist.
    pub fn process_and_attach_signature(
        &mut self,
        identity: &UserIdentity,
        container_bytes: &[u8],
    ) -> Result<(), VoucherCoreError> {
        let container: SecureContainer = serde_json::from_slice(container_bytes)?;
        let (payload, payload_type) =
            crate::services::secure_container_manager::open_secure_container(&container, identity)?;

        if !matches!(payload_type, PayloadType::DetachedSignature) {
            return Err(VoucherCoreError::InvalidPayloadType);
        }

        let signature: DetachedSignature = serde_json::from_slice(&payload)?;
        crate::services::signature_manager::validate_detached_signature(&signature)?;

        let voucher_id = match &signature {
            DetachedSignature::Guarantor(s) => &s.voucher_id,
            DetachedSignature::Additional(s) => &s.voucher_id,
        };

        let (target_voucher, _) = self
            .find_active_voucher_by_voucher_id(voucher_id)
            .ok_or_else(|| VoucherCoreError::VoucherNotFound(voucher_id.clone()))?;

        match signature {
            DetachedSignature::Guarantor(s) => target_voucher.guarantor_signatures.push(s),
            DetachedSignature::Additional(s) => target_voucher.additional_signatures.push(s),
        }

        Ok(())
    }

    /// Findet die aktive Instanz eines Gutscheins anhand seiner globalen `voucher_id`.
    fn find_active_voucher_by_voucher_id(
        &mut self,
        voucher_id: &str,
    ) -> Option<(&mut Voucher, &mut VoucherStatus)> {
        self.voucher_store
            .vouchers
            .values_mut()
            .find(|(voucher, status)| {
                voucher.voucher_id == voucher_id && *status == VoucherStatus::Active
            })
            .map(|(voucher, status)| (voucher, status))
    }
}