//! # src/app_service/signature_handler.rs
//!
//! Enthält alle `AppService`-Funktionen, die sich auf den Signatur-Workflow beziehen,
//! wie das Anfordern, Erstellen und Anhängen von losgelösten Signaturen.

use super::{AppState, AppService};
use crate::models::signature::DetachedSignature;
use crate::models::voucher::Voucher;
use crate::wallet::instance::VoucherStatus;

impl AppService {
    /// Erstellt ein Bundle, um einen Gutschein zur Unterzeichnung an einen Bürgen zu senden.
    ///
    /// Diese Operation verändert den Wallet-Zustand nicht und erfordert kein Speichern.
    ///
    /// # Returns
    /// Die serialisierten Bytes des `SecureContainer`, bereit zum Versand an den Bürgen.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet gesperrt ist oder der angeforderte Gutschein nicht existiert.
    pub fn create_signing_request_bundle(
        &self,
        local_instance_id: &str,
        recipient_id: &str,
    ) -> Result<Vec<u8>, String> {
        let wallet = self.get_wallet()?;
        let identity = match &self.state {
            AppState::Unlocked { identity, .. } => identity,
            AppState::Locked => return Err("Wallet is locked".to_string()),
        };
        wallet
            .create_signing_request(identity, local_instance_id, recipient_id)
            .map_err(|e| e.to_string())
    }

    /// Erstellt eine losgelöste Signatur als Antwort auf eine Signaturanfrage.
    ///
    /// Diese Operation wird vom Bürgen aufgerufen und verändert dessen Wallet-Zustand nicht.
    ///
    /// # Returns
    /// Die serialisierten Bytes des `SecureContainer` mit der Signatur, bereit für den Rückversand.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet des Bürgen gesperrt ist.
    pub fn create_detached_signature_response_bundle(
        &self,
        voucher_to_sign: &Voucher,
        signature_data: DetachedSignature,
        original_sender_id: &str,
    ) -> Result<Vec<u8>, String> {
        let identity = match &self.state {
            AppState::Unlocked { identity, .. } => identity,
            AppState::Locked => return Err("Wallet is locked".to_string()),
        };
        let wallet = self.get_wallet()?;
        wallet
            .create_detached_signature_response(
                identity,
                voucher_to_sign,
                signature_data,
                original_sender_id,
            )
            .map_err(|e| e.to_string())
    }

    /// Verarbeitet eine empfangene losgelöste Signatur, fügt sie dem lokalen Gutschein hinzu und speichert den Zustand.
    ///
    /// # Arguments
    /// * `container_bytes` - Die rohen Bytes des `SecureContainer`, der die Signatur enthält.
    /// * `password` - Das Passwort, um den aktualisierten Wallet-Zustand zu speichern.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet gesperrt ist, die Signatur ungültig ist, der zugehörige Gutschein nicht gefunden
    /// wird oder der Speicherzugriff misslingt.
    pub fn process_and_attach_signature(
        &mut self,
        container_bytes: &[u8],
        standard_toml_content: &str,
        password: &str,
    ) -> Result<(), String> {
        let (mut wallet, identity) = match std::mem::replace(&mut self.state, AppState::Locked) {
            AppState::Unlocked { wallet, identity } => (wallet, identity),
            AppState::Locked => return Err("Wallet is locked.".to_string()),
        };

        let (verified_standard, _) =
            match crate::services::standard_manager::verify_and_parse_standard(standard_toml_content)
            {
                Ok(res) => res,
                Err(e) => {
                    self.state = AppState::Unlocked { wallet, identity };
                    return Err(e.to_string());
                }
            };

        let updated_instance_id =
            match wallet.process_and_attach_signature(&identity, container_bytes) {
                Ok(id) => id,
                Err(e) => {
                    self.state = AppState::Unlocked { wallet, identity };
                    return Err(e.to_string());
                }
            };

        let instance = wallet
            .get_voucher_instance(&updated_instance_id)
            .cloned()
            .unwrap();
        let result = match self.determine_voucher_status(&instance.voucher, &verified_standard) {
            Err(fatal_error_msg) => {
                wallet.update_voucher_status(
                    &updated_instance_id,
                    VoucherStatus::Quarantined {
                        reason: fatal_error_msg.clone(),
                    },
                );
                wallet
                    .save(&mut self.storage, &identity, password)
                    .map_err(|e| e.to_string())?;
                Err(format!(
                    "Voucher quarantined due to fatal validation error: {}",
                    fatal_error_msg
                ))
            }
            Ok(new_status) => {
                wallet.update_voucher_status(&updated_instance_id, new_status);
                wallet
                    .save(&mut self.storage, &identity, password)
                    .map_err(|e| e.to_string())
            }
        };
        
        self.state = AppState::Unlocked { wallet, identity };
        result
    }
}