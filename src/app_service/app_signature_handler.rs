//! # src/app_service/app_signature_handler.rs
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
        let current_state = std::mem::replace(&mut self.state, AppState::Locked);

        let (result, new_state) = match current_state {
            AppState::Unlocked { mut storage, wallet, identity } => {
                match crate::services::standard_manager::verify_and_parse_standard(standard_toml_content) {
                    Err(e) => (Err(e.to_string()), AppState::Unlocked { storage, wallet, identity }),
                    Ok((verified_standard, _)) => {
                        // --- BEGINN DER TRANSAKTION ---
                        let mut temp_wallet = wallet.clone();

                        // 1. Signatur an die temporäre Wallet-Instanz anhängen.
                        match temp_wallet.process_and_attach_signature(&identity, container_bytes) {
                            Err(e) => (Err(e.to_string()), AppState::Unlocked { storage, wallet, identity }),
                            Ok(updated_instance_id) => {
                                // 2. Neuen Status basierend auf dem Ergebnis bestimmen.
                                let instance = temp_wallet.get_voucher_instance(&updated_instance_id).cloned().unwrap(); // Muss existieren
                                let operation_result = match self.determine_voucher_status(&instance.voucher, &verified_standard) {
                                    Err(fatal_error_msg) => {
                                        // Status auf der temporären Instanz aktualisieren.
                                        temp_wallet.update_voucher_status(&updated_instance_id, VoucherStatus::Quarantined {
                                            reason: fatal_error_msg.clone(),
                                        });
                                        Err(format!("Voucher quarantined due to fatal validation error: {}", fatal_error_msg))
                                    }
                                    Ok(new_status) => {
                                        // Status auf der temporären Instanz aktualisieren.
                                        temp_wallet.update_voucher_status(&updated_instance_id, new_status);
                                        Ok(())
                                    }
                                };

                                // 3. Versuchen, die Änderungen zu speichern ("Commit").
                                match temp_wallet.save(&mut storage, &identity, password) {
                                    Ok(_) => (
                                        // Erfolg: Gib das Ergebnis der Operation zurück und setze die neue Wallet-Instanz.
                                        operation_result,
                                        AppState::Unlocked { storage, wallet: temp_wallet, identity },
                                    ),
                                    Err(e) => (
                                        // Fehler: Verwirf die Änderungen und gib den Speicherfehler zurück.
                                        Err(e.to_string()),
                                        AppState::Unlocked { storage, wallet, identity },
                                    ),
                                }
                            }
                        }
                    }
                }
            }
            AppState::Locked => (Err("Wallet is locked.".to_string()), AppState::Locked),
        };

        self.state = new_state;
        result
    }
}