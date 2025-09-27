//! # src/app_service/command_handler.rs
//!
//! Enthält die zentralen, schreibenden Aktionen (Commands) des `AppService`,
//! die den Zustand des Wallets verändern und persistieren.

use super::{AppState, AppService};
use crate::archive::VoucherArchive;
use crate::models::conflict::ResolutionEndorsement;
use crate::models::voucher::Voucher;
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use crate::services::voucher_manager::NewVoucherData;
use crate::wallet::ProcessBundleResult;
use std::collections::HashMap;

impl AppService {
    // --- Aktionen (Commands) ---

    /// Erstellt einen brandneuen Gutschein, fügt ihn zum Wallet hinzu und speichert den Zustand.
    ///
    /// # Arguments
    /// * `standard_definition` - Die Regeln des Standards, nach dem der Gutschein erstellt wird.
    /// * `data` - Die spezifischen Daten für den neuen Gutschein (z.B. Betrag).
    /// * `password` - Das Passwort, um den aktualisierten Wallet-Zustand zu speichern.
    ///
    /// # Returns
    /// Das vollständig erstellte `Voucher`-Objekt.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet gesperrt ist, die Erstellung fehlschlägt oder der Speicherzugriff misslingt.
    pub fn create_new_voucher(
        &mut self,
        standard_toml_content: &str,
        lang_preference: &str,
        data: NewVoucherData,
        password: &str,
    ) -> Result<Voucher, String> {
        let current_state = std::mem::replace(&mut self.state, AppState::Locked);

        let (result, new_state) = match current_state {
            AppState::Unlocked { wallet, identity } => {
                match crate::services::standard_manager::verify_and_parse_standard(
                    standard_toml_content,
                ) {
                    Err(e) => (Err(e.to_string()), AppState::Unlocked { wallet, identity }),
                    Ok((verified_standard, standard_hash)) => {
                        match crate::services::voucher_manager::create_voucher(
                            data,
                            &verified_standard,
                            &standard_hash,
                            &identity.signing_key,
                            lang_preference,
                        ) {
                            Err(e) => (Err(e.to_string()), AppState::Unlocked { wallet, identity }),
                            Ok(new_voucher) => {
                                match self.determine_voucher_status(&new_voucher, &verified_standard)
                                {
                                    Err(e) => (Err(e), AppState::Unlocked { wallet, identity }),
                                    Ok(initial_status) => {
                                        // TRANSANKTIONALER ANSATZ:
                                        // 1. Erstelle eine temporäre Kopie des Wallets für die Änderungen.
                                        let mut temp_wallet = wallet.clone();
                                        let local_id = crate::wallet::Wallet::calculate_local_instance_id(&new_voucher, &identity.user_id).unwrap();
                                        temp_wallet.add_voucher_instance(local_id, new_voucher.clone(), initial_status);

                                        // 2. Versuche, die Kopie zu speichern. Dies ist der "Commit"-Punkt.
                                        match temp_wallet.save(&mut self.storage, &identity, password) {
                                            Ok(_) => (
                                                // 3a. Erfolg: Gib die modifizierte Kopie als neuen Zustand zurück.
                                                Ok(new_voucher),
                                                AppState::Unlocked { wallet: temp_wallet, identity },
                                            ),
                                            Err(e) => (
                                                // 3b. Fehler: Verwirf die Kopie und gib den originalen,
                                                // unberührten Zustand zurück.
                                                Err(e.to_string()),
                                                AppState::Unlocked { wallet, identity },
                                            ),
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            AppState::Locked => (Err("Wallet is locked.".to_string()), current_state),
        };

        self.state = new_state;
        result
    }

    /// Erstellt eine Transaktion, verpackt sie in ein `SecureContainer`-Bundle und speichert den neuen Wallet-Zustand.
    ///
    /// # Arguments
    /// * `local_instance_id` - Die ID des zu verwendenden Gutscheins.
    /// * `recipient_id` - Die User-ID des Empfängers.
    /// * `amount_to_send` - Der zu sendende Betrag als String.
    /// * `notes` - Optionale Notizen für den Empfänger.
    /// * `archive` - Ein optionaler `VoucherArchive`-Trait, um den neuen Zustand forensisch zu sichern.
    /// * `password` - Das Passwort, um den aktualisierten Wallet-Zustand zu speichern.
    ///
    /// # Returns
    /// Die serialisierten Bytes des verschlüsselten `SecureContainer`-Bundles, bereit zum Versand.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet gesperrt ist, die Transaktion ungültig ist oder der Speicherzugriff misslingt.
    pub fn create_transfer_bundle(
        &mut self,
        standard_definition: &VoucherStandardDefinition,
        local_instance_id: &str,
        recipient_id: &str,
        amount_to_send: &str,
        notes: Option<String>,
        archive: Option<&dyn VoucherArchive>,
        password: &str,
    ) -> Result<Vec<u8>, String> {
        let current_state = std::mem::replace(&mut self.state, AppState::Locked);
 
        let (result, new_state) = match current_state {
            AppState::Unlocked { wallet, identity } => {
                // TRANSANKTIONALER ANSATZ:
                // 1. Erstelle eine temporäre Kopie des Wallets für die Änderungen.
                let mut temp_wallet = wallet.clone();
 
                // 2. Führe die Operation auf der Kopie aus.
                match temp_wallet.create_transfer(
                    &identity,
                    standard_definition,
                    local_instance_id,
                    recipient_id,
                    amount_to_send,
                    notes,
                    archive,
                ) {
                    // 3. Versuche, die Kopie zu speichern ("Commit").
                    Ok((bundle_bytes, _)) => {
                        match temp_wallet.save(&mut self.storage, &identity, password) {
                            Ok(_) => (
                                // 4a. Erfolg: Gib die modifizierte Kopie als neuen Zustand zurück.
                                Ok(bundle_bytes),
                                AppState::Unlocked { wallet: temp_wallet, identity },
                            ),
                            Err(e) => (
                                // 4b. Fehler: Verwirf die Kopie und gib den originalen,
                                // unberührten Zustand zurück.
                                Err(e.to_string()),
                                AppState::Unlocked { wallet, identity },
                            ),
                        }
                    }
                    Err(e) => (Err(e.to_string()), AppState::Unlocked { wallet, identity }),
                }
            }
            AppState::Locked => (Err("Wallet is locked.".to_string()), AppState::Locked),
        };
        self.state = new_state;
        result
    }
 
    /// Verarbeitet ein empfangenes Transaktions- oder Signatur-Bundle und speichert den neuen Wallet-Zustand.
    ///
    /// # Arguments
    /// * `bundle_data` - Die rohen Bytes des empfangenen `SecureContainer`.
    /// * `archive` - Ein optionaler `VoucherArchive`-Trait, um die neuen Zustände zu sichern.
    /// * `password` - Das Passwort, um den aktualisierten Wallet-Zustand zu speichern.
    ///
    /// # Returns
    /// Ein `ProcessBundleResult`, das Metadaten und das Ergebnis einer eventuellen Double-Spend-Prüfung enthält.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet gesperrt ist, das Bundle ungültig ist oder der Speicherzugriff misslingt.
    pub fn receive_bundle(
        &mut self,
        bundle_data: &[u8],
        // NEU: Caller muss die benötigten Standard-Definitionen als TOML-Strings bereitstellen.
        // Key: Standard-UUID, Value: TOML-Inhalt als String.
        standard_definitions_toml: &HashMap<String, String>,
        archive: Option<&dyn VoucherArchive>,
        password: &str,
    ) -> Result<ProcessBundleResult, String> {
        let current_state = std::mem::replace(&mut self.state, AppState::Locked);
 
        let (result, new_state) = match current_state {
            AppState::Unlocked { wallet, identity } => {
                match self.validate_vouchers_in_bundle(
                    &identity,
                    bundle_data,
                    standard_definitions_toml,
                ) {
                    Err(e) => (Err(e), AppState::Unlocked { wallet, identity }),
                    Ok(_) => {
                        // TRANSANKTIONALER ANSATZ:
                        let mut temp_wallet = wallet.clone();
                        match temp_wallet
                            .process_encrypted_transaction_bundle(&identity, bundle_data, archive)
                        {
                            Ok(proc_result) => {
                                match temp_wallet.save(&mut self.storage, &identity, password) {
                                    Ok(_) => (
                                        Ok(proc_result),
                                        AppState::Unlocked {
                                            wallet: temp_wallet,
                                            identity,
                                        },
                                    ),
                                    Err(e) => (
                                        Err(e.to_string()),
                                        AppState::Unlocked { wallet, identity },
                                    ),
                                }
                            }
                            Err(e) => (Err(e.to_string()), AppState::Unlocked { wallet, identity }),
                        }
                    }
                }
            }
            AppState::Locked => (Err("Wallet is locked.".to_string()), AppState::Locked),
        };
        self.state = new_state;
        result
    }

    /// Importiert eine Beilegungserklärung und fügt sie dem entsprechenden Konfliktbeweis hinzu.
    ///
    /// Diese Operation verändert den Wallet-Zustand und speichert ihn bei Erfolg automatisch.
    ///
    /// # Arguments
    /// * `endorsement` - Die empfangene `ResolutionEndorsement`.
    /// * `password` - Das Passwort, um den aktualisierten Wallet-Zustand zu speichern.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet gesperrt ist, der zugehörige Beweis nicht
    /// gefunden wird oder der Speicherzugriff misslingt.
    pub fn import_resolution_endorsement(
        &mut self,
        endorsement: ResolutionEndorsement,
        password: &str,
    ) -> Result<(), String> {
        let current_state = std::mem::replace(&mut self.state, AppState::Locked);
        let (result, new_state) = match current_state {
            AppState::Unlocked { wallet, identity } => {
                // TRANSANKTIONALER ANSATZ:
                let mut temp_wallet = wallet.clone();
                match temp_wallet.add_resolution_endorsement(endorsement) {
                    Ok(_) => {
                        match temp_wallet.save(&mut self.storage, &identity, password) {
                            Ok(_) => (
                                Ok(()),
                                AppState::Unlocked {
                                    wallet: temp_wallet,
                                    identity,
                                },
                            ),
                            Err(e) => (Err(e.to_string()), AppState::Unlocked { wallet, identity }),
                        }
                    }
                    Err(e) => (Err(e.to_string()), AppState::Unlocked { wallet, identity }),
                }
            }
            AppState::Locked => (Err("Wallet is locked.".to_string()), AppState::Locked),
        };
        self.state = new_state;
        result
    }
}

