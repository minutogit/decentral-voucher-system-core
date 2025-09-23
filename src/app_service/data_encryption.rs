//! # src/app_service/data_encryption.rs
//!
//! Enthält die `AppService`-Methoden zur Ver- und Entschlüsselung von
//! beliebigen, anwendungsspezifischen Daten.

use super::{AppState, AppService};
use crate::storage::{AuthMethod, Storage};

impl AppService {
    // --- Generische Datenverschlüsselung ---

    /// Speichert einen beliebigen Byte-Slice verschlüsselt auf der Festplatte.
    ///
    /// Diese Methode nutzt den gleichen sicheren Verschlüsselungsmechanismus wie das Wallet selbst.
    /// Sie ist ideal, um anwendungsspezifische Daten (z.B. Konfigurationen, Kontakte)
    /// sicher abzulegen, ohne dass die App eigene Schlüssel verwalten muss.
    ///
    /// # Arguments
    /// * `name` - Ein eindeutiger Name für die Daten, dient als Dateiname (z.B. "settings").
    /// * `data` - Der `&[u8]`-Slice, der gespeichert werden soll.
    /// * `password` - Das aktuelle Passwort des Benutzers zum Verschlüsseln.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet gesperrt ist oder der Schreibvorgang misslingt.
    pub fn save_encrypted_data(
        &mut self,
        name: &str,
        data: &[u8],
        password: &str,
    ) -> Result<(), String> {
        match &mut self.state {
            AppState::Unlocked { identity, .. } => self
                .storage
                .save_arbitrary_data(&identity.user_id, password, name, data)
                .map_err(|e| e.to_string()),
            AppState::Locked => Err("Wallet is locked.".to_string()),
        }
    }

    /// Lädt und entschlüsselt einen zuvor gespeicherten, beliebigen Datenblock.
    ///
    /// # Arguments
    /// * `name` - Der Name der zu ladenden Daten.
    /// * `password` - Das Passwort des Benutzers. Aus Sicherheitsgründen wird das Passwort
    ///   für jede Leseoperation benötigt, um den Entschlüsselungsschlüssel abzuleiten.
    ///
    /// # Returns
    /// Die entschlüsselten Daten als `Vec<u8>`.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet gesperrt ist, das Passwort falsch ist oder die Daten nicht gefunden werden können.
    pub fn load_encrypted_data(&self, name: &str, password: &str) -> Result<Vec<u8>, String> {
        match &self.state {
            AppState::Unlocked { identity, .. } => {
                let auth_method = AuthMethod::Password(password);
                self.storage
                    .load_arbitrary_data(&identity.user_id, &auth_method, name)
                    .map_err(|e| e.to_string())
            }
            AppState::Locked => {
                Err("Cannot load data while wallet is locked. Please log in first.".to_string())
            }
        }
    }
}