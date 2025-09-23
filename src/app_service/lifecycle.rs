//! # src/app_service/lifecycle.rs
//!
//! Enthält alle Funktionen, die den Lebenszyklus des `AppService` steuern,
//! wie Initialisierung, Login/Logout und Wiederherstellung.

use super::{AppService, AppState};
use crate::storage::{file_storage::FileStorage, AuthMethod};
use crate::wallet::Wallet;
use bip39::Language;
use std::path::Path;

impl AppService {
    // --- Lebenszyklus-Management ---

    /// Initialisiert einen neuen `AppService` im `Locked`-Zustand.
    ///
    /// Erstellt eine `FileStorage`-Instanz für den angegebenen Pfad. Das Verzeichnis
    /// wird bei Bedarf erstellt.
    ///
    /// # Arguments
    /// * `storage_path` - Der Pfad zum Verzeichnis, in dem die Wallet-Daten
    ///   gespeichert werden sollen.
    pub fn new(storage_path: &Path) -> Result<Self, String> {
        let storage = FileStorage::new(storage_path);
        Ok(AppService {
            storage,
            state: AppState::Locked,
        })
    }

    /// Generiert eine neue BIP-39 Mnemonic-Phrase (Seed-Wörter).
    ///
    /// Diese Methode ist statisch und kann ohne geladenes Wallet aufgerufen werden.
    ///
    /// # Arguments
    /// * `word_count` - Die gewünschte Anzahl an Wörtern. Gültige Werte sind
    ///   typischerweise 12, 15, 18, 21 oder 24.
    ///
    /// # Returns
    /// Ein `Result` mit der Mnemonic-Phrase als `String` oder einer Fehlermeldung.
    pub fn generate_mnemonic(word_count: u32) -> Result<String, String> {
        crate::services::crypto_utils::generate_mnemonic(word_count as usize, Language::English)
            .map_err(|e| e.to_string())
    }

    /// Validiert eine vom Benutzer eingegebene BIP-39 Mnemonic-Phrase.
    ///
    /// Überprüft, ob die Wörter korrekt sind und die interne Prüfsumme der Phrase
    /// gültig ist. Nützlich, um dem Benutzer direktes Feedback zu geben, bevor
    /// ein Wallet wiederhergestellt wird.
    ///
    /// Diese Methode ist statisch und kann ohne geladenes Wallet aufgerufen werden.
    ///
    /// # Arguments
    /// * `mnemonic` - Die zu überprüfende Mnemonic-Phrase.
    ///
    /// # Returns
    /// `Ok(())` bei Erfolg, andernfalls ein `Err` mit der Fehlerursache.
    pub fn validate_mnemonic(mnemonic: &str) -> Result<(), String> {
        crate::services::crypto_utils::validate_mnemonic_phrase(mnemonic)
    }

    /// Erstellt ein komplett neues Benutzerprofil und Wallet und speichert es verschlüsselt.
    ///
    /// Bei Erfolg wird der Service in den `Unlocked`-Zustand versetzt.
    ///
    /// # Arguments
    /// * `mnemonic` - Die BIP39 Mnemonic-Phrase zur Generierung der Master-Keys.
    /// * `user_prefix` - Ein optionales Präfix für die `did:key`-basierte User-ID.
    /// * `password` - Das Passwort, mit dem das neue Wallet verschlüsselt wird.
    ///
    /// # Errors
    /// Schlägt fehl, wenn die Mnemonic-Phrase ungültig ist oder das Speichern fehlschlägt.
    pub fn create_profile(
        &mut self,
        mnemonic: &str,
        user_prefix: Option<&str>,
        password: &str,
    ) -> Result<(), String> {
        let (wallet, identity) = Wallet::new_from_mnemonic(mnemonic, user_prefix)
            .map_err(|e| format!("Failed to create new wallet: {}", e))?;

        wallet
            .save(&mut self.storage, &identity, password)
            .map_err(|e| format!("Failed to save new wallet: {}", e))?;

        self.state = AppState::Unlocked { wallet, identity };
        Ok(())
    }

    /// Entsperrt ein existierendes Wallet und lädt es in den Speicher.
    ///
    /// Verwendet das Passwort, um die Wallet-Daten zu entschlüsseln und zu laden.
    /// Bei Erfolg wird der Service in den `Unlocked`-Zustand versetzt.
    ///
    /// # Arguments
    /// * `password` - Das Passwort zum Entschlüsseln des Wallets.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Passwort falsch ist, oder wenn
    /// die Wallet-Dateien nicht gelesen werden können.
    pub fn login(&mut self, password: &str) -> Result<(), String> {
        // Rufe die refaktorisierte Wallet::load-Funktion auf.
        // Diese gibt nun das Wallet UND die entschlüsselte UserIdentity zurück.
        let (wallet, identity) = Wallet::load(&self.storage, &AuthMethod::Password(password))
            .map_err(|e| format!("Login failed (check password): {}", e))?;

        self.state = AppState::Unlocked { wallet, identity };
        Ok(())
    }

    /// Stellt ein Wallet mit der Mnemonic-Phrase wieder her und setzt ein neues Passwort.
    ///
    /// Diese Funktion ist für den Fall vorgesehen, dass der Benutzer sein Passwort vergessen hat.
    /// Sie lädt das Wallet mit der Mnemonic, speichert es sofort mit dem neuen Passwort
    /// erneut und versetzt den Service bei Erfolg in den `Unlocked`-Zustand.
    ///
    /// # Arguments
    /// * `mnemonic` - Die Mnemonic-Phrase zur Wiederherstellung des Wallets.
    /// * `new_password` - Das neue Passwort, mit dem das Wallet verschlüsselt werden soll.
    ///
    /// # Errors
    /// Schlägt fehl, wenn die Mnemonic-Phrase ungültig ist oder der Speicherzugriff misslingt.
    pub fn recover_wallet_and_set_new_password(
        &mut self,
        mnemonic: &str,
        new_password: &str,
    ) -> Result<(), String> {
        // 1. Lade das Wallet mit der Mnemonic-Phrase (öffnet das "zweite Schloss").
        let (wallet, identity) = Wallet::load(&self.storage, &AuthMethod::Mnemonic(mnemonic))
            .map_err(|e| format!("Recovery failed (check mnemonic phrase): {}", e))?;

        // 2. Setze das Passwort zurück, indem das Mnemonic-Schloss geöffnet und das Passwort-Schloss neu geschrieben wird.
        Wallet::reset_password(&mut self.storage, &identity, new_password)
            .map_err(|e| format!("Failed to set new password: {}", e))?;

        self.state = AppState::Unlocked { wallet, identity };
        Ok(())
    }

    /// Sperrt das Wallet und entfernt sensible Daten (privater Schlüssel) aus dem Speicher.
    ///
    /// Setzt den Zustand zurück auf `Locked`. Diese Operation kann nicht fehlschlagen.
    pub fn logout(&mut self) {
        self.state = AppState::Locked;
    }
}
