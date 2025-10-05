//! # src/app_service/lifecycle.rs
//!
//! Enthält alle Funktionen, die den Lebenszyklus des `AppService` steuern,
//! wie Initialisierung, Login/Logout und Wiederherstellung.

use super::{AppService, AppState, ProfileInfo};
use crate::storage::{file_storage::FileStorage, AuthMethod};
use crate::wallet::Wallet;
use bip39::Language;
use std::path::Path;
use std::fs;

const PROFILES_INDEX_FILE: &str = "profiles.json";

impl AppService {
    // --- Lebenszyklus-Management ---

    /// Initialisiert einen neuen `AppService` im `Locked`-Zustand.
    ///
    /// # Arguments
    /// * `base_storage_path` - Der Pfad zum Basisverzeichnis, in dem alle
    ///   Profil-Unterverzeichnisse und die `profiles.json` gespeichert werden.
    pub fn new(base_storage_path: &Path) -> Result<Self, String> {
        fs::create_dir_all(base_storage_path)
            .map_err(|e| format!("Failed to create base storage directory: {}", e))?;
        Ok(AppService {
            base_storage_path: base_storage_path.to_path_buf(),
            state: AppState::Locked,
        })
    }

    /// Listet alle verfügbaren, im Basisverzeichnis konfigurierten Profile auf.
    ///
    /// Liest die zentrale `profiles.json`-Datei und gibt eine Liste von `ProfileInfo`-
    /// Objekten zurück, die für die Anzeige in einem Login-Screen verwendet werden kann.
    ///
    /// # Returns
    /// Ein `Result` mit einem Vektor von `ProfileInfo` oder einer Fehlermeldung,
    /// falls die Indexdatei nicht gelesen oder geparst werden kann.
    pub fn list_profiles(&self) -> Result<Vec<ProfileInfo>, String> {
        let index_path = self.base_storage_path.join(PROFILES_INDEX_FILE);
        if !index_path.exists() {
            return Ok(Vec::new()); // Keine Profile vorhanden, kein Fehler.
        }

        let content = fs::read_to_string(index_path)
            .map_err(|e| format!("Could not read profiles index file: {}", e))?;
        if content.trim().is_empty() {
            return Ok(Vec::new());
        }

        serde_json::from_str(&content)
            .map_err(|e| format!("Could not parse profiles index file: {}", e))
    }

    /// Generiert eine neue BIP-39 Mnemonic-Phrase (Seed-Wörter).
    ///
    /// Diese Methode ist statisch und kann ohne geladenes Wallet aufgerufen werden.
    pub fn generate_mnemonic(word_count: u32) -> Result<String, String> {
        crate::services::crypto_utils::generate_mnemonic(word_count as usize, Language::English)
            .map_err(|e| e.to_string())
    }

    /// Validiert eine vom Benutzer eingegebene BIP-39 Mnemonic-Phrase.
    ///
    /// Diese Methode ist statisch und kann ohne geladenes Wallet aufgerufen werden.
    pub fn validate_mnemonic(mnemonic: &str) -> Result<(), String> {
        crate::services::crypto_utils::validate_mnemonic_phrase(mnemonic)
    }

    /// Erstellt ein komplett neues Benutzerprofil und Wallet und speichert es verschlüsselt.
    ///
    /// Diese Funktion leitet einen anonymen Ordnernamen aus den Secrets ab, speichert
    /// das Wallet in diesem Ordner und fügt einen Eintrag zur zentralen `profiles.json` hinzu.
    /// Bei Erfolg wird der Service in den `Unlocked`-Zustand versetzt.
    ///
    /// # Arguments
    /// * `profile_name` - Der menschenlesbare Name für das neue Profil. Muss eindeutig sein.
    /// * `mnemonic` - Die BIP39 Mnemonic-Phrase zur Generierung der Master-Keys.
    /// * `passphrase` - Eine optionale, zusätzliche Passphrase für die Mnemonic.
    /// * `user_prefix` - Ein optionales Präfix für die `did:key`-basierte User-ID.
    /// * `password` - Das Passwort, mit dem das neue Wallet verschlüsselt wird.
    pub fn create_profile(
        &mut self,
        profile_name: &str,
        mnemonic: &str,
        passphrase: Option<&str>,
        user_prefix: Option<&str>,
        password: &str,
    ) -> Result<(), String> {
        let mut profiles = self.list_profiles()?;
        if profiles.iter().any(|p| p.profile_name == profile_name) {
            return Err(format!("A profile with the name '{}' already exists.", profile_name));
        }

        let folder_name = Self::derive_folder_name(mnemonic, passphrase, user_prefix);
        let profile_path = self.base_storage_path.join(&folder_name);

        if profile_path.exists() {
            return Err("A profile with these secrets already exists (folder collision).".to_string());
        }

        let mut storage = FileStorage::new(profile_path);

        let (wallet, identity) = Wallet::new_from_mnemonic(mnemonic, passphrase, user_prefix)
            .map_err(|e| format!("Failed to create new wallet: {}", e))?;

        wallet
            .save(&mut storage, &identity, password)
            .map_err(|e| format!("Failed to save new wallet: {}", e))?;

        // Füge das neue Profil zur Indexdatei hinzu
        profiles.push(ProfileInfo {
            profile_name: profile_name.to_string(),
            folder_name,
        });
        let index_path = self.base_storage_path.join(PROFILES_INDEX_FILE);
        let updated_index = serde_json::to_string_pretty(&profiles)
            .map_err(|e| format!("Failed to serialize profile index: {}", e))?;
        fs::write(index_path, updated_index)
            .map_err(|e| format!("Failed to write profile index file: {}", e))?;

        self.state = AppState::Unlocked { storage, wallet, identity };
        Ok(())
    }

    /// Entsperrt ein existierendes Wallet und lädt es in den Speicher.
    ///
    /// # Arguments
    /// * `folder_name` - Der anonyme Ordnername des zu ladenden Profils.
    /// * `password` - Das Passwort zum Entschlüsseln des Wallets.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Profil nicht existiert, das Passwort falsch ist oder
    /// die Wallet-Dateien nicht gelesen werden können.
    pub fn login(
        &mut self,
        folder_name: &str,
        password: &str,
        cleanup_on_login: bool,
    ) -> Result<(), String> {
        let profile_path = self.base_storage_path.join(folder_name);
        if !profile_path.exists() {
            return Err("Profile directory not found.".to_string());
        }

        let mut storage = FileStorage::new(profile_path);

        let (mut wallet, identity) = Wallet::load(&storage, &AuthMethod::Password(password))
            .map_err(|e| format!("Login failed (check password): {}", e))?;

        if cleanup_on_login {
            wallet.run_storage_cleanup(None)
                  .map_err(|e| format!("Storage cleanup on login failed: {}", e))?;
            wallet.save(&mut storage, &identity, password)
                  .map_err(|e| format!("Failed to save wallet after cleanup: {}", e))?;
        }

        self.state = AppState::Unlocked { storage, wallet, identity };
        Ok(())
    }

    /// Stellt ein Wallet mit der Mnemonic-Phrase wieder her und setzt ein neues Passwort.
    ///
    /// # Arguments
    /// * `folder_name` - Der anonyme Ordnername des wiederherzustellenden Profils.
    /// * `mnemonic` - Die Mnemonic-Phrase zur Wiederherstellung des Wallets.
    /// * `passphrase` - Die optionale Passphrase, die bei der Erstellung verwendet wurde.
    /// * `new_password` - Das neue Passwort, mit dem das Wallet verschlüsselt werden soll.
    pub fn recover_wallet_and_set_new_password(
        &mut self,
        folder_name: &str,
        mnemonic: &str,
        passphrase: Option<&str>,
        new_password: &str,
    ) -> Result<(), String> {
        let profile_path = self.base_storage_path.join(folder_name);
        if !profile_path.exists() {
            return Err("Profile directory not found.".to_string());
        }

        let mut storage = FileStorage::new(profile_path);

        // 1. Lade das Wallet mit der Mnemonic-Phrase (öffnet das "zweite Schloss").
        let auth_method = AuthMethod::Mnemonic(mnemonic, passphrase);
        let (wallet, identity) = Wallet::load(&storage, &auth_method)
            .map_err(|e| format!("Recovery failed (check mnemonic phrase and passphrase): {}", e))?;

        // 2. Setze das Passwort zurück, indem das Mnemonic-Schloss geöffnet und das Passwort-Schloss neu geschrieben wird.
        Wallet::reset_password(&mut storage, &identity, new_password)
            .map_err(|e| format!("Failed to set new password: {}", e))?;

        self.state = AppState::Unlocked { storage, wallet, identity };
        Ok(())
    }

    /// Sperrt das Wallet und entfernt sensible Daten (privater Schlüssel) aus dem Speicher.
    ///
    /// Setzt den Zustand zurück auf `Locked`. Diese Operation kann nicht fehlschlagen.
    pub fn logout(&mut self) {
        self.state = AppState::Locked;
    }
}