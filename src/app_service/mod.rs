//! # src/app_service/mod.rs
//!
//! Definiert den `AppService`, eine Fassade über dem `Wallet`, um die
//! Kernlogik für Client-Anwendungen (z.B. GUIs) zu vereinfachen.
//!
//! Diese Schicht verwaltet den Anwendungszustand (Locked/Unlocked), kapselt
//! die `UserIdentity` und stellt sicher, dass Zustandsänderungen im Wallet
//! automatisch gespeichert werden.
//!
//! ## Konzept: Zustandsmanagement
//!
//! Der Service operiert in zwei Zuständen:
//! - **`Locked`**: Kein Wallet geladen. Nur Operationen wie `create_profile` oder `login` sind möglich.
//! - **`Unlocked`**: Ein Wallet ist geladen und entschlüsselt. Alle Operationen (Transfers, Abfragen etc.) sind verfügbar.
//!
//! Aktionen, die den internen Zustand des Wallets verändern (z.B. `create_new_voucher`, `receive_bundle`),
//! speichern das Wallet bei Erfolg automatisch und sicher auf dem Datenträger.
//!
//! ## Beispiel: Typischer Lebenszyklus
//!
//! ```no_run
//! use voucher_lib::app_service::AppService;
//! use std::path::Path;
//! # use voucher_lib::services::voucher_manager::NewVoucherData;
//! # use voucher_lib::models::voucher::Creator;
//! # use voucher_lib::models::voucher_standard_definition::VoucherStandardDefinition;
//!
//! // 1. Initialisierung des Services
//! let storage_path = Path::new("/tmp/my_wallet_docs");
//! let mut app = AppService::new(storage_path).expect("Service konnte nicht erstellt werden.");
//!
//! // 2. Neues Profil erstellen (dies entsperrt das Wallet)
//! // In einer echten Anwendung wird die Mnemonic sicher generiert und gespeichert.
//! let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
//! app.create_profile(&mnemonic, Some("user"), "sicheres-passwort-123")
//!    .expect("Profil konnte nicht erstellt werden.");
//!
//! // 3. Eine Aktion ausführen (z.B. Guthaben prüfen)
//! let balance = app.get_total_balance_by_currency().unwrap();
//! assert!(balance.is_empty()); // Wallet ist noch leer.
//!
//! // 4. Wallet sperren
//! app.logout();
//!
//! // 5. Erneut anmelden
//! app.login(&mnemonic, "sicheres-passwort-123").expect("Login fehlgeschlagen.");
//!
//! // 6. Die User-ID abrufen
//! let user_id = app.get_user_id().unwrap();
//! println!("Angemeldet als: {}", user_id);
//! ```

use crate::archive::VoucherArchive;
use crate::models::profile::UserIdentity;
use crate::models::signature::DetachedSignature;
use crate::models::voucher::Voucher;
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use crate::services::voucher_manager::NewVoucherData;
use crate::storage::file_storage::FileStorage;
use crate::storage::{AuthMethod, Storage};
use crate::wallet::{ProcessBundleResult, VoucherDetails, VoucherSummary, Wallet};
use bip39::Language;
use std::collections::HashMap;
use std::path::Path;

/// Repräsentiert den Kernzustand der Anwendung.
///
/// Der Service kann entweder gesperrt (`Locked`) sein, ohne Zugriff auf Wallet-Daten
/// oder private Schlüssel, oder entsperrt (`Unlocked`), wobei `Wallet` und `UserIdentity`
/// im Speicher gehalten werden.
pub enum AppState {
    /// Es ist kein Wallet geladen und keine `UserIdentity` im Speicher.
    Locked,
    /// Ein Wallet ist geladen und die `UserIdentity` (inkl. privatem Schlüssel)
    /// ist für Operationen verfügbar.
    Unlocked {
        wallet: Wallet,
        identity: UserIdentity,
    },
}

/// Die `AppService`-Fassade.
///
/// Dient als primäre Schnittstelle für Client-Anwendungen. Sie vereinfacht die
/// Interaktion mit der `voucher_core`-Bibliothek, indem sie das Zustandsmanagement
/// und die Persistenzabläufe kapselt.
pub struct AppService {
    /// Die konkrete Storage-Implementierung, die vom Service verwendet wird.
    /// Für Client-Anwendungen ist dies typischerweise `FileStorage`.
    storage: FileStorage,
    /// Der aktuelle Zustand des Services (Locked oder Unlocked).
    state: AppState,
}

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
    /// Leitet die `UserIdentity` aus der Mnemonic ab und verwendet sie zusammen
    /// mit dem Passwort, um die Wallet-Daten zu entschlüsseln und zu laden.
    /// Bei Erfolg wird der Service in den `Unlocked`-Zustand versetzt.
    ///
    /// # Arguments
    /// * `mnemonic` - Die Mnemonic-Phrase des Wallets.
    /// * `password` - Das Passwort zum Entschlüsseln des Wallets.
    ///
    /// # Errors
    /// Schlägt fehl, wenn die Mnemonic-Phrase oder das Passwort falsch sind, oder wenn
    /// die Wallet-Dateien nicht gelesen werden können.
    pub fn login(&mut self, mnemonic: &str, password: &str) -> Result<(), String> {
        // Zuerst das Profil laden, um die korrekte User ID (inkl. Präfix) zu erhalten.
        let (profile, _) = self
            .storage.load_wallet(&AuthMethod::Password(password))
            .map_err(|e| format!("Login failed (check mnemonic/password): {}", e))?;

        // Nun die vollständige Identität mit der geladenen User ID neu ableiten.
        let (public_key, signing_key) =
            crate::services::crypto_utils::derive_ed25519_keypair(mnemonic, None)
                .map_err(|e| format!("Failed to derive keypair: {}", e))?;

        let identity = UserIdentity {
            signing_key,
            public_key,
            user_id: profile.user_id.clone(),
        };

        // Mit der vollständigen Identität das gesamte Wallet laden.
        let wallet = Wallet::load(&self.storage, &AuthMethod::Password(password), identity.clone())
            .map_err(|e| format!("Failed to load full wallet state: {}", e))?;

        self.state = AppState::Unlocked { wallet, identity };
        Ok(())
    }

    /// Sperrt das Wallet und entfernt sensible Daten (privater Schlüssel) aus dem Speicher.
    ///
    /// Setzt den Zustand zurück auf `Locked`. Diese Operation kann nicht fehlschlagen.
    pub fn logout(&mut self) {
        self.state = AppState::Locked;
    }

    // --- Datenabfragen (Queries) ---

    /// Eine private Hilfsfunktion für den Nur-Lese-Zugriff auf das Wallet.
    /// Stellt sicher, dass das Wallet entsperrt ist, bevor eine Operation ausgeführt wird.
    fn get_wallet(&self) -> Result<&Wallet, String> {
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
        let wallet = self.get_wallet()?;
        Ok(wallet.list_vouchers())
    }

    /// Aggregiert die Guthaben aller aktiven Gutscheine, gruppiert nach Währung.
    ///
    /// # Returns
    /// Eine `HashMap`, die von der Währungseinheit (z.B. "Minuten") auf den Gesamtbetrag abbildet.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet gesperrt (`Locked`) ist.
    pub fn get_total_balance_by_currency(&self) -> Result<HashMap<String, String>, String> {
        let wallet = self.get_wallet()?;
        Ok(wallet.get_total_balance_by_currency())
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
        let wallet = self.get_wallet()?;
        wallet
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
        let wallet = self.get_wallet()?;
        Ok(wallet.get_user_id().to_string())
    }

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
        standard_definition: &VoucherStandardDefinition,
        data: NewVoucherData,
        password: &str,
    ) -> Result<Voucher, String> {
        // Temporär den Zustand aus `self` nehmen, um Borrow-Checker-Regeln zu erfüllen.
        let current_state = std::mem::replace(&mut self.state, AppState::Locked);

        let (result, new_state) = match current_state {
            AppState::Unlocked { mut wallet, identity } => {
                match wallet.create_new_voucher(&identity, standard_definition, data) {
                    Ok(new_voucher) => {
                        if let Err(e) = wallet.save(&mut self.storage, &identity, password) {
                            (Err(e.to_string()), AppState::Unlocked { wallet, identity })
                        } else {
                            (Ok(new_voucher), AppState::Unlocked { wallet, identity })
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
            AppState::Unlocked { mut wallet, identity } => {
                match wallet.create_transfer(
                    &identity,
                    standard_definition,
                    local_instance_id,
                    recipient_id,
                    amount_to_send,
                    notes,
                    archive,
                ) {
                    Ok((bundle_bytes, _)) => {
                        if let Err(e) = wallet.save(&mut self.storage, &identity, password) {
                            (Err(e.to_string()), AppState::Unlocked { wallet, identity })
                        } else {
                            (Ok(bundle_bytes), AppState::Unlocked { wallet, identity })
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
        archive: Option<&dyn VoucherArchive>,
        password: &str,
    ) -> Result<ProcessBundleResult, String> {
        let current_state = std::mem::replace(&mut self.state, AppState::Locked);

        let (result, new_state) = match current_state {
            AppState::Unlocked { mut wallet, identity } => {
                match wallet.process_encrypted_transaction_bundle(&identity, bundle_data, archive) {
                    Ok(proc_result) => {
                        if let Err(e) = wallet.save(&mut self.storage, &identity, password) {
                            (Err(e.to_string()), AppState::Unlocked { wallet, identity })
                        } else {
                            (Ok(proc_result), AppState::Unlocked { wallet, identity })
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
            .create_detached_signature_response(identity, voucher_to_sign, signature_data, original_sender_id)
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
        password: &str,
    ) -> Result<(), String> {
        let current_state = std::mem::replace(&mut self.state, AppState::Locked);

        let (result, new_state) = match current_state {
            AppState::Unlocked { mut wallet, identity } => {
                match wallet.process_and_attach_signature(&identity, container_bytes) {
                    Ok(_) => {
                        if let Err(e) = wallet.save(&mut self.storage, &identity, password) {
                            (Err(e.to_string()), AppState::Unlocked { wallet, identity })
                        } else {
                            (Ok(()), AppState::Unlocked { wallet, identity })
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


// --- Interne Hilfsmethoden für Tests ---

impl AppService {
    /// Eine Hilfsmethode nur für Tests, um Zugriff auf die interne Identität zu bekommen.
    #[doc(hidden)]
    pub fn get_unlocked_mut_for_test(&mut self) -> (&mut Wallet, &UserIdentity) {
        match &mut self.state {
            AppState::Unlocked { wallet, identity } => (wallet, identity),
            _ => panic!("Service must be unlocked for this test helper"),
        }
    }
}