//! # src/app_service/mod.rs
//!
//! Definiert den `AppService`, eine Fassade über dem `Wallet`, um die
//! Kernlogik für Client-Anwendungen (z.B. GUIs) zu vereinfachen.
//!
//! Diese Schicht verwaltet den Anwendungszustand (Locked/Unlocked), kapselt
//! die `UserIdentity` und stellt sicher, dass Zustandsänderungen im Wallet
//! automatisch gespeichert werden.

use crate::archive::VoucherArchive;
use crate::models::profile::UserIdentity;
use crate::models::signature::DetachedSignature;
use crate::models::voucher::Voucher;
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use crate::services::voucher_manager::NewVoucherData;
use crate::storage::file_storage::FileStorage;
use crate::storage::{AuthMethod, Storage};
use crate::wallet::{ProcessBundleResult, VoucherDetails, VoucherSummary, Wallet};
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
    // --- Schritt 2: Lebenszyklus-Management ---

    /// Initialisiert einen neuen `AppService`.
    ///
    /// Erstellt eine `FileStorage`-Instanz für den angegebenen Pfad und setzt
    /// den initialen Zustand auf `Locked`.
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

    /// Erstellt ein komplett neues Benutzerprofil und Wallet und speichert es.
    ///
    /// Bei Erfolg wird der Service in den `Unlocked`-Zustand versetzt.
    ///
    /// # Arguments
    /// * `mnemonic` - Die Mnemonic-Phrase zur Generierung der Master-Keys.
    /// * `user_prefix` - Ein optionales Präfix für die User-ID.
    /// * `password` - Das Passwort, mit dem das neue Wallet verschlüsselt wird.
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
    pub fn login(&mut self, mnemonic: &str, password: &str) -> Result<(), String> {
        // Zuerst das Profil laden, um die korrekte User ID (inkl. Präfix) zu erhalten.
        // Dies dient gleichzeitig als Überprüfung von Mnemonic und Passwort.
        // HINWEIS: Die Wallet-API unterstützt kein direktes Laden nur mit Mnemonic.
        // Wir müssen die Identität zuerst vollständig ableiten.
        // DIESE IMPLEMENTIERUNG FUNKTIONIERT NUR FÜR USER-IDS OHNE PRÄFIX.

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
    /// Setzt den Zustand zurück auf `Locked`.
    pub fn logout(&mut self) {
        self.state = AppState::Locked;
    }

    // --- Schritt 3: Implementierung der Datenabfragen (Queries) ---

    /// Eine private Hilfsfunktion für den Nur-Lese-Zugriff auf das Wallet.
    /// Stellt sicher, dass das Wallet entsperrt ist, bevor eine Operation ausgeführt wird.
    fn get_wallet(&self) -> Result<&Wallet, String> {
        match &self.state {
            AppState::Unlocked { wallet, .. } => Ok(wallet),
            AppState::Locked => Err("Wallet is locked.".to_string()),
        }
    }

    /// Gibt eine Liste von Zusammenfassungen aller Gutscheine im Wallet zurück.
    pub fn get_voucher_summaries(&self) -> Result<Vec<VoucherSummary>, String> {
        let wallet = self.get_wallet()?;
        Ok(wallet.list_vouchers())
    }

    /// Aggregiert die Guthaben aller aktiven Gutscheine, gruppiert nach Währung.
    pub fn get_total_balance_by_currency(&self) -> Result<HashMap<String, String>, String> {
        let wallet = self.get_wallet()?;
        Ok(wallet.get_total_balance_by_currency())
    }

    /// Ruft eine detaillierte Ansicht für einen einzelnen Gutschein ab.
    pub fn get_voucher_details(&self, local_id: &str) -> Result<VoucherDetails, String> {
        let wallet = self.get_wallet()?;
        wallet
            .get_voucher_details(local_id)
            .map_err(|e| e.to_string())
    }

    /// Gibt die User-ID des Wallet-Inhabers zurück.
    pub fn get_user_id(&self) -> Result<String, String> {
        let wallet = self.get_wallet()?;
        Ok(wallet.get_user_id().to_string())
    }

    // --- Schritt 4: Implementierung der Aktionen (Commands) ---

    /// Erstellt einen brandneuen Gutschein, fügt ihn zum Wallet hinzu und speichert den Zustand.
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
    /// Diese Operation verändert den Wallet-Zustand nicht und erfordert kein Speichern.
    pub fn create_signing_request_bundle(
        &self,
        local_instance_id: &str,
        recipient_id: &str,
    ) -> Result<Vec<u8>, String> {
        let wallet = self.get_wallet()?;
        // Die Identität wird hier nur für die Verschlüsselung benötigt.
        let identity = match &self.state {
            AppState::Unlocked { identity, .. } => identity,
            AppState::Locked => return Err("Wallet is locked".to_string()),
        };
        wallet
            .create_signing_request(identity, local_instance_id, recipient_id)
            .map_err(|e| e.to_string())
    }

    /// Erstellt eine losgelöste Signatur als Antwort auf eine Signaturanfrage.
    /// Diese Operation verändert den Wallet-Zustand nicht.
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
        // Das Wallet-Objekt wird hier nicht benötigt, nur die Identität des Unterzeichners.
        let wallet = self.get_wallet()?;
        wallet
            .create_detached_signature_response(identity, voucher_to_sign, signature_data, original_sender_id)
            .map_err(|e| e.to_string())
    }

    /// Verarbeitet eine empfangene losgelöste Signatur, fügt sie dem lokalen Gutschein hinzu und speichert den Zustand.
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