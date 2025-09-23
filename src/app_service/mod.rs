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
//! app.create_profile(&mnemonic, None, Some("user"), "sicheres-passwort-123")
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
//! app.login("sicheres-passwort-123").expect("Login fehlgeschlagen.");
//!
//! // 6. Die User-ID abrufen
//! let user_id = app.get_user_id().unwrap();
//! println!("Angemeldet als: {}", user_id);
//! ```

use crate::error::{ValidationError, VoucherCoreError};
use crate::models::profile::UserIdentity;
use crate::models::voucher::Voucher;
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use crate::services::bundle_processor;
use crate::storage::file_storage::FileStorage;
use crate::wallet::instance::{ValidationFailureReason, VoucherStatus};
use crate::wallet::Wallet;
use std::collections::HashMap;

// Deklaration der neuen Handler als öffentliche Sub-Module.
// Jede Datei enthält einen `impl AppService`-Block für ihren spezifischen Bereich.
pub mod command_handler;
pub mod conflict_handler;
pub mod data_encryption;
pub mod lifecycle;
pub mod queries;
pub mod signature_handler;

/// Repräsentiert den Kernzustand der Anwendung.
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

// --- Interne Hilfsmethoden ---

impl AppService {
    /// Die zentrale Logik zur Bestimmung des Gutschein-Status.
    /// Diese Methode wird von mehreren Handlern (`command_handler`, `signature_handler`)
    /// verwendet und verbleibt daher hier.
    fn determine_voucher_status(
        &self,
        voucher: &Voucher,
        standard: &VoucherStandardDefinition,
    ) -> Result<VoucherStatus, String> {
        match crate::services::voucher_validation::validate_voucher_against_standard(
            voucher, standard,
        ) {
            Ok(_) => Ok(VoucherStatus::Active),
            Err(e) => {
                if let VoucherCoreError::Validation(validation_error) = e {
                    let reason = match validation_error {
                        // KORREKTUR: `max` wird jetzt erfasst und übergeben. Duplizierter Arm wurde entfernt.
                        ValidationError::CountOutOfBounds { ref field, min, max, found, .. } if field == "guarantor_signatures" => Some(
                            ValidationFailureReason::GuarantorCountLow {
                                required: min,
                                max,
                                current: found as u32,
                            },
                        ),
                        ValidationError::CountOutOfBounds { ref field, min,  found, .. } if field == "additional_signatures" => Some(
                            ValidationFailureReason::AdditionalSignatureCountLow {
                                required: min,
                                current: found as u32,
                            },
                        ),
                        ValidationError::MissingRequiredSignature {
                            ref role
                        } => Some(
                            ValidationFailureReason::RequiredSignatureMissing {
                                role_description: role.clone(),
                            },
                        ),
                        _ => None,
                    };

                    if let Some(r) = reason{
                        Ok(VoucherStatus::Incomplete { reasons: vec![r] })
                    } else {
                        Err(validation_error.to_string())
                    }
                } else {
                    Err(e.to_string())
                }
            }
        }
    }

    /// Validiert alle Gutscheine innerhalb eines verschlüsselten Bundles.
    /// Diese Methode wird vom `command_handler` vor der Verarbeitung eines Bundles
    /// aufgerufen und bleibt daher hier zentral verfügbar.
    fn validate_vouchers_in_bundle(
        &self,
        identity: &UserIdentity,
        bundle_data: &[u8],
        standard_definitions_toml: &HashMap<String, String>,
    ) -> Result<(), String> {
        let bundle = bundle_processor::open_and_verify_bundle(identity, bundle_data)
            .map_err(|e| e.to_string())?;

        for voucher in &bundle.vouchers {
            let standard_uuid = &voucher.voucher_standard.uuid;
            let standard_toml = standard_definitions_toml.get(standard_uuid).ok_or_else(
                || format!("Required standard definition for UUID '{}' not provided.", standard_uuid),
            )?;

            let (verified_standard, _) =
                crate::services::standard_manager::verify_and_parse_standard(standard_toml)
                    .map_err(|e| e.to_string())?;

            crate::services::voucher_validation::validate_voucher_against_standard(
                voucher,
                &verified_standard,
            )
                .map_err(|e| e.to_string())?;
        }
        Ok(())
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