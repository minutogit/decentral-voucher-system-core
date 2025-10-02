//! # src/wallet/mod.rs
//!
//! Definiert die `Wallet`-Fassade, die zentrale Verwaltungsstruktur für ein
//! Nutzerprofil. Sie kapselt den In-Memory-Zustand (`UserProfile`, `VoucherStore`)
//! und orchestriert die Interaktionen mit einem `Storage`-Backend und den
//! kryptographischen Operationen der `UserIdentity`.

// Deklariert das `instance`-Modul als öffentlichen Teil des `wallet`-Moduls.
pub mod instance;
// Deklariere die anderen Dateien als Teil dieses Moduls
mod conflict_handler;
mod queries;
mod signature_handler;
// in src/wallet/mod.rs
// ...
#[cfg(test)]
mod tests;

use crate::archive::VoucherArchive;
use crate::error::{ValidationError, VoucherCoreError};
use crate::wallet::instance::{ValidationFailureReason, VoucherInstance, VoucherStatus};
use crate::models::conflict::{FingerprintStore, ProofStore, TransactionFingerprint};
use crate::models::profile::{
    BundleMetadataStore, TransactionBundleHeader, TransactionDirection, UserIdentity, UserProfile, VoucherStore,
};
use crate::models::secure_container::{PayloadType, SecureContainer};
use crate::models::voucher::{Transaction, Voucher};
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use crate::services::crypto_utils::{create_user_id, get_hash, get_pubkey_from_user_id, verify_ed25519};
use crate::services::utils::to_canonical_json;
use crate::services::{bundle_processor, conflict_manager, voucher_manager, voucher_validation};
use crate::storage::{AuthMethod, Storage, StorageError};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::services::voucher_manager::NewVoucherData;

/// Die zentrale Verwaltungsstruktur für ein Nutzer-Wallet.
/// Hält den In-Memory-Zustand und interagiert mit dem Speichersystem.
#[derive(Clone)]
pub struct Wallet {
    /// Die öffentlichen Profildaten und die Transaktionshistorie.
    pub profile: UserProfile,
    /// Der Bestand an Gutscheinen des Nutzers.
    pub voucher_store: VoucherStore,
    /// Die Historie der Transaktions-Metadaten.
    pub bundle_meta_store: BundleMetadataStore,
    /// Der Speicher für Transaktions-Fingerprints zur Double-Spending-Erkennung.
    pub fingerprint_store: FingerprintStore,
    /// Der Speicher für kryptographisch bewiesene Double-Spend-Konflikte.
    pub proof_store: ProofStore,
}

/// Das Ergebnis der Verarbeitung eines eingehenden Transaktionsbündels.
#[derive(Debug, Default)]
pub struct ProcessBundleResult {
    pub header: TransactionBundleHeader,
    pub check_result: DoubleSpendCheckResult,
}

/// Das Ergebnis einer Double-Spend-Prüfung.
#[derive(Debug, Default, Clone)]
pub struct DoubleSpendCheckResult {
    pub verifiable_conflicts: HashMap<String, Vec<crate::models::conflict::TransactionFingerprint>>,
    pub unverifiable_warnings: HashMap<String, Vec<crate::models::conflict::TransactionFingerprint>>,
}

/// Repräsentiert ein aggregiertes Guthaben für einen bestimmten Gutschein-Standard und eine Währungseinheit.
/// Wird verwendet, um eine zusammenfassende Dashboard-Ansicht der Guthaben zu erstellen.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct AggregatedBalance {
    /// Der Name des Gutschein-Standards (z.B. "Minuto-Gutschein").
    pub standard_name: String,
    /// Die eindeutige UUID des Gutschein-Standards.
    pub standard_uuid: String,
    /// Die Währungseinheit des Guthabens (z.B. "Min", "€").
    pub unit: String,
    /// Der als String formatierte Gesamtbetrag.
    pub total_amount: String,
}

/// Eine zusammenfassende Ansicht eines Gutscheins für Listen-Darstellungen.
///
/// Diese Struktur wird von der Funktion `AppService::get_voucher_summaries`
/// zurückgegeben und dient dazu, eine übersichtliche Darstellung der
/// Gutschein-Daten zu liefern, ohne das gesamte, komplexe `Voucher`-Objekt
/// übertragen zu müssen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoucherSummary {
    /// Die eindeutige, lokale ID der Gutschein-Instanz im Wallet.
    pub local_instance_id: String,
    /// Der aktuelle Status des Gutscheins (z.B. `Active`, `Archived`).
    pub status: VoucherStatus,
    /// Die eindeutige ID des Erstellers (oft ein Public Key).
    pub creator_id: String,
    /// Das Gültigkeitsdatum des Gutscheins im ISO 8601-Format.
    pub valid_until: String,
    /// Eine allgemeine, menschenlesbare Beschreibung des Gutscheins.
    pub description: String,
    /// Der aktuelle, verfügbare Betrag des Gutscheins als String.
    pub current_amount: String,
    /// Die Einheit des Gutscheinwerts (z.B. "m" für Minuten).
    pub unit: String,
    /// Der Name des Standards, zu dem dieser Gutschein gehört (z.B. "Minuto-Gutschein").
    pub voucher_standard_name: String,
    /// Die eindeutige Kennung (UUID) des Standards, zu dem dieser Gutschein gehört.
    pub voucher_standard_uuid: String,
    /// Die Anzahl der Transaktionen, exklusive der initialen `init`-Transaktion.
    pub transaction_count: u32,
    /// Die Anzahl der vorhandenen Bürgen-Signaturen.
    pub guarantor_signatures_count: u32,
    /// Die Anzahl der vorhandenen zusätzlichen, optionalen Signaturen.
    pub additional_signatures_count: u32,
    /// Ein Flag, das anzeigt, ob der Gutschein besichert ist.
    pub has_collateral: bool,
    /// Der Vorname des ursprünglichen Erstellers.
    pub creator_first_name: String,
    /// Der Nachname des ursprünglichen Erstellers.
    pub creator_last_name: String,
    pub creator_coordinates: String,
    /// Eine Markierung, ob es sich um einen nicht einlösbaren Testgutschein handelt.
    pub non_redeemable_test_voucher: bool,
}

/// Eine zusammenfassende Ansicht eines Double-Spend-Beweises für Listen-Darstellungen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfDoubleSpendSummary {
    pub proof_id: String,
    pub offender_id: String,
    pub fork_point_prev_hash: String,
    pub report_timestamp: String,
    pub is_resolved: bool,
    pub has_l2_verdict: bool,
}

/// Eine detaillierte Ansicht eines Gutscheins inklusive seiner Transaktionshistorie.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoucherDetails {
    pub local_instance_id: String,
    /// Der aktuelle Status des Gutscheins (z.B. `Active`, `Archived`).
    pub status: VoucherStatus,
    pub voucher: Voucher,
}

impl Wallet {
    /// Erstellt ein brandneues, leeres Wallet aus einer Mnemonic-Phrase.
    pub fn new_from_mnemonic(
        mnemonic_phrase: &str,
        passphrase: Option<&str>,
        user_prefix: Option<&str>,
    ) -> Result<(Self, UserIdentity), VoucherCoreError> {
        // Das Präfix wird Teil der Passphrase, um kryptographisch getrennte Konten zu erzeugen.
        let final_passphrase_str = format!(
            "{}{}",
            passphrase.unwrap_or(""),
            user_prefix.unwrap_or("").to_lowercase()
        );
        let final_passphrase = if final_passphrase_str.is_empty() {
            None
        } else {
            Some(final_passphrase_str.as_str())
        };
        let (public_key, signing_key) = crate::services::crypto_utils::derive_ed25519_keypair(mnemonic_phrase, final_passphrase)?;
        let user_id = create_user_id(&public_key, user_prefix)
            .map_err(|e| VoucherCoreError::Crypto(e.to_string()))?;

        let identity = UserIdentity {
            signing_key,
            public_key,
            user_id: user_id.clone(),
        };

        let profile = UserProfile { user_id };

        let voucher_store = VoucherStore::default();
        let bundle_meta_store = BundleMetadataStore::default();
        let fingerprint_store = FingerprintStore::default();
        let proof_store = ProofStore::default();

        let wallet = Wallet {
            profile,
            voucher_store,
            bundle_meta_store,
            fingerprint_store,
            proof_store,
        };

        Ok((wallet, identity))
    }

    /// Lädt ein existierendes Wallet aus einem `Storage`-Backend.
    /// Gibt das Wallet und die entschlüsselte UserIdentity zurück.
    pub fn load<S: Storage>(
        storage: &S,
        auth: &AuthMethod,
    ) -> Result<(Self, UserIdentity), VoucherCoreError> {
        let (profile, voucher_store, identity) = storage.load_wallet(auth)?;
        let bundle_meta_store = storage.load_bundle_metadata(&identity.user_id, auth)?;
        let fingerprint_store = storage.load_fingerprints(&identity.user_id, auth)?;
        let proof_store = storage.load_proofs(&identity.user_id, auth)?;

        // Sicherheitsüberprüfung, um sicherzustellen, dass die entschlüsselte Identität
        // mit den Profildaten übereinstimmt.
        if profile.user_id != identity.user_id {
            return Err(StorageError::AuthenticationFailed.into());
        }

        let wallet = Wallet {
            profile,
            voucher_store,
            bundle_meta_store,
            fingerprint_store,
            proof_store,
        };
        Ok((wallet, identity))
    }

    /// Speichert den aktuellen Zustand des Wallets in einem `Storage`-Backend.
    pub fn save<S: Storage>(
        &self,
        storage: &mut S,
        identity: &UserIdentity,
        password: &str,
    ) -> Result<(), StorageError> {
        storage.save_wallet(&self.profile, &self.voucher_store, identity, password)?;
        storage.save_bundle_metadata(&identity.user_id, password, &self.bundle_meta_store)?;
        storage.save_fingerprints(&identity.user_id, password, &self.fingerprint_store)?;
        storage.save_proofs(&identity.user_id, password, &self.proof_store)?;
        Ok(())
    }

    /// Setzt das Passwort für ein Wallet in einem `Storage`-Backend zurück.
    pub fn reset_password<S: Storage>(
        storage: &mut S,
        identity: &UserIdentity,
        new_password: &str,
    ) -> Result<(), StorageError> {
        storage.reset_password(identity, new_password)
    }

    /// Erstellt ein `TransactionBundle`, verpackt es und aktualisiert den Wallet-Zustand.
    /// Dies ist nun eine private Hilfsmethode.
    pub fn create_and_encrypt_transaction_bundle(
        &mut self,
        identity: &UserIdentity,
        vouchers: Vec<Voucher>,
        recipient_id: &str,
        notes: Option<String>,
    ) -> Result<Vec<u8>, VoucherCoreError> {
        for v in &vouchers {
            let local_id = Self::calculate_local_instance_id(v, &identity.user_id)?;
            if let Some(instance) = self.voucher_store.vouchers.get(&local_id) {
                if matches!(instance.status, VoucherStatus::Quarantined { .. }) {
                    return Err(VoucherCoreError::VoucherInQuarantine);
                }
            }
        }

        let (container_bytes, bundle) =
            bundle_processor::create_and_encrypt_bundle(identity, vouchers.clone(), recipient_id, notes)?;

        let header = bundle.to_header(TransactionDirection::Sent);
        self.bundle_meta_store
            .history
            .insert(header.bundle_id.clone(), header);

        Ok(container_bytes)
    }

    /// Verarbeitet einen serialisierten `SecureContainer`, der ein `TransactionBundle` enthält.
    pub fn process_encrypted_transaction_bundle(
        &mut self,
        identity: &UserIdentity,
        container_bytes: &[u8],
        archive: Option<&dyn VoucherArchive>,
    ) -> Result<ProcessBundleResult, VoucherCoreError> {
        let bundle = bundle_processor::open_and_verify_bundle(identity, container_bytes)?;

        for voucher in bundle.vouchers.clone() {
            // KORREKTUR: Für jeden empfangenen Gutschein muss die korrekte, deterministische
            // lokale ID berechnet werden. Die `voucher_id` als Schlüssel zu verwenden ist falsch
            // und führt dazu, dass konfliktierende Instanzen sich gegenseitig überschreiben.
            let local_id = Self::calculate_local_instance_id(&voucher, &identity.user_id)?;
            println!(
                "\n[Debug Wallet] Verarbeite empfangenen Gutschein: ID={}, Tx-Anzahl={}",
                voucher.voucher_id,
                voucher.transactions.len()
            );
            self.add_voucher_instance(local_id, voucher, VoucherStatus::Active);
        }

        let header = bundle.to_header(TransactionDirection::Received);
        self.bundle_meta_store
            .history
            .insert(header.bundle_id.clone(), header.clone());

        conflict_manager::scan_and_update_own_fingerprints(
            &self.voucher_store,
            &mut self.fingerprint_store,
        )?;

        // Wenn eine Signatur empfangen wird, muss der Status des Gutscheins aktualisiert werden
        if let Ok(deserialized_container) = serde_json::from_slice::<SecureContainer>(container_bytes)
        {
            if matches!(
                deserialized_container.payload_type,
                PayloadType::DetachedSignature
            ) {
                self.process_and_attach_signature(identity, container_bytes)?;
                return Ok(ProcessBundleResult::default());
            }
        }
        let check_result = conflict_manager::check_for_double_spend(&self.fingerprint_store);

        for (_conflict_hash, fingerprints) in &check_result.verifiable_conflicts {
            if let Some(archive_backend) = archive {
                // Die Logik zum Verifizieren und Erstellen von Beweisen ist nun hier im Wallet.
                let verified_proof = self.verify_and_create_proof(identity, fingerprints, archive_backend)?;

                if let Some(proof) = verified_proof {
                    // Der Beweis wurde erfolgreich erstellt und kann nun verwendet werden.
                    if let Some(verdict) = &proof.layer2_verdict {
                        // Logik zur Verarbeitung eines L2-Urteils
                        for tx in &proof.conflicting_transactions {
                            let instance_id_opt = self.find_local_voucher_by_tx_id(&tx.t_id).map(|i| i.local_instance_id.clone());
                            if let Some(instance_id) = instance_id_opt {
                                if let Some(instance_mut) = self.voucher_store.vouchers.get_mut(&instance_id) {
                                    instance_mut.status = if tx.t_id == verdict.valid_transaction_id {
                                        VoucherStatus::Active
                                    } else {
                                        VoucherStatus::Quarantined {
                                            reason: "L2 verdict".to_string(),
                                        }
                                    };
                                }
                            }
                        }
                    } else {
                        // Offline-Konfliktlösung, wenn kein L2-Urteil vorliegt
                        resolve_conflict_offline(&mut self.voucher_store, fingerprints);
                    }
                    // WICHTIG: Den erstellten Beweis persistent speichern.
                    self.proof_store.proofs.insert(proof.proof_id.clone(), proof);
                }
            } else {
                // KORREKTUR: Dieser `else`-Block fehlte. Er stellt sicher, dass die Offline-Logik auch
                // dann greift, wenn kein Layer-2-Backend (`archive`) konfiguriert ist.
                resolve_conflict_offline(&mut self.voucher_store, fingerprints);
            }
        }

        Ok(ProcessBundleResult {
            header,
            check_result,
        })
    }

    /// Verifiziert einen Konflikt und erstellt einen Beweis. Interne Methode.
    fn verify_and_create_proof(
        &self,
        identity: &UserIdentity,
        fingerprints: &[TransactionFingerprint],
        archive: &dyn VoucherArchive,
    ) -> Result<Option<crate::models::conflict::ProofOfDoubleSpend>, VoucherCoreError> {
        let mut conflicting_transactions = Vec::new();

        // 1. Finde die vollständigen Transaktionen zu den Fingerprints.
        for fp in fingerprints {
            if let Some(tx) = self.find_transaction_in_stores(&fp.t_id, archive)? {
                conflicting_transactions.push(tx);
            }
        }

        if conflicting_transactions.len() < 2 {
            return Ok(None);
        }

        // 2. Extrahiere Kerndaten und verifiziere Signaturen.
        let offender_id = conflicting_transactions[0].sender_id.clone();
        let fork_point_prev_hash = conflicting_transactions[0].prev_hash.clone();
        let offender_pubkey = get_pubkey_from_user_id(&offender_id)?;

        let mut verified_tx_count = 0;
        for tx in &conflicting_transactions {
            if tx.sender_id != offender_id || tx.prev_hash != fork_point_prev_hash {
                return Ok(None);
            }

            let signature_payload = serde_json::json!({
                "prev_hash": &tx.prev_hash, "sender_id": &tx.sender_id, "t_id": &tx.t_id
            });
            let signature_payload_hash = get_hash(to_canonical_json(&signature_payload)?);
            let signature_bytes = bs58::decode(&tx.sender_signature).into_vec()?;
            let signature = Signature::from_slice(&signature_bytes)?;

            if verify_ed25519(&offender_pubkey, signature_payload_hash.as_bytes(), &signature) {
                verified_tx_count += 1;
            }
        }

        // 3. Wenn mindestens zwei Signaturen gültig sind, ist der Betrug bewiesen.
        if verified_tx_count < 2 {
            return Ok(None);
        }

        let voucher = self.find_voucher_for_transaction(&conflicting_transactions[0].t_id, archive)?
            .ok_or_else(|| VoucherCoreError::VoucherNotFound("for proof creation".to_string()))?;
        let voucher_valid_until = voucher.valid_until.clone();

        // 4. Rufe den Service auf, um das Beweis-Objekt zu erstellen.
        let proof = conflict_manager::create_proof_of_double_spend(
            offender_id,
            fork_point_prev_hash,
            conflicting_transactions,
            voucher_valid_until,
            identity,
        )?;

        Ok(Some(proof))
    }

    pub fn add_voucher_instance(
        &mut self,
        local_id: String,
        voucher: Voucher,
        status: VoucherStatus,
    ) {
        let instance = VoucherInstance {
            voucher,
            status,
            local_instance_id: local_id.clone(),
        };
        self.voucher_store
            .vouchers
            .insert(local_id, instance);
    }

    pub fn get_voucher_instance(&self, local_instance_id: &str) -> Option<&VoucherInstance> {
        self.voucher_store.vouchers.get(local_instance_id)
    }

    pub fn update_voucher_status(&mut self, local_instance_id: &str, new_status: VoucherStatus) {
        if let Some(instance) = self.voucher_store.vouchers.get_mut(local_instance_id) {
            instance.status = new_status;
        }
    }

    /// Berechnet eine deterministische, lokale ID für eine Gutschein-Instanz.
    pub fn calculate_local_instance_id(
        voucher: &Voucher,
        profile_owner_id: &str,
    ) -> Result<String, VoucherCoreError> {
        let mut defining_transaction_id: Option<String> = None;

        // Die definierende Transaktion ist einfach die letzte, in der der Benutzer
        // als Sender oder Empfänger auftaucht.
        for tx in voucher.transactions.iter().rev() {
            if tx.recipient_id == profile_owner_id || tx.sender_id == profile_owner_id {
                defining_transaction_id = Some(tx.t_id.clone());
                break;
            }
        }

        if let Some(t_id) = defining_transaction_id {
            Ok(get_hash(format!(
                "{}{}{}",
                voucher.voucher_id, t_id, profile_owner_id
            )))
        } else {
            Err(VoucherCoreError::VoucherOwnershipNotFound(format!(
                "User '{}' has no ownership history for voucher '{}'",
                profile_owner_id, voucher.voucher_id
            )))
        }
    }

    /// Erstellt eine Transaktion, um einen Gutschein oder einen Teilbetrag davon zu überweisen.
    pub fn create_transfer(
        &mut self,
        identity: &UserIdentity,
        standard_definition: &VoucherStandardDefinition,
        local_instance_id: &str,
        recipient_id: &str,
        amount_to_send: &str,
        notes: Option<String>,
        archive: Option<&dyn VoucherArchive>,
    ) -> Result<(Vec<u8>, Voucher), VoucherCoreError> {
        let instance = self
            .voucher_store
            .vouchers
            .get(local_instance_id)
            .ok_or(VoucherCoreError::VoucherNotFound(
                local_instance_id.to_string(),
            ))?;

        if !matches!(instance.status, VoucherStatus::Active) {
            return Err(VoucherCoreError::VoucherNotActive(instance.status.clone()));
        }
        let voucher_to_spend = instance.voucher.clone();

        let last_tx = voucher_to_spend
            .transactions
            .last()
            .ok_or_else(|| {
                VoucherCoreError::Generic("Cannot spend voucher with no transactions.".to_string())
            })?;
        let prev_hash = get_hash(to_canonical_json(last_tx)?);
        let fingerprint_hash = get_hash(format!("{}{}", prev_hash, identity.user_id));

        if self
            .fingerprint_store
            .own_fingerprints
            .contains_key(&fingerprint_hash)
        {
            return Err(VoucherCoreError::DoubleSpendAttemptBlocked);
        }

        let new_voucher_state = voucher_manager::create_transaction(
            &voucher_to_spend,
            standard_definition,
            &identity.user_id,
            &identity.signing_key,
            recipient_id,
            amount_to_send,
        )?;

        // KORREKTE LOGIK ZUR ZUSTANDSVERWALTUNG:
        // 1. Entferne die alte Instanz, die gerade ausgegeben wurde.
        self.voucher_store.vouchers.remove(local_instance_id);

        // 2. Bestimme den Status des neuen Gutschein-Zustands für den Sender.
        if let Some(last_tx) = new_voucher_state.transactions.last() {
            let (new_status, owner_id) =
                if last_tx.sender_id == identity.user_id && last_tx.sender_remaining_amount.is_some() {
                    // Es ist ein Split, der Sender behält einen aktiven Restbetrag.
                    (VoucherStatus::Active, &identity.user_id)
                } else {
                    // Es ist ein voller Transfer, die Kopie des Senders wird archiviert.
                    (VoucherStatus::Archived, &identity.user_id)
                };

            // 3. Ein neuer Zustand bekommt IMMER eine neue lokale ID.
            let new_local_id = Self::calculate_local_instance_id(&new_voucher_state, owner_id)?;

            // 4. Füge die neue Instanz mit der NEUEN ID und dem korrekten Status hinzu.
            self.add_voucher_instance(
                new_local_id,
                new_voucher_state.clone(),
                new_status,
            );
        }

        if let Some(archive_backend) = archive {
            archive_backend.archive_voucher(&new_voucher_state, &identity.user_id, standard_definition)?;
        }

        let vouchers_for_bundle = vec![new_voucher_state.clone()];
        let container_bytes = self.create_and_encrypt_transaction_bundle(
            identity,
            vouchers_for_bundle.clone(),
            recipient_id,
            notes,
        )?;

        let created_tx = new_voucher_state.transactions.last().unwrap();
        let fingerprint =
            conflict_manager::create_fingerprint_for_transaction(created_tx, &new_voucher_state)?;

        self.fingerprint_store
            .own_fingerprints
            .entry(fingerprint.prvhash_senderid_hash.clone())
            .or_default()
            .push(fingerprint);

        Ok((container_bytes, new_voucher_state))
    }

    /// Erstellt einen brandneuen Gutschein und fügt ihn direkt zum Wallet hinzu.
    ///
    /// Diese Methode orchestriert die Erstellung eines neuen Gutscheins basierend auf
    /// einem Standard, signiert ihn mit der Identität des Erstellers und speichert
    /// ihn sofort im `VoucherStore` mit dem Status `Active`.
    ///
    /// # Arguments
    /// * `identity` - Die Identität des Erstellers, enthält den Signierschlüssel.
    /// * `standard_definition` - Die Regeln und Vorlagen des Gutschein-Standards.
    /// * `data` - Die spezifischen Daten für den neuen Gutschein (z.B. Betrag).
    ///
    /// # Returns
    /// Ein `Result` mit dem vollständig erstellten `Voucher` bei Erfolg.
    pub fn create_new_voucher(
        &mut self,
        identity: &UserIdentity,
        // Die Signatur wird erweitert, um die verifizierten Daten zu erhalten
        verified_standard: &VoucherStandardDefinition,
        standard_hash: &str,
        lang_preference: &str,
        data: NewVoucherData,
    ) -> Result<Voucher, VoucherCoreError> {
        let new_voucher = voucher_manager::create_voucher(
            data,
            verified_standard,
            standard_hash,
            &identity.signing_key,
            lang_preference,
        )?;

        // KORREKTE LOGIK ZUR ZUSTANDSVERWALTUNG:
        // 1. Berechne die korrekte lokale ID basierend auf der `init`-Transaktion.
        let local_id = Self::calculate_local_instance_id(&new_voucher, &identity.user_id)?;

        // 2. Bestimme den initialen Status durch eine sofortige Validierung.
        let initial_status = match voucher_validation::validate_voucher_against_standard(&new_voucher, verified_standard) {
            Ok(_) => VoucherStatus::Active,
            // Wenn Bürgen fehlen, ist der Status `Incomplete`.
            Err(VoucherCoreError::Validation(ValidationError::CountOutOfBounds { field, min, max, found })) if field == "guarantor_signatures" => {
                VoucherStatus::Incomplete {
                    reasons: vec![ValidationFailureReason::GuarantorCountLow {
                        required: min,
                        max: max,
                        current: found as u32,
                    }],
                }
            },
            // Jeder andere Validierungsfehler bei der Erstellung ist ein fataler Fehler.
            Err(e) => return Err(e),
        };

        // 3. Füge die Instanz mit der korrekten ID und dem korrekten Status hinzu.
        self.add_voucher_instance(local_id, new_voucher.clone(), initial_status);

        Ok(new_voucher)
    }

    /// Führt Wartungsarbeiten am Wallet-Speicher durch, um veraltete Daten zu entfernen.
    pub fn cleanup_storage(&mut self, archive_grace_period_years: i64) {
        self.cleanup_expired_fingerprints();

        let now = Utc::now();
        let grace_period = Duration::days(archive_grace_period_years * 365);

        self.voucher_store
            .vouchers
            .retain(|_, instance| {
                if !matches!(instance.status, VoucherStatus::Archived) {
                    return true;
                }
                if let Ok(valid_until) = DateTime::parse_from_rfc3339(&instance.voucher.valid_until) {
                    let purge_date = valid_until.with_timezone(&Utc) + grace_period;
                    return now < purge_date;
                }
                true
            });

        self.proof_store.proofs.retain(|_, proof| {
            if let Ok(valid_until) = DateTime::parse_from_rfc3339(&proof.voucher_valid_until) {
                let purge_date = valid_until.with_timezone(&Utc) + grace_period;
                return now < purge_date;
            }
            true
        });
    }

    /// Sucht eine Transaktion anhand ihrer ID (`t_id`) zuerst im aktiven
    /// `voucher_store` und dann im `VoucherArchive`.
    fn find_transaction_in_stores(
        &self,
        t_id: &str,
        archive: &dyn VoucherArchive,
    ) -> Result<Option<Transaction>, VoucherCoreError> {
        // Zuerst im aktiven Store suchen
        for instance in self.voucher_store.vouchers.values() {
            if let Some(tx) = instance.voucher.transactions.iter().find(|t| t.t_id == t_id) {
                return Ok(Some(tx.clone()));
            }
        }

        // Danach im Archiv suchen
        let result = archive.find_transaction_by_id(t_id)?;
        Ok(result.map(|(_, tx)| tx))
    }

    /// Sucht einen Gutschein anhand einer enthaltenen Transaktions-ID (`t_id`).
    /// Durchsucht zuerst den aktiven `voucher_store` und dann das `VoucherArchive`.
    fn find_voucher_for_transaction(
        &self,
        t_id: &str,
        archive: &dyn VoucherArchive,
    ) -> Result<Option<Voucher>, VoucherCoreError> {
        // Zuerst im aktiven Store suchen
        for instance in self.voucher_store.vouchers.values() {
            if instance.voucher.transactions.iter().any(|t| t.t_id == t_id) {
                return Ok(Some(instance.voucher.clone()));
            }
        }

        // Danach im Archiv suchen
        Ok(archive.find_voucher_by_tx_id(t_id)?)
    }

    /// Findet die lokale ID und den Status eines Gutscheins anhand einer enthaltenen Transaktions-ID.
    fn find_local_voucher_by_tx_id(&self, tx_id: &str) -> Option<&VoucherInstance>{
        self.voucher_store
            .vouchers
            .values()
            .find(|instance| instance.voucher.transactions.iter().any(|tx| tx.t_id == tx_id) )
    }
}

/// Gekapselte Offline-Konfliktlösung via "Earliest Wins"-Heuristik.
fn resolve_conflict_offline(
    voucher_store: &mut VoucherStore,
    fingerprints: &[crate::models::conflict::TransactionFingerprint],
) {
    let tx_ids: std::collections::HashSet<_> = fingerprints.iter().map(|fp| &fp.t_id).collect();

    // --- 1. Lese-Phase: Finde den Gewinner, ohne den Store zu verändern ---
    let conflicting_txs: Vec<_> = voucher_store.vouchers.values().flat_map(|inst| &inst.voucher.transactions).filter(|tx| tx_ids.contains(&tx.t_id)).collect();

    let mut winner_tx: Option<&crate::models::voucher::Transaction> = None;
    let mut earliest_time = u128::MAX;

    for tx in &conflicting_txs {
        if let Some(fp) = fingerprints.iter().find(|f| f.t_id == tx.t_id) {
            if let Ok(decrypted_nanos) = conflict_manager::decrypt_transaction_timestamp(tx, fp.encrypted_timestamp) {
                if decrypted_nanos < earliest_time {
                    earliest_time = decrypted_nanos;
                    winner_tx = Some(tx);
                }
            }
        }
    }

    // --- 2. Schreib-Phase: Aktualisiere den Status basierend auf der Gewinner-ID ---
    // Die `conflicting_txs`-Liste ist nun nicht mehr im Scope, die unveränderliche Ausleihe ist beendet.
    if let Some(winner_id) = winner_tx.map(|tx| tx.t_id.clone()) {
        for instance in voucher_store.vouchers.values_mut() {
            // Finde heraus, ob diese Instanz eine der Konflikt-Transaktionen enthält.
            if let Some(tx) = instance.voucher.transactions.iter().find(|tx| tx_ids.contains(&tx.t_id)) {
                instance.status = if tx.t_id == winner_id {
                    VoucherStatus::Active
                } else {
                    VoucherStatus::Quarantined { reason: "Lost offline race".to_string() }
                };
            }
        }
    }
}