//! # src/wallet.rs
//!
//! Definiert die `Wallet`-Fassade, die zentrale Verwaltungsstruktur für ein
//! Nutzerprofil. Sie kapselt den In-Memory-Zustand (`UserProfile`, `VoucherStore`)
//! und orchestriert die Interaktionen mit einem `Storage`-Backend und den
//! kryptographischen Operationen der `UserIdentity`.

use crate::archive::VoucherArchive;
use crate::error::VoucherCoreError;
use crate::models::conflict::{FingerprintStore, ProofStore, TransactionFingerprint};
use crate::models::profile::{
    BundleMetadataStore, TransactionBundleHeader, TransactionDirection,
    UserIdentity, UserProfile, VoucherStatus, VoucherStore,
};
use crate::models::secure_container::{PayloadType, SecureContainer};
use crate::models::signature::DetachedSignature;

use crate::models::voucher::Voucher;
use crate::services::crypto_utils::{
    create_user_id, get_hash,
};
use crate::services::{bundle_processor, conflict_manager};
use crate::services::utils::to_canonical_json; 
use crate::storage::{AuthMethod, Storage, StorageError};
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use chrono::{DateTime, Duration, Utc};
use crate::services::voucher_manager;

use std::collections::HashMap;

/// Die zentrale Verwaltungsstruktur für ein Nutzer-Wallet.
/// Hält den In-Memory-Zustand und interagiert mit dem Speichersystem.
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

impl Wallet {
    /// Erstellt ein brandneues, leeres Wallet aus einer Mnemonic-Phrase.
    pub fn new_from_mnemonic(
        mnemonic_phrase: &str,
        user_prefix: Option<&str>,
    ) -> Result<(Self, UserIdentity), VoucherCoreError> {
        let (public_key, signing_key) =
            crate::services::crypto_utils::derive_ed25519_keypair(mnemonic_phrase, None)?;
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
    pub fn load<S: Storage>(
        storage: &S,
        auth: &AuthMethod,
        identity: UserIdentity,
    ) -> Result<Self, VoucherCoreError> {
        let (profile, voucher_store) = storage.load_wallet(auth)?;
        let bundle_meta_store = storage.load_bundle_metadata(&identity.user_id, auth)?;
        let fingerprint_store = storage.load_fingerprints(&identity.user_id, auth)?;
        let proof_store = storage.load_proofs(&identity.user_id, auth)?;

        if profile.user_id != identity.user_id {
            return Err(StorageError::AuthenticationFailed.into());
        }

        Ok(Wallet {
            profile,
            voucher_store,
            bundle_meta_store,
            fingerprint_store,
            proof_store,
        })
    }

    /// Speichert den aktuellen Zustand des Wallets in einem `Storage`-Backend.
    pub fn save<S: Storage>(
        &self,
        storage: &mut S,
        identity: &UserIdentity,
        password: &str,
    ) -> Result<(), StorageError> {
        storage.save_wallet(&self.profile, &self.voucher_store, identity, password)?;
        storage.save_bundle_metadata(
            &identity.user_id,
            password,
            &self.bundle_meta_store,
        )?;
        storage.save_fingerprints(
            &identity.user_id,
            password,
            &self.fingerprint_store,
        )?;
        storage.save_proofs(
            &identity.user_id,
            password,
            &self.proof_store,
        )?;
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
            if let Some((_, status)) = self.voucher_store.vouchers.get(&local_id) {
                if *status == VoucherStatus::Quarantined {
                    return Err(VoucherCoreError::VoucherInQuarantine);
                }
            }
        }

        let (container_bytes, bundle) = bundle_processor::create_and_encrypt_bundle(
            identity,
            vouchers.clone(),
            recipient_id,
            notes,
        )?;

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
        archive: Option<&impl VoucherArchive>,
    ) -> Result<ProcessBundleResult, VoucherCoreError> {
        let bundle =
            bundle_processor::open_and_verify_bundle(identity, container_bytes)?;

        for voucher in bundle.vouchers.clone() {
            println!("\n[Debug Wallet] Verarbeite empfangenen Gutschein: ID={}, Tx-Anzahl={}", voucher.voucher_id, voucher.transactions.len());
            self.add_voucher_to_store(voucher, VoucherStatus::Active, &identity.user_id)?;
        }

        let header = bundle.to_header(TransactionDirection::Received);
        self.bundle_meta_store
            .history
            .insert(header.bundle_id.clone(), header.clone());

        conflict_manager::scan_and_update_own_fingerprints(&self.voucher_store, &mut self.fingerprint_store)?;

        // Wenn eine Signatur empfangen wird, muss der Status des Gutscheins aktualisiert werden
        if let Ok(deserialized_container) = serde_json::from_slice::<SecureContainer>(container_bytes) {
            if matches!(deserialized_container.payload_type, PayloadType::DetachedSignature) {
                self.process_and_attach_signature(identity, container_bytes)?;
                // Wir geben hier ein leeres Ergebnis zurück, da die Signaturverarbeitung
                // keine Header oder Double-Spend-Prüfungen im herkömmlichen Sinne erzeugt.
                // Die aufrufende Anwendung sollte den `PayloadType` prüfen, um das Ergebnis zu interpretieren.
                // TODO: Eine bessere Rückgabestruktur für `process_...` entwerfen, die verschiedene Payloads berücksichtigt.
                return Ok(ProcessBundleResult::default());
            }
        }
        let check_result = conflict_manager::check_for_double_spend(&self.fingerprint_store);

        for (conflict_hash, fingerprints) in &check_result.verifiable_conflicts {
            if let Some(archive_backend) = archive {
                if let Some(proof) = conflict_manager::verify_conflict_and_create_proof(
                    &self.voucher_store, identity, conflict_hash, fingerprints, archive_backend
                )? {
                    if let Some(verdict) = &proof.layer2_verdict {
                        // TODO: Die Signatur des Verdicts hier verifizieren.
                        // Logik für Layer-2-Urteil: Die als gültig deklarierte Transaktion wird aktiviert,
                        // alle anderen im Konflikt stehenden werden unter Quarantäne gestellt.
                        for tx in &proof.conflicting_transactions {
                            if let Some((local_id, _)) = self.find_local_voucher_by_tx_id(&tx.t_id) {
                                if let Some((_, status)) = self.voucher_store.vouchers.get_mut(&local_id) {
                                    *status = if tx.t_id == verdict.valid_transaction_id {
                                        VoucherStatus::Active
                                    } else {
                                        VoucherStatus::Quarantined
                                    };
                                }
                            }
                        }
                    } else {
                        // Offline "Der Früheste gewinnt"-Logik.
                        // Findet die Transaktion mit dem frühesten Zeitstempel und erklärt sie zum Gewinner.
                        let mut winner_tx: Option<&crate::models::voucher::Transaction> = None;
                        let mut earliest_time = u128::MAX;

                        for tx in &proof.conflicting_transactions {
                            if let Some(fp) = fingerprints.iter().find(|f| f.t_id == tx.t_id) {
                                if let Ok(decrypted_nanos) = conflict_manager::decrypt_transaction_timestamp(tx, fp.encrypted_timestamp) {
                                    if decrypted_nanos < earliest_time {
                                        earliest_time = decrypted_nanos;
                                        winner_tx = Some(tx);
                                    }
                                }
                            }
                        }

                        if let Some(the_winner) = winner_tx {
                            for tx in &proof.conflicting_transactions {
                                if let Some((local_id, _)) = self.find_local_voucher_by_tx_id(&tx.t_id) {
                                    if let Some((_, status)) = self.voucher_store.vouchers.get_mut(&local_id) {
                                        *status = if tx.t_id == the_winner.t_id { VoucherStatus::Active } else { VoucherStatus::Quarantined };
                                    }
                                }
                            }
                        }
                    }

                    self.proof_store.proofs.insert(proof.proof_id.clone(), proof);
                }
            }
        }

        Ok(ProcessBundleResult {
            header,
            check_result,
        })
    }

    /// Fügt einen Gutschein zum `VoucherStore` hinzu.
    pub fn add_voucher_to_store(
        &mut self,
        voucher: Voucher,
        status: VoucherStatus,
        profile_owner_id: &str,
    ) -> Result<(), VoucherCoreError> {
        let local_id = Self::calculate_local_instance_id(&voucher, profile_owner_id)?;
        println!("[Debug Wallet] Füge Gutschein zum Store hinzu mit berechneter lokaler ID: {}", local_id);
        self.voucher_store
            .vouchers
            .insert(local_id, (voucher, status));
        Ok(())
    }

    /// Berechnet eine deterministische, lokale ID für eine Gutschein-Instanz.
    pub fn calculate_local_instance_id(
        voucher: &Voucher,
        profile_owner_id: &str,
    ) -> Result<String, VoucherCoreError> {
        let mut ownership_defining_tx_id: Option<String> = None;

        // Suche rückwärts nach der letzten Transaktion, die dem Profilinhaber zu tun hat.
        for tx in voucher.transactions.iter().rev() {
            let is_recipient = tx.recipient_id == profile_owner_id;
            let is_sender = tx.sender_id == profile_owner_id;

            // Eine neue ID wird definiert, wenn der User den Gutschein empfängt ODER sendet.
            if is_recipient || is_sender {
                ownership_defining_tx_id = Some(tx.t_id.clone());
                break;
            }
        }

        match ownership_defining_tx_id {
            Some(t_id) => Ok(get_hash(format!("{}{}{}", voucher.voucher_id, t_id, profile_owner_id))),
            None => Err(VoucherCoreError::Generic(format!(
                "Voucher instance '{}' was never owned by profile holder '{}'.",
                voucher.voucher_id,
                profile_owner_id
            ))),
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
        archive: Option<&impl VoucherArchive>,
    ) -> Result<(Vec<u8>, Voucher), VoucherCoreError> {
        // 1. Gutschein aus dem Store holen und Status prüfen.
        let (voucher_to_spend, status) = self
            .voucher_store
            .vouchers
            .get(local_instance_id)
            .ok_or(VoucherCoreError::VoucherNotFound(local_instance_id.to_string()))?;
 
        if *status != VoucherStatus::Active {
            return Err(VoucherCoreError::VoucherNotActive(status.clone()));
        }
        let voucher_to_spend = voucher_to_spend.clone();
 
        // 2. Proaktive Double-Spend-Prüfung durchführen.
        let last_tx = voucher_to_spend.transactions.last()
            .ok_or_else(|| VoucherCoreError::Generic("Cannot spend voucher with no transactions.".to_string()))?;
        let prev_hash = get_hash(to_canonical_json(last_tx)?);
        let fingerprint_hash = get_hash(format!("{}{}", prev_hash, identity.user_id));
 
        if self.fingerprint_store.own_fingerprints.contains_key(&fingerprint_hash) {
            return Err(VoucherCoreError::DoubleSpendAttemptBlocked);
        }
 
        // 3. Neue Transaktion und den daraus resultierenden neuen Gutschein-Zustand erstellen.
        let new_voucher_state = voucher_manager::create_transaction(
            &voucher_to_spend,
            standard_definition,
            &identity.user_id,
            &identity.signing_key,
            recipient_id,
            amount_to_send,
        )?;
 
        // 4. Den neuen Gutschein-Zustand dem Wallet hinzufügen, bevor der alte entfernt wird.
        if let Some(last_tx) = new_voucher_state.transactions.last() {
            if last_tx.sender_id == identity.user_id && last_tx.sender_remaining_amount.is_some() {
                // Bei einem Split verbleibt ein aktiver Restbetrag beim Sender.
                self.add_voucher_to_store(new_voucher_state.clone(), VoucherStatus::Active, &identity.user_id)?;
            } else {
                // Bei einem vollen Transfer wird der gesendete Zustand für die Historie archiviert.
                self.add_voucher_to_store(new_voucher_state.clone(), VoucherStatus::Archived, &identity.user_id)?;
            }
        }
        // Der alte, ausgegebene Gutschein wird nun aus dem Store gelöscht.
        self.voucher_store.vouchers.remove(local_instance_id);
 
        // 5. Den neuen Zustand optional in ein externes Archiv für forensische Zwecke schreiben.
        if let Some(archive_backend) = archive {
            archive_backend.archive_voucher(
                &new_voucher_state,
                &identity.user_id,
                standard_definition,
            )?;
        }
 
        // 6. Den neuen Gutschein-Zustand für den Versand an den Empfänger verpacken.
        let vouchers_for_bundle = vec![new_voucher_state.clone()];
        let container_bytes = self.create_and_encrypt_transaction_bundle(identity, vouchers_for_bundle.clone(), recipient_id, notes)?;
 
        // 7. Einen Fingerprint der Transaktion erstellen und für die Double-Spend-Erkennung speichern.
        let created_tx = vouchers_for_bundle[0].transactions.last().unwrap();
        let fingerprint = TransactionFingerprint {
            prvhash_senderid_hash: fingerprint_hash.clone(),
            t_id: created_tx.t_id.clone(),
            sender_signature: created_tx.sender_signature.clone(),
            valid_until: vouchers_for_bundle[0].valid_until.clone(),
            encrypted_timestamp: conflict_manager::encrypt_transaction_timestamp(created_tx)?,
        };
 
        self.fingerprint_store
            .own_fingerprints
            .entry(fingerprint_hash)
            .or_default()
            .push(fingerprint);
 
        Ok((container_bytes, new_voucher_state))
    }
 
    /// Führt Wartungsarbeiten am Wallet-Speicher durch, um veraltete Daten zu entfernen.
    pub fn cleanup_storage(&mut self, archive_grace_period_years: i64) {
        self.cleanup_expired_fingerprints();

        let now = Utc::now();
        let grace_period = Duration::days(archive_grace_period_years * 365);

        self.voucher_store.vouchers.retain(|_, (voucher, status)| {
            if *status != VoucherStatus::Archived {
                return true;
            }
            if let Ok(valid_until) = DateTime::parse_from_rfc3339(&voucher.valid_until) {
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
}

/// Das Ergebnis der Verarbeitung eines eingehenden Transaktionsbündels.
#[derive(Debug, Default)]
pub struct ProcessBundleResult {
    pub header: TransactionBundleHeader,
    pub check_result: DoubleSpendCheckResult,
}

/// Methoden für den Signatur-Workflow.
impl Wallet {
    /// Erstellt einen `SecureContainer`, um einen Gutschein zur Unterzeichnung zu versenden.
    ///
    /// Diese Funktion verändert den Wallet-Zustand nicht. Sie dient nur dazu, eine
    /// Anfrage zu verpacken.
    ///
    /// # Arguments
    /// * `identity` - Die Identität des anfragenden Gutschein-Besitzers.
    /// * `local_instance_id` - Die ID des Gutscheins im lokalen `voucher_store`.
    /// * `recipient_id` - Die User ID des potenziellen Unterzeichners.
    ///
    /// # Returns
    /// Die serialisierten Bytes des `SecureContainer`.
    pub fn create_signing_request(
        &self,
        identity: &UserIdentity,
        local_instance_id: &str,
        recipient_id: &str,
    ) -> Result<Vec<u8>, VoucherCoreError> {
        let (voucher, _) = self.voucher_store.vouchers.get(local_instance_id)
            .ok_or(VoucherCoreError::VoucherNotFound(local_instance_id.to_string()))?;

        let payload = to_canonical_json(voucher)?;

        let container = crate::services::secure_container_manager::create_secure_container( 
            identity,
            &[recipient_id.to_string()],
            payload.as_bytes(),
            PayloadType::VoucherForSigning,
        )?;

        Ok(serde_json::to_vec(&container)?)
    }

    /// Erstellt eine `DetachedSignature` für einen Gutschein und verpackt sie in einem
    /// `SecureContainer` für den Rückversand.
    ///
    /// # Arguments
    /// * `identity` - Die Identität des Unterzeichners.
    /// * `voucher_to_sign` - Der Gutschein, der unterzeichnet werden soll (vom Client validiert).
    /// * `signature_data` - Die vom Client vorbereiteten Metadaten der Signatur.
    /// * `original_sender_id` - Die User ID des ursprünglichen Anfragers (Empfänger der Antwort).
    ///
    /// # Returns
    /// Die serialisierten Bytes des `SecureContainer` mit der Signatur.
    pub fn create_detached_signature_response(
        &self,
        identity: &UserIdentity,
        voucher_to_sign: &Voucher,
        signature_data: DetachedSignature,
        original_sender_id: &str,
    ) -> Result<Vec<u8>, VoucherCoreError> {
        let signed_signature = crate::services::signature_manager::complete_and_sign_detached_signature(
            signature_data,
            &voucher_to_sign.voucher_id,
            identity,
        )?;

        let payload = to_canonical_json(&signed_signature)?;

        let container = crate::services::secure_container_manager::create_secure_container( 
            identity,
            &[original_sender_id.to_string()],
            payload.as_bytes(),
            PayloadType::DetachedSignature,
        )?;

        Ok(serde_json::to_vec(&container)?)
    }

    /// Verarbeitet einen `SecureContainer`, der eine `DetachedSignature` enthält,
    /// und fügt diese dem entsprechenden lokalen Gutschein hinzu.
    ///
    /// # Arguments
    /// * `identity` - Die Identität des Empfängers.
    /// * `container_bytes` - Die empfangenen Container-Daten.
    ///
    /// # Returns
    /// Ein `Result`, das bei Erfolg leer ist.
    pub fn process_and_attach_signature(
        &mut self,
        identity: &UserIdentity,
        container_bytes: &[u8],
    ) -> Result<(), VoucherCoreError> {
        let container: SecureContainer = serde_json::from_slice(container_bytes)?;
        let (payload, payload_type) =
            crate::services::secure_container_manager::open_secure_container(&container, identity)?;

        if !matches!(payload_type, PayloadType::DetachedSignature) {
            return Err(VoucherCoreError::InvalidPayloadType);
        }

        let signature: DetachedSignature = serde_json::from_slice(&payload)?;
        crate::services::signature_manager::validate_detached_signature(&signature)?;

        let voucher_id = match &signature {
            DetachedSignature::Guarantor(s) => &s.voucher_id,
            DetachedSignature::Additional(s) => &s.voucher_id,
        };

        let (target_voucher, _) = self.find_active_voucher_by_voucher_id(voucher_id)
            .ok_or_else(|| VoucherCoreError::VoucherNotFound(voucher_id.clone()))?;

        match signature {
            DetachedSignature::Guarantor(s) => target_voucher.guarantor_signatures.push(s),
            DetachedSignature::Additional(s) => target_voucher.additional_signatures.push(s),
        }

        Ok(())
    }
}

/// Das Ergebnis einer Double-Spend-Prüfung.
#[derive(Debug, Default, Clone)]
pub struct DoubleSpendCheckResult {
    pub verifiable_conflicts: HashMap<String, Vec<TransactionFingerprint>>,
    pub unverifiable_warnings: HashMap<String, Vec<TransactionFingerprint>>,
}

/// Methoden zur Verwaltung des Fingerprint-Speichers und der Double-Spending-Logik.
impl Wallet {
    /// Durchsucht alle eigenen Gutscheine und aktualisiert den `own_fingerprints`-Store.
    pub fn scan_and_update_own_fingerprints(&mut self) -> Result<(), VoucherCoreError> {
        conflict_manager::scan_and_update_own_fingerprints(
            &self.voucher_store,
            &mut self.fingerprint_store,
        )
    }

    /// Führt eine vollständige Double-Spend-Prüfung durch.
    pub fn check_for_double_spend(&self) -> DoubleSpendCheckResult {
        conflict_manager::check_for_double_spend(&self.fingerprint_store)
    }

    /// Entfernt alle abgelaufenen Fingerprints aus dem Speicher.
    pub fn cleanup_expired_fingerprints(&mut self) {
        conflict_manager::cleanup_expired_fingerprints(&mut self.fingerprint_store);
    }

    /// Serialisiert die eigenen Fingerprints für den Export.
    pub fn export_own_fingerprints(&self) -> Result<Vec<u8>, VoucherCoreError> {
        conflict_manager::export_own_fingerprints(&self.fingerprint_store)
    }

    /// Importiert und merged fremde Fingerprints in den Speicher.
    pub fn import_foreign_fingerprints(
        &mut self,
        data: &[u8],
    ) -> Result<usize, VoucherCoreError> {
        conflict_manager::import_foreign_fingerprints(&mut self.fingerprint_store, data)
    }

    /// Findet die lokale ID und den Status eines Gutscheins anhand einer enthaltenen Transaktions-ID.
    fn find_local_voucher_by_tx_id(&self, tx_id: &str) -> Option<(String, VoucherStatus)> {
        self.voucher_store
            .vouchers
            .iter()
            .find_map(|(local_id, (voucher, status))| {
                if voucher.transactions.iter().any(|tx| tx.t_id == tx_id) {
                    Some((local_id.clone(), status.clone()))
                } else {
                    None
                }
            })
    }

    /// Findet die aktive Instanz eines Gutscheins anhand seiner globalen `voucher_id`.
    fn find_active_voucher_by_voucher_id(
        &mut self,
        voucher_id: &str,
    ) -> Option<(&mut Voucher, &mut VoucherStatus)> {
        self.voucher_store
            .vouchers
            .values_mut()
            .find(|(voucher, status)| {
                voucher.voucher_id == voucher_id && *status == VoucherStatus::Active
            })
            .map(|(voucher, status)| (voucher, status))
    }
}