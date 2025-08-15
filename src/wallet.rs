//! # src/wallet.rs
//!
//! Definiert die `Wallet`-Fassade, die zentrale Verwaltungsstruktur für ein
//! Nutzerprofil. Sie kapselt den In-Memory-Zustand (`UserProfile`, `VoucherStore`)
//! und orchestriert die Interaktionen mit einem `Storage`-Backend und den
//! kryptographischen Operationen der `UserIdentity`.

use crate::error::VoucherCoreError;
use crate::models::fingerprint::{FingerprintStore, TransactionFingerprint};
use crate::models::profile::{
    TransactionBundle, TransactionBundleHeader, TransactionDirection, UserIdentity, UserProfile,
    VoucherStatus, VoucherStore,
};
use crate::models::secure_container::{PayloadType, SecureContainer};
use crate::models::voucher::Voucher;
use crate::services::crypto_utils::{
    create_user_id, get_hash, get_pubkey_from_user_id, sign_ed25519, verify_ed25519,
};
use crate::services::secure_container_manager::{create_secure_container, open_secure_container};
use crate::services::utils::{get_current_timestamp, to_canonical_json};
use crate::services::voucher_validation::ValidationError;
use crate::storage::{AuthMethod, Storage, StorageError};
use ed25519_dalek::Signature;
use rust_decimal::Decimal;
use std::collections::HashMap;
use std::str::FromStr;

/// Die zentrale Verwaltungsstruktur für ein Nutzer-Wallet.
/// Hält den In-Memory-Zustand und interagiert mit dem Speichersystem.
pub struct Wallet {
    /// Die öffentlichen Profildaten und die Transaktionshistorie.
    pub profile: UserProfile,
    /// Der Bestand an Gutscheinen des Nutzers.
    pub voucher_store: VoucherStore,
    /// Der Speicher für Transaktions-Fingerprints zur Double-Spending-Erkennung.
    pub fingerprint_store: FingerprintStore,
}

impl Wallet {
    /// Erstellt ein brandneues, leeres Wallet aus einer Mnemonic-Phrase.
    pub fn new_from_mnemonic(
        mnemonic_phrase: &str,
        user_prefix: Option<&str>,
    ) -> Result<(Self, UserIdentity), VoucherCoreError> {
        let (public_key, signing_key) =
            crate::services::crypto_utils::derive_ed25519_keypair(mnemonic_phrase, None);
        let user_id = create_user_id(&public_key, user_prefix)
            .map_err(|e| VoucherCoreError::Crypto(e.to_string()))?;

        let identity = UserIdentity {
            signing_key,
            public_key,
            user_id: user_id.clone(),
        };

        let profile = UserProfile {
            user_id,
            bundle_history: Default::default(),
        };

        let voucher_store = VoucherStore::default();
        let fingerprint_store = FingerprintStore::default();

        let wallet = Wallet {
            profile,
            voucher_store,
            fingerprint_store,
        };

        Ok((wallet, identity))
    }

    /// Lädt ein existierendes Wallet aus einem `Storage`-Backend.
    pub fn load<S: Storage>(
        storage: &S,
        auth: &AuthMethod,
        identity: UserIdentity,
    ) -> Result<Self, VoucherCoreError> {
        let (profile, voucher_store) = storage.load(auth)?;
        let fingerprint_store = storage.load_fingerprints(&identity.user_id, auth)?;

        if profile.user_id != identity.user_id {
            return Err(StorageError::AuthenticationFailed.into());
        }

        Ok(Wallet {
            profile,
            voucher_store,
            fingerprint_store,
        })
    }

    /// Speichert den aktuellen Zustand des Wallets in einem `Storage`-Backend.
    pub fn save<S: Storage>(
        &self,
        storage: &mut S,
        identity: &UserIdentity,
        password: &str,
    ) -> Result<(), StorageError> {
        storage.save(&self.profile, &self.voucher_store, identity, password)?;
        storage.save_fingerprints(
            &identity.user_id,
            password,
            &self.fingerprint_store,
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

    /// Erstellt ein `TransactionBundle`, verpackt es in einen `SecureContainer` und serialisiert diesen.
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

        let mut bundle = TransactionBundle {
            bundle_id: "".to_string(),
            sender_id: identity.user_id.clone(),
            recipient_id: recipient_id.to_string(),
            vouchers: vouchers.clone(),
            timestamp: get_current_timestamp(),
            notes,
            sender_signature: "".to_string(),
        };

        let bundle_json_for_id = to_canonical_json(&bundle)?;
        bundle.bundle_id = get_hash(bundle_json_for_id);

        let signature = sign_ed25519(&identity.signing_key, bundle.bundle_id.as_bytes());
        bundle.sender_signature = bs58::encode(signature.to_bytes()).into_string();
        let signed_bundle_bytes = serde_json::to_vec(&bundle)?;

        let secure_container = create_secure_container(
            identity,
            &[recipient_id.to_string()],
            &signed_bundle_bytes,
            PayloadType::TransactionBundle,
        )?;

        let container_bytes = serde_json::to_vec(&secure_container)?;

        let header = bundle.to_header(TransactionDirection::Sent);
        self.profile
            .bundle_history
            .insert(header.bundle_id.clone(), header);

        for voucher in vouchers {
            // ÄNDERUNG: Statt den Gutschein zu löschen, wird sein Status auf 'Archived' gesetzt.
            // Dies ist entscheidend für die lückenlose Double-Spending-Erkennung.
            let local_id = Self::calculate_local_instance_id(&voucher, &identity.user_id)?;
            if let Some(entry) = self.voucher_store.vouchers.get_mut(&local_id) {
                entry.1 = VoucherStatus::Archived;
            }
        }

        Ok(container_bytes)
    }

    /// Verarbeitet einen serialisierten `SecureContainer`, der ein `TransactionBundle` enthält.
    pub fn process_encrypted_transaction_bundle(
        &mut self,
        identity: &UserIdentity,
        container_bytes: &[u8],
    ) -> Result<ProcessBundleResult, VoucherCoreError> {
        let container: SecureContainer = serde_json::from_slice(container_bytes)?;
        let (decrypted_bundle_bytes, payload_type) = open_secure_container(&container, identity)?;

        if payload_type != PayloadType::TransactionBundle {
            return Err(VoucherCoreError::InvalidPayloadType);
        }

        let bundle: TransactionBundle = serde_json::from_slice(&decrypted_bundle_bytes)?;
        Self::verify_bundle_signature(&bundle)?;

        for voucher in bundle.vouchers.clone() {
            println!("\n[Debug Wallet] Verarbeite empfangenen Gutschein: ID={}, Tx-Anzahl={}", voucher.voucher_id, voucher.transactions.len());
            self.add_voucher_to_store(voucher, VoucherStatus::Active, &identity.user_id)?;
        }

        let header = bundle.to_header(TransactionDirection::Received);
        self.profile
            .bundle_history
            .insert(header.bundle_id.clone(), header.clone());

        self.scan_and_update_own_fingerprints()?;
        let check_result = self.check_for_double_spend();

        for (conflict_hash, fingerprints) in &check_result.verifiable_conflicts {
            self.verify_conflict_and_quarantine(conflict_hash, fingerprints)?;
        }

        Ok(ProcessBundleResult {
            header,
            check_result,
        })
    }

    /// Verifiziert die digitale Signatur eines `TransactionBundle`.
    fn verify_bundle_signature(bundle: &TransactionBundle) -> Result<(), VoucherCoreError> {
        let sender_pubkey_ed = get_pubkey_from_user_id(&bundle.sender_id)?;
        let signature_bytes = bs58::decode(&bundle.sender_signature)
            .into_vec()
            .map_err(|e| ValidationError::SignatureDecodeError(e.to_string()))?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|e| ValidationError::SignatureDecodeError(e.to_string()))?;

        if !verify_ed25519(&sender_pubkey_ed, bundle.bundle_id.as_bytes(), &signature) {
            return Err(ValidationError::InvalidBundleSignature.into());
        }

        Ok(())
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
        println!("\n[Debug ID Calc] Starte Berechnung für Gutschein '{}', Owner '{}'", voucher.voucher_id, profile_owner_id);

        // Iteriere rückwärts durch die Transaktionen, um den ANFANG der letzten
        // Besitz-Periode zu finden.
        for i in (0..voucher.transactions.len()).rev() {
            let history_slice = &voucher.transactions[..=i];
            let current_tx_id = &voucher.transactions[i].t_id;
            println!("[Debug ID Calc] Prüfe Tx #{} (ID: {})", i, current_tx_id);

            let balance = Self::get_balance_at_transaction(
                history_slice,
                profile_owner_id,
                &voucher.nominal_value.amount,
            );
            println!("[Debug ID Calc] -> Guthaben nach dieser Tx: {}", balance);

            if balance > rust_decimal::Decimal::ZERO {
                // Diese Transaktion ist Teil einer Besitz-Periode. Wir merken uns ihre ID
                // als potenziellen Startpunkt. Da wir rückwärts iterieren, wird der
                // gemerkte Wert immer der früheste Punkt der aktuellen Besitz-Periode sein.
                ownership_defining_tx_id = Some(voucher.transactions[i].t_id.clone());
                println!("[Debug ID Calc] -> Guthaben > 0. Setze definierende Tx-ID auf: '{}'", ownership_defining_tx_id.as_ref().unwrap());
            } else {
                // Der Kontostand ist null. Das bedeutet, die letzte Besitz-Periode ist hier zu Ende.
                // Wenn wir bereits einen Kandidaten gefunden haben, ist das der definitive Startpunkt.
                // Wir können die Suche beenden.
                if ownership_defining_tx_id.is_some() {
                    break;
                }
            }
        }

        println!("[Debug ID Calc] Finale definierende Tx-ID für Instanz: {:?}", ownership_defining_tx_id);
        match ownership_defining_tx_id {
            Some(t_id) => {
                // Die zuletzt gemerkte ID ist somit die der Transaktion, die deine letzte Besitz-Periode gestartet hat.
                let combined_string = format!("{}{}{}", voucher.voucher_id, t_id, profile_owner_id);
                Ok(get_hash(combined_string))
            }
            None => {
                Err(VoucherCoreError::Generic(
                    "Voucher instance never owned by profile holder.".to_string(),
                ))
            }
        }
    }

    /// Berechnet das Guthaben eines bestimmten Nutzers nach einer spezifischen Transaktionshistorie.
    /// Diese Funktion ist bewusst einfach gehalten und validiert die Transaktionen nicht;
    /// sie wendet sie lediglich mechanisch an, um einen Kontostand zu einem bestimmten Zeitpunkt zu ermitteln.
    pub fn get_balance_at_transaction(
        history: &[crate::models::voucher::Transaction],
        user_id: &str,
        initial_amount: &str,
    ) -> Decimal {
        let mut balances: HashMap<String, Decimal> = HashMap::new();
        if history.is_empty() {
            return Decimal::ZERO;
        }

        // 1. Initialisiere den Kontostand mit der 'init'-Transaktion.
        let init_tx = &history[0];
        if init_tx.t_type == "init" {
            let initial_dec = Decimal::from_str(initial_amount).unwrap_or_default();
            balances.insert(init_tx.sender_id.clone(), initial_dec);
        }

        // 2. Wende alle nachfolgenden Transaktionen an.
        for tx in history.iter().skip(1) {
            let sender_id = &tx.sender_id;
            let recipient_id = &tx.recipient_id;

            if let Some(remaining_str) = &tx.sender_remaining_amount {
                // --- FALL 1: SPLIT (Teilzahlung) ---
                let tx_amount = Decimal::from_str(&tx.amount).unwrap_or_default();
                let remaining_amount = Decimal::from_str(remaining_str).unwrap_or_default();

                // Setze das Guthaben des Senders auf den expliziten Restbetrag.
                balances.insert(sender_id.clone(), remaining_amount);
                // Füge den gesendeten Betrag dem Empfänger hinzu.
                *balances.entry(recipient_id.clone()).or_default() += tx_amount;
            } else {
                // --- FALL 2: VOLLER TRANSFER ---
                // Der gesamte bisherige Kontostand des Senders wird übertragen.
                let sender_balance_before = balances.get(sender_id).cloned().unwrap_or_default();

                // Füge das Guthaben des Senders dem Empfänger hinzu.
                *balances.entry(recipient_id.clone()).or_default() += sender_balance_before;
                // Das Guthaben des Senders wird auf 0 gesetzt.
                balances.insert(sender_id.clone(), Decimal::ZERO);
            }
        }

        // Gib das finale Guthaben für den angefragten Nutzer zurück.
        *balances.get(user_id).unwrap_or(&Decimal::ZERO)
    }
}

/// Das Ergebnis der Verarbeitung eines eingehenden Transaktionsbündels.
#[derive(Debug)]
pub struct ProcessBundleResult {
    /// Der Header des verarbeiteten Bundles für die Historie.
    pub header: TransactionBundleHeader,
    /// Das Ergebnis der durchgeführten Double-Spend-Prüfung.
    pub check_result: DoubleSpendCheckResult,
}

/// Das Ergebnis einer Double-Spend-Prüfung.
#[derive(Debug, Default, Clone)]
pub struct DoubleSpendCheckResult {
    /// Konflikte, bei denen mindestens ein beteiligter Fingerprint aus dem eigenen
    /// Wallet stammt.
    pub verifiable_conflicts: HashMap<String, Vec<TransactionFingerprint>>,
    /// Konflikte, die ausschließlich in den von Dritten importierten Fingerprints
    /// gefunden wurden.
    pub unverifiable_warnings: HashMap<String, Vec<TransactionFingerprint>>,
}

/// Methoden zur Verwaltung des Fingerprint-Speichers und der Double-Spending-Logik.
impl Wallet {
    /// Durchsucht alle eigenen Gutscheine und aktualisiert den `own_fingerprints`-Store.
    pub fn scan_and_update_own_fingerprints(&mut self) -> Result<(), VoucherCoreError> {
        self.fingerprint_store.own_fingerprints.clear();

        for (voucher, _) in self.voucher_store.vouchers.values() {
            for tx in &voucher.transactions {
                let prev_hash_sender_id = format!("{}{}", tx.prev_hash, tx.sender_id);
                let hash = get_hash(&prev_hash_sender_id);

                let fingerprint = TransactionFingerprint {
                    prvhash_senderid_hash: hash.clone(),
                    t_id: tx.t_id.clone(),
                    t_time: tx.t_time.clone(),
                    sender_signature: tx.sender_signature.clone(),
                    valid_until: voucher.valid_until.clone(),
                };

                self.fingerprint_store
                    .own_fingerprints
                    .entry(hash)
                    .or_default()
                    .push(fingerprint);
            }
        }
        Ok(())
    }

    /// Führt eine vollständige Double-Spend-Prüfung durch.
    pub fn check_for_double_spend(&self) -> DoubleSpendCheckResult {
        let mut result = DoubleSpendCheckResult::default();
        let mut all_fingerprints: HashMap<String, Vec<TransactionFingerprint>> =
            self.fingerprint_store.own_fingerprints.clone();

        for (hash, fps) in &self.fingerprint_store.foreign_fingerprints {
            all_fingerprints
                .entry(hash.clone())
                .or_default()
                .extend_from_slice(fps);
        }

        for (hash, fps) in all_fingerprints {
            let unique_t_ids = fps
                .iter()
                .map(|fp| &fp.t_id)
                .collect::<std::collections::HashSet<_>>();
            if unique_t_ids.len() > 1 {
                if self.fingerprint_store.own_fingerprints.contains_key(&hash) {
                    result.verifiable_conflicts.insert(hash.clone(), fps);
                } else {
                    result.unverifiable_warnings.insert(hash.clone(), fps);
                }
            }
        }
        result
    }

    /// Versucht, einen Konflikt zu beweisen und setzt bei Erfolg den Gutschein unter Quarantäne.
    fn verify_conflict_and_quarantine(
        &mut self,
        conflict_hash: &str,
        _fingerprints: &[TransactionFingerprint],
    ) -> Result<bool, VoucherCoreError> {
        if let Some((local_id, _)) = self.find_local_voucher_by_conflict_hash(conflict_hash) {
            let local_id_clone = local_id.clone();
            if let Some(entry) = self.voucher_store.vouchers.get_mut(&local_id_clone) {
                entry.1 = VoucherStatus::Quarantined;
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Findet die lokale ID und eine Referenz auf einen Gutschein basierend auf einem Konflikt-Hash.
    fn find_local_voucher_by_conflict_hash(
        &self,
        conflict_hash: &str,
    ) -> Option<(String, &Voucher)> {
        for (local_id, (voucher, _)) in &self.voucher_store.vouchers {
            for tx in voucher.transactions.iter().rev() {
                let current_hash = get_hash(format!("{}{}", tx.prev_hash, tx.sender_id));
                if current_hash == conflict_hash {
                    return Some((local_id.clone(), voucher));
                }
            }
        }
        None
    }

    /// Entfernt alle abgelaufenen Fingerprints aus dem Speicher.
    pub fn cleanup_expired_fingerprints(&mut self) {
        let now = get_current_timestamp();
        self.fingerprint_store
            .own_fingerprints
            .retain(|_, fps| {
                fps.retain(|fp| fp.valid_until > now);
                !fps.is_empty()
            });
        self.fingerprint_store
            .foreign_fingerprints
            .retain(|_, fps| {
                fps.retain(|fp| fp.valid_until > now);
                !fps.is_empty()
            });
    }

    /// Serialisiert die eigenen Fingerprints für den Export.
    pub fn export_own_fingerprints(&self) -> Result<Vec<u8>, VoucherCoreError> {
        Ok(serde_json::to_vec(
            &self.fingerprint_store.own_fingerprints,
        )?)
    }

    /// Importiert und merged fremde Fingerprints in den Speicher.
    pub fn import_foreign_fingerprints(
        &mut self,
        data: &[u8],
    ) -> Result<usize, VoucherCoreError> {
        let incoming: HashMap<String, Vec<TransactionFingerprint>> =
            serde_json::from_slice(data)?;
        let mut new_count = 0;
        for (hash, fps) in incoming {
            let entry = self
                .fingerprint_store
                .foreign_fingerprints
                .entry(hash)
                .or_default();
            for fp in fps {
                if !entry.contains(&fp) {
                    entry.push(fp);
                    new_count += 1;
                }
            }
        }
        Ok(new_count)
    }
}