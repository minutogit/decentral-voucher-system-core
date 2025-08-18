//! # src/wallet.rs
//!
//! Definiert die `Wallet`-Fassade, die zentrale Verwaltungsstruktur für ein
//! Nutzerprofil. Sie kapselt den In-Memory-Zustand (`UserProfile`, `VoucherStore`)
//! und orchestriert die Interaktionen mit einem `Storage`-Backend und den
//! kryptographischen Operationen der `UserIdentity`.

use crate::archive::VoucherArchive;
use crate::error::VoucherCoreError;
use crate::models::conflict::{FingerprintStore, ProofOfDoubleSpend, ProofStore, TransactionFingerprint};
use crate::models::profile::{
    BundleMetadataStore, TransactionBundle, TransactionBundleHeader, TransactionDirection,
    UserIdentity, UserProfile, VoucherStatus, VoucherStore,
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
use chrono::{DateTime, Duration, Utc};
use crate::models::voucher::Transaction;
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
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
            crate::services::crypto_utils::derive_ed25519_keypair(mnemonic_phrase, None);
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
        self.bundle_meta_store
            .history
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
        archive: Option<&impl VoucherArchive>,
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
        self.bundle_meta_store
            .history
            .insert(header.bundle_id.clone(), header.clone());

        self.scan_and_update_own_fingerprints()?;
        let check_result = self.check_for_double_spend();

        for (conflict_hash, fingerprints) in &check_result.verifiable_conflicts {
            if let Some(archive_backend) = archive {
                if let Some(proof) = self.verify_conflict_and_create_proof(
                    identity, conflict_hash, fingerprints, archive_backend
                )? {
                    self.proof_store.proofs.insert(proof.proof_id.clone(), proof);
                }
            }
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

        // Iteriere rückwärts durch die Transaktionen. Die erste Transaktion, die den
        // `profile_owner_id` zum Besitzer macht, ist die maßgebliche Transaktion
        // für die ID dieser spezifischen Gutschein-Instanz.
        for tx in voucher.transactions.iter().rev() {
            let is_recipient = tx.recipient_id == profile_owner_id;

            // Der Sender wird (wieder) zum Besitzer, wenn es einen Restbetrag gibt (Split).
            let is_sender_with_remainder = tx.sender_id == profile_owner_id && tx.sender_remaining_amount.is_some();

            if is_recipient || is_sender_with_remainder {
                ownership_defining_tx_id = Some(tx.t_id.clone());
                break; // Die erste gefundene Transaktion ist die richtige.
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
    /// Dies ist die zentrale, sichere Methode für Client-Anwendungen, um einen Transfer zu initiieren.
    /// Sie kapselt die Geschäftslogik, Sicherheitsprüfungen und die Zustandsverwaltung.
    ///
    /// # Arguments
    /// * `identity` - Die Identität des Senders.
    /// * `standard_definition` - Die Standard-Definition, die für den Gutschein gilt.
    /// * `local_instance_id` - Die lokale ID der zu verwendenden Gutschein-Instanz im Wallet.
    /// * `recipient_id` - Die ID des Empfängers.
    /// * `amount_to_send` - Der zu sendende Betrag als String.
    /// * `notes` - Optionale Notizen für das Transaktionsbündel.
    ///
    /// # Returns
    /// Ein `Result`, das entweder die serialisierten Bytes des `SecureContainer` für den
    /// Transfer oder einen `VoucherCoreError` enthält.
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
        // 1. Gutschein-Instanz klonen, um Borrowing-Konflikte zu vermeiden, und Status prüfen.
        let (voucher_to_spend, status) = self
            .voucher_store
            .vouchers
            .get(local_instance_id)
            .ok_or(VoucherCoreError::VoucherNotFound(local_instance_id.to_string()))?;

        if *status != VoucherStatus::Active {
            return Err(VoucherCoreError::VoucherNotActive(status.clone()));
        }
        let voucher_to_spend = voucher_to_spend.clone();

        // Phase 3: Proaktive Double-Spend-Prüfung.
        let last_tx = voucher_to_spend.transactions.last()
            .ok_or_else(|| VoucherCoreError::Generic("Cannot spend voucher with no transactions.".to_string()))?;
        let prev_hash = get_hash(to_canonical_json(last_tx)?);
        let fingerprint_hash = get_hash(format!("{}{}", prev_hash, identity.user_id));

        if self.fingerprint_store.own_fingerprints.contains_key(&fingerprint_hash) {
            return Err(VoucherCoreError::DoubleSpendAttemptBlocked);
        }

        // 2. Erzeuge den neuen Gutschein-Zustand durch Aufruf der `voucher_manager`-Funktion.
        let new_voucher_state = voucher_manager::create_transaction(
            &voucher_to_spend,
            standard_definition,
            &identity.user_id,
            &identity.signing_key,
            recipient_id,
            amount_to_send,
        )?;

        // Phase 4: Wallet-Zustandsverwaltung aktualisieren.
        // Die alte Instanz wird archiviert.
        self.voucher_store.vouchers.get_mut(local_instance_id).unwrap().1 = VoucherStatus::Archived;

        // NEU: Versuche, den nun (potenziell) vollständig ausgegebenen Gutschein zu archivieren.
        if let Some(archive_backend) = archive {
            archive_backend.archive_voucher(
                &new_voucher_state,
                &identity.user_id,
                standard_definition,
            )?;
        }

        // Wenn es ein Split war, wird eine neue, aktive Instanz für den Restbetrag des Senders erstellt.
        if let Some(last_tx) = new_voucher_state.transactions.last() {
            if last_tx.sender_id == identity.user_id && last_tx.sender_remaining_amount.is_some() {
                let new_local_id = Self::calculate_local_instance_id(&new_voucher_state, &identity.user_id)?;
                self.voucher_store.vouchers.insert(new_local_id, (new_voucher_state.clone(), VoucherStatus::Active));
            }
        }

        // 3. Erstelle das `TransactionBundle` und den `SecureContainer`.
        // Diese Logik wird von `create_and_encrypt_transaction_bundle` hierher verschoben,
        // um die Zustandsverwaltung an einem Ort zu zentralisieren. Wir klonen hier, damit wir den
        // new_voucher_state am Ende zurückgeben können.
        let vouchers_for_bundle = vec![new_voucher_state.clone()];
        let mut bundle = TransactionBundle {
            bundle_id: "".to_string(),
            sender_id: identity.user_id.clone(),
            recipient_id: recipient_id.to_string(),
            vouchers: vouchers_for_bundle,
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
        self.bundle_meta_store
            .history
            .insert(header.bundle_id.clone(), header);

        // Nach dem Erstellen des signierten Bündels den Fingerprint der soeben erstellten
        // Transaktion zum eigenen Store hinzufügen. Dies ist die proaktive Schutzmaßnahme.
        let created_tx = bundle.vouchers[0].transactions.last().unwrap();
        let fingerprint = TransactionFingerprint {
            prvhash_senderid_hash: fingerprint_hash.clone(),
            t_id: created_tx.t_id.clone(),
            t_time: created_tx.t_time.clone(),
            sender_signature: created_tx.sender_signature.clone(),
            valid_until: bundle.vouchers[0].valid_until.clone(),
        };

        self.fingerprint_store
            .own_fingerprints
            .entry(fingerprint_hash)
            .or_default()
            .push(fingerprint);

        Ok((container_bytes, new_voucher_state))
    }

    /// Führt Wartungsarbeiten am Wallet-Speicher durch, um veraltete Daten zu entfernen.
    ///
    /// Diese Funktion sollte periodisch aufgerufen werden (z.B. beim Start der Anwendung),
    /// um die Größe der Speicherdateien zu kontrollieren.
    ///
    /// # Tasks
    /// - Entfernt alle abgelaufenen Fingerprints (sowohl eigene als auch fremde).
    /// - Entfernt archivierte Gutschein-Instanzen, deren Gültigkeitsdatum eine
    ///   bestimmte Schonfrist (`archive_grace_period_years`) überschritten hat.
    ///
    /// # Arguments
    /// * `archive_grace_period_years` - Die Anzahl der Jahre, die ein archivierter Gutschein
    ///   nach seinem Ablaufdatum aufbewahrt werden soll, bevor er endgültig gelöscht wird.
    pub fn cleanup_storage(&mut self, archive_grace_period_years: i64) {
        // 1. Veraltete Fingerprints entfernen (existierende Funktion wiederverwenden).
        self.cleanup_expired_fingerprints();

        // 2. Veraltete archivierte Gutscheine entfernen.
        let now = Utc::now();
        let grace_period = Duration::days(archive_grace_period_years * 365); // Vereinfachung

        self.voucher_store.vouchers.retain(|_, (voucher, status)| {
            if *status != VoucherStatus::Archived {
                return true; // Behalte alle nicht-archivierten Gutscheine.
            }

            // Versuche, das Ablaufdatum zu parsen.
            if let Ok(valid_until) = DateTime::parse_from_rfc3339(&voucher.valid_until) {
                let purge_date = valid_until.with_timezone(&Utc) + grace_period;
                // Behalte den Gutschein, wenn das Löschdatum noch nicht erreicht ist.
                return now < purge_date;
            }
            true // Behalte den Gutschein, wenn das Datum nicht geparst werden kann.
        });

        // 3. Veraltete Beweise aus dem ProofStore entfernen.
        self.proof_store.proofs.retain(|_, proof| {
            if let Ok(valid_until) = DateTime::parse_from_rfc3339(&proof.voucher_valid_until) {
                let purge_date = valid_until.with_timezone(&Utc) + grace_period;
                // Behalte den Beweis, wenn das Löschdatum noch nicht erreicht ist.
                return now < purge_date;
            }
            // Behalte den Beweis im Zweifelsfall (z.B. bei Parse-Fehler),
            // um keine wichtigen Informationen zu verlieren.
            true
        });
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

    /// Verifiziert einen Double-Spend-Konflikt kryptographisch und erstellt bei Erfolg einen
    /// fälschungssicheren, portablen Beweis (`ProofOfDoubleSpend`).
    ///
    /// Diese Funktion ist der Kern der Betrugsaufdeckung. Sie führt folgende Schritte aus:
    /// 1. Sucht die vollständigen Transaktionsobjekte, die zu den widersprüchlichen
    ///    Fingerprints gehören, sowohl im aktiven `VoucherStore` als auch im `VoucherArchive`.
    /// 2. Rekonstruiert für jede gefundene Transaktion die Nachricht, die signiert wurde.
    /// 3. Verifiziert die `sender_signature` jeder Transaktion gegen den Public Key des Senders.
    /// 4. Wenn mindestens zwei gültig signierte, aber widersprüchliche Transaktionen gefunden
    ///    wurden, ist der Betrug bewiesen.
    /// 5. Erstellt, signiert und gibt das `ProofOfDoubleSpend`-Objekt zurück.
    /// 6. Setzt als letzte Konsequenz alle lokalen Gutschein-Instanzen, die von diesem Betrug
    ///    betroffen sind, unter Quarantäne.
    ///
    /// # Arguments
    /// * `identity` - Die Identität des Wallet-Besitzers, der den Beweis erstellt (Reporter).
    /// * `conflict_hash` - Der `prvhash_senderid_hash`, der den Konflikt markiert.
    /// * `fingerprints` - Die Liste der widersprüchlichen Fingerprints.
    /// * `archive` - Eine Referenz auf das `VoucherArchive` für die Suche nach alten Transaktionen.
    ///
    /// # Returns
    /// Ein `Result`, das bei Erfolg ein `Option<ProofOfDoubleSpend>` enthält.
    /// - `Some(proof)`: Der Betrug wurde bewiesen.
    /// - `None`: Es konnte kein Beweis erbracht werden (z.B. weil Transaktionen nicht
    ///   gefunden wurden oder Signaturen ungültig waren).
    fn verify_conflict_and_create_proof(
        &mut self,
        identity: &UserIdentity,
        conflict_hash: &str,
        fingerprints: &[TransactionFingerprint],
        archive: &impl VoucherArchive,
    ) -> Result<Option<ProofOfDoubleSpend>, VoucherCoreError> {
        let mut conflicting_transactions = Vec::new();

        // 1. Finde die vollständigen Transaktionen zu den Fingerprints.
        for fp in fingerprints {
            if let Some(tx) = self.find_transaction_in_stores(&fp.t_id, archive)? {
                conflicting_transactions.push(tx);
            }
        }

        // Wir brauchen mindestens zwei Transaktionen, um einen Beweis zu führen.
        if conflicting_transactions.len() < 2 {
            return Ok(None);
        }

        // 2. Extrahiere Kerndaten und verifiziere Signaturen.
        let offender_id = conflicting_transactions[0].sender_id.clone();
        let fork_point_prev_hash = conflicting_transactions[0].prev_hash.clone();
        let offender_pubkey = get_pubkey_from_user_id(&offender_id)?;

        let mut verified_tx_count = 0;
        for tx in &conflicting_transactions {
            // Sicherheitsprüfung: Alle müssen vom selben Sender und prev_hash stammen.
            if tx.sender_id != offender_id || tx.prev_hash != fork_point_prev_hash {
                return Ok(None); // Daten sind inkonsistent, kein gültiger Beweis.
            }

            let signature_payload = serde_json::json!({
                "prev_hash": &tx.prev_hash, "sender_id": &tx.sender_id,
                "t_id": &tx.t_id, "t_time": &tx.t_time
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

        // Finde den zugehörigen Gutschein, um `valid_until` zu bekommen.
        let voucher = self
            .find_voucher_for_transaction(&conflicting_transactions[0].t_id, archive)?
            .ok_or_else(|| {
                VoucherCoreError::VoucherNotFound("for proof creation".to_string())
            })?;
        let voucher_valid_until = voucher.valid_until.clone();

        // 4. Beweis-Objekt erstellen und signieren.
        let proof_id = get_hash(format!("{}{}", offender_id, fork_point_prev_hash));
        let reporter_signature = sign_ed25519(&identity.signing_key, proof_id.as_bytes());

        let proof = ProofOfDoubleSpend {
            proof_id,
            offender_id,
            fork_point_prev_hash,
            conflicting_transactions,
            voucher_valid_until,
            reporter_id: identity.user_id.clone(),
            report_timestamp: get_current_timestamp(),
            reporter_signature: bs58::encode(reporter_signature.to_bytes()).into_string(),
            resolutions: None,
        };

        // 5. Als Konsequenz alle betroffenen lokalen Gutscheine unter Quarantäne stellen.
        let ids_to_quarantine = self.find_all_local_vouchers_by_conflict_hash(conflict_hash);
        for local_id in ids_to_quarantine {
            if let Some(entry) = self.voucher_store.vouchers.get_mut(&local_id) {
                entry.1 = VoucherStatus::Quarantined;
            }
        }

        Ok(Some(proof))
    }

    /// Findet die lokalen IDs aller Gutschein-Instanzen, die einen bestimmten Konflikt-Hash enthalten.
    fn find_all_local_vouchers_by_conflict_hash(
        &self,
        conflict_hash: &str,
    ) -> Vec<String> {
        let mut matching_ids = Vec::new();
        for (local_id, (voucher, _)) in &self.voucher_store.vouchers {
            // Wir müssen nur prüfen, ob die betrügerische Transaktion in der Kette ist.
            for tx in &voucher.transactions {
                let current_hash = get_hash(format!("{}{}", tx.prev_hash, tx.sender_id));
                if current_hash == conflict_hash {
                    matching_ids.push(local_id.clone());
                    // Sobald ein Gutschein als betroffen identifiziert ist,
                    // können wir die Prüfung seiner restlichen Transaktionen abbrechen.
                    break;
                }
            }
        }
        matching_ids
    }

    /// Sucht eine Transaktion anhand ihrer ID (`t_id`) zuerst im aktiven
    /// `voucher_store` und dann im `VoucherArchive`.
    fn find_transaction_in_stores(
        &self,
        t_id: &str,
        archive: &impl VoucherArchive,
    ) -> Result<Option<Transaction>, VoucherCoreError> {
        // Zuerst im aktiven Store suchen
        for (voucher, _) in self.voucher_store.vouchers.values() {
            if let Some(tx) = voucher.transactions.iter().find(|t| t.t_id == t_id) {
                return Ok(Some(tx.clone()));
            }
        }

        // Danach im Archiv suchen (falls im aktiven Store nicht gefunden)
        let result = archive.find_transaction_by_id(t_id)?;
        Ok(result.map(|(_, tx)| tx))
    }

    /// Sucht einen Gutschein anhand einer enthaltenen Transaktions-ID (`t_id`).
    /// Durchsucht zuerst den aktiven `voucher_store` und dann das `VoucherArchive`.
    fn find_voucher_for_transaction(
        &self,
        t_id: &str,
        archive: &impl VoucherArchive,
    ) -> Result<Option<Voucher>, VoucherCoreError> {
        // Zuerst im aktiven Store suchen
        for (voucher, _) in self.voucher_store.vouchers.values() {
            if voucher.transactions.iter().any(|t| t.t_id == t_id) {
                return Ok(Some(voucher.clone()));
            }
        }

        // Danach im Archiv suchen
        Ok(archive.find_voucher_by_tx_id(t_id)?)
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