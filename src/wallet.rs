//! # src/wallet.rs
//!
//! Definiert die `Wallet`-Fassade, die zentrale Verwaltungsstruktur für ein
//! Nutzerprofil. Sie kapselt den In-Memory-Zustand (`UserProfile`, `VoucherStore`)
//! und orchestriert die Interaktionen mit einem `Storage`-Backend und den
//! kryptographischen Operationen der `UserIdentity`.

use crate::error::VoucherCoreError;
use crate::models::profile::{
    TransactionBundle, TransactionDirection, UserIdentity, UserProfile, VoucherStore,
};
use crate::models::secure_container::{PayloadType, SecureContainer};
use crate::models::voucher::Voucher;
use crate::services::crypto_utils::{
    create_user_id, get_hash, get_pubkey_from_user_id, sign_ed25519, verify_ed25519,
};
use crate::services::secure_container_manager::{
    create_secure_container, open_secure_container, ContainerManagerError,
};
use crate::services::utils::{get_current_timestamp, to_canonical_json};
use crate::services::voucher_validation::ValidationError;
use crate::storage::{AuthMethod, Storage, StorageError};
use ed25519_dalek::Signature;
use rust_decimal::Decimal;

/// Die zentrale Verwaltungsstruktur für ein Nutzer-Wallet.
/// Hält den In-Memory-Zustand und interagiert mit dem Speichersystem.
pub struct Wallet {
    /// Die öffentlichen Profildaten und die Transaktionshistorie.
    pub profile: UserProfile,
    /// Der Bestand an Gutscheinen des Nutzers.
    pub store: VoucherStore,
}

impl Wallet {
    /// Erstellt ein brandneues, leeres Wallet aus einer Mnemonic-Phrase.
    /// Das Wallet existiert zunächst nur im Speicher.
    ///
    /// # Returns
    /// Ein Tupel, das die neue `Wallet`-Instanz und die dazugehörige `UserIdentity` enthält.
    /// Die `UserIdentity` wird separat zurückgegeben, da sie den geheimen Schlüssel enthält
    /// und vom Aufrufer sicher verwaltet werden muss.
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

        let store = VoucherStore::default();

        let wallet = Wallet { profile, store };

        Ok((wallet, identity))
    }

    /// Lädt ein existierendes Wallet aus einem `Storage`-Backend.
    ///
    /// # Arguments
    /// * `storage` - Eine Implementierung des `Storage`-Traits (z.B. `FileStorage`).
    /// * `auth` - Die Authentifizierungsmethode (`Password` oder `RecoveryIdentity`).
    /// * `identity` - Die `UserIdentity`, die aus der Mnemonic-Phrase des Nutzers rekonstruiert wurde.
    ///             Dies ist notwendig, um kryptographische Operationen durchzuführen und die
    ///             Konsistenz des geladenen Profils zu überprüfen.
    pub fn load<S: Storage>(
        storage: &S,
        auth: &AuthMethod,
        identity: UserIdentity,
    ) -> Result<Self, VoucherCoreError> {
        let (profile, store) = storage.load(auth)?;

        // Sicherheitsprüfung: Stellen Sie sicher, dass die bereitgestellte Identität
        // mit dem geladenen Profil übereinstimmt.
        if profile.user_id != identity.user_id {
            return Err(VoucherCoreError::Storage(StorageError::AuthenticationFailed));
        }

        Ok(Wallet { profile, store })
    }

    /// Speichert den aktuellen Zustand des Wallets in einem `Storage`-Backend.
    pub fn save<S: Storage>(
        &self,
        storage: &mut S,
        identity: &UserIdentity,
        password: &str,
    ) -> Result<(), StorageError> {
        storage.save(&self.profile, &self.store, identity, password)
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
            let local_id = Self::calculate_local_instance_id(&voucher, &identity.user_id)?;
            self.store.vouchers.remove(&local_id);
        }

        Ok(container_bytes)
    }

    /// Verarbeitet einen serialisierten `SecureContainer`, der ein `TransactionBundle` enthält.
    pub fn process_encrypted_transaction_bundle(
        &mut self,
        identity: &UserIdentity,
        container_bytes: &[u8],
    ) -> Result<(), VoucherCoreError> {
        let container: SecureContainer = serde_json::from_slice(container_bytes)?;
        let (decrypted_bundle_bytes, payload_type) = open_secure_container(&container, identity)?;

        if payload_type != PayloadType::TransactionBundle {
            return Err(VoucherCoreError::Container(
                ContainerManagerError::NotAnIntendedRecipient,
            ));
        }

        let bundle: TransactionBundle = serde_json::from_slice(&decrypted_bundle_bytes)?;
        let sender_pubkey_ed = get_pubkey_from_user_id(&bundle.sender_id)?;

        let signature_bytes =
            bs58::decode(&bundle.sender_signature)
                .into_vec()
                .map_err(|e| {
                    VoucherCoreError::Validation(ValidationError::SignatureDecodeError(e.to_string()))
                })?;
        let signature = Signature::from_slice(&signature_bytes).map_err(|e| {
            VoucherCoreError::Validation(ValidationError::SignatureDecodeError(e.to_string()))
        })?;

        if !verify_ed25519(&sender_pubkey_ed, bundle.bundle_id.as_bytes(), &signature) {
            return Err(VoucherCoreError::Validation(
                ValidationError::InvalidCreatorSignature, // TODO: Besserer Fehler
            ));
        }

        for voucher in bundle.vouchers.clone() {
            self.add_voucher_to_store(voucher, &identity.user_id)?;
        }

        let header = bundle.to_header(TransactionDirection::Received);
        self.profile
            .bundle_history
            .insert(header.bundle_id.clone(), header);

        Ok(())
    }

    /// Fügt einen Gutschein zum `VoucherStore` hinzu.
    fn add_voucher_to_store(
        &mut self,
        voucher: Voucher,
        profile_owner_id: &str,
    ) -> Result<(), VoucherCoreError> {
        let local_id = Self::calculate_local_instance_id(&voucher, profile_owner_id)?;
        self.store.vouchers.insert(local_id, voucher);
        Ok(())
    }

    /// Berechnet eine deterministische, lokale ID für eine Gutschein-Instanz.
    pub fn calculate_local_instance_id(
        voucher: &Voucher,
        profile_owner_id: &str,
    ) -> Result<String, VoucherCoreError> {
        let mut defining_transaction_id: Option<String> = None;

        for i in (0..voucher.transactions.len()).rev() {
            let history_slice = &voucher.transactions[..=i];
            let balance = Self::get_balance_at_transaction(
                history_slice,
                profile_owner_id,
                &voucher.nominal_value.amount,
            );

            if balance > Decimal::ZERO {
                defining_transaction_id = Some(voucher.transactions[i].t_id.clone());
                break;
            }
        }

        match defining_transaction_id {
            Some(t_id) => {
                let combined_string = format!("{}{}{}", voucher.voucher_id, t_id, profile_owner_id);
                Ok(get_hash(combined_string))
            }
            None => Err(VoucherCoreError::Generic(
                "Voucher instance never owned by profile holder.".to_string(),
            )),
        }
    }

    /// Berechnet das Guthaben eines bestimmten Nutzers nach einer spezifischen Transaktionshistorie.
    pub fn get_balance_at_transaction(
        history: &[crate::models::voucher::Transaction],
        user_id: &str,
        initial_amount: &str,
    ) -> Decimal {
        let mut current_balance = Decimal::ZERO;
        let total_amount = Decimal::from_str_exact(initial_amount).unwrap_or_default();

        for tx in history {
            let tx_amount = Decimal::from_str_exact(&tx.amount).unwrap_or_default();
            if tx.recipient_id == user_id {
                if tx.t_type == "init" { current_balance = total_amount; } else { current_balance += tx_amount; }
            } else if tx.sender_id == user_id {
                if let Some(remaining_str) = &tx.sender_remaining_amount {
                    if let Ok(remaining_amount) = Decimal::from_str_exact(remaining_str) {
                        current_balance = remaining_amount;
                    } else { current_balance = Decimal::ZERO; }
                } else { current_balance = Decimal::ZERO; }
            }
        }
        current_balance
    }
}