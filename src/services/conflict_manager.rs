//! # src/services/conflict_manager.rs
//!
//! Dieses Modul kapselt die gesamte Geschäftslogik zur Erkennung, Verifizierung
//! und Verwaltung von Double-Spending-Konflikten. Es operiert auf den
//! Datenstrukturen des Wallets, ist aber von der `Wallet`-Fassade entkoppelt.

use std::collections::HashMap;
use ed25519_dalek::Signature;

use crate::archive::VoucherArchive;
use crate::error::VoucherCoreError;
use crate::models::conflict::{
    FingerprintStore, ProofOfDoubleSpend, TransactionFingerprint,
};
use crate::models::profile::{UserIdentity, VoucherStore};
use crate::models::voucher::{Transaction, Voucher};
use crate::services::crypto_utils::{get_hash, get_pubkey_from_user_id, sign_ed25519, verify_ed25519};
use crate::services::utils::{get_current_timestamp, to_canonical_json};
use crate::wallet::DoubleSpendCheckResult;
use chrono::{DateTime, Datelike, NaiveDate, SecondsFormat};

/// Erstellt einen einzelnen, anonymisierten Fingerprint für eine gegebene Transaktion.
/// Enthält die Logik zur Anonymisierung des `valid_until`-Zeitstempels.
pub fn create_fingerprint_for_transaction(
    transaction: &Transaction,
    voucher: &Voucher,
) -> Result<TransactionFingerprint, VoucherCoreError> {
    // 1. Anonymisiere den `valid_until`-Zeitstempel durch Runden auf das Monatsende.
    let valid_until_rounded = {
        let parsed_date = DateTime::parse_from_rfc3339(&voucher.valid_until)
            .map_err(|e| VoucherCoreError::Generic(format!("Failed to parse valid_until: {}", e)))?;

        let year = parsed_date.year();
        let month = parsed_date.month();

        let first_of_next_month = if month == 12 {
            NaiveDate::from_ymd_opt(year + 1, 1, 1)
        } else {
            NaiveDate::from_ymd_opt(year, month + 1, 1)
        }
            .ok_or_else(|| VoucherCoreError::Generic("Failed to calculate next month's date".to_string()))?;

        let last_day_of_month = first_of_next_month.pred_opt().unwrap();
        let end_of_month_dt = last_day_of_month.and_hms_micro_opt(23, 59, 59, 999999).unwrap().and_utc();
        end_of_month_dt.to_rfc3339_opts(SecondsFormat::Micros, true)
    };

    // 2. Erstelle den Fingerprint mit dem gerundeten Zeitstempel.
    let prev_hash_sender_id = format!("{}{}", transaction.prev_hash, transaction.sender_id);
    let hash = get_hash(&prev_hash_sender_id);

    Ok(TransactionFingerprint {
        prvhash_senderid_hash: hash,
        t_id: transaction.t_id.clone(),
        sender_signature: transaction.sender_signature.clone(),
        valid_until: valid_until_rounded,
        encrypted_timestamp: encrypt_transaction_timestamp(transaction)?,
    })
}

/// Durchsucht alle Gutscheine eines Nutzers und aktualisiert den `own_fingerprints`-Store.
/// Diese Funktion sollte nach dem Empfang neuer Gutscheine aufgerufen werden.
pub fn scan_and_update_own_fingerprints(
    voucher_store: &VoucherStore,
    fingerprint_store: &mut FingerprintStore,
) -> Result<(), VoucherCoreError> {
    fingerprint_store.own_fingerprints.clear();

    for (voucher, _) in voucher_store.vouchers.values() {
        for tx in &voucher.transactions {
            let fingerprint = create_fingerprint_for_transaction(tx, voucher)?;

            fingerprint_store
                .own_fingerprints
                .entry(fingerprint.prvhash_senderid_hash.clone())
                .or_default()
                .push(fingerprint);
        }
    }
    Ok(())
}

/// Führt eine vollständige Double-Spend-Prüfung durch, indem eigene und fremde
/// Fingerprints kombiniert und auf Kollisionen geprüft werden.
pub fn check_for_double_spend(fingerprint_store: &FingerprintStore) -> DoubleSpendCheckResult {
    let mut result = DoubleSpendCheckResult::default();
    let mut all_fingerprints: HashMap<String, Vec<TransactionFingerprint>> =
        fingerprint_store.own_fingerprints.clone();

    for (hash, fps) in &fingerprint_store.foreign_fingerprints {
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
            if fingerprint_store.own_fingerprints.contains_key(&hash) {
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
/// * `voucher_store` - Der veränderbare Gutscheinspeicher des Wallets.
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
pub fn verify_conflict_and_create_proof(
    voucher_store: &VoucherStore,
    identity: &UserIdentity,
    _conflict_hash: &str,
    fingerprints: &[TransactionFingerprint],
    archive: &impl VoucherArchive,
) -> Result<Option<ProofOfDoubleSpend>, VoucherCoreError> {
    let mut conflicting_transactions = Vec::new();

    // 1. Finde die vollständigen Transaktionen zu den Fingerprints.
    for fp in fingerprints {
        if let Some(tx) = find_transaction_in_stores(voucher_store, &fp.t_id, archive)? {
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
            "t_id": &tx.t_id
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
    let voucher = find_voucher_for_transaction(voucher_store, &conflicting_transactions[0].t_id, archive)?
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
        layer2_verdict: None,
    };

    Ok(Some(proof))
}

/// Sucht eine Transaktion anhand ihrer ID (`t_id`) zuerst im aktiven
/// `voucher_store` und dann im `VoucherArchive`.
fn find_transaction_in_stores(
    voucher_store: &VoucherStore,
    t_id: &str,
    archive: &impl VoucherArchive,
) -> Result<Option<Transaction>, VoucherCoreError> {
    // Zuerst im aktiven Store suchen
    for (voucher, _) in voucher_store.vouchers.values() {
        if let Some(tx) = voucher.transactions.iter().find(|t| t.t_id == t_id) {
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
    voucher_store: &VoucherStore,
    t_id: &str,
    archive: &impl VoucherArchive,
) -> Result<Option<Voucher>, VoucherCoreError> {
    // Zuerst im aktiven Store suchen
    for (voucher, _) in voucher_store.vouchers.values() {
        if voucher.transactions.iter().any(|t| t.t_id == t_id) {
            return Ok(Some(voucher.clone()));
        }
    }

    // Danach im Archiv suchen
    Ok(archive.find_voucher_by_tx_id(t_id)?)
}

/// Entfernt alle abgelaufenen Fingerprints aus dem Speicher.
pub fn cleanup_expired_fingerprints(fingerprint_store: &mut FingerprintStore) {
    let now = get_current_timestamp();
    fingerprint_store.own_fingerprints.retain(|_, fps| {
        fps.retain(|fp| fp.valid_until > now);
        !fps.is_empty()
    });
    fingerprint_store.foreign_fingerprints.retain(|_, fps| {
        fps.retain(|fp| fp.valid_until > now);
        !fps.is_empty()
    });
}

/// Serialisiert die eigenen Fingerprints für den Export.
pub fn export_own_fingerprints(
    fingerprint_store: &FingerprintStore,
) -> Result<Vec<u8>, VoucherCoreError> {
    Ok(serde_json::to_vec(
        &fingerprint_store.own_fingerprints,
    )?)
}

/// Importiert und merged fremde Fingerprints in den Speicher.
pub fn import_foreign_fingerprints(
    fingerprint_store: &mut FingerprintStore,
    data: &[u8],
) -> Result<usize, VoucherCoreError> {
    let incoming: HashMap<String, Vec<TransactionFingerprint>> = serde_json::from_slice(data)?;
    let mut new_count = 0;
    for (hash, fps) in incoming {
        let entry = fingerprint_store
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


/// Verschlüsselt den Zeitstempel einer Transaktion für die Verwendung in einem L2-Kontext.
///
/// Die Verschlüsselung erfolgt via XOR mit einem Schlüssel, der deterministisch aus der
/// Transaktion selbst abgeleitet wird. Dies stellt sicher, dass jeder, der die
/// widersprüchlichen Transaktionen besitzt, den Zeitstempel entschlüsseln kann.
///
/// # Arguments
/// * `transaction` - Die Transaktion, deren Zeitstempel verschlüsselt werden soll.
///
/// # Returns
/// Ein `u128` Wert, der den verschlüsselten Zeitstempel in Nanosekunden darstellt.
pub fn encrypt_transaction_timestamp(transaction: &Transaction) -> Result<u128, VoucherCoreError> {
    // a. Zeitstempel parsen und in Nanosekunden (u128) umwandeln.
    let nanos = DateTime::parse_from_rfc3339(&transaction.t_time)
        .map_err(|e| VoucherCoreError::Generic(format!("Failed to parse timestamp: {}", e)))?
        .timestamp_nanos_opt()
        .ok_or_else(|| VoucherCoreError::Generic("Invalid timestamp for nanosecond conversion".to_string()))? as u128;

    // b. Schlüssel (u128) aus dem Hash von prev_hash und t_id ableiten.
    let key_material = format!("{}{}", transaction.prev_hash, transaction.t_id);
    let key_hash_b58 = get_hash(key_material);
    let key_hash_bytes = bs58::decode(key_hash_b58)
        .into_vec()
        .map_err(|_| VoucherCoreError::Generic("Failed to decode base58 hash for key derivation".to_string()))?;

    // Wir nehmen die ersten 16 Bytes (128 Bits) des Hashes als Schlüssel.
    let key_bytes: [u8; 16] = key_hash_bytes[..16].try_into()
        .map_err(|_| VoucherCoreError::Generic("Hash too short for key derivation".to_string()))?;
    let key = u128::from_le_bytes(key_bytes);

    // c. Zeitstempel via XOR verschlüsseln und zurückgeben.
    Ok(nanos ^ key)
}

/// Entschlüsselt den Zeitstempel einer Transaktion, der mit `encrypt_transaction_timestamp`
/// verschlüsselt wurde.
///
/// Da die Verschlüsselung auf XOR basiert, ist die Entschlüsselungsfunktion identisch.
///
/// # Arguments
/// * `transaction` - Die Transaktion, zu der der Zeitstempel gehört.
/// * `encrypted_nanos` - Der verschlüsselte Zeitstempel in Nanosekunden (`u128`).
///
/// # Returns
/// Der ursprüngliche, entschlüsselte Zeitstempel in Nanosekunden.
pub fn decrypt_transaction_timestamp(transaction: &Transaction, encrypted_nanos: u128) -> Result<u128, VoucherCoreError> {
    let key_material = format!("{}{}", transaction.prev_hash, transaction.t_id);
    let key_hash_b58 = get_hash(key_material);
    let key_hash_bytes = bs58::decode(key_hash_b58)
        .into_vec()
        .map_err(|_| VoucherCoreError::Generic("Failed to decode base58 hash for key derivation".to_string()))?;

    let key_bytes: [u8; 16] = key_hash_bytes[..16].try_into()
        .map_err(|_| VoucherCoreError::Generic("Hash too short for key derivation".to_string()))?;
    let key = u128::from_le_bytes(key_bytes);

    Ok(encrypted_nanos ^ key)
}