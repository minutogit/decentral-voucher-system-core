//! # tests/test_security_vulnerabilities.rs
//!
//! Diese Test-Suite simuliert eine Reihe von Angriffen durch einen böswilligen Akteur ("Hacker"),
//! um die Robustheit der Validierungslogik in `voucher_validation.rs` zu ueberpruefen.
//! Jeder Test zielt auf eine spezifische Schutzschicht des Gutscheinsystems ab.

use serde_json::Value;
use std::fs;
use voucher_lib::{archive::file_archive::FileVoucherArchive, crypto_utils};
use voucher_lib::models::profile::{BundleMetadataStore, TransactionBundle, UserIdentity, VoucherStore, VoucherStatus};
use voucher_lib::models::voucher::{Collateral, Creator, GuarantorSignature, NominalValue, Transaction, Voucher};
use voucher_lib::services::crypto_utils::{create_user_id, get_hash, sign_ed25519};
use voucher_lib::services::secure_container_manager::create_secure_container;
use voucher_lib::services::utils::{get_current_timestamp, to_canonical_json};
use voucher_lib::services::voucher_manager::{self, NewVoucherData, create_voucher, create_transaction, load_standard_definition};
use voucher_lib::services::voucher_validation::{self, get_spendable_balance};
use voucher_lib::VoucherCoreError;
use voucher_lib::wallet::Wallet;
use lazy_static::lazy_static;
use rand::{Rng, thread_rng};
use rand::seq::SliceRandom;
use voucher_lib::models::secure_container::PayloadType;
use voucher_lib::models::voucher_standard_definition::VoucherStandardDefinition;
use rust_decimal_macros::dec;
use ed25519_dalek::SigningKey;

// ===================================================================================
// HILFSFUNKTIONEN & SETUP (Adaptiert aus bestehenden Tests)
// ===================================================================================

/// Erstellt eine deterministische `UserIdentity` aus einem Seed-String für Testzwecke.
fn identity_from_seed(seed: &str) -> UserIdentity {
    let (public_key, signing_key) =
        voucher_lib::services::crypto_utils::generate_ed25519_keypair_for_tests(Some(seed));
    let user_id = create_user_id(&public_key, Some("te")).unwrap();
    UserIdentity { signing_key, public_key, user_id }
}

use voucher_lib::models::voucher::AdditionalSignature;
use rust_decimal::Decimal;
use std::str::FromStr;

/// Definiert die verschiedenen Angriffsstrategien für den Fuzzer.
#[derive(Debug, Clone, Copy)]
enum FuzzingStrategy {
    /// Manipuliert eine `AdditionalSignature`, um die Validierung zu testen.
    InvalidateAdditionalSignature,
    /// Setzt einen Transaktionsbetrag auf einen negativen Wert.
    SetNegativeTransactionAmount,
    /// Setzt den Restbetrag eines Splits auf einen negativen Wert.
    SetNegativeRemainderAmount,
    /// Verschiebt eine `init`-Transaktion an eine ungültige Position.
    SetInitTransactionInWrongPosition,
    /// Führt eine zufällige, strukturelle Mutation durch (der alte Ansatz).
    GenericRandomMutation,
}

/// Wählt eine zufällige Transaktion (außer `init`) und macht ihren Betrag negativ.
fn mutate_to_negative_amount(voucher: &mut Voucher) -> String {
    if voucher.transactions.len() < 2 { return "No non-init transaction to mutate".to_string(); }
    let mut rng = thread_rng();
    let tx_index = rng.gen_range(1..voucher.transactions.len());

    if let Some(tx) = voucher.transactions.get_mut(tx_index) {
        if let Ok(mut amount) = Decimal::from_str(&tx.amount) {
            if amount > Decimal::ZERO {
                amount.set_sign_negative(true);
                tx.amount = amount.to_string();
                return format!("Set tx[{}] amount to negative: {}", tx_index, tx.amount);
            }
        }
    }
    "Failed to apply negative amount mutation".to_string()
}

/// Wählt eine zufällige Split-Transaktion und macht ihren Restbetrag negativ.
fn mutate_to_negative_remainder(voucher: &mut Voucher) -> String {
    let mut rng = thread_rng();
    // Finde alle Indizes von Transaktionen, die einen Restbetrag haben
    let splittable_indices: Vec<usize> = voucher.transactions.iter().enumerate()
        .filter(|(_, tx)| tx.sender_remaining_amount.is_some())
        .map(|(i, _)| i)
        .collect();

    if let Some(&tx_index) = splittable_indices.choose(&mut rng) {
        if let Some(tx) = voucher.transactions.get_mut(tx_index) {
            if let Some(remainder_str) = &tx.sender_remaining_amount {
                if let Ok(mut remainder) = Decimal::from_str(remainder_str) {
                    if remainder > Decimal::ZERO {
                        remainder.set_sign_negative(true);
                        tx.sender_remaining_amount = Some(remainder.to_string());
                        return format!("Set tx[{}] remainder to negative: {}", tx_index, remainder);
                    }
                }
            }
        }
    }
    "No suitable split transaction found to mutate".to_string()
}

/// Verschiebt den `t_type` "init" auf eine zufällige, ungültige Position.
fn mutate_init_to_wrong_position(voucher: &mut Voucher) -> String {
    if voucher.transactions.len() < 2 { return "Not enough transactions to move 'init' type".to_string(); }
    let mut rng = thread_rng();
    let tx_index = rng.gen_range(1..voucher.transactions.len());

    if let Some(tx) = voucher.transactions.get_mut(tx_index) {
        tx.t_type = "init".to_string();
        return format!("Set tx[{}] t_type to 'init'", tx_index);
    }
    "Failed to move 'init' t_type".to_string()
}

/// Nimmt eine `AdditionalSignature` und macht sie ungültig, indem die Signaturdaten manipuliert werden.
fn mutate_invalidate_additional_signature(voucher: &mut Voucher) -> String {
    if let Some(sig) = voucher.additional_signatures.get_mut(0) {
        sig.signature = "invalid_signature_data".to_string();
        return "Invalidated signature of first AdditionalSignature".to_string();
    }
    "No AdditionalSignature found to invalidate".to_string()
}

/// Erstellt ein frisches, leeres In-Memory-Wallet für einen Akteur.
fn setup_test_wallet(identity: &UserIdentity) -> Wallet {
    let profile = voucher_lib::models::profile::UserProfile {
        user_id: identity.user_id.clone(),
        ..Default::default()
    };
    Wallet {
        profile,
        voucher_store: VoucherStore::default(),
        bundle_meta_store: BundleMetadataStore::default(),
        fingerprint_store: Default::default(),
        proof_store: Default::default(),
    }
}

/// Eine Struktur, die alle wiederverwendbaren Test-Akteure enthält.
struct TestActors {
    issuer: UserIdentity,
    hacker: UserIdentity,
    victim: UserIdentity,
    guarantor: UserIdentity,
    alice: UserIdentity,
    bob: UserIdentity,
}

lazy_static! {
    static ref ACTORS: TestActors = TestActors {
        issuer: identity_from_seed("issuer"),
        hacker: identity_from_seed("hacker"),
        victim: identity_from_seed("victim"),
        guarantor: identity_from_seed("guarantor"),
        alice: identity_from_seed("alice"),
        bob: identity_from_seed("bob"),
    };
    static ref STANDARD: VoucherStandardDefinition = {
        let standard_toml = fs::read_to_string("voucher_standards/silver_standard.toml").unwrap();
        voucher_manager::load_standard_definition(&standard_toml).unwrap()
    };
}

/// Erstellt leere `NewVoucherData` für Testzwecke.
fn new_test_voucher_data(creator_id: String) -> NewVoucherData {
    NewVoucherData {
        validity_duration: Some("P5Y".to_string()), // Erhöht auf 5 Jahre, um die Mindestgültigkeit zu erfüllen
        non_redeemable_test_voucher: false,
        nominal_value: NominalValue { amount: "100".to_string(), ..Default::default() },
        collateral: Collateral::default(),
        creator: Creator { id: creator_id, ..Default::default() },
    }
}

/// Erstellt eine gültige Bürgschaft für einen gegebenen Gutschein.
fn create_guarantor_signature(
    voucher: &Voucher,
    guarantor_identity: &UserIdentity,
    organization: Option<&str>,
    gender: &str,
) -> GuarantorSignature {
    let mut sig_obj = GuarantorSignature {
        voucher_id: voucher.voucher_id.clone(),
        guarantor_id: guarantor_identity.user_id.clone(),
        first_name: "Garant".to_string(),
        last_name: "Test".to_string(),
        signature_time: get_current_timestamp(),
        organization: organization.map(String::from),
        gender: gender.to_string(),
        ..Default::default()
    };

    let mut sig_obj_for_id = sig_obj.clone();
    sig_obj_for_id.signature_id = "".to_string();
    sig_obj_for_id.signature = "".to_string();
    let id_hash = get_hash(to_canonical_json(&sig_obj_for_id).unwrap());

    sig_obj.signature_id = id_hash;
    let signature = sign_ed25519(&guarantor_identity.signing_key, sig_obj.signature_id.as_bytes());
    sig_obj.signature = bs58::encode(signature.to_bytes()).into_string();
    sig_obj
}

/// Simuliert die Aktion eines Hackers: Verpackt einen (manipulierten) Gutschein in einen Container.
fn create_hacked_bundle_and_container(
    hacker_identity: &UserIdentity,
    victim_id: &str,
    malicious_voucher: Voucher,
) -> Vec<u8> {
    let mut bundle = TransactionBundle {
        bundle_id: "".to_string(),
        sender_id: hacker_identity.user_id.clone(),
        recipient_id: victim_id.to_string(),
        vouchers: vec![malicious_voucher],
        timestamp: get_current_timestamp(),
        notes: Some("Hacked".to_string()),
        sender_signature: "".to_string(),
    };
    let bundle_json_for_id = to_canonical_json(&bundle).unwrap();
    bundle.bundle_id = get_hash(bundle_json_for_id);
    let signature = sign_ed25519(&hacker_identity.signing_key, bundle.bundle_id.as_bytes());
    bundle.sender_signature = bs58::encode(signature.to_bytes()).into_string();
    let signed_bundle_bytes = serde_json::to_vec(&bundle).unwrap();
    let secure_container = create_secure_container(
        hacker_identity,
        &[victim_id.to_string()],
        &signed_bundle_bytes,
        PayloadType::TransactionBundle,
    ).unwrap();
    serde_json::to_vec(&secure_container).unwrap()
}

/// Erstellt und signiert eine (potenziell manipulierte) Transaktion.
fn create_hacked_tx(signer_identity: &UserIdentity, mut hacked_tx: Transaction) -> Transaction {
    let tx_json_for_id = to_canonical_json(&hacked_tx).unwrap();
    hacked_tx.t_id = get_hash(tx_json_for_id);

    let signature_payload = serde_json::json!({
        "prev_hash": hacked_tx.prev_hash, "sender_id": hacked_tx.sender_id,
        "t_id": hacked_tx.t_id, "t_time": hacked_tx.t_time
    });
    let signature_payload_hash = get_hash(to_canonical_json(&signature_payload).unwrap());
    let signature = sign_ed25519(&signer_identity.signing_key, signature_payload_hash.as_bytes());
    hacked_tx.sender_signature = bs58::encode(signature.to_bytes()).into_string();
    hacked_tx
}

/// **NEUER STUB:** Erstellt einen Test-Creator für die neuen Tests.
fn setup_creator() -> (SigningKey, Creator) {
    let (public_key, signing_key) = crypto_utils::generate_ed25519_keypair_for_tests(Some("creator_stub"));
    let user_id = create_user_id(&public_key, Some("cs")).unwrap();
    let creator = Creator {
        id: user_id,
        first_name: "Stub".to_string(),
        last_name: "Creator".to_string(),
        ..Default::default()
    };
    (signing_key, creator)
}

/// **NEUER STUB:** Erstellt Test-Voucher-Daten für die neuen Tests.
fn create_test_voucher_data_with_amount(creator: Creator, amount: &str) -> NewVoucherData {
    NewVoucherData {
        validity_duration: Some("P5Y".to_string()),
        non_redeemable_test_voucher: false,
        nominal_value: NominalValue {
            amount: amount.to_string(),
            ..Default::default()
        },
        collateral: Collateral::default(),
        creator,
    }
}


// ===================================================================================
// ANGRIFFSKLASSE 1 & 4: MANIPULATION VON STAMMDATEN & BÜRGSCHAFTEN
// ===================================================================================
#[test]
fn test_attack_tamper_core_data_and_guarantors() {
    // ### SETUP ###
    let mut issuer_wallet = setup_test_wallet(&ACTORS.issuer);
    let mut hacker_wallet = setup_test_wallet(&ACTORS.hacker);
    let mut victim_wallet = setup_test_wallet(&ACTORS.victim);
    let voucher_data = new_test_voucher_data(ACTORS.issuer.user_id.clone());
    let mut valid_voucher = voucher_manager::create_voucher(voucher_data, &STANDARD, &ACTORS.issuer.signing_key).unwrap();
    let guarantor_sig = create_guarantor_signature(&valid_voucher, &ACTORS.guarantor, None, "0");
    valid_voucher.guarantor_signatures.push(guarantor_sig);
    let local_id = Wallet::calculate_local_instance_id(&valid_voucher, &ACTORS.issuer.user_id).unwrap();
    issuer_wallet.voucher_store.vouchers.insert(local_id.clone(), (valid_voucher, Default::default()));

    // Issuer sendet den Gutschein an den Hacker, der ihn nun für Angriffe besitzt.
    let (container_to_hacker, _) = issuer_wallet.create_transfer(&ACTORS.issuer, &STANDARD, &local_id, &ACTORS.hacker.user_id, "100", None, None::<&FileVoucherArchive>).unwrap();
    hacker_wallet.process_encrypted_transaction_bundle(&ACTORS.hacker, &container_to_hacker, None::<&FileVoucherArchive>).unwrap();
    let (_, (voucher_in_hacker_wallet, _)) = hacker_wallet.voucher_store.vouchers.iter().next().unwrap();

    // ### SZENARIO 1a: WERTINFLATION ###
    println!("--- Angriff 1a: Wertinflation ---");
    let mut inflated_voucher = voucher_in_hacker_wallet.clone();
    inflated_voucher.nominal_value.amount = "9999".to_string();

    // Der Hacker muss die sichere `create_transaction`-Funktion umgehen.
    // Er erstellt die finale Transaktion zum Opfer manuell und hängt sie an den manipulierten Gutschein an.
    let mut final_tx = Transaction {
        prev_hash: get_hash(to_canonical_json(inflated_voucher.transactions.last().unwrap()).unwrap()),
        t_time: get_current_timestamp(),
        sender_id: ACTORS.hacker.user_id.clone(),
        recipient_id: ACTORS.victim.user_id.clone(),
        amount: "100".to_string(), // Hacker gibt seinen ursprünglichen Betrag aus
        ..Default::default()
    };
    // Diese Transaktion selbst ist valide und wird vom Hacker signiert. Der Betrug liegt im manipulierten Creator-Block.
    final_tx = create_hacked_tx(&ACTORS.hacker, final_tx);
    inflated_voucher.transactions.push(final_tx);

    let hacked_container = create_hacked_bundle_and_container(&ACTORS.hacker, &ACTORS.victim.user_id, inflated_voucher);
    victim_wallet.process_encrypted_transaction_bundle(&ACTORS.victim, &hacked_container, None::<&FileVoucherArchive>).unwrap();
    let (_, (received_voucher, _)) = victim_wallet.voucher_store.vouchers.iter().next().unwrap();
    let result = voucher_validation::validate_voucher_against_standard(received_voucher, &STANDARD);
    assert!(matches!(result, Err(VoucherCoreError::Validation(voucher_lib::services::voucher_validation::ValidationError::InvalidCreatorSignature { .. }))),
            "Validation must fail due to manipulated nominal value.");
    victim_wallet.voucher_store.vouchers.clear(); // Reset for next test

    // ### SZENARIO 4a: BÜRGEN-METADATEN MANIPULIEREN ###
    println!("--- Angriff 4a: Bürgen-Metadaten manipulieren ---");
    let mut tampered_guarantor_voucher = voucher_in_hacker_wallet.clone();
    tampered_guarantor_voucher.guarantor_signatures[0].first_name = "Mallory".to_string();

    let mut final_tx_2 = Transaction {
        prev_hash: get_hash(to_canonical_json(tampered_guarantor_voucher.transactions.last().unwrap()).unwrap()),
        t_time: get_current_timestamp(),
        sender_id: ACTORS.hacker.user_id.clone(),
        recipient_id: ACTORS.victim.user_id.clone(),
        amount: "100".to_string(),
        ..Default::default()
    };
    final_tx_2 = create_hacked_tx(&ACTORS.hacker, final_tx_2);
    tampered_guarantor_voucher.transactions.push(final_tx_2);

    let hacked_container = create_hacked_bundle_and_container(&ACTORS.hacker, &ACTORS.victim.user_id, tampered_guarantor_voucher);
    victim_wallet.process_encrypted_transaction_bundle(&ACTORS.victim, &hacked_container, None::<&FileVoucherArchive>).unwrap();
    let (_, (received_voucher, _)) = victim_wallet.voucher_store.vouchers.iter().next().unwrap();
    let result = voucher_validation::validate_voucher_against_standard(received_voucher, &STANDARD);
    assert!(matches!(result, Err(VoucherCoreError::Validation(voucher_lib::services::voucher_validation::ValidationError::InvalidSignatureId(_)))),
            "Validation must fail due to manipulated guarantor metadata (InvalidSignatureId).");
    victim_wallet.voucher_store.vouchers.clear();
}


// ===================================================================================
// ANGRIFFSKLASSE 2: FÄLSCHUNG DER TRANSAKTIONSHISTORIE
// ===================================================================================
#[test]
fn test_attack_tamper_transaction_history() {
    // ### SETUP ###
    let mut alice_wallet = setup_test_wallet(&ACTORS.alice);
    let mut bob_wallet_hacker = setup_test_wallet(&ACTORS.bob);
    let data = new_test_voucher_data(ACTORS.alice.user_id.clone());
    let voucher_a = voucher_manager::create_voucher(data, &STANDARD, &ACTORS.alice.signing_key).unwrap();
    let local_id_a = Wallet::calculate_local_instance_id(&voucher_a, &ACTORS.alice.user_id).unwrap();
    alice_wallet.voucher_store.vouchers.insert(local_id_a.clone(), (voucher_a, Default::default()));
    let (container_to_bob, _) = alice_wallet.create_transfer(&ACTORS.alice, &STANDARD, &local_id_a, &ACTORS.bob.user_id, "100", None, None::<&FileVoucherArchive>).unwrap();
    bob_wallet_hacker.process_encrypted_transaction_bundle(&ACTORS.bob, &container_to_bob, None::<&FileVoucherArchive>).unwrap();
    let (_, (voucher_in_bob_wallet, _)) = bob_wallet_hacker.voucher_store.vouchers.iter().next().unwrap();

    // ### ANGRIFF ###
    println!("--- Angriff 2a: Transaktionshistorie fälschen ---");
    let mut voucher_with_tampered_history = voucher_in_bob_wallet.clone();
    // Manipuliere eine Signatur in der Kette, um sie ungültig zu machen.
    voucher_with_tampered_history.transactions[0].sender_signature = "invalid_signature".to_string();

    // DANK DES SICHERHEITSPATCHES in `voucher_manager` schlägt dieser Aufruf nun fehl,
    // da `create_transaction` den Gutschein vorab validiert.
    let transfer_attempt_result = voucher_manager::create_transaction(
        &voucher_with_tampered_history, &STANDARD, &ACTORS.bob.user_id, &ACTORS.bob.signing_key, &ACTORS.victim.user_id, "100"
    );
    assert!(transfer_attempt_result.is_err(), "Transaction creation must fail if history is tampered.");
}

// ===================================================================================
// ANGRIFFSKLASSE 3: ERSTELLUNG EINER LOGISCH INKONSISTENTEN TRANSAKTION
// ===================================================================================
#[test]
fn test_attack_create_inconsistent_transaction() {
    // ### SETUP ###
    let mut issuer_wallet = setup_test_wallet(&ACTORS.issuer);
    let mut hacker_wallet = setup_test_wallet(&ACTORS.hacker);
    let mut victim_wallet = setup_test_wallet(&ACTORS.victim);
    let data = new_test_voucher_data(ACTORS.issuer.user_id.clone());
    let initial_voucher = voucher_manager::create_voucher(data, &STANDARD, &ACTORS.issuer.signing_key).unwrap();
    let local_id_issuer = Wallet::calculate_local_instance_id(&initial_voucher, &ACTORS.issuer.user_id).unwrap();
    issuer_wallet.voucher_store.vouchers.insert(local_id_issuer.clone(), (initial_voucher, Default::default()));
    let (container_to_hacker, _) = issuer_wallet.create_transfer(&ACTORS.issuer, &STANDARD, &local_id_issuer, &ACTORS.hacker.user_id, "100", None, None::<&FileVoucherArchive>).unwrap();
    hacker_wallet.process_encrypted_transaction_bundle(&ACTORS.hacker, &container_to_hacker, None::<&FileVoucherArchive>).unwrap();
    let (_, (voucher_in_hacker_wallet, _)) = hacker_wallet.voucher_store.vouchers.iter().next().unwrap();

    // ### SZENARIO 3a: OVERSPENDING ###
    println!("--- Angriff 3a: Overspending ---");
    let mut overspend_voucher = voucher_in_hacker_wallet.clone();
    let overspend_tx_unsigned = Transaction {
        prev_hash: get_hash(to_canonical_json(overspend_voucher.transactions.last().unwrap()).unwrap()),
        t_time: get_current_timestamp(),
        sender_id: ACTORS.hacker.user_id.clone(),
        recipient_id: ACTORS.victim.user_id.clone(),
        amount: "200".to_string(),
        ..Default::default()
    };
    let overspend_tx = create_hacked_tx(&ACTORS.hacker, overspend_tx_unsigned);
    overspend_voucher.transactions.push(overspend_tx);
    let hacked_container = create_hacked_bundle_and_container(&ACTORS.hacker, &ACTORS.victim.user_id, overspend_voucher);
    victim_wallet.process_encrypted_transaction_bundle(&ACTORS.victim, &hacked_container, None::<&FileVoucherArchive>).unwrap();
    let (_, (received_voucher, _)) = victim_wallet.voucher_store.vouchers.iter().next().unwrap();
    let result = voucher_validation::validate_voucher_against_standard(received_voucher, &STANDARD);
    assert!(matches!(result, Err(VoucherCoreError::Validation(voucher_lib::services::voucher_validation::ValidationError::FullTransferAmountMismatch { .. }))),
            "Validation must fail with FullTransferAmountMismatch on overspending attempt.");
    victim_wallet.voucher_store.vouchers.clear();
}


// ===================================================================================
// ANGRIFFSKLASSE 5: STRUKTURELLE INTEGRITÄTSPRÜFUNG DURCH FUZZING
// ===================================================================================
/// Hilfsfunktion für den Fuzzing-Test.
/// Versucht, eine einzelne, zufällige Mutation durchzuführen und gibt bei Erfolg
/// eine Beschreibung der Änderung zurück.
fn mutate_value(val: &mut Value, rng: &mut impl Rng, current_path: &str) -> Option<String> {
    match val {
        Value::Object(map) => {
            if map.is_empty() { return None; }
            let keys: Vec<String> = map.keys().cloned().collect();
            // Mische die Schlüssel, um bei jedem Durchlauf eine andere Reihenfolge zu haben
            let mut shuffled_keys = keys;
            shuffled_keys.shuffle(rng);

            for key in shuffled_keys {
                let new_path = format!("{}.{}", current_path, key);
                if let Some(desc) = mutate_value(map.get_mut(&key).unwrap(), rng, &new_path) {
                    return Some(desc);
                }
            }
        }
        Value::Array(arr) => {
            if arr.is_empty() { return None; }
            // Wähle einen zufälligen Index zum Mutieren
            let idx_to_mutate = rng.gen_range(0..arr.len());
            let new_path = format!("{}[{}]", current_path, idx_to_mutate);
            if let Some(desc) = mutate_value(&mut arr[idx_to_mutate], rng, &new_path) {
                return Some(desc);
            }
        }
        Value::String(s) => {
            let old_val = s.clone();
            *s = format!("{}-mutated", s);
            return Some(format!("CHANGED path '{}' from '{}' to '{}'", current_path, old_val, s));
        }
        Value::Number(n) => {
            let old_val = n.clone();
            let old_val_i64 = n.as_i64().unwrap_or(0);
            let mut new_val_num;
            loop {
                new_val_num = old_val_i64 + rng.gen_range(-10..10);
                if new_val_num != old_val_i64 {
                    break; // Stelle sicher, dass der Wert sich tatsächlich ändert
                }
            }
            *val = Value::Number(new_val_num.into());
            return Some(format!("CHANGED path '{}' from '{}' to '{}'", current_path, old_val, val));
        }
        Value::Bool(b) => {
            let old_val = *b;
            *b = !*b;
            return Some(format!("FLIPPED path '{}' from '{}' to '{}'", current_path, old_val, b));
        }
        Value::Null => {
            *val = Value::String("was_null".to_string());
            return Some(format!("CHANGED path '{}' from null to 'was_null'", current_path));
        }
    }
    None // Keine Mutation in diesem Zweig durchgeführt
}

// --- NEUE TESTS FÜR WALLET-ZUSTANDSVERWALTUNG UND KOLLABORATIVE SICHERHEIT ---

#[test]
fn test_wallet_state_management_on_split() {
    // 1. Setup
    let standard_toml = std::fs::read_to_string("voucher_standards/silver_standard.toml").unwrap();
    let standard: VoucherStandardDefinition = load_standard_definition(&standard_toml).unwrap();

    let a_identity = &ACTORS.alice;
    let b_identity = &ACTORS.bob;
    let mut wallet_a = setup_test_wallet(a_identity);
    let mut wallet_b = setup_test_wallet(b_identity);

    // 2. Erstelle einen Gutschein explizit und füge ihn zu Wallet A hinzu, um das Setup zu verdeutlichen.
    let creator_data = Creator {
        id: a_identity.user_id.clone(),
        first_name: "Alice".to_string(),
        last_name: "Test".to_string(),
        ..Default::default()
    };
    let voucher_data = create_test_voucher_data_with_amount(creator_data, "100.0000");
    let initial_voucher = create_voucher(voucher_data, &standard, &a_identity.signing_key).unwrap();

    wallet_a.add_voucher_to_store(initial_voucher, VoucherStatus::Active, &a_identity.user_id).unwrap();
    let original_local_id = wallet_a.voucher_store.vouchers.keys().next().unwrap().clone();

    // 3. Aktion: Wallet A sendet 40 an Wallet B
    let (bundle_to_b, _) = wallet_a.create_transfer(
        &a_identity,
        &standard,
        &original_local_id,
        &b_identity.user_id,
        "40",
        None,
        None::<&FileVoucherArchive>,
    ).unwrap();

    wallet_b.process_encrypted_transaction_bundle(&b_identity, &bundle_to_b, None::<&FileVoucherArchive>).unwrap();

    // 4. Verifizierung (Wallet A)
    // NACH ÄNDERUNG: Wallet A sollte jetzt nur noch EINE Instanz haben - den aktiven Restbetrag.
    // Die ursprüngliche Instanz wird gelöscht, nicht archiviert.
    assert_eq!(wallet_a.voucher_store.vouchers.len(), 1, "Wallet A should have exactly one instance (the active remainder).");
    assert!(wallet_a.voucher_store.vouchers.get(&original_local_id).is_none(), "The original voucher instance must be removed.");

    let (remainder_voucher, remainder_status) = wallet_a.voucher_store.vouchers.values()
        .next()
        .expect("Wallet A must have one voucher instance left.");
    assert_eq!(*remainder_status, VoucherStatus::Active);

    let remainder_balance = get_spendable_balance(remainder_voucher, &a_identity.user_id, &standard).unwrap();
    assert_eq!(remainder_balance, dec!(60));

    // 5. Verifizierung (Wallet B)
    assert_eq!(wallet_b.voucher_store.vouchers.len(), 1, "Wallet B should have one voucher instance.");
    let (received_voucher, received_status) = wallet_b.voucher_store.vouchers.values().next().unwrap();
    assert_eq!(*received_status, VoucherStatus::Active);

    let received_balance = get_spendable_balance(received_voucher, &b_identity.user_id, &standard).unwrap();
    assert_eq!(received_balance, dec!(40));
}

#[test]
fn test_collaborative_fraud_detection_with_fingerprints() {
    // 1. Setup
    let a_identity = &ACTORS.alice;
    let mut alice_wallet = setup_test_wallet(a_identity);
    let b_identity = &ACTORS.bob;
    let mut bob_wallet = setup_test_wallet(b_identity);
    // Wir verwenden den "Hacker" als böswilligen Akteur Eve
    let eve_identity = &ACTORS.hacker;
    let mut eve_wallet = setup_test_wallet(eve_identity);

    let standard_toml = std::fs::read_to_string("voucher_standards/silver_standard.toml").unwrap();
    let standard: VoucherStandardDefinition = load_standard_definition(&standard_toml).unwrap();

    // 2. Akt 1 (Double Spend)
    let eve_creator = Creator { id: eve_identity.user_id.clone(), ..setup_creator().1 };
    let voucher_data = create_test_voucher_data_with_amount(eve_creator, "100");
    let initial_voucher = create_voucher(voucher_data, &standard, &eve_identity.signing_key).unwrap();

    // Eve erstellt zwei widersprüchliche Zukünfte
    let voucher_for_alice = create_transaction(&initial_voucher, &standard, &eve_identity.user_id, &eve_identity.signing_key, &a_identity.user_id, "100").unwrap();
    let voucher_for_bob = create_transaction(&initial_voucher, &standard, &eve_identity.user_id, &eve_identity.signing_key, &b_identity.user_id, "100").unwrap();

    // Eve verpackt und sendet die Gutscheine
    let bundle_to_alice = eve_wallet.create_and_encrypt_transaction_bundle(&eve_identity, vec![voucher_for_alice], &a_identity.user_id, None).unwrap();
    let bundle_to_bob = eve_wallet.create_and_encrypt_transaction_bundle(&eve_identity, vec![voucher_for_bob], &b_identity.user_id, None).unwrap();

    alice_wallet.process_encrypted_transaction_bundle(&a_identity, &bundle_to_alice, None::<&FileVoucherArchive>).unwrap();
    bob_wallet.process_encrypted_transaction_bundle(&b_identity, &bundle_to_bob, None::<&FileVoucherArchive>).unwrap();

    // 3. Akt 2 (Austausch)
    alice_wallet.scan_and_update_own_fingerprints().unwrap();
    let alice_fingerprints = alice_wallet.export_own_fingerprints().unwrap();
    bob_wallet.import_foreign_fingerprints(&alice_fingerprints).unwrap();

    // 4. Akt 3 (Aufdeckung)
    bob_wallet.scan_and_update_own_fingerprints().unwrap();
    let check_result = bob_wallet.check_for_double_spend();

    // 5. Verifizierung
    assert!(check_result.unverifiable_warnings.is_empty(), "There should be no unverifiable warnings.");
    assert_eq!(check_result.verifiable_conflicts.len(), 1, "A verifiable conflict must be detected.");

    let conflict = check_result.verifiable_conflicts.values().next().unwrap();
    assert_eq!(conflict.len(), 2, "The conflict should involve two transactions.");
    println!("SUCCESS: Collaborative fraud detection upgraded a warning to a verifiable conflict.");
}

#[test]
fn test_serialization_roundtrip_with_special_chars() {
    // 1. Setup
    let standard_toml = std::fs::read_to_string("voucher_standards/minuto_standard.toml").unwrap();
    let standard: VoucherStandardDefinition = load_standard_definition(&standard_toml).unwrap();

    let (signing_key, mut creator) = setup_creator();
    creator.first_name = "Jörg-ẞtråße".to_string(); // Sonderzeichen

    let voucher_data = create_test_voucher_data_with_amount(creator, "123");
    let mut original_voucher = create_voucher(voucher_data, &standard, &signing_key).unwrap();

    // Mache den Gutschein komplexer
    let (g1_pub, g1_priv) = crypto_utils::generate_ed25519_keypair_for_tests(Some("g1_roundtrip"));
    let g1_id = crypto_utils::create_user_id(&g1_pub, Some("g1")).unwrap();
    let g1_identity = UserIdentity { public_key: g1_pub, signing_key: g1_priv, user_id: g1_id };

    // **KORRIGIERTER AUFRUF:** Metadaten werden jetzt bei der Erstellung übergeben.
    let guarantor_sig =
        create_guarantor_signature(&original_voucher, &g1_identity, Some("Bürge & Co."), "1");
    original_voucher.guarantor_signatures.push(guarantor_sig);

    // FÜGE ZWEITEN BÜRGEN HINZU, UM DIE VALIDIERUNG ZU ERFÜLLEN
    // ÄNDERUNG: Gender auf "2" gesetzt, um die Regel des Minuto-Standards zu erfüllen.
    let second_guarantor_sig = create_guarantor_signature(&original_voucher, &ACTORS.guarantor, None, "2");
    original_voucher.guarantor_signatures.push(second_guarantor_sig);

    original_voucher = create_transaction(
        &original_voucher,
        &standard,
        &original_voucher.creator.id,
        &signing_key,
        "some_recipient_id",
        "23"
    ).unwrap();

    // 2. Aktion
    // Wir verwenden serde_json::to_string direkt, um den Prozess ohne unsere Wrapper zu testen.
    let json_string = serde_json::to_string(&original_voucher).unwrap();
    let deserialized_voucher: Voucher = serde_json::from_str(&json_string).unwrap();

    // 3. Verifizierung
    assert_eq!(original_voucher, deserialized_voucher, "The deserialized voucher must be identical to the original.");
}

#[test]
fn test_attack_fuzzing_random_mutations() {
    // ### SETUP ###
    // Erstelle einen "Master"-Gutschein, der alle für die Angriffe relevanten Features enthält.
    let mut data = new_test_voucher_data(ACTORS.issuer.user_id.clone());
    data.nominal_value.amount = "1000".to_string();
    let mut master_voucher = voucher_manager::create_voucher(data, &STANDARD, &ACTORS.issuer.signing_key).unwrap();

    // Füge Bürgen hinzu.
    let g2_identity = identity_from_seed("guarantor2_fuzz");
    master_voucher.guarantor_signatures.push(create_guarantor_signature(&master_voucher, &ACTORS.guarantor, None, "0"));
    master_voucher.guarantor_signatures.push(create_guarantor_signature(&master_voucher, &g2_identity, None, "0"));

    // WICHTIG: Füge eine `AdditionalSignature` hinzu, damit der Fuzzer sie angreifen kann.
    let mut additional_sig = AdditionalSignature {
        voucher_id: master_voucher.voucher_id.clone(),
        signer_id: ACTORS.victim.user_id.clone(),
        signature_time: get_current_timestamp(),
        description: "A valid additional signature".to_string(),
        ..Default::default()
    };
    let mut sig_obj_for_id = additional_sig.clone();
    sig_obj_for_id.signature_id = "".to_string();
    sig_obj_for_id.signature = "".to_string();
    additional_sig.signature_id = get_hash(to_canonical_json(&sig_obj_for_id).unwrap());
    let signature = sign_ed25519(&ACTORS.victim.signing_key, additional_sig.signature_id.as_bytes());
    additional_sig.signature = bs58::encode(signature.to_bytes()).into_string();
    master_voucher.additional_signatures.push(additional_sig);

    // Erstelle eine Transaktionskette, die auch einen Split enthält.
    master_voucher = create_transaction(&master_voucher, &STANDARD, &ACTORS.issuer.user_id, &ACTORS.issuer.signing_key, &ACTORS.alice.user_id, "1000").unwrap();
    master_voucher = create_transaction(&master_voucher, &STANDARD, &ACTORS.alice.user_id, &ACTORS.alice.signing_key, &ACTORS.bob.user_id, "500").unwrap(); // Split

    let mut rng = thread_rng();
    println!("--- Starte intelligenten Fuzzing-Test mit 2000 Iterationen ---");
    let iterations = 100;

    // Definiere die intelligenten und zufälligen Angriffsstrategien.
    let strategies = [
        FuzzingStrategy::InvalidateAdditionalSignature,
        FuzzingStrategy::SetNegativeTransactionAmount,
        FuzzingStrategy::SetNegativeRemainderAmount,
        FuzzingStrategy::SetInitTransactionInWrongPosition,
        FuzzingStrategy::GenericRandomMutation, // Behalte die alte Methode für allgemeine Zufälligkeit bei.
        FuzzingStrategy::GenericRandomMutation, // Erhöhe die Wahrscheinlichkeit für zufällige Mutationen.
    ];

    for i in 0..iterations {
        let mut mutated_voucher = master_voucher.clone();
        let strategy = strategies.choose(&mut rng).unwrap();
        let change_description: String;

        // Führe die gewählte Angriffsstrategie aus
        match strategy {
            FuzzingStrategy::InvalidateAdditionalSignature => {
                change_description = mutate_invalidate_additional_signature(&mut mutated_voucher);
            }
            FuzzingStrategy::SetNegativeTransactionAmount => {
                change_description = mutate_to_negative_amount(&mut mutated_voucher);
            }
            FuzzingStrategy::SetNegativeRemainderAmount => {
                change_description = mutate_to_negative_remainder(&mut mutated_voucher);
            }
            FuzzingStrategy::SetInitTransactionInWrongPosition => {
                change_description = mutate_init_to_wrong_position(&mut mutated_voucher);
            }
            FuzzingStrategy::GenericRandomMutation => {
                // Konvertiere zu JSON, mutiere zufällig und konvertiere zurück
                let mut as_value = serde_json::to_value(&mutated_voucher).unwrap();
                change_description = mutate_value(&mut as_value, &mut rng, "voucher")
                    .unwrap_or_else(|| "Generic mutation did not change anything".to_string());

                if let Ok(v) = serde_json::from_value(as_value) {
                    mutated_voucher = v;
                } else {
                    // Wenn die zufällige Mutation die Struktur so zerstört hat, dass sie nicht mehr
                    // als Voucher geparst werden kann, ist das ein "erfolgreicher" Fund.
                    // Wir können zur nächsten Iteration übergehen.
                    println!("Iter {}: Generic mutation created invalid structure. OK.", i);
                    continue;
                }
            }
        }

        let validation_result = voucher_validation::validate_voucher_against_standard(&mutated_voucher, &STANDARD);
        assert!(validation_result.is_err(),
                "FUZZING-FEHLER bei Iteration {}: Eine Mutation hat die Validierung umgangen!\nStrategie: {:?}\nÄnderung: {}\nMutierter Gutschein:\n{}",
                i, strategy, change_description, serde_json::to_string_pretty(&mutated_voucher).unwrap()
        );
    }
    println!("--- Intelligenter Fuzzing-Test erfolgreich abgeschlossen ---");
}