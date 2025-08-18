//! # tests/test_security_vulnerabilities.rs
//!
//! Diese Test-Suite simuliert eine Reihe von Angriffen durch einen böswilligen Akteur ("Hacker"),
//! um die Robustheit der Validierungslogik in `voucher_validation.rs` zu ueberpruefen.
//! Jeder Test zielt auf eine spezifische Schutzschicht des Gutscheinsystems ab.

use serde_json::Value;
use std::fs;
use voucher_lib::{archive::file_archive::FileVoucherArchive, crypto_utils};
use voucher_lib::models::profile::{BundleMetadataStore, TransactionBundle, UserIdentity, VoucherStore};
use voucher_lib::models::voucher::{Collateral, Creator, GuarantorSignature, NominalValue, Transaction, Voucher};
use voucher_lib::services::crypto_utils::{create_user_id, get_hash, sign_ed25519};
use voucher_lib::services::secure_container_manager::create_secure_container;
use voucher_lib::services::utils::{get_current_timestamp, to_canonical_json};
use voucher_lib::services::voucher_manager::{self, NewVoucherData};
use voucher_lib::services::voucher_validation;
use voucher_lib::VoucherCoreError;
use voucher_lib::wallet::Wallet;
use lazy_static::lazy_static;
use rand::{Rng, thread_rng};
use rand::seq::SliceRandom;
use voucher_lib::models::secure_container::PayloadType;
use voucher_lib::models::voucher_standard_definition::VoucherStandardDefinition;

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
fn create_guarantor_signature(voucher: &Voucher, guarantor_identity: &UserIdentity) -> GuarantorSignature {
    let mut sig_obj = GuarantorSignature {
        voucher_id: voucher.voucher_id.clone(),
        guarantor_id: guarantor_identity.user_id.clone(),
        first_name: "Garant".to_string(),
        last_name: "Test".to_string(),
        signature_time: get_current_timestamp(),
        ..Default::default()
    };
    let sig_obj_for_id = {
        let mut temp = sig_obj.clone();
        temp.signature_id = "".to_string();
        temp.signature = "".to_string();
        temp
    };
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
    let guarantor_sig = create_guarantor_signature(&valid_voucher, &ACTORS.guarantor);
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
    assert!(matches!(result, Err(VoucherCoreError::Validation(voucher_lib::services::voucher_validation::ValidationError::InvalidCreatorSignature))),
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
    assert!(matches!(result, Err(VoucherCoreError::Validation(voucher_lib::services::voucher_validation::ValidationError::InsufficientFunds))),
            "Validation must fail with InsufficientFunds on overspending attempt.");
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

#[test]
fn test_attack_fuzzing_random_mutations() {
    // ### SETUP ###
    // Erstelle einen maximal komplexen "Master"-Gutschein mit über 10 Transaktionen.
    let mut data = new_test_voucher_data(ACTORS.issuer.user_id.clone());
    data.nominal_value.amount = "1000".to_string(); // Höherer Startwert für mehr Transaktionen

    let mut master_voucher = voucher_manager::create_voucher(data, &STANDARD, &ACTORS.issuer.signing_key).unwrap();

    // Füge mehrere Bürgen hinzu, um die Komplexität des Objekts zu erhöhen.
    let (g2_pub, g2_priv) = crypto_utils::generate_ed25519_keypair_for_tests(Some("guarantor2_fuzz"));
    let g2_id = crypto_utils::create_user_id(&g2_pub, Some("g2")).unwrap();
    let sig1 = create_guarantor_signature(&master_voucher, &ACTORS.guarantor);
    let sig2 = create_guarantor_signature(&master_voucher, &UserIdentity { signing_key: g2_priv, public_key: g2_pub, user_id: g2_id });
    master_voucher.guarantor_signatures.push(sig1);
    master_voucher.guarantor_signatures.push(sig2);

    // KORRIGIERTE "Ping-Pong"-Kette, die mit der "letzte Transaktion"-Logik kompatibel ist.
    master_voucher = voucher_manager::create_transaction(&master_voucher, &STANDARD, &ACTORS.issuer.user_id, &ACTORS.issuer.signing_key, &ACTORS.alice.user_id, "1000").unwrap();
    master_voucher = voucher_manager::create_transaction(&master_voucher, &STANDARD, &ACTORS.alice.user_id, &ACTORS.alice.signing_key, &ACTORS.bob.user_id, "1000").unwrap();
    master_voucher = voucher_manager::create_transaction(&master_voucher, &STANDARD, &ACTORS.bob.user_id, &ACTORS.bob.signing_key, &ACTORS.hacker.user_id, "1000").unwrap();
    master_voucher = voucher_manager::create_transaction(&master_voucher, &STANDARD, &ACTORS.hacker.user_id, &ACTORS.hacker.signing_key, &ACTORS.victim.user_id, "1000").unwrap();
    master_voucher = voucher_manager::create_transaction(&master_voucher, &STANDARD, &ACTORS.victim.user_id, &ACTORS.victim.signing_key, &ACTORS.issuer.user_id, "1000").unwrap();
    master_voucher = voucher_manager::create_transaction(&master_voucher, &STANDARD, &ACTORS.issuer.user_id, &ACTORS.issuer.signing_key, &ACTORS.alice.user_id, "1000").unwrap();
    master_voucher = voucher_manager::create_transaction(&master_voucher, &STANDARD, &ACTORS.alice.user_id, &ACTORS.alice.signing_key, &ACTORS.bob.user_id, "1000").unwrap();
    master_voucher = voucher_manager::create_transaction(&master_voucher, &STANDARD, &ACTORS.bob.user_id, &ACTORS.bob.signing_key, &ACTORS.hacker.user_id, "1000").unwrap();
    master_voucher = voucher_manager::create_transaction(&master_voucher, &STANDARD, &ACTORS.hacker.user_id, &ACTORS.hacker.signing_key, &ACTORS.victim.user_id, "500").unwrap(); // Split am Ende
    master_voucher = voucher_manager::create_transaction(&master_voucher, &STANDARD, &ACTORS.victim.user_id, &ACTORS.victim.signing_key, &ACTORS.issuer.user_id, "500").unwrap(); // Voller Transfer des erhaltenen Betrags


    let master_json_value = serde_json::to_value(&master_voucher).unwrap();
    let mut rng = thread_rng();
    println!("--- Starte Fuzzing-Test mit 1000 Iterationen ---");
    let iterations = 1000;

    for i in 0..iterations {
        let mut mutated_value = master_json_value.clone();
        let change_description = mutate_value(&mut mutated_value, &mut rng, "voucher").unwrap_or_else(|| "No mutation occurred".to_string());
        let deserialized_voucher: Voucher = match serde_json::from_value(mutated_value.clone()) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let validation_result = voucher_validation::validate_voucher_against_standard(&deserialized_voucher, &STANDARD);
        assert!(validation_result.is_err(),
                "FUZZING-FEHLER bei Iteration {}: Eine Mutation hat die Validierung umgangen!\nÄnderung: {}\nMutierter Gutschein:\n{}",
                i, change_description, serde_json::to_string_pretty(&mutated_value).unwrap()
        );
    }
    println!("--- Fuzzing-Test erfolgreich abgeschlossen ---");
}