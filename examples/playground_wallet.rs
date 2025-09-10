// run with: cargo run --example playground_wallet
//! # examples/playground_wallet.rs
//!
//! Ein kurzer Playground für die Wallet-Fassade.
//! 1. Erstellt zwei Identitäten (Alice als Senderin, Bob als Empfänger).
//! 2. Initialisiert Alices Wallet und fügt einen neuen Gutschein hinzu.
//! 3. Alice sendet den Gutschein über `wallet.create_transfer` an Bob.
//! 4. Gibt den finalen Gutschein-Zustand und den dabei erzeugten
//!    anonymen Transaktions-Fingerprint im Terminal aus.

use voucher_lib::models::profile::{UserIdentity, VoucherStatus};
use voucher_lib::models::voucher::{Address, Collateral, Creator, NominalValue};
use voucher_lib::services::crypto_utils;
use voucher_lib::services::voucher_manager::{self, to_json, NewVoucherData};
use voucher_lib::wallet::Wallet;
use voucher_lib::VoucherStandardDefinition;

/// Hilfsfunktion, um eine deterministische UserIdentity für Tests zu erstellen.
fn create_test_identity(seed: &str, prefix: &str) -> UserIdentity {
    let (public_key, signing_key) =
        crypto_utils::generate_ed25519_keypair_for_tests(Some(seed));
    let user_id = crypto_utils::create_user_id(&public_key, Some(prefix)).unwrap();
    UserIdentity {
        signing_key,
        public_key,
        user_id,
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- WALLET TRANSACTION PLAYGROUND ---");

    // --- SCHRITT 1: Setup ---
    println!("\n--- SCHRITT 1: Erstelle Identitäten, Wallet und einen initialen Gutschein ---");

    // Erstelle Identitäten für Alice (Senderin) und Bob (Empfänger)
    let alice_identity = create_test_identity("alice", "al");
    let bob_identity = create_test_identity("bob", "bo");
    println!("✅ Identitäten für Alice ({}) und Bob ({}) erstellt.", alice_identity.user_id, bob_identity.user_id);

    // Lade den für den Gutschein gültigen Standard
    let standard_toml = std::fs::read_to_string("voucher_standards/silver_standard.toml")?;
    let standard: VoucherStandardDefinition = voucher_manager::load_standard_definition(&standard_toml)?;
    println!("✅ Standard '{}' geladen.", standard.metadata.name);

    // Erstelle eine neue, leere Wallet für Alice
    let mut alice_wallet = Wallet {
        profile: voucher_lib::models::profile::UserProfile { user_id: alice_identity.user_id.clone() },
        voucher_store: Default::default(),
        bundle_meta_store: Default::default(),
        fingerprint_store: Default::default(),
        proof_store: Default::default(),
    };
    println!("✅ Leeres Wallet für Alice erstellt.");

    // Erstelle einen neuen Gutschein und füge ihn Alices Wallet hinzu
    let voucher_data = NewVoucherData {
        validity_duration: Some("P5Y".to_string()), // 5 Jahre, entspricht dem Standard-Default
        non_redeemable_test_voucher: false,
        nominal_value: NominalValue { amount: "1.5".to_string(), ..Default::default() }, // 1.5 Unzen
        collateral: Collateral::default(),
        creator: Creator { id: alice_identity.user_id.clone(), first_name: "Alice".into(), last_name: "Silversmith".into(), address: Address::default(), gender: "2".into(), signature: "".into(), ..Default::default() },
    };
    let initial_voucher = voucher_manager::create_voucher(voucher_data, &standard, &alice_identity.signing_key)?;
    alice_wallet.add_voucher_to_store(initial_voucher, VoucherStatus::Active, &alice_identity.user_id)?;
    println!("✅ Initialen Gutschein erstellt und zu Alices Wallet hinzugefügt.");


    // --- SCHRITT 2: Transaktion durchführen ---
    println!("\n--- SCHRITT 2: Alice sendet 0.5 Unzen an Bob ---");

    // Die lokale ID des Gutscheins in Alices Wallet holen
    let local_instance_id = alice_wallet.voucher_store.vouchers.keys().next().unwrap().clone();

    // Die `create_transfer`-Methode auf der Wallet-Fassade aufrufen
    let (_container_bytes, voucher_after_split) = alice_wallet.create_transfer(
        &alice_identity,
        &standard,
        &local_instance_id,
        &bob_identity.user_id,
        "0.5", // Teilbetrag, dies erzeugt eine Split-Transaktion
        Some("Payment for services".to_string()), // Notizen
        None::<&dyn voucher_lib::archive::VoucherArchive>, // Kein Archiv
    )?;
    println!("✅ Transaktion erfolgreich durchgeführt. Wallet-Zustand wurde aktualisiert.");


    // --- AUSGABE 1: Gutschein-Zustand nach der Transaktion (JSON) ---
    println!("\n--- AUSGABE 1: Gutschein-Zustand nach der Transaktion (JSON) ---");
    println!("Dieser JSON-String repräsentiert den Gutschein, den Bob erhalten würde.");
    println!("{}", to_json(&voucher_after_split)?);


    // --- AUSGABE 2: Anonymer Fingerprint der Transaktion (Rohdaten) ---
    println!("\n--- AUSGABE 2: Anonymer Fingerprint der Transaktion (Rohdaten) ---");
    println!("Dieser Fingerprint wurde automatisch von `create_transfer` erzeugt und in Alices Wallet gespeichert, um Double-Spending proaktiv zu verhindern.");

    // Den erzeugten Fingerprint aus dem Store des Wallets auslesen
    let fingerprint = alice_wallet.fingerprint_store
        .own_fingerprints
        .values()
        .next() // Nimm den ersten (und einzigen) Vektor von Fingerprints
        .and_then(|fps| fps.first()) // Nimm den ersten (und einzigen) Fingerprint aus dem Vektor
        .expect("Fingerprint sollte im Wallet-Store vorhanden sein.");

    // Gib die "Rohdaten" des Fingerprints aus
    println!("{:#?}", fingerprint);

    println!("\n--- PLAYGROUND BEENDET ---");
    Ok(())
}