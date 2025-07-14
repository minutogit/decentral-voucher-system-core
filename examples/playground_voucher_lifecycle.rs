//! # playground_voucher_lifecycle.rs
//!
//! Zeigt den gesamten Lebenszyklus eines Gutscheins:
//! 1. Erstellung eines neuen (unvollständigen) Gutscheins.
//! 2. Fehlgeschlagene Validierung, da Bürgen fehlen.
//! 3. Hinzufügen von kryptographisch echten Bürgen-Signaturen.
//! 4. Erfolgreiche Validierung des vollständigen Gutscheins.
//! 5. Manipulationsversuch und erneute fehlgeschlagene Validierung.
//
// Ausführen mit: cargo run --example playground_voucher_lifecycle

use voucher_lib::{
    create_voucher, crypto_utils, load_standard_definition, to_json,
    validate_voucher_against_standard, Creator, GuarantorSignature, NewVoucherData,
    NominalValue, ValidationError, VoucherStandard, VoucherStandardDefinition, Address, Collateral,
};

// Test-Standard, um nicht jedes Mal die Datei laden zu müssen.
const MINUTO_STANDARD_JSON: &str = r#"{
  "name": "Minuto-Gutschein",
  "uuid": "MINUTO-V1-XXXX-YYYY",
  "description": "Ein Gutschein für Waren oder Dienstleistungen im Wert von X Minuten qualitativer Leistung, besichert durch eine Gemeinschaft.",
  "nominal_value_unit": "Minuten",
  "is_divisible": true,
  "primary_redemption_type": "goods_or_services",
  "guarantor_requirements": {
    "needed_count": 2,
    "gender_specific": true,
    "genders_needed": ["1", "2"],
    "description": "Ein männlicher und ein weiblicher Bürge sind erforderlich."
  },
  "collateral": {
    "type": "Community-Besicherung",
    "description": "Besichert durch das Vertrauen und die Leistung der Minuto-Community.",
    "redeem_condition": "Keine direkte physische Einlösung."
  },
  "required_voucher_fields": ["voucher_id", "creation_date", "creator.signature", "guarantor_signatures"],
  "allowed_transaction_types": ["init", "split", "redeem"]
}"#;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- VOUCHER LIFECYCLE PLAYGROUND ---");

    // --- SETUP ---
    // Standard laden und Schlüsselpaare für alle Teilnehmer erzeugen
    let standard: VoucherStandardDefinition = load_standard_definition(MINUTO_STANDARD_JSON)?;
    println!("\n✅ Standard '{}' erfolgreich geladen.", standard.name);

    let (creator_pub, creator_priv) = crypto_utils::generate_ed25519_keypair_for_tests(Some("creator"));
    let (g1_pub, g1_priv) = crypto_utils::generate_ed25519_keypair_for_tests(Some("guarantor1"));
    let (g2_pub, g2_priv) = crypto_utils::generate_ed25519_keypair_for_tests(Some("guarantor2"));

    // --- SCHRITT 1: Gutschein erstellen ---
    println!("\n--- SCHRITT 1: Erstelle einen neuen Minuto-Gutschein ---");
    let creator_id = crypto_utils::create_user_id(&creator_pub, Some("cr"))?;
    let creator_data = Creator {
        id: creator_id,
        first_name: "Max".into(),
        last_name: "Creator".into(),
        address: Address { street: "Musterweg".into(), house_number: "1a".into(), zip_code: "12345".into(), city: "Musterstadt".into(), country: "DE".into(), full_address: "Musterweg 1a, 12345 Musterstadt".into() },
        gender: "1".into(),
        signature: "".into(), // wird von `create_voucher` gefüllt
        // ... weitere optionale Felder hier ...
        organization: None, community: None, phone: None, email: None, url: None, service_offer: None, needs: None, coordinates: "0,0".into(),
    };
    let voucher_data = NewVoucherData {
        voucher_standard: VoucherStandard { name: "Minuto-Gutschein".into(), uuid: "MINUTO-V1-XXXX-YYYY".into() },
        description: "Gutschein für 60 Minuten Leistung".into(),
        divisible: true, years_valid: 1, non_redeemable_test_voucher: true,
        nominal_value: NominalValue { unit: "Minuten".into(), amount: "60".into(), abbreviation: "m".into(), description: "Leistung".into() },
        collateral: Collateral { type_: "Community-Besicherung".into(), unit: "".into(), amount: "".into(), abbreviation: "".into(), description: "Vertrauen".into(), redeem_condition: "Keine Einlösung".into() },
        creator: creator_data,
        needed_guarantors: 2,
    };

    let mut voucher = create_voucher(voucher_data, &creator_priv)?;
    println!("✅ Gutschein erfolgreich erstellt. Aktueller JSON-Inhalt:");
    println!("{}", to_json(&voucher)?);
    println!("(Beachte: 'guarantor_signatures' ist noch leer)");


    // --- SCHRITT 2: Unvollständigen Gutschein validieren (erwarteter Fehler) ---
    println!("\n--- SCHRITT 2: Validiere unvollständigen Gutschein (erwarteter Fehler) ---");
    match validate_voucher_against_standard(&voucher, &standard) {
        Err(ValidationError::GuarantorRequirementsNotMet(reason)) => {
            println!("✅ Erfolg! Validierung wie erwartet fehlgeschlagen.");
            println!("   Grund: {}", reason);
        },
        Ok(_) => eprintln!("❌ Fehler: Validierung war unerwartet erfolgreich."),
        Err(e) => eprintln!("❌ Fehler: Unerwarteter Validierungsfehler: {}", e),
    }

    // --- SCHRITT 3: Bürgen fügen ihre Signaturen hinzu ---
    println!("\n--- SCHRITT 3: Bürgen fügen ihre (echten) Signaturen hinzu ---");
    let g1_id = crypto_utils::create_user_id(&g1_pub, Some("g1"))?;
    let g2_id = crypto_utils::create_user_id(&g2_pub, Some("g2"))?;

    let message_to_sign = crypto_utils::get_hash(&voucher.voucher_id);
    let g1_signature = crypto_utils::sign_ed25519(&g1_priv, message_to_sign.as_bytes());
    let g2_signature = crypto_utils::sign_ed25519(&g2_priv, message_to_sign.as_bytes());

    voucher.guarantor_signatures.push(GuarantorSignature {
        guarantor_id: g1_id, gender: "1".into(), first_name: "Hans".into(), last_name: "Bürge".into(),
        signature: bs58::encode(g1_signature.to_bytes()).into_string(),
        signature_time: "2025-07-20T10:00:00Z".into(),
        // ... weitere optionale Felder ...
        organization: None, community: None, address: None, email: None, phone: None, coordinates: None, url: None,
    });
    voucher.guarantor_signatures.push(GuarantorSignature {
        guarantor_id: g2_id, gender: "2".into(), first_name: "Gabi".into(), last_name: "Bürgin".into(),
        signature: bs58::encode(g2_signature.to_bytes()).into_string(),
        signature_time: "2025-07-20T10:05:00Z".into(),
        // ... weitere optionale Felder ...
        organization: None, community: None, address: None, email: None, phone: None, coordinates: None, url: None,
    });
    println!("✅ Bürgen-Signaturen hinzugefügt. Aktueller JSON-Inhalt:");
    println!("{}", to_json(&voucher)?);

    // --- SCHRITT 4: Vollständigen Gutschein validieren (erwarteter Erfolg) ---
    println!("\n--- SCHRITT 4: Validiere den vollständigen Gutschein (erwarteter Erfolg) ---");
    match validate_voucher_against_standard(&voucher, &standard) {
        Ok(_) => println!("✅ Erfolg! Der vollständige Gutschein ist jetzt gültig."),
        Err(e) => eprintln!("❌ Fehler: Validierung des vollständigen Gutscheins fehlgeschlagen: {}", e),
    }

    // --- SCHRITT 5: Manipulation und erneute Validierung (erwarteter Fehler) ---
    println!("\n--- SCHRITT 5: Manipuliere eine Bürgen-Signatur (erwarteter Fehler) ---");
    let mut tampered_voucher = voucher.clone();
    tampered_voucher.guarantor_signatures[0].signature = "dies_ist_eine_gefaelschte_signatur".to_string();
    println!("Eine Signatur wurde mit ungültigen Daten überschrieben.");
    match validate_voucher_against_standard(&tampered_voucher, &standard) {
        Err(ValidationError::SignatureDecodeError(_)) => {
            println!("✅ Erfolg! Validierung wie erwartet fehlgeschlagen, da die Signatur ungültig ist.");
        },
        Ok(_) => eprintln!("❌ Fehler: Validierung war unerwartet erfolgreich."),
        Err(e) => eprintln!("❌ Fehler: Unerwarteter Validierungsfehler: {}", e),
    }

    println!("\n--- PLAYGROUND BEENDET ---");
    Ok(())
}