// run with: cargo run --example playground_voucher_lifecycle
//! # playground_voucher_lifecycle.rs
//!
//! Zeigt den gesamten Lebenszyklus eines Gutscheins:
//! 1. Erstellung eines neuen (unvollständigen) Gutscheins.
//! 2. Fehlgeschlagene Validierung, da Bürgen fehlen.
//! 3. Hinzufügen von kryptographisch echten, entkoppelten Bürgen-Signaturen.
//! 4. Erfolgreiche Validierung des vollständigen Gutscheins.
//! 5. Manipulationsversuch der Metadaten und erneute fehlgeschlagene Validierung.
//
// Ausführen mit: cargo run --example playground_voucher_lifecycle

use voucher_lib::{
    create_voucher, crypto_utils, load_standard_definition, to_canonical_json, to_json,
    validate_voucher_against_standard, Address, Collateral, Creator, GuarantorSignature,
    NewVoucherData, NominalValue, ValidationError, VoucherManagerError, VoucherStandardDefinition,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- VOUCHER LIFECYCLE PLAYGROUND ---");

    // --- SETUP ---
    // Standard laden und Schlüsselpaare für alle Teilnehmer erzeugen
    // Lade den Standard aus der TOML-Datei
    let standard_toml = std::fs::read_to_string("voucher_standards/minuto_standard.toml")?;
    let standard: VoucherStandardDefinition = load_standard_definition(&standard_toml)?;
    println!(
        "\n✅ Standard '{}' erfolgreich geladen.",
        standard.metadata.name
    );

    let (creator_pub, creator_priv) =
        crypto_utils::generate_ed25519_keypair_for_tests(Some("creator"));
    let (g1_pub, g1_priv) = crypto_utils::generate_ed25519_keypair_for_tests(Some("guarantor1"));
    let (g2_pub, g2_priv) = crypto_utils::generate_ed25519_keypair_for_tests(Some("guarantor2"));

    // Erstelle die Creator-Daten, die für beide Versuche (den fehlschlagenden und den erfolgreichen) verwendet werden.
    let creator_id = crypto_utils::create_user_id(&creator_pub, Some("cr"))?;
    let base_creator_data = Creator {
        id: creator_id,
        first_name: "Max".into(),
        last_name: "Creator".into(),
        address: Address { street: "Musterweg".into(), house_number: "1a".into(), zip_code: "12345".into(), city: "Musterstadt".into(), country: "DE".into(), full_address: "Musterweg 1a, 12345 Musterstadt".into() },
        gender: "1".into(),
        signature: "".into(), // wird von `create_voucher` gefüllt
        organization: None, community: None, phone: None, email: None, url: None, service_offer: None, needs: None, coordinates: "0,0".into(),
    };

    // --- (NEU) SCHRITT 0: Versuch, einen Gutschein mit ungültiger Dauer zu erstellen ---
    println!("\n--- SCHRITT 0: Versuch, einen Gutschein mit zu kurzer Gültigkeit zu erstellen (erwarteter Fehler) ---");
    let invalid_voucher_data = NewVoucherData {
        validity_duration: Some("P30D".to_string()), // Zu kurz, Minuto-Standard erfordert P90D
        non_redeemable_test_voucher: true,
        nominal_value: NominalValue { unit: "".into(), amount: "30".into(), abbreviation: "".into(), description: "Leistung".into() },
        collateral: Collateral { type_: "".into(), unit: "".into(), amount: "".into(), abbreviation: "".into(), description: "".into(), redeem_condition: "".into() },
        creator: base_creator_data.clone(),
    };
    match create_voucher(invalid_voucher_data, &standard, &creator_priv) {
        Err(VoucherManagerError::InvalidValidityDuration(reason)) => {
            println!("✅ Erfolg! Erstellung wie erwartet fehlgeschlagen.");
            println!("   Grund: {}", reason);
        }
        Ok(_) => eprintln!("❌ Fehler: Erstellung war unerwartet erfolgreich."),
        Err(e) => eprintln!("❌ Fehler: Unerwarteter Fehler bei der Erstellung: {}", e),
    }

    // --- SCHRITT 1: Gültigen Gutschein erstellen ---
    println!("\n--- SCHRITT 1: Erstelle einen neuen, gültigen Minuto-Gutschein ---");
    let voucher_data = NewVoucherData {
        validity_duration: Some("P5Y".to_string()), // Gültigkeit von 2 Jahren
        non_redeemable_test_voucher: true,
        nominal_value: NominalValue {
            unit: "".to_string(), // Wird vom Standard überschrieben
            amount: "60".to_string(),
            abbreviation: "".to_string(), // Wird vom Standard überschrieben
            description: "Leistung".to_string(),
        },
        collateral: Collateral {
            type_: "".to_string(), // Wird vom Standard überschrieben
            unit: "".to_string(), amount: "".to_string(), abbreviation: "".to_string(), description: "".to_string(), redeem_condition: "".to_string(),
        },
        creator: base_creator_data,
    };
    let mut voucher = create_voucher(voucher_data, &standard, &creator_priv)?;
    println!("✅ Gutschein erfolgreich erstellt.");
    println!("   -> Die Beschreibung wurde aus der Vorlage generiert: \"{}\"", voucher.description);

    // Zeige die Rohdaten (kanonisches JSON), deren Hash die Creator-Signatur bildet.
    let mut raw_view = voucher.clone();
    // Um die signierten Daten anzuzeigen, müssen wir den Zustand exakt rekonstruieren:
    raw_view.creator.signature = "".to_string();
    raw_view.voucher_id = "".to_string();
    raw_view.guarantor_signatures.clear(); // Waren bei Erstellung leer
    raw_view.additional_signatures.clear(); // Waren bei Erstellung leer
    println!("   - Rohdaten (kanonisches JSON), die vom Ersteller signiert wurden:\n     {}", to_canonical_json(&raw_view)?);

    println!("\nSchön formatierter Gutschein (aktueller Zustand):");
    println!("{}", to_json(&voucher)?);
    println!("(Beachte: 'guarantor_signatures' ist noch leer)");

    // --- SCHRITT 2: Unvollständigen Gutschein validieren (erwarteter Fehler) ---
    println!("\n--- SCHRITT 2: Validiere unvollständigen Gutschein (erwarteter Fehler) ---");
    match validate_voucher_against_standard(&voucher, &standard) {
        Err(ValidationError::GuarantorRequirementsNotMet(reason)) => {
            println!("✅ Erfolg! Validierung wie erwartet fehlgeschlagen.");
            println!("   Grund: {}", reason);
        }
        Ok(_) => eprintln!("❌ Fehler: Validierung war unerwartet erfolgreich."),
        Err(e) => eprintln!("❌ Fehler: Unerwarteter Validierungsfehler: {}", e),
    }

    // --- SCHRITT 3: Bürgen fügen ihre Signaturen nach dem neuen Schema hinzu ---
    println!("\n--- SCHRITT 3: Bürgen fügen ihre (entkoppelten) Signaturen hinzu ---");
    let g1_id = crypto_utils::create_user_id(&g1_pub, Some("g1"))?;
    let g2_id = crypto_utils::create_user_id(&g2_pub, Some("g2"))?;

    // -- Bürge 1 --
    println!("\nErstelle Signatur für Bürge 1 (Hans Bürge)...");
    // 1. Erstelle die Metadaten der Signatur. `signature_id` und `signature` sind noch leer.
    let mut g1_sig_obj = GuarantorSignature {
        voucher_id: voucher.voucher_id.clone(),
        signature_id: "".to_string(), // Wird jetzt berechnet
        signature: "".to_string(),    // Wird jetzt berechnet
        guarantor_id: g1_id,
        gender: "1".into(),
        first_name: "Hans".into(),
        last_name: "Bürge".into(),
        signature_time: "2025-07-20T10:00:00Z".into(),
        organization: None, community: None, address: None, email: None, phone: None, coordinates: None, url: None,
    };
    // 2. Erzeuge die `signature_id` durch Hashing der Metadaten.
    let raw_g1_metadata = to_canonical_json(&g1_sig_obj)?;
    println!("   - Rohdaten der Signatur (kanonisches JSON), die zur ID-Generierung gehasht werden:\n     {}", raw_g1_metadata);
    let g1_sig_id = crypto_utils::get_hash(&raw_g1_metadata);
    g1_sig_obj.signature_id = g1_sig_id;
    println!("   - Berechnete signature_id: {}", g1_sig_obj.signature_id);

    // 3. Signiere die `signature_id`.
    let g1_digital_sig =
        crypto_utils::sign_ed25519(&g1_priv, g1_sig_obj.signature_id.as_bytes());
    g1_sig_obj.signature = bs58::encode(g1_digital_sig.to_bytes()).into_string();
    println!("   - Finale digitale Signatur (Base58): {}...", &g1_sig_obj.signature[..44]);

    // -- Bürge 2 --
    println!("\nErstelle Signatur für Bürgin 2 (Gabi Bürgin)...");
    let mut g2_sig_obj = GuarantorSignature {
        voucher_id: voucher.voucher_id.clone(), signature_id: "".into(), signature: "".into(),
        guarantor_id: g2_id, gender: "2".into(), first_name: "Gabi".into(), last_name: "Bürgin".into(),
        signature_time: "2025-07-20T10:05:00Z".into(),
        organization: None, community: None, address: None, email: None, phone: None, coordinates: None, url: None,
    };
    let g2_sig_id = crypto_utils::get_hash(to_canonical_json(&g2_sig_obj)?);
    g2_sig_obj.signature_id = g2_sig_id;
    let g2_digital_sig =
        crypto_utils::sign_ed25519(&g2_priv, g2_sig_obj.signature_id.as_bytes());
    g2_sig_obj.signature = bs58::encode(g2_digital_sig.to_bytes()).into_string();

    // Füge die fertigen, in sich geschlossenen Signatur-Objekte zum Gutschein hinzu.
    voucher.guarantor_signatures.push(g1_sig_obj);
    voucher.guarantor_signatures.push(g2_sig_obj);
    println!("\n✅ Beide Bürgen-Signaturen hinzugefügt.");

    // --- SCHRITT 4: Vollständigen Gutschein validieren (erwarteter Erfolg) ---
    println!("\n--- SCHRITT 4: Validiere den vollständigen Gutschein (erwarteter Erfolg) ---");
    match validate_voucher_against_standard(&voucher, &standard) {
        Ok(_) => println!("✅ Erfolg! Der vollständige Gutschein ist jetzt gültig."),
        Err(e) => {
            eprintln!("❌ Fehler: Validierung des vollständigen Gutscheins fehlgeschlagen: {}", e)
        }
    }

    // --- SCHRITT 5: Manipulation der Metadaten und erneute Validierung ---
    println!("\n--- SCHRITT 5: Manipuliere die Metadaten einer Bürgschaft (erwarteter Fehler) ---");
    let mut tampered_voucher = voucher.clone();
    // Ein Angreifer ändert den Vornamen des ersten Bürgen, NACHDEM die Signatur erstellt wurde.
    tampered_voucher.guarantor_signatures[0].first_name = "Betrüger".to_string();
    println!("Der Name des ersten Bürgen wurde zu 'Betrüger' geändert.");

    match validate_voucher_against_standard(&tampered_voucher, &standard) {
        Err(ValidationError::InvalidSignatureId(id)) => {
            println!("✅ Erfolg! Validierung wie erwartet fehlgeschlagen.");
            println!("   Grund: Die Metadaten der Signatur mit ID '{}' wurden manipuliert und passen nicht mehr zum Hash.", id);
        }
        Ok(_) => eprintln!("❌ Fehler: Validierung war unerwartet erfolgreich."),
        Err(e) => eprintln!("❌ Fehler: Unerwarteter Validierungsfehler: {}", e),
    }

    println!("\n--- PLAYGROUND BEENDET ---");
    Ok(())
}