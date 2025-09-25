// run with: cargo run --example playground_voucher_lifecycle
//! # playground_voucher_lifecycle.rs
//!
//! Demonstriert den gesamten Lebenszyklus eines Gutscheins unter Verwendung der
//! High-Level `AppService`-Fassade, so wie es eine echte Client-Anwendung tun würde.
//!
//! ### Simulierte Schritte:
//! 1.  **Setup:** Erstellt separate `AppService`-Instanzen für alle Teilnehmer (Ersteller, 2 Bürgen, Empfänger).
//! 2.  **Gutschein-Erstellung:** Der Ersteller legt einen neuen Gutschein an, der initial unvollständig ist.
//! 3.  **Bürgen-Workflow (asynchron):**
//!     - Ersteller sendet eine Signaturanfrage an Bürge 1.
//!     - Bürge 1 signiert und sendet die Signatur zurück.
//!     - Ersteller fügt die Signatur an. Der Gutschein ist immer noch unvollständig.
//!     - Der Prozess wird für Bürge 2 wiederholt.
//! 4.  **Aktivierung:** Nach Erhalt der zweiten Signatur wird der Gutschein automatisch `Active`.
//! 5.  **Transfer:** Der Ersteller sendet einen Teilbetrag an einen Empfänger.
//! 6.  **Verifizierung:** Die neuen Kontostände werden bei beiden Teilnehmern geprüft.
//! 7.  **Rohdaten-Ausgabe:** Der finale Zustand des Gutscheins wird als JSON ausgegeben.

use voucher_lib::app_service::AppService;
use voucher_lib::models::signature::DetachedSignature;
use voucher_lib::models::voucher::{Creator, GuarantorSignature, NominalValue};
use voucher_lib::{verify_and_parse_standard, NewVoucherData, VoucherStatus};
use std::collections::HashMap;
use tempfile::tempdir;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- VOUCHER LIFECYCLE PLAYGROUND (AppService API) ---");

    // --- 1. SETUP: Erstelle Services für alle Teilnehmer ---
    let dir_creator = tempdir()?;
    let dir_g1 = tempdir()?;
    let dir_g2 = tempdir()?;
    let dir_recipient = tempdir()?;
    let dir_charlie = tempdir()?;
    let password = "password123";

    let mut service_creator = AppService::new(dir_creator.path())?;
    let mut service_g1 = AppService::new(dir_g1.path())?;
    let mut service_g2 = AppService::new(dir_g2.path())?;
    let mut service_recipient = AppService::new(dir_recipient.path())?;
    let mut service_charlie = AppService::new(dir_charlie.path())?;

    // Erstelle Profile für alle Teilnehmer
    service_creator.create_profile(&AppService::generate_mnemonic(12)?, None, Some("creator"), password)?;
    service_g1.create_profile(&AppService::generate_mnemonic(12)?, None, Some("g1"), password)?;
    service_g2.create_profile(&AppService::generate_mnemonic(12)?, None, Some("g2"), password)?;
    service_recipient.create_profile(&AppService::generate_mnemonic(12)?, None, Some("rcp"), password)?;
    service_charlie.create_profile(&AppService::generate_mnemonic(12)?, None, Some("charlie"), password)?;

    let creator_id = service_creator.get_user_id()?;
    let g1_id = service_g1.get_user_id()?;
    let g2_id = service_g2.get_user_id()?;
    let recipient_id = service_recipient.get_user_id()?;
    let charlie_id = service_charlie.get_user_id()?;
    println!("\n✅ Profile für Ersteller, 2 Bürgen und Empfänger erstellt.");

    // Lade den Minuto-Standard
    let standard_toml = std::fs::read_to_string("voucher_standards/minuto_v1/standard.toml")?;
    let (standard, _) = verify_and_parse_standard(&standard_toml)?;

    // --- 2. Gutschein-Erstellung durch den Ersteller ---
    println!("\n--- SCHRITT 2: Ersteller legt einen neuen (unvollständigen) Gutschein an ---");
    let voucher_data = NewVoucherData {
        validity_duration: Some("P5Y".to_string()),
        nominal_value: NominalValue { amount: "60".to_string(), ..Default::default() },
        creator: Creator { id: creator_id.clone(), first_name: "Max".into(), last_name: "Creator".into(), ..Default::default() },
        ..Default::default()
    };
    let created_voucher = service_creator.create_new_voucher(&standard_toml, "de", voucher_data, password)?;

    let summary = service_creator.get_voucher_summaries(None, None)?.pop().unwrap();
    let local_id = summary.local_instance_id;
    println!("✅ Gutschein '{}' erstellt. Status: {:?}", created_voucher.voucher_id, summary.status);
    assert!(matches!(summary.status, VoucherStatus::Incomplete {..}));

    // --- 3. Bürgen-Workflow ---
    println!("\n--- SCHRITT 3: Asynchroner Bürgen-Workflow ---");

    // **Teil A: Bürge 1**
    println!("\n  -> Ersteller sendet Signaturanfrage an Bürge 1...");
    let _request_bundle_to_g1 = service_creator.create_signing_request_bundle(&local_id, &g1_id)?;
    // In einer echten App würde `request_bundle_to_g1` nun z.B. via QR-Code übertragen.

    println!("  -> Bürge 1 empfängt die Anfrage, signiert und sendet die Signatur zurück...");
    // Der Bürge muss den Gutschein aus dem Bundle extrahieren, um ihn zu signieren.
    // In einer echten App würde die App des Bürgen das Bundle öffnen. Hier simulieren wir das.
    let signature_data_g1 = DetachedSignature::Guarantor(GuarantorSignature {
        voucher_id: created_voucher.voucher_id.clone(), // KORREKTUR: Die ID des Gutscheins muss hier gesetzt werden.
        guarantor_id: g1_id.clone(),
        first_name: "Hans".into(), last_name: "Bürge".into(), gender: "1".into(),
        ..Default::default()
    });
    let response_bundle_from_g1 = service_g1.create_detached_signature_response_bundle(&created_voucher, signature_data_g1, &creator_id)?;

    println!("  -> Ersteller empfängt die Signatur von Bürge 1 und fügt sie an...");
    service_creator.process_and_attach_signature(&response_bundle_from_g1, &standard_toml, password)?;
    let details_after_g1 = service_creator.get_voucher_details(&local_id)?;
    println!("     -> Status nach 1. Signatur: {:?}", details_after_g1.status);
    assert!(matches!(details_after_g1.status, VoucherStatus::Incomplete {..}));

    // **Teil B: Bürge 2**
    println!("\n  -> Ersteller sendet Signaturanfrage an Bürge 2...");
    let _request_bundle_to_g2 = service_creator.create_signing_request_bundle(&local_id, &g2_id)?;

    println!("  -> Bürge 2 empfängt, signiert und sendet zurück...");
    let signature_data_g2 = DetachedSignature::Guarantor(GuarantorSignature {
        voucher_id: created_voucher.voucher_id.clone(), // KORREKTUR: Die ID des Gutscheins muss hier gesetzt werden.
        guarantor_id: g2_id.clone(),
        first_name: "Gabi".into(), last_name: "Bürgin".into(), gender: "2".into(),
        ..Default::default()
    });
    let response_bundle_from_g2 = service_g2.create_detached_signature_response_bundle(&created_voucher, signature_data_g2, &creator_id)?;

    println!("  -> Ersteller empfängt die Signatur von Bürge 2 und fügt sie an...");
    service_creator.process_and_attach_signature(&response_bundle_from_g2, &standard_toml, password)?;

    // --- 4. Aktivierung des Gutscheins ---
    println!("\n--- SCHRITT 4: Gutschein wird automatisch aktiviert ---");
    let final_details = service_creator.get_voucher_details(&local_id)?;
    println!("✅ Gutschein ist nach Erhalt der 2. Signatur vollständig und wurde automatisch aktiviert.");
    println!("   -> Finaler Status: {:?}", final_details.status);
    assert!(matches!(final_details.status, VoucherStatus::Active));

    // --- 5. Transfer eines Teilbetrags ---
    println!("\n--- SCHRITT 5: Ersteller sendet 25 Minuto an den Empfänger ---");
    let mut standards_map = HashMap::new();
    standards_map.insert(standard.metadata.uuid.clone(), standard_toml.clone());

    let transfer_bundle = service_creator.create_transfer_bundle(&standard, &local_id, &recipient_id, "25", Some("Viel Spaß!".to_string()), None, password)?;

    // --- 6. Verifizierung der Kontostände ---
    println!("\n--- SCHRITT 6: Empfänger erhält das Bundle und Kontostände werden geprüft ---");
    service_recipient.receive_bundle(&transfer_bundle, &standards_map, None, password)?;

    let balance_creator = service_creator.get_total_balance_by_currency()?;
    let balance_recipient = service_recipient.get_total_balance_by_currency()?;

    println!("   -> Kontostand Ersteller: {:?}", balance_creator);
    println!("   -> Kontostand Empfänger: {:?}", balance_recipient);

    // KORREKTUR: Suchen Sie den Saldo im Vec<AggregatedBalance> anhand der Einheit.
    let creator_balance_str = balance_creator
        .iter()
        .find(|b| b.unit == "Min")
        .map(|b| b.total_amount.as_str())
        .unwrap_or("0");
    let recipient_balance_str = balance_recipient
        .iter()
        .find(|b| b.unit == "Min")
        .map(|b| b.total_amount.as_str())
        .unwrap_or("0");
    assert_eq!(creator_balance_str, "35");
    assert_eq!(recipient_balance_str, "25");

    // --- (NEU) SCHRITT 7: Zweiter Transfer in der Kette ---
    println!("\n--- SCHRITT 7: Empfänger sendet 10 Minuto an einen neuen Teilnehmer (Charlie) ---");

    // Finde die local_id des Gutscheins im Wallet des ersten Empfängers
    let recipient_summary = service_recipient.get_voucher_summaries(None, None)?.pop().unwrap();
    let recipient_local_id = recipient_summary.local_instance_id;

    // Der erste Empfänger erstellt jetzt das Transfer-Bundle für Charlie
    let transfer_bundle_to_charlie = service_recipient.create_transfer_bundle(
        &standard,
        &recipient_local_id,
        &charlie_id,
        "25", // (ÄNDERUNG) Sende den vollen Restbetrag
        Some("Weitergereicht!".to_string()),
        None,
        password,
    )?;

    // Charlie empfängt das Bundle
    service_charlie.receive_bundle(&transfer_bundle_to_charlie, &standards_map, None, password)?;

    // Überprüfe die finalen Kontostände
    let balance_recipient_after_send = service_recipient.get_total_balance_by_currency()?;
    let balance_charlie = service_charlie.get_total_balance_by_currency()?;
    println!("   -> Kontostand Empfänger (jetzt Sender): {:?}", balance_recipient_after_send);
    println!("   -> Kontostand Charlie (neuer Empfänger): {:?}", balance_charlie);

    // KORREKTUR: Suchen Sie den Saldo im Vec<AggregatedBalance> anhand der Einheit.
    let recipient_has_balance = balance_recipient_after_send.iter().any(|b| b.unit == "Min");
    let charlie_balance_str = balance_charlie
        .iter()
        .find(|b| b.unit == "Min")
        .map(|b| b.total_amount.as_str())
        .unwrap_or("0");
    assert!(!recipient_has_balance, "Nach einem vollen Transfer sollte der Sender keinen Minuto-Saldo mehr haben.");
    assert_eq!(charlie_balance_str, "25");

    // --- 8. Finale Rohdaten-Ausgabe ---
    println!("\n--- SCHRITT 8: Finale Rohdaten-Ausgabe des Gutscheins bei Charlie ---");
    let charlie_summary = service_charlie.get_voucher_summaries(None, None)?.pop().unwrap();
    let charlie_voucher_details = service_charlie.get_voucher_details(&charlie_summary.local_instance_id)?;
    println!("{}", serde_json::to_string_pretty(&charlie_voucher_details.voucher)?);


    println!("\n--- PLAYGROUND BEENDET ---");
    Ok(())
}