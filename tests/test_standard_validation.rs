//! # tests/test_standard_validation.rs
//!
//! Enthält alle Tests zur Verifizierung der Gutschein-Standard-Definitionen
//! und deren korrekte Integration in den Gutschein-Lebenszyklus.

// Lokale Hilfsfunktionen und statische Akteure aus der `test_utils.rs` Datei.
mod test_utils;

// HINWEIS: SILVER_STANDARD wird entfernt, da es nur in einem Untermodul benötigt wird.
use crate::test_utils::{add_voucher_to_wallet, generate_signed_standard_toml, setup_in_memory_wallet, ACTORS, MINUTO_STANDARD, TEST_ISSUER};
use voucher_lib::error::StandardDefinitionError;
// KORREKTUR: Unbenutzter Import `VoucherStandardDefinition` entfernt.
use voucher_lib::models::voucher_standard_definition::LocalizedText;
use voucher_lib::services::standard_manager::{get_localized_text, verify_and_parse_standard};
use voucher_lib::services::voucher_manager;
use voucher_lib::services::voucher_validation::validate_voucher_against_standard;
use voucher_lib::VoucherCoreError;

/// Tests, die sich auf die Kernlogik im `standard_manager` konzentrieren.
#[cfg(test)]
mod standard_manager_tests {
    use super::*;
    use ed25519_dalek::Signer;
    // KORREKTUR: Unbenutzter Import `sign_ed25519` entfernt.
    use voucher_lib::services::crypto_utils::get_hash;
    use voucher_lib::services::utils::to_canonical_json;
    use crate::test_utils::SILVER_STANDARD;

    /// # Test 1.1: `verify_and_parse_standard`
    /// Diese Tests stellen sicher, dass nur authentische und unveränderte Standard-Dateien geladen werden.

    #[test]
    fn test_valid_standard_passes_verification() {
        // Vorgehen: Nutze die Hilfsfunktion, um eine zur Laufzeit korrekt signierte TOML zu erzeugen.
        let valid_toml_str =
            generate_signed_standard_toml("voucher_standards/minuto_v1/standard.toml");

        // Erwartung: Die Verifizierung muss erfolgreich sein.
        let result = verify_and_parse_standard(&valid_toml_str);
        assert!(result.is_ok());

        // Zusätzliche Prüfung: Der zurückgegebene Hash muss mit dem aus den Test-Utils übereinstimmen.
        let (_standard, hash) = result.unwrap();
        assert_eq!(hash, MINUTO_STANDARD.1);
    }

    #[test]
    fn test_tampered_content_with_valid_signature_fails() {
        // Vorgehen: Erzeuge einen gültigen TOML-String und manipuliere ihn danach.
        let mut tampered_toml_str =
            generate_signed_standard_toml("voucher_standards/minuto_v1/standard.toml");
        tampered_toml_str = tampered_toml_str.replace("amount_decimal_places = 0", "amount_decimal_places = 8");

        // Erwartung: Die Verifizierung muss mit einem Signaturfehler fehlschlagen.
        let result = verify_and_parse_standard(&tampered_toml_str);
        assert!(result.is_err());
        match result.unwrap_err() {
            VoucherCoreError::Standard(StandardDefinitionError::InvalidSignature) => (), // Erfolg
            e => panic!("Expected InvalidSignature error, but got {:?}", e),
        }
    }

    #[test]
    fn test_missing_signature_block_fails() {
        // Vorgehen: Erzeuge einen gültigen TOML-String und entferne den Signatur-Block.
        let mut toml_without_signature =
            generate_signed_standard_toml("voucher_standards/minuto_v1/standard.toml");
        // Einfache String-Manipulation, um den Block zu entfernen.
        let signature_block_start = toml_without_signature.find("[signature]").unwrap();
        toml_without_signature.truncate(signature_block_start);

        // Erwartung: Die Verifizierung muss mit einem Fehler wegen des fehlenden Blocks fehlschlagen.
        let result = verify_and_parse_standard(&toml_without_signature);
        assert!(result.is_err());
        match result.unwrap_err() {
            VoucherCoreError::Standard(StandardDefinitionError::MissingSignatureBlock) => (), // Erfolg
            e => panic!("Expected MissingSignatureBlock error, but got {:?}", e),
        }
    }

    #[test]
    fn test_signature_from_wrong_issuer_fails() {
        // Vorgehen: Signiere den Standard mit dem "Hacker"-Schlüssel, aber gib den offiziellen Issuer an.
        let mut standard = SILVER_STANDARD.0.clone();
        standard.signature = None;
        let hash_to_sign = get_hash(to_canonical_json(&standard).unwrap());

        // Signatur vom Hacker erstellen
        let hacker_signature = ACTORS.hacker.signing_key.sign(hash_to_sign.as_bytes());

        // Signatur-Block mit der ID des offiziellen Issuers, aber der Signatur des Hackers füllen.
        standard.signature = Some(voucher_lib::models::voucher_standard_definition::SignatureBlock {
            issuer_id: TEST_ISSUER.user_id.clone(), // Offizielle ID
            signature: bs58::encode(hacker_signature.to_bytes()).into_string(), // Falsche Signatur
        });

        let manipulated_toml = toml::to_string(&standard).unwrap();

        // Erwartung: Die Verifizierung muss fehlschlagen.
        let result = verify_and_parse_standard(&manipulated_toml);
        assert!(result.is_err());
        match result.unwrap_err() {
            VoucherCoreError::Standard(StandardDefinitionError::InvalidSignature) => (), // Erfolg
            e => panic!("Expected InvalidSignature error due to wrong key, but got {:?}", e),
        }
    }

    #[test]
    fn test_malformed_issuer_id_fails() {
        // Vorgehen: Erzeuge einen gültigen TOML-String und ersetze die issuer_id durch Unsinn.
        let mut invalid_toml_str =
            generate_signed_standard_toml("voucher_standards/minuto_v1/standard.toml");
        // Regex wäre robuster, aber für den Test reicht ein einfacher Austausch.
        invalid_toml_str = invalid_toml_str.replace(&TEST_ISSUER.user_id, "did:key:invalid-format-123");

        // Erwartung: Die Funktion muss fehlschlagen, da der Public Key nicht extrahiert werden kann.
        let result = verify_and_parse_standard(&invalid_toml_str);
        assert!(result.is_err());
        // Der zugrundeliegende Fehler ist ein `GetPubkeyError`, der hier korrekt durchgereicht wird.
    }

    /// # Test 1.2: `get_localized_text`
    /// Diese Unit-Tests stellen die korrekte Fallback-Logik für mehrsprachige Texte sicher.

    #[test]
    fn test_localized_text_direct_match() {
        let texts = vec![
            LocalizedText { lang: "de".to_string(), text: "Hallo".to_string() },
            LocalizedText { lang: "en".to_string(), text: "Hello".to_string() },
        ];
        // Erwartung: Der deutsche Text wird gefunden.
        assert_eq!(get_localized_text(&texts, "de"), Some("Hallo"));
    }

    #[test]
    fn test_localized_text_fallback_to_english() {
        let texts = vec![
            LocalizedText { lang: "de".to_string(), text: "Hallo".to_string() },
            LocalizedText { lang: "en".to_string(), text: "Hello".to_string() },
        ];
        // Erwartung: Da "fr" nicht existiert, wird auf Englisch zurückgegriffen.
        assert_eq!(get_localized_text(&texts, "fr"), Some("Hello"));
    }

    #[test]
    fn test_localized_text_fallback_to_first_if_no_english() {
        let texts = vec![
            LocalizedText { lang: "de".to_string(), text: "Hallo".to_string() },
            LocalizedText { lang: "es".to_string(), text: "Hola".to_string() },
        ];
        // Erwartung: Da "fr" und "en" nicht existieren, wird der erste Eintrag ("de") genommen.
        assert_eq!(get_localized_text(&texts, "fr"), Some("Hallo"));
    }
}

/// Tests, die das Zusammenspiel zwischen Gutschein, Standard und Wallet validieren.
#[cfg(test)]
mod voucher_integration_tests {
    use super::*;
    use voucher_lib::models::voucher::Creator;
    use voucher_lib::services::voucher_manager::NewVoucherData;

    #[test]
    fn test_voucher_validation_fails_if_hash_in_voucher_is_wrong() {
        // Vorgehen:
        // 1. Richte ein Test-Wallet ein.
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);

        // 2. Füge einen gültigen Gutschein hinzu.
        let _local_id = add_voucher_to_wallet(
            &mut wallet,
            identity,
            "100",
            &MINUTO_STANDARD.0,
            false,
        )
            .unwrap();

        // 3. Greife auf den Gutschein zu und manipuliere den Hash.
        // KORREKTUR: Direkter Zugriff auf die `vouchers` HashMap anstelle der nicht-existenten Methode.
        let (voucher_in_store, _) = wallet.voucher_store.vouchers.values().next().expect("Voucher store should have one voucher").clone();
        let mut voucher = voucher_in_store; // Re-bind to make mutable
        voucher.voucher_standard.standard_definition_hash = "invalid_hash_string_123".to_string();

        // 4. Validiere den manipulierten Gutschein.
        let validation_result =
            validate_voucher_against_standard(&voucher, &MINUTO_STANDARD.0);

        // Erwartung: Die Validierung muss mit einem Hash-Mismatch-Fehler fehlschlagen.
        assert!(validation_result.is_err());
        match validation_result.unwrap_err() {
            VoucherCoreError::Standard(StandardDefinitionError::StandardHashMismatch) => (), // Erfolg
            e => panic!("Expected StandardHashMismatch, but got {:?}", e),
        }
    }

    #[test]
    fn test_voucher_creation_uses_correct_localized_description() {
        // Vorgehen:
        // Erstelle die Basisdaten für einen neuen Gutschein.
        let creator_info = Creator {
            id: ACTORS.alice.user_id.clone(),
            ..Default::default()
        };
        let new_voucher_data = NewVoucherData {
            creator: creator_info,
            nominal_value: voucher_lib::models::voucher::NominalValue {
                amount: "888".to_string(), ..Default::default()
            },
            ..Default::default()
        };

        // Fall A: Erstelle einen Gutschein mit deutscher Sprachpräferenz.
        let voucher_de = voucher_manager::create_voucher(
            new_voucher_data,
            &MINUTO_STANDARD.0,
            &MINUTO_STANDARD.1,
            &ACTORS.alice.signing_key,
            "de",
        )
            .unwrap();

        // Fall B: Erstelle denselben Gutschein mit einer nicht vorhandenen Präferenz (sollte auf Englisch zurückfallen).
        let creator_info_2 = Creator {
            id: ACTORS.alice.user_id.clone(),
            ..Default::default()
        };
        let new_voucher_data_2 = NewVoucherData {
            creator: creator_info_2,
            nominal_value: voucher_lib::models::voucher::NominalValue {
                amount: "888".to_string(), ..Default::default()
            },
            ..Default::default()
        };

        let voucher_fr = voucher_manager::create_voucher(
            new_voucher_data_2,
            &MINUTO_STANDARD.0,
            &MINUTO_STANDARD.1,
            &ACTORS.alice.signing_key,
            "fr",
        )
            .unwrap();


        // Erwartung:
        // Die Beschreibungen müssen den korrekten Text aus dem Standard enthalten.
        assert!(voucher_de.description.contains("Minuten qualitativer Leistung"));
        assert!(voucher_fr.description.contains("minutes of quality performance"));
    }
}

/// Enthält fortgeschrittene Tests für Geschäftsregeln und Randfälle.
#[cfg(test)]
mod advanced_validation_tests {
    use super::*;
    // KORREKTUR: Importe werden hier spezifisch geholt, um die Top-Level-Warnung zu beheben.
    use crate::test_utils::{ACTORS, SILVER_STANDARD};
    use voucher_lib::services::voucher_manager::VoucherManagerError; // KORREKTUR: Korrekter Import-Pfad.
    use voucher_lib::models::voucher_standard_definition::VoucherStandardDefinition;
    use voucher_lib::services::crypto_utils::get_hash;
    use voucher_lib::services::utils::to_canonical_json;
    use voucher_lib::VoucherCoreError;

    /// Hilfsfunktion, um einen Standard zur Laufzeit anzupassen und neu zu signieren.
    fn create_custom_standard(
        base_standard: &VoucherStandardDefinition,
        modifier: impl FnOnce(&mut VoucherStandardDefinition),
    ) -> (VoucherStandardDefinition, String) {
        let mut standard = base_standard.clone();
        modifier(&mut standard);

        standard.signature = None;
        let canonical_json = to_canonical_json(&standard).unwrap();
        let hash = get_hash(canonical_json.as_bytes());

        let signature = ed25519_dalek::Signer::sign(&TEST_ISSUER.signing_key, hash.as_bytes());

        standard.signature = Some(voucher_lib::models::voucher_standard_definition::SignatureBlock {
            issuer_id: TEST_ISSUER.user_id.clone(),
            signature: bs58::encode(signature.to_bytes()).into_string(),
        });

        (standard, hash)
    }

    #[test]
    fn test_cross_standard_validation_fails_on_uuid_mismatch() {
        // Szenario: Validiere einen Minuto-Gutschein mit dem Silber-Standard.
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);
        add_voucher_to_wallet(&mut wallet, identity, "100", &MINUTO_STANDARD.0, true).unwrap();
        let minuto_voucher = wallet.voucher_store.vouchers.values().next().unwrap().0.clone();

        // Erwartung: Die Validierung muss am UUID-Konflikt scheitern.
        let result = validate_voucher_against_standard(&minuto_voucher, &SILVER_STANDARD.0);
        assert!(result.is_err());
        match result.unwrap_err() {
            VoucherCoreError::Validation(e) => {
                // Die `ValidationError` ist nicht öffentlich, daher prüfen wir den String.
                assert!(e.to_string().contains("Voucher standard UUID mismatch"));
            }
            e => panic!("Expected a validation error, but got {:?}", e),
        }
    }

    #[test]
    fn test_transaction_creation_fails_with_wrong_standard() {
        // Szenario: Erstelle eine Transaktion für einen Silber-Gutschein, aber mit den Minuto-Regeln.
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);
        add_voucher_to_wallet(&mut wallet, identity, "5", &SILVER_STANDARD.0, false).unwrap();
        let silver_voucher = wallet.voucher_store.vouchers.values().next().unwrap().0.clone();

        let result = voucher_manager::create_transaction(
            &silver_voucher,
            &MINUTO_STANDARD.0, // Falscher Standard!
            &identity.user_id,
            &identity.signing_key,
            &ACTORS.bob.user_id,
            "1",
        );

        // Erwartung: Die interne Validierung in `create_transaction` muss den Fehler finden.
        assert!(result.is_err());
        match result.unwrap_err() {
            VoucherCoreError::Validation(e) => {
                 assert!(e.to_string().contains("Voucher standard UUID mismatch"));
            }
            e => panic!("Expected a validation error, but got {:?}", e),
        }
    }

    #[test]
    fn test_non_divisible_voucher_fails_on_split() {
        // Szenario: Erstelle einen Standard für einen nicht-teilbaren Gutschein.
        let (non_divisible_standard, _hash) = create_custom_standard(&SILVER_STANDARD.0, |s| {
            s.template.fixed.is_divisible = false;
        });

        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);
        add_voucher_to_wallet(&mut wallet, identity, "100", &non_divisible_standard, false).unwrap();
        let voucher = wallet.voucher_store.vouchers.values().next().unwrap().0.clone();

        // Versuche, eine Split-Transaktion durchzuführen.
        let result = voucher_manager::create_transaction(
            &voucher,
            &non_divisible_standard,
            &identity.user_id,
            &identity.signing_key,
            &ACTORS.bob.user_id,
            "40", // Eindeutig ein Split
        );

        // Erwartung: Die Transaktionserstellung muss fehlschlagen.
        assert!(result.is_err());
        match result.unwrap_err() {
            VoucherCoreError::Manager(VoucherManagerError::VoucherNotDivisible) => (), // Erfolg
            e => panic!("Expected VoucherNotDivisible error, but got {:?}", e),
        }
    }

    #[test]
    fn test_transaction_fails_if_type_not_allowed() {
        // Szenario: Standard erlaubt nur "init", aber wir versuchen einen Transfer.
        let (restricted_standard, _hash) = create_custom_standard(&MINUTO_STANDARD.0, |s| {
            s.validation.allowed_transaction_types = vec!["init".to_string()];
        });

        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);
        add_voucher_to_wallet(&mut wallet, identity, "100", &restricted_standard, true).unwrap();
        let voucher = wallet.voucher_store.vouchers.values().next().unwrap().0.clone();

        let result = voucher_manager::create_transaction(
            &voucher,
            &restricted_standard,
            &identity.user_id,
            &identity.signing_key,
            &ACTORS.bob.user_id,
            "100", // Voller Transfer
        );

        // Erwartung: Die Validierung sollte den ungültigen Transaktionstyp erkennen.
        assert!(result.is_err());
        match result.unwrap_err() {
            VoucherCoreError::Validation(e) => {
                // Wir erwarten den neuen, spezifischen Fehler.
                assert!(e.to_string().contains("Transaction type 'transfer' is not allowed"));
            }
            e => panic!("Expected a transaction type validation error, but got {:?}", e),
        }
    }
}
