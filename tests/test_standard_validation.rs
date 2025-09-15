//! # tests/test_standard_validation.rs
//!
//! Enthält alle Tests zur Verifizierung der Gutschein-Standard-Definitionen
//! und deren korrekte Integration in den Gutschein-Lebenszyklus.

mod test_utils;

use crate::test_utils::{generate_signed_standard_toml, setup_in_memory_wallet, ACTORS, MINUTO_STANDARD, TEST_ISSUER, add_voucher_to_wallet};
use voucher_lib::error::StandardDefinitionError;
use voucher_lib::models::voucher_standard_definition::{LocalizedText, VoucherStandardDefinition};
use voucher_lib::services::standard_manager::{get_localized_text, verify_and_parse_standard};
use voucher_lib::services::{voucher_manager, crypto_utils, utils};
use voucher_lib::services::voucher_validation::validate_voucher_against_standard;
use voucher_lib::VoucherCoreError;
use ed25519_dalek::Signer;

/// Hilfsfunktion, um einen Standard zur Laufzeit anzupassen und neu zu signieren.
/// Ist auf oberster Ebene definiert, damit alle Test-Module sie nutzen können.
fn create_custom_standard(
    base_standard: &VoucherStandardDefinition,
    modifier: impl FnOnce(&mut VoucherStandardDefinition),
) -> (VoucherStandardDefinition, String) {
    let mut standard = base_standard.clone();
    modifier(&mut standard);

    standard.signature = None;
    let canonical_json = utils::to_canonical_json(&standard).unwrap();
    let hash = crypto_utils::get_hash(canonical_json.as_bytes());

    let signature = TEST_ISSUER.signing_key.sign(hash.as_bytes());

    standard.signature = Some(voucher_lib::models::voucher_standard_definition::SignatureBlock {
        issuer_id: TEST_ISSUER.user_id.clone(),
        signature: bs58::encode(signature.to_bytes()).into_string(),
    });

    (standard, hash)
}


/// Tests, die sich auf die Kernlogik im `standard_manager` konzentrieren.
#[cfg(test)]
mod standard_manager_tests {
    use super::*;
    use crate::test_utils::SILVER_STANDARD;

    #[test]
    fn test_valid_standard_passes_verification() {
        let valid_toml_str =
            generate_signed_standard_toml("voucher_standards/minuto_v1/standard.toml");
        let result = verify_and_parse_standard(&valid_toml_str);
        assert!(result.is_ok());
        let (_standard, hash) = result.unwrap();
        assert_eq!(hash, MINUTO_STANDARD.1);
    }

    #[test]
    fn test_tampered_content_with_valid_signature_fails() {
        let mut tampered_toml_str =
            generate_signed_standard_toml("voucher_standards/minuto_v1/standard.toml");
        tampered_toml_str = tampered_toml_str.replace("amount_decimal_places = 0", "amount_decimal_places = 8");
        let result = verify_and_parse_standard(&tampered_toml_str);
        assert!(matches!(result.unwrap_err(), VoucherCoreError::Standard(StandardDefinitionError::InvalidSignature)));
    }

    #[test]
    fn test_missing_signature_block_fails() {
        let mut toml_without_signature =
            generate_signed_standard_toml("voucher_standards/minuto_v1/standard.toml");
        let signature_block_start = toml_without_signature.find("[signature]").unwrap();
        toml_without_signature.truncate(signature_block_start);
        let result = verify_and_parse_standard(&toml_without_signature);
        assert!(matches!(result.unwrap_err(), VoucherCoreError::Standard(StandardDefinitionError::MissingSignatureBlock)));
    }

    #[test]
    fn test_signature_from_wrong_issuer_fails() {
        let mut standard = SILVER_STANDARD.0.clone();
        standard.signature = None;
        let hash_to_sign = crypto_utils::get_hash(utils::to_canonical_json(&standard).unwrap());
        let hacker_signature = ACTORS.hacker.signing_key.sign(hash_to_sign.as_bytes());

        standard.signature = Some(voucher_lib::models::voucher_standard_definition::SignatureBlock {
            issuer_id: TEST_ISSUER.user_id.clone(),
            signature: bs58::encode(hacker_signature.to_bytes()).into_string(),
        });

        let manipulated_toml = toml::to_string(&standard).unwrap();
        let result = verify_and_parse_standard(&manipulated_toml);
        assert!(matches!(result.unwrap_err(), VoucherCoreError::Standard(StandardDefinitionError::InvalidSignature)));
    }

    #[test]
    fn test_malformed_issuer_id_fails() {
        let mut invalid_toml_str =
            generate_signed_standard_toml("voucher_standards/minuto_v1/standard.toml");
        invalid_toml_str = invalid_toml_str.replace(&TEST_ISSUER.user_id, "did:key:invalid-format-123");
        let result = verify_and_parse_standard(&invalid_toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_localized_text_direct_match() {
        let texts = vec![
            LocalizedText { lang: "de".to_string(), text: "Hallo".to_string() },
            LocalizedText { lang: "en".to_string(), text: "Hello".to_string() },
        ];
        assert_eq!(get_localized_text(&texts, "de"), Some("Hallo"));
    }

    #[test]
    fn test_localized_text_fallback_to_english() {
        let texts = vec![
            LocalizedText { lang: "de".to_string(), text: "Hallo".to_string() },
            LocalizedText { lang: "en".to_string(), text: "Hello".to_string() },
        ];
        assert_eq!(get_localized_text(&texts, "fr"), Some("Hello"));
    }

    #[test]
    fn test_localized_text_fallback_to_first_if_no_english() {
        let texts = vec![
            LocalizedText { lang: "de".to_string(), text: "Hallo".to_string() },
            LocalizedText { lang: "es".to_string(), text: "Hola".to_string() },
        ];
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
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);
        add_voucher_to_wallet(&mut wallet, identity, "100", &MINUTO_STANDARD.0, false).unwrap();
        let (mut voucher, _) = wallet.voucher_store.vouchers.values().next().unwrap().clone();
        voucher.voucher_standard.standard_definition_hash = "invalid_hash_string_123".to_string();
        let validation_result = validate_voucher_against_standard(&voucher, &MINUTO_STANDARD.0);
        assert!(matches!(validation_result.unwrap_err(), VoucherCoreError::Standard(StandardDefinitionError::StandardHashMismatch)));
    }

    #[test]
    fn test_voucher_creation_uses_correct_localized_description() {
        // Fall A: Erstelle einen Gutschein mit deutscher Sprachpräferenz.
        let new_voucher_data_de = NewVoucherData {
            creator: Creator { id: ACTORS.alice.user_id.clone(), ..Default::default() },
            nominal_value: voucher_lib::models::voucher::NominalValue { amount: "888".to_string(), ..Default::default() },
            ..Default::default()
        };
        let voucher_de = test_utils::create_voucher_for_manipulation(
            new_voucher_data_de, &MINUTO_STANDARD.0, &MINUTO_STANDARD.1, &ACTORS.alice.signing_key, "de"
        );

        // Fall B: Erstelle denselben Gutschein mit einer nicht vorhandenen Präferenz (sollte auf Englisch zurückfallen).
        let new_voucher_data_fr = NewVoucherData {
            creator: Creator { id: ACTORS.alice.user_id.clone(), ..Default::default() },
            nominal_value: voucher_lib::models::voucher::NominalValue { amount: "888".to_string(), ..Default::default() },
            ..Default::default()
        };
        let voucher_fr = test_utils::create_voucher_for_manipulation(
            new_voucher_data_fr, &MINUTO_STANDARD.0, &MINUTO_STANDARD.1, &ACTORS.alice.signing_key, "fr"
        );

        assert!(voucher_de.description.contains("Minuten qualitativer Leistung"));
        assert!(voucher_fr.description.contains("minutes of quality performance"));
    }
}

/// Enthält fortgeschrittene Tests für Geschäftsregeln und Randfälle.
#[cfg(test)]
mod advanced_business_rule_tests {
    use super::*;
    use crate::test_utils::SILVER_STANDARD;
    
    #[test]
    fn test_cross_standard_validation_fails_on_uuid_mismatch() {
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);
        add_voucher_to_wallet(&mut wallet, identity, "100", &MINUTO_STANDARD.0, true).unwrap();
        let (minuto_voucher, _) = wallet.voucher_store.vouchers.values().next().unwrap().clone();
        let result = validate_voucher_against_standard(&minuto_voucher, &SILVER_STANDARD.0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Voucher standard UUID mismatch"));
    }

    #[test]
    fn test_transaction_creation_fails_with_wrong_standard() {
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);
        add_voucher_to_wallet(&mut wallet, identity, "5", &SILVER_STANDARD.0, false).unwrap();
        let (silver_voucher, _) = wallet.voucher_store.vouchers.values().next().unwrap().clone();

        let result = voucher_manager::create_transaction(&silver_voucher, &MINUTO_STANDARD.0, &identity.user_id, &identity.signing_key, &ACTORS.bob.user_id, "1");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Voucher standard UUID mismatch"));
    }
}

/// Enthält fortgeschrittene Tests für Geschäftsregeln und Randfälle.
#[cfg(test)]
mod advanced_validation_tests {
    use super::*;
    use crate::test_utils::{ACTORS, SILVER_STANDARD};
    use voucher_lib::services::voucher_manager::VoucherManagerError;

    #[test]
    fn test_cross_standard_validation_fails_on_uuid_mismatch() {
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);
        add_voucher_to_wallet(&mut wallet, identity, "100", &MINUTO_STANDARD.0, true).unwrap();
        let (minuto_voucher, _) = wallet.voucher_store.vouchers.values().next().unwrap().clone();
        let result = validate_voucher_against_standard(&minuto_voucher, &SILVER_STANDARD.0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Voucher standard UUID mismatch"));
    }

    #[test]
    fn test_non_divisible_voucher_fails_on_split() {
        let (non_divisible_standard, _hash) = create_custom_standard(&SILVER_STANDARD.0, |s| {
            s.template.fixed.is_divisible = false;
        });

        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);
        add_voucher_to_wallet(&mut wallet, identity, "100", &non_divisible_standard, false).unwrap();
        let (voucher, _) = wallet.voucher_store.vouchers.values().next().unwrap().clone();

        let result = voucher_manager::create_transaction(&voucher, &non_divisible_standard, &identity.user_id, &identity.signing_key, &ACTORS.bob.user_id, "40");
        assert!(matches!(result.unwrap_err(), VoucherCoreError::Manager(VoucherManagerError::VoucherNotDivisible)));
    }

    #[test]
    fn test_transaction_fails_if_type_not_allowed() {
        let (restricted_standard, _hash) = create_custom_standard(&MINUTO_STANDARD.0, |s| {
            s.validation.as_mut().unwrap().behavior_rules.as_mut().unwrap().allowed_t_types = Some(vec!["init".to_string()]);
        });

        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);
        add_voucher_to_wallet(&mut wallet, identity, "100", &restricted_standard, true).unwrap();
        let (voucher, _) = wallet.voucher_store.vouchers.values().next().unwrap().clone();

        let result = voucher_manager::create_transaction(&voucher, &restricted_standard, &identity.user_id, &identity.signing_key, &ACTORS.bob.user_id, "100");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Transaction type 'transfer' is not allowed"));
    }
}

/// # Neue Tests zur Härtung der Standard-Verarbeitung
/// Diese Tests denken wie ein Angreifer und versuchen, die Logik durch
/// manipulierte, aber syntaktisch valide, Standard-Definitionen auszuhebeln.
#[cfg(test)]
mod security_and_hardening_tests {
    use super::*;
    use voucher_lib::services::voucher_manager::NewVoucherData;
    use voucher_lib::models::voucher::{Creator, NominalValue};

    /// ## Test A: Signatur-Schwachstellen
    /// Dieser Test stellt sicher, dass eine Signatur, die kein gültiger Base58-String ist
    /// (wie ein Platzhalter), korrekt zu einem Dekodierungsfehler führt.
    #[test]
    fn test_verification_fails_on_invalid_signature_string() {
        // 1. Starte mit einem garantiert gültig signierten Standard.
        let mut toml_str =
            generate_signed_standard_toml("voucher_standards/minuto_v1/standard.toml");

        // 2. Ersetze die gültige Signatur durch einen ungültigen Platzhalter.
        let original_sig_line = format!("signature = \"{}\"", MINUTO_STANDARD.0.signature.as_ref().unwrap().signature);
        let placeholder_sig_line = "signature = \"This-is-an-invalid-placeholder-signature\"";
        toml_str = toml_str.replace(&original_sig_line, placeholder_sig_line);

        // 3. Die Verifizierung muss nun fehlschlagen, weil der String nicht dekodiert werden kann.
        let result = verify_and_parse_standard(&toml_str);
        assert!(result.is_err(), "Function should have failed but returned Ok");
        assert!(matches!(result.unwrap_err(), VoucherCoreError::Standard(StandardDefinitionError::SignatureDecode(_))));
    }

    #[test]
    fn test_verification_fails_on_empty_signature_string() {
        let mut toml_str = generate_signed_standard_toml("voucher_standards/minuto_v1/standard.toml");
        let original_sig_line = format!("signature = \"{}\"", MINUTO_STANDARD.0.signature.as_ref().unwrap().signature);
        toml_str = toml_str.replace(&original_sig_line, "signature = \"\"");
        let result = verify_and_parse_standard(&toml_str);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), VoucherCoreError::Standard(StandardDefinitionError::SignatureDecode(_))));
    }

    /// ## Test B: Manipulative und ungültige Regel-Definitionen
    #[test]
    fn test_standard_deserialization_fails_on_type_mismatch() {
        let raw_toml_str = include_str!("../voucher_standards/minuto_v1/standard.toml");
        let manipulated_toml = raw_toml_str
            .replace(&format!("uuid = \"{}\"", MINUTO_STANDARD.0.metadata.uuid), "uuid = 12345")
            .replace("amount_decimal_places = 0", "amount_decimal_places = \"zero\"");
        let result = verify_and_parse_standard(&manipulated_toml);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), VoucherCoreError::Toml(_)));
    }

    #[test]
    fn test_voucher_creation_fails_with_incomplete_standard_template() {
        let (incomplete_standard, hash) = create_custom_standard(&MINUTO_STANDARD.0, |s| {
            s.template.fixed.nominal_value.unit = "".to_string();
        });

        let new_voucher_data = NewVoucherData {
            creator: Creator { id: ACTORS.alice.user_id.clone(), ..Default::default() },
            nominal_value: NominalValue { amount: "50".to_string(), ..Default::default() },
            ..Default::default()
        };

        let result = voucher_manager::create_voucher(new_voucher_data, &incomplete_standard, &hash, &ACTORS.alice.signing_key, "en");

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), VoucherCoreError::Manager(_)));
    }
}