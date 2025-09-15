//! # tests/test_voucher_validation.rs
//!
//! Unit-Tests für die datengesteuerte Validierungs-Engine.

use voucher_core::error::ValidationError;
use voucher_core::models::voucher::{GuarantorSignature, NominalValue, Transaction, Voucher};
use voucher_core::models::voucher_standard_definition::{
    StandardMetadata, VoucherStandardDefinition,
};
use voucher_core::services::voucher_validation;
use std::fs;

// --- Test-Hilfsfunktionen ---

/// Lädt einen Test-Standard aus dem `test_data`-Verzeichnis.
fn load_test_standard(file_name: &str) -> VoucherStandardDefinition {
    let path = format!("tests/test_data/standards/{}", file_name);
    let toml_str = fs::read_to_string(path).expect("Failed to read test standard file");
    toml::from_str(&toml_str).expect("Failed to parse test standard TOML")
}

/// Erstellt einen minimalen, leeren Gutschein für Testzwecke.
fn create_base_voucher() -> Voucher {
    let mut voucher = Voucher::default();
    voucher.nominal_value = NominalValue {
        unit: "EUR".to_string(),
        amount: "50.00".to_string(),
        ..Default::default()
    };
    voucher.description = "INV-123456".to_string();
    voucher.transactions.push(Transaction::default());
    voucher
}

// --- Test-Module ---

#[cfg(test)]
mod counts_validation {
    use super::*;

    #[test]
    fn test_counts_ok() {
        let standard = load_test_standard("standard_strict_counts.toml");
        let mut voucher = create_base_voucher();
        voucher.guarantor_signatures.push(GuarantorSignature::default()); // 1 ist erlaubt

        let result =
            voucher_validation::validate_voucher_against_standard(&voucher, &standard);
        // Hinweis: Wir erwarten hier einen Fehler bei der kryptographischen Prüfung,
        // aber keinen `CountOutOfBounds`-Fehler.
        assert!(!matches!(
            result.err().unwrap(),
            ValidationError::CountOutOfBounds { .. }
        ));
    }

    #[test]
    fn test_fails_if_guarantor_count_below_min() {
        let standard = load_test_standard("standard_strict_counts.toml");
        let voucher = create_base_voucher(); // Hat 0 Bürgen, min ist 1

        let result =
            voucher_validation::validate_voucher_against_standard(&voucher, &standard);
        assert!(matches!(
            result.err().unwrap().downcast_ref::<ValidationError>().unwrap(),
            ValidationError::CountOutOfBounds { field, min, max, found }
            if field == "guarantor_signatures" && *min == 1 && *max == 1 && *found == 0
        ));
    }

    #[test]
    fn test_fails_if_additional_signatures_above_max() {
        let standard = load_test_standard("standard_strict_counts.toml");
        let mut voucher = create_base_voucher();
        voucher.guarantor_signatures.push(GuarantorSignature::default());
        voucher
            .additional_signatures
            .push(Default::default()); // Hat 1, max ist 0

        let result =
            voucher_validation::validate_voucher_against_standard(&voucher, &standard);
        assert!(matches!(
            result.err().unwrap().downcast_ref::<ValidationError>().unwrap(),
            ValidationError::CountOutOfBounds { field, min, max, found }
            if field == "additional_signatures" && *min == 0 && *max == 0 && *found == 1
        ));
    }
}

#[cfg(test)]
mod content_rules_validation {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_content_rules_ok() {
        let standard = load_test_standard("standard_content_rules.toml");
        let mut voucher = create_base_voucher();
        // Werte entsprechen den Regeln in der TOML
        voucher.divisible = false;
        voucher.nominal_value.unit = "EUR".to_string();
        voucher.nominal_value.amount = "50.00".to_string();
        voucher.description = "INV-999888".to_string();

        // Dummy-Standard-Metadaten für die Hauptvalidierungsfunktion
        voucher.voucher_standard.uuid = "TEST-CONTENT-RULES-V1".to_string();

        let result =
            voucher_validation::validate_voucher_against_standard(&voucher, &standard);
        assert!(!matches!(
            result.err().unwrap(),
            ValidationError::FieldValueMismatch { .. }
                | ValidationError::FieldValueNotAllowed { .. }
                | ValidationError::FieldRegexMismatch { .. }
        ));
    }

    #[test]
    fn test_fails_on_wrong_fixed_field() {
        let standard = load_test_standard("standard_content_rules.toml");
        let mut voucher = create_base_voucher();
        voucher.nominal_value.unit = "USD".to_string(); // Falsch, muss EUR sein
        voucher.voucher_standard.uuid = "TEST-CONTENT-RULES-V1".to_string();

        let result =
            voucher_validation::validate_voucher_against_standard(&voucher, &standard);
        assert!(matches!(
            result.err().unwrap().downcast_ref::<ValidationError>().unwrap(),
            ValidationError::FieldValueMismatch { field, expected, found }
            if field == "nominal_value.unit" && *expected == json!("EUR") && *found == json!("USD")
        ));
    }

    #[test]
    fn test_fails_on_disallowed_value() {
        let standard = load_test_standard("standard_content_rules.toml");
        let mut voucher = create_base_voucher();
        voucher.nominal_value.amount = "75.00".to_string(); // Nicht in ["50.00", "100.00"]
        voucher.voucher_standard.uuid = "TEST-CONTENT-RULES-V1".to_string();

        let result =
            voucher_validation::validate_voucher_against_standard(&voucher, &standard);
        assert!(matches!(
            result.err().unwrap().downcast_ref::<ValidationError>().unwrap(),
            ValidationError::FieldValueNotAllowed { field, found, .. }
            if field == "nominal_value.amount" && *found == json!("75.00")
        ));
    }

    #[test]
    fn test_fails_on_regex_mismatch() {
        let standard = load_test_standard("standard_content_rules.toml");
        let mut voucher = create_base_voucher();
        voucher.description = "INVALID-123".to_string(); // Passt nicht zu '^INV-[0-9]{6}$'
        voucher.voucher_standard.uuid = "TEST-CONTENT-RULES-V1".to_string();

        let result =
            voucher_validation::validate_voucher_against_standard(&voucher, &standard);
        assert!(matches!(
            result.err().unwrap().downcast_ref::<ValidationError>().unwrap(),
            ValidationError::FieldRegexMismatch { field, found, .. }
            if field == "description" && found == "INVALID-123"
        ));
    }
}