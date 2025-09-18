//! # tests/validation/unit_service.rs
//!
//! Unit-Tests für die einzelnen, datengesteuerten Funktionen
//! der Validierungs-Engine im `voucher_validation`-Service.

use voucher_lib::error::ValidationError;
use voucher_lib::models::voucher::{
    AdditionalSignature, GuarantorSignature, NominalValue, Transaction, Voucher,
};
use voucher_lib::models::voucher_standard_definition::VoucherStandardDefinition;
use voucher_lib::services::voucher_validation;
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

/// Prüft die `validate_counts`-Logik.
#[cfg(test)]
mod counts_validation {
    use super::*;

    #[test]
    fn test_validate_counts_when_counts_are_valid_then_succeeds() {
        let standard = load_test_standard("standard_strict_counts.toml");
        let mut voucher = create_base_voucher();
        voucher.guarantor_signatures.push(GuarantorSignature::default()); // 1 ist erlaubt

        let count_rules = standard.validation.as_ref().unwrap().counts.as_ref().unwrap();
        let result = voucher_validation::validate_counts(&voucher, count_rules);

        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_counts_when_guarantor_count_is_below_min_then_fails() {
        let standard = load_test_standard("standard_strict_counts.toml");
        let voucher = create_base_voucher(); // Hat 0 Bürgen, Standard erfordert min 1

        let count_rules = standard.validation.as_ref().unwrap().counts.as_ref().unwrap();
        let result = voucher_validation::validate_counts(&voucher, count_rules);

        assert!(matches!(
            result.err().unwrap(),
            ValidationError::CountOutOfBounds { field, min, max, found }
            if field == "guarantor_signatures" && min == 1 && max == 1 && found == 0
        ));
    }

    #[test]
    fn test_validate_counts_when_additional_signatures_are_above_max_then_fails() {
        let standard = load_test_standard("standard_strict_counts.toml");
        let mut voucher = create_base_voucher();
        voucher.guarantor_signatures.push(GuarantorSignature::default());
        voucher
            .additional_signatures
            .push(AdditionalSignature::default()); // Hat 1, max ist 0

        let count_rules = standard.validation.as_ref().unwrap().counts.as_ref().unwrap();
        let result = voucher_validation::validate_counts(&voucher, count_rules);

        assert!(matches!(
            result.err().unwrap(),
            ValidationError::CountOutOfBounds { field, min, max, found }
            if field == "additional_signatures" && min == 0 && max == 0 && found == 1
        ));
    }
}

/// Prüft die `validate_content_rules`-Logik.
#[cfg(test)]
mod content_rules_validation {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_validate_content_rules_when_content_is_valid_then_succeeds() {
        let standard = load_test_standard("standard_content_rules.toml");
        let mut voucher = create_base_voucher();
        // Werte entsprechen den Regeln in der TOML
        voucher.divisible = false;
        voucher.nominal_value.unit = "EUR".to_string();
        voucher.nominal_value.amount = "50.00".to_string();
        voucher.description = "INV-999888".to_string();

        let voucher_json = serde_json::to_value(&voucher).unwrap();
        let content_rules = standard.validation.as_ref().unwrap().content_rules.as_ref().unwrap();
        let result = voucher_validation::validate_content_rules(&voucher_json, content_rules);

        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_content_rules_when_fixed_field_is_wrong_then_fails() {
        let standard = load_test_standard("standard_content_rules.toml");
        let mut voucher = create_base_voucher();
        voucher.nominal_value.unit = "USD".to_string(); // Falsch, Standard erfordert EUR

        let voucher_json = serde_json::to_value(&voucher).unwrap();
        let content_rules = standard.validation.as_ref().unwrap().content_rules.as_ref().unwrap();
        let result = voucher_validation::validate_content_rules(&voucher_json, content_rules);

        assert!(matches!(
            result.err().unwrap(),
            ValidationError::FieldValueMismatch { field, expected, found }
            if field == "nominal_value.unit" && expected == json!("EUR") && found == json!("USD")
        ));
    }

    #[test]
    fn test_validate_content_rules_when_value_is_disallowed_then_fails() {
        let standard = load_test_standard("standard_content_rules.toml");
        let mut voucher = create_base_voucher();
        voucher.nominal_value.amount = "75.00".to_string(); // Nicht in der erlaubten Liste

        let voucher_json = serde_json::to_value(&voucher).unwrap();
        let content_rules = standard.validation.as_ref().unwrap().content_rules.as_ref().unwrap();
        let result = voucher_validation::validate_content_rules(&voucher_json, content_rules);

        assert!(matches!(
            result.err().unwrap(),
            ValidationError::FieldValueNotAllowed { field, found, .. }
            if field == "nominal_value.amount" && found == json!("75.00")
        ));
    }

    #[test]
    fn test_validate_content_rules_when_regex_mismatches_then_fails() {
        let standard = load_test_standard("standard_content_rules.toml");
        let mut voucher = create_base_voucher();
        voucher.description = "INVALID-123".to_string(); // Passt nicht zum Regex-Muster

        let voucher_json = serde_json::to_value(&voucher).unwrap();
        let content_rules = standard.validation.as_ref().unwrap().content_rules.as_ref().unwrap();
        let result = voucher_validation::validate_content_rules(&voucher_json, content_rules);

        assert!(matches!(
            result.err().unwrap(),
            ValidationError::FieldRegexMismatch { field, pattern: _, found }
            if field == "description" && found == "INVALID-123"
        ));
    }
}

/// Prüft die `validate_field_group_rules`-Logik.
#[cfg(test)]
mod field_group_rules_validation {
    use super::*;
    use serde_json::json;

    fn create_test_guarantor(gender: &str) -> GuarantorSignature {
        let mut sig = GuarantorSignature::default();
        sig.gender = gender.to_string();
        sig
    }

    #[test]
    fn test_validate_field_group_rules_when_counts_are_correct_then_succeeds() {
        let standard = load_test_standard("standard_field_group_rules.toml");
        let mut voucher = create_base_voucher();
        // Entspricht exakt der Regel: 1x "A", 2x "B"
        voucher.guarantor_signatures = vec![
            create_test_guarantor("A"),
            create_test_guarantor("B"),
            create_test_guarantor("B"),
        ];

        let voucher_json = serde_json::to_value(&voucher).unwrap();
        let rules = standard.validation.as_ref().unwrap().field_group_rules.as_ref().unwrap();
        let result = voucher_validation::validate_field_group_rules(&voucher_json, rules);

        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_field_group_rules_when_value_count_is_wrong_then_fails() {
        let standard = load_test_standard("standard_field_group_rules.toml");
        let mut voucher = create_base_voucher();
        // Falsch: 2x "A", 1x "B". Gesamtzahl 3 ist aber korrekt.
        voucher.guarantor_signatures = vec![
            create_test_guarantor("A"),
            create_test_guarantor("A"),
            create_test_guarantor("B"),
        ];

        let voucher_json = serde_json::to_value(&voucher).unwrap();
        let rules = standard.validation.as_ref().unwrap().field_group_rules.as_ref().unwrap();
        let result = voucher_validation::validate_field_group_rules(&voucher_json, rules);

        let err = result.err().unwrap();
        assert!(matches!(
            err,
            ValidationError::FieldValueCountOutOfBounds { path, field, .. } if path == "guarantor_signatures" && field == "gender"
        ));
    }

    #[test]
    fn test_validate_field_group_rules_when_other_values_exist_but_required_are_met_then_succeeds() {
        let standard = load_test_standard("standard_field_group_rules.toml");
        let mut voucher = create_base_voucher();
        // Enthält 1x "A" und 2x "B", aber auch ein "C".
        voucher.guarantor_signatures = vec![
            create_test_guarantor("A"),
            create_test_guarantor("B"),
            create_test_guarantor("B"),
            create_test_guarantor("C"),
        ];

        let voucher_json = serde_json::to_value(&voucher).unwrap();
        let rules = standard.validation.as_ref().unwrap().field_group_rules.as_ref().unwrap();
        let result = voucher_validation::validate_field_group_rules(&voucher_json, rules);

        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_field_group_rules_when_path_is_not_found_then_fails() {
        let standard = load_test_standard("standard_path_not_found.toml");
        let voucher = create_base_voucher(); // Hat kein "non_existent_field"
        let voucher_json = serde_json::to_value(&voucher).unwrap();
        let rules = standard.validation.as_ref().unwrap().field_group_rules.as_ref().unwrap();
        let result = voucher_validation::validate_field_group_rules(&voucher_json, rules);

        assert!(matches!(
            result.err().unwrap(),
            ValidationError::PathNotFound { path } if path == "non_existent_field"
        ));
    }

    #[test]
    fn test_validate_field_group_rules_when_path_is_not_an_array_then_fails() {
        let standard = load_test_standard("standard_field_group_rules.toml");
        let voucher_json = json!({
            "guarantor_signatures": "this should be an array"
        });

        let rules = standard.validation.as_ref().unwrap().field_group_rules.as_ref().unwrap();
        let result = voucher_validation::validate_field_group_rules(&voucher_json, rules);

        assert!(matches!(
            result.err().unwrap(),
            ValidationError::InvalidDataType { path, expected }
            if path == "guarantor_signatures" && expected == "Array"
        ));
    }
}