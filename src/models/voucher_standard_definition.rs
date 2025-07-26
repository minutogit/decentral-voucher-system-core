//! # voucher_standard_definition.rs
//!
//! Definiert die Rust-Datenstrukturen für die Gutschein-Standards.
//! Diese neue Struktur trennt klar zwischen Metadaten, Kopiervorlagen und Validierungsregeln.

use serde::{Serialize, Deserialize};

/// Metadaten, die den Standard selbst beschreiben.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct StandardMetadata {
    pub name: String,
    pub uuid: String,
    pub abbreviation: String,
}

/// Eine Vorlage für Felder, die 1:1 in einen neuen Gutschein kopiert werden.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct VoucherTemplate {
    pub description: Option<String>,
    pub primary_redemption_type: String,
    pub is_divisible: bool,
    pub nominal_value: TemplateNominalValue,
    pub collateral: TemplateCollateral,
    pub guarantor_info: TemplateGuarantorInfo,
}

/// Vorlage für den Nennwert (nur die Einheit wird vom Standard vorgegeben).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct TemplateNominalValue {
    pub unit: String,
}

/// Vorlage für die Besicherung.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct TemplateCollateral {
    #[serde(rename = "type")]
    pub type_: String,
    pub description: String,
    pub redeem_condition: String,
}

/// Vorlage für die Bürgen-Informationen, die in den Gutschein kopiert werden.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct TemplateGuarantorInfo {
    pub needed_count: i64,
    pub description: String,
}

/// Regeln, die zur Validierung eines Gutscheins herangezogen werden.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ValidationRules {
    pub guarantor_rules: ValidationGuarantorRules,
    pub required_voucher_fields: Vec<String>,
    pub allowed_transaction_types: Vec<String>,
}

/// Spezifische Validierungsregeln für die Bürgen.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ValidationGuarantorRules {
    pub gender_specific: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub genders_needed: Vec<String>,
}

/// Das neue Haupt-Struct, das die gesamte Standard-Definition kapselt.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct VoucherStandardDefinition {
    pub metadata: StandardMetadata,
    pub template: VoucherTemplate,
    pub validation: ValidationRules
}