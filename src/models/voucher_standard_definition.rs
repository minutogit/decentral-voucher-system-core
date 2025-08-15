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

/// Enthält alle Werte, die vom Standard zwingend und unveränderlich vorgegeben werden.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct TemplateFixed {
    pub description: Option<String>,
    /// Ein optionaler Fußnotentext, der vom Standard vorgegeben wird.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub footnote: Option<String>,
    pub primary_redemption_type: String,
    pub is_divisible: bool,
    pub nominal_value: TemplateNominalValue,
    pub collateral: TemplateCollateral,
    pub guarantor_info: TemplateGuarantorInfo,
    /// Optionales Feld, um das Gültigkeitsdatum aufzurunden (z.B. P1D, P1M, P1Y).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub round_up_validity_to: Option<String>,
}

/// Enthält alle Werte, die als Vorschläge dienen und überschrieben werden können.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct TemplateDefault {
    /// Standard-Gültigkeitsdauer (z.B. P5Y), wenn vom Ersteller nicht anders angegeben.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_validity_duration: Option<String>,
}

/// Eine Vorlage für Felder, die in einen neuen Gutschein kopiert werden,
/// aufgeteilt in feste und überschreibbare Standardwerte.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct VoucherTemplate {
    pub fixed: TemplateFixed,
    #[serde(default)]
    pub default: TemplateDefault,
}

/// Regeln, die zur Validierung eines Gutscheins herangezogen werden.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ValidationRules {
    /// Mindestgültigkeitsdauer, die ein Gutschein bei der Erstellung haben muss (z.B. P90D).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuance_minimum_validity_duration: Option<String>,
    /// Definiert die Anzahl der Nachkommastellen für Betragsberechnungen, um Rundungsfehler zu vermeiden.
    #[serde(default)]
    pub amount_decimal_places: u8,
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