//! # voucher_standard_definition.rs
//!
//! Definiert die Rust-Datenstrukturen für die Gutschein-Standards.
//! Diese neue Struktur trennt klar zwischen Metadaten, Kopiervorlagen und Validierungsregeln
//! und fügt die Unterstützung für kryptographische Signaturen und Mehrsprachigkeit hinzu.

use serde::{Serialize, Deserialize};

/// Repräsentiert einen einzelnen, sprachabhängigen Text.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct LocalizedText {
    pub lang: String,
    pub text: String,
}

/// Metadaten, die den Standard selbst beschreiben, inklusive optionaler Felder.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct StandardMetadata {
    pub uuid: String,
    pub name: String,
    pub abbreviation: String,
    pub issuer_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub homepage_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub documentation_url: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keywords: Vec<String>,
}

/// Vorlage für den Nennwert (nur die Einheit wird vom Standard vorgegeben).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct TemplateNominalValue {
    pub unit: String,
}

/// Vorlage für die Besicherung.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct TemplateCollateral {
    #[serde(rename = "type")]
    pub type_: String,
    pub description: String,
    pub redeem_condition: String,
}

/// Vorlage für die Bürgen-Informationen, die in den Gutschein kopiert werden.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct TemplateGuarantorInfo {
    pub needed_count: i64,
    pub description: String,
}

/// Enthält alle Werte, die vom Standard zwingend und unveränderlich vorgegeben werden.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct TemplateFixed {
    // Mehrsprachige Beschreibung wird jetzt als Liste von Tabellen im TOML abgebildet.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub description: Vec<LocalizedText>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub footnote: Option<String>,
    pub primary_redemption_type: String,
    pub is_fungible: bool,
    pub is_divisible: bool,
    pub nominal_value: TemplateNominalValue,
    pub collateral: TemplateCollateral,
    pub guarantor_info: TemplateGuarantorInfo,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub round_up_validity_to: Option<String>,
}

/// Enthält alle Werte, die als Vorschläge dienen und überschrieben werden können.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct TemplateDefault {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_validity_duration: Option<String>,
}

/// Eine Vorlage für Felder, die in einen neuen Gutschein kopiert werden.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct VoucherTemplate {
    pub fixed: TemplateFixed,
    #[serde(default)]
    pub default: TemplateDefault,
}

/// Regeln, die zur Validierung eines Gutscheins herangezogen werden.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct ValidationRules {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuance_minimum_validity_duration: Option<String>,
    #[serde(default)]
    pub amount_decimal_places: u8,
    pub guarantor_rules: ValidationGuarantorRules,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_voucher_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_transaction_types: Vec<String>,
}

/// Spezifische Validierungsregeln für die Bürgen.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct ValidationGuarantorRules {
    pub gender_specific: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub genders_needed: Vec<String>,
}

/// Enthält die kryptographische Signatur, die die Authentizität des Standards beweist.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct SignatureBlock {
    /// Die `did:key` des Herausgebers.
    pub issuer_id: String,
    /// Die Base58-kodierte Ed25519-Signatur.
    pub signature: String,
}

/// Das Haupt-Struct, das die gesamte, nun signierte Standard-Definition kapselt.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct VoucherStandardDefinition {
    pub metadata: StandardMetadata,
    pub template: VoucherTemplate,
    pub validation: ValidationRules,
    // Die Signatur ist optional, da sie für die Kanonisierung temporär entfernt wird.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureBlock>,
}