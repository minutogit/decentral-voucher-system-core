//! # voucher_standard_definition.rs
//!
//! Definiert die Rust-Datenstrukturen für die Gutschein-Standards.
//! Diese Strukturen ermöglichen das Parsen der "Regelwerk"-JSON-Dateien
//! (z.B., `minuto_standard.json`, `silver_payment_standard.json`),
//! um die spezifischen Eigenschaften und Validierungsregeln eines Gutscheintyps
//! zur Laufzeit zu laden.

use serde::{Serialize, Deserialize};

/// Definiert die spezifischen Anforderungen an die Bürgen für einen Gutschein-Standard.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct GuarantorRequirements {
    /// Die Anzahl der benötigten Bürgen.
    pub needed_count: i64,
    /// Gibt an, ob geschlechtsspezifische Anforderungen bestehen.
    pub gender_specific: bool,
    /// Eine Liste der benötigten Geschlechter, falls `gender_specific` true ist.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub genders_needed: Vec<String>,
    /// Eine menschenlesbare Beschreibung der Bürgenanforderungen.
    pub description: String,
}

/// Definiert die Besicherungsinformationen innerhalb eines Gutschein-Standards.
/// Beachte, dass diese Struktur sich von der `Collateral`-Struktur im Haupt-Voucher unterscheidet,
/// da sie die Regeln und nicht die spezifischen Daten eines einzelnen Vouchers definiert.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct StandardCollateral {
    /// Die Art der Besicherung (z.B. "Community-Besicherung").
    #[serde(rename = "type")]
    pub type_: String,
    /// Eine allgemeine Beschreibung der Besicherung für diesen Standard.
    pub description: String,
    /// Die allgemeingültige Einlösebedingung für diesen Standard.
    pub redeem_condition: String,
    /// Die Einheit der Besicherung (optional, falls für den Standard relevant).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    /// Die Menge der Besicherung (oft eine beschreibende Regel, z.B. "entspricht dem Nennwert").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
}

/// Das Haupt-Struct, das ein vollständiges "Regelwerk" für einen Gutschein-Standard abbildet.
/// Es wird durch das Parsen einer Standard-JSON-Datei (z.B. `minuto_standard.json`) instanziiert.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct VoucherStandardDefinition {
    /// Der offizielle Name des Standards (z.B. "Minuto-Gutschein").
    pub name: String,
    /// Die eindeutige Kennung (UUID) des Standards.
    pub uuid: String,
    /// Eine allgemeine Beschreibung des Gutschein-Standards.
    pub description: String,
    /// Die feste Einheit des Nennwerts für diesen Standard (z.B. "Minuten").
    pub nominal_value_unit: String,
    /// Eine gängige Abkürzung für den Standard (z.B. "Minuto").
    pub abbreviation: String,
    /// Gibt an, ob Gutscheine dieses Standards standardmäßig teilbar sind.
    pub is_divisible: bool,
    /// Der primäre Einlösezweck (z.B. "goods_or_services").
    pub primary_redemption_type: String,
    /// Die spezifischen Anforderungen an die Bürgen.
    pub guarantor_requirements: GuarantorRequirements,
    /// Die Besicherungsregeln für diesen Standard.
    pub collateral: StandardCollateral,
    /// Eine Liste von Feldpfaden, die in einem Gutschein dieses Standards zwingend vorhanden sein müssen.
    /// (z.B. "creator.signature", "nominal_value.amount").
    pub required_voucher_fields: Vec<String>,
    /// Eine Liste der erlaubten Transaktionstypen (z.B. "init", "split").
    pub allowed_transaction_types: Vec<String>,
}