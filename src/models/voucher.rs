//! # voucher.rs
//!
//! Definiert die Kern-Datenstrukturen für das universelle Gutschein-Container-Format.
//! Diese Strukturen bilden das im `llm-context.md` definierte JSON-Schema exakt ab
//! und verwenden `serde` für die Serialisierung und Deserialisierung.

use serde::{Serialize, Deserialize};

/// Definiert den Standard, zu dem ein Gutschein gehört.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct VoucherStandard {
    /// Der Name des Standards (z.B. "Minuto-Gutschein").
    pub name: String,
    /// Die eindeutige Kennung (UUID) des Standards.
    pub uuid: String,
}

/// Definiert den Nennwert, den ein Gutschein repräsentiert.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct NominalValue {
    /// Die Einheit des Gutscheinwerts (z.B. "Minuten", "Unzen").
    pub unit: String,
    /// Die genaue Menge des Werts, als String für maximale Flexibilität.
    pub amount: String,
    /// Eine gängige Abkürzung der Einheit (z.B. "m", "oz").
    pub abbreviation: String,
    /// Eine Beschreibung des Werts (z.B. "Objektive Zeit").
    pub description: String,
}

/// Enthält Informationen zur Besicherung des Gutscheins.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct Collateral {
    /// Die Art der Besicherung (z.B. "Physisches Edelmetall").
    #[serde(rename = "type")]
    pub type_: String,
    /// Die Einheit der Besicherung (z.B. "Unzen").
    pub unit: String,
    /// Die Menge der Besicherung.
    pub amount: String,
    /// Eine gängige Abkürzung für die Besicherungseinheit.
    pub abbreviation: String,
    /// Eine detailliertere Beschreibung der Besicherung.
    pub description: String,
    /// **Extrem wichtig:** Bedingungen, unter denen die Besicherung eingelöst werden kann.
    pub redeem_condition: String,
}

/// Detaillierte Adressinformationen.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct Address {
    /// Straße.
    pub street: String,
    /// Hausnummer.
    pub house_number: String,
    /// Postleitzahl.
    pub zip_code: String,
    /// Stadt.
    pub city: String,
    /// Land.
    pub country: String,
    /// Vollständige, formatierte Adresse.
    pub full_address: String,
}

/// Detaillierte Informationen zum Ersteller des Gutscheins.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Creator {
    /// Eindeutige ID des Erstellers (z.B. eine User ID, die aus dem Public Key generiert wird).
    pub id: String,
    /// Vorname des Erstellers.
    pub first_name: String,
    /// Nachname des Erstellers.
    pub last_name: String,
    /// Die Adresse des Erstellers.
    pub address: Address,
    /// Die Organisation des Erstellers (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    /// Die Gemeinschaft, zu der der Ersteller gehört (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub community: Option<String>,
    /// Telefonnummer des Erstellers (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    /// E-Mail-Adresse des Erstellers (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// URL des Erstellers oder dessen Webseite (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Geschlecht des Erstellers nach ISO 5218.
    pub gender: String,
    /// Beschreibung der Angebote oder Talente des Erstellers (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_offer: Option<String>,
    /// Beschreibung der Gesuche oder Bedürfnisse des Erstellers (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub needs: Option<String>,
    /// Die digitale Signatur des Erstellers, die den Gutschein authentifiziert.
    pub signature: String,
    /// Geografische Koordinaten des Erstellers (z.B. "Breitengrad, Längengrad").
    pub coordinates: String,
}

/// Repräsentiert die Signatur eines Bürgen.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct GuarantorSignature {
    /// Die eindeutige ID des Gutscheins, auf den sich diese Signatur bezieht.
    pub voucher_id: String,
    /// Die eindeutige ID dieser Signatur, generiert aus dem Hash ihrer eigenen Daten.
    pub signature_id: String,
    /// Eindeutige ID des Bürgen.
    pub guarantor_id: String,
    /// Vorname des Bürgen.
    pub first_name: String,
    /// Nachname des Bürgen.
    pub last_name: String,
    /// Organisation des Bürgen (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    /// Community des Bürgen (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub community: Option<String>,
    /// Adresse des Bürgen (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<Address>,
    /// Geschlecht des Bürgen nach ISO 5218.
    pub gender: String,
    /// E-Mail des Bürgen (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Telefonnummer des Bürgen (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    /// Geografische Koordinaten des Bürgen (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordinates: Option<String>,
    /// URL des Bürgen (optional, von mir hinzugefügt für Konsistenz).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Die digitale Signatur des Bürgen.
    pub signature: String,
    /// Zeitpunkt der Bürgen-Signatur im ISO 8601-Format.
    pub signature_time: String,
}

/// Repräsentiert eine einzelne Transaktion in der Transaktionskette des Gutscheins.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Transaction {
    /// Eindeutige ID der Transaktion.
    pub t_id: String,
    /// Art der Transaktion (z.B. "init", "split", "redeem").
    pub t_type: String,
    /// Zeitpunkt der Transaktion im ISO 8601-Format.
    pub t_time: String,
    /// ID des Senders der Transaktion.
    pub sender_id: String,
    /// ID des Empfängers der Transaktion.
    pub recipient_id: String,
    /// Der Betrag, der bei dieser Transaktion bewegt wurde.
    pub amount: String,
    /// Der Restbetrag beim Sender nach einer Teilung (nur bei "split"-Transaktionen relevant).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_remaining_amount: Option<String>,
    /// Digitale Signatur des Senders für diese Transaktion.
    pub sender_signature: String,
    /// Der Hash der vorhergehenden Transaktion oder der voucher_id für die init-Transaktion.
    pub prev_hash: String,
}

/// Repräsentiert eine zusätzliche, optionale Signatur, die an den Gutschein angehängt wird.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AdditionalSignature {
    /// Die eindeutige ID des Gutscheins, auf den sich diese Signatur bezieht.
    pub voucher_id: String,
    /// Die eindeutige ID dieser Signatur, generiert aus dem Hash ihrer eigenen Daten.
    pub signature_id: String,
    /// Eindeutige ID des zusätzlichen Unterzeichners.
    pub signer_id: String,
    /// Die digitale Signatur.
    pub signature: String,
    /// Zeitpunkt der Signatur im ISO 8601-Format.
    pub signature_time: String,
    /// Eine Beschreibung, warum diese Signatur hinzugefügt wurde.
    pub description: String,
}

/// Das Haupt-Struct, das den universellen Gutschein-Container repräsentiert.
/// Es fasst alle anderen Strukturen und Felder gemäß dem allgemeinen JSON-Schema zusammen.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Voucher {
    /// Definiert den Standard, dem dieser Gutschein folgt.
    pub voucher_standard: VoucherStandard,
    /// Die eindeutige ID dieses spezifischen Gutscheins.
    pub voucher_id: String,
    /// Eine allgemeine, menschenlesbare Beschreibung des spezifischen Gutscheins.
    pub description: String,
    /// Der primäre Einlösezweck, übernommen vom Standard (z.B. "goods_or_services").
    pub primary_redemption_type: String,
    /// Gibt an, ob der Gutschein in kleinere Einheiten aufgeteilt werden kann.
    pub divisible: bool,
    /// Das Erstellungsdatum des Gutscheins im ISO 8601-Format.
    pub creation_date: String,
    /// Das Gültigkeitsdatum des Gutscheins im ISO 8601-Format.
    pub valid_until: String,
    /// Die bei der Erstellung gültige Mindestgültigkeitsdauer aus dem Standard (ISO 8601 Duration).
    pub standard_minimum_issuance_validity: String,
    /// Eine Markierung, ob es sich um einen nicht einlösbaren Testgutschein handelt.
    pub non_redeemable_test_voucher: bool,
    /// Definiert den Nennwert des Gutscheins.
    pub nominal_value: NominalValue,
    /// Informationen zur Besicherung des Gutscheins.
    pub collateral: Collateral,
    /// Detaillierte Informationen zum Ersteller des Gutscheins.
    pub creator: Creator,
    /// Eine menschenlesbare Beschreibung der Bürgenanforderungen, übernommen vom Standard.
    pub guarantor_requirements_description: String,
    /// Ein optionaler Fußnotentext, der vom Standard vorgegeben wird.
    pub footnote: String,
    /// Ein Array von Signaturen der Bürgen.
    pub guarantor_signatures: Vec<GuarantorSignature>,
    /// Die Anzahl der für diesen Gutschein benötigten Bürgen.
    pub needed_guarantors: i64,
    /// Eine chronologische Liste aller Transaktionen dieses Gutscheins.
    pub transactions: Vec<Transaction>,
    /// Ein Array für zusätzliche, optionale Signaturen.
    pub additional_signatures: Vec<AdditionalSignature>,
}