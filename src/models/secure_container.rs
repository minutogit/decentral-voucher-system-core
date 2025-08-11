//! # src/models/secure_container.rs
//!
//! Definiert die Datenstruktur für einen generischen, signierten und für mehrere
//! Empfänger verschlüsselten Daten-Container. Dieser Container dient als universelles
//! und sicheres Transportmittel für beliebige Daten zwischen Nutzern.

use serde::{Serialize, Deserialize};
use std::collections::HashMap;

/// Definiert die Art des Inhalts, der im `SecureContainer` transportiert wird.
///
/// Die Verwendung eines Enums anstelle eines reinen Strings erhöht die Typsicherheit
/// und macht die Absicht des Senders im Code explizit.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum PayloadType {
    /// Der Payload ist ein `TransactionBundle` für eine Gutschein-Transaktion.
    TransactionBundle,
    /// Der Payload ist ein `Voucher`, der einem Bürgen zur Signierung vorgelegt wird.
    VoucherForSigning,
    /// Der Payload ist eine `TrustAssertion` für das Web-of-Trust.
    TrustAssertion,
    /// Ein generischer Typ für zukünftige, noch nicht definierte Anwendungsfälle.
    Generic(String),
}

/// Repräsentiert einen sicheren Container für den Datenaustausch.
///
/// Die Struktur implementiert das "Key Wrapping"-Muster:
/// 1. Der eigentliche `encrypted_payload` wird mit einem einmaligen, symmetrischen Schlüssel ("Payload Key") verschlüsselt.
/// 2. Dieser Payload Key wird für jeden Empfänger in `recipient_key_map` einzeln verschlüsselt,
///    und zwar mit einem Schlüssel, der aus einem statischen Diffie-Hellman-Austausch
///    zwischen Sender und dem jeweiligen Empfänger abgeleitet wird.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SecureContainer {
    /// Eine eindeutige ID für diesen Container, generiert aus dem Hash seines Inhalts.
    pub container_id: String,
    /// Die User-ID des Senders.
    pub sender_id: String,
    /// Gibt an, welche Art von Daten im `encrypted_payload` enthalten ist.
    pub payload_type: PayloadType,
    /// Die verschlüsselten Nutzdaten.
    pub encrypted_payload: Vec<u8>,
    /// Eine Map, die jedem Empfänger (`user_id`) den für ihn verschlüsselten Payload Key zuordnet.
    ///
    /// - Key: `user_id` des Empfängers.
    /// - Value: Der verschlüsselte Payload Key als Byte-Vektor.
    pub recipient_key_map: HashMap<String, Vec<u8>>,
    /// Die digitale Signatur des Senders, die die `container_id` unterzeichnet und somit die
    /// Authentizität und Integrität des gesamten Containers sicherstellt.
    pub sender_signature: String,
}