//! # src/models/profile.rs
//!
//! Definiert die Datenstrukturen für ein vollständiges Nutzerprofil,
//! inklusive Identität, Gutschein-Bestand und einer Historie von Transaktionsbündeln.
//! Diese Strukturen sind für die Verwaltung der "Wallet" eines Nutzers zuständig.

use crate::models::voucher::Voucher;
use ed25519_dalek::{SigningKey, VerifyingKey as EdPublicKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use zeroize::ZeroizeOnDrop;

/// Repräsentiert die kryptographische Identität eines Nutzers.
/// Der private Schlüssel wird sicher im Speicher gehalten und beim Verlassen des Gültigkeitsbereichs genullt.
#[derive(ZeroizeOnDrop)]
pub struct UserIdentity {
    /// Der private Ed25519-Schlüssel des Nutzers.
    /// **Wichtig:** Dieser Schlüssel wird nicht serialisiert und verlässt niemals das Profil.
    #[zeroize]
    pub signing_key: SigningKey,
    /// Der öffentliche Ed25519-Schlüssel, abgeleitet vom privaten Schlüssel.
    pub public_key: EdPublicKey,
    /// Die öffentliche, teilbare User-ID, generiert aus dem Public Key.
    pub user_id: String,
}

/// Ein Enum, das die Richtung einer Transaktion aus der Perspektive des Profilinhabers angibt.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum TransactionDirection {
    Sent,
    Received,
}

/// Eine leichtgewichtige Zusammenfassung eines `TransactionBundle` für die Anzeige in einer Historie.
/// Enthält alle Metadaten, aber anstelle der vollständigen Gutscheine nur deren IDs.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct TransactionBundleHeader {
    /// Die eindeutige ID des zugehörigen Bündels.
    pub bundle_id: String,
    /// Die User-ID des Senders.
    pub sender_id: String,
    /// Die User-ID des Empfängers.
    pub recipient_id: String,
    /// Eine Liste der IDs der in diesem Bündel übertragenen Gutscheine.
    pub voucher_ids: Vec<String>,
    /// Der Zeitstempel der Bündel-Erstellung im ISO 8601-Format.
    pub timestamp: String,
    /// Eine optionale, vom Sender hinzugefügte Notiz.
    pub notes: Option<String>,
    /// Die digitale Signatur des Senders, die die Authentizität des Bündels bestätigt.
    pub sender_signature: String,
    /// Gibt an, ob das Bündel gesendet oder empfangen wurde.
    pub direction: TransactionDirection,
}

/// Repräsentiert ein vollständiges, signiertes Bündel für einen Austausch von Gutscheinen.
/// Dies ist die atomare Einheit, die zwischen Nutzern ausgetauscht wird.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct TransactionBundle {
    /// Eine eindeutige ID für dieses Bündel, generiert aus dem Hash seines Inhalts (ohne Signatur).
    pub bundle_id: String,
    /// Die User-ID des Senders.
    pub sender_id: String,
    /// Die User-ID des Empfängers.
    pub recipient_id: String,
    /// Eine Liste der vollständigen `Voucher`-Objekte, die übertragen werden.
    pub vouchers: Vec<Voucher>,
    /// Der Zeitstempel der Bündel-Erstellung im ISO 8601-Format.
    pub timestamp: String,
    /// Eine optionale, für den Empfänger sichtbare Notiz.
    pub notes: Option<String>,
    /// Die digitale Signatur des Senders, die die `bundle_id` unterzeichnet und somit das
    /// gesamte Bündel fälschungssicher macht.
    pub sender_signature: String,
}

impl TransactionBundle {
    /// Erstellt einen `TransactionBundleHeader` aus einem `TransactionBundle`.
    pub fn to_header(&self, direction: TransactionDirection) -> TransactionBundleHeader {
        TransactionBundleHeader {
            bundle_id: self.bundle_id.clone(),
            sender_id: self.sender_id.clone(),
            recipient_id: self.recipient_id.clone(),
            voucher_ids: self.vouchers.iter().map(|v| v.voucher_id.clone()).collect(),
            timestamp: self.timestamp.clone(),
            notes: self.notes.clone(),
            sender_signature: self.sender_signature.clone(),
            direction,
        }
    }
}

/// Die Hauptstruktur, die den gesamten Zustand eines Nutzer-Wallets repräsentiert.
/// Sie enthält die Identität, den Bestand an Gutscheinen und die Transaktionshistorie.
/// Diese Struktur wird serialisiert und verschlüsselt auf der Festplatte gespeichert.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserProfile {
    /// Die öffentliche User-ID. Wird aus `identity` abgeleitet und hier für einfachen Zugriff dupliziert.
    pub user_id: String,
    /// Der aktuelle Bestand an Gutscheinen, indiziert nach ihrer `voucher_id`.
    pub vouchers: HashMap<String, Voucher>,
    /// Eine Menge von Tupeln `(voucher_id, prev_hash)`, um bereits gesehene Transaktionszustände
    /// zu speichern. Dies dient als einfacher Mechanismus zur Erkennung von Double-Spending-Versuchen.
    pub known_tx_refs: HashSet<(String, String)>,
    /// Eine Historie aller gesendeten und empfangenen Transaktionsbündel,
    /// indiziert nach der `bundle_id`.
    pub bundle_history: HashMap<String, TransactionBundleHeader>,
}

// Implementiere `Default` für UserProfile, um eine leere Instanz zu erzeugen, die dann gefüllt wird.
// Die `identity` wird nach der Erstellung separat hinzugefügt.
impl Default for UserProfile {
    fn default() -> Self {
        Self {
            user_id: String::new(),
            vouchers: HashMap::new(),
            known_tx_refs: HashSet::new(),
            bundle_history: HashMap::new(),
        }
    }
}