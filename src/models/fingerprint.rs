//! # src/models/fingerprint.rs
//!
//! Definiert die Datenstrukturen für die Double-Spending-Erkennung mittels
//! anonymer Transaktions-Fingerprints.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Repräsentiert einen einzelnen, anonymisierten Fingerprint einer Transaktion.
/// Diese Struktur enthält alle notwendigen Informationen, um einen Double Spend
/// nachzuweisen und abgelaufene Fingerprints zu verwalten.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct TransactionFingerprint {
    /// Der kryptographische Hash von `prev_hash + sender_id`.
    /// Dies ist der primäre Schlüssel, um potenzielle Konflikte zu gruppieren.
    pub prvhash_senderid_hash: String,

    /// Die eindeutige ID der Transaktion (`t_id`). Ein abweichender Wert hier bei
    /// identischem `prvhash_senderid_hash` signalisiert einen Double Spend.
    pub t_id: String,

    /// Der Zeitstempel der Transaktion (`t_time`). Hilft bei der Entscheidung,
    /// welche Transaktion im Konfliktfall die frühere war.
    pub t_time: String,

    /// Die Signatur des Senders. Dient als kryptographischer Beweis, um den
    /// Betrugsversuch dem Verursacher zweifelsfrei zuordnen zu können.
    pub sender_signature: String,

    /// Das Gültigkeitsdatum des zugehörigen Gutscheins (abgeleitet aus `voucher.valid_until`).
    /// Nach diesem Datum kann der Fingerprint sicher aus dem Speicher entfernt werden.
    pub valid_until: String,
}

/// Dient als Speichercontainer für alle gesammelten Transaktions-Fingerprints.
/// Trennt zwischen Fingerprints aus eigenen Transaktionen und solchen, die von
/// externen Quellen (Peers, Server) empfangen wurden.
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct FingerprintStore {
    /// Eine Sammlung von Fingerprints, die aus den Transaktionen der Gutscheine
    /// im eigenen `VoucherStore` generiert wurden.
    /// Der Key ist der `prvhash_senderid_hash`. Der Vec enthält alle zugehörigen
    /// Fingerprints (ein Vec mit >1 Elementen ist ein Konflikt).
    #[serde(default)]
    pub own_fingerprints: HashMap<String, Vec<TransactionFingerprint>>,

    /// Eine Sammlung von Fingerprints, die von anderen Teilnehmern im Netzwerk
    /// empfangen wurden. Dient als Indizien-Datenbank.
    #[serde(default)]
    pub foreign_fingerprints: HashMap<String, Vec<TransactionFingerprint>>,
}