// In: src/models/conflict.rs

//! # src/models/conflict.rs
//!
//! Definiert die Datenstrukturen für die Erkennung, den Beweis und die
//! Lösung von Double-Spending-Konflikten.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::models::voucher::Transaction;

//==============================================================================
// TEIL 1: STRUKTUREN ZUR KONFLIKTERKENNUNG (aus fingerprint.rs)
//==============================================================================

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


//==============================================================================
// TEIL 2: STRUKTUREN ZUM BEWEIS UND ZUR LÖSUNG VON KONFLIKTEN
//==============================================================================

/// Repräsentiert einen kryptographisch verifizierbaren Beweis für einen
/// Double-Spend-Versuch. Dieses Objekt ist portabel und dient als Grundlage
/// für soziale oder technische (Layer 2) Konfliktlösungen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfDoubleSpend {
    /// Die eindeutige, deterministische ID dieses Konflikts.
    /// Sie wird aus dem Hash der Kerndaten des Konflikts gebildet:
    /// `proof_id = hash(offender_id + fork_point_prev_hash)`.
    /// Dadurch erzeugt jeder, der denselben Konflikt entdeckt, dieselbe ID.
    pub proof_id: String,

    /// Die ID des Senders (Verursacher), der den Double Spend durchgeführt hat.
    pub offender_id: String,

    /// Der `prev_hash`, von dem die betrügerischen Transaktionen abzweigen.
    pub fork_point_prev_hash: String,

    /// Die vollständigen, widersprüchlichen Transaktionen, die den Betrug beweisen.
    pub conflicting_transactions: Vec<Transaction>,

    /// Das Gültigkeitsdatum des Gutscheins, den dieser Konflikt betrifft.
    /// Dient der späteren automatischen Bereinigung (`cleanup`).
    pub voucher_valid_until: String,

    // Metadaten zum spezifischen Report dieses Beweises
    pub reporter_id: String,
    pub report_timestamp: String,

    /// Die Signatur des Erstellers (Reporters) über der `proof_id`, um die
    /// Authentizität dieses Reports zu bestätigen.
    pub reporter_signature: String,

    /// Eine Liste von Bestätigungen, die belegen, dass der Konflikt
    /// mit den Opfern beigelegt wurde. Kann `None` sein, wenn ungelöst.
    pub resolutions: Option<Vec<ResolutionEndorsement>>,

    /// Das optionale, signierte Urteil eines Layer-2-Dienstes.
    /// Wenn `Some`, überschreibt dieses Urteil die lokale "maximale Vorsicht"-Regel.
    #[serde(default)]
    pub layer2_verdict: Option<Layer2Verdict>,
}

/// Bestätigung durch ein Opfer, dass ein durch eine `proof_id` identifizierter
/// Konflikt beigelegt wurde.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolutionEndorsement {
    /// Die eindeutige ID dieser Bestätigung.
    /// Wird erzeugt durch Hashing der eigenen Metadaten (alles außer id/signatur),
    /// inklusive der `proof_id`, um eine kryptographische Kette zu bilden.
    pub endorsement_id: String,

    /// Die ID des Beweises, auf den sich diese Lösung bezieht. Stellt die
    /// kryptographische Verbindung zum Konflikt her.
    pub proof_id: String,

    /// Die ID des Opfers, das die Lösung bestätigt. Muss mit einem der
    /// `recipient_id`s aus den `conflicting_transactions` übereinstimmen.
    pub victim_id: String,

    /// Zeitstempel der Bestätigung.
    pub resolution_timestamp: String,

    /// Optionale Notiz, z.B. "Schaden wurde vollständig beglichen".
    pub notes: Option<String>,

    /// Die Signatur des Opfers über der `endorsement_id`. Bestätigt, dass
    /// das Opfer der Beilegung des durch `proof_id` bezeichneten Konflikts zustimmt.
    pub victim_signature: String,
}

//==============================================================================
// TEIL 3: SPEICHER-CONTAINER FÜR KONFLIKTBEWEISE
//==============================================================================

/// Dient als Speichercontainer für alle kryptographisch bewiesenen Double-Spend-Konflikte.
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct ProofStore {
    /// Eine Sammlung aller `ProofOfDoubleSpend`-Objekte.
    /// Der Key ist die deterministische `proof_id` des jeweiligen Konflikts.
    #[serde(default)]
    pub proofs: HashMap<String, ProofOfDoubleSpend>,
}

/// Repräsentiert das fälschungssichere Urteil eines Layer-2-Servers über einen Konflikt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Layer2Verdict {
    /// Die ID des Servers oder Gremiums, das das Urteil gefällt hat.
    pub server_id: String,
    /// Der Zeitstempel des Urteils.
    pub verdict_timestamp: String,
    /// Die `t_id` der Transaktion, die vom Server als "gültig" (weil zuerst gesehen) eingestuft wurde.
    pub valid_transaction_id: String,
    /// Die Signatur des Servers über dem Hash dieses Verdict-Objekts, um es fälschungssicher zu machen.
    pub server_signature: String,
}

