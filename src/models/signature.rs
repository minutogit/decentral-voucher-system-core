//! # src/models/signature.rs
//!
//! Definiert eine generische Wrapper-Struktur für losgelöste Signaturen,
//! die für den Signatur-Workflow benötigt wird.

use crate::models::voucher::{AdditionalSignature, GuarantorSignature};
use serde::{Deserialize, Serialize};

/// Ein Enum, das eine der möglichen losgelösten Signaturen kapselt.
///
/// Dies wird als Payload für den `SecureContainer` verwendet, wenn ein Unterzeichner
/// seine Signatur an den Gutschein-Ersteller zurücksendet. Durch diesen Wrapper
/// kann die `Wallet`-Logik agnostisch gegenüber dem spezifischen Signaturtyp bleiben.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum DetachedSignature {
    /// Kapselt eine `GuarantorSignature`.
    Guarantor(GuarantorSignature),
    /// Kapselt eine `AdditionalSignature`.
    Additional(AdditionalSignature),
}