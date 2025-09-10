//! # voucher_core
//!
//! Die Kernlogik eines dezentralen, vertrauensbasierten elektronischen Gutschein-Zahlungssystems.
//! Diese Bibliothek stellt die Datenstrukturen und Funktionen zur Erstellung, Verwaltung
//! und Verifizierung von digitalen Gutscheinen bereit.

// Deklariert die Hauptmodule der Bibliothek und macht sie öffentlich.
pub mod models;
pub mod error;
pub mod app_service;
pub mod archive;
pub mod storage;
pub mod wallet;
pub mod services;

// Re-exportiert die wichtigsten öffentlichen Typen für eine einfachere Nutzung.
// Anstatt `voucher_core::models::voucher::Voucher` können Benutzer nun `voucher_core::Voucher` schreiben.

// Modelle
pub use models::voucher::{
    Address, AdditionalSignature, Collateral, Creator, GuarantorSignature, NominalValue, Transaction,
    Voucher, VoucherStandard,
};
pub use models::voucher_standard_definition::{
    VoucherStandardDefinition,
};
pub use models::profile::{UserIdentity, UserProfile, VoucherStore};
pub use error::VoucherCoreError;

// Wallet & Storage Fassaden
pub use wallet::Wallet;
pub use storage::{Storage, AuthMethod, StorageError};
pub use storage::file_storage::FileStorage;

// Archive
pub use archive::{ArchiveError, VoucherArchive};
pub use archive::file_archive::FileVoucherArchive;

// Services
pub use services::crypto_utils;
pub use services::utils::to_canonical_json;
pub use services::utils;
pub use services::voucher_manager::{
    create_transaction, create_voucher, from_json, to_json, load_standard_definition, NewVoucherData
};
pub use services::voucher_validation::{
    get_spendable_balance, validate_voucher_against_standard
};
