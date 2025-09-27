//! # tests/wallet_api/mod.rs
//!
//! Deklariert die Sub-Module für die API-Integrationstests.

pub mod general_workflows;
pub mod signature_workflows;

// Deklariert das neue Modul für komplexe Zustands- und Konflikttests.
mod state_management;
// Deklariert das neue Modul für Tests zur atomaren Zustandsverwaltung (Transaktionalität).
mod transactionality;
mod lifecycle_and_data;
mod hostile_bundles;
mod hostile_standards;
