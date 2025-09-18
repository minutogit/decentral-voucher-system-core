// tests/core_logic/mod.rs

//! # Test-Modul für die Kernlogik
//!
//! Dieses Modul bündelt alle Tests, die sich auf die zentrale Geschäftslogik,
//! die mathematische Korrektheit von Transaktionen und die grundlegenden
//! Sicherheitsmechanismen konzentrieren.
//!
//! ## Enthaltene Module:
//!
//! - **`lifecycle`**: Tests den gesamten Lebenszyklus eines Gutscheins.
//! - **`math`**: Stellt die numerische Robustheit von Transaktionen sicher.
//! - **`security`**: Prüft auf Sicherheitslücken und die Double-Spend-Erkennung.

pub mod lifecycle;
pub mod math;
pub mod security;