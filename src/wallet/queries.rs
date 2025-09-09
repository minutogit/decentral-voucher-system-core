//! # src/wallet/queries.rs
//!
//! Enthält die Implementierung der `Wallet`-Methoden, die als "View-Models"
//! dienen. Sie bereiten Daten für die Anzeige in Client-Anwendungen auf.

use super::{VoucherDetails, VoucherSummary, Wallet};
use crate::error::VoucherCoreError;
use crate::models::profile::VoucherStatus;
use rust_decimal::Decimal;
use rust_decimal::prelude::Zero;
use std::collections::HashMap;
use std::str::FromStr;

/// View-Model / Komfort-Funktionen für Client-Anwendungen.
impl Wallet {
    /// Gibt eine Liste von Zusammenfassungen aller Gutscheine im Wallet zurück.
    ///
    /// Diese Methode ist ideal, um eine Übersicht aller Guthaben in einer UI anzuzeigen.
    ///
    /// # Returns
    /// Ein `Vec<VoucherSummary>` mit den wichtigsten Daten jedes Gutscheins.
    pub fn list_vouchers(&self) -> Vec<VoucherSummary> {
        self.voucher_store
            .vouchers
            .iter()
            .map(|(local_id, (voucher, status))| {
                // Der aktuelle Betrag steht in der letzten Transaktion.
                // Bei einem Split ist es `sender_remaining_amount`, sonst `amount`.
                let current_amount = voucher
                    .transactions
                    .last()
                    .map(|tx| {
                        if tx.sender_id == self.profile.user_id && tx.sender_remaining_amount.is_some()
                        {
                            tx.sender_remaining_amount
                                .clone()
                                .unwrap_or_else(|| "0".to_string())
                        } else {
                            tx.amount.clone()
                        }
                    })
                    .unwrap_or_else(|| "0".to_string());

                VoucherSummary {
                    local_instance_id: local_id.clone(),
                    status: status.clone(),
                    valid_until: voucher.valid_until.clone(),
                    description: voucher.description.clone(),
                    current_amount,
                    unit: voucher.nominal_value.unit.clone(),
                }
            })
            .collect()
    }

    /// Ruft eine detaillierte Ansicht für einen einzelnen Gutschein anhand seiner lokalen ID ab.
    ///
    /// # Arguments
    /// * `local_instance_id` - Die lokale ID des Gutscheins im Wallet.
    ///
    /// # Returns
    /// Ein `Result` mit `VoucherDetails` bei Erfolg oder `VoucherCoreError`, wenn
    /// der Gutschein nicht gefunden wird.
    pub fn get_voucher_details(
        &self,
        local_instance_id: &str,
    ) -> Result<VoucherDetails, VoucherCoreError> {
        let (voucher, status) = self
            .voucher_store
            .vouchers
            .get(local_instance_id)
            .ok_or_else(|| VoucherCoreError::VoucherNotFound(local_instance_id.to_string()))?;

        Ok(VoucherDetails {
            local_instance_id: local_instance_id.to_string(),
            status: status.clone(),
            voucher: voucher.clone(),
        })
    }

    /// Aggregiert die Guthaben aller aktiven Gutscheine, gruppiert nach Währung/Einheit.
    ///
    /// Diese Funktion summiert die Werte aller Gutscheine mit dem Status `Active` auf
    /// und gibt eine Map zurück, die von der Währungseinheit (z.B. "Minuten", "EUR")
    /// auf den Gesamtbetrag abbildet.
    ///
    /// # Returns
    /// Eine `HashMap<String, String>`, die die Gesamtsummen pro Währung enthält.
    pub fn get_total_balance_by_currency(&self) -> HashMap<String, String> {
        let mut balances: HashMap<String, Decimal> = HashMap::new();

        for (_, (voucher, status)) in self.voucher_store.vouchers.iter() {
            if *status == VoucherStatus::Active {
                let amount_str = voucher
                    .transactions
                    .last()
                    .map(|tx| {
                        if tx.sender_id == self.profile.user_id
                            && tx.sender_remaining_amount.is_some()
                        {
                            tx.sender_remaining_amount
                                .clone()
                                .unwrap_or_else(|| "0".to_string())
                        } else {
                            tx.amount.clone()
                        }
                    })
                    .unwrap_or_else(|| "0".to_string());

                if let Ok(amount) = Decimal::from_str(&amount_str) {
                    *balances
                        .entry(voucher.nominal_value.unit.clone())
                        .or_insert_with(Decimal::zero) += amount;
                }
            }
        }

        balances
            .into_iter()
            .map(|(unit, total)| (unit, total.to_string()))
            .collect()
    }
}