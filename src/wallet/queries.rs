//! # src/wallet/queries.rs
//!
//! Enthält die Implementierung der `Wallet`-Methoden, die als "View-Models"
//! dienen. Sie bereiten Daten für die Anzeige in Client-Anwendungen auf.

use super::{VoucherDetails, VoucherSummary, Wallet};
use crate::error::VoucherCoreError;
use crate::wallet::instance::VoucherStatus;
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
    pub fn list_vouchers(
        &self,
        voucher_standard_uuid_filter: Option<&[String]>,
        status_filter: Option<&[VoucherStatus]>,
    ) -> Vec<VoucherSummary> {
        self.voucher_store
            .vouchers
            .iter()
            .filter(|(_, instance)| {
                let uuid_match = match voucher_standard_uuid_filter {
                    // Wenn eine Liste von UUIDs vorhanden und nicht leer ist, prüfen, ob die des Gutscheins enthalten ist.
                    Some(uuids) if !uuids.is_empty() => {
                        uuids.contains(&instance.voucher.voucher_standard.uuid)
                    }
                    // Wenn keine Liste oder eine leere Liste übergeben wird, gilt der Filter als erfüllt.
                    _ => true,
                };

                let status_match = match status_filter {
                    // Gleiche Logik für den Status-Filter.
                    Some(statuses) if !statuses.is_empty() => statuses.contains(&instance.status),
                    _ => true,
                };

                uuid_match && status_match
            })
            .map(|(local_id, instance)| {
                let voucher = &instance.voucher;

                // Der aktuelle Betrag steht in der letzten Transaktion.
                // Bei einem Split ist es `sender_remaining_amount`, sonst `amount`.
                // Ein archivierter Gutschein hat für den Besitzer immer den Betrag 0.
                let current_amount = if matches!(instance.status, VoucherStatus::Archived) {
                    "0".to_string()
                } else {
                    voucher
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
                        .unwrap_or_else(|| "0".to_string())
                };

                VoucherSummary {
                    local_instance_id: local_id.clone(),
                    status: instance.status.clone(),
                    creator_id: voucher.creator.id.clone(),
                    valid_until: voucher.valid_until.clone(),
                    description: voucher.description.clone(),
                    current_amount,
                    unit: voucher.nominal_value.abbreviation.clone(),
                    voucher_standard_name: voucher.voucher_standard.name.clone(),
                    voucher_standard_uuid: voucher.voucher_standard.uuid.clone(),
                    // Zähle Transaktionen exkl. der initialen "init" Transaktion.
                    transaction_count: (voucher.transactions.len() as u32).saturating_sub(1),
                    guarantor_signatures_count: voucher.guarantor_signatures.len() as u32,
                    additional_signatures_count: voucher.additional_signatures.len() as u32,
                    // Ein Gutschein gilt als besichert, wenn das `type_`-Feld im `collateral`-Objekt nicht leer ist.
                    has_collateral: !voucher.collateral.type_.is_empty(),
                    creator_first_name: voucher.creator.first_name.clone(),
                    creator_last_name: voucher.creator.last_name.clone(),
                    creator_coordinates: voucher.creator.coordinates.clone(),
                    non_redeemable_test_voucher: voucher.non_redeemable_test_voucher,
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
        let instance = self
            .voucher_store
            .vouchers
            .get(local_instance_id)
            .ok_or_else(|| VoucherCoreError::VoucherNotFound(local_instance_id.to_string()))?;

        Ok(VoucherDetails {
            local_instance_id: instance.local_instance_id.clone(),
            status: instance.status.clone(),
            voucher: instance.voucher.clone(),
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

        for instance in self.voucher_store.vouchers.values() {
            if matches!(instance.status, VoucherStatus::Active) {
                let amount_str = instance
                    .voucher
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
                        .entry(instance.voucher.nominal_value.abbreviation.clone())
                        .or_insert_with(Decimal::zero) += amount;
                }
            }
        }

        balances
            .into_iter()
            .map(|(unit, total)| (unit, total.to_string()))
            .collect()
    }


    /// Gibt die User-ID des Wallet-Inhabers zurück.
    ///
    /// # Returns
    /// Eine Referenz auf die User-ID-Zeichenkette.
    pub fn get_user_id(&self) -> &str {
        &self.profile.user_id
    }
}