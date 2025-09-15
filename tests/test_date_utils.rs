// In tests/test_date_utils.rs (oder einer anderen Test-Datei)

// HINWEIS: Damit diese Tests funktionieren, müssen die Hilfsfunktionen
// `add_iso8601_duration`, `round_up_date` etc. im Modul `voucher_manager`
// als `pub` oder `pub(crate)` deklariert werden, um von außerhalb sichtbar zu sein.

use voucher_lib::{
    services::{
        crypto_utils,
        voucher_manager::{self, create_voucher},
        voucher_validation::{validate_voucher_against_standard},
    },
    error::ValidationError,
    services::utils::to_canonical_json, // Behalte diesen Import, da er hier verwendet wird.
    NewVoucherData, VoucherCoreError,
};
use chrono::{DateTime, Utc};
mod test_utils;
use test_utils::{ACTORS, SILVER_STANDARD};

#[test]
fn test_iso8601_duration_date_math_correctness() {
    // Diese Testfälle wurden speziell entwickelt, um die Schwächen
    // der alten, vereinfachten Datumsberechnung aufzudecken.

    let test_cases = vec![
        // 1. Kritischer Fall: Monats-Überlauf
        // 31. Januar + 1 Monat sollte der 28. Februar sein, nicht der 2. März.
        ("2025-01-31T10:00:00Z", "P1M", "2025-02-28T10:00:00Z"),

        // 2. Kritischer Fall: Schaltjahr-Logik
        // 15. Feb 2024 (Schaltjahr) + 1 Jahr sollte der 15. Feb 2025 sein.
        // Die alte Logik (+365 Tage) würde auf den 14. Feb 2025 kommen.
        ("2024-02-15T10:00:00Z", "P1Y", "2025-02-15T10:00:00Z"),

        // 3. Kritischer Fall: Start am Schalttag
        // 29. Feb 2024 + 1 Jahr sollte auf den 28. Feb 2025 ausweichen.
        ("2024-02-29T10:00:00Z", "P1Y", "2025-02-28T10:00:00Z"),

        // 4. Standardfall Monat (zur Absicherung)
        ("2025-04-15T10:00:00Z", "P2M", "2025-06-15T10:00:00Z"),

        // 5. Standardfall Tag (zur Absicherung)
        ("2025-01-01T10:00:00Z", "P10D", "2025-01-11T10:00:00Z"),
    ];

    for (start_str, duration_str, expected_str) in test_cases {
        let start_date = DateTime::parse_from_rfc3339(start_str)
            .unwrap()
            .with_timezone(&Utc);

        let expected_date = DateTime::parse_from_rfc3339(expected_str)
            .unwrap()
            .with_timezone(&Utc);

        // Annahme: `add_iso8601_duration` ist für den Test aufrufbar.
        let result_date = voucher_manager::add_iso8601_duration(start_date, duration_str)
            .expect("Date calculation should not fail");

        // Wir vergleichen nur die Datums- und Zeit-Komponenten bis zur Sekunde,
        // um mögliche minimale Abweichungen in Nanosekunden zu ignorieren.
        assert_eq!(
            result_date.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            expected_date.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "Failed on test case: {} + {}",
            start_str,
            duration_str
        );
    }
}

#[test]
fn test_round_up_date_logic() {
    let test_cases = vec![
        // 1. Aufrunden auf das Ende des Tages
        ("2025-08-26T10:20:30Z", "P1D", "2025-08-26T23:59:59.999999999Z"),

        // 2. Aufrunden auf das Ende des Monats (31 Tage)
        ("2025-01-15T12:00:00Z", "P1M", "2025-01-31T23:59:59.999999999Z"),

        // 3. Aufrunden auf das Ende des Monats (Februar, kein Schaltjahr)
        ("2025-02-10T00:00:00Z", "P1M", "2025-02-28T23:59:59.999999999Z"),

        // 4. Randfall: Aufrunden am letzten Tag des Monats (Schaltjahr)
        ("2024-02-29T18:00:00Z", "P1M", "2024-02-29T23:59:59.999999999Z"),

        // 5. Aufrunden auf das Ende des Jahres
        ("2025-03-01T01:00:00Z", "P1Y", "2025-12-31T23:59:59.999999999Z"),

        // 6. Randfall: Aufrunden am letzten Tag des Jahres
        ("2025-12-31T23:00:00Z", "P1Y", "2025-12-31T23:59:59.999999999Z"),
    ];

    for (start_str, rounding_str, expected_str) in test_cases {
        let start_date = DateTime::parse_from_rfc3339(start_str).unwrap().with_timezone(&Utc);
        let expected_date = DateTime::parse_from_rfc3339(expected_str).unwrap().with_timezone(&Utc);

        // Annahme: `round_up_date` ist für den Test aufrufbar.
        let result_date = voucher_manager::round_up_date(start_date, rounding_str)
            .expect("Rounding calculation should not fail");

        assert_eq!(
            result_date,
            expected_date,
            "Failed on rounding case: {} with rule {}",
            start_str,
            rounding_str
        );
    }
}

#[test]
fn test_chronological_validation_with_timezones() {
    // 1. Setup
    let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
    let test_user = &ACTORS.test_user;

    let creator_data = voucher_lib::Creator {
        id: test_user.user_id.clone(),
        ..Default::default()
    };
    let voucher_data = NewVoucherData {
        validity_duration: Some("P3Y".to_string()),
        nominal_value: voucher_lib::models::voucher::NominalValue {
            amount: "100".to_string(),
            ..Default::default()
        },
        creator: creator_data,
        ..Default::default()
    };

    // KORREKTUR: Übergebe den korrekten `signing_key` vom Typ &SigningKey.
    let mut voucher = create_voucher(voucher_data, standard, standard_hash, &test_user.signing_key, "en").unwrap();

    // 2. Manipuliere den Zeitstempel der `init`-Transaktion so, dass er VOR dem Erstellungsdatum des Gutscheins liegt.
    // Die Validierung sollte dies als Fehler erkennen.
    voucher.transactions[0].t_time = "2020-01-01T00:00:00Z".to_string(); // Eindeutig in der Vergangenheit

    // Damit der Fehler isoliert wird, müssen wir die Transaktion neu hashen und signieren.
    let mut tx = voucher.transactions[0].clone();
    tx.t_id = "".to_string(); // Hash-relevante Felder zurücksetzen
    tx.sender_signature = "".to_string();
    tx.t_id = crypto_utils::get_hash(to_canonical_json(&tx).unwrap());
    let payload = serde_json::json!({ "prev_hash": tx.prev_hash, "sender_id": tx.sender_id, "t_id": tx.t_id });
    let signature_hash = crypto_utils::get_hash(to_canonical_json(&payload).unwrap());
    // KORREKTUR: Übergebe den korrekten `signing_key` vom Typ &SigningKey.
    tx.sender_signature = bs58::encode(crypto_utils::sign_ed25519(&test_user.signing_key, signature_hash.as_bytes()).to_bytes()).into_string();
    voucher.transactions[0] = tx;

    // 3. Validierung: Die Transaktionszeit (`2020`) liegt nun vor dem Erstellungsdatum (`~2025`).
    // Die Validierung muss dies als `InvalidTimeOrder` erkennen.
    let result = validate_voucher_against_standard(&voucher, standard);

    // Verbessere die Fehlerausgabe wie gewünscht.
    let err = result.expect_err("Validation should have failed but returned Ok");
    assert!(
        matches!(
            err, // Der Compiler schlägt die korrekte Syntax für ein struct variant vor.
            VoucherCoreError::Validation(ValidationError::InvalidTimeOrder { .. })
        ),
        "Expected InvalidTimeOrder, but got a different error: {:?}",
        err
    );
}