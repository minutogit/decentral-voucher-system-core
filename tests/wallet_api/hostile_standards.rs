//! # tests/validation/hostile_standards.rs
//!
//! Enthält Tests, die das System gegen feindselige oder logisch inkonsistente
//! Gutschein-Standard-Definitionen härten.

use voucher_lib::{
    app_service::AppService,
    models::voucher::{Creator, NominalValue},
    services::voucher_manager::NewVoucherData,
    test_utils::{create_custom_standard, generate_valid_mnemonic, SILVER_STANDARD},
};
use tempfile::tempdir;

/// Test 1.1: Stellt sicher, dass ein Transfer fehlschlägt, wenn der Transaktionstyp
/// (`split`) laut Standard nicht erlaubt ist.
#[test]
fn test_disallowed_transaction_type() {
    // 1. ARRANGE: Standard erstellen, der "split" verbietet
    let (hostile_standard, _) = create_custom_standard(&SILVER_STANDARD.0, |s| {
        if let Some(validation) = &mut s.validation {
            if let Some(behavior) = &mut validation.behavior_rules {
                behavior.allowed_t_types = Some(vec!["init".to_string(), "transfer".to_string()]);
            }
        }
    });
    let hostile_standard_toml = toml::to_string(&hostile_standard).unwrap();

    let dir = tempdir().unwrap();
    let mut service = AppService::new(dir.path()).unwrap();
    let password = "password";
    service
        .create_profile(&generate_valid_mnemonic(), None, Some("test"), password)
        .unwrap();
    let user_id = service.get_user_id().unwrap();

    let voucher = service
        .create_new_voucher(
            &hostile_standard_toml,
            "en",
            NewVoucherData {
                creator: Creator { id: user_id, ..Default::default() },
                nominal_value: NominalValue { amount: "100".to_string(), ..Default::default() },
                ..Default::default()
            },
            password,
        )
        .unwrap();
    let local_id = service.get_voucher_summaries(None, None).unwrap()[0]
        .local_instance_id
        .clone();
    assert_eq!(voucher.voucher_standard.uuid, hostile_standard.metadata.uuid);

    // 2. ACT: Versuche einen Split-Transfer
    let result = service.create_transfer_bundle(
        &hostile_standard,
        &local_id,
        "recipient-id",
        "40", // Teilbetrag -> "split"
        None,
        None,
        password,
    );

    // 3. ASSERT: Operation muss fehlschlagen
    assert!(result.is_err());
    let error_string = result.unwrap_err();
    assert!(
        error_string.contains("type 'split' is not allowed"),
        "Error message should indicate that 'split' is not allowed. Got: {}",
        error_string
    );
}

/// Test 1.2: Stellt sicher, dass die Erstellung eines Gutscheins fehlschlägt, wenn die
/// angegebene Gültigkeitsdauer die im Standard definierte maximale Dauer überschreitet.
#[test]
fn test_violation_of_max_creation_validity() {
    // 1. ARRANGE: Standard mit maximaler Gültigkeit von 1 Jahr erstellen
    let (hostile_standard, _) = create_custom_standard(&SILVER_STANDARD.0, |s| {
        if let Some(validation) = &mut s.validation {
            if let Some(behavior) = &mut validation.behavior_rules {
                behavior.max_creation_validity_duration = Some("P1Y".to_string());
            }
        }
    });
    let hostile_standard_toml = toml::to_string(&hostile_standard).unwrap();

    let dir = tempdir().unwrap();
    let mut service = AppService::new(dir.path()).unwrap();
    let password = "password";
    service
        .create_profile(&generate_valid_mnemonic(), None, Some("test"), password)
        .unwrap();
    let user_id = service.get_user_id().unwrap();

    // 2. ACT: Versuche, einen Gutschein mit einer Gültigkeit von 2 Jahren zu erstellen
    let result = service.create_new_voucher(
        &hostile_standard_toml,
        "en",
        NewVoucherData {
            creator: Creator { id: user_id, ..Default::default() },
            nominal_value: NominalValue { amount: "100".to_string(), ..Default::default() },
            validity_duration: Some("P2Y".to_string()), // Länger als erlaubt
            ..Default::default()
        },
        password,
    );

    // 3. ASSERT: Operation muss fehlschlagen
    assert!(result.is_err());
    let error_string = result.unwrap_err();
    assert!(
        error_string.contains("validity duration is too long"),
        "Error message should indicate that validity is too long. Got: {}",
        error_string
    );
}