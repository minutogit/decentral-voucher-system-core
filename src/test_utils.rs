//! # src/test_utils.rs
//!
//! HINWEIS: Diese Datei wurde stark refaktorisiert, um die Mnemonic-Phrasen der Test-Akteure für die neuen APIs verfügbar zu machen.
//! Zentrale Hilfsfunktionen für alle Tests (intern und extern).

// HINWEIS: Absoluter Pfad zu externen Crates für mehr Robustheit
use lazy_static::lazy_static;
use toml;
use bip39::{Language};
use ed25519_dalek::Signer;
use std::path::Path;
use std::path::PathBuf;

// HINWEIS: Alle `voucher_lib` Imports wurden zu `crate` geändert.
use crate::models::{
    conflict::{FingerprintStore, ProofStore},
    profile::{BundleMetadataStore, UserProfile, VoucherStore},
    signature::DetachedSignature,
    voucher::{
        Address, Collateral, Creator, GuarantorSignature, NominalValue, Transaction,
    },
    voucher_standard_definition::{SignatureBlock, VoucherStandardDefinition},
};
use crate::services::{
    bundle_processor,
    crypto_utils::{self, create_user_id, get_hash, generate_ed25519_keypair_for_tests, sign_ed25519},
    secure_container_manager,
    signature_manager,
    utils::to_canonical_json,
    voucher_manager::{create_transaction, create_voucher, NewVoucherData},
};
use crate::wallet::Wallet;
use crate::{models::voucher::Voucher, UserIdentity, VoucherCoreError, VoucherInstance, VoucherStatus};
use crate::app_service::{AppService, ProfileInfo};
use std::ops::Deref;

/// Bündelt alle Informationen eines Test-Benutzers.
/// Enthält die Mnemonic, die für `FileStorage::new` und `login` benötigt wird.
#[derive(Clone)]
pub struct TestUser {
    pub identity: UserIdentity,
    pub mnemonic: String,
    pub passphrase: Option<&'static str>,
    pub prefix: Option<&'static str>,
}

impl Deref for TestUser {
    type Target = UserIdentity;

    fn deref(&self) -> &Self::Target {
        &self.identity
    }
}

/// Erstellt eine `TestUser`-Instanz mit der langsamen, produktionssicheren Schlüsselableitung.
/// Notwendig für Tests, die Passphrasen oder die Recovery-Logik verifizieren.
fn user_from_mnemonic_slow(
    mnemonic: &str,
    passphrase: Option<&'static str>,
    prefix: Option<&'static str>,
) -> TestUser {
    // HINWEIS: Dies ist absichtlich die "langsame" Funktion, um sicherzustellen, dass die Tests
    // exakt dieselbe kryptographische Logik wie der Produktionscode verwenden.
    let (public_key, signing_key) = crypto_utils::derive_ed25519_keypair(mnemonic, passphrase)
        .expect("Failed to derive keypair from test mnemonic");

    let user_id = create_user_id(&public_key, prefix).unwrap();

    let identity = UserIdentity {
        signing_key,
        public_key,
        user_id,
    };

    TestUser {
        identity,
        mnemonic: mnemonic.to_string(),
        passphrase,
        prefix,
    }
}

/// Erstellt eine `TestUser`-Instanz mit der schnellen, nur für Tests gedachten Schlüsselableitung.
/// Hält die meisten Tests performant. Ignoriert Passphrasen.
fn user_from_mnemonic_fast(mnemonic: &str, prefix: Option<&'static str>) -> TestUser {
    let (public_key, signing_key) =
        crypto_utils::generate_ed25519_keypair_for_tests(Some(mnemonic));

    let user_id = create_user_id(&public_key, prefix).unwrap();

    let identity = UserIdentity {
        signing_key,
        public_key,
        user_id,
    };

    TestUser {
        identity,
        mnemonic: mnemonic.to_string(),
        passphrase: None, // Passphrase wird von der schnellen Methode nicht verwendet.
        prefix,
    }
}

/// Feste, deterministische Mnemonics für reproduzierbare Tests.
mod mnemonics {
    pub const ALICE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    pub const BOB: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    pub const CHARLIE: &str = "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";
    pub const DAVID: &str = "brother offer escape switch virtual school pet quiz point hurdle boil popular";
    pub const HACKER: &str = "clog cloud attitude around people thought sad will cute police feature junior";
    // HINZUGEFÜGT: Fehlende Mnemonics für Konsistenz
    pub const REPORTER: &str = "travel shell spy arctic clarify velvet wrist cigar jewel vintage life head";
}

/// Eine Struktur, die alle für Tests benötigten, einmalig erstellten Identitäten enthält.
#[allow(dead_code)]
pub struct TestActors {
    pub alice: TestUser,
    pub bob: TestUser,
    pub charlie: TestUser,
    pub david: TestUser,
    pub issuer: TestUser,
    pub hacker: TestUser,
    pub guarantor1: TestUser,
    pub guarantor2: TestUser,
    pub male_guarantor: TestUser,
    pub female_guarantor: TestUser,
    pub sender: TestUser,
    pub recipient1: TestUser,
    pub recipient2: TestUser,
    pub test_user: TestUser,
    pub victim: TestUser,
    pub reporter: TestUser,
}

lazy_static! {
    /// Ein deterministischer Herausgeber, der zum Signieren der Test-Standards verwendet wird.
    pub static ref TEST_ISSUER: TestUser = user_from_mnemonic_fast(
        "seek ethics foam novel hat faculty royal donkey burger frost advice visa",
        Some("issuer")
    );
}

lazy_static! {
    /// Initialisiert einmalig alle Akteure, sodass sie in allen Tests wiederverwendet werden können.
    pub static ref ACTORS: TestActors = TestActors {
        // Alice wird in Krypto-Tests verwendet und MUSS die langsame Ableitung nutzen
        alice: user_from_mnemonic_slow(mnemonics::ALICE, None, Some("al")),
        bob: user_from_mnemonic_fast(mnemonics::BOB, Some("bo")),
        charlie: user_from_mnemonic_fast(mnemonics::CHARLIE, Some("ch")),
        david: user_from_mnemonic_fast(mnemonics::DAVID, Some("da")),
        issuer: user_from_mnemonic_fast(mnemonics::BOB, Some("is")), // Re-use a known-good one
        guarantor1: user_from_mnemonic_fast(&generate_valid_mnemonic(), Some("g1")),
        guarantor2: user_from_mnemonic_fast(&generate_valid_mnemonic(), Some("g2")),
        male_guarantor: user_from_mnemonic_fast(&generate_valid_mnemonic(), Some("mg")),
        female_guarantor: user_from_mnemonic_fast(&generate_valid_mnemonic(), Some("fg")),
        sender: user_from_mnemonic_fast(&generate_valid_mnemonic(), Some("se")),
        recipient1: user_from_mnemonic_fast(&generate_valid_mnemonic(), Some("r1")),
        recipient2: user_from_mnemonic_fast(&generate_valid_mnemonic(), Some("r2")),
        victim: user_from_mnemonic_fast(&generate_valid_mnemonic(), Some("vi")),
        reporter: user_from_mnemonic_fast(mnemonics::REPORTER, Some("reporter")),

        // Diese Akteure MÜSSEN die langsame, produktionsgetreue Ableitung verwenden
        hacker: user_from_mnemonic_slow(mnemonics::HACKER, Some("wrong"), Some("ha")),
        test_user: user_from_mnemonic_slow(&generate_valid_mnemonic(), Some("pass"), Some("tu")),
    };

    /// Ein deterministischer Herausgeber, der zum Signieren der Test-Standards verwendet wird.

    /// Lädt den Minuto-Standard und signiert ihn zur Laufzeit für die Tests.
    pub static ref MINUTO_STANDARD: (VoucherStandardDefinition, String) = {
        let issuer = &TEST_ISSUER;
        let toml_str = include_str!("../voucher_standards/minuto_v1/standard.toml");

        let mut standard: VoucherStandardDefinition = toml::from_str(toml_str)
            .expect("Failed to parse Minuto TOML template for tests");

        standard.signature = None;
        let canonical_json_for_signing = to_canonical_json(&standard)
            .expect("Failed to create canonical JSON for Minuto standard");
        let hash_to_sign = get_hash(canonical_json_for_signing.as_bytes());

        let signature = sign_ed25519(&issuer.identity.signing_key, hash_to_sign.as_bytes());
        let signature_block = SignatureBlock {
            issuer_id: issuer.identity.user_id.clone(),
            signature: bs58::encode(signature.to_bytes()).into_string(),
        };
        standard.signature = Some(signature_block);
        (standard, hash_to_sign)
    };

    /// Lädt den Silber-Standard und signiert ihn zur Laufzeit für die Tests.
    pub static ref SILVER_STANDARD: (VoucherStandardDefinition, String) = {
        let issuer = &TEST_ISSUER;
        let toml_str = include_str!("../voucher_standards/silver_v1/standard.toml");

        let mut standard: VoucherStandardDefinition = toml::from_str(toml_str)
            .expect("Failed to parse Silver TOML template for tests");

        standard.signature = None;
        let canonical_json = to_canonical_json(&standard).unwrap();
        let hash = get_hash(canonical_json.as_bytes());
        let signature = sign_ed25519(&issuer.identity.signing_key, hash.as_bytes());
        standard.signature = Some(SignatureBlock { issuer_id: issuer.identity.user_id.clone(), signature: bs58::encode(signature.to_bytes()).into_string() });
        (standard, hash)
    };

    /// Lädt den `required_signatures`-Test-Standard und signiert ihn zur Laufzeit.
    pub static ref REQUIRED_SIG_STANDARD: (VoucherStandardDefinition, String) = {
        let issuer = &TEST_ISSUER;
        // HINWEIS: Pfad wurde angepasst, um von `src/` aus zu funktionieren.
        let toml_str = include_str!("../tests/test_data/standards/standard_required_signatures.toml");

        let mut standard: VoucherStandardDefinition = toml::from_str(toml_str)
            .expect("Failed to parse Required Sig TOML template for tests");

        // HINZUGEFÜGT: Korrigiere die hartkodierten, veralteten User-IDs in den Validierungsregeln.
        // Die TOML-Datei enthält `did:key:...`-Strings ohne Prüfsumme. Wir ersetzen sie hier im Speicher
        // durch die korrekte, zur Laufzeit generierte User-ID unseres Test-Herausgebers.
        if let Some(validation) = standard.validation.as_mut() {
            if let Some(sig_rules) = validation.required_signatures.as_mut() {
                for rule in sig_rules.iter_mut() {
                    // Wir aktualisieren alle Regeln, um sicherzustellen, dass sie die neue User-ID verwenden.
                    // Dadurch wird der Vergleich in `validate_required_signatures` erfolgreich sein.
                    rule.allowed_signer_ids = vec![issuer.identity.user_id.clone()];
                }
            }
        }

        standard.signature = None;
        let canonical_json_for_signing = to_canonical_json(&standard)
            .expect("Failed to create canonical JSON for Required Sig standard");
        let hash_to_sign = get_hash(canonical_json_for_signing.as_bytes());

        let signature = sign_ed25519(&issuer.identity.signing_key, hash_to_sign.as_bytes());
        let signature_block = SignatureBlock {
            issuer_id: issuer.identity.user_id.clone(),
            signature: bs58::encode(signature.to_bytes()).into_string(),
        };
        standard.signature = Some(signature_block);
        (standard, hash_to_sign)
    };
}

#[allow(dead_code)]
pub fn generate_valid_mnemonic() -> String {
    crypto_utils::generate_mnemonic(12, Language::English)
        .expect("Test mnemonic generation should not fail")
}

#[allow(dead_code)]
pub fn generate_signed_standard_toml(template_path: &str) -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let mut absolute_path = PathBuf::from(manifest_dir);
    absolute_path.push(template_path);

    let issuer = &crate::test_utils::TEST_ISSUER;
    let toml_str = std::fs::read_to_string(&absolute_path)
        .unwrap_or_else(|e| panic!("Failed to read TOML template at '{:?}': {}", absolute_path, e));

    let mut standard: VoucherStandardDefinition = toml::from_str(&toml_str)
        .expect("Failed to parse TOML template for signing");

    standard.signature = None;
    let canonical_json_for_signing = to_canonical_json(&standard)
        .expect("Failed to create canonical JSON for standard");
    let hash_to_sign = get_hash(canonical_json_for_signing.as_bytes());

    let signature = sign_ed25519(&issuer.identity.signing_key, hash_to_sign.as_bytes());
    let signature_block = SignatureBlock {
        issuer_id: issuer.identity.user_id.clone(),
        signature: bs58::encode(signature.to_bytes()).into_string(),
    };
    standard.signature = Some(signature_block);

    toml::to_string(&standard).expect("Failed to serialize standard back to TOML string")
}

#[allow(dead_code)]
pub fn create_custom_standard(
    base_standard: &VoucherStandardDefinition,
    modifier: impl FnOnce(&mut VoucherStandardDefinition),
) -> (VoucherStandardDefinition, String) {
    let mut standard = base_standard.clone();
    modifier(&mut standard);

    standard.signature = None;
    let canonical_json = to_canonical_json(&standard).unwrap();
    let hash = get_hash(canonical_json.as_bytes());

    let signature = crate::test_utils::TEST_ISSUER.identity.signing_key.sign(hash.as_bytes());

    standard.signature = Some(crate::models::voucher_standard_definition::SignatureBlock {
        issuer_id: crate::test_utils::TEST_ISSUER.identity.user_id.clone(),
        signature: bs58::encode(signature.to_bytes()).into_string(),
    });

    (standard, hash)
}

#[allow(dead_code)]
pub fn setup_voucher_with_one_tx() -> (
    &'static VoucherStandardDefinition,
    String,
    &'static UserIdentity,
    &'static UserIdentity,
    Voucher,
) {
    let (standard, standard_hash) = (&crate::test_utils::SILVER_STANDARD.0, &crate::test_utils::SILVER_STANDARD.1);
    let creator = &crate::test_utils::ACTORS.alice.identity;
    let recipient = &crate::test_utils::ACTORS.bob.identity;

    let voucher_data = NewVoucherData {
        creator: Creator { id: creator.user_id.clone(), ..Default::default() },
        nominal_value: NominalValue { amount: "100.0000".to_string(), ..Default::default() },
        validity_duration: Some("P4Y".to_string()),
        ..Default::default()
    };

    let initial_voucher = create_voucher(voucher_data, standard, standard_hash, &creator.signing_key, "en").unwrap();

    let voucher_after_tx1 = create_transaction(
        &initial_voucher, standard, &creator.user_id, &creator.signing_key,
        &recipient.user_id, "40.0000",
    )
        .unwrap();

    (standard, standard_hash.to_string(), creator, recipient, voucher_after_tx1)
}

#[allow(dead_code)]
pub fn setup_in_memory_wallet(identity: &UserIdentity) -> Wallet {
    let profile = UserProfile {
        user_id: identity.user_id.clone(),
    };
    Wallet {
        profile,
        voucher_store: VoucherStore::default(),
        bundle_meta_store: BundleMetadataStore::default(),
        fingerprint_store: FingerprintStore::default(),
        proof_store: ProofStore::default(),
    }
}

#[allow(dead_code)]
pub fn create_test_wallet(
    seed_phrase_extra: &str,
) -> Result<(Wallet, UserIdentity), VoucherCoreError> {
    let (public_key, signing_key) =
        generate_ed25519_keypair_for_tests(Some(seed_phrase_extra));
    let user_id = create_user_id(&public_key, Some("test"))
        .map_err(|e| VoucherCoreError::Crypto(e.to_string()))?;

    let identity = UserIdentity {
        signing_key,
        public_key,
        user_id: user_id.clone(),
    };

    let profile = UserProfile { user_id };

    let wallet = Wallet {
        profile,
        voucher_store: VoucherStore::default(),
        bundle_meta_store: BundleMetadataStore::default(),
        fingerprint_store: FingerprintStore::default(),
        proof_store: ProofStore::default(),
    };

    Ok((wallet, identity))
}

#[allow(dead_code)]
pub fn add_voucher_to_wallet(
    wallet: &mut Wallet,
    identity: &UserIdentity,
    amount: &str,
    standard: &VoucherStandardDefinition,
    with_valid_guarantors: bool,
) -> Result<String, VoucherCoreError> {
    let creator_info = Creator {
        id: identity.user_id.clone(),
        first_name: "Test".to_string(),
        last_name: "User".to_string(),
        address: Address::default(),
        ..Default::default()
    };

    let nominal_value_info = NominalValue {
        amount: amount.to_string(),
        ..Default::default()
    };

    let new_voucher_data = NewVoucherData {
        creator: creator_info,
        nominal_value: nominal_value_info,
        validity_duration: Some("P4Y".to_string()),
        ..Default::default()
    };

    let mut standard_to_hash = standard.clone();
    standard_to_hash.signature = None;
    let standard_hash = get_hash(to_canonical_json(&standard_to_hash)?);

    let mut voucher = create_voucher_for_manipulation(new_voucher_data, standard, &standard_hash, &identity.signing_key, "en");

    if with_valid_guarantors {
        let sig_data1 =
            create_guarantor_signature_data(&crate::test_utils::ACTORS.guarantor1.identity, "1", &voucher.voucher_id);
        let sig_data2 =
            create_guarantor_signature_data(&crate::test_utils::ACTORS.guarantor2.identity, "2", &voucher.voucher_id);

        let signed_sig1 = signature_manager::complete_and_sign_detached_signature(
            sig_data1,
            &voucher.voucher_id,
            &crate::test_utils::ACTORS.guarantor1.identity,
        )?;
        let signed_sig2 = signature_manager::complete_and_sign_detached_signature(
            sig_data2,
            &voucher.voucher_id,
            &crate::test_utils::ACTORS.guarantor2.identity,
        )?;

        if let DetachedSignature::Guarantor(s) = signed_sig1 {
            voucher.guarantor_signatures.push(s);
        }
        if let DetachedSignature::Guarantor(s) = signed_sig2 {
            voucher.guarantor_signatures.push(s);
        }
    }

    let local_id = Wallet::calculate_local_instance_id(&voucher, &identity.user_id)?;
    wallet
        .voucher_store
        .vouchers
        .insert(local_id.clone(), VoucherInstance {
            voucher: voucher.clone(),
            status: VoucherStatus::Active,
            local_instance_id: local_id.clone(),
        });


    Ok(local_id.clone())
}

/// Eine zentrale Hilfsfunktion, um einen `AppService` zu instanziieren
/// und direkt ein Profil darin zu erstellen.
///
/// Diese Funktion kapselt den korrekten, mehrstufigen Prozess des Profil-Managements
/// und gibt alle notwendigen Informationen für nachfolgende Testschritte zurück.
///
/// # Returns
/// Ein Tupel `(AppService, ProfileInfo)`, wobei:
/// - `AppService` die entsperrte Service-Instanz ist.
/// - `ProfileInfo` die Metadaten des erstellten Profils enthält (inkl. `folder_name`).
#[allow(dead_code)]
pub fn setup_service_with_profile(
    base_path: &Path,
    user: &TestUser,
    profile_name: &str,
    password: &str,
) -> (AppService, ProfileInfo) {
    let mut service = AppService::new(base_path).expect("Failed to create AppService in test setup");

    service
        .create_profile(profile_name, &user.mnemonic, user.passphrase, user.prefix, password)
        .unwrap_or_else(|e| panic!("Failed to create profile '{}' in test setup: {}", profile_name, e));

    let profile_info = service.list_profiles().expect("Failed to list profiles after creation")
        .into_iter().find(|p| p.profile_name == profile_name)
        .expect("Could not find freshly created profile in index");

    (service, profile_info)
}

pub fn create_guarantor_signature_data(
    guarantor_identity: &UserIdentity,
    gender: &str,
    voucher_id: &str,
) -> DetachedSignature {
    let data = GuarantorSignature {
        guarantor_id: guarantor_identity.user_id.clone(),
        first_name: "Guarantor".to_string(),
        last_name: "Test".to_string(),
        gender: gender.to_string(),
        voucher_id: voucher_id.to_string(),
        signature_id: String::new(),
        signature: String::new(),
        signature_time: String::new(),
        organization: None,
        community: None,
        address: None,
        email: None,
        phone: None,
        coordinates: None,
        url: None,
    };
    DetachedSignature::Guarantor(data)
}

#[allow(dead_code)]
pub fn create_additional_signature_data(
    signer_identity: &UserIdentity,
    voucher_id: &str,
    description: &str,
) -> DetachedSignature {
    let data = crate::models::voucher::AdditionalSignature {
        voucher_id: voucher_id.to_string(),
        signature_id: String::new(),
        signer_id: signer_identity.user_id.clone(),
        signature: String::new(),
        signature_time: String::new(),
        description: description.to_string(),
    };
    DetachedSignature::Additional(data)
}

#[allow(dead_code)]
pub fn debug_open_container(
    container_bytes: &[u8],
    recipient_identity: &UserIdentity,
) -> Result<(Voucher, String), VoucherCoreError> {
    let container: crate::models::secure_container::SecureContainer =
        serde_json::from_slice(container_bytes)?;
    let (payload, _) =
        secure_container_manager::open_secure_container(&container, recipient_identity)?;
    let voucher: Voucher = serde_json::from_slice(&payload)?;
    let sender_id = container.sender_id;
    Ok((voucher, sender_id))
}

#[allow(dead_code)]
pub fn create_minuto_voucher_data(creator: Creator) -> NewVoucherData {
    NewVoucherData {
        validity_duration: Some("P4Y".to_string()),
        non_redeemable_test_voucher: true,
        nominal_value: NominalValue {
            unit: "".to_string(),
            amount: "60".to_string(),
            abbreviation: "".to_string(),
            description: "Qualitative Leistung".to_string(),
        },
        collateral: Collateral {
            type_: "".to_string(),
            unit: "".to_string(),
            amount: "".to_string(),
            abbreviation: "".to_string(),
            description: "".to_string(),
            redeem_condition: "".to_string(),
        },
        creator,
    }
}

#[allow(dead_code)]
pub fn create_voucher_for_manipulation(
    data: NewVoucherData,
    standard: &VoucherStandardDefinition,
    standard_hash: &str,
    signing_key: &ed25519_dalek::SigningKey,
    lang_preference: &str,
) -> Voucher {
    let creation_date_str = crate::services::utils::get_current_timestamp();
    let creation_dt = chrono::DateTime::parse_from_rfc3339(&creation_date_str).unwrap();
    let duration_str = data.validity_duration.as_deref().unwrap_or_else(|| {
        panic!(
            "Test voucher creation requires a validity_duration. Voucher details: creator='{}', amount='{}'",
            data.creator.id, data.nominal_value.amount
        )
    });
    let mut valid_until_dt = crate::services::voucher_manager::add_iso8601_duration(creation_dt.into(), duration_str)
        .expect("Failed to calculate validity in test helper");

    if let Some(rule) = &standard.template.fixed.round_up_validity_to {
        if rule == "end_of_year" {
            use chrono::{Datelike, TimeZone};
            let rounded_date = chrono::NaiveDate::from_ymd_opt(valid_until_dt.year(), 12, 31).unwrap();
            let rounded_time = chrono::NaiveTime::from_hms_micro_opt(23, 59, 59, 999_999).unwrap();
            valid_until_dt = chrono::Utc.from_utc_datetime(&rounded_date.and_time(rounded_time));
        }
    }

    let valid_until = valid_until_dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);

    let mut nonce_bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
    let voucher_nonce = bs58::encode(nonce_bytes).into_string();

    let description_template = crate::services::standard_manager::get_localized_text(
        &standard.template.fixed.description,
        lang_preference,
    ).unwrap_or("");
    let final_description = description_template.replace("{{amount}}", &data.nominal_value.amount);

    let mut final_nominal_value = data.nominal_value;
    final_nominal_value.unit = standard.template.fixed.nominal_value.unit.clone();
    final_nominal_value.abbreviation = standard.metadata.abbreviation.clone();

    let final_collateral = if !standard.template.fixed.collateral.type_.is_empty() {
        crate::models::voucher::Collateral {
            type_: standard.template.fixed.collateral.type_.clone(),
            description: standard.template.fixed.collateral.description.clone(),
            redeem_condition: standard.template.fixed.collateral.redeem_condition.clone(),
            ..data.collateral
        }
    } else {
        crate::models::voucher::Collateral::default()
    };

    let mut voucher = Voucher {
        voucher_standard: crate::models::voucher::VoucherStandard {
            name: standard.metadata.name.clone(),
            uuid: standard.metadata.uuid.clone(),
            standard_definition_hash: standard_hash.to_string(),
        },
        voucher_id: "".to_string(), voucher_nonce, description: final_description,
        primary_redemption_type: "goods_or_services".to_string(),
        divisible: standard.template.fixed.is_divisible, creation_date: creation_date_str.clone(), valid_until,
        standard_minimum_issuance_validity: standard.validation.as_ref().and_then(|v| v.behavior_rules.as_ref()).and_then(|b| b.issuance_minimum_validity_duration.clone()).unwrap_or_default(),
        non_redeemable_test_voucher: false, nominal_value: final_nominal_value, collateral: final_collateral,
        creator: data.creator, guarantor_requirements_description: standard.template.fixed.guarantor_info.description.clone(), footnote: standard.template.fixed.footnote.clone().unwrap_or_default(),
        guarantor_signatures: vec![], needed_guarantors: standard.template.fixed.guarantor_info.needed_count, transactions: vec![], additional_signatures: vec![],
    };

    let mut voucher_to_hash = voucher.clone();
    voucher_to_hash.creator.signature = "".to_string(); voucher_to_hash.voucher_id = "".to_string();
    voucher_to_hash.transactions.clear();
    voucher_to_hash.guarantor_signatures.clear();
    voucher_to_hash.additional_signatures.clear();
    let voucher_json = to_canonical_json(&voucher_to_hash).unwrap();
    let voucher_hash = crypto_utils::get_hash(voucher_json);
    voucher.voucher_id = voucher_hash.clone();
    let signature = crypto_utils::sign_ed25519(signing_key, voucher_hash.as_bytes());
    voucher.creator.signature = bs58::encode(signature.to_bytes()).into_string();

    let prev_hash = crypto_utils::get_hash(format!("{}{}", &voucher.voucher_id, &voucher.voucher_nonce));
    let init_tx = Transaction { t_id: "".to_string(), prev_hash, t_type: "init".to_string(), t_time: creation_date_str, sender_id: voucher.creator.id.clone(), recipient_id: voucher.creator.id.clone(), amount: voucher.nominal_value.amount.clone(), sender_remaining_amount: None, sender_signature: "".to_string() };
    voucher.transactions.push(resign_transaction(init_tx, signing_key));
    voucher
}

#[allow(dead_code)]
pub fn create_guarantor_signature_with_time(
    voucher_id: &str,
    guarantor_identity: &UserIdentity,
    guarantor_first_name: &str,
    guarantor_gender: &str,
    signature_time: &str,
) -> GuarantorSignature {
    let mut signature_data = GuarantorSignature {
        voucher_id: voucher_id.to_string(),
        signature_id: "".to_string(),
        guarantor_id: guarantor_identity.user_id.clone(),
        first_name: guarantor_first_name.to_string(),
        last_name: "Guarantor".to_string(),
        gender: guarantor_gender.to_string(),
        signature_time: signature_time.to_string(),
        ..Default::default()
    };

    let mut data_for_id_hash = signature_data.clone();
    data_for_id_hash.signature_id = "".to_string();
    data_for_id_hash.signature = "".to_string();
    signature_data.signature_id = get_hash(to_canonical_json(&data_for_id_hash).unwrap());

    let digital_signature = sign_ed25519(&guarantor_identity.signing_key, signature_data.signature_id.as_bytes());
    signature_data.signature = bs58::encode(digital_signature.to_bytes()).into_string();
    signature_data
}

#[allow(dead_code)]
pub fn create_guarantor_signature(
    voucher: &Voucher,
    guarantor_identity: &UserIdentity,
    guarantor_first_name: &str,
    guarantor_gender: &str,
) -> GuarantorSignature {
    let creation_dt = chrono::DateTime::parse_from_rfc3339(&voucher.creation_date).unwrap();
    let signature_time = (creation_dt + chrono::Duration::days(1)).to_rfc3339();
    create_guarantor_signature_with_time(
        &voucher.voucher_id,
        guarantor_identity,
        guarantor_first_name,
        guarantor_gender,
        &signature_time,
    )
}

#[allow(dead_code)]
pub fn create_male_guarantor_signature(voucher: &Voucher) -> GuarantorSignature {
    let creation_dt = chrono::DateTime::parse_from_rfc3339(&voucher.creation_date).unwrap();
    let signature_time = (creation_dt + chrono::Duration::days(1)).to_rfc3339();
    create_guarantor_signature_with_time(&voucher.voucher_id, &crate::test_utils::ACTORS.male_guarantor.identity, "Martin", "1", &signature_time)
}

#[allow(dead_code)]
pub fn create_female_guarantor_signature(voucher: &Voucher) -> GuarantorSignature {
    let creation_dt = chrono::DateTime::parse_from_rfc3339(&voucher.creation_date).unwrap();
    let signature_time = (creation_dt + chrono::Duration::days(2)).to_rfc3339();
    create_guarantor_signature_with_time(&voucher.voucher_id, &crate::test_utils::ACTORS.female_guarantor.identity, "Frida", "2", &signature_time)
}

#[allow(dead_code)]
pub fn resign_transaction(
    mut tx: Transaction,
    signer_key: &ed25519_dalek::SigningKey,
) -> Transaction {
    tx.t_id = "".to_string();
    tx.sender_signature = "".to_string();
    tx.t_id = crypto_utils::get_hash(to_canonical_json(&tx).unwrap());
    let payload = serde_json::json!({
        "prev_hash": tx.prev_hash,
        "sender_id": tx.sender_id,
        "t_id": tx.t_id
    });
    let signature_hash = crypto_utils::get_hash(to_canonical_json(&payload).unwrap());
    tx.sender_signature = bs58::encode(
        crypto_utils::sign_ed25519(signer_key, signature_hash.as_bytes()).to_bytes(),
    )
        .into_string();
    tx
}

#[allow(dead_code)]
pub fn create_test_bundle(
    sender_identity: &UserIdentity,
    vouchers: Vec<Voucher>,
    recipient_id: &str,
    message: Option<&str>,
) -> Result<Vec<u8>, VoucherCoreError> {
    let result = bundle_processor::create_and_encrypt_bundle(
        sender_identity,
        vouchers,
        recipient_id,
        message.map(|s| s.to_string()),
    )?;
    Ok(result.0)
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Datelike, Timelike, Utc};
    use regex::Regex;
    use crate::services::utils::{get_current_timestamp, get_timestamp};

    // Helper function to parse the timestamp string and check basic format
    fn parse_and_validate_format(timestamp_str: &str) -> Result<DateTime<Utc>, String> {
        let re = Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$").unwrap();
        if !re.is_match(timestamp_str) {
            return Err(format!("Timestamp '{}' does not match expected format YYYY-MM-DDTHH:MM:SS.ffffffZ", timestamp_str));
        }

        DateTime::parse_from_rfc3339(timestamp_str)
            .map(|dt| dt.with_timezone(&Utc))
            .map_err(|e| format!("Failed to parse timestamp '{}': {}", timestamp_str, e))
    }

    #[test]
    fn test_get_current_timestamp_format() {
        let timestamp = get_current_timestamp();
        println!("Current Timestamp: {}", timestamp);
        assert!(parse_and_validate_format(&timestamp).is_ok());
    }

    #[test]
    fn test_get_timestamp_add_years() {
        let years_to_add = 2;
        let now = Utc::now();
        let expected_year = now.year() + years_to_add;

        let timestamp = get_timestamp(years_to_add, false);
        println!("Timestamp (+{} years): {}", years_to_add, timestamp);
        let parsed_dt = parse_and_validate_format(&timestamp).expect("Timestamp should be valid");

        assert_eq!(parsed_dt.year(), expected_year, "Year should be incremented correctly");
    }

    #[test]
    fn test_get_timestamp_end_of_current_year() {
        let now = Utc::now();
        let current_year = now.year();

        let timestamp = get_timestamp(0, true);
        println!("Timestamp (End of Current Year {}): {}", current_year, timestamp);
        let parsed_dt = parse_and_validate_format(&timestamp).expect("Timestamp should be valid");

        assert_eq!(parsed_dt.year(), current_year, "Year should be the current year");
        assert_eq!(parsed_dt.month(), 12, "Month should be December");
        assert_eq!(parsed_dt.day(), 31, "Day should be 31st");
        assert_eq!(parsed_dt.hour(), 23, "Hour should be 23");
        assert_eq!(parsed_dt.minute(), 59, "Minute should be 59");
        assert_eq!(parsed_dt.second(), 59, "Second should be 59");
        assert_eq!(parsed_dt.nanosecond(), 999_999_000, "Nanoseconds should indicate the last microsecond");
    }

    #[test]
    fn test_get_timestamp_end_of_future_year() {
        let years_to_add = 3;
        let now = Utc::now();
        let expected_year = now.year() + years_to_add;

        let timestamp = get_timestamp(years_to_add, true);
        println!("Timestamp (End of Future Year {}): {}", expected_year, timestamp);
        let parsed_dt = parse_and_validate_format(&timestamp).expect("Timestamp should be valid");

        assert_eq!(parsed_dt.year(), expected_year, "Year should be the future year");
        assert_eq!(parsed_dt.month(), 12, "Month should be December");
        assert_eq!(parsed_dt.day(), 31, "Day should be 31st");
        assert_eq!(parsed_dt.hour(), 23, "Hour should be 23");
        assert_eq!(parsed_dt.minute(), 59, "Minute should be 59");
        assert_eq!(parsed_dt.second(), 59, "Second should be 59");
        assert_eq!(parsed_dt.nanosecond(), 999_999_000, "Nanoseconds should indicate the last microsecond");
    }

    #[test]
    fn test_get_timestamp_end_of_leap_year() {
        let now = Utc::now();
        let mut years_to_add = 0;
        loop {
            let target_year = now.year() + years_to_add;
            if chrono::NaiveDate::from_ymd_opt(target_year, 2, 29).is_some() {
                break;
            }
            years_to_add += 1;
            if years_to_add > 4 {
                panic!("Could not find a leap year within 4 years for testing");
            }
        }

        let leap_year = now.year() + years_to_add;
        println!("Testing end_of_year for leap year: {}", leap_year);

        let timestamp = get_timestamp(years_to_add, true);
        let parsed_dt = parse_and_validate_format(&timestamp).expect("Timestamp should be valid");

        assert_eq!(parsed_dt.year(), leap_year, "Year should be the target leap year");
        assert_eq!(parsed_dt.month(), 12, "Month should be December");
        assert_eq!(parsed_dt.day(), 31, "Day should be 31st");
    }

    #[test]
    fn test_get_timestamp_add_years_crossing_leap_day() {
        let now = Utc::now();
        let mut years_to_add = 0;
        loop {
            let target_year = now.year() + years_to_add;
            if chrono::NaiveDate::from_ymd_opt(target_year, 2, 29).is_some() {
                if years_to_add > 0 {
                    break;
                }
            }
            years_to_add += 1;
            if years_to_add > 4 {
                panic!("Could not find a future leap year within 4 years for testing");
            }
        }

        let target_leap_year = now.year() + years_to_add;
        println!("Testing add_years to reach leap year: {}", target_leap_year);

        let timestamp = get_timestamp(years_to_add, false);
        let parsed_dt = parse_and_validate_format(&timestamp).expect("Timestamp should be valid");

        assert_eq!(parsed_dt.year(), target_leap_year, "Year should be the target leap year");
    }
}