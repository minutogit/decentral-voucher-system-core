//! # tests/test_utils.rs
//!
//! Hilfsfunktionen für die Integrationstests, um Boilerplate-Code zu reduzieren.
use lazy_static::lazy_static;
use bip39::Language;
use voucher_lib::models::{
    conflict::{FingerprintStore, ProofStore}, profile::{BundleMetadataStore, UserProfile, VoucherStore},
};
use voucher_lib::{UserIdentity};
use voucher_lib::models::signature::DetachedSignature;
use voucher_lib::models::voucher::{Address, GuarantorSignature, Voucher};
use voucher_lib::models::voucher::Collateral;
use voucher_lib::models::voucher_standard_definition::{SignatureBlock, VoucherStandardDefinition};
use voucher_lib::services::crypto_utils::{
    self,
    create_user_id, generate_ed25519_keypair_for_tests, sign_ed25519,
};
use ed25519_dalek::Signer;
use voucher_lib::services::secure_container_manager;
use voucher_lib::services::signature_manager;
use voucher_lib::services::voucher_manager::{create_transaction, create_voucher, NewVoucherData};
use voucher_lib::wallet::Wallet;
use voucher_lib::{
    models::voucher::{Creator, NominalValue, Transaction},
    VoucherStatus,
    VoucherCoreError,
};
use voucher_lib::services::crypto_utils::get_hash;
use voucher_lib::services::utils::to_canonical_json;
use toml;
use std::path::PathBuf;
// --- Zentralisierte Akteure und Standards ---

/// Eine private Hilfsfunktion, um eine deterministische UserIdentity aus einem Seed zu erstellen.
fn identity_from_seed(seed: &str, prefix: &str) -> UserIdentity {
    let (public_key, signing_key) =
        generate_ed25519_keypair_for_tests(Some(seed));
    let user_id = create_user_id(&public_key, Some(prefix)).unwrap();
    UserIdentity { signing_key, public_key, user_id }
}

/// Eine Struktur, die alle für Tests benötigten, einmalig erstellten Identitäten enthält.
#[allow(dead_code)]
pub struct TestActors {
    pub alice: UserIdentity,
    pub bob: UserIdentity,
    pub charlie: UserIdentity,
    pub david: UserIdentity,
    pub issuer: UserIdentity,
    pub hacker: UserIdentity,
    pub guarantor1: UserIdentity,
    pub guarantor2: UserIdentity,
    pub male_guarantor: UserIdentity,
    pub female_guarantor: UserIdentity,
    pub sender: UserIdentity,
    pub recipient1: UserIdentity,
    pub recipient2: UserIdentity,
    pub test_user: UserIdentity,
    pub victim: UserIdentity,
}

lazy_static! {
    /// Initialisiert einmalig alle Akteure, sodass sie in allen Tests wiederverwendet werden können.
    pub static ref ACTORS: TestActors = TestActors {
        alice: identity_from_seed("alice", "al"),
        bob: identity_from_seed("bob", "bo"),
        charlie: identity_from_seed("charlie", "ch"),
        david: identity_from_seed("david", "da"),
        issuer: identity_from_seed("issuer", "is"),
        hacker: identity_from_seed("hacker", "ha"),
        guarantor1: identity_from_seed("guarantor1", "g1"),
        guarantor2: identity_from_seed("guarantor2", "g2"),
        male_guarantor: identity_from_seed("male_guarantor", "mg"),
        female_guarantor: identity_from_seed("female_guarantor", "fg"),
        sender: identity_from_seed("sender", "se"),
        recipient1: identity_from_seed("recipient1", "r1"),
        recipient2: identity_from_seed("recipient2", "r2"),
        test_user: identity_from_seed("test_user", "tu"),
        victim: identity_from_seed("victim", "vi"),
    };

    /// Ein deterministischer Herausgeber, der zum Signieren der Test-Standards verwendet wird.
    pub static ref TEST_ISSUER: UserIdentity = identity_from_seed("test-issuer-seed-123", "issuer");

    /// Lädt den Minuto-Standard und signiert ihn zur Laufzeit für die Tests.
    /// Das Ergebnis ist immer ein valider Standard mit einer korrekten Signatur.
    pub static ref MINUTO_STANDARD: (VoucherStandardDefinition, String) = {
        let issuer = &TEST_ISSUER;
        let toml_str = include_str!("../voucher_standards/minuto_v1/standard.toml");

        // 1. Parse die TOML in eine Struct, ignoriere die (ungültige) Signatur in der Datei.
        let mut standard: VoucherStandardDefinition = toml::from_str(toml_str)
            .expect("Failed to parse Minuto TOML template for tests");

        // 2. Entferne die Signatur, erstelle den kanonischen Hash für die Signatur.
        standard.signature = None;
        let canonical_json_for_signing = to_canonical_json(&standard)
            .expect("Failed to create canonical JSON for Minuto standard");
        let hash_to_sign = get_hash(canonical_json_for_signing.as_bytes());

        // 3. Erstelle die gültige Signatur mit dem Test-Issuer.
        let signature = sign_ed25519(&issuer.signing_key, hash_to_sign.as_bytes());
        let signature_block = SignatureBlock {
            issuer_id: issuer.user_id.clone(),
            signature: bs58::encode(signature.to_bytes()).into_string(),
        };
        standard.signature = Some(signature_block);

        // 4. Der Konsistenz-Hash, der in Gutscheinen verwendet wird, ist der Hash, der signiert wurde.
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
        let signature = sign_ed25519(&issuer.signing_key, hash.as_bytes());
        standard.signature = Some(SignatureBlock { issuer_id: issuer.user_id.clone(), signature: bs58::encode(signature.to_bytes()).into_string() });
        (standard, hash)
    };

    /// Lädt den `required_signatures`-Test-Standard und signiert ihn zur Laufzeit.
    /// Verwendet `include_str!` für maximale Robustheit in der Testumgebung.
    pub static ref REQUIRED_SIG_STANDARD: (VoucherStandardDefinition, String) = {
        let issuer = &TEST_ISSUER;
        // Der Pfad ist relativ zur aktuellen Datei (test_utils.rs)
        let toml_str = include_str!("test_data/standards/standard_required_signatures.toml");

        let mut standard: VoucherStandardDefinition = toml::from_str(toml_str)
            .expect("Failed to parse Required Sig TOML template for tests");

        standard.signature = None;
        let canonical_json_for_signing = to_canonical_json(&standard)
            .expect("Failed to create canonical JSON for Required Sig standard");
        let hash_to_sign = get_hash(canonical_json_for_signing.as_bytes());

        let signature = sign_ed25519(&issuer.signing_key, hash_to_sign.as_bytes());
        let signature_block = SignatureBlock {
            issuer_id: issuer.user_id.clone(),
            signature: bs58::encode(signature.to_bytes()).into_string(),
        };
        standard.signature = Some(signature_block);
        (standard, hash_to_sign)
    };
}

#[allow(dead_code)]
/// Generiert eine neue, valide 12-Wort BIP39 Mnemonic-Phrase für Tests.
pub fn generate_valid_mnemonic() -> String {
    crypto_utils::generate_mnemonic(12, Language::English)
        .expect("Test mnemonic generation should not fail")
}

/// Liest eine Standard-TOML-Datei, ersetzt die Platzhalter-Signatur durch eine
/// gültige, zur Laufzeit generierte Signatur und gibt den neuen Inhalt als String zurück.
/// Dies stellt sicher, dass Tests, die rohe TOML-Strings benötigen, eine valide
/// und verifizierbare Definition erhalten.
#[allow(dead_code)]
pub fn generate_signed_standard_toml(template_path: &str) -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let mut absolute_path = PathBuf::from(manifest_dir);
    absolute_path.push(template_path);

    let issuer = &TEST_ISSUER;
    let toml_str = std::fs::read_to_string(&absolute_path)
        .unwrap_or_else(|e| panic!("Failed to read TOML template at '{:?}': {}", absolute_path, e));

    let mut standard: VoucherStandardDefinition = toml::from_str(&toml_str)
        .expect("Failed to parse TOML template for signing");

    standard.signature = None;
    let canonical_json_for_signing = to_canonical_json(&standard)
        .expect("Failed to create canonical JSON for standard");
    let hash_to_sign = get_hash(canonical_json_for_signing.as_bytes());

    let signature = sign_ed25519(&issuer.signing_key, hash_to_sign.as_bytes());
    let signature_block = SignatureBlock {
        issuer_id: issuer.user_id.clone(),
        signature: bs58::encode(signature.to_bytes()).into_string(),
    };
    standard.signature = Some(signature_block);

    toml::to_string(&standard).expect("Failed to serialize standard back to TOML string")
}

/// Hilfsfunktion, um einen Standard zur Laufzeit anzupassen und neu zu signieren.
/// Ist auf oberster Ebene definiert, damit alle Test-Module sie nutzen können.
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

    let signature = TEST_ISSUER.signing_key.sign(hash.as_bytes());

    standard.signature = Some(voucher_lib::models::voucher_standard_definition::SignatureBlock {
        issuer_id: TEST_ISSUER.user_id.clone(),
        signature: bs58::encode(signature.to_bytes()).into_string(),
    });

    (standard, hash)
}

/// Bereitet einen Gutschein mit einer validen ersten Transaktion (einem Split) vor.
#[allow(dead_code)]
pub fn setup_voucher_with_one_tx() -> (
    &'static VoucherStandardDefinition,
    &'static String,
    &'static UserIdentity,
    &'static UserIdentity,
    Voucher,
) {
    let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
    let creator = &ACTORS.alice;
    let recipient = &ACTORS.bob;

    let voucher_data = NewVoucherData {
        creator: Creator { id: creator.user_id.clone(), ..Default::default() },
        nominal_value: NominalValue { amount: "100.0000".to_string(), ..Default::default() },
        // HINWEIS: Auf P4Y erhöht, um konsistent zu sein und mögliche Fehler mit
        // anspruchsvolleren Standards (z.B. Minuto) zu vermeiden.
        validity_duration: Some("P4Y".to_string()),
        ..Default::default()
    };

    let initial_voucher = create_voucher(voucher_data, standard, standard_hash, &creator.signing_key, "en").unwrap();

    // Erstelle eine valide Split-Transaktion. Creator -> Recipient
    // Creator hat danach 60.0000, Recipient hat 40.0000
    let voucher_after_tx1 = create_transaction(
        &initial_voucher, standard, &creator.user_id, &creator.signing_key,
        &recipient.user_id, "40.0000",
    )
    .unwrap();

    (standard, standard_hash, creator, recipient, voucher_after_tx1)
}
// --- Öffentliche Hilfsfunktionen für Integrationstests ---



/// Erstellt ein frisches, leeres In-Memory-Wallet für einen gegebenen Akteur.
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

/// Erstellt ein neues Test-Wallet aus einem deterministischen Seed.
#[allow(dead_code)]
pub fn create_test_wallet(
    seed_phrase_extra: &str,
) -> Result<(Wallet, UserIdentity), VoucherCoreError> {
    // Verwende die dedizierte Test-Funktion, die kein valides Mnemonic-Format benötigt.
    // Sie erzeugt deterministisch einen Schlüssel aus dem Seed-String.
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

/// Erstellt ein Test-Wallet und fügt sofort einen Gutschein mit dem angegebenen Betrag hinzu.
#[allow(dead_code)]
pub fn add_voucher_to_wallet(
    wallet: &mut Wallet,
    identity: &UserIdentity,
    amount: &str,
    standard: &VoucherStandardDefinition,
    with_valid_guarantors: bool,
) -> Result<String, VoucherCoreError> {
    // Erstelle die Creator- und NominalValue-Strukturen, die für NewVoucherData benötigt werden.
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
        // KORREKTUR: P1Y ist für Standards wie Minuto zu kurz. Erhöht auf P4Y,
        // um `ValidityDurationTooShort`-Fehler in abhängigen Tests zu vermeiden.
        validity_duration: Some("P4Y".to_string()),
        ..Default::default()
    };

    // Hash für den Aufruf von create_voucher neu berechnen.
    let mut standard_to_hash = standard.clone();
    standard_to_hash.signature = None;
    let standard_hash = get_hash(to_canonical_json(&standard_to_hash)?);
    
    let mut voucher = create_voucher_for_manipulation(new_voucher_data, standard, &standard_hash, &identity.signing_key, "en");

    if with_valid_guarantors {
        let sig_data1 =
            create_guarantor_signature_data(&ACTORS.guarantor1, "1", &voucher.voucher_id);
        let sig_data2 =
            create_guarantor_signature_data(&ACTORS.guarantor2, "2", &voucher.voucher_id);

        let signed_sig1 = signature_manager::complete_and_sign_detached_signature(
            sig_data1,
            &voucher.voucher_id,
            &ACTORS.guarantor1,
        )?;
        let signed_sig2 = signature_manager::complete_and_sign_detached_signature(
            sig_data2,
            &voucher.voucher_id,
            &ACTORS.guarantor2,
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
        .add_voucher_instance(local_id.clone(), voucher, VoucherStatus::Active);

    Ok(local_id.clone())
}

/// Erstellt die Metadaten für eine Bürgen-Signatur.
/// Die eigentliche Signatur wird erst von der zu testenden Funktion hinzugefügt.
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

/// Erstellt die Metadaten für eine zusätzliche Signatur (AdditionalSignature).
#[allow(dead_code)]
pub fn create_additional_signature_data(
    signer_identity: &UserIdentity,
    voucher_id: &str,
    description: &str,
) -> DetachedSignature {
    let data = voucher_lib::models::voucher::AdditionalSignature {
        voucher_id: voucher_id.to_string(),
        signature_id: String::new(),
        signer_id: signer_identity.user_id.clone(),
        signature: String::new(),
        signature_time: String::new(),
        description: description.to_string(),
    };
    DetachedSignature::Additional(data)
}

/// Eine Helferfunktion, um einen SecureContainer für Testzwecke zu öffnen.
#[allow(dead_code)]
pub fn debug_open_container(
    container_bytes: &[u8],
    recipient_identity: &UserIdentity,
) -> Result<(Voucher, String), VoucherCoreError> {
    let container: voucher_lib::models::secure_container::SecureContainer =
        serde_json::from_slice(container_bytes)?;
    let (payload, _) =
        secure_container_manager::open_secure_container(&container, recipient_identity)?;
    let voucher: Voucher = serde_json::from_slice(&payload)?;
    let sender_id = container.sender_id;
    Ok((voucher, sender_id))
}

/// Erstellt die Basisdaten für einen Minuto-Gutschein.
#[allow(dead_code)]
pub fn create_minuto_voucher_data(creator: Creator) -> NewVoucherData {
    NewVoucherData {
        // Anstelle von `years_valid` wird nun die ISO 8601-Dauer verwendet.
        // Wir verwenden P4Y, da dies die neue Mindestanforderung von P3Y erfüllt.
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

/// Erstellt einen Gutschein ohne die finale Validierung, um Manipulationen zu ermöglichen.
#[allow(dead_code)]
pub fn create_voucher_for_manipulation(
    data: NewVoucherData,
    standard: &VoucherStandardDefinition,
    standard_hash: &str,
    signing_key: &ed25519_dalek::SigningKey,
    lang_preference: &str,
) -> Voucher {
    // KORREKTUR: Die Funktion muss die übergebene `validity_duration` berücksichtigen,
    // anstatt einen hartcodierten Wert zu verwenden.
    let creation_date_str = voucher_lib::services::utils::get_current_timestamp();
    let creation_dt = chrono::DateTime::parse_from_rfc3339(&creation_date_str).unwrap();
    // KORREKTUR: Die Panic-Message wurde verbessert, um mehr Kontext zu liefern.
    let duration_str = data.validity_duration.as_deref().unwrap_or_else(|| {
        panic!(
            "Test voucher creation requires a validity_duration. Voucher details: creator='{}', amount='{}'",
            data.creator.id, data.nominal_value.amount
        )
    });
    let mut valid_until_dt = voucher_lib::services::voucher_manager::add_iso8601_duration(creation_dt.into(), duration_str)
        .expect("Failed to calculate validity in test helper");

    // KORREKTUR: Repliziere die Logik zum Aufrunden des Gültigkeitsdatums aus dem voucher_manager.
    // Dies ist notwendig, damit Tests, die diese Logik prüfen, nicht fehlschlagen.
    if let Some(rule) = &standard.template.fixed.round_up_validity_to {
        if rule == "end_of_year" {
            use chrono::{Datelike, TimeZone};
            let rounded_date = chrono::NaiveDate::from_ymd_opt(valid_until_dt.year(), 12, 31).unwrap();
            let rounded_time = chrono::NaiveTime::from_hms_micro_opt(23, 59, 59, 999_999).unwrap();
            // KORREKTUR: `from_utc` ist veraltet. Ersetzt durch die empfohlene Methode.
            valid_until_dt = chrono::Utc.from_utc_datetime(&rounded_date.and_time(rounded_time));
        }
    }

    let valid_until = valid_until_dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);

    let mut nonce_bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
    let voucher_nonce = bs58::encode(nonce_bytes).into_string();

    // Korrekte Logik zur Erstellung der Beschreibung (aus voucher_manager kopiert)
    let description_template = voucher_lib::services::standard_manager::get_localized_text(
        &standard.template.fixed.description,
        lang_preference,
    ).unwrap_or("");
    let final_description = description_template.replace("{{amount}}", &data.nominal_value.amount);

    // KORREKTUR: Die Logik aus `voucher_manager::create_voucher` muss hier repliziert werden,
    // damit die Tests, die diese Hilfsfunktion nutzen, korrekte Gutscheine erstellen.
    let mut final_nominal_value = data.nominal_value;
    final_nominal_value.unit = standard.template.fixed.nominal_value.unit.clone();
    final_nominal_value.abbreviation = standard.metadata.abbreviation.clone();

    let final_collateral = if !standard.template.fixed.collateral.type_.is_empty() {
        voucher_lib::models::voucher::Collateral {
            type_: standard.template.fixed.collateral.type_.clone(),
            description: standard.template.fixed.collateral.description.clone(),
            redeem_condition: standard.template.fixed.collateral.redeem_condition.clone(),
            ..data.collateral
        }
    } else {
        voucher_lib::models::voucher::Collateral::default()
    };

    let mut voucher = Voucher {
        voucher_standard: voucher_lib::models::voucher::VoucherStandard {
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
    // KORREKTUR: Laut Spezifikation müssen für die Signatur des Creator-Blocks
    // alle Listen für Signaturen und Transaktionen geleert werden.
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

/// **ZENTRALISIERTER HELFER**
/// Erstellt eine konfigurierbare, gültige Bürgen-Signatur für einen gegebenen Gutschein.
/// Wird für Tests benötigt, die spezifische Konstellationen (z.B. falsche Zeit) erfordern.
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

    // KORREKTUR: Die signature_id muss aus dem Hash eines Objekts berechnet werden,
    // bei dem die Felder `signature_id` und `signature` geleert sind, um konsistent
    // mit der Verifizierungslogik zu sein.
    let mut data_for_id_hash = signature_data.clone();
    data_for_id_hash.signature_id = "".to_string();
    data_for_id_hash.signature = "".to_string();
    signature_data.signature_id = get_hash(to_canonical_json(&data_for_id_hash).unwrap());

    let digital_signature = sign_ed25519(&guarantor_identity.signing_key, signature_data.signature_id.as_bytes());
    signature_data.signature = bs58::encode(digital_signature.to_bytes()).into_string();
    signature_data
}

/// **KOMPATIBILITÄTS-HELFER**
/// Stellt die alte, einfache Signatur wieder her, die von den meisten Tests verwendet wird.
/// Berechnet eine valide Standard-Signaturzeit (Erstellung + 1 Tag).
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

/// Erstellt eine valide Signatur vom dedizierten männlichen Test-Bürgen.
#[allow(dead_code)]
pub fn create_male_guarantor_signature(voucher: &Voucher) -> GuarantorSignature {
    let creation_dt = chrono::DateTime::parse_from_rfc3339(&voucher.creation_date).unwrap();
    let signature_time = (creation_dt + chrono::Duration::days(1)).to_rfc3339();
    create_guarantor_signature_with_time(&voucher.voucher_id, &ACTORS.male_guarantor, "Martin", "1", &signature_time)
}

/// Erstellt eine valide Signatur vom dedizierten weiblichen Test-Bürgen.
#[allow(dead_code)]
pub fn create_female_guarantor_signature(voucher: &Voucher) -> GuarantorSignature {
    let creation_dt = chrono::DateTime::parse_from_rfc3339(&voucher.creation_date).unwrap();
    let signature_time = (creation_dt + chrono::Duration::days(2)).to_rfc3339();
    create_guarantor_signature_with_time(&voucher.voucher_id, &ACTORS.female_guarantor, "Frida", "2", &signature_time)
}

/// **ZENTRALISIERTER HELFER**
/// Helper zum Neuberechnen von t_id und Signatur einer manipulierten Transaktion.
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

// --- Bestehende interne Tests für die `utils`-Services ---

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Datelike, Timelike, Utc};
    use regex::Regex;
    use voucher_lib::services::utils::{get_current_timestamp, get_timestamp};

    // Helper function to parse the timestamp string and check basic format
    fn parse_and_validate_format(timestamp_str: &str) -> Result<DateTime<Utc>, String> {
        // Regex to validate the ISO 8601 format with microseconds and Z suffix
        // Example: 2023-10-27T10:30:55.123456Z
        let re = Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$").unwrap();
        if !re.is_match(timestamp_str) {
            return Err(format!("Timestamp '{}' does not match expected format YYYY-MM-DDTHH:MM:SS.ffffffZ", timestamp_str));
        }

        // Try parsing the timestamp
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
        // We can't easily assert the exact day/month/time due to potential leap year adjustments
        // and the exact moment Utc::now() is called, but we check the year.
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
        // Check for 999_999 microseconds (which corresponds to 999_999_000 nanoseconds)
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

    // --- Tests related to Leap Year Logic ---
    // NOTE: Directly testing the internal leap year adjustment logic of `get_timestamp`
    // is difficult because it always starts from `Utc::now()`. We cannot easily force
    // it to start from Feb 29th without mocking the clock.
    // However, we can test the `end_of_year` flag in a leap year context and trust
    // that the underlying `chrono` library handles date calculations correctly,
    // including the fallback logic implemented in `get_timestamp`.

    #[test]
    fn test_get_timestamp_end_of_leap_year() {
        let now = Utc::now();
        let mut years_to_add = 0;
        // Find the next leap year relative to the current year
        loop {
            let target_year = now.year() + years_to_add;
            if chrono::NaiveDate::from_ymd_opt(target_year, 2, 29).is_some() {
                break; // Found a leap year
            }
            years_to_add += 1;
            if years_to_add > 4 {
                // Safety break
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
        assert_eq!(parsed_dt.hour(), 23, "Hour should be 23");
        assert_eq!(parsed_dt.minute(), 59, "Minute should be 59");
        assert_eq!(parsed_dt.second(), 59, "Second should be 59");
        assert_eq!(parsed_dt.nanosecond(), 999_999_000, "Nanoseconds should indicate the last microsecond");
    }

    #[test]
    fn test_get_timestamp_add_years_crossing_leap_day() {
        // This test demonstrates adding years, but doesn't guarantee crossing Feb 29th
        // in a specific way due to starting from Utc::now().
        // It primarily verifies the year increment is correct, even if the target is a leap year.
        let now = Utc::now();
        let mut years_to_add = 0;
        // Find the next leap year relative to the current year
        loop {
            let target_year = now.year() + years_to_add;
            if chrono::NaiveDate::from_ymd_opt(target_year, 2, 29).is_some() {
                if years_to_add > 0 {
                    // Ensure we actually add years
                    break;
                }
            }
            years_to_add += 1;
            if years_to_add > 4 {
                // Safety break
                panic!("Could not find a future leap year within 4 years for testing");
            }
        }

        let target_leap_year = now.year() + years_to_add;
        println!("Testing add_years to reach leap year: {}", target_leap_year);

        let timestamp = get_timestamp(years_to_add, false);
        let parsed_dt = parse_and_validate_format(&timestamp).expect("Timestamp should be valid");

        assert_eq!(parsed_dt.year(), target_leap_year, "Year should be the target leap year");
        // Further assertions on day/month are unreliable without mocking time.
    }
}