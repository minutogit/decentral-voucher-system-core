// Zufallszahlengenerierung
use rand::Rng;
use rand::RngCore;
use rand_core::OsRng;

// Kryptografische Hashes (SHA-2)
use sha2::{Sha256, Sha512, Digest};

// Ed25519 Signaturen
use ed25519_dalek::{
    SigningKey,
    Signature,
    VerifyingKey as EdPublicKey,
    Signer,
    Verifier,
    SignatureError,
};

// X25519 Schlüsselvereinbarung
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

// BIP39 Mnemonic Phrase
use bip39::{Mnemonic, Language};

// Key Derivation Functions
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use hkdf::Hkdf;

// Standard Bibliothek
use std::convert::TryInto;
use std::fmt;


/// Generates a mnemonic phrase with a specified word count and language.
///
/// # Arguments
///
/// * `word_count` - The number of words in the mnemonic phrase (12, 15, 18, 21, or 24).
/// * `language` - The language of the mnemonic phrase.
///
/// # Errors
///
/// Returns an error if the `word_count` is invalid.
pub fn generate_mnemonic(word_count: usize, language: Language) -> Result<String, Box<dyn std::error::Error>> {
    let entropy_length = match word_count {
        12 => 16,
        15 => 20,
        18 => 24,
        21 => 28,
        24 => 32,
        _  => return Err("Invalid entropy length".into()),
    };
    let mut rng = rand::thread_rng();
    let entropy: Vec<u8> = (0..entropy_length).map(|_| rng.gen()).collect();
    let mnemonic = Mnemonic::from_entropy_in(language, &entropy)?;
    Ok(mnemonic.to_string())
}

/// Computes a SHA3-256 hash of the input and returns it as a base58-encoded string.
///
/// # Arguments
///
/// * `input` - The data to hash. Accepts anything that can be referenced as a byte slice.
///
/// # Returns
///
/// A base58-encoded SHA3-256 hash string.
pub fn get_hash(input: impl AsRef<[u8]>) -> String {
    use sha3::Digest;
    let mut hasher = sha3::Sha3_256::new();
    hasher.update(input.as_ref());
    let hash_bytes = hasher.finalize();
    bs58::encode(hash_bytes).into_string()
}


/// Derives an Ed25519 keypair from a mnemonic phrase and an optional passphrase.
///
/// This function takes a BIP-39 mnemonic phrase and an optional passphrase,
/// and derives an Ed25519 keypair using PBKDF2 and HMAC-based key derivation.
///
/// # Arguments
///
/// * `mnemonic_phrase` - The BIP-39 mnemonic phrase.
/// * `passphrase` - An optional passphrase.
///
/// # Returns
///
/// A tuple containing the Ed25519 public key and signing key.
pub fn derive_ed25519_keypair(
    mnemonic_phrase: &str,
    passphrase: Option<&str>,
) -> (EdPublicKey, SigningKey) {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, mnemonic_phrase)
        .expect("Invalid BIP-39 mnemonic phrase");
    
    let passphrase = passphrase.unwrap_or("");
    let salt = format!("mnemonic{}", passphrase);
    let mut seed = [0u8; 64];
    
    pbkdf2::<Hmac<Sha512>>(
        &mnemonic.to_entropy(),
        salt.as_bytes(),
        100_000,
        &mut seed
    ).expect("PBKDF2 failed");
    
    let hmac_context = b"DCVOUCHER-KDF-v1";
    let mut hmac = Hmac::<Sha512>::new_from_slice(hmac_context)
        .expect("HMAC key error");
    hmac.update(&seed);
    let derived_seed = hmac.finalize().into_bytes();
    
    let mut stretched_key = [0u8; 32];
    pbkdf2::<Hmac<Sha512>>(
        &derived_seed,
        b"ed25519-key-stretch",
        10_000,
        &mut stretched_key
    ).expect("PBKDF2 stretching failed");
    
    let signing_key = SigningKey::from_bytes(&stretched_key);
    let public_key = signing_key.verifying_key();
    (public_key, signing_key)
}

/// Erzeugt ein zufälliges oder deterministisches Ed25519-Schlüsselpaar für Testzwecke.
///
/// # Warnung
/// **Diese Funktion ist NICHT für den produktiven Einsatz geeignet!**
/// Der deterministische Pfad verwendet eine sehr geringe Anzahl von PBKDF2-Iterationen
/// und einen statischen Salt, was ihn kryptographisch unsicher macht. Er dient
/// ausschließlich dazu, in Tests reproduzierbare Schlüsselpaare zu erzeugen.
///
/// # Arguments
/// * `seed` - Ein optionaler String.
///   - `None`: Erzeugt ein vollständig zufälliges, neues Schlüsselpaar.
///   - `Some(seed_str)`: Erzeugt ein deterministisches Schlüsselpaar aus dem Seed-String.
///
/// # Returns
/// Ein Tupel, das den öffentlichen und den privaten Ed25519-Schlüssel enthält.
pub fn generate_ed25519_keypair_for_tests(seed: Option<&str>) -> (EdPublicKey, SigningKey) {
    if let Some(seed_str) = seed {
        // Deterministischer, aber UNSICHERER Pfad für reproduzierbare Tests
        let mut key_bytes = [0u8; 32];
        pbkdf2::<Hmac<Sha512>>(
            seed_str.as_bytes(),
            b"insecure-test-salt",
            100, // Sehr wenige Iterationen, nur für schnelle Tests!
            &mut key_bytes,
        )
        .expect("PBKDF2 for testing failed");

        let signing_key = SigningKey::from_bytes(&key_bytes);
        let public_key = signing_key.verifying_key();
        (public_key, signing_key)
    } else {
        // Sicherer, zufälliger Pfad für allgemeine Tests
        let mut csprng = OsRng {};
        let mut key_bytes: [u8; 32] = [0; 32];
        csprng.fill_bytes(&mut key_bytes);
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let public_key = signing_key.verifying_key();
        (public_key, signing_key)
    }
}


/// Converts an Ed25519 public key to an X25519 public key for Diffie-Hellman key exchange.
///
/// This function converts an Ed25519 public key to its X25519 equivalent,
/// which is required for performing Diffie-Hellman key exchange.
///
/// # Arguments
///
/// * `ed_pub` - The Ed25519 public key.
///
/// # Returns
///
/// The X25519 public key.
pub fn ed25519_pub_to_x25519(ed_pub: &EdPublicKey) -> X25519PublicKey {
    let montgomery_point = ed_pub.to_montgomery();
    let x25519_bytes: [u8; 32] = montgomery_point.to_bytes();
    X25519PublicKey::from(x25519_bytes)
}


/// Generates a temporary X25519 key pair for Diffie-Hellman (Forward Secrecy).
///
/// This function generates a fresh X25519 key pair for each Diffie-Hellman exchange,
/// ensuring forward secrecy.
///
/// # Returns
///
/// A tuple containing the X25519 public key and the ephemeral secret.
pub fn generate_ephemeral_x25519_keypair() -> (X25519PublicKey, EphemeralSecret) {
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = X25519PublicKey::from(&secret);
    (public, secret)
}


/// Performs Diffie-Hellman key exchange.
///
/// This function performs Diffie-Hellman key exchange using our ephemeral secret
/// and the other party's public key.
///
/// # Arguments
///
/// * `our_secret` - Our ephemeral secret.
/// * `their_public` - The other party's public key.
///
/// # Returns
///
/// The shared secret.
pub fn perform_diffie_hellman(
    our_secret: EphemeralSecret,
    their_public: &X25519PublicKey,
) -> [u8; 32] {
    let shared_secret = our_secret.diffie_hellman(their_public);
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut output = [0u8; 32];
    hkdf.expand(b"key", &mut output).unwrap();
    output
}

/// Signs a message with an Ed25519 signing key.
///
/// # Arguments
///
/// * `signing_key` - The Ed25519 signing key.
/// * `message` - The message to be signed.
///
/// # Returns
///
/// The signature.
pub fn sign_ed25519(signing_key: &SigningKey, message: &[u8]) -> Signature {
    signing_key.sign(message)
}

/// Verifies an Ed25519 signature.
///
/// # Arguments
///
/// * `public_key` - The Ed25519 public key.
/// * `message` - The message to be verified.
/// * `signature` - The signature to be verified.
///
/// # Returns
///
/// `true` if the signature is valid, `false` otherwise.
pub fn verify_ed25519(public_key: &EdPublicKey, message: &[u8], signature: &Signature) -> bool {
    public_key.verify(message, signature).is_ok()
}


/// Error types for user ID creation.
#[derive(Debug)]
pub enum UserIdError {
    /// Indicates that the provided prefix length is invalid.
    InvalidPrefixLength(usize),
}

impl fmt::Display for UserIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UserIdError::InvalidPrefixLength(len) => write!(f, "Invalid prefix length: {}. Maximum allowed is 2.", len),
        }
    }
}

impl std::error::Error for UserIdError {}


/// Generates a user ID from the public key with an optional prefix, checksum, and prefix length indicator.
///
/// The format is: `[prefix][base58(public_key)][checksum][prefix_length]`
///
/// # Arguments
///
/// * `public_key` - The Ed25519 public key.
/// * `user_prefix` - An optional prefix string (max 2 characters).
///
/// # Returns
///
/// A `Result` containing the user ID string or a `UserIdError`.
///
/// # Errors
///
/// Returns `UserIdError::InvalidPrefixLength` if the prefix is longer than 2 characters.
pub fn create_user_id(public_key: &EdPublicKey, user_prefix: Option<&str>) -> Result<String, UserIdError> {
    let prefix = user_prefix.unwrap_or("");
    let prefix_len = prefix.chars().count();

    if prefix_len > 2 {
        return Err(UserIdError::InvalidPrefixLength(prefix_len));
    }

    let key_bytes = public_key.to_bytes();
    let base58_key = bs58::encode(&key_bytes).into_string();
    let data_to_hash = format!("{}{}", prefix, base58_key);

    let mut hasher = Sha256::new();
    hasher.update(data_to_hash.as_bytes());
    let hash_result = hasher.finalize();

    let base58_hash = bs58::encode(hash_result).into_string();

    let checksum = if base58_hash.len() >= 4 {
        &base58_hash[base58_hash.len() - 4..]
    } else {
        &base58_hash
    };

    let prefix_len_char = match prefix_len {
        0 => '0',
        1 => '1',
        2 => '2',
        _ => unreachable!(),
    };

    let user_id = format!("{}{}{}{}", prefix, base58_key, checksum, prefix_len_char);

    Ok(user_id)
}


/// Validates a user ID string.
///
/// # Arguments
///
/// * `user_id` - The user ID string to validate.
///
/// # Returns
///
/// `true` if the user ID is valid, `false` otherwise.
pub fn validate_user_id(user_id: &str) -> bool {
    if user_id.len() < 7 {
        return false;
    }

    let (rest, prefix_len_char) = user_id.split_at(user_id.len() - 1);
    let prefix_len = match prefix_len_char.chars().next() {
        Some('0') => 0,
        Some('1') => 1,
        Some('2') => 2,
        _ => return false,
    };

    if rest.len() != user_id.len() - 1 {
        return false;
    }

    let (prefix, rest_with_checksum) = rest.split_at(prefix_len);
    
    if rest_with_checksum.len() < 4 {
        return false;
    }
    let (base58_key, checksum_stored) = rest_with_checksum.split_at(rest_with_checksum.len() - 4);

    let data_to_hash = format!("{}{}", prefix, base58_key);
    let mut hasher = Sha256::new();
    hasher.update(data_to_hash.as_bytes());
    let hash = bs58::encode(hasher.finalize()).into_string();

    let checksum_actual = if hash.len() >= 4 {
        &hash[hash.len() - 4..]
    } else {
        &hash
    };

    checksum_stored == checksum_actual
}

/// Custom error type for `get_pubkey_from_user_id` function.
#[derive(Debug)]
pub enum GetPubkeyError {
    /// Indicates that the user ID format or checksum is invalid.
    ValidationFailed,
    /// Indicates that Base58 decoding failed.
    DecodingFailed(bs58::decode::Error),
    /// Indicates that the decoded public key has an invalid length.
    InvalidLength(usize),
    /// Indicates that public key conversion failed.
    ConversionFailed(SignatureError),
}

impl std::fmt::Display for GetPubkeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GetPubkeyError::ValidationFailed => 
                write!(f, "Invalid user ID format or checksum"),
            GetPubkeyError::DecodingFailed(e) => 
                write!(f, "Base58 decoding failed: {}", e),
            GetPubkeyError::InvalidLength(len) => 
                write!(f, "Decoded public key has invalid length (expected 32, got {})", len),
            GetPubkeyError::ConversionFailed(e) => 
                write!(f, "Public key conversion failed: {}", e),
        }
    }
}

impl std::error::Error for GetPubkeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            GetPubkeyError::DecodingFailed(e) => Some(e),
            GetPubkeyError::ConversionFailed(e) => Some(e),
            _ => None,
        }
    }
}

/// Extracts the Ed25519 public key from a user ID string.
///
/// Uses `validate_user_id` for format and checksum checks.
///
/// # Arguments
///
/// * `user_id` - The user ID string created by `create_user_id`.
///
/// # Returns
///
/// A `Result` containing the `EdPublicKey` or a `GetPubkeyError`.
pub fn get_pubkey_from_user_id(user_id: &str) -> Result<EdPublicKey, GetPubkeyError> {
    if !validate_user_id(user_id) {
        return Err(GetPubkeyError::ValidationFailed);
    }

    let prefix_len_char = user_id.chars().last().unwrap();
    let prefix_len = match prefix_len_char {
        '0' => 0,
        '1' => 1,
        '2' => 2,
        _ => unreachable!(),
    };

    let content_len = user_id.len() - 1;
    let checksum_len = 4;
    let checksum_start_index = content_len.saturating_sub(checksum_len);
    let base58_key = &user_id[prefix_len..checksum_start_index];

    let key_bytes_vec = bs58::decode(base58_key)
        .into_vec()
        .map_err(GetPubkeyError::DecodingFailed)?;

    let actual_len = key_bytes_vec.len();
    let key_bytes_array: [u8; 32] = key_bytes_vec
        .try_into()
        .map_err(|_| GetPubkeyError::InvalidLength(actual_len))?;

    EdPublicKey::try_from(&key_bytes_array as &[u8])
        .map_err(GetPubkeyError::ConversionFailed)
}
