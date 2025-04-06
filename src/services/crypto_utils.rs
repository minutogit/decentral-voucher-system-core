use bip39::{Mnemonic, Language};
use rand::Rng;
use sha2::{Sha256, Digest};
use ed25519_dalek::{SigningKey, Signature, VerifyingKey as EdPublicKey, Signer, Verifier};
use std::convert::TryInto;
use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use std::fmt; // Für das Error-Handling


/// Generates a mnemonic phrase of a specified word count and language.
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
    // Determine the number of bytes of entropy based on the word count.
    let entropy_length = match word_count {
        12 => 16,
        15 => 20,
        18 => 24,
        21 => 28,
        24 => 32,
        _  => return Err("Invalid entropy length".into()),
    };
    // Generate random entropy.
    let mut rng = rand::thread_rng();
    let entropy: Vec<u8> = (0..entropy_length).map(|_| rng.gen()).collect();
    // Generate mnemonic from entropy with the specified language.
    let mnemonic = Mnemonic::from_entropy_in(language, &entropy)?;
    Ok(mnemonic.to_string())
}

// Für Ed25519 (Signatur)
pub fn derive_ed25519_keypair(mnemonic: &str) -> (EdPublicKey, SigningKey) {
    // For simplicity, we'll just generate a key from the first 32 bytes of the mnemonic
    let mut key_bytes = [0u8; 32];
    
    // Use a simple deterministic algorithm based on the mnemonic
    for (i, c) in mnemonic.bytes().enumerate() {
        if i < 32 {
            key_bytes[i] = c;
        }
    }
    
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let public_key = signing_key.verifying_key();
    (public_key, signing_key)
}

///wird benötigt öffentlichen schlüssel des empfängers in Diffie-Hellman format zu bringen.
/// Converts an Ed25519 public key to an X25519 public key
pub fn ed25519_pub_to_x25519(ed_pub: &EdPublicKey) -> X25519PublicKey {
    // Konvertiere zu Montgomery-Point und extrahiere die Bytes
         let montgomery_point = ed_pub.to_montgomery();
         let x25519_bytes: [u8; 32] = montgomery_point.to_bytes();
    
    // Erstelle den X25519PublicKey aus den Rohbytes
         X25519PublicKey::from(x25519_bytes)
}


/// Generates a temporary X25519 key pair for Diffie-Hellman (Forward Secrecy)
pub fn generate_ephemeral_x25519_keypair() -> (X25519PublicKey, EphemeralSecret) {
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = X25519PublicKey::from(&secret);
    (public, secret)
}

/// Perform Diffie-Hellman key exchange
pub fn perform_diffie_hellman(
    our_secret: EphemeralSecret,
    their_public: &X25519PublicKey,
) -> [u8; 32] {
    our_secret.diffie_hellman(their_public).to_bytes()
}

/// Signs a message with an Ed25519 signing key.
pub fn sign_ed25519(signing_key: &SigningKey, message: &[u8]) -> Signature {
    signing_key.sign(message)
}

/// Verifies an Ed25519 signature.
pub fn verify_ed25519(public_key: &EdPublicKey, message: &[u8], signature: &Signature) -> bool {
    public_key.verify(message, signature).is_ok()
}


/// Error types for user ID creation.
#[derive(Debug)]
pub enum UserIdError {
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
/// The format is: [prefix][base58(public_key)][checksum][prefix_length]
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
    let prefix_len = prefix.chars().count(); // Verwende chars().count() für korrekte Zeichenzählung

    if prefix_len > 2 {
        return Err(UserIdError::InvalidPrefixLength(prefix_len));
    }

    // 1. Public Key Bytes holen
    let key_bytes = public_key.to_bytes();

    // 2. Public Key Base58 encoden
    let base58_key = bs58::encode(&key_bytes).into_string();

    // 3. String für Checksummenberechnung erstellen (Prefix + Base58 Key)
    let data_to_hash = format!("{}{}", prefix, base58_key);

    // 4. SHA256 Hash berechnen
    let mut hasher = Sha256::new();
    hasher.update(data_to_hash.as_bytes());
    let hash_result = hasher.finalize();

    // 5. Hash Base58 encoden
    let base58_hash = bs58::encode(hash_result).into_string();

    // 6. Checksumme extrahieren (letzte 3 Zeichen)
    let checksum = if base58_hash.len() >= 3 {
        &base58_hash[base58_hash.len() - 3..]
    } else {
        // Fallback, falls der Base58-Hash unerwartet kurz ist
        &base58_hash
    };

    // 7. Präfixlänge als Ziffer (Char)
    let prefix_len_char = match prefix_len {
        0 => '0',
        1 => '1',
        2 => '2',
        _ => unreachable!(), // Sollte durch die Prüfung oben abgedeckt sein
    };

    // 8. User ID zusammensetzen
    let user_id = format!("{}{}{}{}", prefix, base58_key, checksum, prefix_len_char);

    Ok(user_id)
}


pub fn validate_user_id(user_id: &str) -> bool {
    // Mindestlänge: 1 (Präfixlänge) + 1 (Base58 Key) + 3 (Checksum) + 1 (Suffix) = 6
    if user_id.len() < 6 {
        return false;
    }

    // Letztes Zeichen ist die Präfixlänge
    let (rest, prefix_len_char) = user_id.split_at(user_id.len() - 1);
    let prefix_len = match prefix_len_char.chars().next() {
        Some('0') => 0,
        Some('1') => 1,
        Some('2') => 2,
        _ => return false,
    };

    // Check total length consistency
    if rest.len() != user_id.len() - 1 {
        return false;
    }

    // Zerlege in Präfix + Base58 Key + Checksum
    let (prefix, rest_with_checksum) = rest.split_at(prefix_len);
    
    // Checksumme sind die letzten 3 Zeichen
    if rest_with_checksum.len() < 3 {
        return false;
    }
    let (base58_key, checksum_stored) = rest_with_checksum.split_at(rest_with_checksum.len() - 3);

    // Checksumme neu berechnen
    let data_to_hash = format!("{}{}", prefix, base58_key);
    let mut hasher = Sha256::new();
    hasher.update(data_to_hash.as_bytes());
    let hash = bs58::encode(hasher.finalize()).into_string();

    let checksum_actual = if hash.len() >= 3 {
        &hash[hash.len() - 3..]
    } else {
        &hash
    };

    checksum_stored == checksum_actual
}