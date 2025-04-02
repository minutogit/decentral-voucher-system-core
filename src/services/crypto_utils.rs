use bip39::{Mnemonic, Language};
use rand::Rng;
use sha2::{Sha512, Digest};
use ed25519_dalek::{SigningKey, VerifyingKey as EdPublicKey};
///use x25519_dalek::PublicKey as X25519PublicKey;
use std::convert::TryInto;
use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

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
