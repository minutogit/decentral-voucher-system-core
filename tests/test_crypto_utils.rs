// cargo test --test test_crypto_utils


#[cfg(test)]
mod tests {
    use voucher_lib::services::crypto_utils::{
        generate_mnemonic,
        derive_ed25519_keypair,
        generate_ed25519_keypair_for_tests,
        generate_ephemeral_x25519_keypair,
        perform_diffie_hellman,
        ed25519_pub_to_x25519,
        ed25519_sk_to_x25519_sk,
        encrypt_data,
        decrypt_data,
        sign_ed25519,
        verify_ed25519,
        create_user_id,
        validate_user_id,
        get_pubkey_from_user_id,
        validate_mnemonic_phrase,
    };
    use bip39::Language;
    use hex;
    use x25519_dalek::PublicKey as X25519PublicKey;
    use hkdf::Hkdf;
    use sha2::Sha256;

    #[test]
    fn test_generate_mnemonic() -> Result<(), Box<dyn std::error::Error>> {
        let mnemonic = generate_mnemonic(24, Language::English)?;
        assert!(!mnemonic.is_empty());
        println!("Generated mnemonic: {}", mnemonic);
        Ok(())
    }

    #[test]
    fn test_derive_ed25519_keypair() -> Result<(), Box<dyn std::error::Error>> {
        let mnemonic = generate_mnemonic(24, Language::English)?;
        let (ed_pub, ed_priv) = derive_ed25519_keypair(&mnemonic, None)?;
        assert_eq!(ed_pub.as_bytes().len(), 32);
        assert_eq!(ed_priv.as_bytes().len(), 32);
        println!("Ed25519 Public Key: {}", hex::encode(ed_pub.to_bytes()));
        println!("Ed25519 Private Key: {}", hex::encode(ed_priv.to_bytes()));
        Ok(())
    }

    #[test]
    fn test_validate_mnemonic() {
        // 1. Test mit einer bekanntermaßen gültigen Phrase
        let valid_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let result = validate_mnemonic_phrase(valid_mnemonic);
        assert!(result.is_ok(), "Validation of a correct mnemonic failed. Error: {:?}", result.err());
        println!("SUCCESS: Correctly validated a valid mnemonic.");

        // 2. Test mit einem ungültigen Wort
        let invalid_word_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon hello";
        let result = validate_mnemonic_phrase(invalid_word_mnemonic);
        assert!(result.is_err(), "Validation should have failed for an invalid word.");
        println!("SUCCESS: Correctly identified a mnemonic with an invalid word.");

        // 3. Test mit einer ungültigen Prüfsumme
        // "about" wurde durch "abandon" ersetzt, was die Prüfsumme ungültig macht.
        let bad_checksum_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        let result = validate_mnemonic_phrase(bad_checksum_mnemonic);
        assert!(result.is_err(), "Validation should have failed for a bad checksum.");
        println!("SUCCESS: Correctly identified a mnemonic with a bad checksum.");
    }

    #[test]
    fn test_user_id_creation() -> Result<(), Box<dyn std::error::Error>> {
        let mnemonic = generate_mnemonic(24, Language::English)?;
        let (ed_pub, _) = derive_ed25519_keypair(&mnemonic, None)?;

        let user_id_no_prefix = create_user_id(&ed_pub, None).unwrap();
        assert!(!user_id_no_prefix.is_empty());
        println!("User ID (no prefix):   {}", user_id_no_prefix);

        let prefix = "ID";
        let user_id_with_prefix = create_user_id(&ed_pub, Some(prefix)).unwrap();
        assert!(!user_id_with_prefix.is_empty());
        println!("User ID (prefix '{}'): {}", prefix, user_id_with_prefix);

        let is_valid = validate_user_id(&user_id_with_prefix);
        assert!(is_valid);
        println!("Checksum validation for user_id: {}", is_valid);
        Ok(())
    }

    #[test]
    fn test_ed25519_to_x25519_conversion() -> Result<(), Box<dyn std::error::Error>> {
        let mnemonic = generate_mnemonic(24, Language::English)?;
        let (ed_pub, _) = derive_ed25519_keypair(&mnemonic, None)?;
        let x25519_pub = ed25519_pub_to_x25519(&ed_pub);
        assert_eq!(x25519_pub.as_bytes().len(), 32);
        println!("X25519 Public Key: {}", hex::encode(x25519_pub.to_bytes()));
        Ok(())
    }

    #[test]
    fn test_ephemeral_dh_key_generation() {
        let (alice_dh_pub, alice_dh_priv) = generate_ephemeral_x25519_keypair();
        let (bob_dh_pub, bob_dh_priv) = generate_ephemeral_x25519_keypair();
        assert_eq!(alice_dh_pub.as_bytes().len(), 32);
        assert_eq!(bob_dh_pub.as_bytes().len(), 32);
        println!("Alice's ephemeral public key: {}", hex::encode(alice_dh_pub.to_bytes()));
        println!("Bob's ephemeral public key: {}", hex::encode(bob_dh_pub.to_bytes()));

        let alice_shared = perform_diffie_hellman(alice_dh_priv, &bob_dh_pub);
        let bob_shared = perform_diffie_hellman(bob_dh_priv, &alice_dh_pub);
        assert_eq!(alice_shared.len(), 32);
        assert_eq!(bob_shared.len(), 32);
        println!("Alice's shared secret: {}", hex::encode(alice_shared));
        println!("Bob's shared secret: {}", hex::encode(bob_shared));

        assert_eq!(alice_shared, bob_shared);
        println!("Success! Shared secrets match.");
    }

    #[test]
    fn test_ed25519_signature() -> Result<(), Box<dyn std::error::Error>> {
        let mnemonic = generate_mnemonic(24, Language::English)?;
        let (_, ed_priv) = derive_ed25519_keypair(&mnemonic, None)?;
        let message = b"Voucher system test message";

        let signature = sign_ed25519(&ed_priv, message);
        let ed_pub = ed_priv.verifying_key();
        let is_valid = verify_ed25519(&ed_pub, message, &signature);
        assert!(is_valid);
        println!("Signature valid? {}", is_valid);

        let tampered_message = b"Voucher system test messagE";
        let is_valid_tampered = verify_ed25519(&ed_pub, tampered_message, &signature);
        assert!(!is_valid_tampered);
        println!("Tampered message valid? {}", is_valid_tampered);
        Ok(())
    }

    #[test]
    fn test_get_pubkey_from_user_id() -> Result<(), Box<dyn std::error::Error>> {
        let mnemonic = generate_mnemonic(24, Language::English)?;
        let (ed_pub, ed_sk) = derive_ed25519_keypair(&mnemonic, None)?;
        let prefix = "ID";
        let user_id_with_prefix = create_user_id(&ed_pub, Some(prefix)).unwrap();

        let recovered_ed_pub = get_pubkey_from_user_id(&user_id_with_prefix)?;
        assert_eq!(ed_pub.to_bytes(), recovered_ed_pub.to_bytes());
        println!("Recovered key matches original key.");

        let message = b"Voucher system test message";
        let signature = sign_ed25519(&ed_sk, message);
        let is_valid_recovered = verify_ed25519(&recovered_ed_pub, message, &signature);
        assert!(is_valid_recovered);
        println!("Signature valid (using RECOVERED key)? {}", is_valid_recovered);
        Ok(())
    }

    #[test]
    fn test_static_encryption_flow() {
        // 1. Erzeuge zwei deterministische Identitäten für einen wiederholbaren Test.
        let (alice_ed_pub, alice_ed_sk) = generate_ed25519_keypair_for_tests(Some("alice"));
        let (bob_ed_pub, bob_ed_sk) = generate_ed25519_keypair_for_tests(Some("bob"));

        // 2. Teste die Konvertierung des geheimen Schlüssels.
        // Die Konvertierung muss konsistent sein: Der aus dem konvertierten geheimen Schlüssel
        // abgeleitete öffentliche Schlüssel muss mit dem direkt konvertierten öffentlichen
        // Schlüssel übereinstimmen.
        let alice_x_sk_static = ed25519_sk_to_x25519_sk(&alice_ed_sk);
        let alice_x_pub_from_sk = X25519PublicKey::from(&alice_x_sk_static);
        let alice_x_pub_from_pub = ed25519_pub_to_x25519(&alice_ed_pub);
        assert_eq!(alice_x_pub_from_sk.as_bytes(), alice_x_pub_from_pub.as_bytes());
        println!("SUCCESS: Private key conversion (Ed25519 -> X25519) is consistent.");

        // 3. Führe einen statischen Diffie-Hellman-Austausch durch.
        // Alice verwendet ihren statischen geheimen Schlüssel und Bobs öffentlichen Schlüssel.
        let bob_x_pub = ed25519_pub_to_x25519(&bob_ed_pub);
        let shared_secret_alice = alice_x_sk_static.diffie_hellman(&bob_x_pub);

        // Bob macht dasselbe mit seinem statischen geheimen Schlüssel und Alice' öffentlichem Schlüssel.
        let bob_x_sk_static = ed25519_sk_to_x25519_sk(&bob_ed_sk);
        let shared_secret_bob = bob_x_sk_static.diffie_hellman(&alice_x_pub_from_pub);

        // Beide müssen zum selben Ergebnis kommen.
        assert_eq!(shared_secret_alice.as_bytes(), shared_secret_bob.as_bytes());
        println!("SUCCESS: Static Diffie-Hellman resulted in a matching shared secret.");

        // 4. Leite einen sicheren Verschlüsselungsschlüssel aus dem gemeinsamen Geheimnis ab (Best Practice).
        let hkdf = Hkdf::<Sha256>::new(None, shared_secret_alice.as_bytes());
        let mut encryption_key = [0u8; 32];
        hkdf.expand(b"voucher-p2p-encryption", &mut encryption_key).unwrap();

        // 5. Teste die Ver- und Entschlüsselung.
        let plaintext = b"This is a secret message for Bob.";
        println!("Plaintext: '{}'", std::str::from_utf8(plaintext).unwrap());

        let encrypted_data = encrypt_data(&encryption_key, plaintext).unwrap();
        println!("Encrypted (hex, nonce prefixed): {}", hex::encode(&encrypted_data));
        assert_ne!(plaintext, &encrypted_data[..]); // Sicherstellen, dass es kein Klartext ist.

        let decrypted_data = decrypt_data(&encryption_key, &encrypted_data).unwrap();
        println!("Decrypted: '{}'", std::str::from_utf8(&decrypted_data).unwrap());
        assert_eq!(plaintext.to_vec(), decrypted_data);
        println!("SUCCESS: Message was encrypted and decrypted correctly.");

        // 6. Negativtest: Entschlüsselung mit falschem Schlüssel muss fehlschlagen.
        let mut wrong_key = encryption_key;
        wrong_key[0] ^= 0xff; // Einen Bit im Schlüssel ändern.
        let result = decrypt_data(&wrong_key, &encrypted_data);
        assert!(result.is_err(), "Decryption should fail with a wrong key");
        println!("SUCCESS: Decryption correctly failed with the wrong key.");
    }
}
