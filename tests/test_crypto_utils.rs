// cargo test --test test_crypto_utils


#[cfg(test)]
mod tests {
    use voucher_lib::services::crypto_utils::{
        generate_mnemonic,
        derive_ed25519_keypair,
        generate_ephemeral_x25519_keypair,
        perform_diffie_hellman,
        ed25519_pub_to_x25519,
        sign_ed25519,
        verify_ed25519,
        create_user_id,
        validate_user_id,
        get_pubkey_from_user_id
    };
    use bip39::Language;
    use hex;

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
        let (ed_pub, ed_priv) = derive_ed25519_keypair(&mnemonic, None);
        assert_eq!(ed_pub.as_bytes().len(), 32);
        assert_eq!(ed_priv.as_bytes().len(), 32);
        println!("Ed25519 Public Key: {}", hex::encode(ed_pub.to_bytes()));
        println!("Ed25519 Private Key: {}", hex::encode(ed_priv.to_bytes()));
        Ok(())
    }

    #[test]
    fn test_user_id_creation() -> Result<(), Box<dyn std::error::Error>> {
        let mnemonic = generate_mnemonic(24, Language::English)?;
        let (ed_pub, _) = derive_ed25519_keypair(&mnemonic, None);

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
        let (ed_pub, _) = derive_ed25519_keypair(&mnemonic, None);
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
        let (_, ed_priv) = derive_ed25519_keypair(&mnemonic, None);
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
        let (ed_pub, _) = derive_ed25519_keypair(&mnemonic, None);
        let prefix = "ID";
        let user_id_with_prefix = create_user_id(&ed_pub, Some(prefix)).unwrap();

        let recovered_ed_pub = get_pubkey_from_user_id(&user_id_with_prefix)?;
        assert_eq!(ed_pub.to_bytes(), recovered_ed_pub.to_bytes());
        println!("Recovered key matches original key.");

        let message = b"Voucher system test message";
        let signature = sign_ed25519(&derive_ed25519_keypair(&mnemonic, None).1, message);
        let is_valid_recovered = verify_ed25519(&recovered_ed_pub, message, &signature);
        assert!(is_valid_recovered);
        println!("Signature valid (using RECOVERED key)? {}", is_valid_recovered);
        Ok(())
    }
}
