use voucher_lib::services::crypto_utils::{
    generate_mnemonic, 
    derive_ed25519_keypair,
    generate_ephemeral_x25519_keypair,
    perform_diffie_hellman,
    ed25519_pub_to_x25519
};
use bip39::Language;
use hex;


fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting program...");
    
    // Mnemonic generieren
    println!("\nGenerating mnemonic...");
    let mnemonic = generate_mnemonic(24, Language::English)?;
    println!("Mnemonic phrase: {}", mnemonic);

    // Ed25519-Schlüsselpaar ableiten
    println!("\nDeriving Ed25519 keys...");
    let (ed_pub, ed_priv) = derive_ed25519_keypair(&mnemonic);
    println!("Ed25519 Public Key: {}", hex::encode(ed_pub.to_bytes()));
    println!("Ed25519 Private Key: {}", hex::encode(ed_priv.to_bytes()));

    // Ed25519 zu X25519 konvertieren
    println!("\nConverting to X25519...");
    let x25519_pub = ed25519_pub_to_x25519(&ed_pub);
    println!("X25519 Public Key: {}", hex::encode(x25519_pub.to_bytes()));

    // Ephemere DH-Schlüssel generieren
    println!("\nGenerating ephemeral DH keys...");
    let (alice_dh_pub, alice_dh_priv) = generate_ephemeral_x25519_keypair();
    let (bob_dh_pub, bob_dh_priv) = generate_ephemeral_x25519_keypair();
    
    println!("Alice's ephemeral public key: {}", hex::encode(alice_dh_pub.to_bytes()));
    println!("Bob's ephemeral public key: {}", hex::encode(bob_dh_pub.to_bytes()));

    // Schlüsselaustausch durchführen
    println!("\nPerforming Diffie-Hellman...");
    let alice_shared = perform_diffie_hellman(alice_dh_priv, &bob_dh_pub);
    let bob_shared = perform_diffie_hellman(bob_dh_priv, &alice_dh_pub);
    
    println!("Alice's shared secret: {}", hex::encode(alice_shared));
    println!("Bob's shared secret: {}", hex::encode(bob_shared));
    
    // Verifizieren dass die Secrets übereinstimmen
    assert_eq!(alice_shared, bob_shared);
    println!("\nSuccess! Shared secrets match.");

    Ok(())
}