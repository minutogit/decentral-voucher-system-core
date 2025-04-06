use voucher_lib::services::crypto_utils::{
    generate_mnemonic, 
    derive_ed25519_keypair,
    generate_ephemeral_x25519_keypair,
    perform_diffie_hellman,
    ed25519_pub_to_x25519,
    sign_ed25519,
    verify_ed25519
};
use bip39::Language;
use hex;


fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting program...");
    

    Ok(())
}
