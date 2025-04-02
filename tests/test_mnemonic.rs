#[cfg(test)]
mod tests {
    use voucher_lib::services::crypto_utils::generate_mnemonic;
    use bip39::Language;

    #[test]
    fn test_generate_mnemonic() {
        let mnemonic = generate_mnemonic(12, Language::English).unwrap();
        println!("Mnemonic: {}", mnemonic);
        assert!(true);
    }
}
