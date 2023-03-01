
use ed25519_bip32::{XPrv, XPub, XPRV_SIZE, XPUB_SIZE};
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use sha2::Sha256;
use hkdf::Hkdf;
use hex_literal::hex;
fn main(){
    let mnemonic = Mnemonic::from_phrase("club fame frame deposit luxury derive rely upgrade abuse school town dog", Language::English).unwrap(); // 12 words = (128 bits + 4 checksum bits)/11 bits
	println!("mnemonic {:?}", mnemonic.entropy()); // 128 bits = 16 bytes

	let seed = Seed::new(&mnemonic, "");
	println!("seed {:?}", seed);
	println!("seed bytes {:?}", seed.as_bytes().len()); // 64 bytes


	// let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
	// let ikm = seed.as_bytes();
	// let salt = hex!("000102030405060708090a0b0c");
    // let hk = Hkdf::<Sha256>::new(Some(&salt[..]), &ikm);

	let info = hex!("f0f1f2f3f4f5f6f7f8f9");
    let hk = Hkdf::<Sha256>::from_prk(&seed.as_bytes()).expect("PRK should be large enough");

	let mut okm = [0u8; XPRV_SIZE];
    println!("XPRV_SIZE {:?}", XPRV_SIZE);
	hk.expand(&info, &mut okm)
		.expect("{XPRV_SIZE:?} is a valid length for Sha256 to output");
    println!("okm1 {:?}", okm);
    let xprv = XPrv::normalize_bytes_ed25519(okm);
    println!("xprv {:?}", xprv);

    let xprv_str = xprv.to_string();
    let decoded = hex::decode(xprv_str).expect("Decoding failed");

    println!("decoded xprv {:?}", decoded);
    println!("decoded xprv {:?}", decoded.len()); // 96

    let xprv_bytes = xprv.extended_secret_key_bytes();
    println!("extended_secret_key_bytes {:?}", xprv_bytes); // 64
    println!("extended_secret_key_bytes len {:?}", xprv_bytes.len());

    let cc = xprv.chain_code();
    println!("cc {:?}", cc);



	let xpk = xprv.public();
    println!("xpk {:?}", xpk);
    let xpk_str = xpk.to_string();
    let decoded = hex::decode(xpk_str).expect("Decoding failed");

    println!("decoded xpk {:?}", decoded);
    println!("decoded xpk len {:?}", decoded.len()); // 64 bytes



    let pk = xpk.public_key();
    println!("pk {:?}", pk); // 32
    let cc = xpk.chain_code();
    println!("cc {:?}", cc); // 32




}