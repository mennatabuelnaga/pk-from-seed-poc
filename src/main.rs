use bip39::{Language, Mnemonic, Seed};
use sha2::Sha256;
use hkdf::Hkdf;
use hex_literal::hex;
use ed25519_dalek::{SECRET_KEY_LENGTH, SecretKey, PublicKey};
fn main(){
    let mnemonic = Mnemonic::from_phrase("club fame frame deposit luxury derive rely upgrade abuse school town dog", Language::English).unwrap(); // 12 words = (128 bits + 4 checksum bits)/11 bits
	println!("mnemonic {:?}", mnemonic.entropy()); // 128 bits = 16 bytes

	let seed = Seed::new(&mnemonic, "");
	println!("seed bytes {:?}", seed.as_bytes().len()); // 64 bytes
    let info = hex!("f0f1f2f3f4f5f6f7f8f9");
    let hk = Hkdf::<Sha256>::from_prk(&seed.as_bytes()).expect("PRK should be large enough");

	let mut okm = [0u8; SECRET_KEY_LENGTH];
	hk.expand(&info, &mut okm)
		.expect("32 is a valid length for Sha256 to output");
    println!("okm {:?}", okm);
    let sk = SecretKey::from_bytes(okm.as_slice()).unwrap();
    let pk: PublicKey = (&sk).into();
    println!("pk {:?}", pk);






}