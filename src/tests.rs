#![cfg(test)]

use serde::Deserialize;

use crate::{
    aes::{Aes128, Aes192, Aes256},
    block::BlockCipher,
    Hctr2,
};

#[derive(Deserialize)]
#[allow(dead_code)]
struct TestVector {
    cipher: TestCipher,
    description: String,
    input: Input,
    #[serde(default, with = "hex::serde")]
    plaintext_hex: Vec<u8>,
    #[serde(default, with = "hex::serde")]
    ciphertext_hex: Vec<u8>,
    #[serde(default, with = "hex::serde")]
    hash_hex: Vec<u8>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct Input {
    #[serde(with = "hex::serde")]
    key_hex: Vec<u8>,
    #[serde(default, with = "hex::serde")]
    tweak_hex: Vec<u8>,
    #[serde(default, with = "hex::serde")]
    message_hex: Vec<u8>,
    #[serde(default, with = "hex::serde")]
    nonce_hex: Vec<u8>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct TestCipher {
    cipher: String,
    block_cipher: Option<TestBlockCipher>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct TestBlockCipher {
    cipher: String,
    lengths: Lengths,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct Lengths {
    block: usize,
    key: usize,
    nonce: usize,
}

macro_rules! xctr2_test {
    ($name:ident, $cipher:ty, $path:expr) => {
        #[test]
        fn $name() {
            const DATA: &str =
                include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/", $path));

            let vecs: Vec<TestVector> = serde_json::from_str(DATA).expect("should be valid JSON,");
            for (i, v) in vecs.iter().enumerate() {
                let cipher =
                    <$cipher>::new(v.input.key_hex[..].try_into().expect("should not fail"));
                let nonce = v.input.nonce_hex.as_slice().try_into().unwrap();
                let plaintext = &v.plaintext_hex;
                let ciphertext = &v.ciphertext_hex;

                let mut got = vec![0u8; plaintext.len()];
                cipher.xctr(&mut got, plaintext, &nonce);
                assert_eq!(&got, ciphertext, "#{i}: `xctr`");
            }
        }
    };
}
xctr2_test!(test_xctr2_aes128, Aes128, "XCTR_AES128.json");
xctr2_test!(test_xctr2_aes192, Aes192, "XCTR_AES192.json");
xctr2_test!(test_xctr2_aes256, Aes256, "XCTR_AES256.json");

macro_rules! hctr2_test {
    ($name:ident, $C:ident, $path:expr) => {
        #[test]
        fn $name() {
            const DATA: &str =
                include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/", $path));

            let vecs: Vec<TestVector> = serde_json::from_str(DATA).expect("should be valid JSON,");
            for (i, v) in vecs.iter().enumerate() {
                let mut c = Hctr2::<$C>::new($C::new(
                    v.input.key_hex[..].try_into().expect("should not fail"),
                ));
                let tweak = &v.input.tweak_hex;
                let plaintext = &v.plaintext_hex;
                let ciphertext = &v.ciphertext_hex;

                let mut got = &mut vec![0u8; plaintext.len()];

                c.seal(&mut got, &plaintext, &tweak)
                    .expect("should not fail");
                assert_eq!(got, ciphertext, "#{i}: `seal`");

                c.open(&mut got, &ciphertext, &tweak)
                    .expect("should not fail");
                assert_eq!(got, plaintext, "#{i}: `open`");

                c.seal_in_place(&mut got, &tweak).expect("should not fail");
                assert_eq!(got, ciphertext, "#{i}: `seal_in_place`");

                c.open_in_place(&mut got, &tweak).expect("should not fail");
                assert_eq!(got, plaintext, "#{i}: `open_in_place`");
            }
        }
    };
}
hctr2_test!(test_hctr2_aes128, Aes128, "HCTR2_AES128.json");
hctr2_test!(test_hctr2_aes192, Aes192, "HCTR2_AES192.json");
hctr2_test!(test_hctr2_aes256, Aes256, "HCTR2_AES256.json");
