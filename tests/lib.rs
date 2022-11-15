use aes::{Aes128, Aes192, Aes256};
use cipher::{generic_array::GenericArray, KeyInit};
use hctr2::Cipher;
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};

#[derive(Serialize, Deserialize, Debug)]
pub struct TestVector {
    cipher: TestVectorCipher,
    description: String,
    input: TestVectorInput,
    ciphertext_hex: String,
    plaintext_hex: String,
    hash_hex: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TestVectorCipher {
    blockcipher: TestVectorBlockCipher,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TestVectorBlockCipher {
    cipher: String,
    lengths: TestVectorBlockCipherLengths,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TestVectorBlockCipherLengths {
    block: usize,
    key: usize,
    nonce: Option<usize>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TestVectorInput {
    key_hex: String,
    tweak_hex: String,
    nonce_hex: Option<String>,
}

static MFST_DIR: &str = env!("CARGO_MANIFEST_DIR");

macro_rules! hctr2_test {
    ($name:ident, $C:ident, $fname:expr) => {
        #[test]
        fn $name() {
            let mut path = PathBuf::from(MFST_DIR);
            path.push("tests");
            path.push("testdata");
            path.push($fname);
            let data = fs::read(path).unwrap();

            let vecs: Vec<TestVector> =
                serde_json::from_slice(&data[..]).unwrap();
            for v in &vecs {
                let key = &hex::decode(&v.input.key_hex).unwrap();
                let mut c =
                    Cipher::<$C>::new(GenericArray::from_slice(&key[..]));
                let tweak = hex::decode(&v.input.tweak_hex).unwrap();
                let plaintext = hex::decode(&v.plaintext_hex).unwrap();
                let ciphertext = hex::decode(&v.ciphertext_hex).unwrap();

                let mut got = &mut vec![0u8; plaintext.len()][..];

                c.encrypt(&mut got, &plaintext, &tweak);
                assert_eq!(got, ciphertext);

                c.decrypt(&mut got, &ciphertext, &tweak);
                assert_eq!(got, plaintext);

                c.encrypt_in_place(&mut got, &tweak);
                assert_eq!(got, ciphertext);

                c.decrypt_in_place(&mut got, &tweak);
                assert_eq!(got, plaintext);
            }
        }
    };
}
hctr2_test!(test_hctr2_aes256, Aes256, "HCTR2_AES256.json");
hctr2_test!(test_hctr2_aes192, Aes192, "HCTR2_AES192.json");
hctr2_test!(test_hctr2_aes128, Aes128, "HCTR2_AES128.json");
