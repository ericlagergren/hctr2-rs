#![forbid(unsafe_code)]

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};

use super::BLOCK_SIZE;
use crate::block::{Block, BlockCipher};

macro_rules! impl_aes {
    ($name:ident, $key_size:literal) => {
        #[derive(Clone)]
        #[repr(transparent)]
        pub(super) struct $name(aes::$name);

        impl $name {
            pub fn new(key: &[u8; $key_size]) -> Self {
                Self(<aes::$name>::new(key.into()))
            }
        }

        impl BlockCipher for $name {
            const BLOCK_SIZE: usize = BLOCK_SIZE;
            type BlockSize = typenum::U16;
            type Stride = typenum::U1;
            fn encrypt_block(&self, dst: &mut Block<Self>, src: &[u8; BLOCK_SIZE]) {
                self.0.encrypt_block_b2b(src.into(), dst.into())
            }
            fn encrypt_block_in_place(&self, data: &mut Block<Self>) {
                self.0.encrypt_block(data.into())
            }
            fn decrypt_block(&self, dst: &mut Block<Self>, src: &[u8; BLOCK_SIZE]) {
                self.0.decrypt_block_b2b(src.into(), dst.into())
            }
            fn decrypt_block_in_place(&self, data: &mut Block<Self>) {
                self.0.decrypt_block(data.into())
            }
        }
    };
}
impl_aes!(Aes128, 16);
impl_aes!(Aes192, 24);
impl_aes!(Aes256, 32);
