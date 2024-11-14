//! AES block ciphers for [`Hctr2`][crate::Hctr2].
//!
//! TODO(eric): Document backends

#![cfg(feature = "aes")]
#![cfg_attr(docsrs, doc(cfg(feature = "aes")))]

mod aarch64;
mod generic;
mod soft;
mod x86;

use core::{fmt, mem::ManuallyDrop};

use crate::block::{Block, BlockCipher};

cfg_if::cfg_if! {
    if #[cfg(feature = "soft")] {
        use soft as imp;
    } else if #[cfg(target_arch = "aarch64")] {
        use aarch64 as imp;
    } else if #[cfg(any(target_arch = "x86", target_arch="x86_64"))] {
        use x86 as imp;
    } else {
        use soft as imp;
    }
}

pub(super) const BLOCK_SIZE: usize = 16;

union Aes<A, G> {
    asm: ManuallyDrop<A>,
    soft: ManuallyDrop<G>,
}

macro_rules! impl_aes {
    (
        $(#[$meta:meta])*
        name = $name:ident,
        key_size = $key_size:literal $(,)?
    ) => {
        $(#[$meta])*
        pub struct $name(Aes<imp::$name, generic::$name>);

        impl $name {
            /// Creates a new AES cipher.
            pub fn new(key: &[u8; $key_size]) -> Self {
                let aes = if imp::supported() {
                    // SAFETY: `supported` is true, so we can
                    // call this method.
                    #[allow(unused_unsafe)]
                    let aes = unsafe { imp::$name::new(key) };
                    Aes {
                        asm: ManuallyDrop::new(aes),
                    }
                } else {
                    let aes = generic::$name::new(key);
                    Aes {
                        soft: ManuallyDrop::new(aes),
                    }
                };
                Self(aes)
            }
        }

        impl BlockCipher for $name {
            const BLOCK_SIZE: usize = BLOCK_SIZE;

            type BlockSize = typenum::U16;
            type Stride = typenum::U8;

            fn encrypt_block(&self, dst: &mut Block<Self>, src: &Block<Self>) {
                if imp::supported() {
                    // SAFETY: `supported` is true, so `asm` is
                    // initialized.
                    unsafe { self.0.asm.encrypt_block(dst.as_mut(), src.as_ref()) }
                } else {
                    // SAFETY: `supported` is false, so `soft` is
                    // initialized.
                    unsafe { self.0.soft.encrypt_block(dst.into(), src.into()) }
                }
            }

            // fn encrypt_blocks(&self, dst: &mut [Block<Self>], src: &[Block<Self>]) {
            //     if imp::supported() {
            //         // SAFETY: `supported` is true, so `asm` is
            //         // initialized.
            //         unsafe { self.0.asm.encrypt_blocks(dst.into(), src.into()) }
            //     } else {
            //         // SAFETY: `supported` is false, so `soft` is
            //         // initialized.
            //         unsafe { self.0.soft.encrypt_blocks(dst.into(), src.into()) }
            //     }
            // }

            fn encrypt_block_in_place(&self, data: &mut Block<Self>) {
                if imp::supported() {
                    // SAFETY: `supported` is true, so `asm` is
                    // initialized.
                    unsafe { self.0.asm.encrypt_block_in_place(data.as_mut()) }
                } else {
                    // SAFETY: `supported` is false, so `soft` is
                    // initialized.
                    unsafe { self.0.soft.encrypt_block_in_place(data) }
                }
            }

            fn decrypt_block(&self, dst: &mut Block<Self>, src: &Block<Self>) {
                if imp::supported() {
                    // SAFETY: `supported` is true, so `asm` is
                    // initialized.
                    unsafe { self.0.asm.decrypt_block(dst.as_mut(), src.as_ref()) }
                } else {
                    // SAFETY: `supported` is false, so `soft` is
                    // initialized.
                    unsafe { self.0.soft.decrypt_block(dst.as_mut(), src.as_ref()) }
                }
            }

            fn decrypt_block_in_place(&self, data: &mut Block<Self>) {
                if imp::supported() {
                    // SAFETY: `supported` is true, so `asm` is
                    // initialized.
                    unsafe { self.0.asm.decrypt_block_in_place(data.as_mut()) }
                } else {
                    // SAFETY: `supported` is false, so `soft` is
                    // initialized.
                    unsafe { self.0.soft.decrypt_block_in_place(data.as_mut()) }
                }
            }

            // fn xctr(&self, dst: &mut [u8], src: &[u8], nonce: &Block<Self>) {
            //     if imp::supported() {
            //         // SAFETY: `supported` is true, so `asm` is
            //         // initialized.
            //         unsafe { self.0.asm.xctr(dst, src, nonce.as_ref()) }
            //     } else {
            //         // SAFETY: `supported` is false, so `soft` is
            //         // initialized.
            //         unsafe { self.0.soft.xctr(dst, src, nonce.as_ref()) }
            //     }
            // }
        }

        impl Clone for $name {
            fn clone(&self) -> Self {
                let aes = if imp::supported() {
                    Aes {
                        // SAFETY: `supported` is true, so `asm`
                        // is initialized.
                        asm: unsafe { &self.0.asm }.clone(),
                    }
                } else {
                    Aes {
                        // SAFETY: `supported` is false, so
                        // `soft` is initialized.
                        soft: unsafe { &self.0.soft }.clone(),
                    }
                };
                Self(aes)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                if imp::supported() {
                    // SAFETY: `supported` is true, so `asm` is
                    // initialized.
                    unsafe { ManuallyDrop::drop(&mut self.0.asm) }
                } else {
                    // SAFETY: `supported` is false, so `soft` is
                    // initialized.
                    unsafe { ManuallyDrop::drop(&mut self.0.soft) }
                }
            }
        }

        #[cfg(feature = "zeroize")]
        impl zeroize::ZeroizeOnDrop for $name {}
    };
}

impl_aes!(
    /// AES-128.
    name = Aes128,
    key_size = 16,
);

impl_aes!(
    /// AES-192.
    ///
    /// # Warning
    ///
    /// Except for compatibility purposes, there isn't any reason
    /// to use AES-192. Use AES-128 or AES-256 instead.
    name = Aes192,
    key_size = 24,
);

impl_aes!(
    /// AES-256.
    name = Aes256,
    key_size = 32,
);
