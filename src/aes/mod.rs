//! AES block ciphers for HCTR2.

#![cfg(feature = "aes")]
#![cfg_attr(docsrs, doc(cfg(feature = "aes")))]

mod aarch64;
mod generic;
mod soft;
mod x86;

use core::{fmt, mem::ManuallyDrop};

use polyhash::Polyval;
use typenum::U16;

use crate::{
    block::{Block, BlockCipher, BlockClosure, BlockSize},
    xctr::{self, Xctr},
};

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

macro_rules! impl_hctr {
    (
        $(#[$meta:meta])*
        $name:ident, $cipher:ty, $key_size:literal $(,)?
    ) => {
        $(#[$meta])*
        #[derive(Clone)]
        pub struct $name($crate::hctr::Hctr2<$cipher, Polyval>);

        impl $name {
            /// Creates a HCTR2 cipher.
            pub fn new(key: &[u8; $key_size]) -> Self {
                let cipher = <$cipher>::new(key);
                Self($crate::hctr::Hctr2::new(cipher))
            }

            /// Encrypts `src` into `dst` using `tweak`.
            ///
            /// It is an error if `dst` is not at least as long
            /// as `src`, if either are less than one block, or
            /// if `tweak` is longer than a block.
            pub fn seal(
                &mut self,
                dst: &mut [u8],
                src: &[u8],
                tweak: &[u8],
            ) -> Result<(), $crate::Error> {
                self.0.seal(dst, src, tweak)
            }

            /// Decrypts `src` into `dst` using `tweak`.
            ///
            /// It is an error if `dst` is not at least as long
            /// as `src`, if either are less than one block, or
            /// if `tweak` is longer than a block.
            pub fn open(
                &mut self,
                dst: &mut [u8],
                src: &[u8],
                tweak: &[u8],
            ) -> Result<(), $crate::Error> {
                self.0.open(dst, src, tweak)
            }

            /// Encrypts `data` in-place using `tweak`.
            ///
            /// It is an error if `data` is less than one block
            /// or if `tweak` is longer than a block.
            pub fn seal_in_place(
                &mut self,
                data: &mut [u8],
                tweak: &[u8],
            ) -> Result<(), $crate::Error> {
                self.0.seal_in_place(data, tweak)
            }

            /// Decrypts `data` in-place using `tweak`.
            ///
            /// It is an error if `data` is less than one block
            /// or if `tweak` is longer than a block.
            pub fn open_in_place(
                &mut self,
                data: &mut [u8],
                tweak: &[u8],
            ) -> Result<(), $crate::Error> {
                self.0.open_in_place(data, tweak)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }
    };
}

impl_hctr! {
    /// HCTR2 with AES-128.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use hctr2::Hctr2Aes128;
    ///
    /// let mut hctr = Hctr2Aes128::new(&[
    ///     0x74, 0xf9, 0x8f, 0x60, 0x78, 0x6a, 0xbf, 0xa8,
    ///     0x5b, 0x0b, 0xbb, 0xa0, 0x59, 0xe0, 0xf9, 0x1e,
    /// ]);
    /// let mut data = [
    ///     0x6b, 0x26, 0x83, 0x7b, 0xdc, 0x1c, 0x58, 0x3d,
    ///     0xc1, 0x42, 0xc6, 0xab, 0x7b, 0x3f, 0x43, 0xb0,
    /// ];
    /// hctr.seal_in_place(&mut data, &[]);
    /// let want = [
    ///     0xdd, 0x05, 0xa8, 0xae, 0x51, 0xf1, 0xe8, 0x21,
    ///     0x2f, 0xd6, 0xc3, 0x3b, 0x94, 0x67, 0x03, 0x6d,
    /// ];
    /// assert_eq!(data, want);
    /// ```
    Hctr2Aes128, Aes128, 16,
}

impl_hctr! {
    /// HCTR2 with AES-192.
    ///
    /// # ⚠️ Warning
    ///
    /// Except for compatibility purposes, there isn't any reason
    /// to use `Hctr2Aes192`. Use [`Hctr2Aes128`] or
    /// [`Hctr2Aes256`] instead.
    Hctr2Aes192, Aes192, 24,
}

impl_hctr! {
    /// HCTR2 with AES-256.
    Hctr2Aes256, Aes256, 32,
}

union Aes<A, G> {
    asm: ManuallyDrop<A>,
    soft: ManuallyDrop<G>,
}

macro_rules! impl_aes {
    ($name:ident, $key_size:literal $(,)?) => {
        pub(crate) struct $name(Aes<imp::$name, generic::$name>);

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

        impl BlockSize for $name {
            type BlockSize = typenum::U16;
        }

        impl BlockCipher for $name {
            fn encrypt_with_backend(&self, f: impl BlockClosure<BlockSize = U16>) {
                if imp::supported() {
                    // SAFETY: `supported` is true, so `asm` is
                    // initialized.
                    unsafe { f.call(&mut self.0.asm.get_enc_backend()) }
                } else {
                    // SAFETY: `supported` is false, so `soft` is
                    // initialized.
                    unsafe { f.call(&mut self.0.soft.get_enc_backend()) }
                }
            }

            fn decrypt_with_backend(&self, f: impl BlockClosure<BlockSize = U16>) {
                if imp::supported() {
                    // SAFETY: `supported` is true, so `asm` is
                    // initialized.
                    unsafe { f.call(&mut self.0.asm.get_dec_backend()) }
                } else {
                    // SAFETY: `supported` is false, so `soft` is
                    // initialized.
                    unsafe { f.call(&mut self.0.soft.get_dec_backend()) }
                }
            }
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

        // impl Xctr for $name {
        //     fn crypt(&self, dst: &mut [u8], src: &[u8], nonce: &Block<Self>) {
        //         if imp::supported() {
        //             // SAFETY: `supported` is true, so `asm` is
        //             // initialized.
        //             unsafe { self.0.asm.xctr_crypt(dst, src, nonce) }
        //         } else {
        //             xctr::crypt(self, dst, src, nonce)
        //         }
        //     }

        //     fn crypt_in_place(&self, data: &mut [u8], nonce: &Block<Self>) {
        //         if imp::supported() {
        //             // SAFETY: `supported` is true, so `asm` is
        //             // initialized.
        //             unsafe { self.0.asm.xctr_crypt_in_place(data, nonce) }
        //         } else {
        //             xctr::crypt_in_place(self, data, nonce)
        //         }
        //     }
        // }

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
impl_aes!(Aes128, 16);
impl_aes!(Aes192, 24);
impl_aes!(Aes256, 32);
