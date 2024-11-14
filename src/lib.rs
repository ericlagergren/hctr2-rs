//! The HCTR2 length-preserving encryption algorithm.
//!
//! HCTR2 is designed for situations where the length of the
//! ciphertext must exactly match the length of the plaintext,
//! like disk encryption.
//!
//! This implementation uses a hardware-accelerated POLYVAL
//! implementation when possible; the block cipher is left to the
//! caller. The recommended block cipher is AES. The
//! [`aes`][mod@aes] module provides optimized AES
//! implementations.
//!
//! [hctr2]: https://eprint.iacr.org/2021/1441

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]
#![deny(
    clippy::alloc_instead_of_core,
    clippy::cast_lossless,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::expect_used,
    clippy::implicit_saturating_sub,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::panic,
    clippy::ptr_as_ptr,
    clippy::string_slice,
    clippy::transmute_ptr_to_ptr,
    clippy::undocumented_unsafe_blocks,
    clippy::unimplemented,
    clippy::unwrap_used,
    clippy::wildcard_imports,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

pub mod aes;
mod block;
mod cipher;
mod tests;
mod xctr;

pub use crate::{block::BlockCipher, cipher::Hctr2};
