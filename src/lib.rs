//! The [HCTR2] length-preserving encryption algorithm.
//!
//! HCTR2 is a tweakable super-pseudorandom permutation designed
//! for situations where the length of the ciphertext must
//! exactly match the length of the plaintext, like disk
//! encryption.
//!
//! This crate provides the standard AES-based instantiations by
//! default. In also provides opt-in support for custom block
//! ciphers and reduction polynomials.
//!
//! # Examples
//!
//! ```rust
//! use hctr2::{Hctr2Aes256, hazmat::Hctr2};
//!
//! let hctr = Hctr2Aes256::new(&[
//!     0x74, 0xf9, 0x8f, 0x60, 0x78, 0x6a, 0xbf, 0xa8,
//!     0x5b, 0x0b, 0xbb, 0xa0, 0x59, 0xe0, 0xf9, 0x1e,
//! ]);
//! let mut data = [
//!     0x6b, 0x26, 0x83, 0x7b, 0xdc, 0x1c, 0x58, 0x3d,
//!     0xc1, 0x42, 0xc6, 0xab, 0x7b, 0x3f, 0x43, 0xb0,
//! ];
//! hctr.seal_in_place(&mut data, &[]);
//! let want = [
//!     0xdd, 0x05, 0xa8, 0xae, 0x51, 0xf1, 0xe8, 0x21,
//!     0x2f, 0xd6, 0xc3, 0x3b, 0x94, 0x67, 0x03, 0x6d,
//! ];
//! assert_eq!(data, want);
//! ```
//!
//! # Features
//!
//! - `aes`: Enable the standard HCTR2 instantiations with
//!   AES-128, AES-192, and AES-256 (default).
//! - `hazmat`: Enable cryptographically dangerous features.
//! - `polyval`: Enable POLYVAL support. (Enabled by `aes`.)
//! - `soft`: Force software implementations where possible.
//! - `std`: Enable `std` support.
//! - `zeroize`: Enable [`zeroize`] support.
//!
//! [HCTR2]: https://eprint.iacr.org/2021/1441
//! [`zeroize`]: https://docs.rs/zeroize/latest/zeroize/

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

mod aes;
mod block;
pub mod hazmat;
mod hctr;
mod poly;
mod tests;
mod xctr;

pub use aes::{Hctr2Aes128, Hctr2Aes192, Hctr2Aes256};
pub use xctr::Foo;

pub use crate::{block::BlockCipher, hctr::Error};
