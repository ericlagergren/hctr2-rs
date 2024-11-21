//! Low level cryptography.
//!
//! # ⚠️ Warning
//!
//! Do not use this module unless you know what you're doing.

#![cfg(feature = "hazmat")]
#![cfg_attr(docsrs, doc(cfg(feature = "hazmat")))]

pub use generic_array;
#[cfg(feature = "polyval")]
#[cfg_attr(docsrs, doc(cfg(feature = "polyval")))]
pub use polyhash::Polyval;
pub use typenum;

pub use super::{
    block::{Block, BlockBackend, BlockCipher, BlockClosure, BlockSize},
    hctr::{Backend, Hctr2},
    poly::Poly,
};

/// TODO
pub mod xctr {
    pub use crate::xctr::*;
}
