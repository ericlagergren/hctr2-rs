//! Low level cryptography.
//!
//! # Warning
//!
//! Do not use this module unless you know what you're doing.

#![cfg(feature = "hazmat")]
#![cfg_attr(docsrs, doc(cfg(feature = "hazmat")))]

#[cfg(feature = "polyval")]
#[cfg_attr(docsrs, doc(cfg(feature = "polyval")))]
pub use polyhash::Polyval;

pub use crate::{hctr::Hctr2, poly::Poly};
