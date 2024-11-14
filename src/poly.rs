use generic_array::GenericArray;
use polyhash::{Key, Polyval};
use typenum::{Unsigned, U16};

use super::block::{Block, BlockSize};

/// A polynomial hash function in GF(2ⁿ) where `n` is the block
/// size in bits.
///
/// # Warning
///
/// This is a low-level primitive. Only use it if you know what
/// you are doing.
pub trait Poly: BlockSize + Clone + Sized {
    /// Creates a new polynomial.
    fn new(key: &Block<Self>) -> Self;
    /// Writes one or more blocks to the running hash.
    fn update(&mut self, blocks: &[Block<Self>]);
    /// Writes one or more blocks to the running hash.
    ///
    /// `blocks` is padded with zeros out to a multiple of the
    /// block size.
    fn update_padded(&mut self, blocks: &[u8]);
    /// Returns the current state of the polynomial.
    fn tag(self) -> Block<Self>;
}

#[cfg(feature = "polyval")]
#[cfg_attr(docsrs, doc(cfg(feature = "polyval")))]
impl BlockSize for Polyval {
    type BlockSize = U16;
}

#[cfg(feature = "polyval")]
#[cfg_attr(docsrs, doc(cfg(feature = "polyval")))]
impl Poly for Polyval {
    fn new(key: &Block<Self>) -> Self {
        let key = Key::new_unchecked((*key).into());
        Polyval::new(&key)
    }
    fn update(&mut self, blocks: &[Block<Self>]) {
        let blocks = GenericArray::into_chunks::<{ <Self as BlockSize>::BlockSize::USIZE }>(blocks);
        self.update_blocks(blocks);
    }
    fn update_padded(&mut self, blocks: &[u8]) {
        self.update_padded(blocks)
    }
    fn tag(self) -> Block<Self> {
        let tag: [u8; 16] = self.tag().into();
        tag.into()
    }
}
