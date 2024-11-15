use super::block::{Block, BlockSize};

/// A polynomial hash function in GF(2ⁿ) where `n` is the block
/// size in bits.
///
/// # Warning
///
/// This is a low-level primitive. Only use it if you know what
/// you are doing.
pub trait Poly: BlockSize + Clone + Sized {
    /// Import/export state.
    type State: Clone + Default + Sized;
    /// Creates a new polynomial.
    fn new(key: &Block<Self>) -> Self;
    /// Writes one or more blocks to the running hash.
    fn update(&mut self, blocks: &[Block<Self>]);
    /// Writes one or more blocks to the running hash.
    ///
    /// `blocks` is padded with zeros out to a multiple of the
    /// block size.
    fn update_padded(&mut self, blocks: &[u8]);
    /// Exports the current state of the hash.
    fn export(&self) -> Self::State;
    /// Resets the hash function to `state`.
    fn reset(&mut self, state: &Self::State);
    /// Returns the hash result.
    fn tag(&self) -> Block<Self>;
}

#[cfg(feature = "polyval")]
#[cfg_attr(docsrs, doc(cfg(feature = "polyval")))]
mod polyval {
    use generic_array::GenericArray;
    use polyhash::{experimental::State, Key, Polyval, BLOCK_SIZE};
    use typenum::U16;

    use super::Poly;
    use crate::block::{Block, BlockSize};

    impl BlockSize for Polyval {
        type BlockSize = U16;
    }

    impl Poly for Polyval {
        type State = State;
        fn new(key: &Block<Self>) -> Self {
            let key = Key::new_unchecked(key.as_ref());
            Polyval::new(&key)
        }
        fn update(&mut self, blocks: &[Block<Self>]) {
            let blocks = GenericArray::into_chunks::<BLOCK_SIZE>(blocks);
            self.update(blocks);
        }
        fn update_padded(&mut self, blocks: &[u8]) {
            self.update_padded(blocks)
        }
        fn tag(&self) -> Block<Self> {
            let tag: [u8; 16] = self.current_tag().into();
            tag.into()
        }
        fn export(&self) -> Self::State {
            self.export()
        }
        fn reset(&mut self, state: &Self::State) {
            self.reset(state)
        }
    }
}
