use super::{
    block::{Block, BlockSize},
    util,
};

/// A polynomial hash function in `GF(2ⁿ)` where `n` is the block
/// size in bits.
///
/// # ⚠️ Warning
///
/// This is a low-level primitive. Only use it if you know what
/// you are doing.
pub trait Poly: BlockSize + Clone + Sized {
    /// Creates a new hash function.
    ///
    /// *Note*: `key` is the output of the block cipher.
    fn new(key: &Block<Self>) -> Self;

    /// Writes zero or more blocks to the hash.
    fn update(&mut self, blocks: &[Block<Self>]);

    /// Writes zero or more blocks to the running hash.
    ///
    /// `blocks` is padded with zeros out to a multiple of the
    /// block size.
    fn update_padded(&mut self, blocks: &[u8]) {
        let (head, tail) = util::as_blocks::<Self>(blocks);
        if !head.is_empty() {
            self.update(head);
        }
        if !tail.is_empty() {
            let mut block = Block::<Self>::default();
            #[allow(
                clippy::indexing_slicing,
                reason = "The compiler can prove the slice is in bounds."
            )]
            block[..tail.len()].copy_from_slice(tail);
            self.update(&[block]);
        }
    }

    /// The internal state of the hash function.
    ///
    /// This is typically a single field element in `GF(2ⁿ)`.
    ///
    /// *Note*: The state should NOT include the key.
    type State: Clone + Default + Sized;

    /// Exports the current state of the hash.
    fn export(&self) -> Self::State;

    /// Resets the hash function to `state`.
    ///
    /// *Note*: The hash function should reuse the same key.
    fn reset(&mut self, state: &Self::State);

    /// Returns the hash result.
    fn tag(&self) -> Block<Self>;
}

#[cfg(feature = "polyval")]
#[cfg_attr(docsrs, doc(cfg(feature = "polyval")))]
mod polyval {
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
            // `key` is the output of a block cipher, so the
            // likelihood that `key` is zero is cryptographically
            // negligible.
            let key = Key::new_unchecked(key.as_ref());
            Polyval::new(&key)
        }
        fn update(&mut self, blocks: &[Block<Self>]) {
            let blocks = Block::<Self>::into_chunks::<BLOCK_SIZE>(blocks);
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
