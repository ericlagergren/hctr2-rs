//! XCTR stream cipher mode.

use generic_array::ArrayLength;
use typenum::Unsigned;

use super::{
    hctr::dprintln,
    util::{xor_in_place, xor_into},
};
use crate::block::{Block, BlockBackend, BlockCipher, BlockClosure, BlockSize, Blocks, Stride};

/// XCTR stream encryption.
///
/// # ⚠️ Warning
///
/// This is a low-level primitive. Only use it if you know what
/// you are doing.
pub trait Xctr: BlockSize {
    /// The underlying block cipher.
    type Cipher: BlockCipher;

    /// Creates an [`Xctr`].
    fn new(cipher: Self::Cipher, nonce: &Block<Self>) -> Self;

    /// XORs each byte in `src` with the corresponding byte from
    /// the XCTR keystream and writes the resulting byte to
    /// `dst`.
    ///
    /// # Panics
    ///
    /// This method panics if `dst` and `src` do not have the
    /// same length.
    fn apply_keystream(&mut self, dst: &mut [u8], src: &[u8]);

    /// XORs each byte in `data` with the corresponding byte from
    /// the XCTR keystream in place.
    fn apply_keystream_in_place(&mut self, data: &mut [u8]);
}

/// Block-level stream cipher.
///
/// # ⚠️ Warning
///
/// This is a low-level primitive. Only use it if you know what
/// you are doing.
pub trait StreamCipherCore: BlockSize + Sized {
    /// Invokes the closure to process block(s).
    fn process_with_backend(&mut self, f: impl StreamClosure<BlockSize = Self::BlockSize>);

    /// Writes the next keystream block to `block`.
    #[inline]
    fn write_keystream_block(&mut self, block: &mut Block<Self>) {
        self.process_with_backend(WriteBlock { block });
    }

    /// Writes the next keystream blocks to `blocks`.
    #[inline]
    fn write_keystream_blocks(&mut self, blocks: &mut [Block<Self>]) {
        self.process_with_backend(WriteBlocks { blocks });
    }

    /// XORs `src` with the next keystream block and writes it to
    /// `dst`.
    #[inline]
    fn apply_keystream_block(&mut self, dst: &mut Block<Self>, src: &Block<Self>) {
        self.process_with_backend(ApplyBlock { dst, src });
    }

    /// XORs `block` with the next keystream block.
    #[inline]
    fn apply_keystream_block_in_place(&mut self, block: &mut Block<Self>) {
        self.process_with_backend(ApplyBlockInPlace { block });
    }

    /// XORs `src` with the next keystream block and writes it to
    /// `dst`.
    ///
    /// # Panics
    ///
    /// This method panics if `dst` and `src` have different
    /// lengths.
    #[inline]
    fn apply_keystream_blocks(&mut self, dst: &mut [Block<Self>], src: &[Block<Self>]) {
        assert_eq!(dst.len(), src.len());

        self.process_with_backend(ApplyBlocks { dst, src });
    }

    /// XORs `blocks` with the next keystream blocks.
    #[inline]
    fn apply_keystream_blocks_in_place(&mut self, blocks: &mut [Block<Self>]) {
        self.process_with_backend(ApplyBlocksInPlace { blocks });
    }
}

struct WriteBlock<'a, S: ArrayLength> {
    block: &'a mut Block<Self>,
}

impl<S: ArrayLength> BlockSize for WriteBlock<'_, S> {
    type BlockSize = S;
}

impl<S: ArrayLength> StreamClosure for WriteBlock<'_, S> {
    #[inline(always)]
    fn call<B: StreamBackend<BlockSize = S>>(self, backend: &mut B) {
        backend.gen_ks_block(self.block);
    }
}

struct WriteBlocks<'a, S: ArrayLength> {
    blocks: &'a mut [Block<Self>],
}

impl<S: ArrayLength> BlockSize for WriteBlocks<'_, S> {
    type BlockSize = S;
}

impl<S: ArrayLength> StreamClosure for WriteBlocks<'_, S> {
    #[inline(always)]
    fn call<B: StreamBackend<BlockSize = S>>(self, backend: &mut B) {
        let (head, tail) = Blocks::<B>::chunks_from_slice_mut(self.blocks);
        for blocks in head {
            backend.gen_ks_blocks(blocks);
        }
        for block in tail {
            backend.gen_ks_block(block);
        }
    }
}

struct ApplyBlock<'dst, 'src, S: ArrayLength> {
    dst: &'dst mut Block<Self>,
    src: &'src Block<Self>,
}

impl<S: ArrayLength> BlockSize for ApplyBlock<'_, '_, S> {
    type BlockSize = S;
}

impl<S: ArrayLength> StreamClosure for ApplyBlock<'_, '_, S> {
    #[inline(always)]
    fn call<B: StreamBackend<BlockSize = S>>(self, backend: &mut B) {
        let mut ks = Block::<B>::default();
        backend.gen_ks_block(&mut ks);
        xor_into(self.dst, &ks, self.src);
    }
}

struct ApplyBlockInPlace<'a, S: ArrayLength> {
    block: &'a mut Block<Self>,
}

impl<S: ArrayLength> BlockSize for ApplyBlockInPlace<'_, S> {
    type BlockSize = S;
}

impl<S: ArrayLength> StreamClosure for ApplyBlockInPlace<'_, S> {
    #[inline(always)]
    fn call<B: StreamBackend<BlockSize = S>>(self, backend: &mut B) {
        let mut ks = Block::<Self>::default();
        backend.gen_ks_block(&mut ks);
        xor_in_place(self.block, &ks);
    }
}

struct ApplyBlocks<'dst, 'src, S: ArrayLength> {
    dst: &'dst mut [Block<Self>],
    src: &'src [Block<Self>],
}

impl<S: ArrayLength> BlockSize for ApplyBlocks<'_, '_, S> {
    type BlockSize = S;
}

impl<S: ArrayLength> StreamClosure for ApplyBlocks<'_, '_, S> {
    #[inline(always)]
    fn call<B: StreamBackend<BlockSize = S>>(self, backend: &mut B) {
        let (dst_head, dst_tail) = Blocks::<B>::chunks_from_slice_mut(self.dst);
        let (src_head, src_tail) = Blocks::<B>::chunks_from_slice(self.src);
        dprintln!("Stride = {}", <B as Stride>::Stride::USIZE);
        dprintln!(
            "dst={:?} src={:?}",
            (dst_head.len(), dst_tail.len()),
            (src_head.len(), src_tail.len()),
        );
        for (dst, src) in dst_head.iter_mut().zip(src_head) {
            let mut ks = Blocks::<B>::default();
            backend.gen_ks_blocks(&mut ks);
            for ((dst, ks), src) in dst.iter_mut().zip(&ks).zip(src) {
                xor_into(dst, ks, &src);
            }
        }
        for (dst, src) in dst_tail.iter_mut().zip(src_tail) {
            let mut ks = Block::<B>::default();
            backend.gen_ks_block(&mut ks);
            xor_into(dst, &ks, &src);
        }
    }
}

struct ApplyBlocksInPlace<'a, S: ArrayLength> {
    blocks: &'a mut [Block<Self>],
}

impl<S: ArrayLength> BlockSize for ApplyBlocksInPlace<'_, S> {
    type BlockSize = S;
}

impl<S: ArrayLength> StreamClosure for ApplyBlocksInPlace<'_, S> {
    #[inline(always)]
    fn call<B: StreamBackend<BlockSize = S>>(self, backend: &mut B) {
        let (head, tail) = Blocks::<B>::chunks_from_slice_mut(self.blocks);
        for blocks in head {
            let mut ks = Blocks::<B>::default();
            backend.gen_ks_blocks(&mut ks);
            for (block, ks) in blocks.iter_mut().zip(ks) {
                xor_in_place(block, &ks);
            }
        }
        for block in tail {
            let mut ks = Block::<B>::default();
            backend.gen_ks_block(&mut ks);
            xor_in_place(block, &ks);
        }
    }
}

/// Used by [`StreamBackend`].
///
/// # ⚠️ Warning
///
/// This is a low-level primitive. Only use it if you know what
/// you are doing.
pub trait StreamClosure: BlockSize {
    /// Invokes the closure with a [`StreamBackend`].
    fn call<B: StreamBackend<BlockSize = Self::BlockSize>>(self, backend: &mut B);
}

/// Implemented by stream cipher backends.
///
/// # ⚠️ Warning
///
/// This is a low-level primitive. Only use it if you know what
/// you are doing.
pub trait StreamBackend: BlockSize + Stride {
    /// Writes the next keystream block to `block`.
    fn gen_ks_block(&mut self, block: &mut Block<Self>);

    /// Writes the next keystream blocks to `blocks`.
    #[inline(always)]
    fn gen_ks_blocks(&mut self, blocks: &mut Blocks<Self>) {
        for block in blocks {
            self.gen_ks_block(block);
        }
    }
}

#[derive(Clone, Debug)]
struct CtrNonce<S: BlockSize> {
    ctr: usize,
    nonce: Block<S>,
}

impl<S: BlockSize> CtrNonce<S> {
    fn new(nonce: Block<S>) -> Self {
        Self { ctr: 1, nonce }
    }

    fn next(&mut self) -> Block<S> {
        let mut block = Block::<S>::default();
        let bytes = self.ctr.to_le_bytes();
        block[..bytes.len()].copy_from_slice(&bytes);
        xor_in_place(&mut block, &self.nonce);
        block
    }
}

/// A generic implementation of [`Xctr`].
///
/// # ⚠️ Warning
///
/// This is a low-level primitive. Only use it if you know what
/// you are doing.
#[derive(Clone, Debug)]
pub struct XctrCore<'a, C>
where
    C: BlockCipher,
{
    cipher: &'a C,
    ctr: CtrNonce<C>,
}

impl<'a, C: BlockCipher> XctrCore<'a, C> {
    /// Creates a new `XctrCore`.
    pub fn new(cipher: &'a C, nonce: &'a Block<C>) -> Self {
        Self {
            cipher,
            ctr: CtrNonce::new(nonce.clone()),
        }
    }

    /// XORs each byte in `src` with the corresponding byte from
    /// the XCTR keystream and writes the resulting byte to
    /// `dst`.
    ///
    /// # Panics
    ///
    /// This method panics if `dst` and `src` do not have the
    /// same length.
    pub fn apply_keystream(mut self, dst: &mut [u8], src: &[u8]) {
        assert!(dst.len() == src.len());

        let (dst_head, dst_tail) = Block::<C>::chunks_from_slice_mut(dst);
        let (src_head, src_tail) = Block::<C>::chunks_from_slice(src);
        if !dst_head.is_empty() {
            self.apply_keystream_blocks(dst_head, src_head);
        }
        if !dst_tail.is_empty() {
            let mut block = Block::<C>::default();
            self.write_keystream_block(&mut block);
            xor_into(dst, &block, src_tail);
        }
    }

    /// XORs each byte in `data` with the corresponding byte from
    /// the XCTR keystream in place.
    pub fn apply_keystream_in_place(mut self, data: &mut [u8]) {
        let (head, tail) = Block::<C>::chunks_from_slice_mut(data);
        if !head.is_empty() {
            self.apply_keystream_blocks_in_place(head);
        }
        if !tail.is_empty() {
            let mut block = Block::<C>::default();
            self.write_keystream_block(&mut block);
            xor_in_place(tail, &mut block);
        }
    }
}

impl<C: BlockCipher> BlockSize for XctrCore<'_, C> {
    type BlockSize = <C as BlockSize>::BlockSize;
}

impl<'a, C: BlockCipher> StreamCipherCore for XctrCore<'a, C> {
    #[inline(always)]
    fn process_with_backend(&mut self, f: impl StreamClosure<BlockSize = Self::BlockSize>) {
        let Self { cipher, ctr } = self;
        cipher.encrypt_with_backend(XctrClosure::<C, _> { ctr, f });
    }
}

/// A [`BlockClosure`].
struct XctrClosure<'a, S, F>
where
    S: BlockSize,
{
    ctr: &'a mut CtrNonce<S>,
    f: F,
}

impl<S, F> BlockClosure for XctrClosure<'_, S, F>
where
    S: BlockSize,
    F: StreamClosure<BlockSize = S::BlockSize>,
{
    #[inline(always)]
    fn call<B: BlockBackend<BlockSize = Self::BlockSize>>(self, backend: &mut B) {
        let Self { ctr, f } = self;
        f.call(&mut Backend::<B> { ctr, backend });
    }
}

impl<S, F> BlockSize for XctrClosure<'_, S, F>
where
    S: BlockSize,
{
    type BlockSize = S::BlockSize;
}

struct Backend<'a, B: BlockBackend> {
    ctr: &'a mut CtrNonce<B>,
    backend: &'a mut B,
}

impl<B: BlockBackend> StreamBackend for Backend<'_, B> {
    #[inline(always)]
    fn gen_ks_block(&mut self, block: &mut Block<Self>) {
        dprintln!("gen_ks_block ctr={:?}", *self.ctr);
        *block = self.ctr.next();
        self.backend.proc_block_in_place(block);
    }

    #[inline(always)]
    fn gen_ks_blocks(&mut self, blocks: &mut Blocks<Self>) {
        for block in blocks.iter_mut() {
            *block = self.ctr.next();
        }
        self.backend.proc_blocks_in_place(blocks);
    }
}

impl<B: BlockBackend> Stride for Backend<'_, B> {
    type Stride = <B as Stride>::Stride;
}

impl<B: BlockBackend> BlockSize for Backend<'_, B> {
    type BlockSize = <B as BlockSize>::BlockSize;
}
