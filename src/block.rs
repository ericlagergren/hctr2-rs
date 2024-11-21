use generic_array::{ArrayLength, GenericArray};
use typenum::{UInt, Unsigned};

/// A block cipher.
///
/// # ⚠️ Warning
///
/// This is a low-level primitive. Only use it if you know what
/// you are doing.
pub trait BlockCipher: BlockSize + Sized {
    /// Encrypt block(s) with a particular backend.
    fn encrypt_with_backend(&self, f: impl BlockClosure<BlockSize = Self::BlockSize>);

    /// Encrypts `src` into `dst`.
    fn encrypt_block(&self, dst: &mut Block<Self>, src: &Block<Self>) {
        self.encrypt_with_backend(BlockCtx { dst, src });
    }

    /// Encrypts `block` in place.
    fn encrypt_block_in_place(&self, block: &mut Block<Self>) {
        self.encrypt_with_backend(InPlaceBlockCtx { block });
    }

    /// Decrypt block(s) with a particular backend.
    fn decrypt_with_backend(&self, f: impl BlockClosure<BlockSize = Self::BlockSize>);

    /// Decrypts `src` into `dst`.
    fn decrypt_block(&self, dst: &mut Block<Self>, src: &Block<Self>) {
        self.decrypt_with_backend(BlockCtx { dst, src });
    }
}

impl<C: BlockCipher> BlockCipher for &C {
    // TODO(eric): Other methods.
    fn encrypt_with_backend(&self, f: impl BlockClosure<BlockSize = Self::BlockSize>) {
        (*self).encrypt_with_backend(f)
    }
    fn decrypt_with_backend(&self, f: impl BlockClosure<BlockSize = Self::BlockSize>) {
        (*self).decrypt_with_backend(f)
    }
}

/// Used by [`BlockBackend`].
///
/// # ⚠️ Warning
///
/// This is a low-level primitive. Only use it if you know what
/// you are doing.
pub trait BlockClosure: BlockSize {
    /// Invokes the closure with a [`BlockBackend`].
    fn call<B: BlockBackend<BlockSize = Self::BlockSize>>(self, backend: &mut B);
}

/// Specifies the size of blocks used.
pub trait BlockSize {
    /// The size in bytes of a block.
    type BlockSize: ArrayLength;
}

impl<T: BlockSize> BlockSize for &T {
    type BlockSize = T::BlockSize;
}

impl<T: BlockSize> BlockSize for &mut T {
    type BlockSize = T::BlockSize;
}

impl<U, B> BlockSize for UInt<U, B>
where
    Self: ArrayLength,
{
    type BlockSize = Self;
}

/// A single block of data.
///
/// # ⚠️ Warning
///
/// This is a low-level primitive. Only use it if you know what
/// you are doing.
pub type Block<C> = GenericArray<u8, <C as BlockSize>::BlockSize>;

/// Implemented by block cipher backends.
///
/// # ⚠️ Warning
///
/// This is a low-level primitive. Only use it if you know what
/// you are doing.
pub trait BlockBackend: BlockSize + Stride {
    /// Process a single block from `src` into `dst`.
    fn proc_block(&self, dst: &mut Block<Self>, src: &Block<Self>);

    /// Process a single block in place.
    fn proc_block_in_place(&self, block: &mut Block<Self>);

    /// Process a multiple blocks from `src` into `dst`.
    #[inline(always)]
    fn proc_blocks(&self, dst: &mut Blocks<Self>, src: &Blocks<Self>) {
        assert_eq!(dst.len(), src.len());

        for (dst, src) in dst.iter_mut().zip(src.iter()) {
            self.proc_block(dst, src);
        }
    }

    /// Process a multiple blocks in place.
    #[inline(always)]
    fn proc_blocks_in_place(&self, blocks: &mut Blocks<Self>) {
        for block in blocks {
            self.proc_block_in_place(block);
        }
    }
}

/// Specifies the number of blocks processed at once.
///
/// # ⚠️ Warning
///
/// This is a low-level primitive. Only use it if you know what
/// you are doing.
pub trait Stride {
    /// The number of blocks processed at once.
    type Stride: ArrayLength;
}

/// A group of blocks processed at once.
///
/// # ⚠️ Warning
///
/// This is a low-level primitive. Only use it if you know what
/// you are doing.
pub type Blocks<B> = GenericArray<Block<B>, <B as Stride>::Stride>;

struct BlockCtx<'a, S: ArrayLength> {
    dst: &'a mut Block<Self>,
    src: &'a Block<Self>,
}

impl<S: ArrayLength> BlockSize for BlockCtx<'_, S> {
    type BlockSize = S;
}

impl<S: ArrayLength> BlockClosure for BlockCtx<'_, S> {
    #[inline(always)]
    fn call<B: BlockBackend<BlockSize = S>>(self, backend: &mut B) {
        backend.proc_block(self.dst, self.src)
    }
}

struct InPlaceBlockCtx<'a, S: ArrayLength> {
    block: &'a mut Block<Self>,
}

impl<S: ArrayLength> BlockSize for InPlaceBlockCtx<'_, S> {
    type BlockSize = S;
}

impl<S: ArrayLength> BlockClosure for InPlaceBlockCtx<'_, S> {
    #[inline(always)]
    fn call<B: BlockBackend<BlockSize = S>>(self, backend: &mut B) {
        backend.proc_block_in_place(self.block)
    }
}

struct BlocksCtx<'a, S: ArrayLength> {
    dst: &'a mut [Block<Self>],
    src: &'a [Block<Self>],
}

impl<S: ArrayLength> BlockSize for BlocksCtx<'_, S> {
    type BlockSize = S;
}

impl<S: ArrayLength> BlockClosure for BlocksCtx<'_, S> {
    #[inline(always)]
    fn call<B: BlockBackend<BlockSize = S>>(self, backend: &mut B) {
        if B::Stride::USIZE > 1 {
            // TODO
        } else {
            for (dst, src) in self.dst.iter_mut().zip(self.src) {
                backend.proc_block(dst, src);
            }
        }
    }
}

struct BlocksCtxInPlace<'a, S: ArrayLength> {
    blocks: &'a mut Blocks<Self>,
}

impl<S: ArrayLength> BlockSize for BlocksCtxInPlace<'_, S> {
    type BlockSize = S;
}

impl<S: ArrayLength> Stride for BlocksCtxInPlace<'_, S> {
    type Stride = S;
}

impl<S: ArrayLength> BlockClosure for BlocksCtxInPlace<'_, S> {
    #[inline(always)]
    fn call<B: BlockBackend<BlockSize = S>>(self, backend: &mut B) {
        if B::Stride::USIZE > 1 {
            // TODO
        } else {
            for block in self.blocks {
                backend.proc_block_in_place(block);
            }
        }
    }
}

/// A [`BlockBackend`] by ref.
#[repr(transparent)]
pub(crate) struct ByRef<'a, B>(pub &'a B);

impl<B: Stride> Stride for ByRef<'_, B> {
    type Stride = B::Stride;
}

impl<B: BlockSize> BlockSize for ByRef<'_, B> {
    type BlockSize = B::BlockSize;
}

impl<B: BlockBackend> BlockBackend for ByRef<'_, B> {
    fn proc_block(&self, dst: &mut Block<Self>, src: &Block<Self>) {
        self.0.proc_block(dst, src)
    }
    fn proc_block_in_place(&self, block: &mut Block<Self>) {
        self.0.proc_block_in_place(block)
    }
    fn proc_blocks(&self, dst: &mut Blocks<Self>, src: &Blocks<Self>) {
        self.0.proc_blocks(dst, src)
    }
    fn proc_blocks_in_place(&self, blocks: &mut Blocks<Self>) {
        self.0.proc_blocks_in_place(blocks)
    }
}
