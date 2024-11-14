use generic_array::{ArrayLength, GenericArray};

/// A block cipher.
pub trait BlockCipher: Sized {
    /// The size in bytes of a block.
    const BLOCK_SIZE: usize;

    /// TODO
    type BlockSize: ArrayLength;

    /// TODO
    type Stride: ArrayLength;

    /// Encrypts `src` into `dst`.
    fn encrypt_block(&self, dst: &mut Block<Self>, src: &Block<Self>);

    /// Encrypts `data` in place.
    fn encrypt_block_in_place(&self, data: &mut Block<Self>);

    /// TODO
    fn encrypt_blocks(
        &self,
        dst: &mut GenericArray<Block<Self>, Self::Stride>,
        src: &GenericArray<Block<Self>, Self::Stride>,
    ) {
        for (dst, src) in dst.iter_mut().zip(src) {
            self.encrypt_block(dst.into(), src.into());
        }
    }

    /// Decrypts `src` into `dst`.
    fn decrypt_block(&self, dst: &mut Block<Self>, src: &Block<Self>);

    /// Decrypts `data` in place.
    fn decrypt_block_in_place(&self, data: &mut Block<Self>);

    #[doc(hidden)]
    fn xctr(&self, dst: &mut [u8], src: &[u8], nonce: &Block<Self>) {
        crate::xctr::xctr::<Self>(self, dst, src, nonce)
    }

    #[doc(hidden)]
    fn xctr_in_place(&self, data: &mut [u8], nonce: &Block<Self>) {
        crate::xctr::xctr_in_place::<Self>(self, data, nonce)
    }
}

/// TODO
pub const BLOCK_SIZE: usize = 16;

/// TODO
pub type Block<C> = GenericArray<u8, <C as BlockCipher>::BlockSize>;
