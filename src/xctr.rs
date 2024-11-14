use core::iter::zip;

use typenum::Unsigned;

use crate::block::{Block, BlockCipher, BlockSize};

/// TODO
pub struct Foo<'a>(Xctr<&'a crate::aes::Aes128>);
impl Foo<'_> {
    /// TODO
    pub fn encrypt(&self, dst: &mut [u8], src: &[u8], nonce: &Block<typenum::U16>) {
        self.0.encrypt(dst, src, nonce)
    }
}

/// XCTR stream encryption.
///
/// NB: This implements `N ⊕ XCTR_k(S)[0;|N|]`.
#[derive(Clone)]
pub struct Xctr<C> {
    cipher: C,
}

impl<C> Xctr<C> {
    pub(crate) fn new(cipher: C) -> Self {
        Self { cipher }
    }
}

impl<C: BlockCipher> Xctr<&C> {
    /// Encrypt `src` into `dst`.
    pub(crate) fn encrypt(&self, dst: &mut [u8], src: &[u8], nonce: &Block<C>) {
        let mut idx = 1u64;

        // let (dst, dst_tail) =
        //     GenericArray::<u8, <C as BlockCipher>::Stride>::chunks_from_slice_mut(dst);
        // let (src, src_tail) = GenericArray::<u8, <C as BlockCipher>::Stride>::chunks_from_slice(src);

        let bs = <C as BlockSize>::BlockSize::USIZE;
        //let _stride = <C as Stride>::Stride::USIZE;

        // let mut dst = dst.chunks_exact_mut(bs * stride);
        // let mut src = src.chunks_exact(bs * stride);
        // let mut vctr = GenericArray::<Block<C>, _>::default();
        // for (dst, src) in dst.by_ref().zip(src.by_ref()) {
        //     for (i, ctr) in vctr.iter_mut().enumerate() {
        //         xor_in_place(&mut ctr, &nonce);
        //         ctr[..8].copy_from_slice(&(idx + i as u64).to_le_bytes());
        //     }
        //     cipher.encrypt_blocks(dst, src);
        // }

        let mut dst = dst.chunks_exact_mut(bs);
        let mut src = src.chunks_exact(bs);
        for (dst, src) in dst.by_ref().zip(src.by_ref()) {
            let mut ctr = Block::<C>::default();
            ctr[..8].copy_from_slice(&idx.to_le_bytes());
            xor_in_place(&mut ctr, &nonce);
            self.cipher.encrypt_block_in_place((&mut ctr).into());
            xor3_in_place(dst, src, &ctr);
            idx += 1;
        }

        let tail = dst.into_remainder();
        if !tail.is_empty() {
            let mut ctr = Block::<C>::default();
            ctr[..8].copy_from_slice(&idx.to_le_bytes());
            xor_in_place(&mut ctr, &nonce);
            self.cipher.encrypt_block_in_place((&mut ctr).into());
            xor3_in_place(tail, src.remainder(), &ctr);
        }
    }

    /// Encrypt `data` in place.
    pub(crate) fn encrypt_in_place(&self, data: &mut [u8], nonce: &Block<C>) {
        let mut idx = 1u64;

        let bs = <C as BlockSize>::BlockSize::USIZE;
        let mut data = data.chunks_exact_mut(bs);
        for block in &mut data {
            let mut ctr = Block::<C>::default();
            xor_in_place(&mut ctr, &nonce);
            ctr[..8].copy_from_slice(&idx.to_le_bytes());
            self.cipher.encrypt_block_in_place((&mut ctr).into());
            xor_in_place(block, &ctr);
            idx += 1;
        }

        let tail = data.into_remainder();
        if !tail.is_empty() {
            let mut ctr = Block::<C>::default();
            xor_in_place(&mut ctr, &nonce);
            ctr[..8].copy_from_slice(&idx.to_le_bytes());
            self.cipher.encrypt_block_in_place(&mut ctr);
            xor_in_place(tail, &ctr);
        }
    }
}

/// Sets z ^= x.
#[inline(always)]
fn xor_in_place(z: &mut [u8], x: &[u8]) {
    for (z, x) in zip(z.iter_mut(), x) {
        *z ^= x;
    }
}

/// Sets z ^= x.
#[inline(always)]
fn xor3_in_place(z: &mut [u8], x: &[u8], y: &[u8]) {
    for (z, (x, y)) in zip(z.iter_mut(), zip(x, y)) {
        *z ^= x ^ y;
    }
}
