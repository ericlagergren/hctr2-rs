use core::iter::zip;

use generic_array::GenericArray;
use typenum::Unsigned;

use crate::{
    block::{Block, BlockCipher},
    cipher::xor_block_into,
};

#[no_mangle]
pub fn foo(cipher: &crate::aes::Aes256, dst: &mut [u8], src: &[u8], nonce: &Block<C>) {
    xctr(cipher, dst, src, nonce)
}

pub(crate) fn xctr<C: BlockCipher>(cipher: &C, dst: &mut [u8], src: &[u8], nonce: &Block<C>) {
    let mut idx = 1u64;

    // let (dst, dst_tail) =
    //     GenericArray::<u8, <C as BlockCipher>::Stride>::chunks_from_slice_mut(dst);
    // let (src, src_tail) = GenericArray::<u8, <C as BlockCipher>::Stride>::chunks_from_slice(src);

    let bs = <C as BlockCipher>::BlockSize::USIZE;
    let _stride = <C as BlockCipher>::Stride::USIZE;

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
        xor_in_place(&mut ctr, &nonce);
        ctr[..8].copy_from_slice(&idx.to_le_bytes());
        cipher.encrypt_block_in_place((&mut ctr).into());
        xor3_in_place(dst, src, &ctr);
        idx += 1;
    }

    let tail = dst.into_remainder();
    if !tail.is_empty() {
        let mut ctr = Block::<C>::default();
        xor_in_place(&mut ctr, &nonce);
        ctr[..8].copy_from_slice(&idx.to_le_bytes());
        cipher.encrypt_block_in_place((&mut ctr).into());
        xor3_in_place(tail, src.remainder(), &ctr);
    }
}

pub(crate) fn xctr_in_place<C: BlockCipher>(cipher: &C, data: &mut [u8], nonce: &Block<C>) {
    let mut idx = 1u64;

    let bs = <C as BlockCipher>::BlockSize::USIZE;
    let mut data = data.chunks_exact_mut(bs);
    for block in &mut data {
        let mut ctr = Block::<C>::default();
        xor_in_place(&mut ctr, &nonce);
        ctr[..8].copy_from_slice(&idx.to_le_bytes());
        cipher.encrypt_block_in_place((&mut ctr).into());
        xor_in_place(block, &ctr);
        idx += 1;
    }

    let tail = data.into_remainder();
    if !tail.is_empty() {
        let mut ctr = Block::<C>::default();
        xor_in_place(&mut ctr, &nonce);
        ctr[..8].copy_from_slice(&idx.to_le_bytes());
        cipher.encrypt_block_in_place((&mut ctr).into());
        xor_in_place(tail, &ctr);
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
