use core::slice;

use typenum::Unsigned;

use super::block::{Block, BlockSize};

// See https://doc.rust-lang.org/std/primitive.slice.html#method.as_chunks
pub(crate) fn as_blocks<S: BlockSize>(blocks: &[u8]) -> (&[Block<S>], &[u8]) {
    let bs = <S as BlockSize>::BlockSize::USIZE;
    let len_rounded_down = (blocks.len() / bs) * bs;
    // SAFETY: The rounded-down value is always the same or
    // smaller than the original length, and thus must be
    // in-bounds of the slice.
    let (head, tail) = unsafe { blocks.split_at_unchecked(len_rounded_down) };
    let new_len = head.len() / bs;
    // SAFETY: We cast a slice of `new_len * N` elements into
    // a slice of `new_len` many `N` elements chunks.
    let head = unsafe { slice::from_raw_parts(head.as_ptr().cast(), new_len) };
    (head, tail)
}

// See https://doc.rust-lang.org/std/primitive.slice.html#method.as_chunks
pub(crate) fn as_blocks_mut<S: BlockSize>(blocks: &mut [u8]) -> (&mut [Block<S>], &mut [u8]) {
    let bs = <S as BlockSize>::BlockSize::USIZE;
    let len_rounded_down = (blocks.len() / bs) * bs;
    // SAFETY: The rounded-down value is always the same or
    // smaller than the original length, and thus must be
    // in-bounds of the slice.
    let (head, tail) = unsafe { blocks.split_at_mut_unchecked(len_rounded_down) };
    let new_len = head.len() / bs;
    // SAFETY: We cast a slice of `new_len * N` elements into
    // a slice of `new_len` many `N` elements chunks.
    let head = unsafe { slice::from_raw_parts_mut(head.as_mut_ptr().cast(), new_len) };
    (head, tail)
}

/// Sets z ^= x.
#[inline(always)]
pub(crate) fn xor_in_place(z: &mut [u8], x: &[u8]) {
    for (z, x) in z.iter_mut().zip(x) {
        *z ^= x;
    }
}

/// Sets z = x^y.
#[inline(always)]
pub(crate) fn xor_into(z: &mut [u8], x: &[u8], y: &[u8]) {
    for ((z, x), y) in z.iter_mut().zip(x).zip(y) {
        *z = x ^ y;
    }
}

/// Returns x^y.
#[inline(always)]
pub(crate) fn xor2<S: BlockSize>(x: &[u8], y: &Block<S>) -> Block<S> {
    let mut z = Block::<S>::default();
    for ((z, x), y) in z.iter_mut().zip(x).zip(y) {
        *z = x ^ y;
    }
    z
}

/// Returns v^x^y.
#[inline(always)]
pub(crate) fn xor3<S: BlockSize>(v: &Block<S>, x: &Block<S>, y: &Block<S>) -> Block<S> {
    let mut z = Block::<S>::default();
    for (((z, v), x), y) in z.iter_mut().zip(v).zip(x).zip(y) {
        *z = v ^ x ^ y;
    }
    z
}

/// Sets z = x^y.
#[inline(always)]
pub(crate) fn xor_block_into<S: BlockSize>(z: &mut [u8], x: &[u8], y: &Block<S>) {
    for ((z, x), y) in z.iter_mut().zip(x).zip(y) {
        *z = x ^ y;
    }
}
