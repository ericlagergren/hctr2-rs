//! **HCTR2** implements the HCTR2 length-preserving encryption
//! algorithm.
//!
//! HCTR2 is designed for situations where the length of the
//! ciphertext must exactly match the length of the plaintext,
//! like disk encryption.
//!
//! This implementation uses a hardware-accelerated POLYVAL
//! implementation when possible; the block cipher is left to the
//! caller. The recommended block cipher is AES.
//!
//! [hctr2]: https://eprint.iacr.org/2021/1441

#![no_std]
#![deny(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![feature(array_chunks)]
#![feature(let_chains)]
#![feature(slice_as_chunks)]
#![feature(split_array)]
#![warn(missing_docs, rust_2018_idioms)]
// Because I want to use "let S = ..." to match the paper.
#![allow(non_snake_case)]

use byteorder::{ByteOrder, LittleEndian};
use cipher::{
    consts::U16, BlockCipher, BlockDecrypt, BlockEncrypt, Key, KeyInit,
    KeySizeUser,
};
use core::iter::zip;
use polyval::{universal_hash::UniversalHash, Polyval};

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

/// BLOCK_SIZE is the size of the block allowed by this package.
pub const BLOCK_SIZE: usize = 16;

/// Cipher is an instance of the HCTR2 cipher.
#[derive(Clone)]
pub struct Cipher<C>
where
    C: BlockCipher<BlockSize = U16>,
{
    // Underlying block cipher.
    block: C,
    // Ek(bin(0)
    h: cipher::Block<C>,
    // Ek(bin(1))
    L: cipher::Block<C>,
    // The length of the provided tweak.
    //
    // Cached by `init_tweak`.
    tweak_len: Option<usize>,
    // The state of POLYVAL for M % n == 0.
    state0: Polyval,
    // The state of POLYVAL for M % n != 0.
    state1: Polyval,
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<C> Drop for Cipher<C>
where
    C: BlockCipher<BlockSize = U16>,
{
    fn drop(&mut self) {
        // Other fields have very spotty support for zeroize.
        self.h.zeroize();
        self.L.zeroize();
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<C> ZeroizeOnDrop for Cipher<C> where C: BlockCipher<BlockSize = U16> {}

impl<C> KeySizeUser for Cipher<C>
where
    C: BlockCipher<BlockSize = U16> + KeyInit,
{
    type KeySize = C::KeySize;
}

impl<C> KeyInit for Cipher<C>
where
    C: BlockCipher<BlockSize = U16> + BlockEncrypt + KeyInit,
{
    /// new creates an HCTR2 cipher.
    ///
    /// The provided block cipher must have a block size of
    /// exactly BLOCK_SIZE bytes.
    fn new(key: &Key<C>) -> Self {
        let block = C::new(key);

        // h ← Ek(bin(0))
        let mut h = cipher::Block::<C>::default();
        block.encrypt_block(&mut h);

        // L ← Ek(bin(1))
        let mut L = cipher::Block::<C>::default();
        LittleEndian::write_u64(&mut L, 1);
        block.encrypt_block(&mut L);

        Cipher {
            block,
            h,
            L,
            tweak_len: None,
            state0: Polyval::new(&h),
            state1: Polyval::new(&h),
        }
    }
}

impl<C> Cipher<C>
where
    C: BlockCipher<BlockSize = U16> + BlockEncrypt + BlockDecrypt,
{
    /// Encrypts plaintext into ciphertext using tweak.
    ///
    /// It panics if either plaintext or ciphertext are less than
    /// `BLOCK_SIZE` bytes.
    pub fn encrypt(
        &mut self,
        ciphertext: &mut [u8],
        plaintext: &[u8],
        tweak: &[u8],
    ) {
        self.hctr2(&mut ciphertext[..plaintext.len()], plaintext, tweak, true)
    }

    /// Decrypts ciphertext into plaintext using tweak.
    ///
    /// It panics if either ciphertext or plaintext are less than
    /// `BLOCK_SIZE` bytes.
    pub fn decrypt(
        &mut self,
        plaintext: &mut [u8],
        ciphertext: &[u8],
        tweak: &[u8],
    ) {
        self.hctr2(&mut plaintext[..ciphertext.len()], ciphertext, tweak, false)
    }

    fn hctr2(&mut self, dst: &mut [u8], src: &[u8], tweak: &[u8], seal: bool) {
        assert!(dst.len() >= BLOCK_SIZE);
        assert!(src.len() >= BLOCK_SIZE);
        assert!(dst.len() == src.len());

        // M || N ← P, |M| = n
        let (M, N) = src.split_array_ref::<BLOCK_SIZE>();

        self.init_tweak(tweak);

        let mut poly = match N.len() % BLOCK_SIZE {
            0 => self.state0.clone(),
            _ => self.state1.clone(),
        };
        poly.update_padded(tweak);

        // Save the state so we can reuse it later.
        let mut state = poly.clone();

        // MM ← M ⊕ H_h(T, N)
        polyhash(&mut poly, N);
        let MM = xor2(M, &poly.finalize_reset().into());

        // UU ← Ek(MM)
        let mut UU = cipher::Block::<C>::default();
        if seal {
            self.block.encrypt_block_b2b(&MM.into(), &mut UU);
        } else {
            self.block.decrypt_block_b2b(&MM.into(), &mut UU);
        }

        // S ← MM ⊕ UU ⊕ L
        let S = xor3(&MM, &UU.into(), &self.L.into());

        let (U, V) = dst.split_array_mut::<BLOCK_SIZE>();

        // V ← N ⊕ XCTR_k(S)[0;|N|]
        self.xctr(V, N, &S);

        // U ← UU ⊕ Hh(T, V)
        polyhash(&mut state, V);
        xor_block_into(U, &UU.into(), &state.finalize_reset().into());
    }

    fn xctr(&self, dst: &mut [u8], src: &[u8], nonce: &[u8; BLOCK_SIZE]) {
        assert!(dst.len() == src.len());

        let mut ctr = [0u8; BLOCK_SIZE];
        let mut i = 1u64;

        let (dstHead, dstTail) = dst.as_chunks_mut::<BLOCK_SIZE>();
        let (srcHead, srcTail) = src.as_chunks::<BLOCK_SIZE>();

        for (dst, src) in zip(dstHead, srcHead) {
            // TODO(eric): this assumes len(ctr) == 16.
            LittleEndian::write_u64(&mut ctr[..8], i);
            LittleEndian::write_u64(&mut ctr[8..], 0);

            xor_block_in_place(&mut ctr, nonce);
            self.block.encrypt_block((&mut ctr).into());
            xor_block_into(dst, src, &ctr);
            i += 1;
        }

        if !dstTail.is_empty() {
            LittleEndian::write_u64(&mut ctr[..8], i);
            LittleEndian::write_u64(&mut ctr[8..], 0);

            xor_block_in_place(&mut ctr, nonce);
            self.block.encrypt_block((&mut ctr).into());
            xor_into(dstTail, srcTail, &ctr);
        }
    }

    /// Encrypts plaintext in-place using tweak.
    ///
    /// It panics if plaintext is less than `BLOCK_SIZE` bytes.
    pub fn encrypt_in_place(&mut self, plaintext: &mut [u8], tweak: &[u8]) {
        self.hctr2_in_place(plaintext, tweak, true)
    }

    /// Decrypts ciphertext in-place using tweak.
    ///
    /// It panics if ciphertext is less than `BLOCK_SIZE` bytes.
    pub fn decrypt_in_place(&mut self, ciphertext: &mut [u8], tweak: &[u8]) {
        self.hctr2_in_place(ciphertext, tweak, false)
    }

    fn hctr2_in_place(&mut self, data: &mut [u8], tweak: &[u8], seal: bool) {
        assert!(data.len() >= BLOCK_SIZE);

        // M || N ← P, |M| = n
        let (M, N) = data.split_array_mut::<BLOCK_SIZE>();

        self.init_tweak(tweak);

        let mut poly = match N.len() % BLOCK_SIZE {
            0 => self.state0.clone(),
            _ => self.state1.clone(),
        };
        poly.update_padded(tweak);

        // Save the state so we can reuse it later.
        let mut state = poly.clone();

        // MM ← M ⊕ H_h(T, N)
        polyhash(&mut poly, N);
        let MM = xor2(M, &poly.finalize_reset().into());

        // UU ← Ek(MM)
        let mut UU = cipher::Block::<C>::default();
        if seal {
            self.block.encrypt_block_b2b(&MM.into(), &mut UU);
        } else {
            self.block.decrypt_block_b2b(&MM.into(), &mut UU);
        }

        // S ← MM ⊕ UU ⊕ L
        let S = xor3(&MM, &UU.into(), &self.L.into());

        // V ← N ⊕ XCTR_k(S)[0;|N|]
        self.xctr_in_place(N, &S);

        // U ← UU ⊕ Hh(T, V)
        polyhash(&mut state, N);
        xor_block_into(M, &UU.into(), &state.finalize_reset().into());
    }

    fn xctr_in_place(&self, data: &mut [u8], nonce: &[u8; BLOCK_SIZE]) {
        let mut ctr = [0u8; BLOCK_SIZE];
        let mut i = 1u64;

        let (head, tail) = data.as_chunks_mut::<BLOCK_SIZE>();
        for chunk in head {
            // TODO(eric): this assumes len(ctr) == 16.
            LittleEndian::write_u64(&mut ctr[..8], i);
            LittleEndian::write_u64(&mut ctr[8..], 0);

            xor_block_in_place(&mut ctr, nonce);
            self.block.encrypt_block((&mut ctr).into());
            xor_block_in_place(chunk, &ctr);
            i += 1;
        }

        if !tail.is_empty() {
            LittleEndian::write_u64(&mut ctr[..8], i);
            LittleEndian::write_u64(&mut ctr[8..], 0);

            xor_block_in_place(&mut ctr, nonce);
            self.block.encrypt_block((&mut ctr).into());
            xor_in_place(tail, &ctr);
        }
    }

    fn init_tweak(&mut self, tweak: &[u8]) {
        // The first block in the hash of the tweak is the same
        // so long as the length of the tweak is the same, so
        // cache it.
        if let Some(n) = self.tweak_len && n == tweak.len() {
            return;
        }

        // M = the input to the hash.
        // n = the block size of the hash.
        //
        // If n divides |M|:
        //    POLYVAL(h, bin(2*|T| + 2) || pad(T) || M)
        // else:
        //    POLYVAL(h, bin(2*|T| + 3) || pad(T) || pad(M || 1))
        let l = (tweak.len() as u64) * 8 * 2 + 2;
        let mut block = polyval::Block::default();

        let poly = Polyval::new(&self.h);

        LittleEndian::write_u64(&mut block, l);
        self.state1.clone_from(&poly);
        self.state0.update(&[block]);

        LittleEndian::write_u64(&mut block, l + 1);
        self.state1.clone_from(&poly);
        self.state1.update(&[block]);

        self.tweak_len = Some(tweak.len());
    }
}

fn polyhash(p: &mut Polyval, src: &[u8]) {
    let (head, tail) =
        src.split_at((src.len() / polyval::BLOCK_SIZE) * polyval::BLOCK_SIZE);
    if !head.is_empty() {
        p.update_padded(head);
    }
    if !tail.is_empty() {
        let mut block = polyval::Block::default();
        block[..tail.len()].copy_from_slice(tail);
        block[tail.len()] = 1;
        p.update(&[block]);
    }
}

/// Sets z = x^y up to z.len() bytes.
fn xor_into<const N: usize>(z: &mut [u8], x: &[u8], y: &[u8; N]) {
    assert!(z.len() <= N);
    assert!(x.len() >= z.len());

    for i in 0..z.len() {
        z[i] = x[i] ^ y[i];
    }
}

/// Sets z ^= x up to z.len() bytes.
#[inline(always)]
fn xor_in_place<const N: usize>(z: &mut [u8], x: &[u8; N]) {
    for i in 0..z.len() {
        z[i] ^= x[i];
    }
}

/// Sets z = x^y.
#[inline(always)]
fn xor_block_into<const N: usize>(z: &mut [u8; N], x: &[u8; N], y: &[u8; N]) {
    for i in 0..N {
        z[i] = x[i] ^ y[i];
    }
}

/// Sets z ^= x.
#[inline(always)]
fn xor_block_in_place<const N: usize>(z: &mut [u8; N], x: &[u8; N]) {
    for i in 0..N {
        z[i] ^= x[i]
    }
}

/// Returns x^y.
#[inline(always)]
fn xor2<const N: usize>(x: &[u8; N], y: &[u8; N]) -> [u8; N] {
    let mut z = [0u8; N];
    xor_block_into(&mut z, x, y);
    z
}

/// Returns v^x^y.
#[inline(always)]
fn xor3<const N: usize>(v: &[u8; N], x: &[u8; N], y: &[u8; N]) -> [u8; N] {
    let mut z = [0u8; N];
    for i in 0..N {
        z[i] = v[i] ^ x[i] ^ y[i];
    }
    z
}
