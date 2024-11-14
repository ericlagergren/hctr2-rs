//! AArch64 implementation.

#![cfg(all(
    not(feature = "soft"),
    target_arch = "aarch64",
    target_feature = "neon",
))]

use core::{
    arch::aarch64::{
        uint8x16_t, uint8x16x4_t, vaesdq_u8, vaeseq_u8, vaesimcq_u8, vaesmcq_u8, vdupq_n_u32,
        vdupq_n_u64, vdupq_n_u8, veorq_u8, vgetq_lane_u32, vld1q_u8, vld1q_u8_x4,
        vreinterpretq_u32_u8, vreinterpretq_u8_u32, vreinterpretq_u8_u64, vsetq_lane_u64, vst1q_u8,
        vst1q_u8_x4,
    },
    array, slice,
};

use typenum::{U16, U8};

use crate::block::{Block, BlockBackend, BlockSize, Blocks, ByRef, Stride};

const BLOCK_SIZE: usize = 16;

const fn check_sizes<const K: usize, const N: usize>() {
    const { assert!((K == 16 && N == 11) || (K == 24 && N == 13) || (K == 32 && N == 15)) }
}

// NB: `aes` implies `neon`.
cpufeatures::new!(have_aes, "aes");

pub fn supported() -> bool {
    have_aes::get()
}

pub(super) type Aes128 = Aes<16, 11>;
pub(super) type Aes192 = Aes<24, 13>;
pub(super) type Aes256 = Aes<32, 15>;

/// - `K`: key size in bytes.
/// - `N`: number of round keys.
#[derive(Clone)]
pub(super) struct Aes<const K: usize, const N: usize> {
    enc: AesEnc<K, N>,
    dec: AesDec<K, N>,
}

impl<const K: usize, const N: usize> Aes<K, N> {
    /// # Safety
    ///
    /// The NEON and AES architectural features must be
    /// enabled.
    #[inline]
    #[target_feature(enable = "neon,aes")]
    pub unsafe fn new(key: &[u8; K]) -> Self {
        const { check_sizes::<K, N>() }

        let enc = AesEnc::<K, N>::new(key);
        let dec = AesDec::<K, N>::from_enc(&enc);
        Self { enc, dec }
    }

    pub fn get_enc_backend(&self) -> ByRef<'_, AesEnc<K, N>> {
        const { check_sizes::<K, N>() }

        ByRef(&self.enc)
    }

    pub fn get_dec_backend(&self) -> ByRef<'_, AesDec<K, N>> {
        const { check_sizes::<K, N>() }

        ByRef(&self.dec)
    }
}

/// - `K`: key size in bytes.
/// - `N`: number of round keys.
#[derive(Clone)]
#[repr(transparent)]
pub(super) struct AesEnc<const K: usize, const N: usize> {
    keys: [uint8x16_t; N],
}

impl<const K: usize, const N: usize> AesEnc<K, N> {
    /// # Safety
    ///
    /// The NEON and AES architectural features must be
    /// enabled.
    #[inline]
    #[target_feature(enable = "neon,aes")]
    unsafe fn new(key: &[u8; K]) -> Self {
        const { check_sizes::<K, N>() }
        debug_assert!(supported());

        // SAFETY: `expand_key` requires the `aes` and
        // `neon` target features, which we have.
        let keys = unsafe { expand_key(key) };
        Self { keys }
    }

    /// # Safety
    ///
    /// The NEON and AES architectural features must be
    /// enabled.
    #[inline]
    #[target_feature(enable = "neon,aes")]
    unsafe fn encrypt_block(&self, dst: &mut Block<Self>, src: &Block<Self>) {
        const { check_sizes::<K, N>() }
        debug_assert!(supported());

        let mut block = vld1q_u8(src.as_ptr());
        let (head, tail) = self.keys.split_at(self.keys.len() - 2);
        for &rk in head {
            block = vaeseq_u8(block, rk);
            block = vaesmcq_u8(block);
        }
        block = vaeseq_u8(block, tail[0]);
        block = veorq_u8(block, tail[1]);
        vst1q_u8(dst.as_mut_ptr(), block)
    }

    /// # Safety
    ///
    /// The NEON and AES architectural features must be
    /// enabled.
    #[inline]
    #[target_feature(enable = "neon,aes")]
    unsafe fn encrypt_blocks(&self, dst: &mut [Block<Self>], src: &[Block<Self>]) {
        const { check_sizes::<K, N>() }
        debug_assert!(supported());

        const STRIDE: usize = 8;
        let mut dst = dst.chunks_exact_mut(BLOCK_SIZE * STRIDE);
        let mut src = src.chunks_exact(BLOCK_SIZE * STRIDE);
        for (dst, src) in dst.by_ref().zip(src.by_ref()) {
            let (hi, lo) = src.split_at(src.len() / 2);
            let uint8x16x4_t(p0, p1, p2, p3) = vld1q_u8_x4(lo.as_ptr().cast());
            let uint8x16x4_t(p4, p5, p6, p7) = vld1q_u8_x4(hi.as_ptr().cast());

            let mut blocks = [p0, p1, p2, p3, p4, p5, p6, p7];

            let (head, tail) = self.keys.split_at(self.keys.len() - 2);
            for &rk in head {
                for block in &mut blocks {
                    *block = vaeseq_u8(*block, rk);
                    *block = vaesmcq_u8(*block);
                }
            }
            for block in &mut blocks {
                *block = vaeseq_u8(*block, tail[0]);
                *block = veorq_u8(*block, tail[1]);
            }

            let (lo, hi) = dst.split_at_mut(dst.len() / 2);
            vst1q_u8_x4(
                lo.as_mut_ptr().cast(),
                uint8x16x4_t(blocks[0], blocks[1], blocks[2], blocks[3]),
            );
            vst1q_u8_x4(
                hi.as_mut_ptr().cast(),
                uint8x16x4_t(blocks[4], blocks[5], blocks[6], blocks[7]),
            );
        }

        let dst = dst.into_remainder();
        let src = src.remainder();
        for (dst, src) in dst.iter_mut().zip(src) {
            let mut block = vld1q_u8(src.as_ptr());
            let (head, tail) = self.keys.split_at(self.keys.len() - 2);
            for &rk in head {
                block = vaeseq_u8(block, rk);
                block = vaesmcq_u8(block);
            }
            block = vaeseq_u8(block, tail[0]);
            block = veorq_u8(block, tail[1]);
            vst1q_u8(dst.as_mut_ptr(), block);
        }
    }

    /// # Safety
    ///
    /// The NEON and AES architectural features must be
    /// enabled.
    #[inline]
    #[target_feature(enable = "neon,aes")]
    unsafe fn encrypt_blocks_in_place(&self, blocks: &mut [Block<Self>]) {
        const { check_sizes::<K, N>() }
        debug_assert!(supported());

        const STRIDE: usize = 8;
        let mut chunks = blocks.chunks_exact_mut(STRIDE);
        for chunk in chunks.by_ref() {
            let (hi, lo) = chunk.split_at(chunk.len() / 2);
            let uint8x16x4_t(p0, p1, p2, p3) = vld1q_u8_x4(lo.as_ptr().cast());
            let uint8x16x4_t(p4, p5, p6, p7) = vld1q_u8_x4(hi.as_ptr().cast());

            let mut blocks = [p0, p1, p2, p3, p4, p5, p6, p7];

            let (head, tail) = self.keys.split_at(self.keys.len() - 2);
            for &rk in head {
                for block in &mut blocks {
                    *block = vaeseq_u8(*block, rk);
                    *block = vaesmcq_u8(*block);
                }
            }
            for block in &mut blocks {
                *block = vaeseq_u8(*block, tail[0]);
                *block = veorq_u8(*block, tail[1]);
            }

            let (lo, hi) = chunk.split_at_mut(chunk.len() / 2);
            vst1q_u8_x4(
                lo.as_mut_ptr().cast(),
                uint8x16x4_t(blocks[0], blocks[1], blocks[2], blocks[3]),
            );
            vst1q_u8_x4(
                hi.as_mut_ptr().cast(),
                uint8x16x4_t(blocks[4], blocks[5], blocks[6], blocks[7]),
            );
        }

        let chunks = chunks.into_remainder();
        for chunk in chunks {
            let mut block = vld1q_u8(chunk.as_ptr());
            let (head, tail) = self.keys.split_at(self.keys.len() - 2);
            for &rk in head {
                block = vaeseq_u8(block, rk);
                block = vaesmcq_u8(block);
            }
            block = vaeseq_u8(block, tail[0]);
            block = veorq_u8(block, tail[1]);
            vst1q_u8(chunk.as_mut_ptr(), block);
        }
    }

    /// # Safety
    ///
    /// The NEON and AES architectural features must be
    /// enabled.
    #[inline]
    #[target_feature(enable = "neon,aes")]
    unsafe fn encrypt_block_in_place(&self, data: &mut Block<Self>) {
        const { check_sizes::<K, N>() }
        debug_assert!(supported());

        let mut block = vld1q_u8(data.as_ptr());
        let (head, tail) = self.keys.split_at(self.keys.len() - 2);
        for &rk in head {
            block = vaeseq_u8(block, rk);
            block = vaesmcq_u8(block);
        }
        block = vaeseq_u8(block, tail[0]);
        block = veorq_u8(block, tail[1]);
        vst1q_u8(data.as_mut_ptr(), block)
    }

    /// # Safety
    ///
    /// The NEON and AES architectural features must be
    /// enabled.
    #[inline]
    #[target_feature(enable = "neon,aes")]
    unsafe fn xctr(&self, dst: &mut [u8], src: &[u8], nonce: &Block<Self>) {
        const { check_sizes::<K, N>() }
        debug_assert!(supported());

        xctr_asm(&self.keys, dst, src, nonce)
    }
}

impl<const K: usize, const N: usize> Stride for AesEnc<K, N> {
    type Stride = U8;
}

impl<const K: usize, const N: usize> BlockSize for AesEnc<K, N> {
    type BlockSize = U16;
}

impl<const K: usize, const N: usize> BlockBackend for AesEnc<K, N> {
    fn proc_block(&self, dst: &mut Block<Self>, src: &Block<Self>) {
        const { check_sizes::<K, N>() }
        assert!(supported());

        // SAFETY: We've asserted that we have AES support.
        unsafe { self.encrypt_block(dst, src) }
    }

    fn proc_block_in_place(&self, block: &mut Block<Self>) {
        const { check_sizes::<K, N>() }
        assert!(supported());

        // SAFETY: We've asserted that we have AES support.
        unsafe { self.encrypt_block_in_place(block) }
    }

    fn proc_blocks(&self, dst: &mut Blocks<Self>, src: &Blocks<Self>) {
        const { check_sizes::<K, N>() }
        assert!(supported());

        // SAFETY: We've asserted that we have AES support.
        unsafe { self.encrypt_blocks(dst, src) }
    }

    fn proc_blocks_in_place(&self, blocks: &mut Blocks<Self>) {
        const { check_sizes::<K, N>() }
        assert!(supported());

        // SAFETY: We've asserted that we have AES support.
        unsafe { self.encrypt_blocks_in_place(blocks) }
    }
}

#[cfg(feature = "zeroize")]
impl<const K: usize, const N: usize> zeroize::ZeroizeOnDrop for AesEnc<K, N> {}

impl<const K: usize, const N: usize> Drop for AesEnc<K, N> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            zeroize::Zeroize::zeroize(&mut self.keys.iter_mut());
        }

        #[cfg(not(feature = "zeroize"))]
        {
            for k in &mut self.keys {
                *k = unsafe { veorq_u8(*k, *k) };
            }
        }
    }
}

/// - `K`: key size in bytes.
/// - `N`: number of round keys.
#[derive(Clone)]
#[repr(transparent)]
pub(super) struct AesDec<const K: usize, const N: usize> {
    keys: [uint8x16_t; N],
}

impl<const K: usize, const N: usize> AesDec<K, N> {
    /// # Safety
    ///
    /// The NEON and AES architectural features must be
    /// enabled.
    #[inline]
    #[target_feature(enable = "neon,aes")]
    unsafe fn new(key: &[u8; K]) -> Self {
        const { check_sizes::<K, N>() }
        debug_assert!(supported());

        let enc = AesEnc::new(key);
        Self::from_enc(&enc)
    }

    /// # Safety
    ///
    /// The NEON and AES architectural features must be
    /// enabled.
    #[inline]
    #[target_feature(enable = "neon,aes")]
    unsafe fn from_enc(enc: &AesEnc<K, N>) -> Self {
        const { check_sizes::<K, N>() }
        debug_assert!(supported());

        // SAFETY: `invert_enc_keys` requires the `aes`
        // and `neon` target features, which we have.
        let keys = unsafe { invert_enc_keys(&enc.keys) };
        Self { keys }
    }

    /// # Safety
    ///
    /// The NEON and AES architectural features must be
    /// enabled.
    #[inline]
    #[target_feature(enable = "neon,aes")]
    unsafe fn decrypt_block(&self, dst: &mut Block<Self>, src: &Block<Self>) {
        const { check_sizes::<K, N>() }
        debug_assert!(supported());

        let mut block = vld1q_u8(src.as_ptr());
        let (head, tail) = self.keys.split_at(self.keys.len() - 2);
        for &rk in head {
            block = vaesdq_u8(block, rk);
            block = vaesimcq_u8(block);
        }
        block = vaesdq_u8(block, tail[0]);
        block = veorq_u8(block, tail[1]);
        vst1q_u8(dst.as_mut_ptr(), block)
    }

    /// # Safety
    ///
    /// The NEON and AES architectural features must be
    /// enabled.
    #[inline]
    #[target_feature(enable = "neon,aes")]
    unsafe fn decrypt_block_in_place(&self, data: &mut Block<Self>) {
        const { check_sizes::<K, N>() }
        debug_assert!(supported());

        let mut block = vld1q_u8(data.as_ptr());
        let (head, tail) = self.keys.split_at(self.keys.len() - 2);
        for &rk in head {
            block = vaesdq_u8(block, rk);
            block = vaesimcq_u8(block);
        }
        block = vaesdq_u8(block, tail[0]);
        block = veorq_u8(block, tail[1]);
        vst1q_u8(data.as_mut_ptr(), block)
    }
}

impl<const K: usize, const N: usize> Stride for AesDec<K, N> {
    type Stride = U8;
}

impl<const K: usize, const N: usize> BlockSize for AesDec<K, N> {
    type BlockSize = U16;
}

impl<const K: usize, const N: usize> BlockBackend for AesDec<K, N> {
    fn proc_block(&self, dst: &mut Block<Self>, src: &Block<Self>) {
        const { check_sizes::<K, N>() }
        assert!(supported());

        // SAFETY: We've asserted that we have AES support.
        unsafe { self.decrypt_block(dst, src) }
    }

    fn proc_block_in_place(&self, block: &mut Block<Self>) {
        const { check_sizes::<K, N>() }
        assert!(supported());

        // SAFETY: We've asserted that we have AES support.
        unsafe { self.decrypt_block_in_place(block) }
    }

    // TODO
    // fn proc_blocks(&self, dst: &mut Blocks<Self>, src: &Blocks<Self>) {
    //     assert!(supported());

    //     // SAFETY: We've asserted that we have AES support.
    //     unsafe { self.decrypt_blocks(dst, src) }
    // }

    // fn proc_blocks_in_place(&self, blocks: &mut Blocks<Self>) {
    //     assert!(supported());

    //     // SAFETY: We've asserted that we have AES support.
    //     unsafe { self.decrypt_blocks_in_place(blocks) }
    // }
}

#[cfg(feature = "zeroize")]
impl<const K: usize, const N: usize> zeroize::ZeroizeOnDrop for AesDec<K, N> {}

impl<const K: usize, const N: usize> Drop for AesDec<K, N> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            zeroize::Zeroize::zeroize(&mut self.keys.iter_mut());
        }

        #[cfg(not(feature = "zeroize"))]
        {
            for k in &mut self.keys {
                *k = unsafe { veorq_u8(*k, *k) };
            }
        }
    }
}

const ROUND_CONSTS: [u32; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/// AES key expansion.
///
/// - `K`: The length of the key in bytes.
/// - `N`: The length of the expanded key in 128-bit words.
///
/// # Safety
///
/// The NEON and AES architectural features must be enabled.
#[inline]
#[target_feature(enable = "neon,aes")]
unsafe fn expand_key<const K: usize, const N: usize>(key: &[u8; K]) -> [uint8x16_t; N] {
    const { check_sizes::<K, N>() }
    debug_assert!(supported());

    let mut keys = array::from_fn(|_| vdupq_n_u8(0));

    const {
        assert!(align_of::<uint8x16_t>() >= align_of::<u32>());
        assert!(size_of::<uint8x16_t>() == size_of::<u32>() * 4);
    }
    // SAFETY:
    // - The slice is a different view into `keys`, so it is
    //   valid for reads.
    // - `uint8x16_t` is 4 times as large as `u32`, so the length
    //    of the slice is correct.
    // - `uint8x16_t` has the same or greater alignment as `u32`.
    let w = unsafe { slice::from_raw_parts_mut(keys.as_mut_ptr().cast(), keys.len() * 4) };
    for (i, chunk) in key.chunks_exact(4).enumerate() {
        w[i] = u32::from_ne_bytes(chunk.try_into().unwrap());
    }
    let nk = key.len() / 4;
    let mut i = nk;
    while i < w.len() {
        let mut temp = w[i - 1];
        if i % nk == 0 {
            temp = sub_word(temp.rotate_right(8)) ^ ROUND_CONSTS[i / nk - 1];
        } else if nk > 6 && i % nk == 4 {
            temp = sub_word(temp);
        }
        w[i] = w[i - nk] ^ temp;
        i += 1;
    }

    keys
}

/// Invert AES round keys for decryption.
///
/// # Safety
///
/// The NEON and AES architectural features must be enabled.
#[inline]
#[target_feature(enable = "neon,aes")]
unsafe fn invert_enc_keys<const N: usize>(keys: &[uint8x16_t; N]) -> [uint8x16_t; N] {
    const { assert!(N == 11 || N == 13 || N == 15) }
    debug_assert!(supported());

    array::from_fn(|i| {
        if i == 0 {
            keys[N - 1]
        } else if i < N - 1 {
            vaesimcq_u8(keys[N - 1 - i])
        } else {
            keys[0]
        }
    })
}

/// Applies the sbox to each byte in `w0`.
///
/// # Safety
///
/// The NEON and AES architectural features must be enabled.
#[inline]
#[target_feature(enable = "neon,aes")]
unsafe fn sub_word(w0: u32) -> u32 {
    // w -> [w, w, w, w]
    let w = vreinterpretq_u8_u32(vdupq_n_u32(w0));
    // enc = SubBytes(ShiftRows(w ^ 0))
    let enc = vaeseq_u8(w, vdupq_n_u8(0));
    // result = enc[0]
    vgetq_lane_u32(vreinterpretq_u32_u8(enc), 0)
}

/// # Safety
///
/// The NEON and AES architectural features must be enabled.
#[inline]
#[target_feature(enable = "neon,aes")]
unsafe fn xctr_asm<const N: usize>(
    rk: &[uint8x16_t; N],
    dst: &mut [u8],
    src: &[u8],
    nonce: &Block<U16>,
) {
    const { assert!(N == 11 || N == 13 || N == 15) }

    debug_assert!(supported());
    debug_assert_eq!(dst.len(), src.len());

    let mut idx = 1u64;
    let nonce = vld1q_u8(nonce.as_ptr());

    // Handle 8 blocks at a time.
    const STRIDE: usize = 8;
    let mut dst = dst.chunks_exact_mut(BLOCK_SIZE * STRIDE);
    let mut src = src.chunks_exact(BLOCK_SIZE * STRIDE);
    let mut vctr: [uint8x16_t; STRIDE] = array::from_fn(|_| vdupq_n_u8(0));
    for (dst, src) in dst.by_ref().zip(src.by_ref()) {
        let (hi, lo) = src.split_at(src.len() / 2);
        let uint8x16x4_t(p0, p1, p2, p3) = vld1q_u8_x4(lo.as_ptr());
        let uint8x16x4_t(p4, p5, p6, p7) = vld1q_u8_x4(hi.as_ptr());
        let p = [p0, p1, p2, p3, p4, p5, p6, p7];

        for (i, ctr) in vctr.iter_mut().enumerate() {
            let tmp = vsetq_lane_u64(idx + i as u64, vdupq_n_u64(0), 0);
            *ctr = veorq_u8(vreinterpretq_u8_u64(tmp), nonce);
        }

        let (head, tail) = rk.split_at(rk.len() - 2);
        for &rk in head {
            for ctr in &mut vctr {
                *ctr = vaeseq_u8(*ctr, rk);
                *ctr = vaesmcq_u8(*ctr);
            }
        }
        for (ctr, src) in vctr.iter_mut().zip(p) {
            *ctr = vaeseq_u8(*ctr, tail[0]);
            *ctr = veorq_u8(*ctr, tail[1]);
            *ctr = veorq_u8(*ctr, src);
        }

        let (lo, hi) = dst.split_at_mut(dst.len() / 2);
        vst1q_u8_x4(
            lo.as_mut_ptr().cast(),
            uint8x16x4_t(vctr[0], vctr[1], vctr[2], vctr[3]),
        );
        vst1q_u8_x4(
            hi.as_mut_ptr().cast(),
            uint8x16x4_t(vctr[4], vctr[5], vctr[6], vctr[7]),
        );

        idx += 8;
    }

    // Handle single blocks.
    let dst = dst.into_remainder().chunks_exact_mut(BLOCK_SIZE);
    let src = src.remainder().chunks_exact(BLOCK_SIZE);
    for (dst, src) in dst.zip(src) {
        let mut ctr = {
            let tmp = vsetq_lane_u64(idx as u64, vdupq_n_u64(0), 0);
            veorq_u8(vreinterpretq_u8_u64(tmp), nonce)
        };
        let (head, tail) = rk.split_at(rk.len() - 2);
        for &rk in head {
            ctr = vaeseq_u8(ctr, rk);
            ctr = vaesmcq_u8(ctr);
        }
        ctr = vaeseq_u8(ctr, tail[0]);
        ctr = veorq_u8(ctr, tail[1]);

        let src = vld1q_u8(src.as_ptr());
        vst1q_u8(dst.as_mut_ptr(), veorq_u8(ctr, src));

        idx += 1;
    }
}

/// # Safety
///
/// The NEON and AES architectural features must be enabled.
#[inline]
#[target_feature(enable = "neon,aes")]
unsafe fn xctr_asm2<const N: usize>(
    rk: &[uint8x16_t; N],
    dst: &mut [u8],
    src: &[u8],
    nonce: &Block<U16>,
) {
    const { assert!(N == 11 || N == 13 || N == 15) }

    debug_assert!(supported());
    debug_assert_eq!(dst.len(), src.len());

    let mut idx = 1u64;
    let nonce = vld1q_u8(nonce.as_ptr());

    // Handle 8 blocks at a time.
    const STRIDE: usize = 8;
    let mut dst = dst.chunks_exact_mut(BLOCK_SIZE * STRIDE);
    let mut src = src.chunks_exact(BLOCK_SIZE * STRIDE);
    let mut vctr: [uint8x16_t; STRIDE] = array::from_fn(|_| vdupq_n_u8(0));
    for (dst, src) in dst.by_ref().zip(src.by_ref()) {
        let (hi, lo) = src.split_at(src.len() / 2);
        let uint8x16x4_t(p0, p1, p2, p3) = vld1q_u8_x4(lo.as_ptr());
        let uint8x16x4_t(p4, p5, p6, p7) = vld1q_u8_x4(hi.as_ptr());
        let p = [p0, p1, p2, p3, p4, p5, p6, p7];

        for (i, ctr) in vctr.iter_mut().enumerate() {
            let tmp = vsetq_lane_u64(idx + i as u64, vdupq_n_u64(0), 0);
            *ctr = veorq_u8(vreinterpretq_u8_u64(tmp), nonce);
        }

        for (ctr, src) in vctr.iter_mut().zip(p) {
            let (head, tail) = rk.split_at(rk.len() - 2);
            for &rk in head {
                *ctr = vaeseq_u8(*ctr, rk);
                *ctr = vaesmcq_u8(*ctr);
            }
            *ctr = vaeseq_u8(*ctr, tail[0]);
            *ctr = veorq_u8(*ctr, tail[1]);
            *ctr = veorq_u8(*ctr, src);
        }

        vst1q_u8_x4(
            dst.as_mut_ptr(),
            uint8x16x4_t(vctr[0], vctr[1], vctr[2], vctr[3]),
        );
        vst1q_u8_x4(
            dst.as_mut_ptr(),
            uint8x16x4_t(vctr[4], vctr[5], vctr[6], vctr[7]),
        );

        idx += 8;
    }

    // Handle single blocks.
    let dst = dst.into_remainder().chunks_exact_mut(BLOCK_SIZE);
    let src = src.remainder().chunks_exact(BLOCK_SIZE);
    for (dst, src) in dst.zip(src) {
        let mut ctr = {
            let tmp = vsetq_lane_u64(idx as u64, vdupq_n_u64(0), 0);
            veorq_u8(vreinterpretq_u8_u64(tmp), nonce)
        };
        let (head, tail) = rk.split_at(rk.len() - 2);
        for &rk in head {
            ctr = vaeseq_u8(ctr, rk);
            ctr = vaesmcq_u8(ctr);
        }
        ctr = vaeseq_u8(ctr, tail[0]);
        ctr = veorq_u8(ctr, tail[1]);

        let src = vld1q_u8(src.as_ptr());
        vst1q_u8(dst.as_mut_ptr(), veorq_u8(ctr, src));

        idx += 1;
    }
}

/// # Safety
///
/// The NEON and AES architectural features must be enabled.
#[inline]
#[target_feature(enable = "neon,aes")]
unsafe fn xctr_asm0<const N: usize>(
    rk: &[uint8x16_t; N],
    dst: &mut [u8],
    src: &[u8],
    nonce: &Block<U16>,
) {
    const { assert!(N == 11 || N == 13 || N == 15) }

    debug_assert!(supported());

    let nonce = vld1q_u8(nonce.as_ptr());

    for (idx, (dst, src)) in dst
        .chunks_exact_mut(BLOCK_SIZE)
        .zip(src.chunks_exact(BLOCK_SIZE))
        .enumerate()
    {
        let p = vld1q_u8(src.as_ptr());
        let tmp = vsetq_lane_u64((idx + 1) as u64, vdupq_n_u64(0), 0);
        let mut ctr = veorq_u8(vreinterpretq_u8_u64(tmp), nonce);
        let (head, tail) = rk.split_at(rk.len() - 2);
        for &rk in head {
            ctr = vaeseq_u8(ctr, rk);
            ctr = vaesmcq_u8(ctr);
        }
        ctr = vaeseq_u8(ctr, tail[0]);
        ctr = veorq_u8(ctr, tail[1]);
        let c = veorq_u8(ctr, p);
        vst1q_u8(dst.as_mut_ptr(), c);
    }
}

#[cfg(test)]
mod tests {
    use core::arch::aarch64::{vreinterpretq_u32_u8, vst1q_u32};

    use super::*;

    type AesEnc128 = AesEnc<16, 11>;
    type AesEnc192 = AesEnc<24, 13>;
    type AesEnc256 = AesEnc<32, 15>;

    type AesDec128 = AesDec<16, 11>;
    type AesDec192 = AesDec<24, 13>;
    type AesDec256 = AesDec<32, 15>;

    impl<const K: usize, const N: usize> AesEnc<K, N> {
        fn round_keys(&self) -> Vec<u32> {
            self.keys
                .iter()
                .flat_map(|k| {
                    let k = unsafe { vreinterpretq_u32_u8(*k) };
                    let mut w = [0; 4];
                    unsafe {
                        vst1q_u32(w.as_mut_ptr(), k);
                    }
                    w.map(u32::to_be)
                })
                .collect()
        }
    }

    impl<const K: usize, const N: usize> AesDec<K, N> {
        fn round_keys(&self) -> Vec<u32> {
            self.keys
                .iter()
                .flat_map(|k| {
                    let k = unsafe { vreinterpretq_u32_u8(*k) };
                    let mut w = [0; 4];
                    unsafe {
                        vst1q_u32(w.as_mut_ptr(), k);
                    }
                    w.map(u32::to_be)
                })
                .collect()
        }
    }

    #[test]
    fn test_expand_key_aes128() {
        if !supported() {
            return;
        }

        const KEY: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        const ENC_WANT: &[u32] = &[
            0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c, 0xa0fafe17, 0x88542cb1, 0x23a33939,
            0x2a6c7605, 0xf2c295f2, 0x7a96b943, 0x5935807a, 0x7359f67f, 0x3d80477d, 0x4716fe3e,
            0x1e237e44, 0x6d7a883b, 0xef44a541, 0xa8525b7f, 0xb671253b, 0xdb0bad00, 0xd4d1c6f8,
            0x7c839d87, 0xcaf2b8bc, 0x11f915bc, 0x6d88a37a, 0x110b3efd, 0xdbf98641, 0xca0093fd,
            0x4e54f70e, 0x5f5fc9f3, 0x84a64fb2, 0x4ea6dc4f, 0xead27321, 0xb58dbad2, 0x312bf560,
            0x7f8d292f, 0xac7766f3, 0x19fadc21, 0x28d12941, 0x575c006e, 0xd014f9a8, 0xc9ee2589,
            0xe13f0cc8, 0xb6630ca6,
        ];
        const DEC_WANT: &[u32] = &[
            0xd014f9a8, 0xc9ee2589, 0xe13f0cc8, 0xb6630ca6, 0xc7b5a63, 0x1319eafe, 0xb0398890,
            0x664cfbb4, 0xdf7d925a, 0x1f62b09d, 0xa320626e, 0xd6757324, 0x12c07647, 0xc01f22c7,
            0xbc42d2f3, 0x7555114a, 0x6efcd876, 0xd2df5480, 0x7c5df034, 0xc917c3b9, 0x6ea30afc,
            0xbc238cf6, 0xae82a4b4, 0xb54a338d, 0x90884413, 0xd280860a, 0x12a12842, 0x1bc89739,
            0x7c1f13f7, 0x4208c219, 0xc021ae48, 0x969bf7b, 0xcc7505eb, 0x3e17d1ee, 0x82296c51,
            0xc9481133, 0x2b3708a7, 0xf262d405, 0xbc3ebdbf, 0x4b617d62, 0x2b7e1516, 0x28aed2a6,
            0xabf71588, 0x9cf4f3c,
        ];

        let enc = unsafe { AesEnc128::new(&KEY) };
        let got = enc.round_keys();
        assert_eq!(got, ENC_WANT);

        let dec = unsafe { AesDec128::from_enc(&enc) };
        let got = dec.round_keys();
        assert_eq!(got, DEC_WANT);
    }

    #[test]
    fn test_crypt_aes128() {
        if !supported() {
            return;
        }

        const KEY: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        const PT: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        const CT: [u8; 16] = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
            0xc5, 0x5a,
        ];

        let enc = unsafe { AesEnc128::new(&KEY) };
        let mut got = Block::<U16>::default();
        unsafe { enc.encrypt_block(&mut got, &PT.into()) }
        assert_eq!(got.as_slice(), &CT, "`encrypt_block`");

        let dec = unsafe { AesDec128::from_enc(&enc) };
        unsafe { dec.decrypt_block(&mut got, &CT.into()) }
        assert_eq!(got.as_slice(), &PT, "`decrypt_block`");

        let mut got = PT.into();
        unsafe { enc.encrypt_block_in_place(&mut got) }
        assert_eq!(got.as_slice(), &CT, "`encrypt_block_in_place`");

        unsafe { dec.decrypt_block_in_place(&mut got) }
        assert_eq!(got.as_slice(), &PT, "`decrypt_block_in_place`");
    }
}
