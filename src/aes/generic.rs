use core::{array, slice};

use aes::{
    hazmat::{cipher_round, equiv_inv_cipher_round, inv_mix_columns, mix_columns},
    Block,
};
use typenum::{U16, U8};

use crate::block::{BlockBackend, BlockSize, ByRef, Stride};

const BLOCK_SIZE: usize = 16;

const fn check_sizes<const K: usize, const N: usize>() {
    const { assert!((K == 16 && N == 11) || (K == 24 && N == 13) || (K == 32 && N == 15)) }
}

fn cast_block(block: &crate::block::Block<U16>) -> &Block {
    let tmp: &[u8; BLOCK_SIZE] = block.as_ref();
    tmp.into()
}

fn cast_block_mut(block: &mut crate::block::Block<U16>) -> &mut Block {
    let tmp: &mut [u8; BLOCK_SIZE] = block.as_mut();
    tmp.into()
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
    pub fn new(key: &[u8; K]) -> Self {
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
    keys: [Block; N],
}

impl<const K: usize, const N: usize> AesEnc<K, N> {
    fn new(key: &[u8; K]) -> Self {
        const { check_sizes::<K, N>() }

        let keys = expand_key(key);
        Self { keys }
    }

    fn encrypt_block(&self, dst: &mut Block, src: &Block) {
        const { check_sizes::<K, N>() }

        let mut block = *src;
        add_round_key(&mut block, &self.keys[0]);
        for rk in &self.keys[1..self.keys.len() - 1] {
            cipher_round(&mut block, rk);
        }
        cipher_round(&mut block, &Block::default());
        inv_mix_columns(&mut block);
        add_round_key(&mut block, &self.keys[self.keys.len() - 1]);
        *dst = block;
    }

    fn encrypt_block_in_place(&self, block: &mut Block) {
        const { check_sizes::<K, N>() }

        add_round_key(block, &self.keys[0]);
        for rk in &self.keys[1..self.keys.len() - 1] {
            cipher_round(block, rk);
        }
        cipher_round(block, &Block::default());
        // `cipher_round` applies `MixColumns`, so undo that
        // step.
        inv_mix_columns(block);
        add_round_key(block, &self.keys[self.keys.len() - 1]);
    }

    fn xctr(&self, dst: &mut [u8], src: &[u8], nonce: &Block) {
        const { check_sizes::<K, N>() }

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
    fn proc_block(&self, dst: &mut crate::block::Block<Self>, src: &crate::block::Block<Self>) {
        const { check_sizes::<K, N>() }

        self.encrypt_block(cast_block_mut(dst), cast_block(src))
    }

    fn proc_block_in_place(&self, block: &mut crate::block::Block<Self>) {
        const { check_sizes::<K, N>() }

        self.encrypt_block_in_place(cast_block_mut(block))
    }
}

#[cfg(feature = "zeroize")]
impl<const K: usize, const N: usize> zeroize::ZeroizeOnDrop for AesEnc<K, N> {}

impl<const K: usize, const N: usize> Drop for AesEnc<K, N> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            for k in &mut self.keys {
                zeroize::Zeroize::zeroize(k.as_mut_slice());
            }
        }

        #[cfg(not(feature = "zeroize"))]
        {
            for k in &mut self.keys {
                *k = Block::default();
            }
        }
    }
}

/// - `K`: key size in bytes.
/// - `N`: number of round keys.
#[derive(Clone)]
#[repr(transparent)]
pub(super) struct AesDec<const K: usize, const N: usize> {
    keys: [Block; N],
}

impl<const K: usize, const N: usize> AesDec<K, N> {
    fn from_enc(enc: &AesEnc<K, N>) -> Self {
        const { check_sizes::<K, N>() }

        let keys = invert_enc_keys(&enc.keys);
        Self { keys }
    }

    fn decrypt_block(&self, dst: &mut Block, src: &Block) {
        const { check_sizes::<K, N>() }

        let mut block = *src;
        add_round_key(&mut block, &self.keys[0]);
        for rk in &self.keys[1..self.keys.len() - 1] {
            equiv_inv_cipher_round(&mut block, rk);
        }
        equiv_inv_cipher_round(&mut block, &Block::default());
        // `equiv_inv_cipher_round` applies `InvMixColumns`, so
        // undo that step.
        mix_columns(&mut block);
        add_round_key(&mut block, &self.keys[self.keys.len() - 1]);
        *dst = block;
    }

    fn decrypt_block_in_place(&self, block: &mut Block) {
        const { check_sizes::<K, N>() }

        add_round_key(block, &self.keys[0]);
        for rk in &self.keys[1..self.keys.len() - 1] {
            equiv_inv_cipher_round(block, rk);
        }
        equiv_inv_cipher_round(block, &Block::default());
        // `equiv_inv_cipher_round` applies `InvMixColumns`, so
        // undo that step.
        mix_columns(block);
        add_round_key(block, &self.keys[self.keys.len() - 1]);
    }
}

impl<const K: usize, const N: usize> Stride for AesDec<K, N> {
    type Stride = U8;
}

impl<const K: usize, const N: usize> BlockSize for AesDec<K, N> {
    type BlockSize = U16;
}

impl<const K: usize, const N: usize> BlockBackend for AesDec<K, N> {
    fn proc_block(&self, dst: &mut crate::block::Block<Self>, src: &crate::block::Block<Self>) {
        const { check_sizes::<K, N>() }

        self.decrypt_block(cast_block_mut(dst), cast_block(src))
    }

    fn proc_block_in_place(&self, block: &mut crate::block::Block<Self>) {
        const { check_sizes::<K, N>() }

        self.decrypt_block_in_place(cast_block_mut(block))
    }
}

#[cfg(feature = "zeroize")]
impl<const K: usize, const N: usize> zeroize::ZeroizeOnDrop for AesDec<K, N> {}

impl<const K: usize, const N: usize> Drop for AesDec<K, N> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            for k in &mut self.keys {
                zeroize::Zeroize::zeroize(k.as_mut_slice());
            }
        }

        #[cfg(not(feature = "zeroize"))]
        {
            for k in &mut self.keys {
                *k = Block::default();
            }
        }
    }
}

const ROUND_CONSTS: [u32; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/// AES key expansion.
///
/// - `K`: The length of the key in bytes.
/// - `N`: The length of the expanded key in 128-bit words.
fn expand_key<const K: usize, const N: usize>(key: &[u8; K]) -> [Block; N] {
    const { check_sizes::<K, N>() }

    #[derive(Default)]
    #[repr(align(16))]
    struct Block(#[allow(dead_code)] crate::block::Block<U16>);

    let mut keys: [Block; N] = array::from_fn(|_| Block::default());

    const {
        assert!(align_of::<Block>() >= align_of::<u32>());
        assert!(size_of::<Block>() == size_of::<u32>() * 4);
    }
    // SAFETY:
    // - The slice is a different view into `keys`, so it is
    //   valid for reads.
    // - `Block` is 4 times as large as `u32`, so the length
    //    of the slice is correct.
    // - `Block` has the same or greater alignment as `u32`.
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

    // SAFETY: `Block` has the same size as `::Block`.
    unsafe { core::mem::transmute_copy(&keys) }
}

/// Invert AES round keys for decryption.
fn invert_enc_keys<const N: usize>(keys: &[Block; N]) -> [Block; N] {
    const { assert!(N == 11 || N == 13 || N == 15) }

    array::from_fn(|i| {
        if i == 0 {
            keys[N - 1]
        } else if i < N - 1 {
            let mut block = keys[N - 1 - i];
            inv_mix_columns(&mut block);
            block
        } else {
            keys[0]
        }
    })
}

/// Applies the sbox to each byte in `w0`.
fn sub_word(w0: u32) -> u32 {
    // w -> [w, w, w, w]
    let mut w = {
        let mut w = Block::default();
        w[0..4].copy_from_slice(&w0.to_le_bytes());
        w[4..8].copy_from_slice(&w0.to_le_bytes());
        w[8..12].copy_from_slice(&w0.to_le_bytes());
        w[12..16].copy_from_slice(&w0.to_le_bytes());
        w
    };
    // enc = SubBytes(ShiftRows(w ^ 0))
    cipher_round(&mut w, &Block::default());
    // `cipher_round` applies `MixColumns`, so undo that step.
    inv_mix_columns(&mut w);
    // result = enc[0]
    u32::from_le_bytes(w[0..4].try_into().unwrap())
}

fn xctr_asm<const N: usize>(rk: &[Block; N], dst: &mut [u8], src: &[u8], nonce: &Block) {
    const { assert!(N == 11 || N == 13 || N == 15) }

    for (idx, (dst, src)) in dst
        .chunks_exact_mut(BLOCK_SIZE)
        .zip(src.chunks_exact(BLOCK_SIZE))
        .enumerate()
    {
        let mut ctr: Block = ((idx + 1) as u128).to_le_bytes().into();
        xor_in_place(&mut ctr, nonce);
        let (head, tail) = rk.split_at(rk.len() - 2);
        for rk in head {
            cipher_round(&mut ctr, rk);
            mix_columns(&mut ctr);
        }
        cipher_round(&mut ctr, &tail[0]);
        // ctr ^= tail[1]
        // *dst = ctr ^ src
        for (((z, c), k), s) in dst.iter_mut().zip(&ctr).zip(&tail[1]).zip(src) {
            *z = c ^ k ^ s;
        }
    }
}

fn add_round_key(block: &mut Block, rk: &Block) {
    for (b, k) in block.iter_mut().zip(rk) {
        *b ^= k;
    }
}

fn xor_in_place(x: &mut Block, y: &Block) {
    for (x, y) in x.iter_mut().zip(y) {
        *x ^= y;
    }
}

fn xor3_in_place(z: &mut Block, x: &Block, y: &Block) {
    for ((z, x), y) in z.iter_mut().zip(x).zip(y) {
        *z = x ^ y;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type AesEnc128 = AesEnc<16, 11>;
    // type AesEnc192 = AesEnc<24, 13>; // TODO
    // type AesEnc256 = AesEnc<32, 15>; // TODO

    type AesDec128 = AesDec<16, 11>;
    // type AesDec192 = AesDec<24, 13>; // TODO
    // type AesDec256 = AesDec<32, 15>; // TODO

    impl<const K: usize, const N: usize> AesEnc<K, N> {
        fn round_keys(&self) -> Vec<u32> {
            self.keys
                .iter()
                .flat_map(|k| {
                    [
                        u32::from_le_bytes(k[0..4].try_into().unwrap()).to_be(),
                        u32::from_le_bytes(k[4..8].try_into().unwrap()).to_be(),
                        u32::from_le_bytes(k[8..12].try_into().unwrap()).to_be(),
                        u32::from_le_bytes(k[12..16].try_into().unwrap()).to_be(),
                    ]
                })
                .collect()
        }
    }

    impl<const K: usize, const N: usize> AesDec<K, N> {
        fn round_keys(&self) -> Vec<u32> {
            self.keys
                .iter()
                .flat_map(|k| {
                    [
                        u32::from_le_bytes(k[0..4].try_into().unwrap()).to_be(),
                        u32::from_le_bytes(k[4..8].try_into().unwrap()).to_be(),
                        u32::from_le_bytes(k[8..12].try_into().unwrap()).to_be(),
                        u32::from_le_bytes(k[12..16].try_into().unwrap()).to_be(),
                    ]
                })
                .collect()
        }
    }

    #[test]
    fn test_expand_key_aes128() {
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

        let enc = AesEnc128::new(&KEY);
        let got = enc.round_keys();
        assert_eq!(got, ENC_WANT);

        let dec = AesDec128::from_enc(&enc);
        let got = dec.round_keys();
        assert_eq!(got, DEC_WANT);
    }

    #[test]
    fn test_crypt_aes128() {
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

        let enc = AesEnc128::new(&KEY);
        let mut got = Block::default();
        enc.encrypt_block(&mut got, &PT.into());
        assert_eq!(got.as_slice(), &CT, "`encrypt_block`");

        let dec = AesDec128::from_enc(&enc);
        dec.decrypt_block(&mut got, &CT.into());
        assert_eq!(got.as_slice(), &PT, "`decrypt_block`");

        let mut got = PT.into();
        enc.encrypt_block_in_place(&mut got);
        assert_eq!(got.as_slice(), &CT, "`encrypt_block_in_place`");

        dec.decrypt_block_in_place(&mut got);
        assert_eq!(got.as_slice(), &PT, "`decrypt_block_in_place`");
    }
}
