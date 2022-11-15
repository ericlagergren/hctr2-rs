#![feature(test)]

extern crate test;

use aes::{Aes128, Aes256};
use cipher::{generic_array::GenericArray, KeyInit, KeySizeUser};
use core::hint;
use hctr2::{Cipher, BLOCK_SIZE};
use test::Bencher;

#[inline(always)]
fn put_le_bytes(b: &mut [u8], v: u64) {
    b[7] = (v >> 56) as u8;
    b[6] = (v >> 48) as u8;
    b[5] = (v >> 40) as u8;
    b[4] = (v >> 32) as u8;
    b[3] = (v >> 24) as u8;
    b[2] = (v >> 16) as u8;
    b[1] = (v >> 8) as u8;
    b[0] = v as u8;
}

#[inline(always)]
fn get_le_bytes(b: &[u8]) -> u64 {
    return (b[7] as u64) << 56
        | (b[6] as u64) << 48
        | (b[5] as u64) << 40
        | (b[4] as u64) << 32
        | (b[3] as u64) << 24
        | (b[2] as u64) << 16
        | (b[1] as u64) << 8
        | (b[0] as u64);
}

macro_rules! bench {
    ($name:ident, $C:ident, $buflen:expr) => {
        #[bench]
        fn $name(b: &mut Bencher) {
            let mut tweak = [0u8; BLOCK_SIZE];
            let key = vec![0u8; $C::key_size()];
            let mut c = Cipher::<$C>::new(GenericArray::from_slice(&key[..]));
            let mut buf = vec![0u8; $buflen];
            b.bytes = $buflen;
            b.iter(|| {
                let i = get_le_bytes(&tweak);
                put_le_bytes(&mut tweak, i + 1);
                c.encrypt_in_place(&mut buf, &tweak);
            });
            hint::black_box(&mut buf);
        }
    };
}
bench!(bench_hctr2_aes256_512, Aes256, 512);
bench!(bench_hctr2_aes256_4096, Aes256, 4096);
bench!(bench_hctr2_aes256_8192, Aes256, 8192);

// AES-192 isn't benchmarked because nobody cares about its
// performance because nobody uses it and it shouldn't exist.

bench!(bench_hctr2_aes128_512, Aes128, 512);
bench!(bench_hctr2_aes128_4096, Aes128, 4096);
bench!(bench_hctr2_aes128_8192, Aes128, 8192);
