#![feature(test)]

extern crate test;

use aes::{Aes128, Aes256};
use byteorder::{ByteOrder, LittleEndian};
use cipher::{generic_array::GenericArray, KeyInit, KeySizeUser};
use core::hint;
use hctr2::{Cipher, BLOCK_SIZE};
use test::Bencher;

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
                let i = LittleEndian::read_u64(&tweak);
                LittleEndian::write_u64(&mut tweak, i + 1);
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
