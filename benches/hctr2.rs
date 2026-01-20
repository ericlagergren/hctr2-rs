use aes::{Aes128, Aes256};
use byteorder::{ByteOrder, LittleEndian};
use cipher::{generic_array::GenericArray, KeyInit};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use hctr2::{Cipher, BLOCK_SIZE};

fn bench_hctr2<C>(c: &mut Criterion, name: &str)
where
    C: cipher::BlockCipher<BlockSize = cipher::consts::U16>
        + cipher::BlockEncrypt
        + cipher::BlockDecrypt
        + KeyInit,
{
    let mut group = c.benchmark_group(name);

    for size in [512, 4096, 8192] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let mut tweak = [0u8; BLOCK_SIZE];
            let key = vec![0u8; C::key_size()];
            let mut cipher = Cipher::<C>::new(GenericArray::from_slice(&key));
            let mut buf = vec![0u8; size];

            b.iter(|| {
                let i = LittleEndian::read_u64(&tweak);
                LittleEndian::write_u64(&mut tweak, i + 1);
                cipher.encrypt_in_place(black_box(&mut buf), &tweak);
            });
        });
    }

    group.finish();
}

fn bench_aes256(c: &mut Criterion) {
    bench_hctr2::<Aes256>(c, "hctr2-aes256");
}

fn bench_aes128(c: &mut Criterion) {
    bench_hctr2::<Aes128>(c, "hctr2-aes128");
}

criterion_group!(benches, bench_aes256, bench_aes128);
criterion_main!(benches);
