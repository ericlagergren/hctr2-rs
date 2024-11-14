use core::{hint::black_box, time::Duration};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use hctr2::{
    aes::{Aes128, Aes256},
    BlockCipher, Hctr2,
};
use pprof::criterion::{Output, PProfProfiler};

fn bench_seal<C, F>(c: &mut Criterion, name: &'static str, f: &F)
where
    C: BlockCipher,
    F: Fn() -> C,
{
    let mut g = c.benchmark_group(name);
    for size in [512, 4096, 8182].iter() {
        let mut i = 0;
        let mut dst = vec![0u8; *size];
        let src = vec![0u8; *size];
        let block = f();
        let mut cipher = Hctr2::new(block);

        g.throughput(Throughput::Bytes(*size as u64));
        let name = BenchmarkId::new("seal", *size);
        g.bench_function(name, move |b| {
            b.iter(|| {
                let tweak = (i as u128).to_le_bytes();
                cipher
                    .seal(black_box(&mut dst), black_box(&src), black_box(&tweak))
                    .unwrap();
                i += 1;
            })
        });
    }
    g.finish();
}

fn bench_seal_in_place<C, F>(c: &mut Criterion, name: &'static str, f: &F)
where
    C: BlockCipher,
    F: Fn() -> C,
{
    let mut g = c.benchmark_group(name);
    for size in [512, 4096, 8182].iter() {
        let mut i = 0;
        let mut buf = vec![0u8; *size];
        let block = f();
        let mut cipher = Hctr2::new(block);

        g.throughput(Throughput::Bytes(*size as u64));
        let name = BenchmarkId::new("seal_in_place", *size);
        g.bench_function(name, move |b| {
            b.iter(|| {
                let tweak = (i as u128).to_le_bytes();
                cipher
                    .seal_in_place(black_box(&mut buf), black_box(&tweak))
                    .unwrap();
                i += 1;
            })
        });
    }
    g.finish();
}

fn bench_alg<C, F>(c: &mut Criterion, name: &'static str, f: F)
where
    C: BlockCipher,
    F: Fn() -> C,
{
    bench_seal(c, name, &f);
    bench_seal_in_place(c, name, &f);
}

fn bench_throughput(c: &mut Criterion) {
    bench_alg(c, "AES-128", || Aes128::new(&[0; 16]));
    bench_alg(c, "AES-256", || Aes256::new(&[0; 32]));
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .with_profiler(PProfProfiler::new(100, Output::Protobuf));
    targets = bench_throughput,
}
criterion_main!(benches);
