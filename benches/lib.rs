use core::{hint::black_box, time::Duration};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use hctr2::{Error, Hctr2Aes128, Hctr2Aes256};
use pprof::criterion::{Output, PProfProfiler};

#[allow(dead_code, reason = "TODO")]
trait Sprp {
    fn seal(&mut self, dst: &mut [u8], src: &[u8], tweak: &[u8]) -> Result<(), Error>;
    fn open(&mut self, dst: &mut [u8], src: &[u8], tweak: &[u8]) -> Result<(), Error>;
    fn seal_in_place(&mut self, data: &mut [u8], tweak: &[u8]) -> Result<(), Error>;
    fn open_in_place(&mut self, data: &mut [u8], tweak: &[u8]) -> Result<(), Error>;
}
macro_rules! impl_sprp {
    ($name:ident) => {
        impl Sprp for $name {
            fn seal(&mut self, dst: &mut [u8], src: &[u8], tweak: &[u8]) -> Result<(), Error> {
                self.seal(dst, src, tweak)
            }
            fn open(&mut self, dst: &mut [u8], src: &[u8], tweak: &[u8]) -> Result<(), Error> {
                self.open(dst, src, tweak)
            }
            fn seal_in_place(&mut self, data: &mut [u8], tweak: &[u8]) -> Result<(), Error> {
                self.seal_in_place(data, tweak)
            }
            fn open_in_place(&mut self, data: &mut [u8], tweak: &[u8]) -> Result<(), Error> {
                self.open_in_place(data, tweak)
            }
        }
    };
}
impl_sprp!(Hctr2Aes128);
impl_sprp!(Hctr2Aes256);

fn bench_seal<C, F>(c: &mut Criterion, name: &'static str, f: &F)
where
    C: Sprp,
    F: Fn() -> C,
{
    let mut g = c.benchmark_group(name);
    for size in [512, 4096, 8182].iter() {
        let mut i = 0;
        let mut dst = vec![0u8; *size];
        let src = vec![0u8; *size];
        let mut cipher = f();

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
    C: Sprp,
    F: Fn() -> C,
{
    let mut g = c.benchmark_group(name);
    for size in [512, 4096, 8182].iter() {
        let mut i = 0;
        let mut buf = vec![0u8; *size];
        let mut cipher = f();

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
    C: Sprp,
    F: Fn() -> C,
{
    bench_seal(c, name, &f);
    bench_seal_in_place(c, name, &f);
}

fn bench_throughput(c: &mut Criterion) {
    bench_alg(c, "AES-128", || Hctr2Aes128::new(&[0; 16]));
    bench_alg(c, "AES-256", || Hctr2Aes256::new(&[0; 32]));
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .with_profiler(PProfProfiler::new(100, Output::Protobuf));
    targets = bench_throughput,
}
criterion_main!(benches);
