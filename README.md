# hctr2

[![Docs][docs-img]][docs-link]

Length-preserving encryption algorithm https://eprint.iacr.org/2021/1441.pdf

## Installation

```bash
[dependencies]
hctr2 = "0.1"
```

## Performance

The performance of HCTR2 is primarily determined by the XCTR and
POLYVAL implementations. This module provides ARMv8 and x86-64 
assembly XCTR implementations and uses a hardware-accelerated
POLYVAL implementation (see [polyval](https://docs.rs/polyval)).

### Results

#### M1

```
test bench_hctr2_aes128_4096 ... bench:       9,201 ns/iter (+/- 134) = 445 MB/s
test bench_hctr2_aes128_512  ... bench:       1,144 ns/iter (+/- 37) = 447 MB/s
test bench_hctr2_aes128_8192 ... bench:      18,386 ns/iter (+/- 233) = 445 MB/s
test bench_hctr2_aes256_4096 ... bench:       9,545 ns/iter (+/- 172) = 429 MB/s
test bench_hctr2_aes256_512  ... bench:       1,177 ns/iter (+/- 21) = 435 MB/s
test bench_hctr2_aes256_8192 ... bench:      18,922 ns/iter (+/- 242) = 432 MB/s
```

For reference, here are the numbers for the reference
C [implementation](https://github.com/google/hctr2).

| CPU     | ISA   | Frequency | Cycles per byte | API  |
| ---     | ---   | ---       | ---             | ---  |
| RK3399  | ARMv8 | 1.8 GHz   | 1.8             | simd |
| Skylake | x86   | 3.9 GHz   | 1.2             | simd |

## Security

### Disclosure

This project uses full disclosure. If you find a security bug in
an implementation, please e-mail me or create a GitHub issue.

### Disclaimer

You should only use cryptography libraries that have been
reviewed by cryptographers or cryptography engineers. While I am
a cryptography engineer, I'm not your cryptography engineer, and
I have not had this project reviewed by any other cryptographers.

[//]: # (badges)

[docs-img]: https://docs.rs/hctr2/badge.svg
[docs-link]: https://docs.rs/hctr2
