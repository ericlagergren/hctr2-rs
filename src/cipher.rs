use core::{error, fmt, iter::zip};

use polyhash::{self as polyval, Polyval};
use typenum::U16;

use super::block::{Block, BlockCipher, BLOCK_SIZE};

/// An error returned by this API.
#[derive(Copy, Clone, Debug)]
pub enum Error {
    /// The length of an input was invalid.
    ///
    /// For instance, `dst` might be shorter than `src`.
    InvalidLength,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => write!(f, "invalid input length"),
        }
    }
}

impl error::Error for Error {}

/// An instance of HCTR2.
///
/// # Examples
///
/// ```rust
/// use hctr2::{aes::Aes256, Hctr2};
///
/// let cipher = Aes256::new(&[
///     0x74, 0xf9, 0x8f, 0x60, 0x78, 0x6a, 0xbf, 0xa8,
///     0x5b, 0x0b, 0xbb, 0xa0, 0x59, 0xe0, 0xf9, 0x1e,
/// ]);
/// let hctr2 = Hctr2::new(cipher);
/// let mut data = [
///     0x6b, 0x26, 0x83, 0x7b, 0xdc, 0x1c, 0x58, 0x3d,
///     0xc1, 0x42, 0xc6, 0xab, 0x7b, 0x3f, 0x43, 0xb0,
/// ];
/// hctr2.seal_in_place(&mut data, &[]);
/// let want = [
///     0xdd, 0x05, 0xa8, 0xae, 0x51, 0xf1, 0xe8, 0x21,
///     0x2f, 0xd6, 0xc3, 0x3b, 0x94, 0x67, 0x03, 0x6d,
/// ];
/// assert_eq!(data, want);
/// ```
#[derive(Clone)]
pub struct Hctr2<C> {
    // Underlying block cipher.
    cipher: C,
    // Ek(bin(0)
    h: Polyval,
    // Ek(bin(1))
    l: Block,
    // The length of the provided tweak.
    //
    // Cached by `init_tweak`.
    tweak_len: Option<usize>,
    // The state of POLYVAL for M % n == 0.
    state0: Polyval,
    // The state of POLYVAL for M % n != 0.
    state1: Polyval,
}

impl<C: BlockCipher<BlockSize = U16>> Hctr2<C> {
    /// Creates an HCTR2 cipher.
    ///
    /// The provided block cipher must have a block size of
    /// exactly [`BLOCK_SIZE`] bytes.
    pub fn new(cipher: C) -> Self {
        // h ← Ek(bin(0))
        let h = {
            let mut h = Block::<C>::default();
            cipher.encrypt_block_in_place(&mut h);
            // The probability that Ek(bin(0)) is non-zero is
            // negligible and we've already required a 16-byte
            // block cipher.
            let key = polyval::Key::new_unchecked(h.into());
            Polyval::new(&key)
        };

        // L ← Ek(bin(1))
        let mut l = 1u128.to_le_bytes();
        cipher.encrypt_block_in_place((&mut l).into());

        Hctr2 {
            cipher,
            l,
            tweak_len: None,
            state0: h.clone(),
            state1: h.clone(),
            h,
        }
    }

    /// Encrypts `src` into `dst` using `tweak`.
    ///
    /// It is an error if `dst` is not at least as long as `src`,
    /// if either are less than one block, or if `tweak` is
    /// longer than a block.
    pub fn seal(&mut self, dst: &mut [u8], src: &[u8], tweak: &[u8]) -> Result<(), Error> {
        self.hctr2(&mut dst[..src.len()], src, tweak, true)
    }

    /// Decrypts `src` into `dst` using `tweak`.
    ///
    /// It is an error if `dst` is not at least as long as `src`,
    /// if either are less than one block, or if `tweak` is
    /// longer than a block.
    pub fn open(&mut self, dst: &mut [u8], src: &[u8], tweak: &[u8]) -> Result<(), Error> {
        self.hctr2(&mut dst[..src.len()], src, tweak, false)
    }

    fn hctr2(&mut self, dst: &mut [u8], src: &[u8], tweak: &[u8], seal: bool) -> Result<(), Error> {
        if dst.len() < BLOCK_SIZE
            || src.len() < BLOCK_SIZE
            || dst.len() < src.len()
            || tweak.len() > BLOCK_SIZE
        {
            return Err(Error::InvalidLength);
        }

        // M || N ← P, |M| = n
        let (m, n) = src.split_at(BLOCK_SIZE);

        self.init_tweak(tweak);

        let mut poly = if n.len() % BLOCK_SIZE == 0 {
            self.state0.clone()
        } else {
            self.state1.clone()
        };
        poly.update_padded(tweak);

        // Save the state so we can reuse it later.
        let state = poly.clone();

        // MM ← M ⊕ H_h(T, N)
        let t = polyhash(poly, n);
        let mm = xor2(m, &t.into());

        // UU ← Ek(MM)
        let mut uu = Block::<C>::default();
        if seal {
            self.cipher.encrypt_block(&mut uu, &mm.into());
        } else {
            self.cipher.decrypt_block(&mut uu, &mm.into());
        }

        // S ← MM ⊕ UU ⊕ L
        let s = xor3(&mm, &uu.into(), &self.l);

        let (u, v) = dst.split_at_mut(BLOCK_SIZE);

        // V ← N ⊕ XCTR_k(S)[0;|N|]
        self.cipher.xctr(v, n, &s.into());

        // U ← UU ⊕ Hh(T, V)
        let t = polyhash(state, v);
        xor_block_into(u, &uu, &t.into());

        Ok(())
    }

    /// Encrypts `data` in-place using `tweak`.
    ///
    /// It is an error if `data` is less than one block or if
    /// `tweak` is longer than a block.
    pub fn seal_in_place(&mut self, data: &mut [u8], tweak: &[u8]) -> Result<(), Error> {
        self.hctr2_in_place(data, tweak, true)
    }

    /// Decrypts `data` in-place using `tweak`.
    ///
    /// It is an error if `data` is less than one block or if
    /// `tweak` is longer than a block.
    pub fn open_in_place(&mut self, data: &mut [u8], tweak: &[u8]) -> Result<(), Error> {
        self.hctr2_in_place(data, tweak, false)
    }

    fn hctr2_in_place(&mut self, data: &mut [u8], tweak: &[u8], seal: bool) -> Result<(), Error> {
        if data.len() < BLOCK_SIZE || tweak.len() > BLOCK_SIZE {
            return Err(Error::InvalidLength);
        }

        // M || N ← P, |M| = n
        let (m, n) = data.split_at_mut(BLOCK_SIZE);

        self.init_tweak(tweak);

        let mut poly = if n.len() % BLOCK_SIZE == 0 {
            self.state0.clone()
        } else {
            self.state1.clone()
        };
        poly.update_padded(tweak);

        // Save the state so we can reuse it later.
        let state = poly.clone();

        // MM ← M ⊕ H_h(T, N)
        let t = polyhash(poly, n);
        let mm = xor2(m, &t.into());

        // UU ← Ek(MM)
        let mut uu = Block::<C>::default();
        if seal {
            self.cipher.encrypt_block(&mut uu, &mm.into());
        } else {
            self.cipher.decrypt_block(&mut uu, &mm.into());
        }

        // S ← MM ⊕ UU ⊕ L
        let s = xor3(&mm, &uu.into(), &self.l);

        // V ← N ⊕ XCTR_k(S)[0;|N|]
        self.cipher.xctr_in_place(n, &s.into());

        // U ← UU ⊕ Hh(T, V)
        let t = polyhash(state, n);
        xor_block_into(m, &uu, &t.into());

        Ok(())
    }

    fn init_tweak(&mut self, tweak: &[u8]) {
        // The first block in the hash of the tweak is the same
        // so long as the length of the tweak is the same, so
        // cache it.
        if let Some(n) = self.tweak_len {
            if n == tweak.len() {
                return;
            }
        }

        if tweak.len() > (u64::MAX / 16 - 2) as usize {
            // TODO
        }

        // M = the input to the hash.
        // n = the block size of the hash.
        //
        // If n divides |M|:
        //    POLYVAL(h, bin(2*|T| + 2) || pad(T) || M)
        // else:
        //    POLYVAL(h, bin(2*|T| + 3) || pad(T) || pad(M || 1))
        let l = u128::from((tweak.len() as u64) * 8 * 2 + 2);

        self.state0 = self.h.clone();
        self.state0
            .update(&l.to_le_bytes())
            .expect("should be a multiple of `BLOCK_SIZE`");

        self.state1 = self.h.clone();
        self.state1
            .update(&(l + 1).to_le_bytes())
            .expect("should be a multiple of `BLOCK_SIZE`");

        self.tweak_len = Some(tweak.len());
    }
}

fn polyhash(mut p: Polyval, src: &[u8]) -> polyval::Tag {
    let (head, tail) = src.split_at((src.len() / polyval::BLOCK_SIZE) * polyval::BLOCK_SIZE);
    if !head.is_empty() {
        p.update(head)
            .expect("should be a multiple of `BLOCK_SIZE`");
    }
    if !tail.is_empty() {
        let mut block = [0u8; polyval::BLOCK_SIZE];
        block[..tail.len()].copy_from_slice(tail);
        block[tail.len()] = 1;
        p.update(&block)
            .expect("should be a multiple of `BLOCK_SIZE`");
    }
    p.tag()
}

/// Returns x^y.
#[inline(always)]
fn xor2(x: &[u8], y: &[u8; 16]) -> [u8; 16] {
    let mut z = [0u8; BLOCK_SIZE];
    for (z, (x, y)) in zip(z.iter_mut(), zip(x, y)) {
        *z = x ^ y;
    }
    z
}

/// Returns v^x^y.
#[inline(always)]
fn xor3(v: &[u8; 16], x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let mut z = [0u8; BLOCK_SIZE];
    for (z, (v, (x, y))) in zip(z.iter_mut(), zip(v, zip(x, y))) {
        *z = v ^ x ^ y;
    }
    z
}

/// Sets z = x^y.
#[inline(always)]
pub(crate) fn xor_block_into(z: &mut [u8], x: &[u8], y: &[u8; 16]) {
    for (z, (x, y)) in zip(z.iter_mut(), zip(x, y)) {
        *z = x ^ y;
    }
}
