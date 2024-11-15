use core::{error, fmt};

use generic_array::GenericArray;
use typenum::Unsigned;

use super::{
    block::{Block, BlockCipher, BlockSize},
    poly::Poly,
    xctr::Xctr,
};

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
/// # Warning
///
/// This is a low-level primitive. Only use it if you know what
/// you are doing. When in doubt, use
/// [`Hctr2Aes128`][crate::Hctr2Aes128] or
/// [`Hctr2Aes256`][crate::Hctr2Aes256] instead.
#[derive(Clone)]
pub struct Hctr2<C, P>
where
    C: BlockCipher,
    P: Poly<BlockSize = <C as BlockSize>::BlockSize>,
{
    /// The underlying block cipher.
    cipher: C,
    /// P keyed with Ek(bin(0)).
    poly: P,
    /// Ek(bin(1))
    l: Block<C>,
    /// The length of the provided tweak.
    ///
    /// Cached by `init_tweak`.
    tweak_len: Option<usize>,
    /// The cached first block of the hash of the tweak for
    /// |M| % n == 0.
    state0: P::State,
    /// The cached first block of the hash of the tweak for
    /// |M| % n != 0.
    state1: P::State,
}

impl<C, P> Hctr2<C, P>
where
    C: BlockCipher,
    P: Poly<BlockSize = <C as BlockSize>::BlockSize>,
{
    const BLOCK_SIZE: usize = <C as BlockSize>::BlockSize::USIZE;
    const MAX_TWEAK_SIZE: usize = Self::BLOCK_SIZE;

    /// Creates an HCTR2 cipher.
    pub fn new(cipher: C) -> Self {
        let poly = {
            // h ← Ek(bin(0))
            let mut h = Block::<C>::default();
            cipher.encrypt_block_in_place(&mut h);
            P::new(&h)
        };

        // L ← Ek(bin(1))
        let mut l = Block::<C>::default();
        l[0] = 1;
        cipher.encrypt_block_in_place(&mut l);

        Hctr2 {
            cipher,
            poly,
            l,
            tweak_len: None,
            state0: P::State::default(),
            state1: P::State::default(),
        }
    }

    /// Encrypts `src` into `dst` using `tweak`.
    ///
    /// It is an error if `dst` is not at least as long as `src`,
    /// if either are less than one block, or if `tweak` is
    /// longer than a block.
    pub fn seal(&mut self, dst: &mut [u8], src: &[u8], tweak: &[u8]) -> Result<(), Error> {
        self.hctr2(dst, src, tweak, true)
    }

    /// Decrypts `src` into `dst` using `tweak`.
    ///
    /// It is an error if `dst` is not at least as long as `src`,
    /// if either are less than one block, or if `tweak` is
    /// longer than a block.
    pub fn open(&mut self, dst: &mut [u8], src: &[u8], tweak: &[u8]) -> Result<(), Error> {
        self.hctr2(dst, src, tweak, false)
    }

    fn hctr2(&mut self, dst: &mut [u8], src: &[u8], tweak: &[u8], seal: bool) -> Result<(), Error> {
        if dst.len() < Self::BLOCK_SIZE
            || src.len() < Self::BLOCK_SIZE
            || dst.len() < src.len()
            || tweak.len() > Self::MAX_TWEAK_SIZE
        {
            return Err(Error::InvalidLength);
        }
        let dst = &mut dst[..src.len()];

        // M || N ← P, |M| = n
        let (m, n) = src.split_at(Self::BLOCK_SIZE);

        self.init_tweak_len(tweak);

        if n.len() % Self::BLOCK_SIZE == 0 {
            self.poly.reset(&self.state0);
        } else {
            self.poly.reset(&self.state1);
        };
        self.poly.update_padded(tweak); // pad(T)

        // Save the state so we can reuse it later.
        let state = self.poly.export();

        // MM ← M ⊕ H_h(T, N)
        let t = self.polyhash(n);
        let mm = xor2::<C>(m, &t);

        // UU ← Ek(MM)
        let mut uu = Block::<C>::default();
        if seal {
            self.cipher.encrypt_block(&mut uu, &mm);
        } else {
            self.cipher.decrypt_block(&mut uu, &mm);
        }

        // S ← MM ⊕ UU ⊕ L
        let s = xor3::<C>(&mm, &uu, &self.l);

        let (u, v) = dst.split_at_mut(Self::BLOCK_SIZE);
        if cfg!(test) {
            println!("u={} v={}", u.len(), v.len());
        }
        // V ← N ⊕ XCTR_k(S)[0;|N|]
        Xctr::new(&self.cipher).encrypt(v, n, &s);

        // U ← UU ⊕ Hh(T, V)
        self.poly.reset(&state);
        let t = self.polyhash(v);
        xor_block_into::<C>(u, &uu, &t);

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
        if data.len() < Self::BLOCK_SIZE || tweak.len() > Self::MAX_TWEAK_SIZE {
            return Err(Error::InvalidLength);
        }

        // M || N ← P, |M| = n
        let (m, n) = data.split_at_mut(Self::BLOCK_SIZE);

        self.init_tweak_len(tweak);

        if n.len() % Self::BLOCK_SIZE == 0 {
            self.poly.reset(&self.state0);
        } else {
            self.poly.reset(&self.state1);
        };
        self.poly.update_padded(tweak); // pad(T)

        // Save the state so we can reuse it later.
        let state = self.poly.export();

        // MM ← M ⊕ H_h(T, N)
        let t = self.polyhash(n);
        let mm = xor2::<C>(m, &t);

        // UU ← Ek(MM)
        let mut uu = Block::<C>::default();
        if seal {
            self.cipher.encrypt_block(&mut uu, &mm);
        } else {
            self.cipher.decrypt_block(&mut uu, &mm);
        }

        // S ← MM ⊕ UU ⊕ L
        let s = xor3::<C>(&mm, &uu, &self.l);

        // V ← N ⊕ XCTR_k(S)[0;|N|]
        Xctr::new(&self.cipher).encrypt_in_place(n, &s);

        // U ← UU ⊕ Hh(T, V)
        self.poly.reset(&state);
        let t = self.polyhash(n);
        xor_block_into::<C>(m, &uu, &t);

        Ok(())
    }

    /// Hash a message.
    fn polyhash(&mut self, m: &[u8]) -> Block<P> {
        // H_h(T, M) is defined as
        //
        // If n divides |M|:
        //    POLYVAL(h, bin(2*|T| + 2) || pad(T) || M)
        // else:
        //    POLYVAL(h, bin(2*|T| + 3) || pad(T) || pad(M || 1))
        //
        // Here, `self.poly` is initialized with either
        //
        //    POLYVAL(h, bin(2*|T| + 2) || pad(T))
        //    POLYVAL(h, bin(2*|T| + 3) || pad(T))
        //
        // So, write M or pad(M || 1) accordingly.
        let (head, tail) = GenericArray::chunks_from_slice(m);
        if cfg!(test) {
            println!("m={} head={} tail={}", m.len(), head.len(), tail.len());
        }
        if !head.is_empty() {
            self.poly.update(head);
        }
        if !tail.is_empty() {
            let mut block = Block::<P>::default();
            #[allow(
                clippy::indexing_slicing,
                reason = "The compiler can prove the slice is in bounds."
            )]
            block[..tail.len()].copy_from_slice(tail);
            block[tail.len()] = 1;
            self.poly.update(&[block]);
        }
        self.poly.tag()
    }

    fn init_tweak_len(&mut self, tweak: &[u8]) {
        if self.tweak_len.is_some_and(|n| n == tweak.len()) {
            // Fast path. We've already initialized `state0` and
            // `state1` with this tweak length.
            return;
        }

        // The first block in the hash of the tweak is the same
        // so long as the length of the tweak is the same, so
        // cache it.

        self.poly.reset(&P::State::default());
        self.poly.update(&[initial_state::<C>(tweak, false)]);
        self.state0 = self.poly.export();

        self.poly.reset(&P::State::default());
        self.poly.update(&[initial_state::<C>(tweak, true)]);
        self.state1 = self.poly.export();

        self.tweak_len = Some(tweak.len());
    }
}

impl<C, P> fmt::Debug for Hctr2<C, P>
where
    C: BlockCipher,
    P: Poly<BlockSize = <C as BlockSize>::BlockSize>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hctr2").finish_non_exhaustive()
    }
}

/// Computes the initial block written to `poly`.
///
/// `odd` is true for |M| % n != 0.
fn initial_state<S: BlockSize>(tweak: &[u8], odd: bool) -> Block<S> {
    // TODO: overflows?
    if tweak.len() > (usize::MAX / 16 - 2) as usize {
        // TODO
    }

    // M = the input to the hash.
    // n = the block size of the hash.
    //
    // If n divides |M|:
    //    POLYVAL(h, bin(2*|T| + 2) || pad(T) || M)
    // else:
    //    POLYVAL(h, bin(2*|T| + 3) || pad(T) || pad(M || 1))
    let t = (2 * (tweak.len() * 8)) + 2 + odd as usize;
    let mut l = Block::<S>::default();
    l[..usize::BITS as usize / 8].copy_from_slice(&t.to_le_bytes());
    l
}

/// Returns x^y.
#[inline(always)]
fn xor2<S: BlockSize>(x: &[u8], y: &Block<S>) -> Block<S> {
    let mut z = Block::<S>::default();
    for ((z, x), y) in z.iter_mut().zip(x).zip(y) {
        *z = x ^ y;
    }
    z
}

/// Returns v^x^y.
#[inline(always)]
fn xor3<S: BlockSize>(v: &Block<S>, x: &Block<S>, y: &Block<S>) -> Block<S> {
    let mut z = Block::<S>::default();
    for (((z, v), x), y) in z.iter_mut().zip(v).zip(x).zip(y) {
        *z = v ^ x ^ y;
    }
    z
}

/// Sets z = x^y.
#[inline(always)]
pub(crate) fn xor_block_into<S: BlockSize>(z: &mut [u8], x: &[u8], y: &Block<S>) {
    for ((z, x), y) in z.iter_mut().zip(x).zip(y) {
        *z = x ^ y;
    }
}
