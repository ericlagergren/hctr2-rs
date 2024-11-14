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
    // Underlying block cipher.
    cipher: C,
    // Ek(bin(1))
    l: Block<C>,
    // The length of the provided tweak.
    //
    // Cached by `init_tweak`.
    tweak_len: Option<usize>,
    // The cached first block of the hash of the tweak for
    // |M| % n == 0.
    state0: P,
    // The cached first block of the hash of the tweak for
    // |M| % n != 0.
    state1: P,
}

impl<C, P> Hctr2<C, P>
where
    C: BlockCipher,
    P: Poly<BlockSize = <C as BlockSize>::BlockSize>,
{
    const BLOCK_SIZE: usize = <C as BlockSize>::BlockSize::USIZE;
    const MAX_TWEAK_SIZE: usize = (1 << (Self::BLOCK_SIZE - 1)) - 2;

    /// Creates an HCTR2 cipher.
    pub fn new(cipher: C) -> Self {
        // h ← Ek(bin(0))
        let h = {
            let mut h = Block::<C>::default();
            cipher.encrypt_block_in_place(&mut h);
            // The probability that Ek(bin(0)) is non-zero is
            // negligible.
            P::new(&h)
        };

        // L ← Ek(bin(1))
        let mut l = Block::<C>::default();
        l[0] = 1;
        cipher.encrypt_block_in_place(&mut l);

        Hctr2 {
            cipher,
            l,
            tweak_len: None,
            state0: h.clone(),
            state1: h.clone(),
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

        let mut poly = if n.len() % Self::BLOCK_SIZE == 0 {
            self.state0.clone()
        } else {
            self.state1.clone()
        };
        poly.update_padded(tweak);

        // Save the state so we can reuse it later.
        let state = poly.clone();

        // MM ← M ⊕ H_h(T, N)
        let t = polyhash(poly, n);
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

        // V ← N ⊕ XCTR_k(S)[0;|N|]
        Xctr::new(&self.cipher).encrypt(v, n, &s);

        // U ← UU ⊕ Hh(T, V)
        let t = polyhash(state, v);
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

        let mut poly = if n.len() % Self::BLOCK_SIZE == 0 {
            self.state0.clone()
        } else {
            self.state1.clone()
        };
        poly.update_padded(tweak);

        // Save the state so we can reuse it later.
        let state = poly.clone();

        // MM ← M ⊕ H_h(T, N)
        let t = polyhash(poly, n);
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
        let t = polyhash(state, n);
        xor_block_into::<C>(m, &uu, &t);

        Ok(())
    }

    fn init_tweak_len(&mut self, tweak: &[u8]) {
        // The first block in the hash of the tweak is the same
        // so long as the length of the tweak is the same, so
        // cache it.
        match self.tweak_len {
            // Fast path. We've already initialized `state0` and
            // `state1` with this tweak length.
            Some(n) if n == tweak.len() => return,
            // Slow path. We've already initialized `state0` and
            // `state1`, but for a different tweak length.
            Some(_) => return self.update_tweak_len(tweak),
            // Initial path. We haven't updated either `state0`
            // or `state1` yet.
            None => {
                // TODO(eric): Debug assert that `state0` and
                // `state1` are both initialized to `h`.

                self.state0.update(&[state::<C>(tweak, false)]);
                self.state1.update(&[state::<C>(tweak, true)]);

                self.tweak_len = Some(tweak.len());
            }
        }
    }

    #[cold]
    fn update_tweak_len(&mut self, tweak: &[u8]) {
        // h ← Ek(bin(0))
        let h = {
            let mut h = Block::<C>::default();
            self.cipher.encrypt_block_in_place(&mut h);
            // The probability that Ek(bin(0)) is non-zero is
            // negligible.
            P::new(&h)
        };

        self.state0.clone_from(&h);
        self.state0.update(&[state::<C>(tweak, false)]);

        self.state1.clone_from(&h);
        self.state1.update(&[state::<C>(tweak, true)]);

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

/// `odd` is true for |M| % n != 0.
fn state<S: BlockSize>(tweak: &[u8], odd: bool) -> Block<S> {
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
    let t = 2 * (tweak.len() * 8) + 2 + odd as usize;
    let mut l = Block::<S>::default();
    l[..usize::BITS as usize / 8].copy_from_slice(&t.to_le_bytes());
    l
}

/// Hash a message.
///
/// `p` must be initialized with the tweak length.
fn polyhash<P: Poly>(mut p: P, src: &[u8]) -> Block<P> {
    let (head, tail) = GenericArray::chunks_from_slice(src);
    if !head.is_empty() {
        p.update(head);
    }
    if !tail.is_empty() {
        let mut block = Block::<P>::default();
        #[allow(
            clippy::indexing_slicing,
            reason = "The compiler can prove the slice is in bounds."
        )]
        block[..tail.len()].copy_from_slice(tail);
        block[tail.len()] = 1;
        p.update(&[block]);
    }
    p.tag()
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
