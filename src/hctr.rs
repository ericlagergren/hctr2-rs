use core::{error, fmt, marker::PhantomData};

use typenum::Unsigned;

use super::{
    block::{Block, BlockCipher, BlockSize},
    poly::Poly,
    util::{xor2, xor3, xor_block_into},
    xctr::XctrCore,
};

#[allow(unused_macros, reason = "For debugging only")]
macro_rules! dprintln {
    ($($tt:tt)*) => {
        #[cfg(test)] {
            println!($($tt)*);
        }
    }
}
pub(crate) use dprintln;

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
/// # ⚠️ Warning
///
/// This is a low-level primitive. Only use it if you know what
/// you are doing. When in doubt, use
/// [`Hctr2Aes128`][crate::Hctr2Aes128] or
/// [`Hctr2Aes256`][crate::Hctr2Aes256] instead.
#[derive(Clone)]
pub struct Hctr2<C, P>
where
    C: BlockCipher,
    P: Poly<BlockSize = C::BlockSize>,
{
    /// The underlying block cipher.
    cipher: C,
    /// Keyed with Ek(bin(0)).
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
    _xctr: PhantomData<()>,
}

impl<C, P> Hctr2<C, P>
where
    C: BlockCipher,
    P: Poly<BlockSize = C::BlockSize>,
{
    const BLOCK_SIZE: usize = <C as BlockSize>::BlockSize::USIZE;

    const MIN_MSG_SIZE: usize = Self::BLOCK_SIZE;

    // (2^(n-1) - 2) / 8
    const MAX_MSG_SIZE: usize = {
        assert!(Self::BLOCK_SIZE > 0);
        let n = Self::BLOCK_SIZE * 8;
        if n - 1 + 4 >= usize::BITS as usize {
            usize::MAX
        } else {
            let bits = 1 << (n - 1);
            (bits / 8) as usize
        }
    };

    const MAX_TWEAK_SIZE: usize = Self::MAX_MSG_SIZE;

    /// Creates an `Hctr2`.
    pub fn new(cipher: C) -> Self {
        let poly = {
            // h ← Ek(bin(0))
            let mut h = Block::<C>::default();
            cipher.encrypt_block_in_place(&mut h);
            P::new(&h)
        };

        // L ← Ek(bin(1))
        #[allow(
            clippy::indexing_slicing,
            reason = "The compiler can prove the slice is in bounds."
        )]
        let mut l = {
            let mut l = Block::<C>::default();
            l[0] = 1;
            l
        };
        cipher.encrypt_block_in_place(&mut l);

        Hctr2 {
            cipher,
            poly,
            l,
            tweak_len: None,
            state0: P::State::default(),
            state1: P::State::default(),
            _xctr: PhantomData,
        }
    }

    /// Encrypts `src` into `dst` using `tweak`.
    ///
    /// It is an error if `dst` is not at least as long as `src`,
    /// if either are less than one block, or if `tweak` is
    /// longer than a block.
    pub fn seal(&mut self, dst: &mut [u8], src: &[u8], tweak: &[u8]) -> Result<(), Error> {
        self.hctr2::<true>(dst, src, tweak)
    }

    /// Decrypts `src` into `dst` using `tweak`.
    ///
    /// It is an error if `dst` is not at least as long as `src`,
    /// if either are less than one block, or if `tweak` is
    /// longer than a block.
    pub fn open(&mut self, dst: &mut [u8], src: &[u8], tweak: &[u8]) -> Result<(), Error> {
        self.hctr2::<false>(dst, src, tweak)
    }

    fn hctr2<const SEAL: bool>(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
        tweak: &[u8],
    ) -> Result<(), Error> {
        if src.len() < Self::MIN_MSG_SIZE
            || src.len() > Self::MAX_MSG_SIZE
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
        if SEAL {
            self.cipher.encrypt_block(&mut uu, &mm);
        } else {
            self.cipher.decrypt_block(&mut uu, &mm);
        }

        // S ← MM ⊕ UU ⊕ L
        let s = xor3::<C>(&mm, &uu, &self.l);

        let (u, v) = dst.split_at_mut(Self::BLOCK_SIZE);
        // V ← N ⊕ XCTR_k(S)[0;|N|]
        XctrCore::new(&self.cipher, &s).apply_keystream(v, n);

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
        self.hctr2_in_place::<true>(data, tweak)
    }

    /// Decrypts `data` in-place using `tweak`.
    ///
    /// It is an error if `data` is less than one block or if
    /// `tweak` is longer than a block.
    pub fn open_in_place(&mut self, data: &mut [u8], tweak: &[u8]) -> Result<(), Error> {
        self.hctr2_in_place::<false>(data, tweak)
    }

    fn hctr2_in_place<const SEAL: bool>(
        &mut self,
        data: &mut [u8],
        tweak: &[u8],
    ) -> Result<(), Error> {
        if data.len() < Self::MIN_MSG_SIZE
            || data.len() > Self::MAX_MSG_SIZE
            || tweak.len() > Self::MAX_TWEAK_SIZE
        {
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
        if SEAL {
            self.cipher.encrypt_block(&mut uu, &mm);
        } else {
            self.cipher.decrypt_block(&mut uu, &mm);
        }

        // S ← MM ⊕ UU ⊕ L
        let s = xor3::<C>(&mm, &uu, &self.l);

        // V ← N ⊕ XCTR_k(S)[0;|N|]
        XctrCore::new(&self.cipher, &s).apply_keystream_in_place(n);

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
        let (head, tail) = Block::<P>::chunks_from_slice(m);
        if !head.is_empty() {
            self.poly.update(head);
        }
        if !tail.is_empty() {
            #[allow(
                clippy::indexing_slicing,
                reason = "The compiler can prove the slice is in bounds."
            )]
            let block = {
                let mut block = Block::<C>::default();
                block[..tail.len()].copy_from_slice(tail);
                block[tail.len()] = 1;
                block
            };
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
    P: Poly<BlockSize = C::BlockSize>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hctr2").finish_non_exhaustive()
    }
}

/// Computes the initial block written to `poly`.
///
/// `odd` is true for |M| % n != 0.
fn initial_state<S: BlockSize>(tweak: &[u8], odd: bool) -> Block<S> {
    // TODO(eric): What if `t` overflows?

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
