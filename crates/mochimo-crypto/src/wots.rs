// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! WOTS+ key generation, signing, and public-key recovery.

use crate::backend::selected as backend;
use zeroize::Zeroizing;

use crate::consts::{PK_LEN, SEED_LEN, SIG_LEN, WOTSLEN};
use crate::secret::Secret;

/// The WOTS+ hash address, `word32 addr[8]` in the reference implementation.
///
/// The reference mutates it in place, so every operation here takes
/// `&mut Adrs`; the final state is checked against fixtures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Adrs(pub [u32; 8]);

impl Adrs {
    pub const ZERO: Adrs = Adrs([0; 8]);

    pub fn words(&self) -> &[u32; 8] {
        &self.0
    }

    /// The big-endian serialization the reference feeds to `prf`.
    pub fn to_bytes(&self) -> [u8; 32] {
        backend::addr_to_bytes(&self.0)
    }

    /// Builds an address from the little-endian memory image of its eight
    /// words: the layout the reference's `rndbytes((word8 *)addr, 32)` leaves
    /// in a `word32[8]` and the layout the TypeScript implementation's
    /// `addr: ByteArray` takes (see `docs/specification.md`, *Big-endian
    /// serialization versus the little-endian image*). This differs from
    /// [`Adrs::to_bytes`], the big-endian serialization fed to `prf`.
    ///
    /// Used by key derivation (`derive::first_key`).
    pub fn from_le_image(image: &[u8; 32]) -> Adrs {
        let mut words = [0u32; 8];
        for (w, chunk) in words.iter_mut().zip(image.as_chunks::<4>().0) {
            *w = u32::from_le_bytes(*chunk);
        }
        Adrs(words)
    }

    /// The inverse of [`Adrs::from_le_image`].
    pub fn le_image(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (chunk, w) in out.as_chunks_mut::<4>().0.iter_mut().zip(self.0.iter()) {
            *chunk = w.to_le_bytes();
        }
        out
    }
}

impl From<[u32; 8]> for Adrs {
    fn from(words: [u32; 8]) -> Self {
        Adrs(words)
    }
}

pub type PublicKey = Box<[u8; PK_LEN]>;
pub type Signature = Box<[u8; SIG_LEN]>;

pub fn pkgen(secret: &Secret<SEED_LEN>, pub_seed: &[u8; SEED_LEN], adrs: &mut Adrs) -> PublicKey {
    backend::wots_pkgen(secret.expose(), pub_seed, &mut adrs.0)
}

/// The raw WOTS+ signer. Crate-private because a WOTS+ key must sign at most
/// once: the only public path to a signature is `Keystore::sign_spend`, which
/// requires an `AdvanceReceipt` proving the key's index advanced durably
/// before it derives the key and calls this. Tests reach the raw primitive
/// through `backend::selected::wots_sign` under the `raw-backend` feature.
///
/// # Native backend
///
/// This calls [`crate::backend::native::wots_sign`] directly rather than
/// [`backend::selected`], so that the expanded private key never passes
/// through C stack memory that is not zeroized, and so that switching the
/// selected backend cannot change which code handles wallet key material.
/// `pkgen`, used in derivation, still goes through `selected`.
#[cfg(feature = "native")]
pub(crate) fn sign(
    msg: &[u8; SEED_LEN],
    secret: &Secret<SEED_LEN>,
    pub_seed: &[u8; SEED_LEN],
    adrs: &mut Adrs,
) -> Signature {
    crate::backend::native::wots_sign(msg, secret.expose(), pub_seed, &mut adrs.0)
}

/// Recovers the public key implied by a signature.
///
/// Always produces 2144 bytes and does not verify: the caller compares the
/// result against a known public key.
pub fn pk_from_sig(
    sig: &[u8; SIG_LEN],
    msg: &[u8; SEED_LEN],
    pub_seed: &[u8; SEED_LEN],
    adrs: &mut Adrs,
) -> PublicKey {
    backend::wots_pk_from_sig(sig, msg, pub_seed, &mut adrs.0)
}

/// The file-local helpers inside `wots.c`.
///
/// Not part of the wallet API; known-answer test groups A and B check them
/// individually. Crate-private like [`sign`], because together they compose
/// into a complete signer. `tests/kat.rs` reaches the same functions through
/// `backend::selected` under `raw-backend`.
#[allow(dead_code)]
pub(crate) mod internals {
    use super::*;

    pub fn prf(input: &[u8; 32], key: &[u8; SEED_LEN]) -> [u8; 32] {
        backend::prf(input, key)
    }

    pub fn thash_f(input: &[u8; 32], pub_seed: &[u8; SEED_LEN], adrs: &mut Adrs) -> [u8; 32] {
        backend::thash_f(input, pub_seed, &mut adrs.0)
    }

    pub fn expand_seed(inseed: &Secret<SEED_LEN>) -> Box<Zeroizing<[u8; PK_LEN]>> {
        backend::expand_seed(inseed.expose())
    }

    /// The WOTSLEN1 base-w message digits followed by the WOTSLEN2 checksum
    /// digits.
    pub fn chain_lengths(msg: &[u8; SEED_LEN]) -> [i32; WOTSLEN] {
        backend::chain_lengths(msg)
    }
}
