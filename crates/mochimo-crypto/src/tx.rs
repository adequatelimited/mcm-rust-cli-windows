// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! Transaction accessors and length bounds.
//!
//! The free functions below need no transaction value: three options-byte
//! accessors, two address-half accessors, and two minimum lengths. Each is
//! the Rust counterpart of a function-like macro in the reference's
//! `types.h`, delegated through [`crate::backend::selected`], and each has a
//! group D test vector.
//!
//! [`wire`] holds the owned transaction types and the wire codec, used to
//! both read and build transactions.

use crate::consts::ADDR_LEN;

/// `TXDAT_MDST`: the multi-destination transaction-data type.
pub const DAT_MDST: u8 = crate::consts::TXDAT_MDST;

/// `TXDAT_SET_DELEGATE` — the proof-of-stake chain's cold-key delegate
/// assignment. Built by [`wire::Body::SetDelegate`].
pub const DAT_SET_DELEGATE: u8 = crate::consts::TXDAT_SET_DELEGATE;

/// `TXDAT_CLEAR_DELEGATE` — the proof-of-stake chain's cold-key delegate
/// removal. Built by [`wire::Body::ClearDelegate`].
pub const DAT_CLEAR_DELEGATE: u8 = crate::consts::TXDAT_CLEAR_DELEGATE;

/// `TXDAT_CLAIM` — the proof-of-stake chain's release of reward entitlement
/// into spendable balance. Built by [`wire::Body::Claim`].
pub const DAT_CLAIM: u8 = crate::consts::TXDAT_CLAIM;

/// `TXDAT_STAKE` — v4.1: stake part of the spendable balance. Built by
/// [`wire::Body::Stake`].
pub const DAT_STAKE: u8 = crate::consts::TXDAT_STAKE;

/// `TXDAT_UNSTAKE` — v4.1: end the stake. Built by [`wire::Body::Unstake`].
pub const DAT_UNSTAKE: u8 = crate::consts::TXDAT_UNSTAKE;

/// `TXDAT_ACCEPT` — v4.1: consent to a validator designation, or revoke it.
/// Built by [`wire::Body::Accept`].
pub const DAT_ACCEPT: u8 = crate::consts::TXDAT_ACCEPT;

/// `TXDSA_WOTS`: the only signature-algorithm type the reference accepts.
pub const DSA_WOTS: u8 = crate::consts::TXDSA_WOTS;

/// `ADDR_REF_LEN` — the optional destination reference field.
pub const REF_LEN: usize = crate::consts::ADDR_REF_LEN;

/// `HASHLEN` — the transaction id is a SHA-256 digest.
pub const ID_LEN: usize = crate::consts::HASHLEN;

/// The largest destination count an options byte can encode.
///
/// `MDST_COUNT(options)` is `options[2] + 1`, so `0xFF` yields 256. The
/// node relies on this bound to keep its computed offsets inside the buffer.
pub const MAX_DESTINATIONS: u16 = 256;

/// Owned transaction types and the wire codec.
#[cfg(feature = "native")]
pub mod wire;

// --- accessors ---------------------------------------------------------
//
// Wrappers over `types.h` function-like macros, delegating to
// [`crate::backend::selected`].

use crate::backend::selected;

/// The transaction-data type code: the first options byte.
///
/// `TXDAT_TYPE(options)`.
#[must_use]
pub fn dat_type(options: &[u8; 4]) -> u8 {
    selected::dat_type(options)
}

/// The DSA type code: the second options byte.
///
/// `TXDSA_TYPE(options)`.
#[must_use]
pub fn dsa_type(options: &[u8; 4]) -> u8 {
    selected::dsa_type(options)
}

/// The multi-destination count: the third options byte, plus one.
///
/// `MDST_COUNT(options)`. Returns `u16` because the macro's `+ 1`
/// integer-promotes: an options byte of `0xFF` yields 256, not 0.
#[must_use]
pub fn mdst_count(options: &[u8; 4]) -> u16 {
    selected::mdst_count(options)
}

/// The tag half of an address: `ADDR_TAG_LEN` bytes from `ADDR_TAG_OFF`.
///
/// `ADDR_TAG_PTR(ptr)`, returned as a slice, with the offset and length
/// taken from the layout constants. Checked against the recorded group D
/// offsets.
#[must_use]
pub fn tag_ptr(addr: &[u8; ADDR_LEN]) -> &[u8] {
    selected::tag_ptr(addr)
}

/// The hash half of an address: `ADDR_HASH_LEN` bytes from `ADDR_HASH_OFF`.
///
/// `ADDR_HASH_PTR(ptr)`. Unlike `addr::hash_of`, which slices at
/// `ADDR_TAG_LEN`, this reads the offset from `ADDR_HASH_OFF`.
#[must_use]
pub fn hash_ptr(addr: &[u8; ADDR_LEN]) -> &[u8] {
    selected::hash_ptr(addr)
}

/// Minimum length of a transaction received over the network.
///
/// `TXLEN_MIN`, a sum of three `sizeof`s, computed from
/// `crate::consts::wire`, which mirrors the reference's `STATIC_ASSERT`
/// sizes.
#[must_use]
pub fn len_min() -> usize {
    selected::len_min()
}

/// Minimum length of a transaction on disk: `TXLEN_MIN` plus a trailer.
///
/// `TXLEN_DSK_MIN`.
#[must_use]
pub fn len_dsk_min() -> usize {
    selected::len_dsk_min()
}
