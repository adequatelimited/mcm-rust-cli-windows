// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! Base58.
//!
//! The codec carries no checksum. Mochimo's tag checksum is two CRC-16 bytes
//! the caller appends before encoding.
//!
//! # Length probes
//!
//! [`encode_probe_len`] and [`decode_probe_len`] report the lengths the
//! backend computes; the test fixtures check them. On an all-zero payload they
//! report the true length, where the reference C implementation reports one
//! less (fixture `C-base58-degenerate`). `tests/kat.rs` checks both answers on
//! every group C vector that records one.

use crate::backend::selected as backend;
use crate::error::Result;

/// The encode length the selected backend reports.
///
/// Equal to `encode(input)?.len()` under `native`. The reference C probe
/// reports one less when `input` is entirely zero bytes.
pub fn encode_probe_len(input: &[u8]) -> Result<usize> {
    backend::base58_encoded_len(input)
}

/// Encodes `input`.
pub fn encode(input: &[u8]) -> Result<String> {
    backend::base58_encode(input)
}

/// The decode length the selected backend reports.
///
/// Defined for all-`'1'` strings (see [`decode`]).
pub fn decode_probe_len(s: &str) -> Result<usize> {
    backend::base58_decoded_len(s.as_bytes())
}

/// Decodes `s`. Defined for every input.
///
/// # All-`'1'` strings
///
/// A non-empty string of only `'1'` characters of length *n* decodes to *n*
/// zero bytes and is handled before the general decoder. The reference C
/// decoder crashes on this input (`memcpy` with length `(size_t)(-1)`), so
/// the value is specified rather than taken from it: fixture
/// `C-base58-degenerate` states it and the `CX-C-base58-degenerate`
/// crosscheck confirms it against the `bs58` crate.
pub fn decode(s: &str) -> Result<Vec<u8>> {
    if !s.is_empty() && s.as_bytes().iter().all(|&c| c == b'1') {
        return decode_degenerate_class(s);
    }
    decode_via_backend(s)
}

/// Decodes an all-`'1'` string with `native::base58_decode`.
#[cfg(feature = "native")]
fn decode_degenerate_class(s: &str) -> Result<Vec<u8>> {
    crate::backend::native::base58_decode(s.as_bytes())
}

/// Decodes any other string through the selected backend.
fn decode_via_backend(s: &str) -> Result<Vec<u8>> {
    backend::base58_decode(s.as_bytes())
}
