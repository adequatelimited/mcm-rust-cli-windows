// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! Hex as the Mesh API uses it: lowercase on output, either case on input,
//! with or without a `0x` prefix depending on the field (account and block
//! identifiers have `0x`; `signed_transaction` and the submit reply's `hash`
//! do not).
//!
//! Implemented here to avoid a dependency. The decoder does not panic: it
//! reports the offset of the first invalid byte.

use crate::error::{Error, Result};

/// Lowercase hex of `bytes`.
pub fn encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Decodes `s`, either case. An odd length or a non-hex byte is
/// [`Error::Hex`] carrying the offset of the first byte refused.
pub fn decode(s: &str, what: &'static str) -> Result<Vec<u8>> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        // The unpaired nibble is the last byte.
        return Err(Error::Hex {
            what,
            offset: bytes.len().saturating_sub(1),
        });
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for (i, [hi, lo]) in bytes.as_chunks::<2>().0.iter().enumerate() {
        match (nibble(*hi), nibble(*lo)) {
            (Some(hi), Some(lo)) => out.push((hi << 4) | lo),
            (None, _) => return Err(Error::Hex { what, offset: i * 2 }),
            (_, None) => return Err(Error::Hex { what, offset: i * 2 + 1 }),
        }
    }
    Ok(out)
}

/// [`decode`], then exactly `N` bytes or [`Error::Length`].
pub fn decode_exact<const N: usize>(s: &str, what: &'static str) -> Result<[u8; N]> {
    let bytes = decode(s, what)?;
    <[u8; N]>::try_from(bytes.as_slice()).map_err(|_| Error::Length {
        what,
        expected: N,
        got: bytes.len(),
    })
}

/// A `0x`-prefixed field of exactly `N` bytes. A missing prefix is
/// [`Error::Hex`] at offset 0.
pub fn decode_prefixed<const N: usize>(s: &str, what: &'static str) -> Result<[u8; N]> {
    match s.strip_prefix("0x") {
        Some(rest) => decode_exact::<N>(rest, what),
        None => Err(Error::Hex { what, offset: 0 }),
    }
}
