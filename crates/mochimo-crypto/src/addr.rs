// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! Mochimo v3 addresses: a 20-byte tag at offset 0 and a 20-byte hash at
//! offset 20.

use crate::backend::selected as backend;
use crate::consts::{ADDR_HASH_LEN, ADDR_LEN, ADDR_TAG_LEN, PK_LEN};

pub type Address = [u8; ADDR_LEN];
pub type AddrHash = [u8; ADDR_HASH_LEN];
pub type Tag = [u8; ADDR_TAG_LEN];

/// `ripemd160(sha3_512(input))`, the reference's address hash.
pub fn hash_generate(input: &[u8]) -> AddrHash {
    backend::addr_hash_generate(input)
}

/// Builds an implicit address, which repeats the same 20 bytes in both halves.
pub fn from_implicit(tag: &Tag) -> Address {
    backend::addr_from_implicit(tag)
}

/// Hashes exactly `WOTS_PK_LEN` bytes (not the 2208 of a legacy WOTS+
/// address) and forms the implicit address from the result.
pub fn from_wots(pk: &[u8; PK_LEN]) -> Address {
    backend::addr_from_wots(pk)
}

pub fn tag_of(addr: &Address) -> &[u8] {
    &addr[..ADDR_TAG_LEN]
}

pub fn hash_of(addr: &Address) -> &[u8] {
    &addr[ADDR_TAG_LEN..]
}

/// SHA3-224. One function per supported width.
///
/// Fixed widths replace the reference's runtime `outlen`, which accepts
/// unsupported lengths (at `outlen >= 100` the reference writes out of
/// bounds). Only [`sha3_512`] is on the address path.
pub fn sha3_224(input: &[u8]) -> [u8; crate::consts::SHA3LEN224] {
    backend::sha3_224(input)
}

/// SHA3-256. See [`sha3_224`].
pub fn sha3_256(input: &[u8]) -> [u8; crate::consts::SHA3LEN256] {
    backend::sha3_256(input)
}

/// SHA3-384. See [`sha3_224`].
pub fn sha3_384(input: &[u8]) -> [u8; crate::consts::SHA3LEN384] {
    backend::sha3_384(input)
}

/// SHA3-512, the address path's width. See [`sha3_224`].
pub fn sha3_512(input: &[u8]) -> [u8; crate::consts::SHA3LEN512] {
    backend::sha3_512(input)
}

/// RIPEMD-160 of `input`, defined for every input length.
///
/// The reference C implementation writes past its block buffer when
/// `input.len() % 64 >= 56`, so those lengths are checked against
/// `@noble/hashes` (`fixtures/group_rx_ripemd.json`) and all other lengths
/// against the reference.
pub fn ripemd160(input: &[u8]) -> [u8; 20] {
    backend::ripemd160(input)
}

// ---------------------------------------------------------------------------
// The destination identifier
// ---------------------------------------------------------------------------
//
// Mochimo v3 clients take a destination as Base58 over the 20-byte tag
// followed by its CRC16, as the reference composes it:
//
// ```c
// word8 tag[ADDR_TAG_LEN + 2];
// put16(tag + ADDR_TAG_LEN, crc16(tag, ADDR_TAG_LEN));
// base58_encode(tag, sizeof(tag), base58_tag);
// ```
//
// The checksum is little-endian, as in the reference's `put16` unit tests
// and the browser extension.

use crate::error::Error;

/// The shortest Base58 encoding of a 22-byte tag payload (the all-zero tag).
///
/// [`tag_from_base58`] checks this length window before decoding, because
/// Base58 decoding is quadratic in the input length and a length error can
/// describe what a destination looks like. Acceptance itself requires a
/// 22-byte payload with a valid CRC16.
///
/// A hex tag is 40 characters, longer than [`TAG_BASE58_MAX_CHARS`], so no
/// string is valid in both forms.
pub const TAG_BASE58_MIN_CHARS: usize = 22;

/// The longest Base58 encoding of a 22-byte tag payload (the all-`ff` tag).
/// See [`TAG_BASE58_MIN_CHARS`].
pub const TAG_BASE58_MAX_CHARS: usize = 31;

/// Why a string is not a Base58 destination tag.
///
/// Separate from [`crate::Error`] because every variant describes user
/// input; `Display` is the message the CLI shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NotATag {
    /// Outside the length window a 22-byte payload can encode to, checked
    /// before decoding. See [`TAG_BASE58_MIN_CHARS`].
    Length {
        chars: usize,
    },
    /// Not Base58: a character outside the alphabet (which excludes `0`,
    /// `O`, `I`, `l` and all non-alphanumerics), or a non-ASCII byte.
    NotBase58(Error),
    /// Decoded to something other than a 22-byte tag payload.
    PayloadLen {
        got: usize,
    },
    /// Decoded to 22 bytes whose last two are not the CRC16 of the first 20.
    /// Base58 has no checksum of its own, so this is what catches a
    /// mistyped destination.
    Checksum {
        found: u16,
        computed: u16,
    },
}

impl core::fmt::Display for NotATag {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            NotATag::Length { chars } => write!(
                f,
                "it is {chars} character(s); a destination is Base58 over a tag and its \
                 checksum, which is {TAG_BASE58_MIN_CHARS} to {TAG_BASE58_MAX_CHARS}"
            ),
            NotATag::NotBase58(e) => write!(
                f,
                "it is not Base58 ({e}). The alphabet excludes 0, O, I and l, so a character \
                 that looks like a digit or a letter may not be one"
            ),
            NotATag::PayloadLen { got } => write!(
                f,
                "it is Base58 for {got} byte(s); a destination is {} (a {}-byte tag and a \
                 2-byte checksum)",
                ADDR_TAG_LEN + 2,
                ADDR_TAG_LEN
            ),
            NotATag::Checksum { found, computed } => write!(
                f,
                "the checksum does not match: the string carries {found:#06x} and the tag in it \
                 computes {computed:#06x}. One character is wrong -- this is the check that \
                 exists so a mistyped destination is refused here rather than paid to an \
                 address nobody holds"
            ),
        }
    }
}

/// The destination string for `tag`: Base58 over the tag and its CRC16.
///
/// This is the form `create`, `address` and `balance` print, and the form
/// other Mochimo wallets accept.
///
/// # Errors
///
/// Returns an error if Base58 encoding fails.
pub fn tag_to_base58(tag: &Tag) -> crate::Result<String> {
    let mut payload = [0u8; ADDR_TAG_LEN + 2];
    let (body, checksum) = payload.split_at_mut(ADDR_TAG_LEN);
    body.copy_from_slice(tag);
    checksum.copy_from_slice(&crate::bytes::put16(crate::crc16::crc16(tag)));
    crate::base58::encode(&payload)
}

/// The tag inside a destination string, or why it is not one.
///
/// Total over arbitrary input: it never indexes, unwraps or panics.
///
/// The all-zero tag (`1111111111111111111111`) decodes and verifies, as in
/// the reference; `cli::args::refuse_the_zero_tag` refuses it as a payment
/// destination.
///
/// Unlike the extension's `base58ToAddrTag`, this always verifies the CRC16.
///
/// # Errors
///
/// Returns a [`NotATag`] describing why `text` is not a destination tag.
pub fn tag_from_base58(text: &str) -> core::result::Result<Tag, NotATag> {
    let chars = text.chars().count();
    if !(TAG_BASE58_MIN_CHARS..=TAG_BASE58_MAX_CHARS).contains(&chars) {
        return Err(NotATag::Length { chars });
    }
    let raw = crate::base58::decode(text).map_err(NotATag::NotBase58)?;
    let payload: [u8; ADDR_TAG_LEN + 2] = raw
        .as_slice()
        .try_into()
        .map_err(|_| NotATag::PayloadLen { got: raw.len() })?;
    let (body, checksum) = payload.split_at(ADDR_TAG_LEN);
    let tag: Tag = match body.try_into() {
        Ok(t) => t,
        Err(_) => return Err(NotATag::PayloadLen { got: raw.len() }),
    };
    let carried: [u8; 2] = match checksum.try_into() {
        Ok(c) => c,
        Err(_) => return Err(NotATag::PayloadLen { got: raw.len() }),
    };
    let found = crate::bytes::get16(&carried);
    let computed = crate::crc16::crc16(&tag);
    if found != computed {
        return Err(NotATag::Checksum { found, computed });
    }
    Ok(tag)
}
