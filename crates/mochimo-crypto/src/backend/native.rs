// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! The `native` backend: WOTS+ and the address, checksum and Base58 helpers
//! in pure Rust.
//!
//! **No `unsafe`.** Memory safety is checked by running this module under
//! Miri (`invariants.rs::memory_safety_is_established_only_for_the_native_paths_miri_walks`).
//!
//! # Testing
//!
//! `tests/kat.rs` replays the group A and B fixtures against this module
//! through `backend::selected`. `tests/wots_internals.rs` holds property
//! tests the fixtures cannot cover: the two chain loops agree, the checksum
//! formula and its totality, signing counts against digits, and the digit
//! bound.
//!
//! # Hash primitive
//!
//! `sha2::Sha256`. The reference defines `core_hash(out, in, inlen)` as
//! `sha256(in, inlen, out)`.
//!
//! # Zeroization
//!
//! Every scratch buffer holding secret material is [`Zeroizing`]: `prf`'s
//! buffer (which holds the key, the private seed at `expand_seed`'s call
//! site), `thash_f`'s buffer and bitmask, and `gen_chain`'s working value.
//!
//! Not covered: `sha2::Sha256`'s internal block buffer and state, which
//! `Digest` gives no way to scrub.

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use sha3::Sha3_512;
use zeroize::Zeroizing;

use crate::consts::{
    wire, ADDR_HASH_LEN, ADDR_HASH_OFF, ADDR_LEN, ADDR_TAG_LEN, ADDR_TAG_OFF, PARAMSN, PK_LEN,
    SEED_LEN, SHA3LEN224, SHA3LEN256, SHA3LEN384, SHA3LEN512, SIG_LEN, WOTSLEN as WOTSLEN_TOTAL,
    WOTSLEN1, WOTSLEN2, WOTSLOGW, WOTSW,
};
use crate::error::Result;

/// SHA-256, the WOTS+ `core_hash`.
///
/// The reference macro is `core_hash(out, in, inlen) sha256(in, inlen, out)`;
/// note the transposed argument order. Checked against the reference's
/// digests (group HS) in `tests/kat.rs`.
#[must_use]
pub fn sha256(input: &[u8]) -> [u8; 32] {
    Sha256::digest(input).into()
}

// -------------------------------------------------------------------------
// Step 1 --- the chain function
// -------------------------------------------------------------------------

/// The XMSS hash padding domain separators.
const XMSS_HASH_PADDING_F: u64 = 0;
const XMSS_HASH_PADDING_PRF: u64 = 3;

/// Writes `out.len()` bytes of `value` in big-endian order, truncating from
/// the top when `out` is narrower than the value.
///
/// The truncation is required: `wots_checksum` writes a shifted 32-bit sum
/// into 2 bytes.
///
/// # Panics
///
/// Panics if `out` is empty.
pub fn ull_to_bytes(out: &mut [u8], value: u64) {
    assert!(
        !out.is_empty(),
        "ull_to_bytes with an empty output; see this function's doc comment for why \
         zero is refused rather than defined."
    );
    let mut v = value;
    // Decreasing, for big-endianness.
    for byte in out.iter_mut().rev() {
        *byte = (v & 0xff) as u8;
        v >>= 8;
    }
}

/// Serializes the 8 address words big-endian, in order, independent of host
/// endianness.
///
/// The transaction wire format stores the same words little-endian
/// (`put32`), so the two differ by a per-word byte reversal. Both are checked
/// against `fixtures/group_d_tx.json` and group A.
#[must_use]
pub fn addr_to_bytes(adrs: &[u32; 8]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (i, &word) in adrs.iter().enumerate() {
        ull_to_bytes(&mut bytes[i * 4..(i + 1) * 4], u64::from(word));
    }
    bytes
}

// Address word setters. Words 5, 6 and 7 are the chain index, hash index and
// key/mask selector; words 0-4 belong to the caller and are never written
// (checked by fixture `B-adrs-invariance`).
fn set_chain_addr(adrs: &mut [u32; 8], chain: u32) {
    adrs[5] = chain;
}
fn set_hash_addr(adrs: &mut [u32; 8], hash: u32) {
    adrs[6] = hash;
}
fn set_key_and_mask(adrs: &mut [u32; 8], key_and_mask: u32) {
    adrs[7] = key_and_mask;
}

/// `PRF(key, in)` = `sha256(pad(3) ‖ key ‖ in)` over 96 bytes. Infallible.
#[must_use]
pub fn prf(input: &[u8; 32], key: &[u8; SEED_LEN]) -> [u8; 32] {
    // Secret: `key` is the private seed at expand_seed's call site.
    let mut buf = Zeroizing::new([0u8; 2 * PARAMSN + 32]);
    ull_to_bytes(&mut buf[..PARAMSN], XMSS_HASH_PADDING_PRF);
    buf[PARAMSN..2 * PARAMSN].copy_from_slice(key);
    buf[2 * PARAMSN..].copy_from_slice(input);
    sha256(&buf[..])
}

/// The keyed, masked compression step.
///
/// `sha256(pad(0) ‖ PRF(pub_seed, adrs@key=0) ‖ (in ⊕ PRF(pub_seed, adrs@key=1)))`.
///
/// **`adrs` is mutated:** word 7 is set to 0 for the key and 1 for the mask,
/// and left at 1 on return, as in the reference. Callers can observe it, and
/// `wots_pkgen` output is written into transactions.
#[must_use]
pub fn thash_f(input: &[u8; 32], pub_seed: &[u8; SEED_LEN], adrs: &mut [u32; 8]) -> [u8; 32] {
    // Secret: `input` is a private chain element until the final chain step.
    let mut buf = Zeroizing::new([0u8; 3 * PARAMSN]);
    ull_to_bytes(&mut buf[..PARAMSN], XMSS_HASH_PADDING_F);

    set_key_and_mask(adrs, 0);
    let key_addr = addr_to_bytes(adrs);
    let key = prf(&key_addr, pub_seed);
    buf[PARAMSN..2 * PARAMSN].copy_from_slice(&key);

    set_key_and_mask(adrs, 1);
    let mask_addr = addr_to_bytes(adrs);
    let bitmask = Zeroizing::new(prf(&mask_addr, pub_seed));

    for i in 0..PARAMSN {
        buf[2 * PARAMSN + i] = input[i] ^ bitmask[i];
    }
    sha256(&buf[..])
}

/// `steps` applications of [`thash_f`] from chain position `start`.
///
/// Matches the reference loop
/// `for (i = start; i < (start+steps) && i < WOTSW; i++)`:
///
///   * `start + steps` wraps, as the C `unsigned int` sum does, so a `start`
///     near `u32::MAX` runs zero steps.
///   * The `i < WOTSW` guard never binds at the real call sites (every
///     `start + steps` is at most 15) but is kept for direct callers.
///   * `steps == 0` returns the input unchanged without touching `adrs`. For
///     a zero message digit this publishes a raw chain seed, which is why a
///     WOTS+ key is one-time.
#[must_use]
pub fn gen_chain(
    input: &[u8; SEED_LEN],
    start: u32,
    steps: u32,
    pub_seed: &[u8; SEED_LEN],
    adrs: &mut [u32; 8],
) -> [u8; 32] {
    // Secret until the chain reaches its public end.
    let mut out = Zeroizing::new(*input);

    let end = start.wrapping_add(steps);
    let mut i = start;
    while i < end && (i as usize) < WOTSW {
        set_hash_addr(adrs, i);
        *out = thash_f(&out, pub_seed, adrs);
        i += 1;
    }
    *out
}

/// Instrumented [`gen_chain`]: returns the chain value and the number of
/// `thash_f` applications performed.
///
/// The count lets tests check how much work each chain did, which output
/// equality alone cannot. Public (not `cfg(test)`) so integration tests in
/// `tests/` can call it.
///
/// This is a separate copy of the `gen_chain` loop so the count is
/// independent evidence of the loop bound;
/// `tests/wots_internals.rs::gen_chain_counted_walks_the_chain_gen_chain_walks`
/// checks the two loops agree.
#[must_use]
pub fn gen_chain_counted(
    input: &[u8; SEED_LEN],
    start: u32,
    steps: u32,
    pub_seed: &[u8; SEED_LEN],
    adrs: &mut [u32; 8],
) -> ([u8; 32], u32) {
    let mut out = Zeroizing::new(*input);
    let mut count = 0u32;

    let end = start.wrapping_add(steps);
    let mut i = start;
    while i < end && (i as usize) < WOTSW {
        set_hash_addr(adrs, i);
        *out = thash_f(&out, pub_seed, adrs);
        i += 1;
        count += 1;
    }
    (*out, count)
}

// -------------------------------------------------------------------------
// Step 2 --- the Winternitz ladder and checksum
// -------------------------------------------------------------------------

/// Reinterprets `input`'s nibbles as base-`WOTSW` digits, high nibble first,
/// writing `output.len()` of them.
///
/// Keeps the reference's general `bits` accumulator. The `bits == 0` branch
/// depends only on the loop index, not on the input, so it leaks no timing.
///
/// The `& (WOTSW - 1)` mask confines every digit to `0..=15`;
/// `wots_pk_from_sig` relies on this to compute `WOTSW - 1 - lengths[i]`
/// without underflow.
///
/// # Panics
///
/// Panics if `input` is shorter than `output.len().div_ceil(2)` bytes.
pub fn base_w(output: &mut [i32], input: &[u8]) {
    let needed = output.len().div_ceil(2);
    assert!(
        input.len() >= needed,
        "base_w with out_len={} needs at least {needed} input bytes, got {}",
        output.len(),
        input.len()
    );

    let mut in_idx = 0usize;
    let mut total = 0u8;
    let mut bits = 0i32;

    for slot in output.iter_mut() {
        if bits == 0 {
            total = input[in_idx];
            in_idx += 1;
            bits += 8;
        }
        bits -= WOTSLOGW as i32;
        *slot = i32::from((total >> bits) & (WOTSW as u8 - 1));
    }
}

/// The WOTS+ checksum over a base-w message, itself in base w.
///
/// `csum = Σ (WOTSW - 1 - msg[i])` over `WOTSLEN1` digits, then shifted left by
/// `8 - ((WOTSLEN2 * WOTSLOGW) % 8)` = `8 - (12 % 8)` = **4**, then serialized
/// big-endian into `(WOTSLEN2 * WOTSLOGW + 7) / 8` = **2** bytes and read back as
/// `WOTSLEN2` = 3 base-w digits.
///
/// The shift moves the 12 significant bits to the top of the 2 bytes so that
/// `base_w`, which reads high nibble first, finds them in the first three
/// nibbles.
///
/// The arithmetic wraps explicitly, so the function is total over any
/// `[i32; 64]`, not only the masked digits `chain_lengths` produces. For any
/// input the three digits are the base-16 digits of
/// `Σ (15 − d[i]) mod 4096`; the 2^32 wrap never affects them. On real
/// digits (`0..=15`) nothing wraps. Checked by
/// `tests/wots_internals.rs::wots_checksum_is_total_and_reads_the_low_twelve_bits_of_the_sum`.
#[must_use]
pub fn wots_checksum(msg_base_w: &[i32; WOTSLEN1]) -> [i32; WOTSLEN2] {
    let mut csum: i32 = 0;
    for &digit in msg_base_w.iter() {
        csum = csum.wrapping_add((WOTSW as i32 - 1).wrapping_sub(digit));
    }

    csum <<= 8 - ((WOTSLEN2 * WOTSLOGW) % 8);

    // The reference's `(WOTSLEN2 * WOTSLOGW + 7) / 8`, which is 2.
    let mut csum_bytes = [0u8; (WOTSLEN2 * WOTSLOGW).div_ceil(8)];
    ull_to_bytes(&mut csum_bytes, csum as u32 as u64);

    let mut out = [0i32; WOTSLEN2];
    base_w(&mut out, &csum_bytes);
    out
}

/// The `WOTSLEN1` message digits followed by the `WOTSLEN2` checksum digits.
///
/// The reference computes the checksum in place in one array; here the two
/// halves are separate arrays, so read and write ranges cannot overlap.
#[must_use]
pub fn chain_lengths(msg: &[u8; SEED_LEN]) -> [i32; WOTSLEN_TOTAL] {
    let mut msg_digits = [0i32; WOTSLEN1];
    base_w(&mut msg_digits, msg);
    let csum = wots_checksum(&msg_digits);

    let mut lengths = [0i32; WOTSLEN_TOTAL];
    lengths[..WOTSLEN1].copy_from_slice(&msg_digits);
    lengths[WOTSLEN1..].copy_from_slice(&csum);
    lengths
}

// -------------------------------------------------------------------------
// Step 3 --- key generation
// -------------------------------------------------------------------------

/// Compile-time check for the chunked chain loops below.
///
/// [`wots_pkgen`], [`wots_sign_counted`] and [`wots_pk_from_sig_counted`]
/// take their chain count from `as_chunks` and discard the remainder. That
/// is only correct while `PK_LEN` and `SIG_LEN` are equal whole multiples of
/// `PARAMSN`; otherwise fewer chains would run silently.
const _: () = assert!(
    PK_LEN.is_multiple_of(PARAMSN) && PK_LEN == SIG_LEN,
    "PK_LEN and SIG_LEN must be equal whole multiples of PARAMSN: the chunked \
     chain loops take their bound from the buffer and discard the remainder"
);

/// Expands an `n`-byte seed into the `WOTSLEN * PARAMSN` byte private key.
///
/// The return value is the WOTS+ private key; dropping the `Box` zeroizes it.
///
/// Moving the array out (`let key = *expand_seed(&seed)`) frees the heap
/// block without zeroizing it. Keep the `Box` and read through it.
///
/// The [`Zeroizing`] is inside the [`Box`] because `zeroize` does not
/// implement `Zeroize` for `Box<[Z; N]>`.
///
/// Chain seed `i` is `prf(i as 32-byte big-endian, inseed)`.
#[must_use]
pub fn expand_seed(inseed: &[u8; SEED_LEN]) -> Box<Zeroizing<[u8; PK_LEN]>> {
    let mut out = Box::new(Zeroizing::new([0u8; PK_LEN]));
    expand_seed_into(&mut out[..], inseed);
    out
}

/// The expansion, written into a caller-owned buffer so [`wots_pkgen`] and
/// [`wots_sign_counted`] avoid a second copy of the private key.
fn expand_seed_into(out: &mut [u8], inseed: &[u8; SEED_LEN]) {
    assert_eq!(
        out.len(),
        PK_LEN,
        "expand_seed writes WOTSLEN * PARAMSN = {PK_LEN} bytes (wots.c:130)"
    );
    let mut ctr = Zeroizing::new([0u8; 32]);
    for i in 0..WOTSLEN_TOTAL {
        ull_to_bytes(&mut ctr[..], i as u64);
        let seed = Zeroizing::new(prf(&ctr, inseed));
        out[i * PARAMSN..(i + 1) * PARAMSN].copy_from_slice(&seed[..]);
    }
}

/// Seed → private key → public key.
///
/// The private key is expanded into a [`Zeroizing`] buffer and each of the
/// 67 chains is run `WOTSW - 1` times in place; the public key is copied out
/// so the buffer that held the private key is scrubbed.
///
/// Not data-dependent: no branch or count depends on the secret.
///
/// `adrs` is mutated: word 5 ends at `WOTSLEN - 1`, words 6 and 7 at
/// `WOTSW - 2` and 1 (as fixture group A records).
#[must_use]
pub fn wots_pkgen(
    secret: &[u8; SEED_LEN],
    pub_seed: &[u8; SEED_LEN],
    adrs: &mut [u32; 8],
) -> Box<[u8; PK_LEN]> {
    // Secret until the chain loop finishes. A `Vec` because `Zeroizing`
    // supports it and not a boxed array.
    let mut buf = Zeroizing::new(vec![0u8; PK_LEN]);
    expand_seed_into(&mut buf, secret);

    // Exactly `WOTSLEN` chains, no remainder (see the const assertion).
    // Chains are updated in place in the zeroizing buffer.
    let (chains, _nothing_over) = buf.as_chunks_mut::<PARAMSN>();
    for (i, chain) in chains.iter_mut().enumerate() {
        set_chain_addr(adrs, i as u32);
        *chain = gen_chain(chain, 0, WOTSW as u32 - 1, pub_seed, adrs);
    }

    let mut pk = Box::new([0u8; PK_LEN]);
    pk.copy_from_slice(&buf[..]);
    pk
}

// -------------------------------------------------------------------------
// Step 4 --- signing
// Step 5 --- verification
// -------------------------------------------------------------------------

/// Signs a 32-byte message digest.
///
/// Each of the 67 chains is advanced `lengths[i]` times from position 0,
/// where `lengths = chain_lengths(msg)`.
///
/// # Timing
///
/// The per-chain counts depend on `msg`. Every call site signs
/// `tx_hash(TX_HASH_MESSAGE)`, which is public, so the timing variation
/// reveals nothing secret. Nothing enforces that future callers sign only
/// public messages; `docs/specification.md` lists this as a limit.
///
/// A zero digit publishes that chain's expanded private seed directly, which
/// is inherent to WOTS and why each key is one-time.
#[must_use]
pub fn wots_sign(
    msg: &[u8; SEED_LEN],
    secret: &[u8; SEED_LEN],
    pub_seed: &[u8; SEED_LEN],
    adrs: &mut [u32; 8],
) -> Box<[u8; SIG_LEN]> {
    let (sig, _) = wots_sign_counted(msg, secret, pub_seed, adrs);
    sig
}

/// [`wots_sign`] with the 67 per-chain iteration counts, which
/// `tests/wots_internals.rs::wots_sign_counted_runs_each_chain_exactly_its_digit`
/// compares against `chain_lengths(msg)`. [`wots_sign`] wraps this function.
#[must_use]
pub fn wots_sign_counted(
    msg: &[u8; SEED_LEN],
    secret: &[u8; SEED_LEN],
    pub_seed: &[u8; SEED_LEN],
    adrs: &mut [u32; 8],
) -> (Box<[u8; SIG_LEN]>, [u32; WOTSLEN_TOTAL]) {
    let lengths = chain_lengths(msg);

    let mut buf = Zeroizing::new(vec![0u8; SIG_LEN]);
    expand_seed_into(&mut buf, secret);

    let mut counts = [0u32; WOTSLEN_TOTAL];
    // Exactly `WOTSLEN` chains, no remainder. Chains are updated in place in
    // the zeroizing buffer.
    let (chains, _nothing_over) = buf.as_chunks_mut::<PARAMSN>();
    for (i, chain) in chains.iter_mut().enumerate() {
        set_chain_addr(adrs, i as u32);
        // `lengths[i]` is in 0..=15 (masked by `base_w`), so the cast cannot
        // wrap.
        let (out, n) = gen_chain_counted(chain, 0, lengths[i] as u32, pub_seed, adrs);
        *chain = out;
        counts[i] = n;
    }

    let mut sig = Box::new([0u8; SIG_LEN]);
    sig.copy_from_slice(&buf[..]);
    (sig, counts)
}

/// Recovers the public key from a signature and its message.
///
/// Chain `i` resumes at position `lengths[i]`, where signing stopped, and runs
/// the remaining `WOTSW - 1 - lengths[i]` steps. [`wots_pk_from_sig_counted`]
/// returns the per-chain bounds.
///
/// `base_w`'s mask keeps every digit at most 15, so the subtraction cannot
/// underflow. All inputs are public, so nothing here is zeroized.
#[must_use]
pub fn wots_pk_from_sig(
    sig: &[u8; SIG_LEN],
    msg: &[u8; SEED_LEN],
    pub_seed: &[u8; SEED_LEN],
    adrs: &mut [u32; 8],
) -> Box<[u8; PK_LEN]> {
    let (pk, _) = wots_pk_from_sig_counted(sig, msg, pub_seed, adrs);
    pk
}

/// [`wots_pk_from_sig`] with the per-chain `(start, count)` pairs, so tests
/// can check `start == chain_lengths(msg)[i]` and
/// `start + count == WOTSW - 1`.
#[must_use]
pub fn wots_pk_from_sig_counted(
    sig: &[u8; SIG_LEN],
    msg: &[u8; SEED_LEN],
    pub_seed: &[u8; SEED_LEN],
    adrs: &mut [u32; 8],
) -> (Box<[u8; PK_LEN]>, [(u32, u32); WOTSLEN_TOTAL]) {
    let lengths = chain_lengths(msg);

    let mut pk = Box::new([0u8; PK_LEN]);
    let mut bounds = [(0u32, 0u32); WOTSLEN_TOTAL];

    // Both splits are exact and equal in length: signature chain `i` maps to
    // public-key chain `i`.
    let (sig_chains, _sig_nothing_over) = sig.as_chunks::<PARAMSN>();
    let (pk_chains, _pk_nothing_over) = pk.as_chunks_mut::<PARAMSN>();
    for (i, (sig_chain, pk_chain)) in sig_chains.iter().zip(pk_chains).enumerate() {
        set_chain_addr(adrs, i as u32);
        let start = lengths[i] as u32;
        let steps = WOTSW as u32 - 1 - start;
        let (out, n) = gen_chain_counted(sig_chain, start, steps, pub_seed, adrs);
        *pk_chain = out;
        bounds[i] = (start, n);
    }

    (pk, bounds)
}

// -------------------------------------------------------------------------
// The address path
//
// Outside WOTS+: the two paths meet only at `addr_from_wots`, which takes a
// finished public key.
// -------------------------------------------------------------------------

/// SHA3-512 (`outlen = SHA3LEN512`).
///
/// FIPS-202 SHA3 (padding byte `0x06`), not Keccak (`0x07`), matching the
/// reference. The reference reads its state host-endian, so it is FIPS-202
/// only on little-endian hosts; this implementation is endian-independent.
#[must_use]
pub fn sha3_512(input: &[u8]) -> [u8; SHA3LEN512] {
    Sha3_512::digest(input).into()
}

/// SHA3-256 (`outlen = SHA3LEN256`, rate 136).
#[must_use]
pub fn sha3_256(input: &[u8]) -> [u8; SHA3LEN256] {
    sha3::Sha3_256::digest(input).into()
}

/// SHA3-224 (`outlen = SHA3LEN224`, rate 144). Provided with the other
/// widths for completeness; the fixtures cover all four.
#[must_use]
pub fn sha3_224(input: &[u8]) -> [u8; SHA3LEN224] {
    sha3::Sha3_224::digest(input).into()
}

/// SHA3-384 (`outlen = SHA3LEN384`, rate 104).
#[must_use]
pub fn sha3_384(input: &[u8]) -> [u8; SHA3LEN384] {
    sha3::Sha3_384::digest(input).into()
}

/// RIPEMD-160, as the ledger uses it.
#[must_use]
pub fn ripemd160(input: &[u8]) -> [u8; 20] {
    Ripemd160::digest(input).into()
}

/// `ripemd160(sha3_512(in))`.
///
/// The intermediate is a hash of a public key, so it is not zeroized.
#[must_use]
pub fn addr_hash_generate(input: &[u8]) -> [u8; ADDR_HASH_LEN] {
    ripemd160(&sha3_512(input))
}

/// Writes the 20-byte tag into both halves of the 40-byte address. An
/// implicit address is one whose hash half equals its tag.
#[must_use]
pub fn addr_from_implicit(tag: &[u8; ADDR_TAG_LEN]) -> [u8; ADDR_LEN] {
    let mut addr = [0u8; ADDR_LEN];
    addr[..ADDR_TAG_LEN].copy_from_slice(tag);
    addr[ADDR_TAG_LEN..].copy_from_slice(tag);
    addr
}

/// The legacy WOTS+ public key to a v3 hash-based address.
///
/// Hashes exactly `WOTS_PK_LEN` = 2144 bytes, not the 2208-byte pre-v3 form
/// that appended the public seed and address scheme.
#[must_use]
pub fn addr_from_wots(wots: &[u8; PK_LEN]) -> [u8; ADDR_LEN] {
    addr_from_implicit(&addr_hash_generate(wots))
}

// -------------------------------------------------------------------------
// CRC16
// -------------------------------------------------------------------------

/// The `crc16.c` table, computed from the polynomial: `0x1021`, MSB-first, no
/// reflection. Checked against the reference's recorded values by
/// `tests/kat.rs::crc16_vector` and `base58_corpus_replays`.
const CRC16_TABLE: [u16; 256] = {
    let mut table = [0u16; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = (i as u16) << 8;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

/// `crc16.c`. Init `0x0000`, no final xor, no reflection.
#[must_use]
pub fn crc16(input: &[u8]) -> u16 {
    let mut crc: u16 = 0x0000;
    for &byte in input {
        crc = (crc << 8) ^ CRC16_TABLE[usize::from((crc >> 8) as u8 ^ byte)];
    }
    crc
}

// -------------------------------------------------------------------------
// Little-endian wire accessors
// -------------------------------------------------------------------------

/// Encodes a 16-bit value little-endian.
///
/// The reference stores host-endian through a cast pointer; the fixtures
/// were generated little-endian (fixture C8: `crc16` 0xb352 stored as
/// `52b3`). Never `to_ne_bytes`, which would make output host-dependent.
#[must_use]
pub fn put16(value: u16) -> [u8; 2] {
    value.to_le_bytes()
}

/// Decodes a little-endian 16-bit value; the inverse of [`put16`].
#[must_use]
pub fn get16(bytes: &[u8; 2]) -> u16 {
    u16::from_le_bytes(*bytes)
}

/// Encodes a 32-bit value little-endian, as [`put16`] does.
///
/// Fixture group D (`identity.adrs_tail12 = "420000000e00000001000000"`)
/// rules out a big-endian version. A native-endian version is caught only by
/// `invariants.rs::no_native_endian_conversions_anywhere_in_the_crate`, since
/// a little-endian test host cannot tell the difference.
#[must_use]
pub fn put32(value: u32) -> [u8; 4] {
    value.to_le_bytes()
}

/// Decodes a little-endian 32-bit value; the inverse of [`put32`]. No fixture
/// records it.
#[must_use]
pub fn get32(bytes: &[u8; 4]) -> u32 {
    u32::from_le_bytes(*bytes)
}

/// The 22-byte tag payload: the tag, then its CRC16 through [`put16`].
///
/// Base58 itself carries no checksum, so a wrong order here would encode
/// without error.
#[must_use]
pub fn tag_with_crc16(tag: &[u8; ADDR_TAG_LEN]) -> [u8; ADDR_TAG_LEN + 2] {
    let mut out = [0u8; ADDR_TAG_LEN + 2];
    out[..ADDR_TAG_LEN].copy_from_slice(tag);
    out[ADDR_TAG_LEN..].copy_from_slice(&put16(crc16(tag)));
    out
}

// -------------------------------------------------------------------------
// Base58
// -------------------------------------------------------------------------

/// The Base58 wire alphabet.
const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// The inverse of [`BASE58_ALPHABET`], computed from it. Bytes outside the
/// alphabet (including `0`, `O`, `I` and `l`) map to `NONE`.
const BASE58_MAP: [u8; 256] = {
    const NONE: u8 = 0xff;
    let mut map = [NONE; 256];
    let mut i = 0usize;
    while i < 58 {
        map[BASE58_ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    map
};

/// Base58-encodes `input`.
///
/// Written as a plain base conversion rather than a transcription of the
/// reference. The reference's length probe reports one byte short for an
/// all-zero input (a reachable value, fixture C7); this returns the true
/// length.
///
/// # Errors
///
/// [`Error::Reference`](crate::error::Error::Reference) for empty input, as
/// the reference rejects it.
pub fn base58_encode(input: &[u8]) -> Result<String> {
    if input.is_empty() {
        return Err(crate::error::Error::Reference {
            function: "base58_encode",
            rc: -1,
        });
    }

    let zeros = input.iter().take_while(|&&b| b == 0).count();

    // Base58 digits, least-significant first.
    let mut digits: Vec<u8> = Vec::with_capacity(input.len() * 138 / 100 + 1);
    for &byte in &input[zeros..] {
        let mut carry = u32::from(byte);
        for d in &mut digits {
            carry += u32::from(*d) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    let mut out = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        out.push('1');
    }
    for &d in digits.iter().rev() {
        out.push(BASE58_ALPHABET[usize::from(d)] as char);
    }
    Ok(out)
}

/// Base58-decodes `s`.
///
/// The reference faults on a string made entirely of `'1'` characters
/// (fixture `C-base58-degenerate`); this returns *n* zero bytes for such a
/// string of length *n*, checked by `tests/kat.rs::ts_base58_decode`.
///
/// There is no checksum in Base58 itself.
///
/// # Errors
///
/// [`Error::Reference`](crate::error::Error::Reference) for the empty string
/// or any byte outside the alphabet (including bytes with the high bit set),
/// as the reference rejects them.
pub fn base58_decode(s: &[u8]) -> Result<Vec<u8>> {
    let reject = || {
        Err(crate::error::Error::Reference {
            function: "base58_decode",
            rc: -1,
        })
    };

    if s.is_empty() {
        return reject();
    }

    let zeros = s.iter().take_while(|&&c| c == b'1').count();

    // Bytes, least-significant first.
    let mut bytes: Vec<u8> = Vec::with_capacity((s.len() - zeros) * 733 / 1000 + 1);
    for &c in &s[zeros..] {
        let v = BASE58_MAP[usize::from(c)];
        if v == 0xff {
            return reject();
        }
        let mut carry = u32::from(v);
        for b in &mut bytes {
            carry += u32::from(*b) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }

    let mut out = Vec::with_capacity(zeros + bytes.len());
    out.resize(zeros, 0);
    out.extend(bytes.iter().rev());
    Ok(out)
}

/// The length [`base58_encode`] produces, matching the reference's length
/// probe.
///
/// # Errors
///
/// As [`base58_encode`].
pub fn base58_encoded_len(input: &[u8]) -> Result<usize> {
    base58_encode(input).map(|s| s.len())
}

/// The length [`base58_decode`] produces.
///
/// # Errors
///
/// As [`base58_decode`].
pub fn base58_decoded_len(s: &[u8]) -> Result<usize> {
    base58_decode(s).map(|v| v.len())
}

// --- transaction accessors -----------------------------------------------
//
// Ports of the `types.h` macros. Each is a byte read or a slice; none
// assembles a multi-byte integer, so none has a byte order.

/// `TXDAT_TYPE(options)`: the first options byte.
pub fn dat_type(options: &[u8; 4]) -> u8 {
    options[0]
}

/// `TXDSA_TYPE(options)`: the second options byte.
pub fn dsa_type(options: &[u8; 4]) -> u8 {
    options[1]
}

/// `MDST_COUNT(options)`: the third options byte, plus one.
///
/// Widened before the add, as C integer promotion does, so `0xFF` yields 256.
pub fn mdst_count(options: &[u8; 4]) -> u16 {
    u16::from(options[2]) + 1
}

/// `ADDR_TAG_PTR(ptr)`: the tag half of an address, at `ADDR_TAG_OFF`.
pub fn tag_ptr(addr: &[u8; ADDR_LEN]) -> &[u8] {
    &addr[ADDR_TAG_OFF..ADDR_TAG_OFF + ADDR_TAG_LEN]
}

/// `ADDR_HASH_PTR(ptr)`: the hash half of an address, at `ADDR_HASH_OFF`.
pub fn hash_ptr(addr: &[u8; ADDR_LEN]) -> &[u8] {
    &addr[ADDR_HASH_OFF..ADDR_HASH_OFF + ADDR_HASH_LEN]
}

/// `TXLEN_MIN`: `sizeof(TXHDR) + sizeof(MDST) + sizeof(WOTSVAL)`.
///
/// The sizes come from `crate::consts::wire` and are checked against fixture
/// group D by `tests/txwire.rs` and `tests/kat.rs`.
pub fn len_min() -> usize {
    wire::SIZEOF_TXHDR + wire::SIZEOF_MDST + wire::SIZEOF_WOTSVAL
}

/// `TXLEN_DSK_MIN`: [`len_min`] plus a trailer.
pub fn len_dsk_min() -> usize {
    len_min() + wire::SIZEOF_TXTLR
}
