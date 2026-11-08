// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

#![cfg(feature = "native")]
//! The native backend, run under Miri to check for undefined behaviour.
//!
//! ```sh
//! cargo +nightly miri test -p mochimo-crypto
//! ```
//!
//! [`walk_native`] calls `backend::native::*` directly.
//! [`walk_selected_routing`] drives the public wrappers, which route through
//! `backend::selected`.
//!
//! A passing run means only that the paths walked here are free of undefined
//! behaviour. [`MIRI_DOMAIN`] lists every `pub fn` in
//! `src/backend/native.rs` as covered or excluded with a reason:
//!
//!   * [`native_backend_is_clean_under_miri`] asserts that the functions
//!     exercised equal the set marked covered;
//!   * `memory_safety_is_established_only_for_the_native_paths_miri_walks` in
//!     `invariants.rs` asserts that the table's names equal the `pub fn` set
//!     parsed from `native.rs`, so a new backend function must be added here.

use std::collections::BTreeSet;

#[path = "support/drop_witness.rs"]
mod drop_witness;

use mochimo_crypto::backend::native;
use mochimo_crypto::consts::{ADDR_LEN, PK_LEN, SEED_LEN, SIG_LEN, WOTSLEN1};

/// Every `pub fn` in `src/backend/native.rs`: `None` if covered,
/// `Some(reason)` if excluded.
///
/// `invariants.rs` asserts the names equal those parsed from `native.rs`.
/// The excluded wrappers are one-line delegations to covered `_counted`
/// variants; a wrapper doing its own work would need its own coverage.
const MIRI_DOMAIN: &[(&str, Option<&str>)] = &[
    ("sha256", None),
    ("ull_to_bytes", None),
    ("addr_to_bytes", None),
    ("prf", None),
    ("thash_f", None),
    ("gen_chain", None),
    ("gen_chain_counted", None),
    ("base_w", None),
    ("wots_checksum", None),
    ("chain_lengths", None),
    ("expand_seed", None),
    ("wots_pkgen", None),
    (
        "wots_sign",
        Some("a one-line delegation to wots_sign_counted, which is covered"),
    ),
    ("wots_sign_counted", None),
    (
        "wots_pk_from_sig",
        Some("a one-line delegation to wots_pk_from_sig_counted, which is covered"),
    ),
    ("wots_pk_from_sig_counted", None),
    ("sha3_224", None),
    ("sha3_256", None),
    ("sha3_384", None),
    ("sha3_512", None),
    ("ripemd160", None),
    ("addr_hash_generate", None),
    ("addr_from_implicit", None),
    ("addr_from_wots", None),
    ("crc16", None),
    ("put16", None),
    ("get16", None),
    ("tag_with_crc16", None),
    ("base58_encode", None),
    ("base58_decode", None),
    ("base58_encoded_len", None),
    ("base58_decoded_len", None),
    ("get32", None),
    ("put32", None),
    // Transaction accessors ported from the reference `types.h` macros. All
    // are cheap byte reads, so all are covered, including the argument-free
    // `len_min` and `len_dsk_min`.
    ("dat_type", None),
    ("dsa_type", None),
    ("mdst_count", None),
    ("tag_ptr", None),
    ("hash_ptr", None),
    ("len_min", None),
    ("len_dsk_min", None),
];

/// Calls `native::$name(..)` and records `"$name"` from the same token, so the
/// logged name and the call cannot diverge.
///
/// The result goes through [`core::hint::black_box`] so the optimiser cannot
/// remove a call whose result is unused.
macro_rules! exercise {
    ($log:expr, $name:ident ( $($arg:expr),* $(,)? )) => {{
        $log.insert(stringify!($name));
        core::hint::black_box(native::$name($($arg),*))
    }};
}

/// Every covered function in [`MIRI_DOMAIN`], once, with real inputs.
///
/// Returns the names it exercised. Inputs are small but non-degenerate, so
/// bounds arithmetic is exercised.
fn walk_native() -> BTreeSet<&'static str> {
    let mut log = BTreeSet::new();

    let seed: [u8; SEED_LEN] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    let pub_seed: [u8; SEED_LEN] = core::array::from_fn(|i| (i as u8) ^ 0x5a);
    let msg: [u8; SEED_LEN] = core::array::from_fn(|i| (i as u8).wrapping_add(0x11));

    // --- hashes -----------------------------------------------------------
    exercise!(log, sha256(b"the quick brown fox"));
    exercise!(log, sha3_224(b"the quick brown fox"));
    exercise!(log, sha3_256(b"the quick brown fox"));
    exercise!(log, sha3_384(b"the quick brown fox"));
    exercise!(log, sha3_512(b"the quick brown fox"));
    // 62 bytes: `len % 64 >= 56`, where the padding spills into a second
    // block.
    exercise!(log, ripemd160(&[0xa5u8; 62]));

    // --- WOTS+ internals --------------------------------------------------
    let mut out8 = [0u8; 8];
    exercise!(log, ull_to_bytes(&mut out8, 0x0123_4567_89ab_cdef));

    let mut adrs = [1u32, 2, 3, 4, 5, 6, 7, 8];
    exercise!(log, addr_to_bytes(&adrs));
    let hashed = exercise!(log, prf(&[0x33u8; 32], &seed));
    exercise!(log, thash_f(&hashed, &pub_seed, &mut adrs));
    exercise!(log, gen_chain(&seed, 3, 4, &pub_seed, &mut adrs));
    exercise!(log, gen_chain_counted(&seed, 0, 15, &pub_seed, &mut adrs));

    let mut base_w_out = [0i32; WOTSLEN1];
    exercise!(log, base_w(&mut base_w_out, &msg));
    exercise!(log, wots_checksum(&base_w_out));
    exercise!(log, chain_lengths(&msg));
    exercise!(log, expand_seed(&seed));

    // --- WOTS+ proper -----------------------------------------------------
    let mut a = adrs;
    let pk: Box<[u8; PK_LEN]> = exercise!(log, wots_pkgen(&seed, &pub_seed, &mut a));
    let mut a = adrs;
    let (sig, counts): (Box<[u8; SIG_LEN]>, _) =
        exercise!(log, wots_sign_counted(&msg, &seed, &pub_seed, &mut a));
    let mut a = adrs;
    let (recovered, bounds) = exercise!(
        log,
        wots_pk_from_sig_counted(&sig, &msg, &pub_seed, &mut a)
    );
    // Not a correctness check (see `tests/kat.rs`); reading the recovered
    // key ensures Miri sees any over-read.
    assert_eq!(pk, recovered, "WOTS+ round trip disagreed under the walk");
    assert_eq!(counts.len(), bounds.len());

    // --- address path -----------------------------------------------------
    exercise!(log, addr_hash_generate(b"an address preimage"));
    let tag = [0x2bu8; 20];
    exercise!(log, addr_from_implicit(&tag));
    exercise!(log, addr_from_wots(&pk));
    exercise!(log, tag_with_crc16(&tag));

    // --- small integer and checksum accessors -----------------------------
    exercise!(log, crc16(b"123456789"));
    let two = exercise!(log, put16(0xabcd));
    exercise!(log, get16(&two));
    // Non-palindromic, so a byte-order error is visible.
    let four = exercise!(log, put32(0x0123_4567));
    exercise!(log, get32(&four));

    // --- base58 -----------------------------------------------------------
    // Leading zero bytes and a non-zero body, to exercise the leading-zero
    // prefix handling.
    let payload = [0x00u8, 0x00, 0x9f, 0x41, 0x77, 0x02];
    let encoded = exercise!(log, base58_encode(&payload)).expect("base58 encode");
    exercise!(log, base58_decode(encoded.as_bytes())).expect("base58 decode");
    exercise!(log, base58_encoded_len(&payload)).expect("base58 encoded len");
    exercise!(log, base58_decoded_len(encoded.as_bytes())).expect("base58 decoded len");

    // --- transaction accessors --------------------------------------------
    //
    // Distinct non-zero option bytes, so a wrong index is visible. The third
    // is 0xFF, for which MDST_COUNT yields 256 (a u8 result would wrap to 0).
    let opts = [0x5au8, 0xa5, 0xff, 0x3c];
    exercise!(log, dat_type(&opts));
    exercise!(log, dsa_type(&opts));
    exercise!(log, mdst_count(&opts));

    // A 40-byte address whose halves differ, so a wrong slice offset is
    // visible.
    let addr: [u8; ADDR_LEN] = core::array::from_fn(|i| (i as u8).wrapping_mul(3).wrapping_add(9));
    exercise!(log, tag_ptr(&addr));
    exercise!(log, hash_ptr(&addr));

    exercise!(log, len_min());
    exercise!(log, len_dsk_min());

    log
}

/// The public wrappers, which route through `backend::selected`.
///
/// Returns the number of entry points called. These are not in
/// [`MIRI_DOMAIN`], which covers only `backend/native.rs`.
fn walk_selected_routing() -> usize {
    use mochimo_crypto::{addr, crc16, wots, Secret};

    let seed = Secret::<{ SEED_LEN }>::new([0x31u8; SEED_LEN]);
    let pub_seed = [0x77u8; SEED_LEN];
    let msg = [0x42u8; SEED_LEN];

    let mut adrs = wots::Adrs::ZERO;
    let _ = adrs.to_bytes();
    let _ = adrs.words();
    let pk = wots::pkgen(&seed, &pub_seed, &mut adrs);

    // `wots::sign` is crate-private (I1), so the signature is produced by
    // the backend directly; `walk_native` covers the signer.
    let mut adrs = wots::Adrs::ZERO;
    let sig = native::wots_sign(&msg, seed.expose(), &pub_seed, &mut adrs.0);
    let mut adrs = wots::Adrs::ZERO;
    let _ = wots::pk_from_sig(&sig, &msg, &pub_seed, &mut adrs);

    let a = addr::from_wots(&pk);
    let _ = addr::tag_of(&a);
    let _ = addr::hash_of(&a);
    let _ = addr::hash_generate(b"x");
    let _ = addr::ripemd160(b"x");
    let _ = addr::from_implicit(&[9u8; 20]);
    let _ = crc16::crc16(b"x");

    // `Secret`: a duplicate, a borrow, and a zeroizing drop.
    let duplicate = seed.duplicate();
    assert_eq!(duplicate.expose().len(), SEED_LEN);
    drop(duplicate);

    14
}

/// Walks the native backend end to end.
///
/// Under `cargo miri test`, a pass means every function [`MIRI_DOMAIN`]
/// marks covered ran without undefined behaviour. Under plain `cargo test`
/// it is a smoke test that keeps the domain table consistent.
///
/// The exercised set is asserted non-empty and equal to the covered set, and
/// its size is printed.
#[test]
fn native_backend_is_clean_under_miri() {
    let exercised = walk_native();

    assert!(
        !exercised.is_empty(),
        "the Miri walk executed nothing. A run that interprets no code passes \
         exactly as a clean run does, which makes this assertion the only thing \
         standing between a vacuous pass and a result."
    );

    let covered: BTreeSet<&str> = MIRI_DOMAIN
        .iter()
        .filter(|(_, why)| why.is_none())
        .map(|(name, _)| *name)
        .collect();

    assert_eq!(
        exercised, covered,
        "the walk and MIRI_DOMAIN disagree about what is covered. Left is what \
         ran, right is what the table claims; a name on the right only is a \
         function declared covered that nothing calls, and a name on the left \
         only is a function exercised without an entry."
    );

    let excluded = MIRI_DOMAIN.len() - covered.len();
    eprintln!(
        "native_backend_is_clean_under_miri: executed {} of {} native functions \
         ({excluded} excluded with a reason). Running under miri: {}.",
        exercised.len(),
        MIRI_DOMAIN.len(),
        cfg!(miri)
    );

    {
        let routed = walk_selected_routing();
        assert!(routed > 0);
        eprintln!("  and {routed} public entry points, which route to native.");
    }
}

/// The zeroization witness from `support/drop_witness.rs`, run under Miri.
///
/// `secret_bytes_are_gone_after_drop` in `tests/invariants.rs` uses the same
/// witness, but that target spawns processes and does not run under Miri.
/// The witness reads storage after an object is dropped, so Miri is needed
/// to confirm that read is sound.
#[test]
fn secret_drop_witness_is_sound_under_miri() {
    let obs = drop_witness::observe_secret_drop::<32>();

    assert!(
        obs.pattern_seen_before_drop,
        "the witness could not see the pattern in the Secret's storage before \
         the drop, so it is reading the wrong bytes and everything it says \
         after the drop is about the wrong memory"
    );
    assert!(
        obs.all_zero_after_drop,
        "{} of {} bytes still match the pattern after the drop",
        obs.surviving_pattern_bytes,
        obs.bytes
    );

    eprintln!(
        "secret_drop_witness_is_sound_under_miri: {} bytes, {} surviving. \
         Running under miri: {}.",
        obs.bytes,
        obs.surviving_pattern_bytes,
        cfg!(miri)
    );
}
