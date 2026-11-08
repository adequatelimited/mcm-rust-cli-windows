// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

#![cfg(all(feature = "native", not(miri)))]
//! Property tests of the native WOTS+ internals that no fixture covers.
//!
//! The known-answer groups A, AK, B and BK check the values of key
//! generation, signing and recovery. These tests check relations and
//! properties instead:
//!
//! 1. `gen_chain_counted` is a separate copy of `gen_chain`'s loop and must
//!    agree with it.
//! 2. `wots_checksum` is `pub` over any `[i32; 64]` and uses wrapping
//!    arithmetic; fixtures only pass digits in `0..=15`.
//! 3. `wots_sign_counted` returns the 67 per-chain step counts, which
//!    signatures alone do not reveal.
//! 4. `chain_lengths` keeps every digit in `0..=15` through the mask in
//!    `base_w`.
//!
//! Inputs come from a deterministic generator with a constant seed, so
//! failures are reproducible. Expected values are computed from the
//! definitions, never through the function under test. Every test requires
//! a minimum number of inputs and prints how many it tried.
//!
//! Excluded under Miri for run time; `tests/miri.rs` covers these functions.

use std::fmt::Write as _;

use mochimo_crypto::backend::native::{
    chain_lengths, expand_seed, gen_chain, gen_chain_counted, wots_checksum, wots_sign_counted,
};
use mochimo_crypto::consts::{PARAMSN, SEED_LEN, WOTSLEN, WOTSLEN1, WOTSLEN2, WOTSLOGW, WOTSW};

/// splitmix64 under a constant seed: the same sequence on every run and
/// machine, so failing inputs are reproducible.
struct Draws(u64);

impl Draws {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    fn next_i32(&mut self) -> i32 {
        self.next_u32() as i32
    }

    fn next_bytes(&mut self) -> [u8; SEED_LEN] {
        let mut out = [0u8; SEED_LEN];
        let (words, rest) = out.as_chunks_mut::<8>();
        assert!(rest.is_empty(), "SEED_LEN is a multiple of 8");
        for word in words {
            *word = self.next_u64().to_le_bytes();
        }
        out
    }

    fn next_adrs(&mut self) -> [u32; 8] {
        let mut a = [0u32; 8];
        for w in &mut a {
            *w = self.next_u32();
        }
        a
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ---------------------------------------------------------------------------
// 1. gen_chain_counted walks the chain gen_chain walks
// ---------------------------------------------------------------------------

/// How many steps a `(start, steps)` pair performs under the loop bound
/// `for (i = start; i < start + steps && i < 16; i++)`, with the sum in
/// `u32`. A sum that wraps below `start`, or a `start` of 16 or more, runs
/// zero steps; otherwise the walk stops at the smaller of the sum and 16.
fn expected_steps(start: u32, steps: u32) -> u32 {
    let end = start.wrapping_add(steps);
    if end < start {
        0
    } else {
        end.min(WOTSW as u32).saturating_sub(start)
    }
}

#[derive(Default)]
struct ChainStats {
    pairs: usize,
    steps: u64,
    clamped: usize,
    wrapped: usize,
    copies: usize,
}

/// Runs one `(start, steps)` pair through both loops. The bytes, final
/// `adrs` and count must agree, the count must match the loop bound, zero
/// steps must return the input unchanged, and otherwise only words 6 and 7
/// of `adrs` may change.
fn check_pair(
    input: &[u8; SEED_LEN],
    pub_seed: &[u8; SEED_LEN],
    adrs0: &[u32; 8],
    start: u32,
    steps: u32,
    st: &mut ChainStats,
) {
    let mut a = *adrs0;
    let mut b = *adrs0;
    let plain = gen_chain(input, start, steps, pub_seed, &mut a);
    let (counted, n) = gen_chain_counted(input, start, steps, pub_seed, &mut b);
    let expected = expected_steps(start, steps);
    assert_eq!(
        n, expected,
        "gen_chain_counted(start={start}, steps={steps}) counted {n} step(s); the loop bound says {expected}"
    );
    assert_eq!(
        plain, counted,
        "gen_chain and gen_chain_counted disagree on the bytes at (start={start}, steps={steps}), {n} step(s)"
    );
    assert_eq!(
        a, b,
        "gen_chain and gen_chain_counted leave different adrs behind at (start={start}, steps={steps})"
    );
    if n == 0 {
        assert_eq!(plain, *input, "zero steps at (start={start}, steps={steps}) did not copy the input through");
        assert_eq!(a, *adrs0, "zero steps at (start={start}, steps={steps}) touched adrs");
        st.copies += 1;
    } else {
        assert_ne!(plain, *input, "{n} step(s) at (start={start}, steps={steps}) left the input unchanged");
        assert_eq!(
            a[6],
            start + n - 1,
            "word 6 is not the last position hashed at (start={start}, steps={steps})"
        );
        assert_eq!(a[7], 1, "word 7 is not the mask selector after a step at (start={start}, steps={steps})");
        assert_eq!(
            a[..6],
            adrs0[..6],
            "words 0 to 5 moved at (start={start}, steps={steps}); gen_chain writes words 6 and 7 alone"
        );
    }
    let end = start.wrapping_add(steps);
    if end < start {
        st.wrapped += 1;
    } else if n < steps {
        st.clamped += 1;
    }
    st.pairs += 1;
    st.steps += u64::from(n);
}

/// `gen_chain_counted` matches `gen_chain` in bytes and final `adrs`, and
/// counts the steps the loop bound predicts, for every `(start, steps)` in
/// `0..18` squared, at the edges where the `u32` sum wraps, and on random
/// `u32` pairs, over 48 seeds and addresses.
#[test]
fn gen_chain_counted_walks_the_chain_gen_chain_walks() {
    const SEEDS: usize = 48;
    const EXHAUSTIVE: u32 = 18;
    const WIDE_STARTS: [u32; 6] = [16, 17, 100, u32::MAX - 16, u32::MAX - 1, u32::MAX];
    const WIDE_STEPS: [u32; 6] = [0, 1, 2, 15, 16, u32::MAX];
    const RANDOM_PAIRS: usize = 24;

    let mut draws = Draws(0x5749_4E54_4552_4E49);
    let mut st = ChainStats::default();
    for _ in 0..SEEDS {
        let input = draws.next_bytes();
        let pub_seed = draws.next_bytes();
        let adrs0 = draws.next_adrs();
        for start in 0..EXHAUSTIVE {
            for steps in 0..EXHAUSTIVE {
                check_pair(&input, &pub_seed, &adrs0, start, steps, &mut st);
            }
        }
        for start in WIDE_STARTS {
            for steps in WIDE_STEPS {
                check_pair(&input, &pub_seed, &adrs0, start, steps, &mut st);
            }
        }
        for _ in 0..RANDOM_PAIRS {
            let (start, steps) = (draws.next_u32(), draws.next_u32());
            check_pair(&input, &pub_seed, &adrs0, start, steps, &mut st);
        }
    }

    let exhaustive = EXHAUSTIVE as usize * EXHAUSTIVE as usize;
    let wide = WIDE_STARTS.len() * WIDE_STEPS.len();
    let expected_pairs = SEEDS * (exhaustive + wide + RANDOM_PAIRS);
    assert_eq!(st.pairs, expected_pairs, "the loops did not visit every declared pair");
    assert!(st.wrapped >= SEEDS, "only {} pair(s) wrapped the u32 sum; the wide edges are not being tried", st.wrapped);
    assert!(st.clamped >= SEEDS, "only {} pair(s) were clamped at 16; the exhaustive square is not past the clamp", st.clamped);
    assert!(st.copies >= SEEDS, "only {} pair(s) copied the input through; zero steps are not being tried", st.copies);
    assert!(st.steps >= 1_000 * SEEDS as u64, "only {} step(s) walked; the exhaustive square is not walking", st.steps);
    println!(
        "gen_chain vs gen_chain_counted: {} (start, steps) pairs over {SEEDS} seeds -- {} exhaustive in \
         0..{EXHAUSTIVE} squared, {} at the wide edges, {} drawn from the whole u32 range per seed -- \
         {} steps walked by each copy, {} pairs clamped at 16, {} wrapped, {} zero-step copies; bytes, \
         adrs and count equal on every pair",
        st.pairs, exhaustive, wide, RANDOM_PAIRS, st.steps, st.clamped, st.wrapped, st.copies
    );
}

// ---------------------------------------------------------------------------
// 2. wots_checksum is total and reads the low twelve bits of the sum
// ---------------------------------------------------------------------------

/// The shift `wots_checksum` applies: `8 - ((len2 * log2(w)) mod 8)`, which
/// is 4, and the width of the sum that reaches the digits: `len2 * log2(w)`
/// bits, which is 12.
const SHIFT: u32 = (8 - (WOTSLEN2 * WOTSLOGW) % 8) as u32;
const SUM_BITS: u32 = (WOTSLEN2 * WOTSLOGW) as u32;

/// The three checksum digits computed with explicit wrapping `i32`
/// arithmetic and nibble masks, without the function's own helpers
/// (`base_w`, `ull_to_bytes`): a wrapping shift, the low 16 bits, and their
/// top three nibbles.
fn checksum_by_wrapping_i32(digits: &[i32; WOTSLEN1]) -> [i32; WOTSLEN2] {
    let mut sum: i32 = 0;
    for &d in digits {
        sum = sum.wrapping_add((WOTSW as i32 - 1).wrapping_sub(d));
    }
    let shifted = sum.wrapping_mul(1 << SHIFT);
    let low16 = (shifted as u32) & 0xFFFF;
    [((low16 >> 12) & 0xF) as i32, ((low16 >> 8) & 0xF) as i32, ((low16 >> 4) & 0xF) as i32]
}

/// The same three digits over the integers: the sum in `i64` (64 terms
/// below 2^32 cannot overflow), reduced modulo 2^12, in base 16.
fn checksum_over_the_integers(digits: &[i32; WOTSLEN1]) -> [i32; WOTSLEN2] {
    let sum: i64 = digits.iter().map(|&d| i64::from(WOTSW as i32 - 1) - i64::from(d)).sum();
    let m = sum.rem_euclid(1 << SUM_BITS);
    [((m >> 8) & 0xF) as i32, ((m >> 4) & 0xF) as i32, (m & 0xF) as i32]
}

/// The same digits with a wrapping `u32` accumulator, showing the
/// accumulator's type does not affect the result.
fn checksum_by_wrapping_u32(digits: &[i32; WOTSLEN1]) -> [i32; WOTSLEN2] {
    let mut sum: u32 = 0;
    for &d in digits {
        sum = sum.wrapping_add((WOTSW as u32 - 1).wrapping_sub(d as u32));
    }
    let low16 = sum.wrapping_mul(1 << SHIFT) & 0xFFFF;
    [((low16 >> 12) & 0xF) as i32, ((low16 >> 8) & 0xF) as i32, ((low16 >> 4) & 0xF) as i32]
}

/// Whether checked `i32` arithmetic would overflow on this input in the sum
/// or the shift.
fn checked_arithmetic_fails(digits: &[i32; WOTSLEN1]) -> bool {
    let mut sum: Option<i32> = Some(0);
    for &d in digits {
        sum = sum.and_then(|s| (WOTSW as i32 - 1).checked_sub(d).and_then(|t| s.checked_add(t)));
    }
    sum.and_then(|s| s.checked_mul(1 << SHIFT)).is_none()
}

/// `wots_checksum` is total over `[i32; 64]`, and on every input its three
/// digits are the base-16 digits of `Σ (15 − d[i]) mod 4096` over the
/// integers. Checked against wrapping `i32`, exact `i64` and wrapping `u32`
/// computations.
#[test]
fn wots_checksum_is_total_and_reads_the_low_twelve_bits_of_the_sum() {
    const DRAWN_FULL_RANGE: usize = 12_000;
    const DRAWN_NEAR_ZERO: usize = 4_000;
    const DRAWN_IN_DOMAIN: usize = 4_000;

    assert_eq!(SHIFT, 4, "the shift moved; the formula below is written for 4");
    assert_eq!(SUM_BITS, 12, "the digit width moved; the formula below is written for 12");
    // `15 - d` overflows `i32` exactly when `d < i32::MIN + 16`.
    for d in [i32::MIN, i32::MIN + 15] {
        assert!((WOTSW as i32 - 1).checked_sub(d).is_none(), "15 - {d} did not overflow i32");
    }
    for d in [i32::MIN + 16, -1, 0, 15, 16, i32::MAX] {
        assert!((WOTSW as i32 - 1).checked_sub(d).is_some(), "15 - {d} overflowed i32");
    }

    let mut inputs: Vec<[i32; WOTSLEN1]> = vec![
        [0; WOTSLEN1],
        [WOTSW as i32 - 1; WOTSLEN1],
        [WOTSW as i32; WOTSLEN1],
        [-1; WOTSLEN1],
        [i32::MAX; WOTSLEN1],
        [i32::MIN; WOTSLEN1],
        [i32::MIN + 15; WOTSLEN1],
        [i32::MIN + 16; WOTSLEN1],
    ];
    let mut alternating = [i32::MAX; WOTSLEN1];
    for d in alternating.iter_mut().skip(1).step_by(2) {
        *d = i32::MIN;
    }
    inputs.push(alternating);
    let mut one_low = [WOTSW as i32 - 1; WOTSLEN1];
    one_low[WOTSLEN1 - 1] = i32::MIN;
    inputs.push(one_low);
    let structured = inputs.len();

    let mut draws = Draws(0x4348_4543_4B53_554D);
    for _ in 0..DRAWN_FULL_RANGE {
        let mut d = [0i32; WOTSLEN1];
        for x in &mut d {
            *x = draws.next_i32();
        }
        inputs.push(d);
    }
    for _ in 0..DRAWN_NEAR_ZERO {
        let mut d = [0i32; WOTSLEN1];
        for x in &mut d {
            *x = (draws.next_u32() % 201) as i32 - 100;
        }
        inputs.push(d);
    }
    for _ in 0..DRAWN_IN_DOMAIN {
        let mut d = [0i32; WOTSLEN1];
        for x in &mut d {
            *x = (draws.next_u32() % WOTSW as u32) as i32;
        }
        inputs.push(d);
    }

    let (mut in_domain, mut out_of_domain, mut would_panic) = (0usize, 0usize, 0usize);
    for d in &inputs {
        let out = wots_checksum(d);
        assert_eq!(out, checksum_by_wrapping_i32(d), "wrapping i32 formula disagrees on {d:?}");
        assert_eq!(out, checksum_over_the_integers(d), "exact integer formula disagrees on {d:?}");
        assert_eq!(out, checksum_by_wrapping_u32(d), "u32 accumulator disagrees on {d:?}");
        for (i, &x) in out.iter().enumerate() {
            assert!((0..WOTSW as i32).contains(&x), "checksum digit {i} is {x} on {d:?}");
        }
        if d.iter().all(|&x| (0..WOTSW as i32).contains(&x)) {
            in_domain += 1;
        } else {
            out_of_domain += 1;
        }
        if checked_arithmetic_fails(d) {
            would_panic += 1;
        }
    }
    let total = inputs.len();
    assert_eq!(total, structured + DRAWN_FULL_RANGE + DRAWN_NEAR_ZERO + DRAWN_IN_DOMAIN);
    assert!(in_domain >= DRAWN_IN_DOMAIN, "only {in_domain} in-domain input(s); the reachable domain is not being tried");
    assert!(out_of_domain >= DRAWN_FULL_RANGE, "only {out_of_domain} out-of-domain input(s); the wrap is not being reached");
    assert!(
        would_panic >= DRAWN_FULL_RANGE / 2,
        "only {would_panic} input(s) would panic under checked arithmetic; the wrap is not being exercised"
    );
    println!(
        "wots_checksum: {total} inputs ({structured} structured, {DRAWN_FULL_RANGE} drawn from the whole i32 \
         range, {DRAWN_NEAR_ZERO} within 100 of zero, {DRAWN_IN_DOMAIN} in 0..=15) -- {in_domain} in the \
         reachable domain, {out_of_domain} outside it, {would_panic} on which checked arithmetic would \
         have panicked; on every one the three digits are the base-16 digits of the integer sum mod 4096, \
         by wrapping i32, by exact i64 and by wrapping u32 alike"
    );
}

// ---------------------------------------------------------------------------
// 3. wots_sign_counted runs each chain exactly its digit
// ---------------------------------------------------------------------------

/// The five message digests whose digit tables the specification prints,
/// plus three that put every chain at one end or the other.
fn curated_messages() -> Vec<[u8; SEED_LEN]> {
    let mut ordered = [0u8; SEED_LEN];
    for (i, b) in ordered.iter_mut().enumerate() {
        *b = i as u8;
    }
    let mut last_bit = [0u8; SEED_LEN];
    last_bit[SEED_LEN - 1] = 1;
    let mut first_bit = [0u8; SEED_LEN];
    first_bit[0] = 0x80;
    vec![[0u8; SEED_LEN], [0xff; SEED_LEN], ordered, last_bit, first_bit, [0x0f; SEED_LEN], [0xf0; SEED_LEN], [0x10; SEED_LEN]]
}

/// `wots_sign_counted`'s 67 counts equal `chain_lengths(msg)` chain by
/// chain, a chain with digit 0 outputs its expanded seed unchanged and any
/// other digit does not, and word 5 ends at 66 because the chain index is set
/// on every iteration.
#[test]
fn wots_sign_counted_runs_each_chain_exactly_its_digit() {
    const MESSAGES: usize = 320;

    let curated = curated_messages();
    let mut draws = Draws(0x5349_474E_434F_554E);
    let mut messages: Vec<[u8; SEED_LEN]> = curated.clone();
    while messages.len() < MESSAGES {
        messages.push(draws.next_bytes());
    }

    let (mut chains, mut steps, mut zero_digit, mut full) = (0usize, 0u64, 0usize, 0usize);
    for msg in &messages {
        let secret = draws.next_bytes();
        let pub_seed = draws.next_bytes();
        let mut adrs = draws.next_adrs();
        let lengths = chain_lengths(msg);
        let expanded = expand_seed(&secret);
        let (sig, counts) = wots_sign_counted(msg, &secret, &pub_seed, &mut adrs);
        for (i, (&count, &digit)) in counts.iter().zip(lengths.iter()).enumerate() {
            assert_eq!(
                count,
                digit as u32,
                "message {}: chain {i} ran {count} step(s) for digit {digit}",
                hex(msg)
            );
            let block = &sig[i * PARAMSN..(i + 1) * PARAMSN];
            let seed = &expanded[i * PARAMSN..(i + 1) * PARAMSN];
            if digit == 0 {
                assert_eq!(block, seed, "message {}: chain {i} has digit 0 and its block is not the expanded seed", hex(msg));
                zero_digit += 1;
            } else {
                assert_ne!(block, seed, "message {}: chain {i} has digit {digit} and its block is the raw seed", hex(msg));
            }
            if digit == WOTSW as i32 - 1 {
                full += 1;
            }
            steps += u64::from(count);
            chains += 1;
        }
        assert_eq!(adrs[5], WOTSLEN as u32 - 1, "message {}: word 5 did not end at the last chain", hex(msg));
    }
    assert_eq!(messages.len(), MESSAGES);
    assert_eq!(chains, MESSAGES * WOTSLEN);
    assert!(zero_digit >= WOTSLEN1, "only {zero_digit} chain(s) had digit 0; the all-zero message alone gives 64");
    assert!(full >= WOTSLEN1, "only {full} chain(s) had digit 15; the all-ones message alone gives 64");
    println!(
        "wots_sign_counted vs chain_lengths: {MESSAGES} messages ({} curated, {} drawn), {chains} chains, \
         {steps} steps, every count equal to its digit; {zero_digit} chains with digit 0 published their \
         expanded seed unchanged, {full} ran the full 15",
        curated.len(),
        MESSAGES - curated.len()
    );
}

// ---------------------------------------------------------------------------
// 4. chain_lengths never yields a digit outside the base
// ---------------------------------------------------------------------------

/// `chain_lengths` never yields a digit outside `0..=15`. Over every
/// single-byte fill, every one-bit message, the five tables in the
/// specification, and 200,000 random messages: all 67 digits are in range,
/// the first 64 are the message's nibbles high first, and the last three
/// are the base-16 digits of `Σ (15 − m[i])`, which lies in `0..=960`.
#[test]
fn chain_lengths_never_yields_a_digit_outside_the_base() {
    const DRAWN: usize = 200_000;
    const TABLES: [([u8; SEED_LEN], [i32; WOTSLEN2]); 5] = {
        let mut ordered = [0u8; SEED_LEN];
        let mut i = 0;
        while i < SEED_LEN {
            ordered[i] = i as u8;
            i += 1;
        }
        let mut last_bit = [0u8; SEED_LEN];
        last_bit[SEED_LEN - 1] = 1;
        let mut first_bit = [0u8; SEED_LEN];
        first_bit[0] = 0x80;
        [
            ([0u8; SEED_LEN], [3, 12, 0]),
            ([0xff; SEED_LEN], [0, 0, 0]),
            (ordered, [2, 12, 0]),
            (last_bit, [3, 11, 15]),
            (first_bit, [3, 11, 8]),
        ]
    };

    let mut messages: Vec<([u8; SEED_LEN], Option<[i32; WOTSLEN2]>)> = Vec::with_capacity(DRAWN + 600);
    for b in 0..=u8::MAX {
        messages.push(([b; SEED_LEN], None));
    }
    let fills = messages.len();
    for bit in 0..SEED_LEN * 8 {
        let mut m = [0u8; SEED_LEN];
        m[bit / 8] |= 1 << (7 - bit % 8);
        messages.push((m, None));
    }
    let one_bit = messages.len() - fills;
    for (m, digits) in TABLES {
        messages.push((m, Some(digits)));
    }
    let mut draws = Draws(0x4348_4149_4E4C_454E);
    for _ in 0..DRAWN {
        messages.push((draws.next_bytes(), None));
    }

    let (mut checked, mut digits_seen, mut fifteens) = (0usize, 0usize, 0usize);
    let (mut min_digit, mut max_digit) = (i32::MAX, i32::MIN);
    for (msg, table) in &messages {
        let l = chain_lengths(msg);
        for (i, &d) in l.iter().enumerate() {
            assert!((0..WOTSW as i32).contains(&d), "message {}: digit {i} is {d}, outside 0..=15", hex(msg));
            min_digit = min_digit.min(d);
            max_digit = max_digit.max(d);
            if d == WOTSW as i32 - 1 {
                fifteens += 1;
            }
            digits_seen += 1;
        }
        for (i, &d) in l[..WOTSLEN1].iter().enumerate() {
            let byte = msg[i / 2];
            let nibble = if i % 2 == 0 { byte >> 4 } else { byte & 0xF };
            assert_eq!(d, i32::from(nibble), "message {}: digit {i} is not the nibble, high first", hex(msg));
        }
        let sum: i32 = l[..WOTSLEN1].iter().map(|&d| WOTSW as i32 - 1 - d).sum();
        assert!((0..=960).contains(&sum), "message {}: the sum {sum} is outside 0..=960", hex(msg));
        let expected = [(sum >> 8) & 0xF, (sum >> 4) & 0xF, sum & 0xF];
        assert_eq!(&l[WOTSLEN1..], &expected, "message {}: the checksum digits are not the sum's base-16 digits", hex(msg));
        if let Some(t) = table {
            assert_eq!(&l[WOTSLEN1..], t, "message {}: the specification's table says {t:?}", hex(msg));
        }
        checked += 1;
    }
    assert_eq!(checked, fills + one_bit + TABLES.len() + DRAWN);
    assert_eq!(digits_seen, checked * WOTSLEN);
    assert_eq!((min_digit, max_digit), (0, WOTSW as i32 - 1), "the digits did not span the base");
    println!(
        "chain_lengths: {checked} messages ({fills} single-byte fills, {one_bit} one-bit messages, {} tables \
         from the specification, {DRAWN} drawn), {digits_seen} digits examined, every one in 0..=15 (min \
         {min_digit}, max {max_digit}), {fifteens} digits of 15; the first 64 are the message's nibbles \
         high first and the last three the base-16 digits of the sum on every message",
        TABLES.len()
    );
}
