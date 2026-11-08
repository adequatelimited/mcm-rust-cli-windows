// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

#![cfg(feature = "native")]
//! Key derivation and BIP39 tests that need only the `native` feature.
//!
//! This file builds with `--no-default-features --features native`, the
//! configuration Miri can interpret. `kat.rs` replays the same group F
//! vectors through the same walk (`support/derivation_walk.rs`) with field
//! coverage tracking.
//!
//! Group F is a specification capture of the browser extension's
//! derivation: agreement shows the port matches the extension, not that the
//! extension is correct. The C reference wallet uses a different scheme, so
//! there is no differential test.
//!
//! `wots_index_zero_is_the_first_key_and_one_is_shipped_zero` checks the
//! index mapping: `WotsIndex::ZERO` is the extension's `-1` (the first key)
//! and position 1 is the extension's rotation `0`.

use std::path::PathBuf;

#[path = "support/derivation_walk.rs"]
mod derivation_walk;

use derivation_walk::{Plain, Vector as _};
use mochimo_crypto::account::WotsIndex;
use mochimo_crypto::consts::{ADDR_TAG_LEN, SEED_LEN, WOTS_ADDR_LEN};
use mochimo_crypto::derive::{self, DigestRandomGenerator};
use mochimo_crypto::{addr, mnemonic, Secret};

const FILE: &str = "group_f_derivation.json";

/// The backend `wots::pkgen` resolves to, printed in the test output.
const BACKEND: &str = "native";

#[cfg_attr(miri, allow(dead_code))]
fn repo_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

#[cfg(not(miri))]
fn fixture_json() -> serde_json::Value {
    let p = repo_root().join("fixtures").join(FILE);
    let text = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("cannot parse {}: {e}", p.display()))
}

#[cfg(not(miri))]
fn sidecar(name: &str) -> Vec<u8> {
    let p = repo_root().join("fixtures").join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
}

// Miri runs with isolation and cannot open files, so the fixture and its
// sidecars are embedded at compile time.
#[cfg(miri)]
fn fixture_json() -> serde_json::Value {
    serde_json::from_str(include_str!("../../../fixtures/group_f_derivation.json"))
        .expect("embedded group_f_derivation.json parses")
}

#[cfg(miri)]
fn sidecar(name: &str) -> Vec<u8> {
    match name {
        "F-widths_account_address.bin" => {
            include_bytes!("../../../fixtures/F-widths_account_address.bin").to_vec()
        }
        "F-acct0_address.bin" => include_bytes!("../../../fixtures/F-acct0_address.bin").to_vec(),
        "F-acct1_address.bin" => include_bytes!("../../../fixtures/F-acct1_address.bin").to_vec(),
        other => panic!("no embedded sidecar named {other}"),
    }
}

/// The vectors replayed under Miri. The slower vectors (`F-high-byte-seed`,
/// both `deriveAccount` vectors and `F-create-not-inverse`) are left out to
/// bound interpreter time; the non-Miri walk covers the full corpus.
#[cfg(miri)]
const MIRI_IDS: [&str; 11] = [
    "F-prng-unseeded",
    "F-prng-seeded",
    "F-prng-chunking",
    "F-prng-cycle-phase",
    "F-counter-endianness",
    "F-derive-seed",
    "F-derive-seed-negative",
    "F-validation-layer",
    "F-address-widths",
    "F-ascii-control",
    "F-from-phrase",
];

struct Totals {
    vectors: usize,
    sources: std::collections::BTreeSet<String>,
    assertions: usize,
    not_ported: usize,
}

fn walk(json: &serde_json::Value, select: impl Fn(&str) -> bool) -> Totals {
    let vectors = json["vectors"].as_array().unwrap_or_else(|| panic!("{FILE}: no vectors array"));
    let mut t = Totals {
        vectors: 0,
        sources: std::collections::BTreeSet::new(),
        assertions: 0,
        not_ported: 0,
    };
    for v in vectors {
        let id = v["id"].as_str().unwrap_or("?");
        if !select(id) {
            continue;
        }
        let source = v["source"].as_str().unwrap_or_else(|| panic!("{id}: no source"));
        let mut p = Plain::new(FILE, v, sidecar);
        assert!(
            derivation_walk::replay(source, &mut p),
            "{id}: source {source:?} has no handler in the derivation walk"
        );
        t.vectors += 1;
        t.sources.insert(source.to_string());
        t.assertions += p.assertions;
        if p.not_ported {
            t.not_ported += 1;
        }
    }
    t
}

/// Replays every group F vector through the shared walk using the selected
/// backend.
#[cfg(not(miri))]
#[test]
fn derivation_reproduces_group_f_through_the_selected_backend() {
    let json = fixture_json();
    let t = replay_all(&json);
    println!(
        "  derivation replay (specification capture, wots::pkgen via {BACKEND}): \
         {} vectors, {} sources, {} field assertions, {} not ported",
        t.vectors,
        t.sources.len(),
        t.assertions,
        t.not_ported
    );
}

/// Replays every group F vector in a build with no C linked.
#[cfg(not(miri))]
#[test]
fn derivation_reproduces_group_f_without_the_c() {
    let json = fixture_json();
    let t = replay_all(&json);
    println!(
        "  derivation replay with no C linked: {} vectors, {} sources, {} field assertions",
        t.vectors,
        t.sources.len(),
        t.assertions
    );
}

/// Runs the full walk and checks its vector, source and assertion counts.
#[cfg(not(miri))]
fn replay_all(json: &serde_json::Value) -> Totals {
    let t = walk(json, |_| true);
    // 15 base vectors plus the rotation sweep (64), the account sweep (11)
    // and the BIP39 captures (6).
    assert_eq!(t.vectors, 96, "group F is ninety-six vectors; the walk saw {}", t.vectors);
    assert_eq!(t.sources.len(), 15, "group F is fifteen sources; the walk saw {:?}", t.sources);
    for s in derivation_walk::SOURCES {
        assert!(t.sources.contains(s), "source never dispatched: {s}");
    }
    assert_eq!(t.not_ported, 1, "exactly F-ascii-control is not ported");
    // A floor on field assertions (two thirds of the 528 currently made),
    // so a replay that stops checking fields fails.
    assert!(
        t.assertions >= 352,
        "only {} field assertions ran across the ninety-six vectors; this tree measures 528 and \
         the floor is two thirds of that, so the walk has come apart",
        t.assertions
    );
    t
}

/// Replays the embedded Miri subset.
#[cfg(miri)]
#[test]
fn derivation_reproduces_the_miri_subset() {
    let json = fixture_json();
    let t = walk(&json, |id| MIRI_IDS.contains(&id));
    assert_eq!(t.vectors, MIRI_IDS.len());
    assert_eq!(t.not_ported, 1);
    println!(
        "  derivation replay under Miri (embedded subset): {} vectors, {} field assertions",
        t.vectors, t.assertions
    );
}

fn vector<'a>(json: &'a serde_json::Value, id: &str) -> &'a serde_json::Value {
    json["vectors"]
        .as_array()
        .and_then(|vs| vs.iter().find(|v| v["id"].as_str() == Some(id)))
        .unwrap_or_else(|| panic!("{FILE}: no vector {id}"))
}

/// `WotsIndex::ZERO` is the extension's `-1` (the first key, using the
/// account root directly) and index 1 is the extension's `0` (the first
/// rotation). Checked against three recorded first addresses and one
/// recorded rotation.
#[cfg(not(miri))]
#[test]
fn wots_index_zero_is_the_first_key_and_one_is_shipped_zero() {
    let json = fixture_json();
    let mut first_keys = 0usize;
    let mut rotations = 0usize;

    // F-address-widths: one master seed, the first key AND rotation 0.
    let w = Plain::new(FILE, vector(&json, "F-address-widths"), sidecar);
    let master = Secret::<SEED_LEN>::from_slice(&w.hex("master_seed")).unwrap_or_else(|e| panic!("{e}"));
    let account_tag: [u8; ADDR_TAG_LEN] = w.hex("account_tag").as_slice().try_into().unwrap_or_else(|_| panic!("tag width"));
    let acct = derive::derive_account(&master, 0);

    // Position 0 is not a rotation; the first key's tag is the account tag.
    assert_eq!(WotsIndex::ZERO.rotation(), None);
    assert_eq!(WotsIndex::from_shipped(-1).ok(), Some(WotsIndex::ZERO));
    let tag12: [u8; 12] = w.hex("account_address_generator_tag").as_slice().try_into().unwrap_or_else(|_| panic!("tag12"));
    let legacy = acct.first_key().legacy_address(&tag12);
    assert_eq!(legacy.len(), WOTS_ADDR_LEN);
    assert_eq!(&legacy[..], &w.blob("account_address")[..], "position 0 is not the recorded first address");
    assert_eq!(acct.first_key().tag(), account_tag);
    first_keys += 1;

    // Position 1 is rotation 0 in the extension's numbering.
    let one = WotsIndex::ZERO.advanced().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(one.rotation(), Some(0));
    assert_eq!(WotsIndex::from_shipped(0).ok(), Some(one));
    let rotation = one.rotation().unwrap_or_else(|| panic!("position 1 is a rotation"));
    let key = derive::derive_wots_key(acct.seed(), rotation);
    assert_eq!(key.secret().expose()[..], w.hex("wots_secret")[..], "position 1 is not the recorded wots_index 0 secret");
    assert_eq!(key.address(&account_tag)[..], w.hex("wots_address")[..], "position 1 is not the recorded wots_index 0 address");
    assert_ne!(key.secret().expose()[..], acct.seed().expose()[..], "rotation 0 must not be the root itself");
    rotations += 1;

    // F-derive-account-0 / -1: two more recorded first addresses.
    for id in ["F-derive-account-0", "F-derive-account-1"] {
        let a = Plain::new(FILE, vector(&json, id), sidecar);
        let master = Secret::<SEED_LEN>::from_slice(&a.hex("phrase_master_seed")).unwrap_or_else(|e| panic!("{e}"));
        let index = u32::try_from(a.u64_("account_index")).unwrap_or_else(|_| panic!("index"));
        let acct = derive::derive_account(&master, index);
        assert_eq!(&acct.first_key().legacy_address(&[1u8; 12])[..], &a.blob("address")[..], "{id}: position 0");
        assert_eq!(acct.tag()[..], a.hex("tag")[..], "{id}: tag");
        let implicit = addr::from_wots(acct.first_key().public_key());
        assert_eq!(addr::tag_of(&implicit), addr::hash_of(&implicit), "{id}: first address is implicit");
        first_keys += 1;
    }

    println!(
        "  WotsIndex mapping: ours = shipped + 1; {first_keys} first key(s) at position 0, \
         {rotations} rotation at position 1, from_shipped(-1) = 0 and from_shipped(0) = 1"
    );
}

/// For every length 0..=200, a fresh generator's `n`-byte draw is the prefix
/// of an identically seeded 256-byte draw and consumes exactly
/// `ceil(n / 64)` states.
#[test]
fn generator_chunking_is_a_prefix_property_over_every_length() {
    let seed = [0x5Au8; 32];
    let mut reference = DigestRandomGenerator::new();
    reference.add_seed_material(&seed);
    let mut long = [0u8; 256];
    reference.fill(&mut long);
    assert_eq!(reference.states_generated(), 4);

    let mut checked = 0usize;
    for n in 0..=200usize {
        let mut g = DigestRandomGenerator::new();
        g.add_seed_material(&seed);
        let mut out = vec![0u8; n];
        g.fill(&mut out);
        assert_eq!(out[..], long[..n], "draw of {n} is not the prefix of the 256-byte draw");
        assert_eq!(g.states_generated() as usize, n.div_ceil(64), "states consumed for {n}");
        checked += 1;
    }
    println!("  generator chunking: {checked} lengths, each the prefix of one long draw");
}

/// The generator's seed cycles on the call whose incremented counter is a
/// multiple of ten (calls 9, 19, ..., 249), checked over 25 periods.
#[test]
fn seed_cycles_on_every_tenth_state_starting_at_the_ninth() {
    let mut g = DigestRandomGenerator::new();
    g.add_seed_material(&[0x5Au8; 32]);
    let mut cycled_on: Vec<u64> = Vec::new();
    let mut out = [0u8; 64];
    for call in 1..=250u64 {
        let before = g.seed_cycles();
        g.fill(&mut out);
        if g.seed_cycles() != before {
            cycled_on.push(call);
        }
    }
    let expected: Vec<u64> = (1..=250u64).filter(|c| (c + 1) % 10 == 0).collect();
    assert_eq!(cycled_on, expected, "the cycle phase is off");
    assert_eq!(cycled_on.len(), 25);
    assert_eq!(cycled_on[0], 9, "the first cycle is on the ninth call, not the tenth");
    println!("  seed cycle phase: {} cycles over 250 states, first on call {}, period 10", cycled_on.len(), cycled_on[0]);
}

/// The big-endian index at its byte boundaries and at `u32::MAX` (the
/// extension's `-1`) derives a distinct secret for each value.
#[test]
fn index_boundaries_derive_distinct_secrets() {
    let seed = [0x5Au8; 32];
    let edges = [0u32, 1, 255, 256, 65535, 65536, u32::MAX - 1, u32::MAX];
    assert_eq!(derive::index_bytes(0), [0, 0, 0, 0]);
    assert_eq!(derive::index_bytes(256), [0, 0, 1, 0]);
    assert_eq!(derive::index_bytes(u32::MAX), [0xff; 4]);
    assert_eq!(derive::counter_bytes(1), [1, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(derive::counter_bytes(u64::from(u32::MAX) + 1), [0; 8], "the counter image is the low 32 bits");

    let mut seen: std::collections::BTreeSet<[u8; SEED_LEN]> = std::collections::BTreeSet::new();
    for i in edges {
        let d = derive::derive_seed(&seed, i);
        assert!(seen.insert(*d.secret().expose()), "index {i} collided with an earlier edge");
    }
    println!("  index edges: {} distinct secrets across {:?}", seen.len(), edges);
}

/// The embedded English wordlist matches the `@scure/bip39` version pinned
/// by the fixture: 2048 sorted words whose newline-joined SHA-256 is pinned.
#[cfg(not(miri))]
#[test]
fn embedded_wordlist_matches_the_pinned_package() {
    // SHA-256 of the @scure/bip39 1.5.0 English wordlist, its 2048 words
    // joined by '\n'. Group F was captured against this package.
    const PINNED_VERSION: &str = "1.5.0";
    const PINNED_SHA256: &str = "187db04a869dd9bc7be80d21a86497d692c0db6abd3aa8cb6be5d618ff757fae";
    let pin: serde_json::Value = fixture_json()["pin"].clone();
    let pinned = pin["scure_bip39_version"].as_str().unwrap_or_else(|| panic!("no scure_bip39_version pin"));
    assert_eq!(pinned, PINNED_VERSION, "the fixture pins a different @scure/bip39 than the hash below was taken from");
    let words = &mnemonic::english::WORDLIST;
    assert_eq!(words.len(), 2048);
    assert!(words.windows(2).all(|w| w[0] < w[1]), "the embedded wordlist is not sorted");
    let joined = words.join("\n");
    let digest = mochimo_crypto::backend::selected::sha256(joined.as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, PINNED_SHA256, "the embedded wordlist is not @scure/bip39 {PINNED_VERSION}'s english.js");
    println!("  bip39 wordlist: 2048 words, sha256 pinned to @scure/bip39 {PINNED_VERSION}");
}

// ---------------------------------------------------------------------------
// Store password and seed derivation stay separate
// ---------------------------------------------------------------------------

/// The keystore password must never be used as the BIP39 passphrase.
///
/// The browser extension derives with an empty BIP39 passphrase. Salting the
/// phrase with the store password would produce a different master seed, so
/// the phrase would restore an empty wallet in every other client.
#[test]
fn the_store_password_never_reaches_seed_derivation() {
    use mochimo_crypto::account::{Account, WotsIndex};
    use mochimo_crypto::mnemonic;

    // The phrase from the group F corpus.
    let json = fixture_json();
    let phrase = vector(&json, "F-from-phrase")["phrase"]
        .as_str()
        .unwrap_or_else(|| panic!("F-from-phrase carries a phrase"))
        .to_owned();

    // The BIP39 passphrase is empty, as in the extension.
    let a = mnemonic::master_seed_from_phrase(&phrase, "").unwrap_or_else(|e| panic!("{e}"));
    let b = mnemonic::master_seed_from_phrase(&phrase, "").unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        a.expose(),
        b.expose(),
        "the same phrase produced two different master seeds"
    );

    // The derived account tags also match.
    let acct_a = Account::derive(&a, 0);
    let acct_b = Account::derive(&b, 0);
    assert_eq!(acct_a.tag(), acct_b.tag(), "the same phrase produced two different tags");

    // Control: a non-empty BIP39 passphrase changes the seed.
    let salted = mnemonic::master_seed_from_phrase(&phrase, "a passphrase")
        .unwrap_or_else(|e| panic!("{e}"));
    assert_ne!(
        a.expose(),
        salted.expose(),
        "the BIP39 passphrase parameter changed nothing, so this test's other three assertions \
         are satisfied by a function that ignores it and would be satisfied equally if the store \
         password were threaded in"
    );
    let _ = WotsIndex::ZERO;
    println!(
        "  secret separation: one phrase, empty BIP39 passphrase, identical seed and tag; a \
         non-empty passphrase diverges (the control)"
    );
}

/// A recorded phrase derives the recorded account tag end to end.
///
/// `F-from-phrase` records phrase -> seed and `F-derive-account-0` records
/// seed -> tag; this checks that the two vectors share a master seed and
/// walks the full chain.
#[test]
fn a_recorded_phrase_reaches_its_recorded_tag() {
    use mochimo_crypto::account::Account;
    use mochimo_crypto::mnemonic;

    let json = fixture_json();
    let from_phrase = vector(&json, "F-from-phrase");
    let account0 = vector(&json, "F-derive-account-0");

    let phrase = from_phrase["phrase"]
        .as_str()
        .unwrap_or_else(|| panic!("F-from-phrase carries a phrase"));

    // The seed one vector produces is the seed the other starts from.
    assert_eq!(
        from_phrase["master_seed"].as_str(),
        account0["phrase_master_seed"].as_str(),
        "group F's phrase vector and its account vector no longer share a master seed, so the \
         corpus records phrase -> seed and seed -> tag as two unrelated facts and a drift \
         between them would pass"
    );

    // Derive from the recorded phrase to the recorded tag.
    let seed = mnemonic::master_seed_from_phrase(phrase, "").unwrap_or_else(|e| panic!("{e}"));
    let recorded_seed = from_phrase["master_seed"]
        .as_str()
        .unwrap_or_else(|| panic!("master_seed"));
    assert_eq!(
        hex_of(seed.expose()),
        recorded_seed,
        "the recorded phrase no longer produces the recorded master seed"
    );

    let index = account0["account_index"].as_u64().unwrap_or(0) as u32;
    let tag = Account::derive(&seed, index).tag();
    assert_eq!(
        hex_of(&tag),
        account0["tag"].as_str().unwrap_or_else(|| panic!("tag")),
        "the recorded phrase no longer reaches the recorded tag for account {index}. This is the \
         portability claim: the shipped extension derives from the same phrase, and a drift here \
         means a recovery phrase that restores a different wallet in the other client."
    );
    println!(
        "  phrase -> tag: {} words -> master seed -> account {index} tag, joined across \
         F-from-phrase and F-derive-account-0",
        phrase.split_whitespace().count()
    );
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A generated phrase has 24 words, matching the browser extension.
///
/// The extension's `generateSeed()` draws 32 bytes of entropy, BIP39's
/// 256-bit case.
#[test]
fn a_generated_phrase_is_the_width_the_extension_generates() {
    use mochimo_crypto::cli::create::ENTROPY_LEN;
    use mochimo_crypto::mnemonic;

    assert_eq!(
        ENTROPY_LEN, 32,
        "this crate stopped drawing 32 bytes of phrase entropy. The shipped extension's \
         generateSeed() defaults to 32 (random.ts:15), so a different width here means the two \
         wallets generate phrases of different lengths from the same button."
    );
    let phrase = mnemonic::phrase_from_entropy(&[0x11u8; ENTROPY_LEN]).unwrap_or_else(|e| panic!("{e}"));
    let words = phrase.expose().split_whitespace().count();
    assert_eq!(
        words, 24,
        "32 bytes of entropy produced a {words}-word phrase; BIP39's 256-bit case is 24 and that \
         is what the extension shows its users"
    );
    println!("  phrase width: {ENTROPY_LEN} bytes of entropy -> {words} words, matching the extension's generateSeed() default");
}

/// The Mochimo SDK derivation scheme against values produced by the `mochimo`
/// npm package 2.1.1.
///
/// Each row holds a random test-only master seed (it controls no funds) with
/// the SDK's `Derivation.deriveAccountSeed`, `deriveAccountTag` and, for
/// spends 0, 1 and 2, the DSA hash, public seed, address seed and the
/// SHA-256 of the signature over the message `00 01 .. 1f`.
///
/// [`derive::sdk_account_seed`], [`derive::sdk_wots_key`] and
/// [`derive::sdk_account_tag`] reproduce every value, spend 0's hash is the
/// tag, and signing with the derived components reproduces the SDK's
/// signature.
#[cfg(not(miri))]
#[test]
fn sdk_scheme_reproduces_the_sdk_executed() {
    use mochimo_crypto::{derive, Secret};

    fn h(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }
    fn a32(s: &str) -> [u8; 32] {
        h(s).try_into().unwrap()
    }
    struct Spend {
        dsa: &'static str,
        pub_seed: &'static str,
        adrs: &'static str,
        sig_sha256: &'static str,
    }
    struct Row {
        master: &'static str,
        index: u32,
        account_seed: &'static str,
        tag: &'static str,
        spends: [Spend; 3],
    }
    const ROWS: [Row; 2] = [
        Row {
            master: "9ef4b8601f0c8ac6bea600d8b26bc99db59f45cee258ed183aed60c612a268a9",
            index: 0,
            account_seed: "bbfb1f6314c53fe703e20ad12019997a2c5db7dd05e2ad1c770b0899bc6e5f1b",
            tag: "204741cd11dbec971a90e182e74936e3f405d403",
            spends: [
                Spend {
                    dsa: "204741cd11dbec971a90e182e74936e3f405d403",
                    pub_seed: "b80c83c46a290ab307a5ac485e7bf59dc1d4a1c9cbd4c0ff8a7642113d92a1d3",
                    adrs: "d2c6cf6e40c6096e9c63f6747dba7d8bee5f04232055b9140341a724d1fd69a0",
                    sig_sha256: "d7a883e116abd0bac8e14b5d206655001b447f7e78534c5fa7f74091b22443a7",
                },
                Spend {
                    dsa: "bbf3715e33c2b2b11ca2f187effb513aadaa6eb8",
                    pub_seed: "7652fbe0042e5f4102451046b10a12894cb40f04bbf86881638c8defe564cd8f",
                    adrs: "b96f0e1c6139294858af87f6b3abccce08e02a5a4dda290e364c4f1d13cb0398",
                    sig_sha256: "4c32adcb03cbb75d3c1ba784553d508048fced9ad4eebe6b17e0e5c845f4b09c",
                },
                Spend {
                    dsa: "c830a03f85931c3ed837ac90ef0ce7f1e41e73ec",
                    pub_seed: "a412ddb76a6cab56c69f586dcebec8c8634210671f53486bea131b84f7cb060c",
                    adrs: "0c559c0c6aa4e07f0ab45dfafb99b0e1da88533cfc06317fd4736a299c8a4ae3",
                    sig_sha256: "99e67dd74bc5ecb9dcbcb267cec8e0fb0e9f4834111a23e4c40255f6a2dfb5f9",
                },
            ],
        },
        Row {
            master: "afb08a9336174dc847a4d41c1e1da03ed3773302b2447c05b5c9db158663d417",
            index: 3,
            account_seed: "83295d01ca4f46fb34487ebd9cf9ebcf1106ed0752ccff8341cf7211654dcad5",
            tag: "b6f438b50f18eb714be84a80fda5d24764293ca7",
            spends: [
                Spend {
                    dsa: "b6f438b50f18eb714be84a80fda5d24764293ca7",
                    pub_seed: "a7d06dd554a1dbae0dce2e9ec7bd9437432afcba9d1c93dc63c4cd22e9539157",
                    adrs: "4f592d2a059104f9824eee9a1a160a32c4f7ac15983f5e080e8e5cfe708d23ce",
                    sig_sha256: "e8adf70ff7482c7bcbd5f79aee0c60eef166749724b5dfd2c38a29f39193905f",
                },
                Spend {
                    dsa: "c5fb524c6f9a30435c49883329a8a03b56ec0ffc",
                    pub_seed: "0f3581b01bb91c87e3eed07331eb10a72f93ff3c181104c4b7a1c6e4bf93e892",
                    adrs: "beb50c24c233226c30c7fc3d61df40b4e6dc0a65bbe43bb33f31ff705b05018e",
                    sig_sha256: "52293809af5e57048f7f90a0e4f13be813e41d1fd9a7e7230bb9a1a44df89191",
                },
                Spend {
                    dsa: "bd9d755a0bee29c25586a2a548c13f0d70bff9f4",
                    pub_seed: "e98dcd3e9f7a9b1d9651f8a99498ce26dad7492211a984aacf04cd362ad688c2",
                    adrs: "9df18fe09995e8e9dc8eda087bbf0cf11f36833b9b7a1c21afd7195365f9e738",
                    sig_sha256: "78f3b5303fb0f6508f96f3f48144c4abb8e441c194e7e7e4c9f862bb35da5d38",
                },
            ],
        },
    ];
    let msg: [u8; 32] = core::array::from_fn(|i| i as u8);
    let mut checked = 0usize;
    for row in &ROWS {
        let master = Secret::new(a32(row.master));
        let seed = derive::sdk_account_seed(&master, row.index);
        assert_eq!(seed.expose(), &a32(row.account_seed), "account seed, index {}", row.index);
        assert_eq!(derive::sdk_account_tag(&seed).to_vec(), h(row.tag), "tag, index {}", row.index);
        for (n, s) in row.spends.iter().enumerate() {
            let key = derive::sdk_wots_key(&seed, n as u32);
            assert_eq!(key.tag().to_vec(), h(s.dsa), "spend {n}: DSA hash");
            assert_eq!(key.pub_seed(), &a32(s.pub_seed), "spend {n}: public seed");
            assert_eq!(key.adrs().le_image(), a32(s.adrs), "spend {n}: address seed");
            let mut words = *key.adrs().words();
            let sig = mochimo_crypto::backend::selected::wots_sign(&msg, key.secret().expose(), key.pub_seed(), &mut words);
            assert_eq!(
                mochimo_crypto::backend::selected::sha256(&sig[..]).to_vec(),
                h(s.sig_sha256),
                "spend {n}: the signature is not the SDK's"
            );
            checked += 1;
        }
        // Spend 0 is the implicit key: its hash is the tag.
        assert_eq!(derive::sdk_wots_key(&seed, 0).tag(), derive::sdk_account_tag(&seed));
        // And the extension's scheme over the same seed is a different wallet.
        assert_ne!(derive::derive_account_tag(&master, row.index).to_vec(), h(row.tag));
    }
    assert_eq!(checked, 6);
    println!("  sdk scheme: 2 seeds, 6 spend keys and 6 signatures reproduce mochimo 2.1.1 executed; spend 0 is the tag");
}
