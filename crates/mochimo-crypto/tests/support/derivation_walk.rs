// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! The group F replay, shared by `kat.rs` (with field coverage tracking) and
//! `derive.rs`.
//!
//! Both implement [`Vector`]: `kat.rs` over its `Ctx`, which records every
//! field read, and this file over a plain `serde_json` value ([`Plain`]).
//!
//! Group F is a specification capture of the browser extension's
//! derivation, with no second implementation. Agreement shows the port
//! matches the extension, not that the extension is correct.
//!
//! Vectors are dispatched by `source`, one handler per source, named after
//! the extension function the source cites. Where one source has vectors of
//! different shapes, the handler splits on a distinguishing key, asserts
//! every field, and asserts the vector's id matches the shape, so a vector
//! cannot pass as a smaller neighbour.

// Each consumer uses a different subset of this file.
#![allow(dead_code)]

use mochimo_crypto::consts::{ADDR_LEN, ADDR_TAG_LEN, SEED_LEN, WOTS_ADDR_LEN};
use mochimo_crypto::derive::{
    self, counter_bytes, index_bytes, DigestRandomGenerator,
};
use mochimo_crypto::{addr, mnemonic, Secret};

/// The `source` strings group F carries, verbatim from the fixture.
pub const PRNG: &str =
    "DigestRandomGenerator @ reference/mochimo-wallet/src/crypto/digestRandomGenerator.ts:21";
pub const GENERATE_STATE: &str = "DigestRandomGenerator.generateState() @ \
                                  reference/mochimo-wallet/src/crypto/digestRandomGenerator.ts:65";
pub const COUNTERS: &str = "intToBytes + DigestRandomGenerator.digestAddCounter() @ \
                            reference/mochimo-wallet/src/crypto/digestRandomGenerator.ts:3,35";
pub const DERIVE_SEED: &str =
    "Derivation.deriveSeed() @ reference/mochimo-wallet/src/redux/utils/derivation.ts:18";
pub const DERIVE_WOTS: &str = "Derivation.deriveWotsSeedAndAddress() @ \
                               reference/mochimo-wallet/src/redux/utils/derivation.ts:33";
pub const WIDTHS: &str = "Derivation.deriveWotsSeedAndAddress + MasterSeed.deriveAccount() @ \
                          reference/mochimo-wallet/src/redux/utils/derivation.ts:33, \
                          src/core/MasterSeed.ts:115";
pub const DERIVE_TAG: &str =
    "Derivation.deriveAccountTag() @ reference/mochimo-wallet/src/redux/utils/derivation.ts:6";
pub const COMPONENTS: &str =
    "WOTSWallet.componentsGenerator() @ reference/mochimo-wots/src/protocol/wallet.ts:200";
pub const FROM_PHRASE: &str =
    "MasterSeed.fromPhrase() @ reference/mochimo-wallet/src/core/MasterSeed.ts:43";
pub const TO_PHRASE: &str =
    "MasterSeed.toPhrase() @ reference/mochimo-wallet/src/core/MasterSeed.ts:72";
pub const DERIVE_ACCOUNT: &str =
    "MasterSeed.deriveAccount() @ reference/mochimo-wallet/src/core/MasterSeed.ts:115";
// The rotation sweep and BIP39 captures.
pub const ROTATION: &str = "Derivation.deriveWotsSeedAndAddress() @ \
                            reference/mochimo-wallet/src/redux/utils/derivation.ts:33 -- rotation sweep";
pub const BIP39_SEED: &str = "@scure/bip39 mnemonicToSeed() @ \
                              reference/node_modules/@scure/bip39/index.js:127 with a passphrase";
pub const BIP39_ENTROPY: &str = "@scure/bip39 entropyToMnemonic() / mnemonicToEntropy() @ \
                                 reference/node_modules/@scure/bip39/index.js:99,80 below 32 bytes";
pub const BIP39_REJECT: &str = "@scure/bip39 mnemonicToEntropy() @ \
                                reference/node_modules/@scure/bip39/index.js:80 refuses a bad checksum";

/// Every source above, for `derive.rs`'s dispatch check and count.
pub const SOURCES: [&str; 15] = [
    PRNG,
    GENERATE_STATE,
    COUNTERS,
    DERIVE_SEED,
    DERIVE_WOTS,
    WIDTHS,
    DERIVE_TAG,
    COMPONENTS,
    FROM_PHRASE,
    TO_PHRASE,
    DERIVE_ACCOUNT,
    ROTATION,
    BIP39_SEED,
    BIP39_ENTROPY,
    BIP39_REJECT,
];

/// The accessors and assertions a handler needs. `kat.rs`'s `Ctx`
/// implements it with coverage recording; [`Plain`] panics on any failure.
pub trait Vector {
    fn id(&self) -> String;
    fn has(&self, key: &str) -> bool;
    fn hex(&self, key: &str) -> Vec<u8>;
    fn str_(&self, key: &str) -> String;
    fn u64_(&self, key: &str) -> u64;
    fn ints(&self, key: &str) -> Vec<i64>;
    /// `<key>_file` loaded and checked against `<key>_len`.
    fn blob(&self, key: &str) -> Vec<u8>;
    fn eq_bytes(&mut self, key: &str, actual: &[u8]);
    fn eq_blob(&mut self, key: &str, actual: &[u8]);
    fn eq_u64(&mut self, key: &str, actual: u64);
    fn eq_i64(&mut self, key: &str, actual: i64);
    fn eq_bool(&mut self, key: &str, actual: bool);
    fn eq_str(&mut self, key: &str, actual: &str);
    fn eq_ints(&mut self, key: &str, actual: &[i64]);
    /// The vector records behaviour this crate deliberately has no code for.
    fn not_ported(&mut self);
}

fn secret(v: &dyn Vector, key: &str) -> Secret<SEED_LEN> {
    let bytes = v.hex(key);
    Secret::from_slice(&bytes).unwrap_or_else(|e| panic!("{}: `{key}` is not a 32-byte secret: {e}", v.id()))
}

fn arr<const N: usize>(v: &dyn Vector, key: &str) -> [u8; N] {
    let bytes = v.hex(key);
    bytes
        .as_slice()
        .try_into()
        .unwrap_or_else(|_| panic!("{}: `{key}` is {} bytes, expected {N}", v.id(), bytes.len()))
}

fn tag(v: &dyn Vector, key: &str) -> [u8; ADDR_TAG_LEN] {
    arr::<ADDR_TAG_LEN>(v, key)
}

fn fresh(seed_material: Option<&[u8]>) -> DigestRandomGenerator {
    let mut g = DigestRandomGenerator::new();
    if let Some(m) = seed_material {
        g.add_seed_material(m);
    }
    g
}

fn draw(g: &mut DigestRandomGenerator, n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    g.fill(&mut out);
    out
}

/// `DigestRandomGenerator`: three vectors of three shapes under one source,
/// split by key presence.
pub fn prng(v: &mut dyn Vector) {
    if v.has("next64") {
        // F-prng-chunking: independently seeded generators drawing the same
        // bytes in different chunk sizes.
        assert_eq!(v.id(), "F-prng-chunking", "the chunking shape belongs to one vector");
        let m = v.hex("seed_material");
        let mut a = fresh(Some(&m));
        let call1 = draw(&mut a, 32);
        let call2 = draw(&mut a, 32);
        let b64 = draw(&mut fresh(Some(&m)), 64);
        let c100 = draw(&mut fresh(Some(&m)), 100);
        v.eq_bytes("next32_call1", &call1);
        v.eq_bytes("next32_call2", &call2);
        v.eq_bytes("next64", &b64);
        v.eq_bytes("next100", &c100);
        // Recompute the recorded booleans from these draws: the first 32
        // bytes of a 64-byte draw equal the first 32-byte call, and the
        // second half does not equal the second call.
        v.eq_bool("next64_first32_equals_next32_call1", b64[..32] == call1[..]);
        v.eq_bool("next64_second32_equals_next32_call2", b64[32..] == call2[..]);
    } else if v.has("seed_material") {
        // F-prng-seeded: the concatenation order of addSeedMaterial.
        assert_eq!(v.id(), "F-prng-seeded", "the seeded shape belongs to one vector");
        let m = v.hex("seed_material");
        let mut g = fresh(Some(&m));
        let call1 = draw(&mut g, 32);
        let call2 = draw(&mut g, 32);
        v.eq_bytes("next32_call1", &call1);
        v.eq_bytes("next32_call2", &call2);
    } else {
        // F-prng-unseeded: zero state, zero seed, counters at 1.
        assert_eq!(v.id(), "F-prng-unseeded", "the unseeded shape belongs to one vector");
        let mut g = fresh(None);
        let out = draw(&mut g, 32);
        v.eq_bytes("next32", &out);
    }
}

/// `generateState()`'s seed-cycle phase: one-state draws, with each cycle
/// located by watching `seed_cycles()` change.
pub fn generate_state(v: &mut dyn Vector) {
    let m = v.hex("seed_material");
    let mut g = fresh(Some(&m));
    let observed = v.u64_("calls_observed");
    let mut cycled_on: Vec<i64> = Vec::new();
    let mut outs: Vec<Vec<u8>> = Vec::new();
    for call in 1..=observed {
        let before = g.seed_cycles();
        outs.push(draw(&mut g, 64));
        if g.seed_cycles() != before {
            cycled_on.push(call as i64);
        }
    }
    v.eq_u64("cycle_count", DigestRandomGenerator::CYCLE_COUNT);
    v.eq_ints("cycle_calls", &cycled_on);
    v.eq_i64("first_cycle_on_call", cycled_on.first().copied().unwrap_or(-1));
    v.eq_i64(
        "cycle_period",
        match cycled_on.as_slice() {
            [a, b, ..] => b - a,
            _ => -1,
        },
    );
    v.eq_bytes("call_8_out", &outs[7]);
    v.eq_bytes("call_9_out", &outs[8]);
    v.eq_bytes("call_10_out", &outs[9]);
}

/// The two integer encodings: 4-byte big-endian `intToBytes` and 8-byte
/// little-endian `digestAddCounter`.
pub fn counters(v: &mut dyn Vector) {
    let probes = v.ints("probe_values");
    v.eq_u64("int_to_bytes_len", 4);
    v.eq_u64("digest_add_counter_len", 8);
    for p in &probes {
        let n = u32::try_from(*p).unwrap_or_else(|_| panic!("{}: probe {p} is not a u32", v.id()));
        v.eq_bytes(&format!("int_to_bytes_{p}"), &index_bytes(n));
        v.eq_bytes(&format!("digest_add_counter_{p}"), &counter_bytes(u64::from(n)));
    }
    // `same_convention` is compared over the four value bytes, so a port
    // that used one byte order for both encodings would produce `true` and
    // fail against the recorded `false`.
    let third = probes.get(2).copied().unwrap_or(0);
    let n = u32::try_from(third).unwrap_or(0);
    v.eq_bool("same_convention", index_bytes(n)[..] == counter_bytes(u64::from(n))[..4]);
}

/// `deriveSeed`: six indices around the big-endian byte boundaries, and the
/// index `-1` (`u32::MAX`).
pub fn derive_seed(v: &mut dyn Vector) {
    let master = v.hex("master_seed");
    if v.has("index") {
        assert_eq!(v.id(), "F-derive-seed-negative", "the indexed shape belongs to one vector");
        // F-derive-seed-negative: `intToBytes(-1)` is 0xffffffff, which is
        // `u32::MAX` here. The extension's outer function refuses -1; the
        // inner one computes this value.
        v.eq_i64("index", -1);
        v.eq_bool("throws", false);
        let d = derive::derive_seed(&master, u32::MAX);
        v.eq_bytes("secret", d.secret().expose());
    } else {
        assert_eq!(v.id(), "F-derive-seed", "the six-index shape belongs to one vector");
        for i in [0u32, 1, 2, 255, 256, 65536] {
            let d = derive::derive_seed(&master, i);
            v.eq_bytes(&format!("secret_index_{i}"), d.secret().expose());
        }
    }
}

/// The extension's input validation: its outer function refuses a negative
/// index and a 19-byte tag. Here both are unrepresentable (the rotation is a
/// `u32` and the tag a `[u8; 20]`), which the function-pointer bindings below
/// enforce at compile time. The recorded error messages are asserted
/// verbatim, including the extension's double space.
pub fn derive_wots(v: &mut dyn Vector) {
    // Fails to compile if either parameter type is widened.
    let _rotation_is_u32: fn(&Secret<SEED_LEN>, u32) -> derive::WotsKey = derive::derive_wots_key;
    let _tag_is_twenty_bytes: fn(&derive::WotsKey, &[u8; ADDR_TAG_LEN]) -> [u8; ADDR_LEN] =
        derive::WotsKey::address;

    let account_seed = v.hex("account_seed");
    let account_tag = v.hex("account_tag");
    assert_eq!(account_seed.len(), SEED_LEN, "{}: account_seed width", v.id());
    assert_eq!(account_tag.len(), ADDR_TAG_LEN, "{}: account_tag width", v.id());

    v.eq_i64("wots_index_negative", -1);
    assert!(u32::try_from(-1i64).is_err(), "a negative rotation must not be a u32");
    v.eq_bool("derive_wots_negative_throws", true);
    v.eq_str("derive_wots_negative_message", "Invalid wots index");
    v.eq_bool("derive_seed_negative_throws", false);

    let short = v.hex("short_tag");
    v.eq_u64("short_tag_len", short.len() as u64);
    assert_ne!(short.len(), ADDR_TAG_LEN, "{}: the short tag is not short", v.id());
    assert!(
        <[u8; ADDR_TAG_LEN]>::try_from(short.as_slice()).is_err(),
        "a 19-byte tag must not be a Tag"
    );
    v.eq_bool("derive_wots_short_tag_throws", true);
    v.eq_str(
        "derive_wots_short_tag_message",
        "Invalid tag length, expected 20  bytes, got 19",
    );
}

/// The 40-byte v3 address of rotation 0 and the 2208-byte legacy address of
/// the first key, from one master seed. Also checks that the first key's
/// implicit tag is the account tag.
pub fn widths(v: &mut dyn Vector) {
    let master = secret(v, "master_seed");
    let account_seed = secret(v, "account_seed");
    let account_tag = tag(v, "account_tag");

    let acct = derive::derive_account(&master, 0);
    v.eq_bytes("account_seed", acct.seed().expose());
    v.eq_bytes("account_tag", &acct.tag());
    assert_eq!(derive::derive_account_tag(&master, 0), acct.tag(), "{}: two tag paths disagree", v.id());

    // Rotation 0 in the extension's numbering.
    v.eq_u64("wots_index", 0);
    let key = derive::derive_wots_key(&account_seed, 0);
    v.eq_bytes("wots_secret", key.secret().expose());
    let address = key.address(&account_tag);
    v.eq_bytes("wots_address", &address);
    v.eq_u64("wots_address_len", ADDR_LEN as u64);
    v.eq_bool("wots_address_starts_with_account_tag", address[..ADDR_TAG_LEN] == account_tag[..]);

    // The first key's 2208-byte legacy address under the hardcoded 0x01 tag.
    let tag12: [u8; 12] = arr(v, "account_address_generator_tag");
    let legacy = acct.first_key().legacy_address(&tag12);
    v.eq_blob("account_address", &legacy[..]);
    v.eq_bool("widths_differ", ADDR_LEN != WOTS_ADDR_LEN);

    // The sidecar's public key hashes to the account tag.
    let sidecar = v.blob("account_address");
    let pk: [u8; 2144] = sidecar[..2144].try_into().unwrap_or_else(|_| panic!("{}: sidecar too short", v.id()));
    let implicit = addr::from_wots(&pk);
    assert_eq!(addr::tag_of(&implicit), &account_tag[..], "{}: sidecar pk does not hash to the account tag", v.id());
    assert_eq!(addr::tag_of(&implicit), addr::hash_of(&implicit), "{}: first address is not implicit", v.id());
}

/// Derivation from a seed whose every byte is >= 0x80. The recorded
/// counters show `componentsGenerator` is not called on this path; a
/// non-zero count would mean the extension added a step this port lacks.
pub fn derive_tag(v: &mut dyn Vector) {
    let master = secret(v, "master_seed");
    let bytes = master.expose();
    v.eq_u64("master_seed_min_byte", u64::from(bytes.iter().copied().min().unwrap_or(0)));
    v.eq_bool("all_bytes_ge_0x80", bytes.iter().all(|b| *b >= 0x80));

    let acct = derive::derive_account(&master, 0);
    v.eq_bytes("account_seed", acct.seed().expose());
    v.eq_bytes("account_tag", &acct.tag());
    let key = derive::derive_wots_key(acct.seed(), 0);
    v.eq_bytes("wots_secret", key.secret().expose());
    v.eq_bytes("wots_address", &key.address(&acct.tag()));
    v.eq_u64("wots_address_len", ADDR_LEN as u64);
    v.eq_u64("components_generator_calls_derive_account_tag", 0);
    v.eq_u64("components_generator_calls_derive_wots", 0);
}

/// An unused extension code path, not ported: its lossy ASCII round trip is
/// a property of Node's `Buffer`. Asserted to stay off the live derivation
/// path, and marked not-ported.
pub fn components(v: &mut dyn Vector) {
    let calls = v.u64_("components_generator_calls_no_random_generator");
    assert!(calls >= 1, "{}: the control counter is zero; it cannot control", v.id());
    v.eq_bool("on_live_derivation_path", false);
    let probe_in = v.hex("ascii_probe_in");
    let probe_out = v.hex("ascii_probe_out");
    assert_eq!(probe_in.len(), probe_out.len(), "{}: probe widths", v.id());
    assert_ne!(probe_in, probe_out, "{}: the recorded round trip was lossless", v.id());
    v.eq_bool("ascii_roundtrip_lossless", false);
    v.not_ported();
}

/// The restore path: phrase -> entropy, phrase -> 32-byte master seed, and
/// the entropy back to the same phrase.
pub fn from_phrase(v: &mut dyn Vector) {
    let phrase = v.str_("phrase");
    v.eq_u64("word_count", phrase.split(' ').count() as u64);
    let entropy = mnemonic::entropy_from_phrase(&phrase).unwrap_or_else(|e| panic!("{}: {e}", v.id()));
    v.eq_bytes("entropy", &entropy);
    let master = mnemonic::master_seed_from_phrase(&phrase, "").unwrap_or_else(|e| panic!("{}: {e}", v.id()));
    v.eq_bytes("master_seed", master.expose());
    let back = mnemonic::phrase_from_entropy(&entropy).unwrap_or_else(|e| panic!("{}: {e}", v.id()));
    v.eq_str("roundtrip_phrase", back.expose());
    v.eq_bool("roundtrip_matches", back.expose() == phrase);
    v.eq_bool("is_live_master_seed", true);
}

/// `toPhrase` with no stored entropy uses the seed as entropy, and
/// `fromPhrase` of that phrase gives a different seed: the two are not
/// inverses. The vector records which value is the master seed.
pub fn to_phrase(v: &mut dyn Vector) {
    let constructed = secret(v, "constructed_seed");
    let phrase = mnemonic::phrase_from_seed_as_entropy(&constructed).unwrap_or_else(|e| panic!("{}: {e}", v.id()));
    v.eq_str("phrase_from_constructed", phrase.expose());
    let restored_seed =
        mnemonic::master_seed_from_phrase(phrase.expose(), "").unwrap_or_else(|e| panic!("{}: {e}", v.id()));
    let restored_entropy =
        mnemonic::entropy_from_phrase(phrase.expose()).unwrap_or_else(|e| panic!("{}: {e}", v.id()));
    v.eq_bytes("restored_seed", restored_seed.expose());
    v.eq_bytes("restored_entropy", &restored_entropy);
    v.eq_bool("restored_seed_equals_constructed", restored_seed.expose()[..] == constructed.expose()[..]);
    v.eq_bool("restored_entropy_equals_constructed", restored_entropy[..] == constructed.expose()[..]);
    v.eq_bool("is_live_master_seed", false);
}

/// From the phrase-derived master seed: tag, account seed, and the
/// 2208-byte first address under the hardcoded 0x01 tag.
pub fn derive_account(v: &mut dyn Vector) {
    let master = secret(v, "phrase_master_seed");
    let index = v.u64_("account_index");
    let index = u32::try_from(index).unwrap_or_else(|_| panic!("{}: account_index {index} is not a u32", v.id()));
    let acct = derive::derive_account(&master, index);
    v.eq_bytes("tag", &acct.tag());
    v.eq_bytes("seed", acct.seed().expose());
    let legacy = acct.first_key().legacy_address(&[1u8; 12]);
    v.eq_blob("address", &legacy[..]);
}

// --- rotation sweep and BIP39 captures ---------------------------------

/// `deriveWotsSeedAndAddress` at rotations 1..=20 and at power-of-two edges
/// up to 65536, for two accounts. The account seed and tag are also
/// re-derived from the master seed.
pub fn rotation(v: &mut dyn Vector) {
    let master = secret(v, "master_seed");
    let index = v.u64_("account_index");
    let index = u32::try_from(index).unwrap_or_else(|_| panic!("{}: account_index {index} is not a u32", v.id()));
    let acct = derive::derive_account(&master, index);
    v.eq_bytes("account_seed", acct.seed().expose());
    v.eq_bytes("account_tag", &acct.tag());

    let account_seed = secret(v, "account_seed");
    let account_tag = tag(v, "account_tag");
    let rotation = v.u64_("wots_index");
    let rotation = u32::try_from(rotation).unwrap_or_else(|_| panic!("{}: wots_index {rotation} is not a u32", v.id()));
    let key = derive::derive_wots_key(&account_seed, rotation);
    v.eq_bytes("wots_secret", key.secret().expose());
    let address = key.address(&account_tag);
    v.eq_bytes("wots_address", &address);
    v.eq_u64("wots_address_len", ADDR_LEN as u64);
    v.eq_bool("wots_address_starts_with_account_tag", address[..ADDR_TAG_LEN] == account_tag[..]);
}

/// `mnemonicToSeed` with a non-empty passphrase, from the extension's BIP39
/// library: the PBKDF2 salt is `"mnemonic" || passphrase`.
pub fn bip39_seed(v: &mut dyn Vector) {
    let phrase = v.str_("phrase");
    let passphrase = v.str_("passphrase");
    assert!(!passphrase.is_empty(), "{}: the passphrase capture carries an empty passphrase", v.id());
    let seed = mnemonic::bip39_seed(&phrase, &passphrase).unwrap_or_else(|e| panic!("{}: {e}", v.id()));
    v.eq_bytes("seed64", &seed[..]);
    v.eq_u64("seed64_len", mnemonic::BIP39_SEED_LEN as u64);
    let empty = mnemonic::bip39_seed(&phrase, "").unwrap_or_else(|e| panic!("{}: {e}", v.id()));
    v.eq_bytes("seed64_empty_passphrase", &empty[..]);
    v.eq_bool("differs", seed[..] != empty[..]);
    v.eq_bytes("master_seed_first32", &seed[..SEED_LEN]);
    // The wallet-level master seed is the first 32 bytes.
    let master =
        mnemonic::master_seed_from_phrase(&phrase, &passphrase).unwrap_or_else(|e| panic!("{}: {e}", v.id()));
    assert_eq!(
        master.expose()[..],
        seed[..SEED_LEN],
        "{}: master_seed_from_phrase disagrees with the first 32 bytes of bip39_seed",
        v.id()
    );
}

/// `entropyToMnemonic` / `mnemonicToEntropy` at 16, 20, 24 and 28 bytes:
/// the partial-byte checksum path of 12- to 21-word phrases.
pub fn bip39_entropy(v: &mut dyn Vector) {
    let entropy = v.hex("entropy");
    v.eq_u64("entropy_len", entropy.len() as u64);
    let phrase = mnemonic::phrase_from_entropy(&entropy).unwrap_or_else(|e| panic!("{}: {e}", v.id()));
    v.eq_str("phrase", phrase.expose());
    v.eq_u64("word_count", phrase.expose().split(' ').count() as u64);
    let back = mnemonic::entropy_from_phrase(phrase.expose()).unwrap_or_else(|e| panic!("{}: {e}", v.id()));
    v.eq_bytes("roundtrip_entropy", &back);
    v.eq_bool("roundtrip_matches", back[..] == entropy[..]);
    v.eq_bool("valid", true);
}

/// A phrase whose last word was replaced so its checksum no longer matches:
/// both implementations refuse it, and both say why.
pub fn bip39_reject(v: &mut dyn Vector) {
    let phrase = v.str_("phrase");
    v.eq_u64("word_count", phrase.split(' ').count() as u64);
    let result = mnemonic::entropy_from_phrase(&phrase);
    v.eq_bool("valid", result.is_ok());
    v.eq_bool("throws", result.is_err());
    let theirs = v.str_("message");
    let ours = match result {
        Err(e) => e.to_string(),
        Ok(_) => panic!("{}: this crate accepted a phrase the library refused", v.id()),
    };
    assert!(
        theirs.to_lowercase().contains("checksum") && ours.to_lowercase().contains("checksum"),
        "{}: the two refusals do not both name the checksum -- library: {theirs:?}, this crate: {ours:?}",
        v.id()
    );
}

/// Dispatch by source. Returns `false` for a source this walk does not own.
pub fn replay(source: &str, v: &mut dyn Vector) -> bool {
    match source {
        ROTATION => rotation(v),
        BIP39_SEED => bip39_seed(v),
        BIP39_ENTROPY => bip39_entropy(v),
        BIP39_REJECT => bip39_reject(v),
        PRNG => prng(v),
        GENERATE_STATE => generate_state(v),
        COUNTERS => counters(v),
        DERIVE_SEED => derive_seed(v),
        DERIVE_WOTS => derive_wots(v),
        WIDTHS => widths(v),
        DERIVE_TAG => derive_tag(v),
        COMPONENTS => components(v),
        FROM_PHRASE => from_phrase(v),
        TO_PHRASE => to_phrase(v),
        DERIVE_ACCOUNT => derive_account(v),
        _ => return false,
    }
    true
}

// --- plain implementation ---------------------------------------------

/// A vector over a bare `serde_json` object. Accessors panic on a missing
/// field, assertions panic on a mismatch naming the vector and key, and
/// assertions are counted so the caller can require a minimum.
pub struct Plain<'a> {
    pub file: &'a str,
    pub v: &'a serde_json::Value,
    pub sidecar: fn(&str) -> Vec<u8>,
    pub assertions: usize,
    pub not_ported: bool,
}

impl<'a> Plain<'a> {
    pub fn new(file: &'a str, v: &'a serde_json::Value, sidecar: fn(&str) -> Vec<u8>) -> Plain<'a> {
        Plain {
            file,
            v,
            sidecar,
            assertions: 0,
            not_ported: false,
        }
    }

    fn get(&self, key: &str) -> &'a serde_json::Value {
        self.v
            .get(key)
            .unwrap_or_else(|| panic!("{}: vector {} has no `{key}` field", self.file, self.id()))
    }

    fn hex_of(&self, key: &str) -> String {
        let bytes = self.hex(key);
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn check<T: PartialEq + std::fmt::Debug>(&mut self, key: &str, expected: T, actual: T) {
        self.assertions += 1;
        assert!(
            expected == actual,
            "{}: vector {} `{key}`\n  expected: {expected:?}\n  actual:   {actual:?}",
            self.file,
            self.id()
        );
    }
}

impl Vector for Plain<'_> {
    fn id(&self) -> String {
        self.v.get("id").and_then(|x| x.as_str()).unwrap_or("?").to_string()
    }
    fn has(&self, key: &str) -> bool {
        self.v.get(key).is_some()
    }
    fn hex(&self, key: &str) -> Vec<u8> {
        let s = self.str_(key);
        let mut out = Vec::with_capacity(s.len() / 2);
        let b = s.as_bytes();
        assert!(b.len().is_multiple_of(2), "{}: `{key}` has odd hex length", self.id());
        for pair in b.as_chunks::<2>().0 {
            let hi = (pair[0] as char).to_digit(16).unwrap_or_else(|| panic!("{}: `{key}` is not hex", self.id()));
            let lo = (pair[1] as char).to_digit(16).unwrap_or_else(|| panic!("{}: `{key}` is not hex", self.id()));
            out.push((hi * 16 + lo) as u8);
        }
        out
    }
    fn str_(&self, key: &str) -> String {
        self.get(key)
            .as_str()
            .unwrap_or_else(|| panic!("{}: `{key}` is not a string", self.id()))
            .to_string()
    }
    fn u64_(&self, key: &str) -> u64 {
        self.get(key)
            .as_u64()
            .unwrap_or_else(|| panic!("{}: `{key}` is not a u64", self.id()))
    }
    fn ints(&self, key: &str) -> Vec<i64> {
        self.get(key)
            .as_array()
            .unwrap_or_else(|| panic!("{}: `{key}` is not an array", self.id()))
            .iter()
            .map(|x| x.as_i64().unwrap_or_else(|| panic!("{}: `{key}` holds a non-integer", self.id())))
            .collect()
    }
    fn blob(&self, key: &str) -> Vec<u8> {
        let name = self.str_(&format!("{key}_file"));
        let want = self.u64_(&format!("{key}_len")) as usize;
        let bytes = (self.sidecar)(&name);
        assert_eq!(bytes.len(), want, "{}: sidecar {name} length", self.id());
        bytes
    }
    fn eq_bytes(&mut self, key: &str, actual: &[u8]) {
        let expected = self.hex_of(key);
        let actual: String = actual.iter().map(|b| format!("{b:02x}")).collect();
        self.check(key, expected, actual);
    }
    fn eq_blob(&mut self, key: &str, actual: &[u8]) {
        let expected = self.blob(key);
        self.assertions += 1;
        assert!(
            expected[..] == actual[..],
            "{}: vector {} sidecar `{key}` differs ({} vs {} bytes)",
            self.file,
            self.id(),
            expected.len(),
            actual.len()
        );
    }
    fn eq_u64(&mut self, key: &str, actual: u64) {
        let expected = self.u64_(key);
        self.check(key, expected, actual);
    }
    fn eq_i64(&mut self, key: &str, actual: i64) {
        let expected = self
            .get(key)
            .as_i64()
            .unwrap_or_else(|| panic!("{}: `{key}` is not an i64", self.id()));
        self.check(key, expected, actual);
    }
    fn eq_bool(&mut self, key: &str, actual: bool) {
        let expected = self
            .get(key)
            .as_bool()
            .unwrap_or_else(|| panic!("{}: `{key}` is not a bool", self.id()));
        self.check(key, expected, actual);
    }
    fn eq_str(&mut self, key: &str, actual: &str) {
        let expected = self.str_(key);
        self.check(key, expected, actual.to_string());
    }
    fn eq_ints(&mut self, key: &str, actual: &[i64]) {
        let expected = self.ints(key);
        self.check(key, expected, actual.to_vec());
    }
    fn not_ported(&mut self) {
        self.not_ported = true;
    }
}
