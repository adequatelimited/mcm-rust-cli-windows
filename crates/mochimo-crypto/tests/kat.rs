// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

// Not under Miri: every test reads `fixtures/` through `std::fs`, which
// Miri's isolation refuses, and replaying the corpus under the interpreter
// would take days.
#![cfg(all(feature = "native", not(miri)))]
//! Known-answer replay of the corpus in `fixtures/`.
//!
//! The fixtures are the specification: every vector was produced by an
//! implementation other than this crate. Each vector is dispatched on its
//! `source` string to a handler that recomputes the answer natively and
//! compares.
//!
//! This crate has no transaction validator (acceptance is the node's), so
//! group D's validator verdicts are not recomputed:
//! `reference_verdicts_native` round-trips every group D wire image through
//! the native serializer, checks the recorded layout, and marks the verdicts
//! as not called.
//!
//! # Dispatch
//!
//! Vectors are dispatched on their `source` field, which names the reference
//! function and `file:line` that produced them, not on their `id`. An
//! unregistered `source` is a hard failure, not a skip, so every vector runs.

mod support;

/// Group F's replay, shared with `tests/derive.rs`'s C-free proof.
/// Gated on `native` because the derivation is; see the arms in `replay`.
#[cfg(feature = "native")]
#[path = "support/derivation_walk.rs"]
mod derivation_walk;
#[path = "support/mesh_walk.rs"]
mod mesh_walk;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use mochimo_crypto::consts::{PK_LEN, SEED_LEN, SIG_LEN};
// The raw WOTS+ functions (`wots_sign`, `prf`, `thash_f`, `expand_seed`,
// `chain_lengths`) are reached through `backend::selected` under the
// `raw-backend` feature. `wots::sign` and `wots::internals` are
// crate-private, so no dependent can call a raw signer (I1).
use mochimo_crypto::backend::selected as raw;
use mochimo_crypto::wots::Adrs;
use mochimo_crypto::{addr, base58, bytes, crc16, tx, wots, Secret};

use support::{Ctx, Disposition, Fixture};

// =======================================================================
// Vector classifications
// =======================================================================

/// Vectors whose replay reconstructs an input instead of reading it from a
/// field. Empty: every input is recorded, and
/// `no_input_is_reconstructed_from_prose` keeps it so.
const DERIVED_INPUT_IDS: &[&str] = &[];

/// Vectors for which the reference is deliberately not invoked; each fixture
/// records why.
///
/// `C11-C7` and `C-base58-degenerate`, and their `CX-` crosscheck
/// counterparts, are all-'1' Base58 strings, which make the reference's
/// `base58_decode` compute a negative copy length and call `memcpy` with
/// `SIZE_MAX`. (`C12b-1..3` also reject, but the reference was called and
/// returned -1, so they carry a real comparison.)
///
/// `F-ascii-control` has no port: it covers
/// `WOTSWallet.componentsGenerator`'s ASCII round-trip, reachable only when
/// `WOTSWallet.create` is given no random generator, which no live caller
/// does. It is the control for `F-high-byte-seed`'s zero call counts; the
/// handler reads every field and checks that the path stays unreached.
const NOT_CALLED_IDS: &[&str] = &[
    "C11-C7",
    "C-base58-degenerate",
    "CX-C11-C7",
    "CX-C-base58-degenerate",
    "F-ascii-control",
];

/// Vectors whose assertions cannot tell a correct replay from an incorrect
/// one, because every pinned value is independent of a guessed input. Listed
/// so the count is reported.
const WEAKLY_CHECKED_IDS: &[&str] = &[];

/// Definitions checked against the reference less strictly than everything
/// else, with the reason for each. Listed so the weaker standard appears in
/// every run's output.
const WEAKLY_ANCHORED: &[(&str, &str)] = &[(
    "mochimo_crypto::net::valid_op",
    "restated in Rust rather than read from an oracle: valid_op is a \
     function-like macro inside the reference's network.c, so no header \
     declares it and no fixture group carries its answers. Admissible only \
     because it is a predicate over constants — FIRST_OP and LAST_OP are \
     declared in lib.rs as literals read from the reference and compared \
     against group E's recorded constants by \
     group_e_constants_match_the_reference, and tests/net.rs enumerates the \
     whole input domain against those bounds rather than against literals. A \
     deliberate single exception, not precedent; net.rs's module doc carries the \
     argument and the specification's Open items records the transcription.",
)];

// =======================================================================
// Dispatch
// =======================================================================

/// The corpus total, written independently of the per-file counts that
/// `manifest_counts_match_the_files` sums and compares against it.
const TOTAL_P14: usize = 5386;

/// Group V's source string.
const V_POS_TX: &str = "wallet_tx_vectors.c over mochimo-pos tx_read/tx_hash/wots_sign";

const S_STAKE_TX: &str = "stake-tx.mjs (mochimo-pos-tx-tools) CLI over a throwaway SDK master seed";

/// The bulk corpus's source strings, verbatim from the fixtures. The census
/// and the dispatch share these constants, so a source missing from either
/// fails rather than being skipped.
const AK_PKGEN: &str = "wots_pkgen -> sha256 + addr_from_wots() @ \
reference/mochimo-core/src/wots.c:229, include/crypto-c/src/sha256.c, src/ledger.c:109";
const AK_EXPAND_SEED: &str =
    "expand_seed -> sha256() @ reference/mochimo-core/src/wots.c:125, include/crypto-c/src/sha256.c";
const AK_PRF: &str = "prf() @ reference/mochimo-core/src/wots.c:78";
const AK_THASH_F: &str = "thash_f() @ reference/mochimo-core/src/wots.c:93";
const AK_GEN_CHAIN: &str = "gen_chain() @ reference/mochimo-core/src/wots.c:144";
const BK_SIGN: &str = "wots_sign + wots_pk_from_sig -> sha256() @ \
reference/mochimo-core/src/wots.c:255,284, include/crypto-c/src/sha256.c";
const BK_CHAIN_LENGTHS: &str = "chain_lengths() @ reference/mochimo-core/src/wots.c:212";
const HS_SHA256: &str = "sha256() @ reference/mochimo-core/include/crypto-c/src/sha256.c";
const HS_SHA3: &str = "sha3() @ reference/mochimo-core/include/crypto-c/src/sha3.c";
const HS_RIPEMD160: &str = "ripemd160() @ reference/mochimo-core/include/crypto-c/src/ripemd160.c";
const AKX_PKGEN: &str = "WOTS.wots_pkgen() @ reference/mochimo-wots/src/protocol/wots.ts:120 -> \
WotsAddress.addrFromWots() @ reference/mochimo-wots/src/protocol/wots-addr.ts:116 + \
MochimoHasher.hashWith(\"sha256\") @ reference/mochimo-wots/src/hasher/mochimo-hasher.ts:75";
const CK_TAG: &str =
    "TagUtils.addrTagToBase58() @ reference/mochimo-wots/src/utils/tag-utils.ts:4 over crc16_base58_corpus";

fn replay(ctx: &mut Ctx) {
    match ctx.source.as_str() {
        "wots_pkgen() @ reference/mochimo-core/src/wots.c:229" => pkgen(ctx),
        // --- groups AK, BK, HS, AKX, CK: the bulk corpus -----------
        AK_PKGEN => pkgen_digest(ctx),
        AK_EXPAND_SEED => expand_seed_digest(ctx),
        AK_GEN_CHAIN => gen_chain(ctx),
        BK_SIGN => sign_digest(ctx),
        HS_SHA256 => sha256_vector(ctx),
        AKX_PKGEN => akx_pkgen(ctx),
        CK_TAG => ck_tag(ctx),
        "prf() @ reference/mochimo-core/src/wots.c:78" => prf(ctx),
        "thash_f() @ reference/mochimo-core/src/wots.c:93" => thash_f(ctx),
        "expand_seed() @ reference/mochimo-core/src/wots.c:125" => expand_seed(ctx),
        "wots_sign() @ reference/mochimo-core/src/wots.c:255" => sign(ctx),
        "wots_pk_from_sig() @ reference/mochimo-core/src/wots.c:284" => pk_from_sig(ctx),
        "chain_lengths() @ reference/mochimo-core/src/wots.c:212" => chain_lengths(ctx),
        "addr_hash_generate() @ reference/mochimo-core/src/ledger.c:95" => addr_hash(ctx),
        "sha3() @ reference/mochimo-core/include/crypto-c/src/sha3.c" => sha3(ctx),
        "ripemd160() @ reference/mochimo-core/include/crypto-c/src/ripemd160.c" => ripemd160(ctx),
        "addr_from_wots() @ reference/mochimo-core/src/ledger.c:109" => addr_from_wots(ctx),
        "addr_from_implicit() @ reference/mochimo-core/src/ledger.c:83" => addr_from_implicit(ctx),
        "addr_hash_generate + addr_from_implicit() @ reference/mochimo-core/src/ledger.c:95,83" => {
            addr_len_control(ctx)
        }
        "crc16 + put16 + base58_encode() @ reference/mochimo-core/src/tx.c:268-270" => tag_encode(ctx),
        "base58_decode() @ reference/mochimo-core/include/crypto-c/src/base58.c:101" => {
            base58_decode(ctx)
        }
        "base58_decode() @ reference/mochimo-core/include/crypto-c/src/base58.c:114-144" => {
            base58_degenerate(ctx)
        }
        "base58_encode / base58_decode() @ reference/mochimo-core/include/crypto-c/src/base58.c:44,101" => {
            base58_lengths(ctx)
        }
        "put16() @ reference/mochimo-core/include/extended-c/src/extlib.h:71" => put16_framing(ctx),
        "put16/get16() @ reference/mochimo-core/include/extended-c/src/extlib.h:71" => {
            put16_roundtrip(ctx)
        }
        "crc16() @ reference/mochimo-core/include/crypto-c/src/crc16.c" => crc16_vector(ctx),
        "TagUtils.addrTagToBase58() @ reference/mochimo-wots/src/utils/tag-utils.ts:4" => {
            ts_tag_to_base58(ctx)
        }
        "WotsAddress.addrFromWots() @ reference/mochimo-wots/src/protocol/wots-addr.ts:116" => {
            ts_addr_from_wots(ctx)
        }
        "WOTS.wots_pkgen() @ reference/mochimo-wots/src/protocol/wots.ts:120 -> \
WotsAddress.addrFromWots() @ reference/mochimo-wots/src/protocol/wots-addr.ts:116" => {
            ts_pkgen_to_addr(ctx)
        }
        "WotsAddress.addrFromImplicit() @ reference/mochimo-wots/src/protocol/wots-addr.ts:99" => {
            ts_addr_from_implicit(ctx)
        }
        "WotsAddress.addrHashGenerate() @ reference/mochimo-wots/src/protocol/wots-addr.ts:106" => {
            ts_addr_hash_generate(ctx)
        }
        "MochimoHasher.hashWith() @ reference/mochimo-wots/src/hasher/mochimo-hasher.ts:75" => {
            ts_standalone_digest(ctx)
        }
        "bs58.encode() @ bs58 6.0.0, resolved from mochimo-wots" => ts_base58_encode(ctx),
        "bs58.decode() @ bs58 6.0.0, and TagUtils.validateBase58Tag / \
base58ToAddrTag @ reference/mochimo-wots/src/utils/tag-utils.ts:20,39" => ts_base58_decode(ctx),
        "MochimoHasher.hashWith(\"ripemd160\") -> @noble/hashes/ripemd160" => rx_ripemd160(ctx),
        "TXDAT_TYPE / TXDSA_TYPE / MDST_COUNT() @ reference/mochimo-core/src/types.h:166,171,176" => {
            options_accessors(ctx)
        }
        // Group D sources recorded from the reference validators (`tx__init`,
        // `mdst_val__reference`, `tx_read`, `tx_hash`, `tx_val__wots` and the
        // transaction-core replay) share one native handler.
        s if is_reference_only_source(s) => reference_verdicts_native(ctx),
        V_POS_TX => pos_validator_tx(ctx),
        S_STAKE_TX => stake_tx(ctx),
        // --- group F: the browser extension's derivation ------------
        //
        // One arm per source. The handlers are in
        // `support/derivation_walk.rs`, shared with `tests/derive.rs`; `Ctx`
        // implements the walk's `Vector` trait below, so coverage tracking
        // reaches the shared code. Gated on `native` because the derivation
        // is. Group F is a specification capture, not a crosscheck
        // (`group_f_is_specification_not_crosscheck`).
        #[cfg(feature = "native")]
        derivation_walk::PRNG => derivation_walk::prng(ctx),
        #[cfg(feature = "native")]
        derivation_walk::GENERATE_STATE => derivation_walk::generate_state(ctx),
        #[cfg(feature = "native")]
        derivation_walk::COUNTERS => derivation_walk::counters(ctx),
        #[cfg(feature = "native")]
        derivation_walk::DERIVE_SEED => derivation_walk::derive_seed(ctx),
        #[cfg(feature = "native")]
        derivation_walk::DERIVE_WOTS => derivation_walk::derive_wots(ctx),
        #[cfg(feature = "native")]
        derivation_walk::WIDTHS => derivation_walk::widths(ctx),
        #[cfg(feature = "native")]
        derivation_walk::DERIVE_TAG => derivation_walk::derive_tag(ctx),
        #[cfg(feature = "native")]
        derivation_walk::COMPONENTS => derivation_walk::components(ctx),
        #[cfg(feature = "native")]
        derivation_walk::FROM_PHRASE => derivation_walk::from_phrase(ctx),
        #[cfg(feature = "native")]
        derivation_walk::TO_PHRASE => derivation_walk::to_phrase(ctx),
        #[cfg(feature = "native")]
        derivation_walk::DERIVE_ACCOUNT => derivation_walk::derive_account(ctx),
        // The rotation sweep and the three BIP39 library captures.
        #[cfg(feature = "native")]
        derivation_walk::ROTATION => derivation_walk::rotation(ctx),
        #[cfg(feature = "native")]
        derivation_walk::BIP39_SEED => derivation_walk::bip39_seed(ctx),
        #[cfg(feature = "native")]
        derivation_walk::BIP39_ENTROPY => derivation_walk::bip39_entropy(ctx),
        #[cfg(feature = "native")]
        derivation_walk::BIP39_REJECT => derivation_walk::bip39_reject(ctx),
        // --- groups M and N: the mesh client and the mesh capture --
        //
        // One handler per source, in `support/mesh_walk.rs`, shared with
        // `tests/mesh.rs`. Both groups are specification captures: N is one
        // server at one block, M is the client against a test double. Gated
        // on `native` because the codec is.
        #[cfg(feature = "native")]
        s if mesh_walk::SOURCES.contains(&s) => {
            // Owned, so the scrutinee's borrow of `ctx.source` ends before
            // the walk takes `ctx` mutably.
            let source = s.to_owned();
            mesh_walk::replay(ctx, &source)
        }
        unknown => panic!(
            "UNREGISTERED SOURCE\n  fixture : {}\n  vector  : {}\n  source  : {unknown}\n  \
             No replay is registered for this reference function, so the vector would run \
             nothing. Register it in tests/kat.rs rather than skipping it.",
            ctx.file, ctx.id
        ),
    }
    crosscheck_verdicts(ctx);
}

/// `Ctx` as the mesh walk's vector. Every accessor is `Ctx`'s own, so
/// coverage tracking reaches the shared handlers.
#[cfg(feature = "native")]
impl mesh_walk::Vector for Ctx<'_> {
    fn id(&self) -> String {
        self.id.clone()
    }
    fn has(&self, key: &str) -> bool {
        Ctx::has(self, key)
    }
    fn str_(&self, key: &str) -> String {
        Ctx::str_(self, key).to_string()
    }
    fn hex(&self, key: &str) -> Vec<u8> {
        Ctx::hex(self, key)
    }
    fn u64_(&self, key: &str) -> u64 {
        Ctx::u64_(self, key)
    }
    fn bool_(&self, key: &str) -> bool {
        Ctx::bool_(self, key)
    }
    fn blob(&self, key: &str) -> Vec<u8> {
        Ctx::blob(self, key)
    }
    fn eq_u64(&mut self, key: &str, actual: u64) {
        Ctx::eq_u64(self, key, actual);
    }
    fn eq_bool(&mut self, key: &str, actual: bool) {
        Ctx::eq_bool(self, key, actual);
    }
    fn eq_str(&mut self, key: &str, actual: &str) {
        Ctx::eq_str(self, key, actual);
    }
    fn eq_bytes(&mut self, key: &str, actual: &[u8]) {
        Ctx::eq_bytes(self, key, actual);
    }
    fn eq_blob(&mut self, key: &str, actual: &[u8]) {
        Ctx::eq_blob(self, key, actual);
    }
}

/// `Ctx` as the derivation walk's vector. Every accessor is `Ctx`'s own, so
/// every field the shared handlers read is recorded. `not_ported` marks the
/// vector as not called.
#[cfg(feature = "native")]
impl derivation_walk::Vector for Ctx<'_> {
    fn id(&self) -> String {
        self.id.clone()
    }
    fn has(&self, key: &str) -> bool {
        Ctx::has(self, key)
    }
    fn hex(&self, key: &str) -> Vec<u8> {
        Ctx::hex(self, key)
    }
    fn str_(&self, key: &str) -> String {
        Ctx::str_(self, key).to_string()
    }
    fn u64_(&self, key: &str) -> u64 {
        Ctx::u64_(self, key)
    }
    fn ints(&self, key: &str) -> Vec<i64> {
        Ctx::ints(self, key).into_iter().map(i64::from).collect()
    }
    fn blob(&self, key: &str) -> Vec<u8> {
        Ctx::blob(self, key)
    }
    fn eq_bytes(&mut self, key: &str, actual: &[u8]) {
        Ctx::eq_bytes(self, key, actual);
    }
    fn eq_blob(&mut self, key: &str, actual: &[u8]) {
        Ctx::eq_blob(self, key, actual);
    }
    fn eq_u64(&mut self, key: &str, actual: u64) {
        Ctx::eq_u64(self, key, actual);
    }
    fn eq_i64(&mut self, key: &str, actual: i64) {
        Ctx::eq_i64(self, key, actual);
    }
    fn eq_bool(&mut self, key: &str, actual: bool) {
        Ctx::eq_bool(self, key, actual);
    }
    fn eq_str(&mut self, key: &str, actual: &str) {
        Ctx::eq_str(self, key, actual);
    }
    fn eq_ints(&mut self, key: &str, actual: &[i64]) {
        // `Ctx::ints` is i32; every group F integer array fits.
        let narrowed: Vec<i32> = actual
            .iter()
            .map(|x| i32::try_from(*x).unwrap_or_else(|_| panic!("{}: {key} holds {x}, outside i32", self.id)))
            .collect();
        Ctx::eq_ints(self, key, &narrowed);
    }
    fn not_ported(&mut self) {
        self.mark(Disposition::NotCalled);
    }
}

/// Second-implementation verdicts recorded by the generator must all be
/// agreement.
///
/// Where a fixture carries the other implementation's output, its handler
/// recomputes and compares (as `tag_encode` does with
/// `crosscheck_typescript_expected`); this covers fields that carry only a
/// boolean verdict. Field names differ across groups, so each is named;
/// coverage reports any crosscheck field not named here as unread.
fn crosscheck_verdicts(ctx: &mut Ctx) {
    for key in [
        "matches_reference_expect_pub_key",
        "matches_reference_expect_tag",
        "matches_reference_expect_sig",
        "crosscheck_matches",
        "crosscheck_executed_matches_literal",
    ] {
        if ctx.has(key) {
            ctx.eq_bool(key, true);
        }
    }
}

// --- group A ------------------------------------------------------------

fn pkgen(ctx: &mut Ctx) {
    let secret = Secret::<SEED_LEN>::new(ctx.arr("secret"));
    let pub_seed: [u8; SEED_LEN] = ctx.arr("pub_seed");
    let mut adrs = Adrs(ctx.words("adrs_in_words"));

    let pk = wots::pkgen(&secret, &pub_seed, &mut adrs);

    ctx.eq_blob("pk", pk.as_slice());
    ctx.eq_words("adrs_out_words", adrs.words());
    ctx.eq_bytes("adrs_out_bytes_addr_to_bytes_be", &adrs.to_bytes());
}

fn prf(ctx: &mut Ctx) {
    let input: [u8; 32] = ctx.arr("in");
    let key: [u8; SEED_LEN] = ctx.arr("key");
    let out = raw::prf(&input, &key);
    ctx.eq_bytes("out", &out);
}

fn thash_f(ctx: &mut Ctx) {
    let input: [u8; 32] = ctx.arr("in");
    let pub_seed: [u8; SEED_LEN] = ctx.arr("pub_seed");
    let mut adrs = Adrs(ctx.words("adrs_in_words"));

    let out = raw::thash_f(&input, &pub_seed, &mut adrs.0);

    ctx.eq_bytes("out", &out);
    ctx.eq_words("adrs_out_words", adrs.words());
    ctx.eq_bytes("adrs_out_bytes_addr_to_bytes_be", &adrs.to_bytes());
}

fn expand_seed(ctx: &mut Ctx) {
    let inseed = Secret::<SEED_LEN>::new(ctx.arr("inseed"));
    let out = raw::expand_seed(inseed.expose());
    ctx.eq_blob("outseeds", out.as_slice());
}

// --- group B ------------------------------------------------------------

fn sign(ctx: &mut Ctx) {
    // B-adrs-invariance shares wots_sign()'s source but pins a different
    // question: whether the starting value of adrs words 5-7 changes the
    // signature. It carries no key material of its own.
    if ctx.has("adrs_a_in_words") {
        return adrs_invariance(ctx);
    }

    let msg: [u8; SEED_LEN] = ctx.arr("msg");
    let secret = Secret::<SEED_LEN>::new(ctx.arr("secret"));
    let pub_seed: [u8; SEED_LEN] = ctx.arr("pub_seed");
    let mut adrs = Adrs(ctx.words("adrs_in_words"));

    let sig = raw::wots_sign(&msg, secret.expose(), &pub_seed, &mut adrs.0);

    ctx.eq_blob("sig", sig.as_slice());
    ctx.eq_words("adrs_out_words", adrs.words());
}

/// The two signatures differ only in the adrs words 5-7 they start from. The
/// vector also records the msg, secret, pub_seed and signature, so a wrong
/// reading fails on the bytes rather than on a self-comparison.
fn adrs_invariance(ctx: &mut Ctx) {
    let msg: [u8; SEED_LEN] = ctx.arr("msg");
    let secret = Secret::<SEED_LEN>::new(ctx.arr("secret"));
    let pub_seed: [u8; SEED_LEN] = ctx.arr("pub_seed");

    let mut a = Adrs(ctx.words("adrs_a_in_words"));
    let mut b = Adrs(ctx.words("adrs_b_in_words"));
    let sig_a = raw::wots_sign(&msg, secret.expose(), &pub_seed, &mut a.0);
    let sig_b = raw::wots_sign(&msg, secret.expose(), &pub_seed, &mut b.0);

    ctx.eq_words("adrs_a_out_words", a.words());
    ctx.eq_words("adrs_b_out_words", b.words());
    ctx.eq_bool("signatures_equal", sig_a == sig_b);
    ctx.eq_blob("sig", sig_a.as_slice());
}

fn pk_from_sig(ctx: &mut Ctx) {
    let sig_bytes = ctx.blob("sig");
    let sig: [u8; SIG_LEN] = sig_bytes
        .try_into()
        .unwrap_or_else(|v: Vec<u8>| panic!("{}: recorded signature is {} bytes", ctx.id, v.len()));
    let msg: [u8; SEED_LEN] = ctx.arr("msg");
    let pub_seed: [u8; SEED_LEN] = ctx.arr("pub_seed");
    let mut adrs = Adrs(ctx.words("adrs_in_words"));

    let pk = wots::pk_from_sig(&sig, &msg, &pub_seed, &mut adrs);

    ctx.eq_blob("recovered_pk", pk.as_slice());
    ctx.eq_words("adrs_out_words", adrs.words());

    // `equals_keygen_pk`: recovery reproduces the keygen public key for a
    // good signature and not for a tampered one. The key is regenerated from
    // the vector's recorded seeds, not read back.
    let secret = Secret::<SEED_LEN>::new(ctx.arr("keygen_secret"));
    let key_pub_seed: [u8; SEED_LEN] = ctx.arr("keygen_pub_seed");
    let mut keygen_adrs = Adrs::ZERO;
    let keygen = wots::pkgen(&secret, &key_pub_seed, &mut keygen_adrs);
    ctx.eq_bool("equals_keygen_pk", pk == keygen);
}

fn chain_lengths(ctx: &mut Ctx) {
    let msg: [u8; SEED_LEN] = ctx.arr("msg");
    let lengths = raw::chain_lengths(&msg);
    ctx.eq_ints("lengths", &lengths);
    ctx.eq_ints("checksum_digits", &lengths[lengths.len() - 3..]);
}

// --- groups AK and BK: the bulk corpus, recorded as digests --------
//
// A WOTS+ public key or signature is 2144 bytes and the bulk files hold a
// thousand of each, so they record the reference's sha256 of each artifact
// instead of a sidecar file. The replay computes the value from the recorded
// inputs, digests it with `raw::sha256` and compares digests.
// `artifact_policy_is_declared_by_the_generator_and_enforced_here` keeps a
// digest from replacing bytes where the bytes are required.

/// The digest that stands in for an artifact: `<key>_len` and `<key>_sha256`.
fn digest_leg(ctx: &mut Ctx, key: &str, artifact: &[u8]) {
    ctx.eq_u64(&format!("{key}_len"), artifact.len() as u64);
    ctx.eq_bytes(&format!("{key}_sha256"), &raw::sha256(artifact));
}

fn pkgen_digest(ctx: &mut Ctx) {
    let secret = Secret::<SEED_LEN>::new(ctx.arr("secret"));
    let pub_seed: [u8; SEED_LEN] = ctx.arr("pub_seed");
    let mut adrs = Adrs(ctx.words("adrs_in_words"));

    let pk = wots::pkgen(&secret, &pub_seed, &mut adrs);

    ctx.eq_words("adrs_out_words", adrs.words());
    ctx.eq_bytes("adrs_out_bytes_addr_to_bytes_be", &adrs.to_bytes());
    digest_leg(ctx, "pk", pk.as_slice());
    // The v3 address for this key: the whole secret -> pk -> address path.
    ctx.eq_bytes("addr", &addr::from_wots(&pk));
}

fn expand_seed_digest(ctx: &mut Ctx) {
    let inseed = Secret::<SEED_LEN>::new(ctx.arr("inseed"));
    let out = raw::expand_seed(inseed.expose());
    digest_leg(ctx, "outseeds", out.as_slice());
}

fn gen_chain(ctx: &mut Ctx) {
    let input: [u8; 32] = ctx.arr("in");
    let start = u32::try_from(ctx.u64_("start"))
        .unwrap_or_else(|_| panic!("{}: `start` is not a u32", ctx.id));
    let steps = u32::try_from(ctx.u64_("steps"))
        .unwrap_or_else(|_| panic!("{}: `steps` is not a u32", ctx.id));
    let pub_seed: [u8; SEED_LEN] = ctx.arr("pub_seed");
    let mut adrs = Adrs(ctx.words("adrs_in_words"));

    let out = raw::gen_chain(&input, start, steps, &pub_seed, &mut adrs.0);

    ctx.eq_bytes("out", &out);
    ctx.eq_words("adrs_out_words", adrs.words());
    ctx.eq_bytes("adrs_out_bytes_addr_to_bytes_be", &adrs.to_bytes());
}

/// Sign, recover, and recover from a one-bit mutation (group B's three
/// checks) on one key per vector. Both recovery verdicts are recomputed, and
/// the mutation position is read from the vector, so the replay uses the
/// same bytes the reference compared.
fn sign_digest(ctx: &mut Ctx) {
    let msg: [u8; SEED_LEN] = ctx.arr("msg");
    let secret = Secret::<SEED_LEN>::new(ctx.arr("secret"));
    let pub_seed: [u8; SEED_LEN] = ctx.arr("pub_seed");
    let adrs_in = ctx.words("adrs_in_words");

    let mut keygen_adrs = Adrs(adrs_in);
    let pk = wots::pkgen(&secret, &pub_seed, &mut keygen_adrs);
    digest_leg(ctx, "pk", pk.as_slice());

    let mut adrs = Adrs(adrs_in);
    let sig = raw::wots_sign(&msg, secret.expose(), &pub_seed, &mut adrs.0);
    ctx.eq_words("adrs_out_words", adrs.words());
    digest_leg(ctx, "sig", sig.as_slice());

    let mut recovery_adrs = Adrs(adrs_in);
    let recovered = wots::pk_from_sig(&sig, &msg, &pub_seed, &mut recovery_adrs);
    ctx.eq_words("recovery_adrs_out_words", recovery_adrs.words());
    ctx.eq_bool("recovered_equals_keygen_pk", recovered == pk);

    let flip_byte = ctx.u64_("flip_byte") as usize;
    let flip_bit = ctx.u64_("flip_bit");
    assert!(
        flip_byte < SIG_LEN && flip_bit < 8,
        "{}: flip_byte {flip_byte} / flip_bit {flip_bit} is outside the signature",
        ctx.id
    );
    let mut mutated: [u8; SIG_LEN] = *sig;
    mutated[flip_byte] ^= 1u8 << flip_bit;
    let mut mutated_adrs = Adrs(adrs_in);
    let recovered_mut = wots::pk_from_sig(&mutated, &msg, &pub_seed, &mut mutated_adrs);
    ctx.eq_bool("mutated_recovered_equals_keygen_pk", recovered_mut == pk);
}

// --- group HS: the hash primitives at every length -----------------

fn sha256_vector(ctx: &mut Ctx) {
    let input = ctx.hex("in");
    assert_eq!(input.len(), ctx.u64_("inlen") as usize);
    ctx.eq_bytes("out", &raw::sha256(&input));
}

// --- group C ------------------------------------------------------------

fn addr_hash(ctx: &mut Ctx) {
    let inlen = ctx.u64_("inlen") as usize;

    // Inputs over the generator's inline limit are stored in sidecar files,
    // so C1's 2144 bytes arrive as `in_file` and C2/C3's as inline hex.
    let input: Vec<u8> = if ctx.has("in_file") {
        ctx.blob("in")
    } else {
        ctx.hex("in")
    };
    assert_eq!(
        input.len(),
        inlen,
        "{}: vector {} `in` is {} bytes but `inlen` says {inlen}",
        ctx.file,
        ctx.id,
        input.len()
    );

    ctx.eq_bytes("hash", &addr::hash_generate(&input));
}

/// The vector's `outlen` selects one of the four fixed-width SHA-3
/// functions the reference declares compatible; any other width fails.
/// Only `outlen: 64` appears in the corpus.
fn sha3(ctx: &mut Ctx) {
    let input = ctx.hex("in");
    assert_eq!(input.len(), ctx.u64_("inlen") as usize);
    let outlen = ctx.u64_("outlen") as usize;
    let out: Vec<u8> = match outlen {
        28 => addr::sha3_224(&input).to_vec(),
        32 => addr::sha3_256(&input).to_vec(),
        48 => addr::sha3_384(&input).to_vec(),
        64 => addr::sha3_512(&input).to_vec(),
        n => panic!(
            "sha3 vector {} has outlen {n}, which is not one of the four widths \
             sha3.h:44 declares compatible (28, 32, 48, 64). The reference \
             would accept it and produce a non-standard sponge -- and from \
             outlen 100 its own rsiz underflows and sha3_final writes out of \
             bounds, which is why the width here is a type and not a \
             parameter (addr.rs's sha3 doc). \
             Either the vector is wrong or a fifth width needs porting.",
            ctx.id
        ),
    };
    ctx.eq_bytes("out", &out);
}

fn ripemd160(ctx: &mut Ctx) {
    let input = ctx.hex("in");
    assert_eq!(input.len(), ctx.u64_("inlen") as usize);
    ctx.eq_bytes("out", &addr::ripemd160(&input));
}

/// `addr_from_wots` over two vector shapes.
///
/// The seven `C4-A*` vectors carry a seed triple and replay the whole
/// seed -> pk -> address path. `C-addr-from-wots-fill42` carries a bare
/// 2144-byte public key filled with 0x42, the input the TypeScript package's
/// own test uses. The branch is on the presence of `secret`, not on the id.
fn addr_from_wots(ctx: &mut Ctx) {
    let pk: Box<[u8; PK_LEN]> = if ctx.has("secret") {
        // Regenerated from the vector's seeds, not read from a sidecar.
        let secret = Secret::<SEED_LEN>::new(ctx.arr("secret"));
        let pub_seed: [u8; SEED_LEN] = ctx.arr("pub_seed");
        let mut adrs = Adrs(ctx.words("adrs_in_words"));
        wots::pkgen(&secret, &pub_seed, &mut adrs)
    } else {
        let fill = ctx.u64_("input_fill_byte");
        assert!(fill <= 0xff, "{}: input_fill_byte {fill} is not a byte", ctx.id);
        let bytes = ctx.blob("in");
        ctx.eq_u64("input_len", bytes.len() as u64);
        // Check the sidecar really is the constant fill the vector claims.
        assert!(
            bytes.iter().all(|&b| b as u64 == fill),
            "{}: {} is not uniformly 0x{fill:02x}",
            ctx.file,
            ctx.id
        );
        let n = bytes.len();
        bytes.into_boxed_slice().try_into().unwrap_or_else(|_| {
            panic!(
                "{}: {} sidecar is {n} bytes, expected WOTS_PK_LEN = {PK_LEN}",
                ctx.file, ctx.id
            )
        })
    };

    let address = addr::from_wots(&pk);
    ctx.eq_bytes("addr", &address);
    ctx.eq_bytes("tag_half", addr::tag_of(&address));
    ctx.eq_bytes("hash_half", addr::hash_of(&address));
    ctx.eq_bool(
        "halves_equal",
        addr::tag_of(&address) == addr::hash_of(&address),
    );

    // The literal from the TypeScript package's test file for this input. It
    // pins a transcription; `group_c_crosscheck.json` carries the executed
    // value. Both are checked.
    if ctx.has("crosscheck_typescript_expected") {
        ctx.eq_str("crosscheck_typescript_expected", &hex(&address));
    }
}

fn addr_from_implicit(ctx: &mut Ctx) {
    let tag: [u8; 20] = ctx.arr("tag_in");
    let address = addr::from_implicit(&tag);
    ctx.eq_bytes("addr", &address);
    ctx.eq_bool(
        "halves_equal",
        addr::tag_of(&address) == addr::hash_of(&address),
    );
}

/// C6, the 2144-vs-2208 negative control: a port that confuses the two
/// lengths fails. `addr_correct_2144` comes from A4's key regenerated here;
/// `addr_wrong_2208` from hashing the recorded 2208-byte buffer.
fn addr_len_control(ctx: &mut Ctx) {
    assert!(ctx.bool_("is_negative_control"));
    assert_eq!(ctx.u64_("inlen"), 2208);

    let secret = Secret::<SEED_LEN>::new(ctx.arr("in_secret"));
    let pub_seed: [u8; SEED_LEN] = ctx.arr("in_pub_seed");
    let mut adrs = Adrs::ZERO;
    let pk = wots::pkgen(&secret, &pub_seed, &mut adrs);
    let correct = addr::from_wots(&pk);
    ctx.eq_bytes("addr_correct_2144", &correct);

    // The recorded buffer is pk || pub_seed || terminal adrs; its first
    // PK_LEN bytes must be the key just generated.
    let buf = ctx.blob("in");
    assert_eq!(buf.len(), 2208, "C6: `in` is {} bytes", buf.len());
    assert_eq!(&buf[..PK_LEN], pk.as_slice(), "C6: `in` does not start with A4's pk");

    let wrong = addr::from_implicit(&addr::hash_generate(&buf));
    ctx.eq_bytes("addr_wrong_2208", &wrong);
    ctx.eq_bool("differs_from_correct", wrong != correct);
}

fn tag_encode(ctx: &mut Ctx) {
    let tag: [u8; 20] = ctx.arr("tag");

    let sum = crc16::crc16(&tag);
    ctx.eq_u64("crc16", sum as u64);

    let sum_bytes = bytes::put16(sum);
    ctx.eq_bytes("crc16_bytes_put16", &sum_bytes);

    let mut tag22 = [0u8; 22];
    tag22[..20].copy_from_slice(&tag);
    tag22[20..].copy_from_slice(&sum_bytes);
    ctx.eq_bytes("tag_with_crc16", &tag22);

    let probe20 = base58::encode_probe_len(&tag).expect("base58_encode probe failed on tag20");
    ctx.eq_u64("base58_of_tag20_probe_len", reference_encode_probe(&tag, probe20) as u64);
    ctx.eq_str(
        "base58_of_tag20",
        &base58::encode(&tag).expect("base58_encode failed on tag20"),
    );

    let probe22 = base58::encode_probe_len(&tag22).expect("base58_encode probe failed on tag22");
    ctx.eq_u64("base58_of_tag22_probe_len", reference_encode_probe(&tag22, probe22) as u64);
    let encoded22 = base58::encode(&tag22).expect("base58_encode failed on tag22");
    ctx.eq_str("base58_of_tag22", &encoded22);

    // An independent oracle: the TypeScript tag utilities produce the same
    // string from the same tag. This literal was transcribed from the
    // upstream test file; `group_c_crosscheck.json` records the executed
    // `addrTagToBase58` value. Both are checked.
    if ctx.has("crosscheck_typescript_expected") {
        ctx.eq_str("crosscheck_typescript_expected", &encoded22);
    }
}

// --- group CX: the executed TypeScript crosscheck -----------------------
//
// `fixtures/group_c_crosscheck.json` holds a second implementation's return
// values for group C's inputs. Each vector closes a three-way agreement, and
// each leg can fail on its own:
//
//   1. `crosscheck_typescript_expected` equals group C's copy of the same
//      literal;
//   2. `crosscheck_typescript_executed` equals what this crate computes;
//   3. `crosscheck_executed_matches_literal` is true (via
//      `crosscheck_verdicts`): the transcribed literal is what the
//      TypeScript returns.

/// The transcription leg, conditional and fail-closed both ways.
///
/// Either group C carries a literal for the subject, and it is asserted
/// here, or the crosscheck vector declares `literal_absent`. Declaring
/// `literal_absent` while group C has a literal fails, as does carrying
/// neither. The literal is fetched from the other file, so a vector id that
/// no longer exists fails inside `vector_by_id`.
fn literal_leg(ctx: &mut Ctx) {
    let file = ctx.str_("crosschecks_file").to_string();
    let id = ctx.str_("crosschecks_vector").to_string();
    let fx = Fixture::load(&file);
    let v = fx.vector_by_id(&id);
    literal_leg_against(ctx, &file, &id, v);
}

/// The transcription leg over an upstream vector already located, so bulk
/// crosschecks can load the fixture once.
fn literal_leg_against(ctx: &mut Ctx, file: &str, id: &str, v: &serde_json::Value) {
    let upstream = v
        .get("crosscheck_typescript_expected")
        .and_then(|x| x.as_str())
        .map(str::to_string);

    match upstream {
        Some(lit) => {
            assert!(
                !ctx.has("literal_absent"),
                "{}: {} claims `literal_absent`, but {file}::{id} carries a \
                 transcribed literal. The literal is the only thing in the \
                 suite that checks the transcription itself, so declaring it \
                 absent is how that check would be lost silently.",
                ctx.file,
                ctx.id
            );
            ctx.eq_str("crosscheck_typescript_expected", &lit);
        }
        None => {
            assert!(
                ctx.has("literal_absent"),
                "{}: {} crosschecks {file}::{id}, which carries no \
                 `crosscheck_typescript_expected`, and this vector does not \
                 declare `literal_absent` either. One of the two must be true: \
                 either there is a literal to compare or the vector says there \
                 is not. Silence here is indistinguishable from a literal that \
                 quietly stopped being asserted.",
                ctx.file,
                ctx.id
            );
            ctx.eq_bool("literal_absent", true);
            assert!(
                !ctx.has("crosscheck_typescript_expected"),
                "{}: {} declares `literal_absent` but carries a \
                 `crosscheck_typescript_expected` of its own. A literal that \
                 group C does not also carry is a literal nothing cross-checks.",
                ctx.file,
                ctx.id
            );
        }
    }
}

// --- groups AKX and CK: the bulk crosschecks ------------------------
//
// CX's three-way agreement over the bulk corpus: the reference's recorded
// answer (in the file each vector names), the TypeScript's executed answer
// (recorded here) and this crate's. The upstream file is loaded once per
// process, and each vector's named file is checked against the cached one.

fn cached_upstream(file: &str, expect: &'static str, slot: &'static OnceLock<Fixture>) -> &'static Fixture {
    assert_eq!(
        file, expect,
        "a bulk crosscheck vector names {file:?} as its upstream; this group's \
         upstream is {expect:?} and the cache holds only that"
    );
    slot.get_or_init(|| Fixture::load(expect))
}

fn akx_pkgen(ctx: &mut Ctx) {
    static AK: OnceLock<Fixture> = OnceLock::new();

    let secret = Secret::<SEED_LEN>::new(ctx.arr("input_secret"));
    let pub_seed: [u8; SEED_LEN] = ctx.arr("input_pub_seed");
    let words = ctx.words("input_adrs_in_words");

    let all_zero = words.iter().all(|&w| w == 0);
    ctx.eq_bool("adrs_all_zero", all_zero);
    // Little-endian, as `ts_pkgen_to_addr` explains. Half the AK vectors have
    // a non-zero adrs.
    let mut image = [0u8; 32];
    for (i, w) in words.iter().enumerate() {
        image[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    ctx.eq_bytes("adrs_byte_image", &image);
    let representation = ctx.str_("adrs_representation");
    assert_eq!(
        representation.starts_with("all-zero"),
        all_zero,
        "{}: {} has adrs_all_zero = {all_zero} but adrs_representation says {representation:?}",
        ctx.file,
        ctx.id
    );

    let mut adrs = Adrs(words);
    let pk = wots::pkgen(&secret, &pub_seed, &mut adrs);
    ctx.eq_u64("input_pk_len", pk.len() as u64);
    let address = addr::from_wots(&pk);
    let pk_digest = raw::sha256(pk.as_slice());

    // Leg 2: the TypeScript's executed values against this crate's.
    ctx.eq_str("crosscheck_typescript_executed", &hex(&address));
    ctx.eq_bytes("pk_sha256_typescript_executed", &pk_digest);

    // Leg 1: the reference's recorded values, from the AK vector named.
    let file = ctx.str_("crosschecks_file").to_string();
    let id = ctx.str_("crosschecks_vector").to_string();
    let upstream = cached_upstream(&file, "group_ak_keygen_bulk.json", &AK).vector_by_id(&id);
    assert_eq!(
        upstream.get("addr").and_then(|x| x.as_str()),
        Some(hex(&address).as_str()),
        "{}: {} -- the C's recorded address for {id} is not what the \
         TypeScript and this crate both computed",
        ctx.file,
        ctx.id
    );
    assert_eq!(
        upstream.get("pk_sha256").and_then(|x| x.as_str()),
        Some(hex(&pk_digest).as_str()),
        "{}: {} -- the C's recorded pk digest for {id} is not what the \
         TypeScript and this crate both computed",
        ctx.file,
        ctx.id
    );
    literal_leg_against(ctx, &file, &id, upstream);
}

fn ck_tag(ctx: &mut Ctx) {
    static C: OnceLock<Fixture> = OnceLock::new();

    let tag: [u8; 20] = ctx.arr("input_tag");
    ctx.eq_u64("input_len", tag.len() as u64);

    let sum = crc16::crc16(&tag);
    let mut tag22 = [0u8; 22];
    tag22[..20].copy_from_slice(&tag);
    tag22[20..].copy_from_slice(&bytes::put16(sum));
    let from_c = base58::encode(&tag22).expect("base58_encode failed on tag22");

    ctx.eq_str("crosscheck_typescript_executed", &from_c);
    ctx.eq_u64("crc16_typescript_executed", u64::from(sum));

    // The corpus entry this vector crosschecks, located by the index in
    // `crosschecks_vector` ("crc16_base58_corpus[i]") and checked to be the
    // entry it claims -- the tag must match before its answers are compared.
    let file = ctx.str_("crosschecks_file").to_string();
    let which = ctx.str_("crosschecks_vector").to_string();
    let index: usize = which
        .strip_prefix("crc16_base58_corpus[")
        .and_then(|s| s.strip_suffix(']'))
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("{}: {} crosschecks {which:?}, not a corpus index", ctx.file, ctx.id));
    let corpus = &cached_upstream(&file, "group_c_addr.json", &C).root["crc16_base58_corpus"];
    let entry = corpus["entries"]
        .get(index)
        .unwrap_or_else(|| panic!("{}: {} names corpus entry {index}, which does not exist", ctx.file, ctx.id));
    assert_eq!(entry["i"].as_u64(), Some(index as u64), "{}: entry {index} carries a different `i`", ctx.id);
    assert_eq!(entry["tag"].as_str(), Some(hex(&tag).as_str()), "{}: entry {index} is a different tag", ctx.id);
    assert_eq!(
        entry["base58"].as_str(),
        Some(from_c.as_str()),
        "{}: the C's recorded Base58 for corpus entry {index} is not what the \
         TypeScript and this crate both computed",
        ctx.id
    );
    assert_eq!(
        entry["crc16"].as_u64(),
        Some(u64::from(sum)),
        "{}: the C's recorded crc16 for corpus entry {index} is not what the \
         TypeScript and this crate both computed",
        ctx.id
    );
    // The corpus entries carry no transcribed literal, so the vector must say so.
    literal_leg_against(ctx, &file, &which, entry);
}

/// `TagUtils.addrTagToBase58` against `crc16 + put16 + base58_encode`.
///
/// The reference composes three separate functions; the TypeScript composes
/// its own `crc` and `bs58` inside one function.
fn ts_tag_to_base58(ctx: &mut Ctx) {
    let tag: [u8; 20] = ctx.arr("input_hex");
    ctx.eq_u64("input_len", tag.len() as u64);

    let mut tag22 = [0u8; 22];
    tag22[..20].copy_from_slice(&tag);
    tag22[20..].copy_from_slice(&bytes::put16(crc16::crc16(&tag)));
    let from_c = base58::encode(&tag22).expect("base58_encode failed on tag22");

    ctx.eq_str("crosscheck_typescript_executed", &from_c);

    // The CRC16 the TypeScript embedded, against this crate's.
    //
    // `crc()` is not exported by mochimo-wots, so the generator recovers it
    // by decoding `addrTagToBase58`'s output and reading the two checksum
    // bytes. This cannot separate a wrong CRC from a compensating encoder
    // bug, but it is the only direct crosscheck of the CRC parameters.
    ctx.eq_u64("crc16_typescript_executed", u64::from(crc16::crc16(&tag)));

    literal_leg(ctx);
}

/// `WotsAddress.addrFromWots` against `addr_from_wots`.
///
/// Both read the same 2144-byte sidecar. `ctx.blob` checks its length against
/// the vector's own `input_len` before handing the bytes over, so a truncated
/// or swapped sidecar fails as a sidecar rather than as a mismatched address.
fn ts_addr_from_wots(ctx: &mut Ctx) {
    let pk_bytes = ctx.blob("input");

    // The implementations differ on an input that is not WOTS_PK_LEN long:
    // `addrFromWots` returns null, while `addr_from_wots` hashes whatever it
    // is given (hence C6). Checked as its own shape, apart from the value
    // comparison below.
    if pk_bytes.len() != PK_LEN {
        ctx.eq_bool("returned_null", true);
        ctx.eq_opt_str("crosscheck_typescript_executed", None);
        ctx.eq_u64("input_len", pk_bytes.len() as u64);
        literal_leg(ctx);
        return;
    }

    let pk: [u8; PK_LEN] = pk_bytes.as_slice().try_into().unwrap_or_else(|_| {
        panic!(
            "{}: {} sidecar is {} bytes, expected WOTS_PK_LEN = {PK_LEN}",
            ctx.file,
            ctx.id,
            pk_bytes.len()
        )
    });

    let from_c = hex(&addr::from_wots(&pk));
    ctx.eq_str("crosscheck_typescript_executed", &from_c);
    ctx.eq_u64("input_len", pk_bytes.len() as u64);
    literal_leg(ctx);
}

/// `WOTS.wots_pkgen` + `WotsAddress.addrFromWots` against this crate's
/// whole seed → pk → address path.
///
/// Seven vectors, `C4-A1..A7`, each carrying a secret, a public seed and an
/// `adrs`, replayed end to end by two implementations sharing no code. Six
/// of the seven have an all-zero `adrs`, whose byte image is the same under
/// any endianness.
///
/// `adrs_byte_image` is the in-memory little-endian image of the eight
/// words, the form the TypeScript's `addr: ByteArray` parameter takes. It is
/// not `Adrs::to_bytes`, the big-endian serialization fed to `prf`. The
/// generator builds the image with a little-endian `ByteBuffer` and this
/// side with `u32::to_le_bytes`; a big-endian image gives a different
/// address, so `CX-C4-A5` checks that both sides agree on the
/// representation.
fn ts_pkgen_to_addr(ctx: &mut Ctx) {
    let secret = Secret::<SEED_LEN>::new(ctx.arr("input_secret"));
    let pub_seed: [u8; SEED_LEN] = ctx.arr("input_pub_seed");
    let words = ctx.words("input_adrs_in_words");

    let all_zero = words.iter().all(|&w| w == 0);
    ctx.eq_bool("adrs_all_zero", all_zero);

    // The little-endian memory image, built independently of the generator.
    let mut image = [0u8; 32];
    for (i, w) in words.iter().enumerate() {
        image[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    ctx.eq_bytes("adrs_byte_image", &image);

    // The description field must match the branch that ran.
    let representation = ctx.str_("adrs_representation");
    let claims_zero = representation.starts_with("all-zero");
    assert_eq!(
        claims_zero, all_zero,
        "{}: {} has adrs_all_zero = {all_zero} but adrs_representation says \
         {representation:?}. The two describe the same branch of the generator \
         and must agree; a representation string that outlives its case is how \
         a reader learns the wrong thing about which endianness ran.",
        ctx.file, ctx.id
    );

    let mut adrs = Adrs(words);
    let pk = wots::pkgen(&secret, &pub_seed, &mut adrs);
    ctx.eq_u64("input_pk_len", pk.len() as u64);

    ctx.eq_str(
        "crosscheck_typescript_executed",
        &hex(&addr::from_wots(&pk)),
    );
    literal_leg(ctx);
}

/// `WotsAddress.addrFromImplicit` against `addr_from_implicit`.
///
/// Both halves of the 40-byte address receive the 20-byte tag; an
/// implementation that left the hash half zero would still have the right
/// length and prefix.
fn ts_addr_from_implicit(ctx: &mut Ctx) {
    let tag: [u8; 20] = ctx.arr("input_hex");
    ctx.eq_u64("input_len", tag.len() as u64);
    ctx.eq_str(
        "crosscheck_typescript_executed",
        &hex(&addr::from_implicit(&tag)),
    );
    literal_leg(ctx);
}

/// `WotsAddress.addrHashGenerate` against `addr_hash_generate`.
///
/// Both sides compose two published hashes, so a disagreement here is about
/// the composition. `ts_standalone_digest` crosschecks the hashes
/// separately.
fn ts_addr_hash_generate(ctx: &mut Ctx) {
    let input = if ctx.has("input_file") {
        ctx.blob("input")
    } else {
        ctx.hex("input_hex")
    };
    ctx.eq_u64("input_len", input.len() as u64);
    ctx.eq_str(
        "crosscheck_typescript_executed",
        &hex(&addr::hash_generate(&input)),
    );
    literal_leg(ctx);
}

/// `MochimoHasher.hashWith` against crypto-c's `sha3` and `ripemd160`.
///
/// The algorithm is read from the fixture, not the vector id; an unknown
/// algorithm fails.
fn ts_standalone_digest(ctx: &mut Ctx) {
    let input = ctx.hex("input_hex");
    ctx.eq_u64("input_len", input.len() as u64);

    let from_c = match ctx.str_("algorithm") {
        "sha3-512" => hex(&addr::sha3_512(&input)),
        "ripemd160" => {
            // Inputs with `len % 64 >= 56` are a class the reference cannot
            // compute; they belong to group RX, so they are refused here
            // rather than compared under the wrong claim.
            assert!(
                input.len() % 64 < 56,
                "{}: {} carries {} bytes, which is in the reference-faulting \
                 class (len % 64 >= 56). addr::ripemd160 answers that class \
                 with native, so replaying it here would \
                 crosscheck native against the TypeScript while claiming the C \
                 was compared. The class belongs to \
                 fixtures/group_rx_ripemd.json, which says whose answer it is.",
                ctx.file,
                ctx.id,
                input.len()
            );
            hex(&addr::ripemd160(&input))
        }
        other => panic!(
            "{}: {} names algorithm {other:?}, which this handler cannot reach \
             in the reference. Add it rather than letting the vector replay \
             nothing.",
            ctx.file, ctx.id
        ),
    };
    ctx.eq_str("crosscheck_typescript_executed", &from_c);
    literal_leg(ctx);
}

/// `bs58.encode` against `base58_encode`, at the two lengths that are not a
/// 20-byte tag.
///
/// `addrTagToBase58` throws on any length but 20, so the encoder is called
/// directly. These are the only Base58 vectors away from the tag length.
fn ts_base58_encode(ctx: &mut Ctx) {
    for (input_key, executed_key) in [
        ("input_hex_21", "crosscheck_typescript_executed"),
        ("input_hex_23", "crosscheck_typescript_executed_23"),
    ] {
        let input = ctx.hex(input_key);
        let from_c = base58::encode(&input)
            .unwrap_or_else(|e| panic!("{}: {} base58_encode failed: {e:?}", ctx.file, ctx.id));
        ctx.eq_str(executed_key, &from_c);
    }
    literal_leg(ctx);
}

/// `bs58.decode` and the two `TagUtils` entry points, against `base58_decode`.
///
/// For an all-'1' string the reference's `base58_decode` computes a negative
/// copy length and calls `memcpy` with `SIZE_MAX` (`C-base58-degenerate`),
/// so it is not called on that class; this vector records the second
/// implementation's answer instead. Elsewhere the two are compared.
fn ts_base58_decode(ctx: &mut Ctx) {
    let input = ctx.str_("input_base58").to_string();
    ctx.eq_u64("input_len", input.len() as u64);

    let ts_decoded = ctx.opt_str("crosscheck_typescript_executed").map(str::to_string);
    let ts_ok = ctx.bool_("decode_ok");
    assert_eq!(
        ts_ok,
        ts_decoded.is_some(),
        "{}: {} says decode_ok = {ts_ok} but the executed value is {}",
        ctx.file,
        ctx.id,
        if ts_decoded.is_some() { "present" } else { "null" }
    );
    if ts_ok {
        ctx.eq_u64(
            "decoded_len",
            (ts_decoded.as_ref().map_or(0, String::len) / 2) as u64,
        );
    } else {
        // The exception type is recorded but has no reference counterpart:
        // the reference signals failure by return code and errno.
        assert!(
            !ctx.str_("decode_threw").is_empty(),
            "{}: {} failed to decode but names no exception",
            ctx.file,
            ctx.id
        );
    }

    // `validateBase58Tag` and `base58ToAddrTag` over the same string,
    // recorded even where they reject: which inputs a codec refuses is part
    // of its behaviour.
    let validates = ctx.bool_("validate_base58_tag");
    let tag_out = ctx.opt_str("base58_to_addr_tag").map(str::to_string);
    if ctx.has("base58_to_addr_tag_threw") {
        assert!(
            tag_out.is_none(),
            "{}: {} records both a base58ToAddrTag result and a throw",
            ctx.file,
            ctx.id
        );
        assert!(!ctx.str_("base58_to_addr_tag_threw").is_empty());
    }
    if validates {
        assert!(
            tag_out.is_some(),
            "{}: {} says validateBase58Tag accepted {input:?} while \
             base58ToAddrTag produced nothing. Both go through the same \
             22-byte decode, so one accepting and the other not is a \
             contradiction inside the TypeScript rather than a disagreement \
             with the C.",
            ctx.file,
            ctx.id
        );
    }

    // The reference leg. Group C carries the decoded bytes where the
    // reference could be called, and records why where it could not.
    let src = Fixture::load(ctx.str_("crosschecks_file"));
    let subject = src.vector_by_id(ctx.str_("crosschecks_vector"));

    if let Some(from_c) = subject.get("out").and_then(|x| x.as_str()) {
        // The reference decoded it: compare the bytes.
        let ts = ts_decoded.as_deref().unwrap_or_else(|| {
            panic!(
                "{}: {} -- the C decoded this string but the TypeScript \
                 rejected it. That is a genuine disagreement about the codec's \
                 domain and must be reported, not reconciled here.",
                ctx.file, ctx.id
            )
        });
        assert_eq!(
            ts, from_c,
            "{}: {} -- base58_decode and bs58.decode returned different bytes \
             for {input:?}. This is the disagreement group CX exists to \
             produce. Report it; do not decide which side is right.",
            ctx.file, ctx.id
        );
    } else if let Some(rc) = subject.get("rc").and_then(serde_json::Value::as_i64) {
        // The reference rejected the string; the TypeScript must not accept
        // it as a valid tag. Compared at "is this a valid 22-byte tag", not
        // "did decode throw": `bs58.decode("")` returns an empty array where
        // the reference returns an error.
        assert_ne!(
            rc, 0,
            "{}: {} has no `out` and rc == 0, so the C neither failed nor \
             produced output. The vector's shape changed and this handler is \
             reading it wrong.",
            ctx.file, ctx.id
        );
        assert!(
            !validates,
            "{}: {} -- the C rejected {input:?} with rc {rc}, but \
             validateBase58Tag accepted it. The two implementations disagree \
             about which strings are valid tags, which is exactly the kind of \
             disagreement this group exists to surface. Report it.",
            ctx.file, ctx.id
        );
    } else {
        // Neither an output nor a return code: the reference was not called
        // because calling it faults (group C's `decode_not_called`).
        ctx.mark(Disposition::NotCalled);
    }

    literal_leg(ctx);
}

/// Group RX: `@noble/hashes` RIPEMD-160 against the port's own.
///
/// There is no reference leg: the reference `ripemd160` faults on this input
/// class. The recorded `@noble/hashes` digest is compared with
/// `mochimo_crypto::addr::ripemd160` and checked for internal consistency.
fn rx_ripemd160(ctx: &mut Ctx) {
    let input = ctx.hex("in");
    ctx.eq_u64("in_len", input.len() as u64);
    ctx.eq_u64("block_residue", (input.len() % 64) as u64);
    ctx.eq_bool("reference_can_compute", false);

    assert!(
        input.len() % 64 >= 56,
        "{}: {} is {} bytes, residue {} -- OUTSIDE the faulting class. This \
         group's entire premise is that the reference cannot answer here; a \
         vector the reference *can* answer belongs in group C, where it would \
         be crosschecked against the C instead of standing on one \
         implementation.",
        ctx.file,
        ctx.id,
        input.len(),
        input.len() % 64
    );

    let digest = ctx.str_("ripemd160").to_string();
    // The native RIPEMD-160 handles this class; the reference does not.
    ctx.eq_str("ripemd160", &hex(&addr::ripemd160(&input)));
    assert_eq!(
        digest.len(),
        40,
        "{}: {} digest is {} hex chars, not the 40 RIPEMD-160 produces",
        ctx.file,
        ctx.id,
        digest.len()
    );

    // The one vector with a published expected value. The generator checks
    // it at generation time; this checks the committed fixture.
    if ctx.has("published_digest") {
        ctx.eq_str("published_digest", &digest);
        ctx.eq_bool("published_digest_matches_executed", true);
        let ascii = ctx.str_("in_ascii").to_string();
        assert_eq!(
            ascii.as_bytes(),
            input.as_slice(),
            "{}: {} in_ascii and in disagree about the input bytes",
            ctx.file,
            ctx.id
        );
    }
}

/// Lowercase hex, matching what the generators emit.
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn base58_decode(ctx: &mut Ctx) {
    let input = ctx.str_("in").to_string();

    // The fixture records when the reference was not called: an all-'1'
    // string faults inside base58_decode (see C-base58-degenerate). The
    // length probe on the same input is safe and is replayed.
    if ctx.has("decode_not_called") && ctx.bool_("decode_not_called") {
        ctx.mark(Disposition::NotCalled);
        assert!(
            ctx.has("decode_not_called_reason"),
            "{}: {} claims decode_not_called without a reason",
            ctx.file,
            ctx.id
        );
        let probe = base58::decode_probe_len(&input).expect("base58_decode probe failed");
        ctx.eq_u64("probe_len", reference_decode_probe(&input, probe) as u64);
        return;
    }

    match base58::decode(&input) {
        Ok(out) => {
            ctx.eq_i64("rc", 0);
            let probe = base58::decode_probe_len(&input).expect("base58_decode probe failed");
            ctx.eq_u64("probe_len", reference_decode_probe(&input, probe) as u64);
            ctx.eq_bytes("out", &out);
            // C12 additionally recomputes the CRC over the decoded tag to show
            // that the codec carries no checksum of its own.
            if ctx.has("recomputed_crc16") {
                assert!(out.len() >= 20);
                let recomputed = crc16::crc16(&out[..20]);
                ctx.eq_u64("recomputed_crc16", recomputed as u64);
                // A corrupted final character decodes cleanly; only a CRC
                // check catches it. The last two decoded bytes are the
                // embedded CRC.
                if ctx.has("checksum_would_reject") {
                    assert!(out.len() >= 22);
                    let embedded = bytes::get16(&[out[20], out[21]]);
                    ctx.eq_bool("checksum_would_reject", embedded != recomputed);
                }
            }
        }
        Err(mochimo_crypto::Error::ReferenceErrno { rc, errno, .. }) => {
            ctx.eq_i64("rc", rc as i64);
            ctx.eq_i64("errno", errno as i64);
        }
        // The native decoder refuses with the same return code and no errno;
        // the recorded errno is the reference's and is read, not recomputed.
        Err(mochimo_crypto::Error::Reference { rc, .. }) => {
            ctx.eq_i64("rc", rc as i64);
            let _ = ctx.touch("errno");
        }
        Err(e) => panic!("{}: {} unexpected error {e}", ctx.file, ctx.id),
    }
}

/// C-base58-degenerate. The reference's `base58_decode` with a non-NULL
/// `out` reaches a `memcpy` length of `(size_t)(-1)` and faults. Its length
/// probe is safe, and the probe's value is the defect the vector records: it
/// returns 21 for a 22-byte payload.
fn base58_degenerate(ctx: &mut Ctx) {
    ctx.mark(Disposition::NotCalled);
    let input = ctx.str_("in").to_string();
    let probe = base58::decode_probe_len(&input).expect("base58_decode probe failed");
    ctx.eq_u64("reference_probe_len", reference_decode_probe(&input, probe) as u64);

    let correct = ctx.u64_("correct_len");
    // This crate's probe reports the true length; the recorded value is the
    // reference's, which under-reports by one on this class.
    assert!(
        reference_decode_probe(&input, probe) as u64 != correct,
        "{}: the recorded probe no longer under-reports against the true length; the \
         reference defect this vector documents would have been fixed upstream, which \
         is a fixture change, not a harness change",
        ctx.id
    );
}

/// The reference's Base58 length probe, reconstructed from this crate's. The
/// reference under-reports by one for a non-empty all-zero encode input and
/// for an all-'1' decode input, and agrees everywhere else. The recorded
/// values are the reference's, so comparisons use this rule (stated in the
/// specification).
fn reference_encode_probe(input: &[u8], ours: usize) -> usize {
    if !input.is_empty() && input.iter().all(|&b| b == 0) {
        ours - 1
    } else {
        ours
    }
}

fn reference_decode_probe(input: &str, ours: usize) -> usize {
    if !input.is_empty() && input.bytes().all(|b| b == b'1') {
        ours - 1
    } else {
        ours
    }
}

fn base58_lengths(ctx: &mut Ctx) {
    for (input_key, b58_key, probe_key) in [
        ("in21", "base58_21", "decode_probe_len_21"),
        ("in23", "base58_23", "decode_probe_len_23"),
    ] {
        let input = ctx.hex(input_key);
        let encoded = base58::encode(&input).expect("base58_encode failed");
        ctx.eq_str(b58_key, &encoded);
        let probe = base58::decode_probe_len(&encoded).expect("base58_decode probe failed");
        ctx.eq_u64(probe_key, reference_decode_probe(&encoded, probe) as u64);
    }
}

// --- group D, the part that needs no TXENTRY ----------------------------

/// The three `D-acc-` vectors: reads of a bare four-byte options array
/// through the `types.h` accessor macros.
fn options_accessors(ctx: &mut Ctx) {
    let opts: [u8; 4] = ctx.arr("opts");
    ctx.eq_u64("txdat_type", tx::dat_type(&opts) as u64);
    ctx.eq_u64("txdsa_type", tx::dsa_type(&opts) as u64);
    ctx.eq_u64("mdst_count", tx::mdst_count(&opts) as u64);
}

// --- group D, the transaction core --------------------------------------
//
// Every transaction-core source is replayed by `reference_verdicts_native`
// below, which round-trips the wire image natively, checks the recorded
// layout, and marks the validator verdicts as not called.

/// The `source` strings the transaction-core replay serves.
///
/// `D8` records `put64` and `D6`/`D7` record `MDST_COUNT`, because the
/// `source` names the property each vector pins; all are the same replay.
/// `replay()` routes this list and `group_d_core_census` counts over it, so
/// the two sets cannot diverge.
const TX_CORE_SOURCES: [&str; 3] = [
    "tx__init() @ reference/mochimo-core/src/tx.c:119",
    "MDST_COUNT() @ reference/mochimo-core/src/types.h:176",
    "put64() @ reference/mochimo-core/include/extended-c/src/extmath.c",
];

// --- group E ------------------------------------------------------------

fn put16_framing(ctx: &mut Ctx) {
    let network = ctx.u64_("TXNETWORK") as u16;
    ctx.eq_bytes("network_bytes", &bytes::put16(network));
    let eot = ctx.u64_("TXEOT") as u16;
    ctx.eq_bytes("trailer_bytes", &bytes::put16(eot));
}

fn put16_roundtrip(ctx: &mut Ctx) {
    let pversion = ctx.constant(&["PVERSION"]) as u16;
    let encoded = bytes::put16(pversion);
    ctx.eq_bytes("pversion_bytes", &encoded);
    ctx.eq_u64("pversion_roundtrip", bytes::get16(&encoded) as u64);

    ctx.eq_bytes(
        "port1_bytes",
        &bytes::put16(ctx.constant(&["PORT1"]) as u16),
    );
    ctx.eq_bytes(
        "port2_bytes",
        &bytes::put16(ctx.constant(&["PORT2"]) as u16),
    );
    ctx.eq_bytes(
        "op_tx_bytes",
        &bytes::put16(ctx.constant(&["opcodes", "OP_TX"]) as u16),
    );
}

fn crc16_vector(ctx: &mut Ctx) {
    let input = ctx.hex("in");
    assert_eq!(
        input.len(),
        ctx.u64_("in_len") as usize,
        "{}: {} `in` length disagrees with `in_len`",
        ctx.file,
        ctx.id
    );
    ctx.eq_u64("crc16", crc16::crc16(&input) as u64);
}

// =======================================================================
// Tests
// =======================================================================

#[test]
fn manifest_and_disk_agree() {
    let manifest = support::load_manifest();
    let on_disk: BTreeSet<String> = support::json_files_on_disk().into_iter().collect();
    let listed: BTreeSet<String> = manifest.iter().map(|g| g.file.clone()).collect();

    let unlisted: Vec<&String> = on_disk.difference(&listed).collect();
    let missing: Vec<&String> = listed.difference(&on_disk).collect();

    assert!(
        unlisted.is_empty(),
        "fixture files on disk but absent from manifest.toml: {unlisted:?}\n\
         Every fixture must be listed, active or deferred, so nothing goes unverified in silence."
    );
    assert!(
        missing.is_empty(),
        "manifest.toml lists files that do not exist: {missing:?}"
    );
    assert!(
        !listed.is_empty(),
        "manifest.toml lists no fixture files at all"
    );
}

#[test]
fn manifest_counts_match_the_files() {
    let mut total = 0usize;
    for g in support::load_manifest() {
        let fx = Fixture::load(&g.file);
        let vectors = fx.vectors().len();
        let sources = fx.sources().len();
        assert_eq!(
            vectors, g.vectors,
            "{}: manifest says {} vectors, file has {vectors}",
            g.file, g.vectors
        );
        assert_eq!(
            sources, g.sources,
            "{}: manifest says {} distinct sources, file has {sources}",
            g.file, g.sources
        );
        total += vectors;
    }
    // The loop sums the manifest's per-group figures, so the total is also
    // written independently to give the comparison something to fail on.
    assert_eq!(total, TOTAL_P14, "corpus vector count changed");
}

#[test]
fn constants_match_the_reference() {
    use mochimo_crypto::consts as k;
    let fx = Fixture::load("group_a_keygen.json");
    let c = fx
        .root
        .get("constants")
        .expect("group_a_keygen.json has no constants block");
    let want = |name: &str| -> usize {
        c.get(name)
            .and_then(|v| v.as_u64())
            .unwrap_or_else(|| panic!("constants block has no `{name}`")) as usize
    };

    // Each value was printed from the reference's macro when the fixtures
    // were generated. A disagreeing Rust constant fails here rather than
    // inside a 2144-byte diff.
    assert_eq!(k::PARAMSN, want("PARAMSN"));
    assert_eq!(k::WOTSW, want("WOTSW"));
    assert_eq!(k::WOTSLOGW, want("WOTSLOGW"));
    assert_eq!(k::WOTSLEN1, want("WOTSLEN1"));
    assert_eq!(k::WOTSLEN2, want("WOTSLEN2"));
    assert_eq!(k::WOTSLEN, want("WOTSLEN"));
    assert_eq!(k::WOTSSIGBYTES, want("WOTSSIGBYTES"));
    assert_eq!(k::WOTS_ADDR_LEN, want("WOTS_ADDR_LEN"));
    assert_eq!(k::ADDR_LEN, want("ADDR_LEN"));
    assert_eq!(k::ADDR_TAG_LEN, want("ADDR_TAG_LEN"));
    assert_eq!(k::ADDR_HASH_LEN, want("ADDR_HASH_LEN"));
    assert_eq!(k::SHA256LEN, want("SHA256LEN"));
    assert_eq!(k::SHA3LEN512, want("SHA3LEN512"));
    assert_eq!(k::RIPEMDLEN160, want("RIPEMDLEN160"));
    assert_eq!(k::CRC16LEN, want("CRC16LEN"));
    assert_eq!(k::PK_LEN, want("WOTS_PK_LEN"));
    assert_eq!(k::SIG_LEN, want("WOTS_SIG_LEN"));
}

#[test]
fn active_groups_replay() {
    let manifest = support::load_manifest();
    let mut failures: Vec<String> = Vec::new();
    let mut tally: BTreeMap<Disposition, usize> = BTreeMap::new();
    let mut replayed_total = 0usize;
    let mut fields_total = 0usize;

    for g in manifest.iter().filter(|g| g.is_active()) {
        let fx = Fixture::load(&g.file);
        let vectors = fx.vectors();
        let mut in_group = 0usize;

        for v in &vectors {
            let mut ctx = Ctx::new(&fx.file, &fx.root, v);
            replay(&mut ctx);
            *tally.entry(ctx.disposition).or_default() += 1;
            in_group += 1;
            fields_total += ctx.fields_read();
            failures.extend(ctx.into_failures());
        }

        assert_eq!(
            in_group, g.vectors,
            "{}: replayed {in_group} vectors, manifest says {}",
            g.file, g.vectors
        );
        replayed_total += in_group;
        println!("  group {} ({}): {in_group} vectors replayed", g.id, g.name);
    }

    for g in manifest.iter().filter(|g| !g.is_active()) {
        if g.activated.is_empty() {
            println!(
                "  group {} ({}): SKIPPED — {} vectors deferred, {} distinct sources unbound",
                g.id, g.name, g.vectors, g.sources
            );
            continue;
        }

        let fx = Fixture::load(&g.file);
        let mut ran = 0usize;
        for id in &g.activated {
            let v = fx.vector_by_id(id);
            let mut ctx = Ctx::new(&fx.file, &fx.root, v);
            replay(&mut ctx);
            *tally.entry(ctx.disposition).or_default() += 1;
            ran += 1;
            fields_total += ctx.fields_read();
            failures.extend(ctx.into_failures());
        }

        // The activated/deferred partition, checked against the file's ids:
        // an activated id that no longer exists already failed in
        // `vector_by_id`, and a vector the manifest forgot lands in
        // `deferred` and breaks the count.
        let activated: BTreeSet<&str> = g.activated.iter().map(String::as_str).collect();
        let all = fx.vector_ids();
        let deferred = all.iter().filter(|i| !activated.contains(i.as_str())).count();
        assert_eq!(
            ran, g.activated.len(),
            "{}: ran {ran} activated vectors, manifest lists {}",
            g.file,
            g.activated.len()
        );
        assert_eq!(
            deferred, g.still_deferred,
            "{}: the file leaves {deferred} vectors unactivated but the manifest \
             says {}. The manifest states that number rather than deriving it, \
             so this is the check that an id dropped from `activated` cannot \
             quietly stop being replayed.",
            g.file, g.still_deferred
        );

        replayed_total += ran;
        println!(
            "  group {} ({}): DEFERRED — {ran} activated, {deferred} still deferred, \
             {} distinct sources",
            g.id, g.name, g.sources
        );
    }

    assert!(
        replayed_total > 0,
        "no active vectors were replayed; a KAT run must never pass by iterating nothing"
    );
    println!("\n  {replayed_total} vectors replayed in total");
    println!("  {fields_total} fixture fields read and covered");
    for (d, n) in &tally {
        println!("    {d:?}: {n}");
    }

    print_pending(&manifest);

    if !failures.is_empty() {
        panic!(
            "\n\n{} KAT failure(s):\n\n{}\n",
            failures.len(),
            failures.join("\n\n")
        );
    }

    // A floor for the coverage check, asserted after the failure report so a
    // real coverage failure is reported first. It catches the case where
    // nothing is uncovered because nothing was recorded. A floor rather than
    // an exact count, which would change with every added vector.
    assert!(
        fields_total >= 400,
        "coverage recorded only {fields_total} field reads across {replayed_total} \
         vectors. The accessors are meant to funnel through Ctx::get, so a tally \
         this low means fields are being read without being recorded and the \
         coverage check is passing because it sees nothing."
    );
}

#[test]
fn base58_corpus_replays() {
    let fx = Fixture::load("group_c_addr.json");
    let corpus = fx
        .root
        .get("crc16_base58_corpus")
        .expect("group_c_addr.json has no crc16_base58_corpus");
    let entries = corpus
        .get("entries")
        .and_then(|e| e.as_array())
        .expect("corpus has no entries array");
    let count = corpus
        .get("count")
        .and_then(|c| c.as_u64())
        .expect("corpus has no count") as usize;
    assert_eq!(entries.len(), count, "corpus count disagrees with entries");
    assert!(count > 0, "corpus is empty");

    let mut failures = Vec::new();
    for e in entries {
        // Corpus entries carry `i` rather than `id`/`source`; label them so a
        // failure points at the right entry.
        let i = e.get("i").and_then(|x| x.as_u64()).expect("entry has no `i`");
        let source = corpus
            .get("crc16_source")
            .and_then(|s| s.as_str())
            .unwrap_or("crc16_base58_corpus")
            .to_string();
        let mut ctx = Ctx::labelled(
            &fx.file,
            &fx.root,
            e,
            format!("crc16_base58_corpus[{i}]"),
            source,
        );

        let tag: [u8; 20] = ctx.arr("tag");
        let sum = crc16::crc16(&tag);
        ctx.eq_u64("crc16", sum as u64);

        let mut tag22 = [0u8; 22];
        tag22[..20].copy_from_slice(&tag);
        tag22[20..].copy_from_slice(&bytes::put16(sum));
        ctx.eq_str(
            "base58",
            &base58::encode(&tag22).expect("base58_encode failed"),
        );

        failures.extend(ctx.into_failures());
    }

    println!("  {count} crc16/base58 corpus entries replayed");
    if !failures.is_empty() {
        panic!(
            "\n\n{} corpus failure(s):\n\n{}\n",
            failures.len(),
            failures.join("\n\n")
        );
    }
}

#[test]
fn derived_inputs_are_exactly_as_expected() {
    let expected: BTreeSet<&str> = DERIVED_INPUT_IDS.iter().copied().collect();
    let mut not_called: BTreeSet<String> = NOT_CALLED_IDS.iter().map(|s| s.to_string()).collect();
    // Group D vectors recorded from the reference validators are replayed by
    // `reference_verdicts_native` and marked not called. Selected by source,
    // the same predicate the dispatch uses.
    {
        let d = Fixture::load("group_d_tx.json");
        for v in d.vectors() {
            let src = v.get("source").and_then(|s| s.as_str()).unwrap_or("");
            if is_reference_only_source(src) {
                not_called.insert(v["id"].as_str().expect("id").to_string());
            }
        }
    }
    let not_called: BTreeSet<&str> = not_called.iter().map(String::as_str).collect();

    let mut derived_found: BTreeSet<String> = BTreeSet::new();
    let mut not_called_found: BTreeSet<String> = BTreeSet::new();

    // Everything the suite replays: every vector of active groups plus the
    // activated vectors of deferred ones.
    for g in support::load_manifest() {
        let fx = Fixture::load(&g.file);
        let ids = if g.is_active() {
            fx.vector_ids()
        } else {
            g.activated.clone()
        };
        for id in &ids {
            let v = fx.vector_by_id(id);
            let mut ctx = Ctx::new(&fx.file, &fx.root, v);
            replay(&mut ctx);
            match ctx.disposition {
                Disposition::DerivedInput => {
                    derived_found.insert(ctx.id.clone());
                }
                Disposition::NotCalled => {
                    not_called_found.insert(ctx.id.clone());
                }
                Disposition::Replayed => {}
            }
        }
    }

    let derived_found: BTreeSet<&str> = derived_found.iter().map(String::as_str).collect();
    let not_called_found: BTreeSet<&str> = not_called_found.iter().map(String::as_str).collect();

    assert_eq!(
        derived_found, expected,
        "the set of vectors whose inputs are reconstructed from prose changed.\n\
         A new one appearing means a fixture grew a prose input; one disappearing \
         means the fixture now records that input as a field and this list should shrink."
    );
    assert_eq!(
        not_called_found, not_called,
        "the set of vectors that do not invoke the reference changed.\n\
         Two of the ids are the crosscheck vectors for the same two inputs: the \
         reference cannot be called on an all-'1' string in either file, and \
         the CX side is where a second implementation's answer lives. \
         Another is F-ascii-control, the dead-path control this crate has no \
         code for. A SIXTH id appearing means some vector stopped calling \
         the reference without anybody deciding that it should; one \
         disappearing means a handler started computing something it used \
         to declare it could not."
    );

    for id in WEAKLY_CHECKED_IDS {
        assert!(
            expected.contains(id),
            "{id} is listed as weakly checked but not as derived-input"
        );
    }
}

// =======================================================================
// Deferred debt
// =======================================================================

/// Prints known fixture-generator work items, filed on the group they concern,
/// as one block in every run. The affected vectors still run; this is not a
/// skip list.
fn print_pending(manifest: &[support::Group]) {
    let total: usize = manifest.iter().map(|g| g.pending.len()).sum();
    if total == 0 {
        return;
    }
    println!("\n  PENDING — {total} fixture-generator item(s) owed:");
    for g in manifest {
        for item in &g.pending {
            println!("    [group {}] {}", g.id, wrap(item, 72, 14));
        }
    }
}

/// Soft-wraps at `width`, indenting continuation lines by `indent`.
fn wrap(text: &str, width: usize, indent: usize) -> String {
    let pad = " ".repeat(indent);
    let mut out = String::new();
    let mut col = 0usize;
    for word in text.split_whitespace() {
        if col > 0 && col + 1 + word.len() > width {
            out.push('\n');
            out.push_str(&pad);
            col = 0;
        } else if col > 0 {
            out.push(' ');
            col += 1;
        }
        out.push_str(word);
        col += word.len();
    }
    out
}

/// No handler takes an input from a vector's prose description field; every
/// input must be a recorded field.
///
/// Reads the harness's own source, since the property is about the handlers.
/// The needle is assembled at runtime so this test does not match itself.
#[test]
fn no_input_is_reconstructed_from_prose() {
    let src = include_str!("kat.rs");
    let key = "note";
    let forbidden = [format!("(\"{key}\")"), format!("[\"{key}\"]")];

    let hits: Vec<(usize, &str)> = src
        .lines()
        .enumerate()
        .filter(|(_, l)| forbidden.iter().any(|f| l.contains(f.as_str())))
        .map(|(i, l)| (i + 1, l.trim()))
        .collect();

    assert!(
        hits.is_empty(),
        "the harness reads the `{key}` field at {hits:#?}.\n\
         `{key}` is prose. An input taken from it is a guess dressed as a \
         replay, and the one vector where that guess could not be detected \
         (B-adrs-invariance) once passed in the suite without checking \
         anything. If a vector's input is not recorded as a field, fix the \
         generator -- do not parse the sentence."
    );
}

// =======================================================================
// The transaction-core census
// =======================================================================

/// How many transaction-core vectors carry each field that is not universal
/// among them.
///
/// `Ctx::check_coverage` catches a field that is present and unread, but not
/// a field that is absent. `tx_core` gates every non-universal field on
/// `has()`, so if the generator lost a call site the regenerated vector would
/// lack the field and replay green. This census states a count per field and
/// checks it against the corpus: coverage catches a field the handler did not
/// handle; this catches a field the handler was never offered.
///
/// The counts follow `group_d_tx.c`'s call sites: which vectors go through
/// `tx_emit` (and so carry a wire sidecar; `D6`/`D7` do not), call
/// `mdst_val` or `tx_val__wots`, fail with an `errno`, or record
/// `blk_to_live_*` (`D8`, `D18`, the `D9`s) and `rule_not_evaluated` (the
/// `D9`s and `D17`). `D16`/`D16-badref` (a non-zero `MDST::ref`), `D17` (a
/// `chg_addr` whose halves differ), `D18` (distinct asymmetric 64-bit header
/// values) and `D19-totals`/`D19-fees` cover the remaining shape space; the
/// Ds12 sweep adds 22 signed, validated images.
const TX_CORE_CENSUS: &[(&str, usize)] = &[
    ("wire_file", 47),
    ("wire_len", 47),
    ("mdst_val_rc", 44),
    ("mdst_val_rc_name", 44),
    ("tx_val__wots_rc", 40),
    ("tx_val__wots_rc_name", 40),
    ("mdst_val_errno", 8),
    ("mdst_val_errno_name", 8),
    ("mdst_val_errno_text", 8),
    ("blk_to_live_bytes", 5),
    ("blk_to_live_value", 4),
    ("rule_not_evaluated", 4),
    ("amount0_bytes", 1),
    ("amount0_value", 1),
    ("amount1_bytes", 1),
    ("amount1_value", 1),
    // `D8` records the bytes; `D18` the bytes and the value, which is what
    // tests byte order.
    ("send_total_bytes", 2),
    ("send_total_value", 1),
    ("change_total_bytes", 2),
    ("change_total_value", 1),
    ("fee_total_bytes", 2),
    ("fee_total_value", 1),
    ("sizeof_txentry_buffer", 1),
    ("tx_sz_equals_buffer_size", 1),
    // `ref0`/`ref1` are on both `D16` (four destinations) and `D16-badref`
    // (two); `ref2`/`ref3` on `D16` alone.
    ("ref0_bytes", 2),
    ("ref1_bytes", 2),
    ("ref2_bytes", 1),
    ("ref3_bytes", 1),
    ("chg_addr_bytes", 1),
    ("src_chg_tag_equal", 1),
    ("src_chg_hash_equal", 1),
    ("chg_tag_half_equals_hash_half", 1),
    ("fee_minimum_destinations", 1),
];

/// The number of fields every transaction-core vector carries: the 35-field
/// layout core plus the four metadata keys `id`, `note`, `falsifies`,
/// `source`.
///
/// Stated so a change to the core is reported here directly.
const TX_CORE_UNIVERSAL_KEYS: usize = 39;

#[test]
fn group_d_core_census() {
    let fx = Fixture::load("group_d_tx.json");

    let core: Vec<&serde_json::Value> = fx
        .vectors()
        .into_iter()
        .filter(|v| {
            v.get("source")
                .and_then(|s| s.as_str())
                .is_some_and(|s| TX_CORE_SOURCES.contains(&s))
        })
        .collect();

    // Exactly the vectors `replay()` routes here, selected by the same
    // constant.
    assert_eq!(
        core.len(),
        49,
        "the transaction-core sources {TX_CORE_SOURCES:?} now select {} vectors, not 49. \
         Either a vector was added or removed upstream, or a source string moved; \
         both change what the census below describes. The 49 include the six \
         that close the shape-space gap and the 22-count Ds12 sweep.",
        core.len()
    );

    let keys = |v: &serde_json::Value| -> BTreeSet<String> {
        v.as_object()
            .expect("a vector is not a JSON object")
            .keys()
            .cloned()
            .collect()
    };

    let mut universal = keys(core[0]);
    for v in &core {
        universal = universal.intersection(&keys(v)).cloned().collect();
    }
    assert_eq!(
        universal.len(),
        TX_CORE_UNIVERSAL_KEYS,
        "the {} transaction-core vectors now share {} keys, not {TX_CORE_UNIVERSAL_KEYS}. \
         The `tx_core` handler mirrors a 35-field core plus four metadata keys; a change here \
         means the core itself moved.\n  shared: {universal:?}",
        core.len(),
        universal.len()
    );

    let mut found: BTreeMap<&str, usize> = BTreeMap::new();
    for v in &core {
        for k in keys(v) {
            if !universal.contains(&k) {
                // Borrow the name from the census; an unlisted key panics.
                let name = TX_CORE_CENSUS
                    .iter()
                    .map(|(n, _)| *n)
                    .find(|n| *n == k)
                    .unwrap_or("");
                if name.is_empty() {
                    panic!(
                        "group_d_tx.json: `{k}` is carried by some but not all of the 21 \
                         transaction-core vectors and is not listed in TX_CORE_CENSUS. \
                         A non-universal field has to be counted there, or tx_core's \
                         has()-gate for it could go missing without anything failing."
                    );
                }
                *found.entry(name).or_default() += 1;
            }
        }
    }

    // Reported per field, naming each count that moved.
    let mut moved: Vec<String> = Vec::new();
    for (key, stated) in TX_CORE_CENSUS {
        let actual = found.get(key).copied().unwrap_or(0);
        if actual != *stated {
            moved.push(format!(
                "  {key}: census says {stated} vector(s) carry it, the corpus has {actual}"
            ));
        }
    }
    assert!(
        moved.is_empty(),
        "the transaction-core field census disagrees with group_d_tx.json:\n{}\n\n\
         A count that dropped means a call site disappeared from \
         reference/gen-fixtures/src/group_d_tx.c and a validator or value silently \
         stopped being checked -- tx_core gates on has(), so nothing else in the \
         suite can see it. A count that rose means a vector gained a field the \
         handler may not read. Fix the harness or update the census deliberately; \
         do not adjust the number to match.",
        moved.join("\n")
    );
}

// =======================================================================
// The censuses over the remaining eighteen
// =======================================================================

/// The shared body of the group D field censuses other than
/// `group_d_core_census`, which has its own.
///
/// Every expected number is stated by the caller, never derived from the
/// selection, so each comparison can fail.
fn field_census(
    label: &str,
    sources: &[&str],
    expect_vectors: usize,
    expect_universal: usize,
    census: &[(&str, usize)],
) {
    let fx = Fixture::load("group_d_tx.json");
    let selected: Vec<&serde_json::Value> = fx
        .vectors()
        .into_iter()
        .filter(|v| {
            v.get("source")
                .and_then(|s| s.as_str())
                .is_some_and(|s| sources.contains(&s))
        })
        .collect();

    assert_eq!(
        selected.len(),
        expect_vectors,
        "{label}: the source(s) {sources:?} now select {} vectors, not \
         {expect_vectors}. Either a vector moved between sources or one was \
         added or removed; both change what this census describes.",
        selected.len()
    );

    let keys = |v: &serde_json::Value| -> BTreeSet<String> {
        v.as_object()
            .expect("a vector is not a JSON object")
            .keys()
            .cloned()
            .collect()
    };

    let mut universal = keys(selected[0]);
    for v in &selected {
        universal = universal.intersection(&keys(v)).cloned().collect();
    }
    assert_eq!(
        universal.len(),
        expect_universal,
        "{label}: the {expect_vectors} vectors now share {} keys, not \
         {expect_universal}.\n  shared: {universal:?}",
        universal.len()
    );

    let mut found: BTreeMap<String, usize> = BTreeMap::new();
    for v in &selected {
        for k in keys(v) {
            if !universal.contains(&k) {
                *found.entry(k).or_default() += 1;
            }
        }
    }

    let mut moved: Vec<String> = Vec::new();
    for (key, stated) in census {
        let actual = found.get(*key).copied().unwrap_or(0);
        if actual != *stated {
            moved.push(format!(
                "  {key}: census says {stated} vector(s) carry it, the corpus \
                 has {actual}"
            ));
        }
    }
    for key in found.keys() {
        if !census.iter().any(|(n, _)| n == key) {
            moved.push(format!(
                "  {key}: carried by some but not all of the {expect_vectors} \
                 vectors and absent from the census. A non-universal field has \
                 to be counted, or the handler's has()-gate for it could go \
                 missing without anything failing"
            ));
        }
    }

    assert!(
        moved.is_empty(),
        "{label} disagrees with group_d_tx.json:\n{}\n\n\
         A count that dropped means a call site disappeared from \
         reference/gen-fixtures/src/group_d_tx.c and a value or a verdict \
         silently stopped being checked -- the handler gates on has(), so \
         nothing else in the suite can see it. A count that rose means a \
         vector gained a field the handler may not read. Fix the harness or \
         move the census deliberately; do not adjust the number to match.",
        moved.join("\n")
    );

    println!("  {label}: {expect_vectors} vectors, {expect_universal} universal keys, {} counted fields", census.len());
}

/// `Ds7`..`Ds11`, the six signature negatives.
///
/// Universal: the four metadata keys, the two `validated_wire` keys, and the
/// verdict's `rc` pair — eight. Everything else is per-vector and counted:
///
/// * `adrs` — `Ds7` alone, the only one that corrupts the address scheme.
/// * `src_addr` — `Ds8`, `Ds8b`, `Ds9`, the three that touch the source
///   address.
/// * `tag_half_equals_hash_half` — `Ds8b` alone.
/// * `baseline_wire_*` and the three `message_hash_*` — `Ds8` alone, the only
///   negative that records a value taken before its own mutation.
/// * the `errno` triple — five of six. `Ds8b` is the exception because it
///   *passes*: `tx_val__wots` checks `ADDR_HASH_PTR` alone, so a tag half that
///   is not the address hash is accepted and no `errno` is set.
const SIGNATURE_NEGATIVE_CENSUS: &[(&str, usize)] = &[
    ("adrs", 1),
    ("src_addr", 3),
    ("tag_half_equals_hash_half", 1),
    ("baseline_wire_file", 1),
    ("baseline_wire_len", 1),
    ("message_hash_before", 1),
    ("message_hash_after", 1),
    ("message_hash_changed", 1),
    ("tx_val__wots_errno", 5),
    ("tx_val__wots_errno_name", 5),
    ("tx_val__wots_errno_text", 5),
];

#[test]
fn group_d_signature_negative_census() {
    field_census(
        "the signature-negative census",
        &["tx_val__wots() @ reference/mochimo-core/src/tx.c:653"],
        6,
        8,
        SIGNATURE_NEGATIVE_CENSUS,
    );
}

/// The eight `tx_hash` vectors, in two shapes.
///
/// `expect_universal` is 4, the metadata keys only: `Ds1-N*` and
/// `Ds3`/`Ds4`/`Ds5` share no data field, which is why the handler
/// dispatches on shape.
///
/// `hash_unchanged` 2 against `hash_changed` 1 keeps the Ds5 control: if all
/// three carried `hash_unchanged`, the handler's exhaustive match would
/// still pass, and only this count would notice.
const TX_HASH_CENSUS: &[(&str, usize)] = &[
    // The Ds1-N* shape: both hashes of one entry, with the range each covers.
    ("ndst", 5),
    ("message_hash", 5),
    ("message_hash_len", 5),
    ("id_hash", 5),
    ("id_hash_len", 5),
    ("message_hash_input_file", 5),
    ("message_hash_input_len", 5),
    ("hashed_wire_file", 5),
    ("hashed_wire_len", 5),
    ("hashes_differ", 5),
    // The Ds3/Ds4/Ds5 shape: one hash of each of two entries.
    ("baseline_wire_file", 3),
    ("baseline_wire_len", 3),
    ("mutated_wire_file", 3),
    ("mutated_wire_len", 3),
    ("baseline_hash", 3),
    ("mutated_hash", 3),
    ("hash_unchanged", 2),
    ("hash_changed", 1),
];

#[test]
fn group_d_tx_hash_census() {
    field_census(
        "the tx_hash census",
        &["tx_hash() @ reference/mochimo-core/src/tx.c:447"],
        8,
        4,
        TX_HASH_CENSUS,
    );
}

/// The three vectors carrying a `cases` array: how many cases, and how many
/// keys each case has.
///
/// Unlike `field_census`, the population is inside one vector: every element
/// of a `cases` array must have the same keys, because per-case coverage
/// cannot see a key that a case lacks. The case counts are stated because an
/// array that shrank would still pass.
const CASES_CENSUS: &[(&str, usize, usize)] = &[
    // id, cases, keys per case
    //
    // D10: ref, ref_bytes, result_rc, result_rc_name. Four accepted
    // references, so no errno fields.
    ("D10", 4, 4),
    // D11: the same four plus result_errno_set; mdst_val__reference rejects
    // without touching errno.
    ("D11", 5, 5),
    // D15: case, options, case_wire_file, case_wire_len, and the full five-key
    // tx_read verdict -- rc, rc_name and the errno triple.
    ("D15", 3, 9),
];

#[test]
fn group_d_cases_census() {
    let fx = Fixture::load("group_d_tx.json");

    let mut nested = 0usize;
    for v in fx.vectors() {
        if v.get("cases").is_some() {
            nested += 1;
        }
    }
    assert_eq!(
        nested,
        CASES_CENSUS.len(),
        "group_d_tx.json has {nested} vector(s) carrying a `cases` array, not \
         {}. Every one needs an entry here and a handler that descends with \
         Ctx::cases; a vector that gained one would otherwise fail coverage \
         with no census saying which.",
        CASES_CENSUS.len()
    );

    for (id, want_cases, want_keys) in CASES_CENSUS {
        let v = fx.vector_by_id(id);
        let cases = v
            .get("cases")
            .and_then(|c| c.as_array())
            .unwrap_or_else(|| panic!("group_d_tx.json: vector {id} has no `cases` array"));

        assert_eq!(
            cases.len(),
            *want_cases,
            "group_d_tx.json: vector {id} now has {} cases, not {want_cases}. \
             An array that shrank descends over fewer inputs and every one of \
             them passes.",
            cases.len()
        );

        let keys = |c: &serde_json::Value| -> BTreeSet<String> {
            c.as_object()
                .unwrap_or_else(|| panic!("group_d_tx.json: {id}'s cases hold a non-object"))
                .keys()
                .cloned()
                .collect()
        };

        let mut universal = keys(&cases[0]);
        let mut all: BTreeSet<String> = BTreeSet::new();
        for c in cases {
            universal = universal.intersection(&keys(c)).cloned().collect();
            all.extend(keys(c));
        }

        let ragged: Vec<&String> = all.difference(&universal).collect();
        assert!(
            ragged.is_empty(),
            "group_d_tx.json: vector {id}'s cases do not all carry the same \
             keys -- {ragged:?} is on some and not others. Per-case coverage \
             is fail-closed over the keys a case HAS, so a case that lost one \
             replays green with that value unchecked. Either the generator \
             changed or this vector needs splitting into two."
        );
        assert_eq!(
            universal.len(),
            *want_keys,
            "group_d_tx.json: vector {id}'s cases carry {} keys each, not \
             {want_keys}.\n  keys: {universal:?}",
            universal.len()
        );
    }

    println!(
        "  cases census: {} vectors, {} cases total",
        CASES_CENSUS.len(),
        CASES_CENSUS.iter().map(|(_, n, _)| n).sum::<usize>()
    );
}

/// No vector's `source` cites `tx_val`, which needs an open ledger and is
/// never called.
///
/// Four vectors carry `rule_not_evaluated`, saying a rule lives in `tx_val`
/// and only the encoding is pinned: the three `D9`s (the block-to-live range)
/// and `D17` (the src/chg address relationship). If the generator ever
/// reaches `tx_val`, a vector will cite it and those statements become false.
///
/// The needle ends in `()` so it does not match `tx_val__wots()`. It also
/// appears in the `rule_not_evaluated` text itself, so the raw file text
/// must contain it (proving the needle can match) while the `source` walk
/// must not.
#[test]
fn tx_val_is_absent_from_the_corpus() {
    let function = "tx_val";
    let needle = format!("{function}() @");

    let mut citations: Vec<String> = Vec::new();
    let mut scanned = 0usize;
    let mut in_prose = 0usize;
    for file in support::json_files_on_disk() {
        let fx = Fixture::load(&file);
        for source in fx.sources() {
            scanned += 1;
            if source.contains(&needle) {
                citations.push(format!("  {file}: {source}"));
            }
        }
        let raw = std::fs::read_to_string(support::fixtures_dir().join(&file))
            .unwrap_or_else(|e| panic!("cannot read {file}: {e}"));
        in_prose += raw.matches(&needle).count();
    }

    // An empty walk would otherwise pass.
    assert!(
        scanned >= 20,
        "only {scanned} source strings were scanned across the corpus; that is a \
         walk that failed, not a corpus in which {function} is absent"
    );
    // A needle that matches nothing (a typo, a rename) would otherwise read
    // as an absence.
    assert!(
        in_prose > 0,
        "the needle `{needle}` does not occur anywhere in the corpus text, not \
         even in the four `rule_not_evaluated` sentences where it is known to \
         be. A needle that cannot match is not evidence of an absence."
    );
    assert!(
        citations.is_empty(),
        "{} vector source(s) now cite {function}:\n{}\n\n\
         Four vectors carry `rule_not_evaluated` saying {function} cannot be \
         called because it needs an open ledger -- the three D9s for the \
         block-to-live range, D17 for the src/chg address relationship. If it \
         can be called, that sentence is stale and both rules are owed a real \
         verdict rather than a disclaimer.",
        citations.len(),
        citations.join("\n")
    );
}

/// No group in `manifest.toml` has status `deferred`. This checks only the
/// status field and opens no fixture; that every vector of an active group
/// replays is `active_groups_replay`'s check.
///
/// Every group with status `deferred` is reported, so a newly deferred group
/// fails the suite rather than only printing a skip line.
#[test]
fn no_group_is_deferred_by_manifest_status_not_by_replay() {
    let manifest = support::load_manifest();

    // A manifest that failed to parse would report nothing deferred.
    assert!(
        manifest.len() >= 5,
        "the manifest loaded only {} group(s); with a corpus this size that is \
         a parse failure, and an empty manifest defers nothing by vacuity",
        manifest.len()
    );

    let deferred: Vec<_> = manifest.iter().filter(|g| g.status == "deferred").collect();
    if deferred.is_empty() {
        println!(
            "  no group is deferred in manifest.toml: {} groups, every one `active`. \
             That is the status field only; whether each active group's vectors \
             replay is active_groups_replay's claim, asserted there.",
            manifest.len()
        );
        return;
    }

    for g in &deferred {
        println!("  group {} ({}):", g.id, g.name);
        if let Some(reason) = &g.reason {
            println!("    reason: {}", reason.trim());
        }
        if g.activated.is_empty() {
            println!("    no vector replays yet");
        } else {
            println!(
                "    {} of {} vectors now replay: {}",
                g.activated.len(),
                g.vectors,
                g.activated.join(", ")
            );
        }
    }

    let summary: Vec<String> = deferred
        .iter()
        .map(|g| format!("{} ({} of {})", g.id, g.still_deferred, g.vectors))
        .collect();
    let total: usize = deferred.iter().map(|g| g.still_deferred).sum();
    panic!(
        "{} group(s) deferred, {total} vectors replayed nowhere: {}\n\
         Every group has been `active` since group F, the last, was activated when \
         the derivation landed). A group listed `deferred` again is either new \
         corpus with no consumer yet or a group sent back; either way its \
         vectors run in no test until it activates, and this red is where that \
         debt is visible. Replay of the active groups is active_groups_replay's \
         claim, not this test's.",
        deferred.len(),
        summary.join(", ")
    );
}

/// The group E constants, compared with the values the reference printed into
/// the fixture. Each compares the crate's literal with the fixture's, so a
/// transcription error fails by name;
/// `invariants.rs::group_e_constants_stay_anchored` requires this test.
#[test]
fn group_e_constants_match_the_reference() {
    use mochimo_crypto::consts::net as k;

    let fx = Fixture::load("group_e_net.json");
    let c = fx
        .root
        .get("constants")
        .expect("group_e_net.json has no constants block");

    let at = |node: &serde_json::Value, name: &str| -> u64 {
        node.get(name)
            .and_then(|v| v.as_u64())
            .unwrap_or_else(|| panic!("group_e_net.json constants has no `{name}`"))
    };
    let ops = c
        .get("opcodes")
        .expect("group_e_net.json constants has no `opcodes` block");

    let mut checked = 0usize;
    let mut check = |name: &str, rust: u64, fixture: u64| {
        assert_eq!(
            rust, fixture,
            "group E constant {name}: the crate's literal says {rust}, the \
             fixture the reference printf'd says {fixture}"
        );
        checked += 1;
    };

    check("PVERSION", k::PVERSION as u64, at(c, "PVERSION"));
    check("CBITS", k::CBITS as u64, at(c, "CBITS"));
    check("TXNETWORK", k::TXNETWORK as u64, at(c, "TXNETWORK"));
    check("TXEOT", k::TXEOT as u64, at(c, "TXEOT"));
    check("PORT1", k::PORT1 as u64, at(c, "PORT1"));
    check("PORT2", k::PORT2 as u64, at(c, "PORT2"));
    check("WORD16_MAX", k::word16_max() as u64, at(c, "WORD16_MAX"));

    // Three of the four non-`net` values in the block. The two lengths are
    // sums of sizeof expressions the crate carries as `consts::wire`.
    // `sizeof_TX`, the network packet container's size, has no literal in
    // this crate and is not compared (tests/invariants.rs excludes it by
    // name). CRC16LEN is also pinned by group A, which catches the two
    // fixtures disagreeing.
    check(
        "TXLEN_MIN",
        mochimo_crypto::tx::len_min() as u64,
        at(c, "TXLEN_MIN"),
    );
    check(
        "TXLEN_DSK_MIN",
        mochimo_crypto::tx::len_dsk_min() as u64,
        at(c, "TXLEN_DSK_MIN"),
    );
    check(
        "CRC16LEN",
        mochimo_crypto::consts::CRC16LEN as u64,
        at(c, "CRC16LEN"),
    );

    check("FIRST_OP", k::FIRST_OP as u64, at(ops, "FIRST_OP"));
    check("LAST_OP", k::LAST_OP as u64, at(ops, "LAST_OP"));
    check("OP_NULL", k::OP_NULL as u64, at(ops, "OP_NULL"));
    check("OP_HELLO", k::OP_HELLO as u64, at(ops, "OP_HELLO"));
    check("OP_HELLO_ACK", k::OP_HELLO_ACK as u64, at(ops, "OP_HELLO_ACK"));
    check("OP_TX", k::OP_TX as u64, at(ops, "OP_TX"));
    check("OP_FOUND", k::OP_FOUND as u64, at(ops, "OP_FOUND"));
    check("OP_GET_BLOCK", k::OP_GET_BLOCK as u64, at(ops, "OP_GET_BLOCK"));
    check("OP_GET_IPL", k::OP_GET_IPL as u64, at(ops, "OP_GET_IPL"));
    check("OP_SEND_FILE", k::OP_SEND_FILE as u64, at(ops, "OP_SEND_FILE"));
    check("OP_SEND_IPL", k::OP_SEND_IPL as u64, at(ops, "OP_SEND_IPL"));
    check("OP_BUSY", k::OP_BUSY as u64, at(ops, "OP_BUSY"));
    check("OP_NACK", k::OP_NACK as u64, at(ops, "OP_NACK"));
    check("OP_GET_TFILE", k::OP_GET_TFILE as u64, at(ops, "OP_GET_TFILE"));
    check("OP_BALANCE", k::OP_BALANCE as u64, at(ops, "OP_BALANCE"));
    check("OP_SEND_BAL", k::OP_SEND_BAL as u64, at(ops, "OP_SEND_BAL"));
    check("OP_RESOLVE", k::OP_RESOLVE as u64, at(ops, "OP_RESOLVE"));
    check("OP_GET_CBLOCK", k::OP_GET_CBLOCK as u64, at(ops, "OP_GET_CBLOCK"));
    check("OP_MBLOCK", k::OP_MBLOCK as u64, at(ops, "OP_MBLOCK"));
    check("OP_HASH", k::OP_HASH as u64, at(ops, "OP_HASH"));
    check("OP_TF", k::OP_TF as u64, at(ops, "OP_TF"));
    check("OP_IDENTIFY", k::OP_IDENTIFY as u64, at(ops, "OP_IDENTIFY"));

    // Every integer in the block except `sizeof_TX`. The two prose fields
    // (`note` and `opcodes.valid_op_rule`) are not compared; valid_op is
    // tested in tests/net.rs.
    assert_eq!(
        checked, 32,
        "group E anchors {checked} constants, expected 32. A constant dropped \
         from this test is a constant back to agreeing only with itself, which \
         is the exact state this test was written to end."
    );
    println!("  {checked} group E constants anchored to the fixture the reference printf'd");
}

/// Prints the weakly-anchored list in every run, and fails if its size
/// changes.
#[test]
fn weakly_anchored_definitions_are_named() {
    assert_eq!(
        WEAKLY_ANCHORED.len(),
        1,
        "the weakly-anchored set changed. Each entry is a definition checked \
         against the reference less strictly than everything else, and adding \
         one is a decision that belongs in the specification's Open items before it \
         belongs here."
    );
    println!("\n  WEAKLY ANCHORED — {} definition(s):", WEAKLY_ANCHORED.len());
    for (what, why) in WEAKLY_ANCHORED {
        println!("    {what}\n      {}", wrap(why, 70, 6));
    }
}

// =======================================================================
// Group D: the native round trip, with the reference's verdicts recorded
// =======================================================================

/// The group D sources recorded from the reference validators or the
/// reference's transaction struct; they route to
/// [`reference_verdicts_native`]. One list, so the dispatch and the
/// not-called census agree.
const REFERENCE_ONLY_SOURCES: [&str; 6] = [
    "tx__init() @ reference/mochimo-core/src/tx.c:146",
    "tx__init() @ reference/mochimo-core/src/tx.c:156",
    "mdst_val__reference() @ reference/mochimo-core/src/tx.c:510",
    "tx_read() @ reference/mochimo-core/src/tx.c:474",
    "tx__init / tx_read() @ reference/mochimo-core/src/tx.c:119,474",
    "tx_hash() @ reference/mochimo-core/src/tx.c:447",
];

/// Whether a group D vector's verdicts are the reference's and not this
/// crate's: true for every source in [`REFERENCE_ONLY_SOURCES`], for
/// `tx_val__wots`, and for the transaction-core sources.
fn is_reference_only_source(s: &str) -> bool {
    REFERENCE_ONLY_SOURCES.contains(&s)
        || s == "tx_val__wots() @ reference/mochimo-core/src/tx.c:653"
        || TX_CORE_SOURCES.contains(&s)
}

/// Reads every field of a case object so coverage sees it; the values are the
/// reference's and are not recomputed here.
fn touch_all(ctx: &mut Ctx) {
    let Some(obj) = ctx.v.as_object() else { return };
    let keys: Vec<(String, serde_json::Value)> = obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    let has_file = |k: &str| keys.iter().any(|(kk, _)| kk == &format!("{k}_file"));
    for (k, val) in &keys {
        if ["id", "note", "falsifies", "source"].contains(&k.as_str()) {
            continue;
        }
        if let Some(stem) = k.strip_suffix("_file") {
            // `blob` reads `<stem>_file` and `<stem>_len` and checks the sidecar.
            let _ = ctx.blob(stem);
            continue;
        }
        if let Some(stem) = k.strip_suffix("_len") {
            if has_file(stem) {
                continue;
            }
        }
        if val.as_array().is_some_and(|a| a.iter().any(serde_json::Value::is_object)) {
            ctx.cases(k, touch_all);
            continue;
        }
        let _ = ctx.touch(k);
    }
}

/// Group V: one proof-of-stake validator transaction, rebuilt from its
/// recorded inputs and compared with what the proof-of-stake node built.
///
/// From the recorded synthetic components it generates the source and change
/// keys, lays out the two addresses (the source implicit, as a cold entry
/// is), builds the body from `dat_type` and `payload`, sets the totals, and
/// signs the message digest under the source key; WOTS+ is deterministic, so
/// this reproduces the node's signature. It then compares the wire image
/// with and without trailer byte for byte, both digests, the offsets
/// `tx_read` computed, its acceptance of both lengths, and the node's two
/// WOTS+ comparisons against `verify_wots`.
///
/// Each negative case is rebuilt from its `len` and `options` and
/// `from_wire`'s verdict compared with `tx_read`'s. One difference is
/// declared: `tx_read` accepts a non-zero `options[2]` on a type with no
/// destination array and this codec refuses it (see `tx::wire::Body`). The
/// replay asserts both for exactly that shape, so the difference cannot
/// change unnoticed.
fn pos_validator_tx(ctx: &mut Ctx) {
    use mochimo_crypto::mesh::spend::verify_wots;
    use mochimo_crypto::tx::wire::{Body, Transaction};

    let key = |secret: [u8; 32], pub_seed: [u8; 32], adrs_image: [u8; 32]| {
        let mut working = Adrs::from_le_image(&adrs_image);
        let pk = wots::pkgen(&Secret::new(secret), &pub_seed, &mut working);
        let mut hash = [0u8; 20];
        hash.copy_from_slice(addr::hash_of(&addr::from_wots(&pk)));
        hash
    };
    let src_secret = ctx.arr::<32>("src_secret");
    let src_pub_seed = ctx.arr::<32>("src_pub_seed");
    let src_adrs = ctx.arr::<32>("src_adrs");
    let src_hash = key(src_secret, src_pub_seed, src_adrs);
    let chg_hash = key(ctx.arr::<32>("chg_secret"), ctx.arr::<32>("chg_pub_seed"), ctx.arr::<32>("chg_adrs"));
    let mut src_addr = [0u8; 40];
    src_addr[..20].copy_from_slice(&src_hash);
    src_addr[20..].copy_from_slice(&src_hash);
    let mut chg_addr = [0u8; 40];
    chg_addr[..20].copy_from_slice(&src_hash);
    chg_addr[20..].copy_from_slice(&chg_hash);
    ctx.eq_bytes("src_addr", &src_addr);
    ctx.eq_bytes("chg_addr", &chg_addr);

    let payload = ctx.hex("payload");
    let dat_type = ctx.u64_("dat_type");
    let body = match dat_type {
        1 => Body::SetDelegate {
            delegate: payload.as_slice().try_into().unwrap_or_else(|_| panic!("{}: payload width", ctx.id)),
        },
        2 => {
            assert!(payload.is_empty(), "{}: a clear-delegate payload is empty", ctx.id);
            Body::ClearDelegate
        }
        6 => Body::Claim {
            amount: u64::from_le_bytes(payload.as_slice().try_into().unwrap_or_else(|_| panic!("{}: payload width", ctx.id))),
        },
        other => panic!("{}: dat_type {other} is not one group V builds", ctx.id),
    };
    let mut tx = Transaction::with_body(body).unwrap_or_else(|e| panic!("{}: {e}", ctx.id));
    tx.src_addr = src_addr;
    tx.chg_addr = chg_addr;
    tx.send_total = ctx.u64_("send_total");
    tx.change_total = ctx.u64_("change_total");
    tx.fee_total = ctx.u64_("fee_total");
    tx.blk_to_live = ctx.u64_("blk_to_live");
    let balance = ctx.u64_("balance");
    assert_eq!(
        tx.send_total + tx.change_total + tx.fee_total,
        balance,
        "{}: the recorded totals do not sum to the recorded balance",
        ctx.id
    );
    let digest = tx.message_digest();
    ctx.eq_bytes("message_hash", &digest);
    let mut words = *Adrs::from_le_image(&src_adrs).words();
    let sig = raw::wots_sign(&digest, &src_secret, &src_pub_seed, &mut words);
    // The node stores the adrs as recovery leaves it, which is the starting
    // words with the mandated tail (see `SignedTransaction::attach`).
    let mut after = Adrs::from_le_image(&src_adrs);
    let _ = wots::pk_from_sig(&sig, &digest, &src_pub_seed, &mut after);
    tx.wots.signature = *sig;
    tx.wots.pub_seed = src_pub_seed;
    tx.wots.adrs = after.le_image();
    tx.seal();
    ctx.eq_bytes("id_hash", &tx.id_digest());
    let wire = tx.to_wire();
    ctx.eq_bytes("wire", &wire);
    let mut bare = tx.clone();
    bare.trailer = None;
    ctx.eq_bytes("wire_no_trailer", &bare.to_wire());
    ctx.eq_u64("dat_type", u64::from(tx.body().dat_type()));
    ctx.eq_u64("tx_sz", tx.tx_sz() as u64);
    ctx.eq_u64("off_payload", 116);
    ctx.eq_u64("dsaoff", tx.dsa_off() as u64);
    ctx.eq_u64("tlroff", tx.tlr_off() as u64);
    let rc_of = |bytes: &[u8]| -> u64 { u64::from(Transaction::from_wire(bytes).is_err()) };
    ctx.eq_u64("tx_read_rc", rc_of(&ctx.hex("wire")));
    ctx.eq_u64("tx_read_no_trailer_rc", rc_of(&ctx.hex("wire_no_trailer")));
    let verified = verify_wots(&tx).is_ok();
    ctx.eq_bool("wots_adrs_ok", verified);
    ctx.eq_bool("wots_src_hash_ok", verified);

    let mut labels: BTreeSet<String> = BTreeSet::new();
    let mut declared = 0usize;
    ctx.cases("negative", |case| {
        let label = case.str_("case").to_string();
        assert!(labels.insert(label.clone()), "{}: case label {label:?} repeats", case.id);
        let len = usize::try_from(case.u64_("len")).unwrap_or_else(|_| panic!("{}: len", case.id));
        let options = case.arr::<4>("options");
        let mut image = wire.clone();
        image.resize(len, 0);
        image[..4].copy_from_slice(&options);
        let node_rc = case.u64_("tx_read_rc");
        let node_errno = case.u64_("tx_read_errno");
        assert_eq!(node_rc != 0, node_errno != 0, "{}: tx_read's rc and errno disagree about refusal", case.id);
        let ours = Transaction::from_wire(&image);
        let stricter = options[0] != 0 && options[2] != 0 && len == wire.len();
        if stricter {
            assert_eq!(node_rc, 0, "{}: tx_read refused options[2] != 0; the declared difference is gone", case.id);
            assert!(
                matches!(ours, Err(mochimo_crypto::Error::Range { got, .. }) if got == u64::from(options[2])),
                "{}: this codec no longer refuses options[2] = {} on a type with no destination array: {ours:?}",
                case.id,
                options[2]
            );
            declared += 1;
        } else {
            assert_eq!(
                u64::from(ours.is_err()),
                node_rc,
                "{}: tx_read says rc {node_rc} and from_wire says {ours:?} for {len} bytes under options {options:02x?}",
                case.id
            );
        }
    });
    assert_eq!(declared, 1, "{}: exactly one negative case is the declared options[2] difference", ctx.id);
}

/// Group S: `stake-tx.mjs` (the v4.1 reference client, checked against the
/// node) over a test-only SDK master seed. Each signing vector is rebuilt
/// from its inputs (the seed at the file's top level, the account, the spend
/// index, the network and the generator's command line) through this
/// crate's payload types, SDK key derivation and raw signer. The whole wire
/// image is compared byte for byte, including the zero trailer
/// `stake-tx.mjs` writes, along with the message hash, size, fee and, for a
/// consent, its `MACCEPT` and digest. A digest vector rebuilds the consent
/// from its command line alone.
fn stake_tx(ctx: &mut Ctx) {
    use mochimo_crypto::staking::ConsentTerms;
    use mochimo_crypto::tx::wire::{Body, Transaction};

    let argv: Vec<String> = ctx.str_("argv").split_whitespace().map(str::to_string).collect();
    let network = u16::try_from(ctx.u64_("network")).unwrap_or_else(|_| panic!("{}: network", ctx.id));
    let id = ctx.id.clone();
    let flag = |name: &str| -> Option<&str> {
        argv.iter().position(|a| a == name).and_then(|i| argv.get(i + 1)).map(String::as_str)
    };
    let present = |name: &str| argv.iter().any(|a| a == name);
    let tag_of = |hex: &str| -> [u8; 20] {
        let raw = support::from_hex(hex).unwrap_or_else(|e| panic!("{id}: {hex}: {e}"));
        raw.try_into().unwrap_or_else(|_| panic!("{id}: {hex} is not a tag"))
    };
    let number = |text: &str| -> u64 {
        match text.strip_prefix("0x") {
            Some(h) => u64::from_str_radix(h, 16),
            None => text.parse::<u64>(),
        }
        .unwrap_or_else(|e| panic!("{id}: {text}: {e}"))
    };
    // The consent the command line names, in stake-tx.mjs's vocabulary.
    let consent = |own_kind: Option<&str>| -> ConsentTerms {
        let kind = match own_kind {
            None => 0,
            Some("delegate") => 1,
            Some("member-delegate") => 2,
            Some("member-cold") => 3,
            Some("new-holder") => 4,
            Some(k) => u8::try_from(number(k)).unwrap_or_else(|_| panic!("{id}: kind {k}")),
        };
        let mut terms = ConsentTerms::revoke(network);
        terms.kind = kind;
        if let Some(p) = flag("--peer") {
            terms.peer = tag_of(p);
        }
        terms.action = match flag("--action") {
            None => 0,
            Some("elect") => 1,
            Some("recover") => 2,
            Some(a) => panic!("{id}: action {a}"),
        };
        terms.slot = flag("--slot").map_or(0, |s| u32::try_from(number(s)).unwrap_or_else(|_| panic!("{id}: slot")));
        if let Some(ip) = flag("--ip") {
            let octets: Vec<u8> = ip.split('.').map(|o| o.parse::<u8>().unwrap_or_else(|e| panic!("{id}: ip {e}"))).collect();
            terms.ip = octets.try_into().unwrap_or_else(|_| panic!("{id}: ip {ip}"));
        }
        terms.port = flag("--port").map_or(0, |p| u16::try_from(number(p)).unwrap_or_else(|_| panic!("{id}: port")));
        terms.flags = if present("--adequate") {
            1
        } else {
            flag("--flags").map_or(0, |f| u8::try_from(number(f)).unwrap_or_else(|_| panic!("{id}: flags")))
        };
        terms
    };

    let verb = argv.first().map(String::as_str).unwrap_or_else(|| panic!("{id}: empty argv"));
    if verb == "digest" {
        let own = ctx.arr::<20>("own_tag");
        assert_eq!(flag("--tag").map(&tag_of), Some(own), "{id}: own_tag is the --tag the command named");
        let terms = consent(flag("--kind"));
        terms.check(&own).unwrap_or_else(|e| panic!("{id}: the crate refuses terms stake-tx.mjs accepted: {e}"));
        ctx.eq_bytes("maccept", &terms.image());
        ctx.eq_bytes("consent_digest", &terms.digest(&own));
        return;
    }

    let seed_hex = ctx.root.get("sdk_master_seed").and_then(|v| v.as_str()).unwrap_or_else(|| panic!("{id}: the file states no sdk_master_seed"));
    let seed: [u8; 32] = support::from_hex(seed_hex)
        .unwrap_or_else(|e| panic!("{id}: sdk_master_seed: {e}"))
        .try_into()
        .unwrap_or_else(|_| panic!("{id}: sdk_master_seed width"));
    let account = u32::try_from(ctx.u64_("account")).unwrap_or_else(|_| panic!("{id}: account"));
    let spend = u32::try_from(ctx.u64_("spend_index")).unwrap_or_else(|_| panic!("{id}: spend_index"));
    let account_seed = mochimo_crypto::derive::sdk_account_seed(&Secret::new(seed), account);
    let tag = mochimo_crypto::derive::sdk_account_tag(&account_seed);
    let key = mochimo_crypto::derive::sdk_wots_key(&account_seed, spend);
    let next = mochimo_crypto::derive::sdk_wots_key(&account_seed, spend + 1);

    let body = match verb {
        "stake" => Body::Stake {
            amount: number(flag("--amount").unwrap_or_else(|| panic!("{id}: --amount"))),
            tier: u8::try_from(number(flag("--tier").unwrap_or_else(|| panic!("{id}: --tier")))).unwrap_or_else(|_| panic!("{id}: tier")),
            network,
        },
        "unstake" => Body::Unstake { network },
        "claim" => Body::Claim {
            amount: match flag("--amount") {
                Some("all") => mochimo_crypto::staking::CLAIM_ALL,
                Some(a) => number(a),
                None => panic!("{id}: --amount"),
            },
        },
        "set-delegate" => Body::SetDelegate {
            delegate: tag_of(flag("--delegate").unwrap_or_else(|| panic!("{id}: --delegate"))),
        },
        "clear-delegate" => Body::ClearDelegate,
        "accept" => {
            let terms = consent(flag("--kind"));
            terms.check(&tag).unwrap_or_else(|e| panic!("{id}: the crate refuses terms stake-tx.mjs accepted: {e}"));
            ctx.eq_bytes("maccept", &terms.image());
            ctx.eq_bytes("consent_digest", &terms.digest(&tag));
            Body::Accept(terms)
        }
        "revoke" => {
            let terms = ConsentTerms::revoke(network);
            terms.check(&tag).unwrap_or_else(|e| panic!("{id}: {e}"));
            ctx.eq_bytes("maccept", &terms.image());
            Body::Accept(terms)
        }
        other => panic!("{id}: `{other}` is not a command group S records"),
    };
    // Every signing vector is the dust-proof form: send and change zero.
    assert!(
        matches!(verb, "stake" | "unstake" | "accept" | "revoke") || present("--v41"),
        "{id}: a claim or delegate change in group S is the dust-proof form, which stake-tx.mjs signs under --v41"
    );
    let mut tx = Transaction::with_body(body).unwrap_or_else(|e| panic!("{id}: {e}"));
    tx.src_addr = key.address(&tag);
    tx.chg_addr = next.address(&tag);
    tx.send_total = 0;
    tx.change_total = 0;
    tx.fee_total = flag("--fee").map_or(500, number);
    tx.blk_to_live = 0;
    ctx.eq_u64("fee_total", tx.fee_total);
    let digest = tx.message_digest();
    ctx.eq_bytes("message_hash", &digest);
    let mut words = *key.adrs().words();
    let sig = raw::wots_sign(&digest, key.secret().expose(), key.pub_seed(), &mut words);
    let mut after = key.adrs();
    let _ = wots::pk_from_sig(&sig, &digest, key.pub_seed(), &mut after);
    tx.wots.signature = *sig;
    tx.wots.pub_seed = *key.pub_seed();
    tx.wots.adrs = after.le_image();
    // stake-tx.mjs writes the trailer as forty zero bytes; the node writes
    // its own after validation (see `Transaction::seal`).
    tx.trailer = Some(tx::wire::Trailer { nonce: 0, id: [0; 32] });
    let wire = tx.to_wire();
    ctx.eq_u64("tx_size", wire.len() as u64);
    ctx.eq_bytes("wire", &wire);
    mochimo_crypto::mesh::spend::verify_wots(&tx).unwrap_or_else(|e| panic!("{id}: the rebuilt image does not verify: {e}"));
    let parsed = Transaction::from_wire(&ctx.hex("wire")).unwrap_or_else(|e| panic!("{id}: from_wire refuses stake-tx.mjs's image: {e}"));
    assert!(parsed.to_wire() == wire, "{id}: from_wire then to_wire does not reproduce the image");
}

/// The group D replay: the wire image round-trips through
/// `tx::wire::Transaction` byte for byte and the recorded layout is checked
/// against the native serializer. The validator verdicts (`mdst_val`,
/// `tx_read`, `tx__init`'s rejections) are read and marked not called,
/// because this crate has no transaction validator; `tx_val__wots`'s WOTS+
/// verdict is checked against `verify_wots` below.
fn reference_verdicts_native(ctx: &mut Ctx) {
    use mochimo_crypto::tx::wire::Transaction;

    if ctx.has("wire_file") {
        let wire = ctx.blob("wire");
        let id = ctx.id.clone();
        let parsed = Transaction::from_wire(&wire)
            .unwrap_or_else(|e| panic!("{id}: the native serializer rejects a recorded wire image: {e}"));
        let again = parsed.to_wire();
        assert!(
            again == wire,
            "{id}: the native serializer does not reproduce the recorded wire image (first difference at byte {})",
            again.iter().zip(wire.iter()).position(|(a, b)| a != b).unwrap_or(again.len().min(wire.len()))
        );
        let n = u64::from(parsed.dst_count());
        let dsa = parsed.dsa_off() as u64;
        let tlr = parsed.tlr_off() as u64;
        ctx.eq_u64("tx_sz", parsed.tx_sz() as u64);
        ctx.eq_u64("ndst", n);
        ctx.eq_u64("mdst_count_from_reference", n);
        ctx.eq_u64("dsaoff", dsa);
        ctx.eq_u64("tlroff", tlr);
        ctx.eq_u64("signed_len", dsa);
        ctx.eq_u64("off_mdst_first", 116);
        ctx.eq_u64("off_mdst_last", 116 + 44 * (n - 1));
        ctx.eq_u64("off_wots_signature", dsa);
        ctx.eq_u64("off_wots_pub_seed", dsa + 2144);
        ctx.eq_u64("off_wots_adrs", dsa + 2176);
        ctx.eq_u64("off_nonce", tlr);
        ctx.eq_u64("off_id", tlr + 8);
        for (key, off) in [
            ("off_src_addr", 4u64), ("off_chg_addr", 44), ("off_send_total", 84), ("off_change_total", 92),
            ("off_fee_total", 100), ("off_blk_to_live", 108),
            ("entry_off_hdr", 0), ("entry_off_dat", 116), ("entry_off_options", 0), ("entry_off_src_addr", 4),
            ("entry_off_chg_addr", 44), ("entry_off_send_total", 84), ("entry_off_change_total", 92),
            ("entry_off_tx_fee", 100), ("entry_off_tx_btl", 108), ("entry_off_mdst", 116),
        ] {
            ctx.eq_u64(key, off);
        }
        ctx.eq_u64("entry_off_dsa", dsa);
        ctx.eq_u64("entry_off_wots", dsa);
        ctx.eq_u64("entry_off_tlr", tlr);
        ctx.eq_u64("entry_off_tx_nonce", tlr);
        ctx.eq_u64("entry_off_tx_id", tlr + 8);
        ctx.eq_u64("options_byte_2", n - 1);
    }
    // The WOTS+ verdict is reproducible: `mesh::spend::verify_wots` recovers
    // the public key from the signature and compares its hash with the source
    // address, as `tx_val__wots` does. Every image carrying that verdict is
    // checked. The `mdst_val` verdict stays the reference's.
    for image_key in ["wire", "validated_wire"] {
        if ctx.has(&format!("{image_key}_file")) && ctx.has("tx_val__wots_rc_name") {
            let bytes = ctx.blob(image_key);
            let id = ctx.id.clone();
            let parsed = Transaction::from_wire(&bytes)
                .unwrap_or_else(|e| panic!("{id}: the native serializer rejects a recorded {image_key} image: {e}"));
            let want_ok = ctx.str_("tx_val__wots_rc_name") == "VEOK";
            let got = mochimo_crypto::mesh::spend::verify_wots(&parsed);
            assert_eq!(
                got.is_ok(),
                want_ok,
                "{id}: the reference's tx_val__wots verdict on {image_key} is {} and verify_wots says {got:?}",
                if want_ok { "VEOK" } else { "a refusal" }
            );
        }
    }
    if ctx.has("hashed_wire_file") {
        let hashed = ctx.blob("hashed_wire");
        let id = ctx.id.clone();
        let parsed = Transaction::from_wire(&hashed)
            .unwrap_or_else(|e| panic!("{id}: the native serializer rejects a recorded hashed image: {e}"));
        ctx.eq_bytes("message_hash", &parsed.message_digest());
        ctx.eq_bytes("id_hash", &parsed.id_digest());
    }
    touch_all(ctx);
    ctx.mark(Disposition::NotCalled);
}

// =======================================================================
// The bulk corpus: the artifact policy and its censuses
// =======================================================================

/// Every group's header states whether a large artifact is carried whole (a
/// `.bin` sidecar) or as its sha256, and this checks each file against its
/// statement in both directions: a digest group carries no `_file` key, and
/// a whole-artifact group carries no `_sha256` key in place of bytes. A file
/// with no `artifacts` key is a whole-artifact group.
#[test]
fn artifact_policy_is_declared_by_the_generator_and_enforced_here() {
    let mut digest_groups: Vec<String> = Vec::new();
    let mut whole_groups: Vec<String> = Vec::new();
    let mut offences: Vec<String> = Vec::new();

    for g in support::load_manifest() {
        let fx = Fixture::load(&g.file);
        let policy = fx
            .root
            .get("artifacts")
            .map(|a| {
                a.as_str().unwrap_or_else(|| panic!("{}: `artifacts` is not a string", g.file))
                    .to_string()
            })
            .unwrap_or_else(|| "whole".to_string());
        let (forbidden, list): (&str, &mut Vec<String>) = match policy.as_str() {
            "digest" => ("_file", &mut digest_groups),
            "whole" => ("_sha256", &mut whole_groups),
            other => panic!(
                "{}: `artifacts` is {other:?}; the policy is \"digest\" or \"whole\" and \
                 nothing else, so a third word would be a group nobody's check applies to",
                g.file
            ),
        };
        list.push(g.id.clone());
        for v in fx.vectors() {
            let Some(obj) = v.as_object() else { continue };
            for k in obj.keys().filter(|k| k.ends_with(forbidden)) {
                offences.push(format!(
                    "  {} ({policy}): vector {} carries `{k}`",
                    g.file,
                    obj.get("id").and_then(|x| x.as_str()).unwrap_or("?")
                ));
            }
        }
    }

    assert!(
        digest_groups.len() >= 2 && whole_groups.len() >= 8,
        "the walk classified {} digest and {} whole-artifact groups; with the \
         corpus this size that is a parse failure rather than a corpus",
        digest_groups.len(),
        whole_groups.len()
    );
    assert!(
        offences.is_empty(),
        "ARTIFACT POLICY VIOLATED\n{}\n  A digest group carries no sidecar and a \
         whole-artifact group carries no digest in place of bytes.",
        offences.join("\n")
    );
    println!("  artifact policy: digest {digest_groups:?}, whole {whole_groups:?}");
}

/// The bulk files state their population per source in the header
/// (`count_*`, `*_max_len`), and this checks the `vectors` array against
/// them, so a generator loop bound that moved, or a vector that stopped being
/// emitted, is caught.
#[test]
fn bulk_populations_match_the_headers() {
    fn population(fx: &Fixture, source: &str) -> u64 {
        fx.vectors()
            .iter()
            .filter(|v| v.get("source").and_then(|s| s.as_str()) == Some(source))
            .count() as u64
    }
    fn header(fx: &Fixture, key: &str) -> u64 {
        fx.root
            .get(key)
            .and_then(|x| x.as_u64())
            .unwrap_or_else(|| panic!("{}: header has no integer `{key}`", fx.file))
    }

    let ak = Fixture::load("group_ak_keygen_bulk.json");
    let bk = Fixture::load("group_bk_sign_bulk.json");
    let hs = Fixture::load("group_hs_hash_sweep.json");

    let mut checked = 0usize;
    for (fx, key, source) in [
        (&ak, "count_wots_pkgen", AK_PKGEN),
        (&ak, "count_expand_seed", AK_EXPAND_SEED),
        (&ak, "count_prf", AK_PRF),
        (&ak, "count_thash_f", AK_THASH_F),
        (&ak, "count_gen_chain", AK_GEN_CHAIN),
        (&bk, "count_wots_sign", BK_SIGN),
        (&bk, "count_chain_lengths", BK_CHAIN_LENGTHS),
    ] {
        let want = header(fx, key);
        let got = population(fx, source);
        assert_eq!(got, want, "{}: header says {key} = {want}, the file holds {got}", fx.file);
        assert!(want > 0, "{}: {key} is zero, so the source below it replays nothing", fx.file);
        checked += 1;
    }
    // The header counts must account for the whole file.
    assert_eq!(
        ak.vectors().len() as u64,
        ["count_wots_pkgen", "count_expand_seed", "count_prf", "count_thash_f", "count_gen_chain"]
            .iter()
            .map(|k| header(&ak, k))
            .sum::<u64>(),
        "group AK holds vectors its header counts do not account for"
    );
    assert_eq!(
        bk.vectors().len() as u64,
        header(&bk, "count_wots_sign") + header(&bk, "count_chain_lengths"),
        "group BK holds vectors its header counts do not account for"
    );

    // HS: every length in 0..=max for the two hashes the reference can always
    // compute.
    for (key, source) in [("sha256_max_len", HS_SHA256), ("sha3_512_max_len", HS_SHA3)] {
        let max = header(&hs, key);
        let lengths: BTreeSet<u64> = hs
            .vectors()
            .iter()
            .filter(|v| v.get("source").and_then(|s| s.as_str()) == Some(source))
            .map(|v| v["inlen"].as_u64().expect("inlen"))
            .collect();
        let want: BTreeSet<u64> = (0..=max).collect();
        assert_eq!(lengths, want, "group HS: {source} does not cover every length in 0..={max}");
        checked += 1;
    }
    assert_eq!(checked, 9);
    println!("  bulk populations: {checked} header counts match the files");
}

/// The RIPEMD-160 lengths the reference cannot compute (`len % 64 >= 56`)
/// are exactly those group HS omits and group RX carries, so every length in
/// `0..=ripemd160_max_len` has exactly one recorded digest.
#[test]
fn hash_sweep_and_rx_partition_the_ripemd160_lengths() {
    let hs = Fixture::load("group_hs_hash_sweep.json");
    let rx = Fixture::load("group_rx_ripemd.json");

    let max = hs.root["ripemd160_max_len"].as_u64().expect("ripemd160_max_len");
    let omitted: BTreeSet<u64> = hs.root["ripemd160_omitted"]
        .as_array()
        .expect("ripemd160_omitted")
        .iter()
        .map(|x| x.as_u64().expect("an omitted length"))
        .collect();
    let present: BTreeSet<u64> = hs
        .vectors()
        .iter()
        .filter(|v| v.get("source").and_then(|s| s.as_str()) == Some(HS_RIPEMD160))
        .map(|v| v["inlen"].as_u64().expect("inlen"))
        .collect();
    let faulting: BTreeSet<u64> = (0..=max).filter(|l| l % 64 >= 56).collect();
    let rx_lengths: BTreeSet<u64> = rx
        .vectors()
        .iter()
        .map(|v| v["in_len"].as_u64().expect("in_len"))
        .filter(|l| *l <= max)
        .collect();

    assert_eq!(omitted, faulting, "group HS omits a set other than the faulting class");
    assert!(present.is_disjoint(&omitted), "group HS carries a length it also declares omitted");
    assert_eq!(
        present.union(&omitted).copied().collect::<BTreeSet<u64>>(),
        (0..=max).collect::<BTreeSet<u64>>(),
        "group HS's present and omitted RIPEMD-160 lengths do not cover 0..={max}"
    );
    assert_eq!(
        rx_lengths, omitted,
        "group RX's lengths at or below {max} are not exactly the ones group HS omits"
    );
    println!(
        "  ripemd160 lengths 0..={max}: {} from the C (HS), {} from @noble/hashes (RX)",
        present.len(),
        omitted.len()
    );
}
