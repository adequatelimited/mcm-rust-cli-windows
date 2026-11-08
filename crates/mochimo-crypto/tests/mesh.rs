// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

#![cfg(feature = "native")]
//! The Mesh codec and the two Mesh fixture groups, run with no C linked and,
//! for the parts that read no files, under Miri.
//!
//! Runs with `--no-default-features --features native`. The
//! coverage-tracking replay of the same vectors is in `kat.rs`, through the
//! same walk (`support/mesh_walk.rs`).
//!
//! Group N records one server at one block, and group M an existing Mesh
//! client run against a test double; neither proves the codec correct. These
//! tests show that the codec builds the bytes that server accepted, parses
//! its replies into independently derivable values, and refuses every
//! truncation and single-byte corruption of every recorded body without
//! panicking. Whether a node accepts a transaction this crate builds is not
//! testable here.

use std::path::PathBuf;

#[path = "support/mesh_walk.rs"]
mod mesh_walk;

use mesh_walk::Plain;
use mochimo_crypto::mesh::{self, codec, hex, max_response_bytes, MAX_HISTORY_RESPONSE_BYTES, MAX_RECON_RESPONSE_BYTES, MAX_REQUEST_BYTES};
use mochimo_crypto::Error;

const N_FILE: &str = "group_n_mesh_live.json";
const M_FILE: &str = "group_m_mesh_client.json";

#[cfg_attr(miri, allow(dead_code))]
fn repo_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

#[cfg(not(miri))]
fn fixture_json(name: &str) -> serde_json::Value {
    let p = repo_root().join("fixtures").join(name);
    let text = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("cannot parse {}: {e}", p.display()))
}

// Miri runs with isolation on and cannot `open`; the N fixture is embedded
// for the totality run, which reads no sidecar.
#[cfg(miri)]
fn fixture_json(name: &str) -> serde_json::Value {
    assert_eq!(name, N_FILE, "only group N is embedded for Miri");
    serde_json::from_str(include_str!("../../../fixtures/group_n_mesh_live.json")).expect("embedded group N parses")
}

#[cfg(not(miri))]
fn sidecar(name: &str) -> Vec<u8> {
    let p = repo_root().join("fixtures").join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
}

// --- hex ---------------------------------------------------------------------

#[test]
fn hex_round_trips_and_refuses_by_offset() {
    let bytes: Vec<u8> = (0..=255).collect();
    let s = hex::encode(&bytes);
    assert_eq!(s.len(), 512);
    assert_eq!(hex::decode(&s, "t").unwrap_or_else(|e| panic!("{e}")), bytes);
    assert_eq!(hex::decode(&s.to_ascii_uppercase(), "t").unwrap_or_else(|e| panic!("{e}")), bytes);
    assert_eq!(hex::decode("", "t").unwrap_or_else(|e| panic!("{e}")), Vec::<u8>::new());
    assert_eq!(hex::decode("abc", "t"), Err(Error::Hex { what: "t", offset: 2 }));
    assert_eq!(hex::decode("0g", "t"), Err(Error::Hex { what: "t", offset: 1 }));
    assert_eq!(hex::decode("g0", "t"), Err(Error::Hex { what: "t", offset: 0 }));
    assert_eq!(hex::decode("00zz", "t"), Err(Error::Hex { what: "t", offset: 2 }));
    assert_eq!(hex::decode_exact::<2>("0001", "t"), Ok([0, 1]));
    assert_eq!(
        hex::decode_exact::<2>("000102", "t"),
        Err(Error::Length {
            what: "t",
            expected: 2,
            got: 3
        })
    );
    assert_eq!(hex::decode_prefixed::<1>("0xff", "t"), Ok([0xff]));
    assert_eq!(hex::decode_prefixed::<1>("ff", "t"), Err(Error::Hex { what: "t", offset: 0 }));
    println!("  hex: 256 bytes round-tripped, 7 refusals by offset");
}

// --- requests ----------------------------------------------------------------

/// The request known-answer tests against group N depend on `serde_json`
/// emitting keys sorted. If `preserve_order` were enabled, bodies would come
/// out in insertion order; this test names that cause directly.
#[test]
fn request_bodies_serialise_with_sorted_keys() {
    let v = serde_json::json!({ "zeta": 1, "alpha": { "z": 2, "a": 3 }, "mid": true });
    assert_eq!(v.to_string(), r#"{"alpha":{"a":3,"z":2},"mid":true,"zeta":1}"#);
    let body = codec::request_tag_resolve(&[0x11; 20]);
    let text = String::from_utf8(body).unwrap_or_else(|e| panic!("{e}"));
    assert!(text.starts_with(r#"{"method":"tag_resolve","network_identifier":{"blockchain":"mochimo","network":"mainnet"},"parameters":{"tag":"0x"#), "{text}");
    assert!(!text.contains(' '), "compact, no spaces: {text}");
    println!("  request bodies: sorted keys, compact, 1 tag_resolve body inspected");
}

/// The Mesh middleware caps a request body at 30 KiB
/// (`http.MaxBytesReader(w, r.Body, 30*1024)` in `maxRequestSizeMiddleware`);
/// this crate uses the same cap.
#[cfg(not(miri))]
#[test]
fn request_cap_is_the_middlewares() {
    assert_eq!(MAX_REQUEST_BYTES, 30 * 1024);
    println!("  request cap: MAX_REQUEST_BYTES is the middleware's 30*1024");
}

// --- the two groups, replayed with no C -----------------------------------------

#[cfg(not(miri))]
fn replay_group(file: &'static str, want: usize) -> (usize, usize) {
    let json = fixture_json(file);
    let vectors = json["vectors"].as_array().unwrap_or_else(|| panic!("{file}: no vectors"));
    let mut assertions = 0usize;
    let mut replayed = 0usize;
    for v in vectors {
        let source = v["source"].as_str().unwrap_or_else(|| panic!("{file}: a vector has no source"));
        assert!(
            mesh_walk::SOURCES.contains(&source),
            "{file}: vector {} cites a source the walk does not register: {source}",
            v["id"]
        );
        let mut plain = Plain::new(file, v, sidecar);
        mesh_walk::replay(&mut plain, source);
        assertions += plain.assertions;
        replayed += 1;
    }
    assert_eq!(
        replayed, want,
        "{file}: expected {want} vectors, walked {replayed}. If the corpus grew, restate this number deliberately."
    );
    (replayed, assertions)
}

/// Every group N vector through the walk with no C linked. The count is
/// stated, not derived: 22 captured exchanges, of which four read a sealed
/// block rather than the tip and so are the only ones a re-capture must
/// reproduce byte for byte.
#[cfg(not(miri))]
#[test]
fn group_n_replays_with_no_reference() {
    let (n, a) = replay_group(N_FILE, 22);
    println!("  group N specification capture: {n} exchanges replayed, {a} recorded-field assertions, no C linked");
}

/// Every group M vector through the walk with no C linked: 6 vectors, every
/// recorded boolean recomputed from the sidecars.
#[cfg(not(miri))]
#[test]
fn group_m_replays_with_no_reference() {
    let (n, a) = replay_group(M_FILE, 6);
    println!("  group M specification capture: {n} vectors replayed, {a} recorded-field assertions, no C linked");
}

/// The one figure two server code paths spell two ways -- `/call`'s JSON
/// number and `/account/balance`'s decimal string -- parsed by the two
/// parsers and required equal, at the block the pin says both were read.
#[cfg(not(miri))]
#[test]
fn call_amount_and_balance_value_agree_at_one_block() {
    let json = fixture_json(N_FILE);
    let pin = &json["pin"];
    assert_eq!(
        pin["captured_block_index_start"], pin["captured_block_index_end"],
        "the capture's found-tag triple straddled a block; the equality below is not at one height"
    );
    let vectors = json["vectors"].as_array().unwrap_or_else(|| panic!("no vectors"));
    let find = |id: &str| {
        vectors
            .iter()
            .find(|v| v["id"].as_str() == Some(id))
            .unwrap_or_else(|| panic!("no {id}"))
    };
    let found = find("N-call-tag-resolve-found");
    let tag = hex::decode_prefixed::<20>(found["tag"].as_str().unwrap_or(""), "tag").unwrap_or_else(|e| panic!("{e}"));
    let entry = codec::parse_tag_resolve(found["response_body"].as_str().unwrap_or("").as_bytes(), &tag)
        .unwrap_or_else(|e| panic!("{e}"));
    let by_tag = codec::parse_account_balance(find("N-account-balance-found-by-tag")["response_body"].as_str().unwrap_or("").as_bytes())
        .unwrap_or_else(|e| panic!("{e}"));
    let by_address =
        codec::parse_account_balance(find("N-account-balance-found-by-address")["response_body"].as_str().unwrap_or("").as_bytes())
            .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(entry.balance, by_tag.balance, "/call amount vs /account/balance value");
    assert_eq!(entry.balance, by_address.balance, "/call amount vs /account/balance by address");
    assert_eq!(by_tag.tip.index, pin["captured_block_index_start"].as_u64().unwrap_or(0));
    println!(
        "  cross-endpoint balance: 3 parses agree on {} nanoMCM at block {}",
        entry.balance, by_tag.tip.index
    );
}

// --- the documented shape, enforced --------------------------------------------

/// Bodies that spell a field the wrong way, each refused by the parser
/// naming the field. The captured bodies show the documented shape accepted;
/// these show its near neighbours refused.
#[test]
fn parsers_refuse_the_documented_shapes_neighbours() {
    let tag = [0x9f; 20];
    let good_address = format!("0x{}{}", hex::encode(&tag), "ab".repeat(20));
    let resolve = |address: &str, amount: &str| format!(r#"{{"result":{{"address":"{address}","amount":{amount}}},"idempotent":true}}"#);
    let refused = std::cell::Cell::new(0usize);
    let refuse = |body: String, what: &'static str, parse: &dyn Fn(&[u8]) -> Result<(), Error>| {
        assert_eq!(parse(body.as_bytes()), Err(Error::MeshResponse { what }), "body: {body}");
        refused.set(refused.get() + 1);
    };
    let tr = |b: &[u8]| codec::parse_tag_resolve(b, &tag).map(|_| ());
    // The genuine shape parses.
    assert!(codec::parse_tag_resolve(resolve(&good_address, "42").as_bytes(), &tag).is_ok());
    // amount: a string, a float, a negative, absent.
    refuse(resolve(&good_address, "\"42\""), "result.amount: unsigned integer", &tr);
    refuse(resolve(&good_address, "42.0"), "result.amount: unsigned integer", &tr);
    refuse(resolve(&good_address, "-1"), "result.amount: unsigned integer", &tr);
    refuse(
        format!(r#"{{"result":{{"address":"{good_address}"}},"idempotent":true}}"#),
        "result.amount: unsigned integer",
        &tr,
    );
    // address: another tag's address, a 39-byte one, no 0x.
    let other = format!("0x{}{}", "11".repeat(20), "ab".repeat(20));
    refuse(resolve(&other, "42"), "result.address: does not begin with the tag resolved", &tr);
    assert!(matches!(
        codec::parse_tag_resolve(resolve(&good_address[..good_address.len() - 2], "42").as_bytes(), &tag),
        Err(Error::Length { what: "result.address", .. })
    ));
    assert!(matches!(
        codec::parse_tag_resolve(resolve(&good_address[2..], "42").as_bytes(), &tag),
        Err(Error::Hex { what: "result.address", offset: 0 })
    ));
    refused.set(refused.get() + 2);
    // balance: a signed value, a non-decimal, the wrong currency, the wrong
    // scale, an empty list.
    let balance = |value: &str, symbol: &str, decimals: &str| {
        format!(
            r#"{{"block_identifier":{{"index":7,"hash":"0x{}"}},"balances":[{{"value":{value},"currency":{{"symbol":"{symbol}","decimals":{decimals}}}}}]}}"#,
            "00".repeat(32)
        )
    };
    let ab = |b: &[u8]| codec::parse_account_balance(b).map(|_| ());
    assert!(codec::parse_account_balance(balance("\"42\"", "MCM", "9").as_bytes()).is_ok());
    refuse(balance("\"+42\"", "MCM", "9"), "balances[0].value: decimal", &ab);
    refuse(balance("\"4a\"", "MCM", "9"), "balances[0].value: decimal", &ab);
    refuse(balance("\"\"", "MCM", "9"), "balances[0].value: decimal", &ab);
    refuse(balance("\"123456789012345678901\"", "MCM", "9"), "balances[0].value: decimal", &ab);
    refuse(balance("42", "MCM", "9"), "balances[0].value", &ab);
    refuse(balance("\"42\"", "BTC", "9"), "balances[0].currency.symbol: not MCM", &ab);
    refuse(balance("\"42\"", "MCM", "8"), "balances[0].currency.decimals: not 9", &ab);
    refuse(
        format!(r#"{{"block_identifier":{{"index":7,"hash":"0x{}"}},"balances":[]}}"#, "00".repeat(32)),
        "balances[0]",
        &ab,
    );
    // the envelope: not JSON, not an object, an error object without a
    // message (not the middleware's shape, so not routed as its error).
    refuse("nope".to_owned(), "json", &ab);
    refuse("[1,2]".to_owned(), "object", &ab);
    refuse(r#"{"code":4}"#.to_owned(), "block_identifier.index", &ab);
    assert_eq!(
        codec::parse_account_balance(br#"{"code":4,"message":"x"}"#),
        Err(Error::Mesh { code: 4, retriable: false }),
        "retriable absent defaults to false"
    );
    // submit: a 0x-prefixed hash (the handler emits bare hex), a short one.
    let sub = |b: &[u8]| codec::parse_submit(b).map(|_| ());
    assert!(codec::parse_submit(format!(r#"{{"transaction_identifier":{{"hash":"{}"}},"metadata":{{}}}}"#, "ab".repeat(32)).as_bytes()).is_ok());
    assert!(matches!(
        sub(format!(r#"{{"transaction_identifier":{{"hash":"0x{}"}},"metadata":{{}}}}"#, "ab".repeat(32)).as_bytes()),
        Err(Error::Hex { what: "transaction_identifier.hash", .. })
    ));
    assert!(matches!(
        sub(format!(r#"{{"transaction_identifier":{{"hash":"{}"}},"metadata":{{}}}}"#, "ab".repeat(31)).as_bytes()),
        Err(Error::Length { what: "transaction_identifier.hash", .. })
    ));
    refused.set(refused.get() + 2);
    println!(
        "  documented-shape neighbours: {} bodies refused naming the field, 3 genuine shapes parsed",
        refused.get()
    );
}

// --- totality ------------------------------------------------------------------

/// The vector count `fixtures/manifest.toml` declares for one group file, an
/// independently maintained count to compare against.
///
/// Embedded rather than read from disk because its caller also runs under
/// Miri, whose isolation forbids `std::fs`.
fn manifest_vectors_for(file: &str) -> usize {
    let doc: toml::Value = include_str!("../../../fixtures/manifest.toml")
        .parse()
        .unwrap_or_else(|e| panic!("manifest.toml: {e}"));
    doc["group"]
        .as_array()
        .unwrap_or_else(|| panic!("manifest.toml has no [[group]] array"))
        .iter()
        .find(|g| g["file"].as_str() == Some(file))
        .and_then(|g| g["vectors"].as_integer())
        .unwrap_or_else(|| panic!("manifest.toml declares no vector count for {file}"))
        as usize
}

/// Every parser over every truncation and every single-byte corruption of
/// every recorded body returns `Ok` or `Err`, never panics. Under Miri the
/// fixture is embedded and positions are sampled; the printed count is what
/// ran.
#[test]
fn parsers_are_total_over_mutated_bodies() {
    let json = fixture_json(N_FILE);
    let vectors = json["vectors"].as_array().unwrap_or_else(|| panic!("no vectors"));
    let tag = [0x9f; 20];
    let run = |bytes: &[u8]| {
        let _ = codec::parse_network_list(bytes);
        let _ = codec::parse_network_options(bytes);
        let _ = codec::parse_network_status(bytes);
        let _ = codec::parse_tag_resolve(bytes, &tag);
        let _ = codec::parse_account_balance(bytes);
        let _ = codec::parse_submit(bytes);
    };
    let step = if cfg!(miri) { 64 } else { 1 };
    let mut mutations = 0usize;
    let mut bodies = 0usize;
    for v in vectors {
        let body = v["response_body"].as_str().unwrap_or("").as_bytes().to_vec();
        bodies += 1;
        run(&body);
        for cut in (0..body.len()).step_by(step) {
            run(&body[..cut]);
            mutations += 1;
        }
        for i in (0..body.len()).step_by(step) {
            let mut m = body.clone();
            m[i] ^= 0xff;
            run(&m);
            mutations += 1;
            let mut m = body.clone();
            m[i] = b'"';
            run(&m);
            mutations += 1;
        }
    }
    // The byte-based mutation floor has too much slack to notice a lost
    // vector, so the body count is asserted too. It is compared with the
    // manifest's declaration rather than `vectors.len()`, which would compare
    // a count with itself.
    let declared = manifest_vectors_for(N_FILE);
    assert_eq!(
        bodies, declared,
        "the mutation walk saw {bodies} bodies where the manifest declares {declared} vectors \
         for {N_FILE}; a vector the loop skipped is a body no parser was driven over, and the \
         mutation floor has too much slack to notice"
    );
    let floor = if cfg!(miri) { 200 } else { 12_000 };
    assert!(
        mutations >= floor,
        "only {mutations} mutations ran over {bodies} bodies (floor {floor}); the corpus or the loop shrank"
    );
    println!("  parser totality: {mutations} mutations over {bodies} recorded bodies, 6 parsers, 0 panics");
}

// ---------------------------------------------------------------------------
// The three explorer endpoints, replayed against the capture
// ---------------------------------------------------------------------------

/// The request bodies the explorer calls build are byte-equal to the bodies
/// the server accepted, for the shapes group N recorded: `/block` by index
/// and `/search/transactions` by hash.
///
/// A search by account and a block by hash have no recorded vector; they
/// are exercised against a test double in `tests/cli.rs`.
#[cfg(not(miri))]
#[test]
fn the_explorer_request_bodies_are_the_captured_ones() {
    let json = fixture_json(N_FILE);
    let vectors = json["vectors"].as_array().unwrap_or_else(|| panic!("no vectors"));
    let find = |id: &str| {
        vectors
            .iter()
            .find(|v| v["id"].as_str() == Some(id))
            .unwrap_or_else(|| panic!("no {id}"))
    };
    // `request_body` is the request's recorded text, compared as bytes
    // rather than re-serialised.
    let recorded = |id: &str| -> Vec<u8> {
        find(id)["request_body"]
            .as_str()
            .unwrap_or_else(|| panic!("{id}: request_body is not a string"))
            .as_bytes()
            .to_vec()
    };
    let hash = hex::decode_prefixed::<32>(
        find("N-submit-block")["submitted_transaction_id"].as_str().unwrap_or(""),
        "submitted_transaction_id",
    )
    .unwrap_or_else(|e| panic!("{e}"));

    let index = find("N-submit-block")["submitted_block_index"].as_u64().unwrap_or(0);
    assert_eq!(
        codec::request_block_by_index(index),
        recorded("N-submit-block"),
        "/block by index: the body this codec builds is not the body the server was sent"
    );
    assert_eq!(
        codec::request_search_by_hash(&hash),
        recorded("N-submit-search"),
        "/search by hash: the body this codec builds is not the body the server was sent"
    );
    // `/block/transaction` carries both index and hash, which this crate
    // never builds; only the recorded request's shape is checked.
    let bt: serde_json::Value = serde_json::from_str(
        find("N-submit-block-transaction")["request_body"].as_str().unwrap_or(""),
    )
    .unwrap_or_else(|e| panic!("the captured /block/transaction request is not JSON: {e}"));
    assert!(
        bt["block_identifier"]["hash"].is_string() && bt["block_identifier"]["index"].is_u64(),
        "the captured /block/transaction request no longer carries both index and hash"
    );
    println!(
        "  explorer requests: /block by index and /search by hash are byte-equal to the capture; \
         /block/transaction's recorded body carries index AND hash and is not built here"
    );
}

/// The captured replies parse into the fields the pages render, and the two
/// endpoints' different computations are both preserved.
///
/// For one transaction, `/block/transaction` gives three operations with the source
/// debited its NET `-10_000_500` and the change netted away, while
/// `/search/transactions` gives four with the source debited its GROSS
/// `-50_000_000` and the change back as its own destination. The metadata
/// values differ in JSON type by the same split -- decimal strings from
/// `/block`, numbers from `/search` -- and both are rendered as the endpoint
/// spelled them.
#[cfg(not(miri))]
#[test]
fn the_two_endpoints_disagree_and_both_renderings_are_kept() {
    let json = fixture_json(N_FILE);
    let vectors = json["vectors"].as_array().unwrap_or_else(|| panic!("no vectors"));
    let body = |id: &str| -> Vec<u8> {
        vectors
            .iter()
            .find(|v| v["id"].as_str() == Some(id))
            .unwrap_or_else(|| panic!("no {id}"))["response_body"]
            .as_str()
            .unwrap_or("")
            .as_bytes()
            .to_vec()
    };

    let one = codec::parse_block_transaction(&body("N-submit-block-transaction")).unwrap_or_else(|e| panic!("{e}"));
    let page = codec::parse_search(&body("N-submit-search")).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(page.total_count, 1);
    assert_eq!(page.next_offset, None, "a one-row page must carry no next_offset");
    let searched = page.transactions.first().unwrap_or_else(|| panic!("the search page is empty"));
    assert_eq!(one.hash, searched.hash, "the two endpoints rendered different transactions");

    // The operation counts and the source debit: net against gross.
    assert_eq!(one.operations.len(), 3, "/block/transaction no longer gives three operations");
    assert_eq!(searched.operations.len(), 4, "/search no longer gives four operations");
    let source = |t: &codec::MeshTransaction| -> i128 {
        t.operations
            .iter()
            .find(|o| o.kind == codec::OP_SOURCE)
            .unwrap_or_else(|| panic!("no source operation"))
            .amount
    };
    assert_eq!(source(&one), -10_000_500, "/block/transaction's source debit is not the NET");
    assert_eq!(source(searched), -50_000_000, "/search's source debit is not the GROSS");
    assert_eq!(
        source(searched) - source(&one),
        -39_999_500,
        "the difference between the two debits is not the change"
    );
    // The change is its own destination on /search and on neither on /block.
    let dests = |t: &codec::MeshTransaction| -> Vec<i128> {
        t.operations.iter().filter(|o| o.kind == codec::OP_DESTINATION).map(|o| o.amount).collect()
    };
    assert_eq!(dests(&one), vec![10_000_000], "/block/transaction carries a change destination");
    assert_eq!(dests(searched), vec![10_000_000, 39_999_500], "/search does not carry the change as a destination");

    // The metadata, in the spelling each endpoint used.
    let meta = |t: &codec::MeshTransaction, k: &str| -> String {
        t.metadata
            .iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| panic!("no metadata key {k}"))
    };
    assert_eq!(meta(&one, "block_to_live"), "0");
    assert_eq!(meta(searched, "block_to_live"), "0");
    assert_eq!(meta(searched, "send_total"), "10000000");
    assert_eq!(meta(searched, "change_total"), "39999500");
    assert_eq!(meta(searched, "fee_total"), "500");
    // The block and timestamp are on the search row and not on the other.
    assert_eq!(one.block, None);
    assert_eq!(searched.block.map(|b| b.index), Some(1_078_535));
    assert_eq!(searched.timestamp_ms, Some(1_788_500_208_000));
    println!(
        "  net vs gross: /block/transaction 3 ops with source -10,000,500; /search 4 ops with \
         source -50,000,000 and the change 39,999,500 as its own destination; the difference is \
         the change, and both metadata spellings are kept"
    );
}

/// `/block` parses into a whole block: identifier, parent, timestamp and
/// every transaction, the mining reward among them as its own transaction
/// with one `REWARD` operation.
#[cfg(not(miri))]
#[test]
fn the_captured_block_parses_with_its_reward_and_its_transactions() {
    let json = fixture_json(N_FILE);
    let vectors = json["vectors"].as_array().unwrap_or_else(|| panic!("no vectors"));
    let v = vectors
        .iter()
        .find(|v| v["id"].as_str() == Some("N-submit-block"))
        .unwrap_or_else(|| panic!("no N-submit-block"));
    let block = codec::parse_block(v["response_body"].as_str().unwrap_or("").as_bytes()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(block.block.index, 1_078_535);
    assert_eq!(block.parent.index, block.block.index - 1, "the parent is not one below");
    assert_eq!(block.timestamp_ms, 1_788_500_198_000);
    assert_eq!(block.transactions.len(), 5, "the captured block no longer carries five transactions");

    let rewards: Vec<&codec::MeshTransaction> = block
        .transactions
        .iter()
        .filter(|t| t.operations.iter().any(|o| o.kind == codec::OP_REWARD))
        .collect();
    assert_eq!(rewards.len(), 1, "a block has exactly one reward transaction");
    let reward = rewards[0].operations.first().unwrap_or_else(|| panic!("no reward operation"));
    assert_eq!(reward.amount, 12_065_840_589, "the captured reward moved");

    // What `block <n>` sums as "moved": destination transfers in the
    // non-reward transactions. This endpoint has no change operation, so the
    // sum is exactly the value delivered to payees.
    let moved: i128 = block
        .transactions
        .iter()
        .filter(|t| !t.operations.iter().any(|o| o.kind == codec::OP_REWARD))
        .flat_map(|t| t.operations.iter())
        .filter(|o| o.kind == codec::OP_DESTINATION)
        .map(|o| o.amount)
        .sum();
    assert_eq!(moved, 1_111_416_500, "the total delivered to payees in the captured block moved");
    println!(
        "  captured block 1,078,535: parent 1,078,534, 5 transactions, reward 12,065,840,589 \
         excluded, {moved} nanoMCM delivered to payees"
    );
}

/// The captured block's own figures parse as the trailer holds them, and its
/// kind follows from them by the reference's test.
///
/// Every value below is read from the capture's own reply, not from this
/// codec: `difficulty`, `fee`, `tx_count`, `block_size` and `stime` as JSON
/// numbers, the nonce and root as `0x` and 64 hex digits, the haiku with the
/// line breaks the middleware put in it. Four transactions besides the
/// reward and a block number whose low byte is 7 make it a normal block.
#[cfg(not(miri))]
#[test]
fn the_captured_block_carries_its_own_figures_and_reads_as_normal() {
    let json = fixture_json(N_FILE);
    let vectors = json["vectors"].as_array().unwrap_or_else(|| panic!("no vectors"));
    let v = vectors
        .iter()
        .find(|v| v["id"].as_str() == Some("N-submit-block"))
        .unwrap_or_else(|| panic!("no N-submit-block"));
    let body = v["response_body"].as_str().unwrap_or("");
    let block = codec::parse_block(body.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
    let raw: serde_json::Value = serde_json::from_str(body).unwrap_or_else(|e| panic!("{e}"));
    let recorded = &raw["block"]["metadata"];
    let m = block.metadata.as_ref().unwrap_or_else(|| panic!("the captured block's metadata was not read"));
    assert_eq!(Some(u64::from(m.difficulty)), recorded["difficulty"].as_u64());
    assert_eq!(Some(m.fee), recorded["fee"].as_u64());
    assert_eq!(Some(u64::from(m.tx_count)), recorded["tx_count"].as_u64());
    assert_eq!(Some(m.block_size), recorded["block_size"].as_u64());
    assert_eq!(Some(m.stime_ms), recorded["stime"].as_i64());
    assert_eq!(m.stime_ms, block.timestamp_ms, "the trailer's stime is the block's timestamp");
    assert_eq!(Some(m.haiku.as_str()), recorded["haiku"].as_str());
    let hexed = |b: &[u8; 32]| format!("0x{}", b.iter().map(|x| format!("{x:02x}")).collect::<String>());
    assert_eq!(Some(hexed(&m.nonce).as_str()), recorded["nonce"].as_str());
    assert_eq!(Some(hexed(&m.root).as_str()), recorded["root"].as_str());
    assert_eq!(m.tx_count, 4, "the captured block no longer counts four transactions");
    assert_eq!(block.transactions.len(), 5, "four and the reward");
    assert_eq!(block.block.index & 0xff, 7);
    assert_eq!(block.kind(), Some(codec::BlockKind::Normal));
    println!(
        "  captured block 1,078,535: difficulty {}, {} transaction(s), fee floor {}, {} bytes, normal",
        m.difficulty, m.tx_count, m.fee, m.block_size
    );
}

/// A block's metadata is read whole or not at all, and a value of the wrong
/// shape is refused by name; its kind follows the reference's test.
///
/// The reply below is the capture's shape with each case's change. A reply
/// with no `metadata`, or with one of the eight keys missing, reads with
/// none, so a deployment that writes fewer still has its blocks read; a
/// value there that does not fit its field refuses the whole reply, naming
/// the key, as every other field does.
#[cfg(not(miri))]
#[test]
fn block_metadata_is_whole_or_absent_and_a_misshapen_value_is_refused_by_name() {
    use serde_json::{json, Value};
    let zero = format!("0x{}", "00".repeat(32));
    let body = |index: u64, edit: &dyn Fn(&mut Value)| -> Vec<u8> {
        let mut v = json!({"block": {
            "block_identifier": {"index": index, "hash": zero},
            "parent_block_identifier": {"index": index.saturating_sub(1), "hash": zero},
            "timestamp": 1_788_500_198_000_i64,
            "transactions": [],
            "metadata": {
                "block_size": 9824, "difficulty": 37, "fee": 500,
                "haiku": "at night \nsoft snakes \nreturning ",
                "nonce": format!("0x{}", "0c".repeat(32)), "root": format!("0x{}", "fa".repeat(32)),
                "stime": 1_788_500_198_000_i64, "tx_count": 4,
            },
        }});
        edit(&mut v);
        serde_json::to_vec(&v).unwrap_or_else(|e| panic!("{e}"))
    };
    let read = |b: Vec<u8>| codec::parse_block(&b).unwrap_or_else(|e| panic!("{e}"));

    let whole = read(body(1_078_535, &|_| {}));
    assert!(whole.metadata.is_some());
    assert_eq!(whole.kind(), Some(codec::BlockKind::Normal));

    // Absent, null, or one key short: read as none, and the block still reads.
    let none = read(body(1_078_535, &|v| {
        v["block"].as_object_mut().map(|b| b.remove("metadata"));
    }));
    assert_eq!(none.metadata, None);
    assert_eq!(none.kind(), None, "with no count, only a neogenesis number names a kind");
    let null = read(body(1_078_535, &|v| v["block"]["metadata"] = Value::Null));
    assert_eq!(null.metadata, None);
    for key in ["block_size", "difficulty", "fee", "haiku", "nonce", "root", "stime", "tx_count"] {
        let short = read(body(1_078_535, &|v| {
            v["block"]["metadata"].as_object_mut().map(|m| m.remove(key));
        }));
        assert_eq!(short.metadata, None, "metadata without {key} was read");
    }

    // The kind, by the reference's test: no transactions is pseudo; a number
    // whose low byte is zero is neogenesis whatever the count, and with no
    // metadata at all.
    let pseudo = read(body(1_078_535, &|v| v["block"]["metadata"]["tx_count"] = json!(0)));
    assert_eq!(pseudo.kind(), Some(codec::BlockKind::Pseudo));
    assert_eq!(read(body(1_078_528, &|_| {})).kind(), Some(codec::BlockKind::Neogenesis));
    let neogenesis_bare = read(body(1_078_528, &|v| {
        v["block"].as_object_mut().map(|b| b.remove("metadata"));
    }));
    assert_eq!(neogenesis_bare.kind(), Some(codec::BlockKind::Neogenesis));
    assert_eq!(read(body(1_078_529, &|_| {})).kind(), Some(codec::BlockKind::Normal));

    // A value that does not fit is refused, naming the key.
    let refused: [(&str, Value, &str); 7] = [
        ("difficulty", json!(4_294_967_296_u64), "metadata.difficulty"),
        ("tx_count", json!("4"), "metadata.tx_count"),
        ("fee", json!(-1), "metadata.fee"),
        ("block_size", json!(1.5), "metadata.block_size"),
        ("stime", json!("1788500198000"), "metadata.stime"),
        ("haiku", json!("x".repeat(codec::MAX_HAIKU_BYTES + 1)), "metadata.haiku: too long"),
        ("haiku", json!(7), "metadata.haiku"),
    ];
    for (key, value, want) in refused {
        let b = body(1_078_535, &|v| v["block"]["metadata"][key] = value.clone());
        match codec::parse_block(&b) {
            Err(Error::MeshResponse { what }) => assert_eq!(what, want, "{key}"),
            other => panic!("{key} = {value} was not refused as {want}: {other:?}"),
        }
    }
    let longest = read(body(1_078_535, &|v| v["block"]["metadata"]["haiku"] = json!("x".repeat(codec::MAX_HAIKU_BYTES))));
    assert_eq!(longest.metadata.map(|m| m.haiku.len()), Some(codec::MAX_HAIKU_BYTES));
    // A hash one byte long is refused by its length, and one with no `0x` as
    // hex at offset 0, each naming the key.
    for key in ["nonce", "root"] {
        let b = body(1_078_535, &|v| v["block"]["metadata"][key] = json!("0x00"));
        assert!(
            matches!(codec::parse_block(&b), Err(Error::Length { what, expected: 32, got: 1 }) if what == format!("metadata.{key}")),
            "a short {key} was not refused by name"
        );
        let b = body(1_078_535, &|v| v["block"]["metadata"][key] = json!("00".repeat(32)));
        assert!(
            matches!(codec::parse_block(&b), Err(Error::Hex { what, offset: 0 }) if what == format!("metadata.{key}")),
            "a {key} with no 0x was not refused by name"
        );
    }
    let b = body(1_078_535, &|v| v["block"]["metadata"] = json!([1, 2]));
    assert!(matches!(codec::parse_block(&b), Err(Error::MeshResponse { what: "metadata" })), "metadata that is not an object was not refused");
    println!("  block metadata: read whole or as none (absent, null, eight keys one short); 7 shapes and 2 hashes two ways refused by name; pseudo, neogenesis and normal by the reference's test");
}

/// The captured status reads whole and the captured list names its one
/// network, every value compared against the capture's own reply.
#[cfg(not(miri))]
#[test]
fn the_captured_status_and_list_read_whole() {
    let json = fixture_json(N_FILE);
    let vectors = json["vectors"].as_array().unwrap_or_else(|| panic!("no vectors"));
    let reply = |id: &str| -> String {
        vectors
            .iter()
            .find(|v| v["id"].as_str() == Some(id))
            .and_then(|v| v["response_body"].as_str())
            .unwrap_or_else(|| panic!("no {id}"))
            .to_owned()
    };
    let status = reply("N-network-status");
    let raw: serde_json::Value = serde_json::from_str(&status).unwrap_or_else(|e| panic!("{e}"));
    let full = codec::parse_network_status_full(status.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(Some(full.tip.index), raw["current_block_identifier"]["index"].as_u64());
    assert_eq!(Some(full.tip_timestamp_ms), raw["current_block_timestamp"].as_i64());
    assert_eq!(full.tip_timestamp_ms, 1_788_539_881_000);
    assert_eq!(Some(full.genesis.index), raw["genesis_block_identifier"]["index"].as_u64());
    assert_eq!(
        Some(format!("0x{}", hex::encode(&full.genesis.hash)).as_str()),
        raw["genesis_block_identifier"]["hash"].as_str()
    );
    assert_eq!(
        full.sync,
        Some(codec::SyncStatus { stage: "synchronized".to_owned(), synced: true })
    );
    let list = codec::parse_network_identifiers(reply("N-network-list").as_bytes()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(list, [codec::NetworkIdentifier { blockchain: "mochimo".to_owned(), network: "mainnet".to_owned() }]);
    println!(
        "  captured status: tip {} solved at {} ms, genesis 0, synchronized; captured list: mochimo mainnet",
        full.tip.index, full.tip_timestamp_ms
    );
}

/// The full status and the network list refuse what does not fit, by name,
/// and read an absent sync state as none.
#[cfg(not(miri))]
#[test]
fn the_full_status_and_the_network_list_refuse_by_field() {
    use serde_json::{json, Value};
    let zero = format!("0x{}", "00".repeat(32));
    let status = |edit: &dyn Fn(&mut Value)| -> Vec<u8> {
        let mut v = json!({
            "current_block_identifier": {"index": 1_078_875, "hash": zero},
            "current_block_timestamp": 1_788_539_881_000_i64,
            "genesis_block_identifier": {"index": 0, "hash": zero},
            "oldest_block_identifier": {"index": 0, "hash": ""},
            "sync_status": {"stage": "synchronized", "synced": true},
        });
        edit(&mut v);
        serde_json::to_vec(&v).unwrap_or_else(|e| panic!("{e}"))
    };
    let whole = codec::parse_network_status_full(&status(&|_| {})).unwrap_or_else(|e| panic!("{e}"));
    assert!(whole.sync.is_some());
    for absent in [None, Some(Value::Null)] {
        let b = status(&|v| match &absent {
            None => {
                v.as_object_mut().map(|m| m.remove("sync_status"));
            }
            Some(null) => v["sync_status"] = null.clone(),
        });
        let read = codec::parse_network_status_full(&b).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(read.sync, None, "an absent sync state was not read as none");
    }
    /// One change to the reply, erased to the shape the table shares.
    type Edit = dyn Fn(&mut Value);
    let refused: [(&Edit, &str); 7] = [
        (&|v| { v.as_object_mut().map(|m| m.remove("current_block_timestamp")); }, "current_block_timestamp"),
        (&|v| v["current_block_timestamp"] = json!(1.5), "current_block_timestamp"),
        (&|v| { v.as_object_mut().map(|m| m.remove("genesis_block_identifier")); }, "genesis_block_identifier.index"),
        (&|v| v["sync_status"] = json!("synchronized"), "sync_status"),
        (&|v| { v["sync_status"].as_object_mut().map(|m| m.remove("stage")); }, "sync_status.stage"),
        (&|v| v["sync_status"]["stage"] = json!("x".repeat(codec::MAX_SYNC_STAGE_BYTES + 1)), "sync_status.stage"),
        (&|v| v["sync_status"]["synced"] = json!("true"), "sync_status.synced"),
    ];
    for (edit, want) in refused {
        match codec::parse_network_status_full(&status(edit)) {
            Err(Error::MeshResponse { what }) => assert_eq!(what, want),
            other => panic!("{want} was not refused: {other:?}"),
        }
    }
    let longest = status(&|v| v["sync_status"]["stage"] = json!("x".repeat(codec::MAX_SYNC_STAGE_BYTES)));
    assert!(codec::parse_network_status_full(&longest).is_ok(), "the longest stage was refused");

    let list = |entries: Value| serde_json::to_vec(&json!({"network_identifiers": entries})).unwrap_or_else(|e| panic!("{e}"));
    let one = json!({"blockchain": "mochimo", "network": "mainnet"});
    let many: Vec<Value> = (0..=codec::MAX_NETWORKS).map(|_| one.clone()).collect();
    let cases: [(Vec<u8>, &str); 4] = [
        (list(json!(many)), "network_identifiers: too many"),
        (list(json!([{"blockchain": "mochimo", "network": "x".repeat(codec::MAX_NETWORK_NAME_BYTES + 1)}])), "network_identifiers[].network"),
        (list(json!([{"network": "mainnet"}])), "network_identifiers[].blockchain"),
        (list(json!("mainnet")), "network_identifiers: array"),
    ];
    for (b, want) in cases {
        match codec::parse_network_identifiers(&b) {
            Err(Error::MeshResponse { what }) => assert_eq!(what, want),
            other => panic!("{want} was not refused: {other:?}"),
        }
    }
    let at_most: Vec<Value> = (0..codec::MAX_NETWORKS).map(|_| one.clone()).collect();
    assert_eq!(codec::parse_network_identifiers(&list(json!(at_most))).map(|l| l.len()).ok(), Some(codec::MAX_NETWORKS));
    println!("  network status: 7 refusals by name, an absent or null sync state read as none; network list: 4 refusals by name, {} entries taken", codec::MAX_NETWORKS);
}

/// `network_status_full` and `networks` post to their endpoints with the
/// bodies the codec builds, and return what the replies say.
#[cfg(not(miri))]
#[test]
fn the_two_network_reads_post_where_they_say() {
    use std::cell::RefCell;
    struct Recorder {
        posted: RefCell<Vec<(String, Vec<u8>)>>,
        status: Vec<u8>,
        list: Vec<u8>,
    }
    impl mesh::Transport for Recorder {
        fn post(&self, path: &str, body: &[u8]) -> Result<Vec<u8>, Error> {
            self.posted.borrow_mut().push((path.to_owned(), body.to_vec()));
            Ok(match path {
                "/network/status" => self.status.clone(),
                "/network/list" => self.list.clone(),
                other => panic!("posted to {other}"),
            })
        }
    }
    let json = fixture_json(N_FILE);
    let vectors = json["vectors"].as_array().unwrap_or_else(|| panic!("no vectors"));
    let reply = |id: &str| -> Vec<u8> {
        vectors
            .iter()
            .find(|v| v["id"].as_str() == Some(id))
            .and_then(|v| v["response_body"].as_str())
            .unwrap_or_else(|| panic!("no {id}"))
            .as_bytes()
            .to_vec()
    };
    let client = mesh::MeshClient::new(Recorder {
        posted: RefCell::new(Vec::new()),
        status: reply("N-network-status"),
        list: reply("N-network-list"),
    });
    let full = client.network_status_full().unwrap_or_else(|e| panic!("{e}"));
    let named = client.networks().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(full.tip.index, 1_078_875);
    assert_eq!(named.len(), 1);
    let posted = client.transport().posted.borrow().clone();
    assert_eq!(
        posted,
        [
            ("/network/status".to_owned(), codec::request_network_status()),
            ("/network/list".to_owned(), codec::request_network_list()),
        ]
    );
    println!("  network reads: /network/status and /network/list, each once, with the codec's bodies");
}

/// The mempool's two replies parse, and refuse what does not fit, by name.
/// No group N vector records either endpoint, so the shapes are taken from
/// the middleware's handlers: `/mempool` lists `{"hash": "0x…"}` objects, an
/// empty queue encodes as `null`, and `/mempool/transaction` has
/// `/block/transaction`'s shape.
#[cfg(not(miri))]
#[test]
fn the_mempool_replies_parse_and_refuse_by_field() {
    use serde_json::json;
    let id = |b: u8| format!("0x{}", hex::encode(&[b; 32]));
    let listed = codec::parse_mempool(json!({"transaction_identifiers": [{"hash": id(0xa1)}, {"hash": id(0xb2)}]}).to_string().as_bytes())
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(listed, [[0xa1; 32], [0xb2; 32]], "the ids are not the queue's, in its order");
    let empty = codec::parse_mempool(br#"{"transaction_identifiers":null}"#).unwrap_or_else(|e| panic!("{e}"));
    assert!(empty.is_empty(), "an empty queue's null was not read as none");
    let none = codec::parse_mempool(br#"{"transaction_identifiers":[]}"#).unwrap_or_else(|e| panic!("{e}"));
    assert!(none.is_empty());

    // Past the row bound with entries small enough to fit the size cap, so
    // the bound itself is what refuses; at full width a list that long is
    // already over the cap and refused by size, below.
    let too_many: Vec<serde_json::Value> = (0..=4096).map(|_| json!({"hash": ""})).collect();
    let cases: [(String, &str); 4] = [
        (json!({}).to_string(), "transaction_identifiers"),
        (json!({"transaction_identifiers": "0x00"}).to_string(), "transaction_identifiers: array"),
        (json!({"transaction_identifiers": too_many}).to_string(), "transaction_identifiers: too many"),
        (json!({"transaction_identifiers": [{"id": id(0)}]}).to_string(), "transaction_identifiers[].hash"),
    ];
    for (body, want) in cases {
        match codec::parse_mempool(body.as_bytes()) {
            Err(Error::MeshResponse { what }) => assert_eq!(what, want),
            other => panic!("{want} was not refused: {other:?}"),
        }
    }
    let wide: Vec<serde_json::Value> = (0..4000).map(|_| json!({"hash": id(0)})).collect();
    assert!(
        matches!(
            codec::parse_mempool(json!({"transaction_identifiers": wide}).to_string().as_bytes()),
            Err(Error::PayloadTooLarge { max: MAX_HISTORY_RESPONSE_BYTES, .. })
        ),
        "a queue list over the history cap was not refused by size"
    );
    assert!(
        matches!(
            codec::parse_mempool(json!({"transaction_identifiers": [{"hash": "0x00"}]}).to_string().as_bytes()),
            Err(Error::Length { what: "transaction_identifiers[].hash", expected: 32, got: 1 })
        ),
        "a short id was not refused by its length"
    );
    // The handler's own error, through a 200, as every endpoint's.
    assert!(matches!(
        codec::parse_mempool(br#"{"code":2,"message":"Internal general error","retriable":true}"#),
        Err(Error::Mesh { code: 2, .. })
    ));
    assert!(matches!(
        codec::parse_mempool_transaction(br#"{"code":3,"message":"Transaction not found","retriable":true}"#),
        Err(Error::Mesh { code: 3, .. })
    ));

    // One waiting transaction: /block's rendering, so /block/transaction's
    // parser reads it, the reference with it.
    let pending = json!({"transaction": {
        "transaction_identifier": {"hash": id(0xa1)},
        "operations": [
            {"operation_identifier": {"index": 0}, "type": "DESTINATION_TRANSFER", "status": "PENDING",
             "account": {"address": "0xdbc01bb8a41f3dc24b0083bb6b9efe910e2477cb"}, "amount": {"value": "10000000"},
             "metadata": {"memo": "AB-00-EF\0\0\0\0\0\0\0\0"}},
            {"operation_identifier": {"index": 1}, "type": "SOURCE_TRANSFER", "status": "PENDING",
             "account": {"address": "0x371c388eba10f265c648008e1ad2c94e680c0f4a"}, "amount": {"value": "-10000500"}},
            {"operation_identifier": {"index": 2}, "type": "FEE", "status": "PENDING",
             "account": {"address": "0x0000000000000000000000000000000000000000"}, "amount": {"value": "500"}},
        ],
        "metadata": {"block_to_live": "0"},
    }})
    .to_string();
    let t = codec::parse_mempool_transaction(pending.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(t, codec::parse_block_transaction(pending.as_bytes()).unwrap_or_else(|e| panic!("{e}")));
    assert_eq!(t.hash, [0xa1; 32]);
    assert_eq!(t.operations.len(), 3);
    assert_eq!(t.operations[0].memo, "AB-00-EF\0\0\0\0\0\0\0\0", "the reference is kept as the middleware sent it");

    // The request bodies the handlers read.
    assert_eq!(codec::request_mempool(), br#"{"network_identifier":{"blockchain":"mochimo","network":"mainnet"}}"#.to_vec());
    assert_eq!(
        codec::request_mempool_transaction(&[0xab; 32]),
        format!(r#"{{"network_identifier":{{"blockchain":"mochimo","network":"mainnet"}},"transaction_identifier":{{"hash":"0x{}"}}}}"#, "ab".repeat(32)).into_bytes(),
        "the id is not sent as the handler's fmt.Sprintf(\"0x%x\") spells it"
    );
    println!("  mempool: ids in the queue's order, null read as none, 4 shapes, a short id and a list over the cap refused, a waiting transaction read as /block renders one");
}

/// The widest recorded body of each shape in
/// `fixtures/group_n_mesh_live.json`, restated here rather than read from the
/// fixture so the two can disagree.
///
/// The history cap must hold a full `--count 100` page of search rows. The
/// reconciliation cap stays small on purpose, since it bounds an allocation
/// whose size a remote server chooses.
const WIDEST_SEARCH_ROW: usize = 1_221;
const WIDEST_BLOCK_TX: usize = 1_020;
const WIDEST_RECON_REPLY: usize = 664;
/// `--count`'s ceiling in `cli::args`. The history cap must hold this many
/// rows, or `--count 100` would parse but be refused by the transport.
const MAX_COUNT: usize = 100;

/// The caps against the endpoints they serve, checked at compile time.
const _: () = assert!(
    MAX_HISTORY_RESPONSE_BYTES >= WIDEST_SEARCH_ROW * MAX_COUNT,
    "the history cap does not hold a full `--count 100` page of the widest recorded search row"
);
const _: () = assert!(
    MAX_HISTORY_RESPONSE_BYTES >= WIDEST_BLOCK_TX * 64,
    "the history cap does not hold a 64-transaction block at the widest recorded transaction"
);
const _: () = assert!(
    MAX_RECON_RESPONSE_BYTES >= WIDEST_RECON_REPLY * 4,
    "the reconciliation cap leaves no headroom over the widest recorded reply"
);
const _: () = assert!(
    MAX_RECON_RESPONSE_BYTES < MAX_HISTORY_RESPONSE_BYTES,
    "the reconciliation cap is not tighter than the history cap, so it bounds nothing"
);

/// Every endpoint the client posts to resolves to the right one of the two
/// caps. The sizes themselves are checked by the `const` assertions above.
#[cfg(not(miri))]
#[test]
fn every_endpoint_resolves_to_the_cap_its_replies_need() {
    for path in ["/call", "/account/balance", "/account/entitlement", "/network/status", "/network/list", "/construction/submit"] {
        assert_eq!(max_response_bytes(path), MAX_RECON_RESPONSE_BYTES, "{path}");
    }
    for path in ["/block", "/search/transactions", "/mempool", "/mempool/transaction"] {
        assert_eq!(max_response_bytes(path), MAX_HISTORY_RESPONSE_BYTES, "{path}");
    }
    // A path this table does not name is not a reason to widen an allocation.
    assert_eq!(max_response_bytes("/something/new"), MAX_RECON_RESPONSE_BYTES);
    println!(
        "  response caps: recon {MAX_RECON_RESPONSE_BYTES} B, history {MAX_HISTORY_RESPONSE_BYTES} B \
         (a --count {MAX_COUNT} page of {WIDEST_SEARCH_ROW}-byte rows is {} B)",
        WIDEST_SEARCH_ROW * MAX_COUNT
    );
}

/// The explorer parsers refuse an oversize body by size before parsing it,
/// and a body missing a documented field by naming that field. Neither
/// includes response bytes.
#[cfg(not(miri))]
#[test]
fn the_explorer_parsers_refuse_by_size_and_by_field() {

    // One byte over the cap, valid JSON, refused before parsing.
    let mut oversize = br#"{"block":{"pad":""#.to_vec();
    oversize.resize(MAX_HISTORY_RESPONSE_BYTES + 1, b'x');
    /// One parser, erased to the shape these tables share.
    type Parse = fn(&[u8]) -> Result<(), Error>;

    let by_size: [(&str, Parse); 3] = [
        ("parse_block", |b| codec::parse_block(b).map(|_| ())),
        ("parse_block_transaction", |b| codec::parse_block_transaction(b).map(|_| ())),
        ("parse_search", |b| codec::parse_search(b).map(|_| ())),
    ];
    for (what, run) in by_size {
        let e = run(&oversize);
        match e {
            Err(Error::PayloadTooLarge { what: w, max, got }) => {
                assert_eq!(w, "response body", "{what}");
                assert_eq!(max, MAX_HISTORY_RESPONSE_BYTES, "{what}");
                assert_eq!(got, MAX_HISTORY_RESPONSE_BYTES + 1, "{what}");
            }
            other => panic!("{what} did not refuse an oversize body by size: {other:?}"),
        }
    }

    // A field removed from each documented shape, and the field it names.
    let cases: [(&str, &str, Parse); 6] = [
        (
            r#"{"block":{"parent_block_identifier":{"index":1,"hash":"0x00"},"timestamp":1,"transactions":[]}}"#,
            "block_identifier.index",
            |b| codec::parse_block(b).map(|_| ()),
        ),
        (
            r#"{"block":{"block_identifier":{"index":2,"hash":"0x0000000000000000000000000000000000000000000000000000000000000000"},"parent_block_identifier":{"index":1,"hash":"0x0000000000000000000000000000000000000000000000000000000000000000"},"transactions":[]}}"#,
            "timestamp",
            |b| codec::parse_block(b).map(|_| ()),
        ),
        (
            r#"{"transaction":{"operations":[]}}"#,
            "transaction_identifier",
            |b| codec::parse_block_transaction(b).map(|_| ()),
        ),
        (
            r#"{"transaction":{"transaction_identifier":{"hash":"0x0000000000000000000000000000000000000000000000000000000000000000"}}}"#,
            "operations",
            |b| codec::parse_block_transaction(b).map(|_| ()),
        ),
        (r#"{"total_count":0}"#, "transactions", |b| codec::parse_search(b).map(|_| ())),
        (r#"{"transactions":[]}"#, "total_count", |b| codec::parse_search(b).map(|_| ())),
    ];
    for (body, want, run) in cases {
        match run(body.as_bytes()) {
            Err(Error::MeshResponse { what }) => assert_eq!(what, want, "the refusal named {what}, not {want}"),
            other => panic!("{want} was not missed: {other:?}"),
        }
    }

    // An amount that is a JSON number rather than the decimal string both
    // endpoints send is refused, not coerced.
    let numeric = r#"{"transaction":{"transaction_identifier":{"hash":"0x0000000000000000000000000000000000000000000000000000000000000000"},"operations":[{"operation_identifier":{"index":0},"type":"FEE","account":{"address":"0x00"},"amount":{"value":500}}]}}"#;
    match codec::parse_block_transaction(numeric.as_bytes()) {
        Err(Error::MeshResponse { what }) => assert_eq!(what, "operations[].amount.value"),
        other => panic!("a numeric amount was accepted: {other:?}"),
    }
    println!(
        "  explorer refusals: 3 parsers refuse an oversize body by size, 6 missing fields are each \
         named, and an amount sent as a number rather than a decimal string is refused"
    );
}

/// `/account/entitlement`, request and reply. The request names the tag
/// in the 42-character form `/account/balance` takes, with sorted keys. The
/// reply in the endpoint's contract parses to the figure and the block it
/// was read at; a reply naming another account, a currency that is not
/// MCM/9, a value that is not a decimal string, and the middleware's error
/// shapes -- 4 not found, 8 invalid account format, 9 service unavailable,
/// 10 rate limited -- are refused by name.
#[test]
fn the_entitlement_endpoint_is_read_by_its_contract_and_refused_off_it() {
    let tag = [0x92u8; 20];
    let hex_tag: String = tag.iter().map(|b| format!("{b:02x}")).collect();
    let req = String::from_utf8(codec::request_account_entitlement(&tag)).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        req,
        format!(r#"{{"account_identifier":{{"address":"0x{hex_tag}"}},"network_identifier":{{"blockchain":"mochimo","network":"mainnet"}}}}"#)
    );
    let reply = |address: &str, value: &str, symbol: &str, decimals: u64| {
        format!(
            r#"{{"block_identifier":{{"index":1124001,"hash":"0x{}"}},"account_identifier":{{"address":"{address}"}},"entitlement":{{"value":"{value}","currency":{{"symbol":"{symbol}","decimals":{decimals}}}}}}}"#,
            "ab".repeat(32)
        )
        .into_bytes()
    };
    let ok = codec::parse_account_entitlement(&reply(&format!("0x{hex_tag}"), "21582964000000", "MCM", 9), &tag)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(ok.entitlement, 21_582_964_000_000);
    assert_eq!(ok.tip.index, 1_124_001);
    let other = format!("0x{}", "93".repeat(20));
    let refusals: [(Vec<u8>, &str); 5] = [
        (reply(&other, "1", "MCM", 9), "account_identifier.address: not the tag asked about"),
        (reply(&format!("0x{hex_tag}"), "1", "BTC", 9), "entitlement.currency.symbol: not MCM"),
        (reply(&format!("0x{hex_tag}"), "1", "MCM", 8), "entitlement.currency.decimals: not 9"),
        (reply(&format!("0x{hex_tag}"), "+1", "MCM", 9), "entitlement.value: decimal"),
        (reply(&format!("0x{hex_tag}"), "", "MCM", 9), "entitlement.value: decimal"),
    ];
    for (body, what) in refusals {
        assert_eq!(codec::parse_account_entitlement(&body, &tag).err(), Some(Error::MeshResponse { what }), "{what}");
    }
    for (code, retriable) in [(4u64, true), (8, false), (9, true), (10, true)] {
        let body = format!(r#"{{"code":{code},"message":"m","retriable":{retriable}}}"#).into_bytes();
        assert_eq!(codec::parse_account_entitlement(&body, &tag).err(), Some(Error::Mesh { code, retriable }));
    }
    println!("  entitlement endpoint: request pinned, one reply read, 5 shapes and 4 error codes refused");
}

/// The v4.1 reads: `/account/balance`'s stake metadata and `/stats/staking`,
/// in the shapes the middleware's `stakeMetadata` and `stakingHandler`
/// write. No live reply has been recorded. Asserted: every field is read
/// into its place; a
/// reply with no metadata is a stake of `None`, not of zero; a
/// `metadata.spendable` that disagrees with `balances[0].value` is refused;
/// a weight above 64 bits is read whole; and the summary's optional parts
/// may be absent.
#[test]
fn the_v41_stake_reads_parse_the_middlewares_shapes() {
    let h = "0x".to_string() + &"ab".repeat(32);
    let mcm = r#"{"symbol":"MCM","decimals":9}"#;
    let staking = format!(
        r#"{{"block_identifier":{{"index":1136500,"hash":"{h}"}},"balances":[{{"value":"7000000000","currency":{mcm}}}],"metadata":{{"spendable":"7000000000","staked":"500000000000","stake_source":"node","stake_block_index":1136499,"entitlement":"42000","total":"507000042000","stake":{{"commit":1136385,"expiry":1202176,"locked":true,"tier":0,"coefficient":1,"weight":"500000042000"}}}}}}"#
    );
    let at = codec::parse_account_stake(staking.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(at.tip.index, 1_136_500);
    assert_eq!(at.spendable, 7_000_000_000);
    let s = at.stake.unwrap_or_else(|| panic!("no stake read"));
    assert_eq!((s.staked, s.block, s.entitlement, s.total), (500_000_000_000, 1_136_499, Some(42_000), Some(507_000_042_000)));
    assert_eq!(s.source, codec::StakeSource::Node);
    let t = s.terms.unwrap_or_else(|| panic!("no terms"));
    assert_eq!((t.commit, t.expiry, t.locked, t.tier, t.coefficient, t.weight), (1_136_385, 1_202_176, true, Some(0), Some(1), Some(500_000_042_000)));

    let plain = format!(r#"{{"block_identifier":{{"index":9,"hash":"{h}"}},"balances":[{{"value":"5","currency":{mcm}}}]}}"#);
    let at = codec::parse_account_stake(plain.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!((at.spendable, at.stake), (5, None), "no metadata is no stake fields, not a stake of zero");

    let none = format!(
        r#"{{"block_identifier":{{"index":9,"hash":"{h}"}},"balances":[{{"value":"5","currency":{mcm}}}],"metadata":{{"spendable":"5","staked":"0","stake_source":"ledger_cache","stake_block_index":8}}}}"#
    );
    let s = codec::parse_account_stake(none.as_bytes()).unwrap_or_else(|e| panic!("{e}")).stake.unwrap_or_else(|| panic!("none"));
    assert_eq!((s.staked, s.source, s.terms, s.entitlement), (0, codec::StakeSource::LedgerCache, None, None));
    assert_eq!(s.consent, None, "no consent object is no consent report");

    let consent = none.replace(
        r#""stake_block_index":8}"#,
        r#""stake_block_index":8,"consent":{"kind":1,"height":7,"lapses_at":65543,"live":true,"digest":"0x00"}}"#,
    );
    let s = codec::parse_account_stake(consent.as_bytes()).unwrap_or_else(|e| panic!("{e}")).stake.unwrap_or_else(|| panic!("none"));
    assert_eq!(s.consent, Some(codec::ConsentReport { kind: 1, height: 7, live: true }));
    let bad_kind = consent.replace(r#""kind":1"#, r#""kind":256"#);
    assert!(matches!(
        codec::parse_account_stake(bad_kind.as_bytes()),
        Err(Error::MeshResponse { what: "metadata.consent.kind" })
    ));

    let contradiction = none.replace(r#""spendable":"5""#, r#""spendable":"6""#);
    assert!(matches!(
        codec::parse_account_stake(contradiction.as_bytes()),
        Err(Error::MeshResponse { what: "metadata.spendable: not balances[0].value" })
    ));

    let stats = format!(
        r#"{{"block_identifier":{{"index":1136500,"hash":"{h}"}},"v41_trigger":1136384,"v41_active":true,"min_stake":{{"value":"500000000000","currency":{mcm}}},"stake_set":{{"block_identifier":{{"index":1136499,"hash":"{h}"}},"count":2,"pool":{{"value":"2500000000","currency":{mcm}}},"forfeit":{{"value":"0","currency":{mcm}}},"dust":{{"value":"1","currency":{mcm}}},"weight":"36893488147419103232"}},"ledger":{{"block_index":1136400,"last_updated":"2026-11-01T12:00:00Z","stakers":2,"staked":{{"value":"1200000000000","currency":{mcm}}},"weight":"3600000000000"}}}}"#
    );
    let st = codec::parse_staking_stats(stats.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!((st.tip.index, st.trigger, st.active, st.min_stake), (1_136_500, Some(1_136_384), true, 500_000_000_000));
    let ss = st.stake_set.unwrap_or_else(|| panic!("no stake set"));
    assert_eq!((ss.block.index, ss.count, ss.pool, ss.forfeit, ss.dust), (1_136_499, 2, 2_500_000_000, 0, 1));
    assert_eq!(ss.weight, 1u128 << 65, "a weight above 64 bits is read whole");
    let l = st.ledger.unwrap_or_else(|| panic!("no ledger"));
    assert_eq!((l.block, l.stakers, l.staked, l.weight), (1_136_400, 2, 1_200_000_000_000, 3_600_000_000_000));

    let bare = format!(
        r#"{{"block_identifier":{{"index":7,"hash":"{h}"}},"v41_active":false,"min_stake":{{"value":"500000000000","currency":{mcm}}}}}"#
    );
    let st = codec::parse_staking_stats(bare.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!((st.trigger, st.active, st.stake_set, st.ledger), (None, false, None, None));
    assert_eq!(
        String::from_utf8(codec::request_staking_stats()).unwrap_or_else(|e| panic!("{e}")),
        r#"{"network_identifier":{"blockchain":"mochimo","network":"mainnet"}}"#
    );
    println!("  v4.1 reads: stake metadata, none, unreported, contradiction refused; staking summary full and bare");
}
