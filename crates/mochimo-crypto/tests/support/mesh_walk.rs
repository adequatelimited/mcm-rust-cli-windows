// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! Replays of the group M and group N fixtures, shared by `kat.rs` (which
//! implements [`Vector`] with coverage tracking) and `mesh.rs`'s C-free run
//! (which uses [`Plain`]).
//!
//! # Group N
//!
//! `fixtures/group_n_mesh_live.json` is a capture of requests to
//! `api.mochimo.org` at one block, with the replies. The replay checks that
//! `mesh::codec` builds byte-identical requests, and that parsed values agree
//! with independent sources: the tag sent is the prefix of the address
//! returned; `/call` and `/account/balance` agree on the balance;
//! `/construction/hash` returns the id digest recorded in group D; and each
//! error code matches the middleware's `handlers.go`. It describes the
//! deployed middleware's behaviour, not the codec's correctness.
//!
//! # Group M
//!
//! `fixtures/group_m_mesh_client.json` records the Mochimo TypeScript Mesh
//! client run against a recording `fetch` stub. Every recorded boolean is
//! recomputed from the sidecar bytes: what the client sent, what it signed
//! and what it discarded. These are behaviours of that client that this
//! crate does not share.
//!
//! # Dispatch
//!
//! By `source`, one handler per source, named after the Go handler or
//! TypeScript method it cites. A source with vectors of different shapes
//! routes on the vector id and panics on an unknown one.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::OnceLock;

use mochimo_crypto::account;
use mochimo_crypto::addr::{self, Address, Tag};
use mochimo_crypto::consts::{ADDR_LEN, ADDR_REF_LEN, ADDR_TAG_LEN, HASHLEN, MFEE, PK_LEN, SIG_LEN};
use mochimo_crypto::keystore;
use mochimo_crypto::mesh::{self, codec, hex, spend, MAX_REQUEST_BYTES};
use mochimo_crypto::tx::wire::{self as tx_wire, Transaction};
use mochimo_crypto::wots::{self, Adrs};
use mochimo_crypto::Error;

// --- the sources, verbatim from the fixtures ------------------------------

pub const N_LIST: &str = "networkListHandler() @ reference/mochimo-mesh/network_handler.go:15";
pub const N_STATUS: &str = "networkStatusHandler() @ reference/mochimo-mesh/network_handler.go:57";
pub const N_OPTIONS: &str = "networkOptionsHandler() @ reference/mochimo-mesh/network_handler.go:135";
pub const N_CALL: &str = "callHandler() @ reference/mochimo-mesh/call_handler.go:26";
pub const N_BALANCE: &str = "accountBalanceHandler() @ reference/mochimo-mesh/account_handler.go:23";
pub const N_METADATA: &str =
    "constructionMetadataHandler() @ reference/mochimo-mesh/construction_handler.go:215";
pub const N_PARSE: &str = "constructionParseHandler() @ reference/mochimo-mesh/construction_handler.go:541";
pub const N_HASH: &str = "constructionHashHandler() @ reference/mochimo-mesh/construction_handler.go:609";
pub const N_CAP: &str = "maxRequestSizeMiddleware() @ reference/mochimo-mesh/main.go:49";

/// The three block reads, all reading a SEALED block rather than the tip.
pub const N_BLOCK: &str = "blockHandler() @ reference/mochimo-mesh/block_handler.go:23";
pub const N_BLOCK_TX: &str = "blockTransactionHandler() @ reference/mochimo-mesh/block_handler.go:285";
pub const N_SEARCH: &str = "searchTransactionsHandler() @ reference/mochimo-mesh/search_handler.go:49";

pub const M_REQUESTS: &str = "MochimoApiClient.makeRequest() @ reference/mochimo-mesh-api-client/src/api.ts:111";
pub const M_CHANGE: &str =
    "TransactionBuilder.buildAndSignTransaction() @ reference/mochimo-mesh-api-client/src/transaction.ts:214";
pub const M_SIGNED: &str = "sourceWallet.sign(MochimoHasher.hash(unsigned_transaction)) @ \
                            reference/mochimo-mesh-api-client/src/transaction.ts:241";
pub const M_LOCAL: &str =
    "TransactionBuilder.createTransactionBytes() @ reference/mochimo-mesh-api-client/src/transaction.ts:28";
pub const M_OPTIONS: &str =
    "TransactionBuilder.buildTransaction() @ reference/mochimo-mesh-api-client/src/transaction.ts:70";
pub const M_COMBINE: &str =
    "TransactionBuilder.submitSignedTransaction() @ reference/mochimo-mesh-api-client/src/transaction.ts:157";

/// Every source above, for the C-free binary's dispatch and its stated count.
pub const SOURCES: [&str; 18] = [
    N_LIST, N_STATUS, N_OPTIONS, N_CALL, N_BALANCE, N_METADATA, N_PARSE, N_HASH, N_CAP, N_BLOCK, N_BLOCK_TX,
    N_SEARCH, M_REQUESTS, M_CHANGE, M_SIGNED, M_LOCAL, M_OPTIONS, M_COMBINE,
];

/// The accessor-and-assertion surface a handler needs. `kat.rs`'s `Ctx`
/// implements it with coverage recording; [`Plain`] below with panics.
pub trait Vector {
    fn id(&self) -> String;
    fn has(&self, key: &str) -> bool;
    fn str_(&self, key: &str) -> String;
    fn hex(&self, key: &str) -> Vec<u8>;
    fn u64_(&self, key: &str) -> u64;
    fn bool_(&self, key: &str) -> bool;
    /// `<key>_file` loaded and checked against `<key>_len`.
    fn blob(&self, key: &str) -> Vec<u8>;
    fn eq_u64(&mut self, key: &str, actual: u64);
    fn eq_bool(&mut self, key: &str, actual: bool);
    fn eq_str(&mut self, key: &str, actual: &str);
    fn eq_bytes(&mut self, key: &str, actual: &[u8]);
    fn eq_blob(&mut self, key: &str, actual: &[u8]);
}

// --- cross-fixture values, loaded once ------------------------------------

fn repo_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

/// One recorded request from `M-requests.bin`.
#[derive(Clone, Debug)]
pub struct Recorded {
    pub seq: u64,
    pub path: String,
    pub method: String,
    pub content_type: String,
    pub body: serde_json::Value,
    pub body_text: String,
}

/// Values a handler needs from outside its own vector: group D's recorded
/// hashes, the identity ADRS tail, the middleware's error codes, group N's
/// capture range and its found-tag figures (parsed directly, not through the
/// codec under test), and a sidecar loader.
pub struct Cross {
    fixtures: PathBuf,
    pub ds1_n1_message_hash: [u8; HASHLEN],
    pub ds1_n1_id_hash: [u8; HASHLEN],
    pub identity_adrs_tail12: [u8; 12],
    /// `handlers.go`'s `Err* = APIError{code, ..}` constants, by name.
    pub error_codes: BTreeMap<String, u64>,
    pub n_block_start: u64,
    pub n_block_end: u64,
    pub n_middleware_version: String,
    pub n_found_tag: Tag,
    pub n_found_address: Address,
    pub n_found_balance: u64,
    m_requests: OnceLock<Vec<Recorded>>,
}

fn json_file(path: &PathBuf) -> serde_json::Value {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("cannot parse {}: {e}", path.display()))
}

fn hex32(s: &str, what: &str) -> [u8; HASHLEN] {
    hex::decode_exact::<HASHLEN>(s, "cross").unwrap_or_else(|e| panic!("{what}: {e}"))
}

impl Cross {
    pub fn load() -> Cross {
        let root = repo_root();
        let fixtures = root.join("fixtures");

        let d = json_file(&fixtures.join("group_d_tx.json"));
        let ds1 = d["vectors"]
            .as_array()
            .and_then(|vs| vs.iter().find(|v| v["id"].as_str() == Some("Ds1-N1")))
            .unwrap_or_else(|| panic!("group_d_tx.json has no Ds1-N1"));
        let ds1_n1_message_hash = hex32(ds1["message_hash"].as_str().unwrap_or(""), "Ds1-N1.message_hash");
        let ds1_n1_id_hash = hex32(ds1["id_hash"].as_str().unwrap_or(""), "Ds1-N1.id_hash");
        let tail = hex::decode_exact::<12>(d["identity"]["adrs_tail12"].as_str().unwrap_or(""), "cross")
            .unwrap_or_else(|e| panic!("identity.adrs_tail12: {e}"));

        // The middleware's error table (`ErrX = APIError{N, ...}` in
        // `handlers.go` of mochimo-mesh at commit
        // ddc1ee55adb7920c8238212b8c9bf493d1fdba60, the version captured).
        // Code 9 is returned only by handlers this wallet never calls.
        let error_codes: BTreeMap<String, u64> = [
            ("ErrInvalidRequest", 1u64),
            ("ErrInternalError", 2),
            ("ErrTXNotFound", 3),
            ("ErrAccountNotFound", 4),
            ("ErrWrongNetwork", 5),
            ("ErrBlockNotFound", 6),
            ("ErrWrongCurveType", 7),
            ("ErrInvalidAccountFormat", 8),
            ("ErrServiceUnavailable", 9),
        ]
        .into_iter()
        .map(|(name, code)| (name.to_owned(), code))
        .collect();

        let n = json_file(&fixtures.join("group_n_mesh_live.json"));
        let pin = &n["pin"];
        let found = n["vectors"]
            .as_array()
            .and_then(|vs| vs.iter().find(|v| v["id"].as_str() == Some("N-call-tag-resolve-found")))
            .unwrap_or_else(|| panic!("group_n_mesh_live.json has no N-call-tag-resolve-found"));
        let n_found_tag = hex::decode_prefixed::<ADDR_TAG_LEN>(found["tag"].as_str().unwrap_or(""), "cross")
            .unwrap_or_else(|e| panic!("N found tag: {e}"));
        // Parsed directly, not through the codec under test.
        let reply: serde_json::Value =
            serde_json::from_str(found["response_body"].as_str().unwrap_or("")).unwrap_or_else(|e| panic!("N found reply: {e}"));
        let n_found_address = hex::decode_prefixed::<ADDR_LEN>(reply["result"]["address"].as_str().unwrap_or(""), "cross")
            .unwrap_or_else(|e| panic!("N found address: {e}"));
        let n_found_balance = reply["result"]["amount"].as_u64().unwrap_or_else(|| panic!("N found amount is not a u64"));

        Cross {
            fixtures,
            ds1_n1_message_hash,
            ds1_n1_id_hash,
            identity_adrs_tail12: tail,
            error_codes,
            n_block_start: pin["captured_block_index_start"].as_u64().unwrap_or_else(|| panic!("pin start")),
            n_block_end: pin["captured_block_index_end"].as_u64().unwrap_or_else(|| panic!("pin end")),
            n_middleware_version: pin["middleware_version"].as_str().unwrap_or("").to_owned(),
            n_found_tag,
            n_found_address,
            n_found_balance,
            m_requests: OnceLock::new(),
        }
    }

    pub fn sidecar(&self, name: &str) -> Vec<u8> {
        let p = self.fixtures.join(name);
        std::fs::read(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
    }

    /// The code the named `handlers.go` constant carries.
    pub fn code(&self, name: &str) -> u64 {
        *self
            .error_codes
            .get(name)
            .unwrap_or_else(|| panic!("handlers.go declares no {name}; the middleware's table moved"))
    }

    /// Every request the shipped client made, from `M-requests.bin`.
    pub fn m_requests(&self) -> &[Recorded] {
        self.m_requests.get_or_init(|| {
            let text = String::from_utf8(self.sidecar("M-requests.bin")).unwrap_or_else(|e| panic!("M-requests.bin: {e}"));
            text.lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| {
                    let v: serde_json::Value = serde_json::from_str(l).unwrap_or_else(|e| panic!("M-requests.bin line: {e}"));
                    let url = v["url"].as_str().unwrap_or("").to_owned();
                    let path = url.split_once("://").and_then(|(_, rest)| rest.split_once('/')).map_or(String::new(), |(_, p)| format!("/{p}"));
                    let body_text = v["body"].as_str().unwrap_or("").to_owned();
                    Recorded {
                        seq: v["seq"].as_u64().unwrap_or(0),
                        path,
                        method: v["method"].as_str().unwrap_or("").to_owned(),
                        content_type: v["content_type"].as_str().unwrap_or("").to_owned(),
                        body: serde_json::from_str(&body_text).unwrap_or(serde_json::Value::Null),
                        body_text,
                    }
                })
                .collect()
        })
    }

    pub fn m_request(&self, path: &str) -> &Recorded {
        self.m_requests()
            .iter()
            .find(|r| r.path == path)
            .unwrap_or_else(|| panic!("M-requests.bin has no request to {path}"))
    }
}

static CROSS: OnceLock<Cross> = OnceLock::new();

pub fn cross() -> &'static Cross {
    CROSS.get_or_init(Cross::load)
}

static BLOCK_TX: OnceLock<serde_json::Value> = OnceLock::new();

/// `/block`'s rendering of the transaction the block vectors are about, from
/// the `N-submit-block` vector.
///
/// The `/block/transaction` and `/search/transactions` handlers compare their
/// own readings against this one; both are independent sources.
fn block_tx(txid: &str) -> serde_json::Value {
    BLOCK_TX
        .get_or_init(|| {
            let n = json_file(&cross().fixtures.join("group_n_mesh_live.json"));
            let v = n["vectors"]
                .as_array()
                .and_then(|vs| vs.iter().find(|v| v["id"].as_str() == Some("N-submit-block")))
                .unwrap_or_else(|| panic!("group N has no N-submit-block vector"));
            let body: serde_json::Value =
                serde_json::from_str(v["response_body"].as_str().unwrap_or(""))
                    .unwrap_or_else(|e| panic!("N-submit-block response: {e}"));
            let want = v["submitted_transaction_id"].as_str().unwrap_or("");
            body["block"]["transactions"]
                .as_array()
                .and_then(|ts| {
                    ts.iter()
                        .find(|t| t["transaction_identifier"]["hash"].as_str() == Some(want))
                })
                .cloned()
                .unwrap_or_else(|| panic!("N-submit-block does not carry {want}"))
        })
        .clone()
        .tap_id(txid)
}

/// Asserts that the transaction [`block_tx`] loaded is the one the caller
/// asked for.
trait TapId {
    fn tap_id(self, txid: &str) -> Self;
}

impl TapId for serde_json::Value {
    fn tap_id(self, txid: &str) -> Self {
        assert_eq!(
            self["transaction_identifier"]["hash"].as_str(),
            Some(txid),
            "block_tx was asked for a transaction other than the one N-submit-block holds"
        );
        self
    }
}

// --- dispatch --------------------------------------------------------------

pub fn replay(v: &mut dyn Vector, source: &str) {
    match source {
        N_LIST => n_list(v),
        N_STATUS => n_status(v),
        N_OPTIONS => n_options(v),
        N_CALL => n_call(v),
        N_BALANCE => n_balance(v),
        N_METADATA => n_metadata(v),
        N_PARSE => n_parse(v),
        N_HASH => n_hash(v),
        N_CAP => n_cap(v),
        N_BLOCK => n_block(v),
        N_BLOCK_TX => n_block_tx(v),
        N_SEARCH => n_search(v),
        M_REQUESTS => m_requests(v),
        M_CHANGE => m_change(v),
        M_SIGNED => m_signed(v),
        M_LOCAL => m_local(v),
        M_OPTIONS => m_options(v),
        M_COMBINE => m_combine(v),
        other => panic!("{}: no mesh replay is registered for source {other:?}", v.id()),
    }
}

// --- group N ---------------------------------------------------------------

/// The request/response pair every N vector carries.
struct Exchange {
    request: Vec<u8>,
    request_json: serde_json::Value,
    response: Vec<u8>,
}

fn exchange(v: &mut dyn Vector, endpoint: &str) -> Exchange {
    v.eq_str("endpoint", endpoint);
    // The middleware answers everything, errors included, with HTTP 200.
    v.eq_u64("response_status", 200);
    let request = v.str_("request_body").into_bytes();
    let request_json = serde_json::from_slice(&request).unwrap_or_else(|e| panic!("{}: request_body is not JSON: {e}", v.id()));
    let response = v.str_("response_body").into_bytes();
    Exchange {
        request,
        request_json,
        response,
    }
}

fn expect_mesh_error(v: &dyn Vector, response: &[u8], constant: &str) {
    let want = cross().code(constant);
    match codec::parse_network_status(response) {
        Err(Error::Mesh { code, .. }) if code == want => {}
        other => panic!(
            "{}: expected the middleware's {constant} (code {want}) through a 200, got {other:?}",
            v.id()
        ),
    }
}

fn prefixed(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn n_list(v: &mut dyn Vector) {
    let x = exchange(v, "/network/list");
    assert_eq!(x.request, codec::request_network_list(), "{}: request body is not what the codec builds", v.id());
    let serves = codec::parse_network_list(&x.response).unwrap_or_else(|e| panic!("{}: {e}", v.id()));
    assert!(serves, "{}: the middleware does not list mochimo/mainnet", v.id());
    let named = codec::parse_network_identifiers(&x.response).unwrap_or_else(|e| panic!("{}: {e}", v.id()));
    assert_eq!(
        named,
        [codec::NetworkIdentifier { blockchain: "mochimo".into(), network: "mainnet".into() }],
        "{}: the networks named are not the one the capture lists",
        v.id()
    );
}

fn n_status(v: &mut dyn Vector) {
    let x = exchange(v, "/network/status");
    assert_eq!(x.request, codec::request_network_status(), "{}: request body is not what the codec builds", v.id());
    let tip = codec::parse_network_status(&x.response).unwrap_or_else(|e| panic!("{}: {e}", v.id()));
    let full = codec::parse_network_status_full(&x.response).unwrap_or_else(|e| panic!("{}: {e}", v.id()));
    assert_eq!(full.tip, tip, "{}: the two readings of the tip differ", v.id());
    assert_eq!(full.genesis.index, 0, "{}: the genesis block is not block 0", v.id());
    let sync = full.sync.as_ref().unwrap_or_else(|| panic!("{}: the capture's sync_status was not read", v.id()));
    assert!(sync.synced && sync.stage == "synchronized", "{}: the capture was taken synchronized: {sync:?}", v.id());
    let c = cross();
    assert!(
        (c.n_block_start..=c.n_block_end).contains(&tip.index),
        "{}: block {} is outside the capture's {}..={}",
        v.id(),
        tip.index,
        c.n_block_start,
        c.n_block_end
    );
}

fn n_options(v: &mut dyn Vector) {
    let x = exchange(v, "/network/options");
    assert_eq!(x.request, codec::request_network_options(), "{}: request body is not what the codec builds", v.id());
    let opts = codec::parse_network_options(&x.response).unwrap_or_else(|e| panic!("{}: {e}", v.id()));
    let c = cross();
    assert_eq!(opts.middleware_version, c.n_middleware_version, "{}: middleware version vs pin", v.id());
    // The advertised codes are the declared ones minus
    // `ErrServiceUnavailable`, which no handler returns.
    let mut advertised = opts.error_codes.clone();
    advertised.sort_unstable();
    let mut declared: Vec<u64> = c
        .error_codes
        .iter()
        .filter(|(name, _)| name.as_str() != "ErrServiceUnavailable")
        .map(|(_, code)| *code)
        .collect();
    declared.sort_unstable();
    assert_eq!(
        advertised,
        declared,
        "{}: the codes /network/options advertises are not handlers.go's table minus ErrServiceUnavailable",
        v.id()
    );
    assert!(
        !advertised.contains(&c.code("ErrServiceUnavailable")),
        "{}: ErrServiceUnavailable is advertised; the measured fact was that it is declared and never returned",
        v.id()
    );
}

fn tag_field(v: &dyn Vector, key: &str) -> Tag {
    hex::decode_prefixed::<ADDR_TAG_LEN>(&v.str_(key), "tag").unwrap_or_else(|e| panic!("{}: {key}: {e}", v.id()))
}

fn n_call(v: &mut dyn Vector) {
    let id = v.id();
    let x = exchange(v, "/call");
    let c = cross();
    match id.as_str() {
        "N-call-tag-resolve-found" => {
            let tag = tag_field(v, "tag");
            assert_eq!(x.request, codec::request_tag_resolve(&tag), "{id}: request body is not what the codec builds");
            let entry = codec::parse_tag_resolve(&x.response, &tag).unwrap_or_else(|e| panic!("{id}: {e}"));
            assert!(entry.address.starts_with(&tag), "{id}: address does not begin with the tag");
            assert_eq!(entry.address, c.n_found_address, "{id}: address vs the raw-parsed reply");
            assert_eq!(entry.balance, c.n_found_balance, "{id}: amount vs the raw-parsed reply");
            assert_eq!(tag, c.n_found_tag);
        }
        "N-call-tag-resolve-not-found" => {
            let tag = tag_field(v, "tag");
            assert_eq!(x.request, codec::request_tag_resolve(&tag), "{id}: request body is not what the codec builds");
            match codec::parse_tag_resolve(&x.response, &tag) {
                Err(Error::Mesh { code, retriable: true }) if code == c.code("ErrAccountNotFound") => {}
                other => panic!("{id}: expected ErrAccountNotFound, retriable, got {other:?}"),
            }
        }
        "N-call-tag-bad-format" => {
            assert_eq!(x.request_json["parameters"]["tag"].as_str(), Some("0xabc"), "{id}: request shape");
            expect_mesh_error(v, &x.response, "ErrInvalidAccountFormat");
        }
        "N-call-tag-not-a-string" => {
            assert!(x.request_json["parameters"]["tag"].is_number(), "{id}: request shape");
            expect_mesh_error(v, &x.response, "ErrInvalidRequest");
        }
        "N-call-wrong-network" => {
            assert_eq!(x.request_json["network_identifier"]["network"].as_str(), Some("testnet"), "{id}: request shape");
            expect_mesh_error(v, &x.response, "ErrWrongNetwork");
        }
        "N-call-unknown-method" => {
            assert_eq!(x.request_json["method"].as_str(), Some("nope"), "{id}: request shape");
            expect_mesh_error(v, &x.response, "ErrInvalidRequest");
        }
        other => panic!("{other}: a callHandler vector this walk does not know"),
    }
}

/// The transaction the frozen block vectors are about, as one endpoint renders it.
struct OnChain {
    /// The tag the SOURCE_TRANSFER operation names.
    source_tag: [u8; ADDR_TAG_LEN],
    /// `from_address_hash`: the HASH half of the 40-byte source address.
    from_hash: [u8; ADDR_TAG_LEN],
    /// `change_address_hash`: the hash half of the change address.
    change_hash: [u8; ADDR_TAG_LEN],
    /// The middleware's `source_amount` -- what it says the source held.
    source_amount: u64,
    change_amount: u64,
    /// The net debit the SOURCE_TRANSFER operation carries.
    net_debit: u64,
    dest_tag: [u8; ADDR_TAG_LEN],
    dest_amount: u64,
    fee: u64,
    block_to_live: String,
}

/// Pull `OnChain` out of a `/block`-shaped transaction object. Values are
/// read as given, never recomputed.
fn on_chain(id: &str, tx: &serde_json::Value) -> OnChain {
    let hex20 = |s: &str, what: &str| {
        hex::decode_prefixed::<ADDR_TAG_LEN>(s, "on-chain")
            .unwrap_or_else(|e| panic!("{id}: {what}: {e}"))
    };
    let num = |s: &str, what: &str| -> u64 {
        s.trim_start_matches('-')
            .parse()
            .unwrap_or_else(|e| panic!("{id}: {what} `{s}`: {e}"))
    };
    let ops = tx["operations"].as_array().unwrap_or_else(|| panic!("{id}: no operations"));
    let by = |t: &str| {
        ops.iter()
            .find(|o| o["type"].as_str() == Some(t))
            .unwrap_or_else(|| panic!("{id}: no {t} operation"))
    };
    let src = by("SOURCE_TRANSFER");
    let dst = by("DESTINATION_TRANSFER");
    let fee = by("FEE");
    let m = &src["metadata"];
    OnChain {
        source_tag: hex20(src["account"]["address"].as_str().unwrap_or(""), "source account"),
        from_hash: hex20(m["from_address_hash"].as_str().unwrap_or(""), "from_address_hash"),
        change_hash: hex20(m["change_address_hash"].as_str().unwrap_or(""), "change_address_hash"),
        source_amount: num(m["source_amount"].as_str().unwrap_or(""), "source_amount"),
        change_amount: num(m["change_amount"].as_str().unwrap_or(""), "change_amount"),
        net_debit: num(src["amount"]["value"].as_str().unwrap_or(""), "source amount"),
        dest_tag: hex20(dst["account"]["address"].as_str().unwrap_or(""), "destination account"),
        dest_amount: num(dst["amount"]["value"].as_str().unwrap_or(""), "destination amount"),
        fee: num(fee["amount"]["value"].as_str().unwrap_or(""), "fee amount"),
        block_to_live: tx["metadata"]["block_to_live"].as_str().unwrap_or("").to_owned(),
    }
}

/// `/block`: checks on a transaction this crate built that the chain
/// accepted.
///
/// `source_amount` is rendered by `block_handler.go` as change + send + fee,
/// so summing those would prove nothing. Instead `SpendPlan::new` is given the
/// recorded balance, destination and fee and must produce the recorded
/// change.
///
/// The address checks compare different halves of on-chain addresses:
///
/// * `from_address_hash` equals the account tag: an implicit address
///   (`addr_from_implicit`), as an account that has never spent presents;
/// * `change_address_hash` differs from `from_address_hash` while the change
///   returns to the same tag, the pair of rules `tx_val` enforces
///   (`addr_hash_equal` false, `addr_tag_equal` true).
fn n_block(v: &mut dyn Vector) {
    let id = v.id();
    let x = exchange(v, "/block");
    let index = v.u64_("submitted_block_index");
    let txid = v.str_("submitted_transaction_id");
    let body: serde_json::Value =
        serde_json::from_slice(&x.response).unwrap_or_else(|e| panic!("{id}: {e}"));
    assert_eq!(
        x.request_json["block_identifier"]["index"].as_u64(),
        Some(index),
        "{id}: the request did not ask for the block this vector is about"
    );
    assert_eq!(
        body["block"]["block_identifier"]["index"].as_u64(),
        Some(index),
        "{id}: the endpoint answered about a different block"
    );
    let tx = body["block"]["transactions"]
        .as_array()
        .unwrap_or_else(|| panic!("{id}: no transactions"))
        .iter()
        .find(|t| t["transaction_identifier"]["hash"].as_str() == Some(txid.as_str()))
        .unwrap_or_else(|| {
            panic!("{id}: block {index} does not carry {txid}. The corpus's only record that a \
                    transaction this crate built was accepted is this block carrying it.")
        });
    let c = on_chain(&id, tx);

    // The source address was IMPLICIT: both halves are the tag.
    assert_eq!(
        c.from_hash, c.source_tag,
        "{id}: the source address's hash half is not its tag, so the account had spent before. \
         An implicit address is what addr_from_implicit builds and what a never-spent account \
         presents."
    );
    // The change address carries the same tag and a DIFFERENT hash half.
    assert_ne!(
        c.change_hash, c.from_hash,
        "{id}: the change address's hash half equals the source's -- addr_hash_equal, which \
         tx_val refuses with EMCM_TXCHG"
    );
    assert_eq!(c.block_to_live, "0", "{id}: block_to_live");

    // The fee was exactly MFEE for one destination, the minimum both
    // `tx_val` and `SpendPlan` accept.
    assert_eq!(c.fee, MFEE, "{id}: the fee the chain recorded is not MFEE");

    // --- the change, computed by this crate ------------------------------
    let source = addr::from_implicit(&c.source_tag);
    assert_eq!(
        &source[..ADDR_TAG_LEN],
        &c.source_tag[..],
        "{id}: from_implicit did not put the tag in the first half"
    );
    assert_eq!(
        &source[ADDR_TAG_LEN..],
        &c.from_hash[..],
        "{id}: the address from_implicit builds for this tag is not the one the chain holds"
    );
    let mut change = [0u8; ADDR_LEN];
    change[..ADDR_TAG_LEN].copy_from_slice(&c.source_tag);
    change[ADDR_TAG_LEN..].copy_from_slice(&c.change_hash);
    let addresses = keystore::SpendAddresses::unverified(
        c.source_tag,
        account::WotsIndex::ZERO,
        source,
        change,
    );
    let entry = mesh::LedgerEntry {
        address: source,
        balance: c.source_amount,
    };
    let plan = spend::SpendPlan::new(
        &addresses,
        &entry,
        vec![tx_wire::Destination {
            tag: c.dest_tag,
            reference: [0u8; ADDR_REF_LEN],
            amount: c.dest_amount,
        }],
        c.fee,
        0,
    )
    .unwrap_or_else(|e| {
        panic!("{id}: SpendPlan refused the spend a real node accepted: {e}")
    });
    assert_eq!(
        plan.change_total(),
        c.change_amount,
        "{id}: this crate computes a different change than the chain settled on for the same \
         balance, destination and fee"
    );
    assert_eq!(plan.send_total(), c.dest_amount, "{id}: send total");
    assert_eq!(plan.fee_total(), c.fee, "{id}: fee total");
}

/// `/block/transaction`: the same transaction must match `/block`'s
/// rendering.
fn n_block_tx(v: &mut dyn Vector) {
    let id = v.id();
    let x = exchange(v, "/block/transaction");
    let index = v.u64_("submitted_block_index");
    let txid = v.str_("submitted_transaction_id");
    let body: serde_json::Value =
        serde_json::from_slice(&x.response).unwrap_or_else(|e| panic!("{id}: {e}"));
    assert_eq!(
        x.request_json["block_identifier"]["index"].as_u64(),
        Some(index),
        "{id}: request shape"
    );
    let tx = &body["transaction"];
    assert_eq!(
        tx["transaction_identifier"]["hash"].as_str(),
        Some(txid.as_str()),
        "{id}: answered about a different transaction"
    );
    let here = on_chain(&id, tx);
    // Compared with the block's rendering of the same transaction.
    let there = on_chain(&id, &block_tx(&txid));
    assert_eq!(here.source_amount, there.source_amount, "{id}: source_amount disagrees with /block");
    assert_eq!(here.change_amount, there.change_amount, "{id}: change_amount disagrees with /block");
    assert_eq!(here.net_debit, there.net_debit, "{id}: net debit disagrees with /block");
    assert_eq!(here.from_hash, there.from_hash, "{id}: from_address_hash disagrees with /block");
    assert_eq!(here.change_hash, there.change_hash, "{id}: change_address_hash disagrees with /block");
    assert_eq!(here.block_to_live, "0", "{id}: block_to_live is not the string \"0\"");
}

/// `/search/transactions`, compared with `/block`.
///
/// `/block` re-parses the wire and reports the source's net debit, with the
/// gross and the change as decimal strings in metadata. The indexer behind
/// `/search/transactions` stores rows when a block is first seen and reports
/// the gross debit with the change as its own operation, totals as JSON
/// numbers. Both are correct; they are independent sources.
///
/// The endpoint exists only where the deployment enabled `EnableIndexer`
/// (off by default), so a capture without it is accepted.
fn n_search(v: &mut dyn Vector) {
    let id = v.id();
    let x = exchange(v, "/search/transactions");
    let txid = v.str_("submitted_transaction_id");
    let served = v.bool_("indexer_served");
    let body: serde_json::Value =
        serde_json::from_slice(&x.response).unwrap_or_else(|e| panic!("{id}: {e}"));
    assert_eq!(
        x.request_json["transaction_identifier"]["hash"].as_str(),
        Some(txid.as_str()),
        "{id}: request shape"
    );
    let Some(found) = body["transactions"].as_array().and_then(|a| a.first()) else {
        assert!(
            !served,
            "{id}: indexer_served is true and the capture holds no transaction"
        );
        return;
    };
    assert!(served, "{id}: indexer_served is false and the capture holds a transaction");
    assert_eq!(
        found["transaction_identifier"]["hash"].as_str(),
        Some(txid.as_str()),
        "{id}: a different transaction came back"
    );

    // The four totals, as JSON numbers (strings in /block).
    let m = &found["metadata"];
    let n = |k: &str| -> u64 {
        m[k].as_u64()
            .unwrap_or_else(|| panic!("{id}: metadata.{k} is not a JSON number: {}", m[k]))
    };
    let (send, change, fee, btl) = (n("send_total"), n("change_total"), n("fee_total"), n("block_to_live"));

    // Indexed rows against /block's live parse.
    let b = on_chain(&id, &block_tx(&txid));
    assert_eq!(send, b.dest_amount, "{id}: send_total disagrees with /block's destination");
    assert_eq!(change, b.change_amount, "{id}: change_total disagrees with /block's change_amount");
    assert_eq!(fee, b.fee, "{id}: fee_total disagrees with /block's FEE operation");
    assert_eq!(btl, 0, "{id}: block_to_live");
    assert_eq!(
        b.block_to_live, "0",
        "{id}: /block stopped rendering block_to_live as a string. The two endpoints put these \
         values in an untyped map[string]interface{{}}, so the Go expression's type leaks into \
         the JSON and can change with no version bump; a Rust deserializer cannot use one type \
         per key across the two."
    );

    // The gross debit, which /block does not state as an operation.
    let gross: u64 = found["operations"]
        .as_array()
        .unwrap_or_else(|| panic!("{id}: no operations"))
        .iter()
        .find(|o| o["type"].as_str() == Some("SOURCE_TRANSFER"))
        .and_then(|o| o["amount"]["value"].as_str())
        .unwrap_or_else(|| panic!("{id}: no SOURCE_TRANSFER"))
        .trim_start_matches('-')
        .parse()
        .unwrap_or_else(|e| panic!("{id}: gross: {e}"));
    assert_eq!(
        gross, b.source_amount,
        "{id}: the indexer's gross debit is not /block's source_amount -- two computations from \
         two data sources disagreeing about one sealed transaction"
    );
    assert_eq!(
        b.net_debit + change,
        gross,
        "{id}: /block's net debit plus the change is not the gross. These come from different \
         endpoints, so this is a comparison and not a restatement."
    );

    // The change is credited back to the source tag (`addr_tag_equal`).
    let credited: Vec<[u8; ADDR_TAG_LEN]> = found["operations"]
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .filter(|o| o["type"].as_str() == Some("DESTINATION_TRANSFER"))
        .filter(|o| o["amount"]["value"].as_str() == Some(&change.to_string()))
        .filter_map(|o| o["account"]["address"].as_str())
        .filter_map(|a| hex::decode_prefixed::<ADDR_TAG_LEN>(a, "credit").ok())
        .collect();
    assert!(
        credited.contains(&b.source_tag),
        "{id}: the change was not credited back to the source tag. tx_val requires the change \
         address to carry the SAME tag as the source (addr_tag_equal), and this is that rule \
         seen on a ledger."
    );
}

fn n_balance(v: &mut dyn Vector) {
    let id = v.id();
    let x = exchange(v, "/account/balance");
    let c = cross();
    match id.as_str() {
        "N-account-balance-found-by-tag" => {
            let tag = tag_field(v, "tag");
            assert_eq!(x.request, codec::request_account_balance(&tag), "{id}: request body is not what the codec builds");
            let at = codec::parse_account_balance(&x.response).unwrap_or_else(|e| panic!("{id}: {e}"));
            assert_eq!(at.balance, c.n_found_balance, "{id}: the string balance is not the number /call returned");
            assert!((c.n_block_start..=c.n_block_end).contains(&at.tip.index), "{id}: block outside the capture");
        }
        "N-account-balance-found-by-address" => {
            let address = hex::decode_prefixed::<ADDR_LEN>(&v.str_("address"), "address").unwrap_or_else(|e| panic!("{id}: {e}"));
            assert_eq!(address, c.n_found_address, "{id}: the address queried is not the one /call resolved");
            assert_eq!(x.request_json["account_identifier"]["address"].as_str(), Some(prefixed(&address).as_str()), "{id}: request shape");
            let at = codec::parse_account_balance(&x.response).unwrap_or_else(|e| panic!("{id}: {e}"));
            assert_eq!(at.balance, c.n_found_balance, "{id}: the by-address balance is not the by-tag one");
        }
        "N-account-balance-not-found" => {
            let tag = tag_field(v, "tag");
            assert_eq!(x.request, codec::request_account_balance(&tag), "{id}: request body is not what the codec builds");
            match codec::parse_account_balance(&x.response) {
                Err(Error::Mesh { code, .. }) if code == c.code("ErrAccountNotFound") => {}
                other => panic!("{id}: expected ErrAccountNotFound, got {other:?}"),
            }
        }
        "N-account-balance-malformed" => {
            assert_eq!(x.request_json["account_identifier"]["address"].as_str(), Some("0xabc"), "{id}: request shape");
            expect_mesh_error(v, &x.response, "ErrInvalidAccountFormat");
        }
        // The middleware ignores a requested block: `AccountBalanceRequest`
        // (account_handler.go) has no `BlockIdentifier` field. This checks
        // the echoed index is not the requested one, and nothing about the
        // balance, which follows the tip. It fails if the middleware adds
        // historical balances.
        "N-submit-balance-ignores-block" => {
            let asked = v.u64_("requested_block_index");
            let tag = tag_field(v, "tag");
            assert_eq!(
                x.request_json["block_identifier"]["index"].as_u64(),
                Some(asked),
                "{id}: the request did not carry the block_identifier this vector is about"
            );
            assert_eq!(
                x.request_json["account_identifier"]["address"].as_str(),
                Some(prefixed(&tag).as_str()),
                "{id}: request shape"
            );
            let at = codec::parse_account_balance(&x.response).unwrap_or_else(|e| panic!("{id}: {e}"));
            assert_ne!(
                at.tip.index, asked,
                "{id}: the middleware answered at the block_identifier it was given. It has no \
                 field for one, so this asserts it grew a historical-balance path -- which would \
                 put the pre-spend ledger balance, and with it tx_val's EMCM_TXTOTAL arm, within \
                 reach of a capture for the first time. Re-derive before changing this."
            );
        }
        other => panic!("{other}: an accountBalanceHandler vector this walk does not know"),
    }
}

fn n_metadata(v: &mut dyn Vector) {
    let id = v.id();
    let tag = tag_field(v, "tag");
    let x = exchange(v, "/construction/metadata");
    assert_eq!(x.request_json["options"]["source_addr"].as_str(), Some(prefixed(&tag).as_str()), "{id}: request shape");
    let reply: serde_json::Value = serde_json::from_slice(&x.response).unwrap_or_else(|e| panic!("{id}: reply: {e}"));
    // The suggested fee is the protocol minimum, MFEE.
    assert_eq!(
        reply["suggested_fee"][0]["value"].as_str(),
        Some(MFEE.to_string().as_str()),
        "{id}: suggested_fee is not MFEE"
    );
    assert_eq!(reply["suggested_fee"][0]["currency"]["symbol"].as_str(), Some(codec::CURRENCY_SYMBOL), "{id}");
    // The balance it reports is the one /call returned. This crate builds
    // transactions locally and does not use this endpoint.
    assert_eq!(
        reply["metadata"]["source_balance"].as_str(),
        Some(cross().n_found_balance.to_string().as_str()),
        "{id}: source_balance is not the /call amount"
    );
}

fn n_parse(v: &mut dyn Vector) {
    let id = v.id();
    let image = cross().sidecar(&v.str_("transaction_file"));
    let x = exchange(v, "/construction/parse");
    assert_eq!(x.request_json["signed"].as_bool(), Some(true), "{id}: request shape");
    assert_eq!(x.request_json["transaction"].as_str(), Some(hex::encode(&image).as_str()), "{id}: request carries the image");
    let tx = Transaction::from_wire(&image).unwrap_or_else(|e| panic!("{id}: {e:?}"));
    let reply: serde_json::Value = serde_json::from_slice(&x.response).unwrap_or_else(|e| panic!("{id}: reply: {e}"));
    let ops = reply["operations"].as_array().unwrap_or_else(|| panic!("{id}: no operations"));
    let mut sources = 0usize;
    let mut destinations = 0usize;
    let mut fees = 0usize;
    for op in ops {
        match op["type"].as_str().unwrap_or("") {
            "SOURCE_TRANSFER" => {
                sources += 1;
                assert_eq!(op["account"]["address"].as_str(), Some(prefixed(addr::tag_of(&tx.src_addr)).as_str()), "{id}: source tag");
                assert_eq!(
                    op["metadata"]["from_address_hash"].as_str(),
                    Some(prefixed(addr::hash_of(&tx.src_addr)).as_str()),
                    "{id}: from_address_hash"
                );
                assert_eq!(
                    op["metadata"]["change_address_hash"].as_str(),
                    Some(prefixed(addr::hash_of(&tx.chg_addr)).as_str()),
                    "{id}: change_address_hash"
                );
                assert_eq!(op["metadata"]["change_amount"].as_str(), Some(tx.change_total.to_string().as_str()), "{id}: change_amount");
            }
            "DESTINATION_TRANSFER" => {
                let d = &tx.dsts()[destinations];
                destinations += 1;
                assert_eq!(op["account"]["address"].as_str(), Some(prefixed(&d.tag).as_str()), "{id}: destination tag");
                assert_eq!(op["amount"]["value"].as_str(), Some(d.amount.to_string().as_str()), "{id}: destination amount");
            }
            "FEE" => {
                fees += 1;
                assert_eq!(op["amount"]["value"].as_str(), Some(tx.fee_total.to_string().as_str()), "{id}: fee");
            }
            other => panic!("{id}: an operation type this walk does not know: {other:?}"),
        }
    }
    assert_eq!((sources, destinations, fees), (1, tx.dsts().len(), 1), "{id}: operation multiset");
}

fn n_hash(v: &mut dyn Vector) {
    let id = v.id();
    let image = cross().sidecar(&v.str_("signed_transaction_file"));
    let x = exchange(v, "/construction/hash");
    assert_eq!(x.request_json["signed_transaction"].as_str(), Some(hex::encode(&image).as_str()), "{id}: request carries the image");
    let tx = Transaction::from_wire(&image).unwrap_or_else(|e| panic!("{id}: {e:?}"));
    let reply: serde_json::Value = serde_json::from_slice(&x.response).unwrap_or_else(|e| panic!("{id}: reply: {e}"));
    let got = reply["transaction_identifier"]["hash"].as_str().unwrap_or("");
    assert_eq!(got, hex::encode(&tx.id_digest()), "{id}: the middleware's hash is not this crate's id digest");
    if id == "N-construction-hash-Ds1-N1" {
        assert_eq!(got, hex::encode(&cross().ds1_n1_id_hash), "{id}: the middleware's hash is not the C-recorded id_hash");
    }
}

fn n_cap(v: &mut dyn Vector) {
    let id = v.id();
    v.eq_bool("body_len_over_cap", true);
    let x = exchange(v, "/call");
    assert!(
        x.request.len() > MAX_REQUEST_BYTES,
        "{id}: the recorded body ({} bytes) is not over the cap ({MAX_REQUEST_BYTES})",
        x.request.len()
    );
    expect_mesh_error(v, &x.response, "ErrInvalidRequest");
}

// --- group M ---------------------------------------------------------------

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

fn in_any_body(needle: &str) -> bool {
    cross().m_requests().iter().any(|r| r.body_text.contains(needle))
}

fn m_requests(v: &mut dyn Vector) {
    let id = v.id();
    let lines = v.blob("requests");
    assert_eq!(lines, cross().sidecar("M-requests.bin"), "{id}: the vector's sidecar is not the one the cross loader reads");
    let reqs = cross().m_requests();
    v.eq_u64("request_count", reqs.len() as u64);
    v.eq_str("endpoints_called", &reqs.iter().map(|r| r.path.as_str()).collect::<Vec<_>>().join(","));
    v.eq_bool("balance_endpoint_called", reqs.iter().any(|r| r.path == "/account/balance"));
    for (i, r) in reqs.iter().enumerate() {
        assert_eq!(r.seq, i as u64 + 1, "{id}: sequence");
        assert_eq!(r.method, "POST", "{id}: method");
        assert_eq!(r.content_type, "application/json", "{id}: content type");
        assert!(r.body.is_object(), "{id}: body {i} is not a JSON object");
    }
}

fn m_change(v: &mut dyn Vector) {
    let id = v.id();
    let tag = v.hex("change_wallet_tag");
    let hash = v.hex("change_wallet_addr_hash");
    let address = v.hex("change_wallet_address");
    let address: Address = address.as_slice().try_into().unwrap_or_else(|_| panic!("{id}: change_wallet_address width"));
    assert_eq!(addr::tag_of(&address), tag.as_slice(), "{id}: the change address's tag half");
    assert_eq!(addr::hash_of(&address), hash.as_slice(), "{id}: the change address's hash half");

    let pk_sent = v.str_("preprocess_change_pk_sent");
    let addr_sent = v.str_("preprocess_change_addr_sent");
    assert_eq!(pk_sent, prefixed(&hash), "{id}: change_pk is not the 20-byte hash");
    assert_eq!(addr_sent, prefixed(&hash), "{id}: change_addr is not the 20-byte hash");
    let preprocess = cross().m_request("/construction/preprocess");
    assert_eq!(preprocess.body["metadata"]["change_pk"].as_str(), Some(pk_sent.as_str()), "{id}: vs the request log");
    assert_eq!(preprocess.body["metadata"]["change_addr"].as_str(), Some(addr_sent.as_str()), "{id}: vs the request log");

    let source_account = preprocess.body["operations"][0]["account"]["address"].as_str().unwrap_or("");
    v.eq_bool("change_tag_equals_source_tag", source_account == prefixed(&tag));
    v.eq_bool("change_pk_carries_change_tag", pk_sent.contains(&hex::encode(&tag)));
    v.eq_bool("change_addr_carries_change_tag", addr_sent.contains(&hex::encode(&tag)));
    v.eq_bool("change_full_address_in_any_request_body", in_any_body(&hex::encode(&address)));
}

fn m_signed(v: &mut dyn Vector) {
    let id = v.id();
    let c = cross();
    let served = v.blob("served_unsigned");
    let origin = v.str_("served_unsigned_origin_file");
    assert_eq!(served, c.sidecar(&origin), "{id}: the served bytes are not the C-emitted {origin}");
    let decoy = v.str_("served_payload_hex_bytes");
    let digest = v.hex("signed_digest");
    let digest: [u8; HASHLEN] = digest.as_slice().try_into().unwrap_or_else(|_| panic!("{id}: signed_digest width"));
    assert_eq!(
        mochimo_crypto::backend::selected::sha256(&served),
        digest,
        "{id}: the digest signed is not sha256 of the served bytes"
    );
    assert_eq!(digest, c.ds1_n1_message_hash, "{id}: the digest signed is not the C-recorded Ds1-N1 message hash");
    assert_ne!(hex::encode(&digest), decoy, "{id}: the wallet signed the server's payload hex, not its own hash");

    let signature = v.blob("signature");
    let pk = v.blob("source_public_key");
    let pub_seed = v.hex("source_pub_seed");
    let adrs_image = v.hex("source_adrs");
    let address = v.hex("source_address");
    let sig: &[u8; SIG_LEN] = signature.as_slice().try_into().unwrap_or_else(|_| panic!("{id}: signature width"));
    let pk: &[u8; PK_LEN] = pk.as_slice().try_into().unwrap_or_else(|_| panic!("{id}: public key width"));
    let pub_seed: [u8; 32] = pub_seed.as_slice().try_into().unwrap_or_else(|_| panic!("{id}: pub_seed width"));
    let adrs_image: [u8; 32] = adrs_image.as_slice().try_into().unwrap_or_else(|_| panic!("{id}: adrs width"));
    let address: Address = address.as_slice().try_into().unwrap_or_else(|_| panic!("{id}: address width"));
    let start = Adrs::from_le_image(&adrs_image);
    let mut working = start;
    let recovered = wots::pk_from_sig(sig, &digest, &pub_seed, &mut working);
    assert_eq!(&recovered[..], &pk[..], "{id}: the recorded signature does not recover the source public key");
    assert_eq!(working, start, "{id}: the shipped wallet's adrs is not already the terminal state");
    assert_eq!(&adrs_image[20..], &c.identity_adrs_tail12[..], "{id}: the shipped adrs tail is not the mandated triple");
    assert_eq!(addr::hash_of(&addr::from_wots(&recovered)), addr::hash_of(&address), "{id}: the key does not own the source address");

    let amount: u64 = v.str_("requested_amount").parse().unwrap_or_else(|e| panic!("{id}: requested_amount: {e}"));
    let _fee: u64 = v.str_("requested_fee").parse().unwrap_or_else(|e| panic!("{id}: requested_fee: {e}"));
    let dest = hex::decode_prefixed::<ADDR_TAG_LEN>(&v.str_("requested_destination_tag"), "dest").unwrap_or_else(|e| panic!("{id}: {e}"));
    // The served prefix is a header and one destination, with a different
    // source, amount and destination from those requested.
    assert_eq!(served.len(), 116 + 44, "{id}: served prefix is not header plus one destination");
    assert_ne!(&served[4..44], &address[..], "{id}: the served source address is the wallet's own");
    let served_send = u64::from_le_bytes(served[84..92].try_into().unwrap_or([0; 8]));
    assert_ne!(served_send, amount, "{id}: the served send_total is the requested amount");
    assert_ne!(&served[116..136], &dest[..], "{id}: the served destination is the requested one");
}

fn m_local(v: &mut dyn Vector) {
    let id = v.id();
    let local = v.blob("local_tx_bytes");
    v.eq_bool("local_bytes_in_any_request_body", in_any_body(&hex::encode(&local)));
    let sent = v.str_("source_balance_sent");
    let sum = v.str_("requested_amount_plus_fee");
    assert_eq!(sent, sum, "{id}: source_balance is not the hardcoded amount + fee");
    let preprocess = cross().m_request("/construction/preprocess");
    assert_eq!(preprocess.body["metadata"]["source_balance"].as_str(), Some(sent.as_str()), "{id}: vs the request log");
}

fn m_options(v: &mut dyn Vector) {
    let id = v.id();
    let served_pk = v.str_("served_change_pk");
    let served_balance = v.str_("served_source_balance");
    let meta_pk = v.str_("metadata_request_change_pk");
    let pay_pk = v.str_("payloads_request_change_pk");
    let pay_balance = v.str_("payloads_request_source_balance");
    assert_eq!(meta_pk, served_pk, "{id}: the metadata request did not forward the served change_pk");
    assert_eq!(pay_pk, served_pk, "{id}: the payloads request did not forward the served change_pk");
    assert_eq!(pay_balance, served_balance, "{id}: the payloads request did not forward the served balance");
    let c = cross();
    assert_eq!(c.m_request("/construction/metadata").body["options"]["change_pk"].as_str(), Some(meta_pk.as_str()), "{id}: vs the log");
    let payloads = c.m_request("/construction/payloads");
    assert_eq!(payloads.body["metadata"]["change_pk"].as_str(), Some(pay_pk.as_str()), "{id}: vs the log");
    assert_eq!(payloads.body["metadata"]["source_balance"].as_str(), Some(pay_balance.as_str()), "{id}: vs the log");
}

fn m_combine(v: &mut dyn Vector) {
    let id = v.id();
    let c = cross();
    let combine = v.blob("combine_reply");
    let origin = v.str_("combine_reply_origin_file");
    assert_eq!(combine, c.sidecar(&origin), "{id}: the combine reply is not the C-emitted {origin}");
    let submitted = v.blob("submitted");
    v.eq_bool("submitted_equals_combine_reply", submitted == combine);
    let signature = c.sidecar("M-signature.bin");
    v.eq_bool("wallet_signature_in_submitted_bytes", contains(&submitted, &signature));
    assert!(!contains(&submitted, &signature), "{id}: the wallet's own signature is in what it submitted");
    let served_hash = v.str_("served_submit_hash");
    v.eq_str("submit_result_hash", &served_hash);
    let submit = c.m_request("/construction/submit");
    assert_eq!(submit.body["signed_transaction"].as_str(), Some(hex::encode(&submitted).as_str()), "{id}: vs the log");
}

// --- a plain vector, for the binary that links no C --------------------------

pub struct Plain<'a> {
    pub file: &'a str,
    pub v: &'a serde_json::Value,
    pub sidecar: fn(&str) -> Vec<u8>,
    pub assertions: usize,
}

impl<'a> Plain<'a> {
    pub fn new(file: &'a str, v: &'a serde_json::Value, sidecar: fn(&str) -> Vec<u8>) -> Plain<'a> {
        Plain {
            file,
            v,
            sidecar,
            assertions: 0,
        }
    }

    fn get(&self, key: &str) -> &'a serde_json::Value {
        self.v
            .get(key)
            .unwrap_or_else(|| panic!("{}: vector {} has no `{key}` field", self.file, self.id()))
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
    fn str_(&self, key: &str) -> String {
        self.get(key)
            .as_str()
            .unwrap_or_else(|| panic!("{}: `{key}` is not a string", self.id()))
            .to_string()
    }
    fn hex(&self, key: &str) -> Vec<u8> {
        hex::decode(&self.str_(key), "vector").unwrap_or_else(|e| panic!("{}: `{key}`: {e}", self.id()))
    }
    fn u64_(&self, key: &str) -> u64 {
        self.get(key)
            .as_u64()
            .unwrap_or_else(|| panic!("{}: `{key}` is not a u64", self.id()))
    }
    fn bool_(&self, key: &str) -> bool {
        self.get(key)
            .as_bool()
            .unwrap_or_else(|| panic!("{}: `{key}` is not a bool", self.id()))
    }
    fn blob(&self, key: &str) -> Vec<u8> {
        let name = self.str_(&format!("{key}_file"));
        let want = self.u64_(&format!("{key}_len")) as usize;
        let bytes = (self.sidecar)(&name);
        assert_eq!(bytes.len(), want, "{}: sidecar {name} length", self.id());
        bytes
    }
    fn eq_u64(&mut self, key: &str, actual: u64) {
        let expected = self.u64_(key);
        self.check(key, expected, actual);
    }
    fn eq_bool(&mut self, key: &str, actual: bool) {
        let expected = self.bool_(key);
        self.check(key, expected, actual);
    }
    fn eq_str(&mut self, key: &str, actual: &str) {
        let expected = self.str_(key);
        self.check(key, expected, actual.to_string());
    }
    fn eq_bytes(&mut self, key: &str, actual: &[u8]) {
        let expected = hex::encode(&self.hex(key));
        self.check(key, expected, hex::encode(actual));
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
}
