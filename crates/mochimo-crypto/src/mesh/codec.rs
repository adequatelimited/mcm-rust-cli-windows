// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! The Mesh API's request and response bodies, as bytes: pure functions with
//! no transport, each tested against recorded bodies
//! (`fixtures/group_n_mesh_live.json`, captured from one server at one
//! block).
//!
//! # Requests
//!
//! Built with `serde_json::json!` and serialised compactly. `serde_json`'s map
//! is ordered, so keys come out sorted, byte-equal to
//! `json.dumps(obj, sort_keys=True, separators=(',',':'))`. Every endpoint
//! takes the same `network_identifier`, `{blockchain: "mochimo", network:
//! "mainnet"}`, which every handler compares exactly (`ErrWrongNetwork`
//! otherwise).
//!
//! # Responses
//!
//! Parsed by hand from a `serde_json::Value`, never by derive. Each parser
//! reads exactly the documented fields, checking presence, type, width and
//! range. The middleware reports its own failures as HTTP 200 carrying
//! `{code, message, retriable}` (`giveError`), so every parser checks for
//! that shape first and returns [`Error::Mesh`]. Any other deviation is
//! [`Error::MeshResponse`] naming the field, never the bytes.

use serde_json::{json, Map, Value};

use crate::addr::{Address, Tag};
use crate::consts::HASHLEN;
use crate::error::{Error, Result};

use super::hex;
use super::spend::SignedTransaction;
use super::{BalanceAt, ChainTip, EntitlementAt, LedgerEntry, TxId, MAX_HISTORY_RESPONSE_BYTES, MAX_RECON_RESPONSE_BYTES, MAX_REQUEST_BYTES};

/// `Constants.NetworkIdentifier.Blockchain`.
pub const NETWORK_BLOCKCHAIN: &str = "mochimo";
/// `Constants.NetworkIdentifier.Network`.
pub const NETWORK_NAME: &str = "mainnet";
/// The one `/call` method the middleware answers.
pub const TAG_RESOLVE_METHOD: &str = "tag_resolve";
/// `MCMCurrency`: the symbol every amount carries.
pub const CURRENCY_SYMBOL: &str = "MCM";
/// `MCMCurrency`: the decimals every amount carries.
pub const CURRENCY_DECIMALS: u64 = 9;

fn network_identifier() -> Value {
    json!({ "blockchain": NETWORK_BLOCKCHAIN, "network": NETWORK_NAME })
}

fn body(value: &Value) -> Vec<u8> {
    // `Value::to_string` cannot fail for a value built from strings, numbers
    // and objects.
    value.to_string().into_bytes()
}

fn prefixed(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    s.push_str(&hex::encode(bytes));
    s
}

// --- requests -------------------------------------------------------------

/// `POST /network/list` (`networkListHandler`). The endpoint takes no
/// `network_identifier`; the body includes it anyway so every request has the
/// same envelope.
pub fn request_network_list() -> Vec<u8> {
    body(&json!({ "network_identifier": network_identifier() }))
}

/// `POST /network/options` (`networkOptionsHandler`).
pub fn request_network_options() -> Vec<u8> {
    body(&json!({ "network_identifier": network_identifier() }))
}

/// `POST /network/status` (`networkStatusHandler`).
pub fn request_network_status() -> Vec<u8> {
    body(&json!({ "network_identifier": network_identifier() }))
}

/// `POST /call` with `method: "tag_resolve"` (`callHandler`): the tag as
/// `0x` + 40 hex, which the handler requires to the character
/// (`len == 2 + TXTAGLEN*2` and the prefix).
pub fn request_tag_resolve(tag: &Tag) -> Vec<u8> {
    body(&json!({
        "method": TAG_RESOLVE_METHOD,
        "network_identifier": network_identifier(),
        "parameters": { "tag": prefixed(tag) },
    }))
}

/// `POST /account/balance` (`accountBalanceHandler`) for a tag, in the
/// 42-character form, which the handler routes to the same tag resolution
/// `/call` uses.
pub fn request_account_balance(tag: &Tag) -> Vec<u8> {
    body(&json!({
        "account_identifier": { "address": prefixed(tag) },
        "network_identifier": network_identifier(),
    }))
}

/// `POST /account/entitlement` for a tag: the reward entitlement the ledger
/// holds for it, the column `/account/balance` does not report. The same
/// 42-character `account_identifier` form `/account/balance` takes.
pub fn request_account_entitlement(tag: &Tag) -> Vec<u8> {
    body(&json!({
        "account_identifier": { "address": prefixed(tag) },
        "network_identifier": network_identifier(),
    }))
}

/// `POST /construction/submit` (`constructionSubmitHandler`):
/// `signed_transaction` is the bare hex of the whole wire image, trailer
/// included, which the middleware decodes into a `TXENTRY` and re-serialises
/// byte for byte.
///
/// # Errors
///
/// `Error::PayloadTooLarge` if the body would exceed the middleware's request
/// cap, which a 256-destination image nearly reaches.
pub fn request_submit(signed: &SignedTransaction) -> Result<Vec<u8>> {
    request_submit_wire(&signed.wire())
}

/// [`request_submit`] over a wire image the caller already holds, such as the
/// artifact `send` printed, passed back through the `submit` command. Same
/// body and request cap.
pub fn request_submit_wire(wire: &[u8]) -> Result<Vec<u8>> {
    let out = body(&json!({
        "network_identifier": network_identifier(),
        "signed_transaction": hex::encode(wire),
    }));
    if out.len() > MAX_REQUEST_BYTES {
        return Err(Error::PayloadTooLarge {
            what: "submit request body",
            max: MAX_REQUEST_BYTES,
            got: out.len(),
        });
    }
    Ok(out)
}

/// `POST /block` by index (`blockHandler`).
///
/// Index 0 is not genesis: `getBlock` queries by number only when
/// `Index != 0`, and otherwise returns the current block. The command line
/// therefore refuses `block 0`.
pub fn request_block_by_index(index: u64) -> Vec<u8> {
    body(&json!({
        "block_identifier": { "index": index },
        "network_identifier": network_identifier(),
    }))
}

/// `POST /block` by hash (`getBlock`'s second arm).
///
/// The handler takes a hash of at most `32*2+2` characters and reads the
/// block from the deployment's own archive, so a not-found means the
/// deployment did not archive it, not that the chain lacks it.
pub fn request_block_by_hash(hash: &[u8; HASHLEN]) -> Vec<u8> {
    body(&json!({
        "block_identifier": { "hash": prefixed(hash) },
        "network_identifier": network_identifier(),
    }))
}

/// `POST /search/transactions` by transaction hash
/// (`searchTransactionsHandler`).
pub fn request_search_by_hash(hash: &[u8; HASHLEN]) -> Vec<u8> {
    body(&json!({
        "network_identifier": network_identifier(),
        "transaction_identifier": { "hash": prefixed(hash) },
    }))
}

/// `POST /search/transactions` by account, newest first.
///
/// The address is the 20-byte tag, in the form [`request_tag_resolve`]
/// builds; the indexer matches it against `a.account_tag`.
///
/// `limit` is passed as given, and the caller keeps it in range: the handler
/// uses it only when `0 < limit <= 100`, and otherwise silently returns its
/// default of 10 rows. No `offset` is sent; rows come back newest first, so
/// [`request_search_by_account_from`] is the same request starting further
/// down.
pub fn request_search_by_account(tag: &Tag, limit: u64) -> Vec<u8> {
    body(&json!({
        "account_identifier": { "address": prefixed(tag) },
        "limit": limit,
        "network_identifier": network_identifier(),
    }))
}

/// [`request_search_by_account`] with an `offset`: the rows from the
/// `offset`-th newest on, skipping the `offset` newest.
///
/// The handler decodes `offset` as an `int64` and applies it as SQL `OFFSET`
/// after the newest-first ordering. A value above `i64::MAX` does not decode
/// and is answered with code 1, *Invalid request*; the caller keeps it in
/// range.
///
/// The offset counts rows as they stand when the request is served. New rows
/// arrive at the newest end, so a later page fetched with an earlier
/// `next_offset` may repeat rows but never skips one.
///
/// The key is sent even when it is 0.
pub fn request_search_by_account_from(tag: &Tag, limit: u64, offset: u64) -> Vec<u8> {
    body(&json!({
        "account_identifier": { "address": prefixed(tag) },
        "limit": limit,
        "network_identifier": network_identifier(),
        "offset": offset,
    }))
}

/// `POST /mempool` (`mempoolHandler`): every transaction id the node's
/// queue holds.
pub fn request_mempool() -> Vec<u8> {
    body(&json!({ "network_identifier": network_identifier() }))
}

/// `POST /mempool/transaction` (`mempoolTransactionHandler`): one
/// transaction from the node's queue, by id. The handler compares ids as
/// `fmt.Sprintf("0x%x", id)` strings, so the id is sent as `0x` and 64
/// lower-case hex digits.
pub fn request_mempool_transaction(id: &[u8; HASHLEN]) -> Vec<u8> {
    body(&json!({
        "network_identifier": network_identifier(),
        "transaction_identifier": { "hash": prefixed(id) },
    }))
}

// --- responses ------------------------------------------------------------

/// A response body as an object, the error object already routed to
/// [`Error::Mesh`].
fn envelope(bytes: &[u8], cap: usize) -> Result<Map<String, Value>> {
    if bytes.len() > cap {
        return Err(Error::PayloadTooLarge {
            what: "response body",
            max: cap,
            got: bytes.len(),
        });
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| Error::MeshResponse { what: "json" })?;
    let Value::Object(map) = value else {
        return Err(Error::MeshResponse { what: "object" });
    };
    // `giveError`'s shape: {code, message, retriable}. No documented success
    // body carries a top-level `code`.
    if let Some(code) = map.get("code").and_then(Value::as_u64) {
        if map.get("message").and_then(Value::as_str).is_some() {
            let retriable = map.get("retriable").and_then(Value::as_bool).unwrap_or(false);
            return Err(Error::Mesh { code, retriable });
        }
    }
    Ok(map)
}

fn field<'a>(map: &'a Map<String, Value>, key: &str, what: &'static str) -> Result<&'a Value> {
    map.get(key).ok_or(Error::MeshResponse { what })
}

fn object<'a>(v: &'a Value, what: &'static str) -> Result<&'a Map<String, Value>> {
    v.as_object().ok_or(Error::MeshResponse { what })
}

fn unsigned(v: &Value, what: &'static str) -> Result<u64> {
    // `as_u64` is `Some` only for a JSON integer that fits: a float, a
    // negative or a string is refused here rather than coerced.
    v.as_u64().ok_or(Error::MeshResponse { what })
}

fn string<'a>(v: &'a Value, what: &'static str) -> Result<&'a str> {
    v.as_str().ok_or(Error::MeshResponse { what })
}

/// A decimal string of one to twenty ASCII digits, as `/account/balance`
/// spells an amount (`fmt.Sprintf("%d", balance)`). Stricter than
/// `str::parse`, which accepts a leading `+`.
fn decimal(s: &str, what: &'static str) -> Result<u64> {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() > 20 || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(Error::MeshResponse { what });
    }
    s.parse::<u64>().map_err(|_| Error::MeshResponse { what })
}

fn tip(map: &Map<String, Value>, key: &str, what_index: &'static str, what_hash: &'static str) -> Result<ChainTip> {
    let block = object(field(map, key, what_index)?, what_index)?;
    let index = unsigned(field(block, "index", what_index)?, what_index)?;
    let hash = hex::decode_prefixed::<HASHLEN>(string(field(block, "hash", what_hash)?, what_hash)?, what_hash)?;
    Ok(ChainTip { index, hash })
}

/// `/network/list`: whether the middleware serves exactly the identifier this
/// codec sends. `Ok(true)` when `{mochimo, mainnet}` is among the
/// `network_identifiers`; `Ok(false)` when the list is well formed and it is
/// not.
pub fn parse_network_list(bytes: &[u8]) -> Result<bool> {
    let map = envelope(bytes, MAX_RECON_RESPONSE_BYTES)?;
    let list = field(&map, "network_identifiers", "network_identifiers")?
        .as_array()
        .ok_or(Error::MeshResponse {
            what: "network_identifiers: array",
        })?;
    let mut serves = false;
    for entry in list {
        let entry = object(entry, "network_identifiers[]")?;
        let blockchain = string(field(entry, "blockchain", "network_identifiers[].blockchain")?, "network_identifiers[].blockchain")?;
        let network = string(field(entry, "network", "network_identifiers[].network")?, "network_identifiers[].network")?;
        if blockchain == NETWORK_BLOCKCHAIN && network == NETWORK_NAME {
            serves = true;
        }
    }
    Ok(serves)
}

/// A network the middleware serves, as `/network/list` names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkIdentifier {
    pub blockchain: String,
    pub network: String,
}

/// The most networks [`parse_network_identifiers`] copies. Applied before
/// anything is copied.
pub const MAX_NETWORKS: usize = 64;
/// The longest network name [`parse_network_identifiers`] copies.
pub const MAX_NETWORK_NAME_BYTES: usize = 64;

/// `/network/list`: every network the middleware serves, in the reply's
/// order, for showing which network a node is on.
pub fn parse_network_identifiers(bytes: &[u8]) -> Result<Vec<NetworkIdentifier>> {
    let map = envelope(bytes, MAX_RECON_RESPONSE_BYTES)?;
    let list = field(&map, "network_identifiers", "network_identifiers")?
        .as_array()
        .ok_or(Error::MeshResponse {
            what: "network_identifiers: array",
        })?;
    if list.len() > MAX_NETWORKS {
        return Err(Error::MeshResponse { what: "network_identifiers: too many" });
    }
    let name = |entry: &Map<String, Value>, key: &str, what: &'static str| -> Result<String> {
        let s = string(field(entry, key, what)?, what)?;
        if s.len() > MAX_NETWORK_NAME_BYTES {
            return Err(Error::MeshResponse { what });
        }
        Ok(s.to_owned())
    };
    let mut out = Vec::with_capacity(list.len());
    for entry in list {
        let entry = object(entry, "network_identifiers[]")?;
        out.push(NetworkIdentifier {
            blockchain: name(entry, "blockchain", "network_identifiers[].blockchain")?,
            network: name(entry, "network", "network_identifiers[].network")?,
        });
    }
    Ok(out)
}

/// What `/network/options` declares: the three version strings and the
/// error codes it advertises.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkOptions {
    pub rosetta_version: String,
    pub node_version: String,
    pub middleware_version: String,
    pub error_codes: Vec<u64>,
}

/// `/network/options`. Version strings are capped at 64 bytes each and the
/// error table at 64 entries before anything is copied.
pub fn parse_network_options(bytes: &[u8]) -> Result<NetworkOptions> {
    let map = envelope(bytes, MAX_RECON_RESPONSE_BYTES)?;
    let version = object(field(&map, "version", "version")?, "version")?;
    let ver = |key: &str, what: &'static str| -> Result<String> {
        let s = string(field(version, key, what)?, what)?;
        if s.len() > 64 {
            return Err(Error::MeshResponse { what });
        }
        Ok(s.to_owned())
    };
    let rosetta_version = ver("rosetta_version", "version.rosetta_version")?;
    let node_version = ver("node_version", "version.node_version")?;
    let middleware_version = ver("middleware_version", "version.middleware_version")?;
    let allow = object(field(&map, "allow", "allow")?, "allow")?;
    let errors = field(allow, "errors", "allow.errors")?
        .as_array()
        .ok_or(Error::MeshResponse { what: "allow.errors: array" })?;
    if errors.len() > 64 {
        return Err(Error::MeshResponse {
            what: "allow.errors: too many",
        });
    }
    let mut error_codes = Vec::with_capacity(errors.len());
    for e in errors {
        let e = object(e, "allow.errors[]")?;
        error_codes.push(unsigned(field(e, "code", "allow.errors[].code")?, "allow.errors[].code")?);
    }
    Ok(NetworkOptions {
        rosetta_version,
        node_version,
        middleware_version,
        error_codes,
    })
}

/// `/network/status`: the current block only;
/// [`parse_network_status_full`] reads more.
pub fn parse_network_status(bytes: &[u8]) -> Result<ChainTip> {
    let map = envelope(bytes, MAX_RECON_RESPONSE_BYTES)?;
    tip(
        &map,
        "current_block_identifier",
        "current_block_identifier.index",
        "current_block_identifier.hash",
    )
}

/// `/network/status` beyond the tip: when the tip was solved, the genesis
/// block, and the middleware's own sync state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkStatus {
    /// `current_block_identifier`, as [`parse_network_status`] reads it.
    pub tip: ChainTip,
    /// `current_block_timestamp`: when the tip was solved, in milliseconds
    /// since the epoch (its trailer's `stime`). An old value means the tip
    /// has not moved, either on the network or in the node's or middleware's
    /// view of it.
    pub tip_timestamp_ms: i64,
    /// `genesis_block_identifier`: block 0 as the middleware read it from
    /// its node when it started.
    pub genesis: ChainTip,
    /// `sync_status`, or `None` when the reply carries none.
    pub sync: Option<SyncStatus>,
}

/// The middleware's own sync state: how its last refresh of its node's tip
/// went (`RefreshSync`).
///
/// It does not say whether the node is current with the network: a node that
/// has fallen behind reports its old tip, and the middleware still reports
/// itself synchronized. [`NetworkStatus::tip_timestamp_ms`] shows a tip that
/// has not moved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncStatus {
    /// `stage`, in the middleware's words: `synchronized` once a refresh
    /// has finished, `synchronizing` while one takes a new tip, or the step
    /// that failed (`latest block error`, `min fee error` and others).
    pub stage: String,
    /// `synced`: whether the last refresh finished.
    pub synced: bool,
}

/// The longest sync stage [`parse_network_status_full`] copies.
pub const MAX_SYNC_STAGE_BYTES: usize = 64;

/// `/network/status` in full: the tip, its timestamp, the genesis block and
/// the middleware's sync state. The first three are required, as Rosetta
/// requires them; `sync_status` is `None` when absent. The stage is capped at
/// [`MAX_SYNC_STAGE_BYTES`] before it is copied.
pub fn parse_network_status_full(bytes: &[u8]) -> Result<NetworkStatus> {
    let map = envelope(bytes, MAX_RECON_RESPONSE_BYTES)?;
    let current = tip(
        &map,
        "current_block_identifier",
        "current_block_identifier.index",
        "current_block_identifier.hash",
    )?;
    let tip_timestamp_ms = field(&map, "current_block_timestamp", "current_block_timestamp")?
        .as_i64()
        .ok_or(Error::MeshResponse { what: "current_block_timestamp" })?;
    let genesis = tip(
        &map,
        "genesis_block_identifier",
        "genesis_block_identifier.index",
        "genesis_block_identifier.hash",
    )?;
    let sync = match map.get("sync_status") {
        None | Some(Value::Null) => None,
        Some(v) => {
            let s = object(v, "sync_status")?;
            let stage = string(field(s, "stage", "sync_status.stage")?, "sync_status.stage")?;
            if stage.len() > MAX_SYNC_STAGE_BYTES {
                return Err(Error::MeshResponse { what: "sync_status.stage" });
            }
            let synced = field(s, "synced", "sync_status.synced")?
                .as_bool()
                .ok_or(Error::MeshResponse { what: "sync_status.synced" })?;
            Some(SyncStatus { stage: stage.to_owned(), synced })
        }
    };
    Ok(NetworkStatus { tip: current, tip_timestamp_ms, genesis, sync })
}

/// `/call tag_resolve`: `result.address` is the full 40-byte ledger address
/// and `result.amount` the balance as a JSON number (unlike
/// `/account/balance`, which uses a string). The returned address must begin
/// with `tag`, the tag the request carried, or the reply is refused.
pub fn parse_tag_resolve(bytes: &[u8], tag: &Tag) -> Result<LedgerEntry> {
    let map = envelope(bytes, MAX_RECON_RESPONSE_BYTES)?;
    let result = object(field(&map, "result", "result")?, "result")?;
    let address: Address =
        hex::decode_prefixed(string(field(result, "address", "result.address")?, "result.address")?, "result.address")?;
    if !address.starts_with(tag) {
        return Err(Error::MeshResponse {
            what: "result.address: does not begin with the tag resolved",
        });
    }
    let balance = unsigned(field(result, "amount", "result.amount: unsigned integer")?, "result.amount: unsigned integer")?;
    Ok(LedgerEntry { address, balance })
}

/// `/account/balance`: `balances[0].value` as a decimal string in nanoMCM,
/// with the currency checked to be the one the middleware declares, and the
/// block the middleware had cached when it answered.
pub fn parse_account_balance(bytes: &[u8]) -> Result<BalanceAt> {
    let map = envelope(bytes, MAX_RECON_RESPONSE_BYTES)?;
    let tip = tip(&map, "block_identifier", "block_identifier.index", "block_identifier.hash")?;
    let balances = field(&map, "balances", "balances")?
        .as_array()
        .ok_or(Error::MeshResponse { what: "balances: array" })?;
    let first = object(
        balances.first().ok_or(Error::MeshResponse { what: "balances[0]" })?,
        "balances[0]",
    )?;
    let balance = decimal(
        string(field(first, "value", "balances[0].value")?, "balances[0].value")?,
        "balances[0].value: decimal",
    )?;
    let currency = object(field(first, "currency", "balances[0].currency")?, "balances[0].currency")?;
    if string(field(currency, "symbol", "balances[0].currency.symbol")?, "balances[0].currency.symbol")? != CURRENCY_SYMBOL
    {
        return Err(Error::MeshResponse {
            what: "balances[0].currency.symbol: not MCM",
        });
    }
    if unsigned(field(currency, "decimals", "balances[0].currency.decimals")?, "balances[0].currency.decimals")?
        != CURRENCY_DECIMALS
    {
        return Err(Error::MeshResponse {
            what: "balances[0].currency.decimals: not 9",
        });
    }
    Ok(BalanceAt { balance, tip })
}

/// `/account/entitlement`: `entitlement.value` as a decimal string in
/// nanoMCM, with the currency checked as `/account/balance`'s is, and the
/// block the middleware answered at. `account_identifier.address` must be
/// `tag`, or the reply is refused.
pub fn parse_account_entitlement(bytes: &[u8], tag: &Tag) -> Result<EntitlementAt> {
    let map = envelope(bytes, MAX_RECON_RESPONSE_BYTES)?;
    let tip = tip(&map, "block_identifier", "block_identifier.index", "block_identifier.hash")?;
    let account = object(field(&map, "account_identifier", "account_identifier")?, "account_identifier")?;
    let answered: Tag = hex::decode_prefixed(
        string(field(account, "address", "account_identifier.address")?, "account_identifier.address")?,
        "account_identifier.address",
    )?;
    if answered != *tag {
        return Err(Error::MeshResponse {
            what: "account_identifier.address: not the tag asked about",
        });
    }
    let entitlement = object(field(&map, "entitlement", "entitlement")?, "entitlement")?;
    let amount = decimal(
        string(field(entitlement, "value", "entitlement.value")?, "entitlement.value")?,
        "entitlement.value: decimal",
    )?;
    let currency = object(field(entitlement, "currency", "entitlement.currency")?, "entitlement.currency")?;
    if string(field(currency, "symbol", "entitlement.currency.symbol")?, "entitlement.currency.symbol")? != CURRENCY_SYMBOL {
        return Err(Error::MeshResponse {
            what: "entitlement.currency.symbol: not MCM",
        });
    }
    if unsigned(field(currency, "decimals", "entitlement.currency.decimals")?, "entitlement.currency.decimals")?
        != CURRENCY_DECIMALS
    {
        return Err(Error::MeshResponse {
            what: "entitlement.currency.decimals: not 9",
        });
    }
    Ok(EntitlementAt { entitlement: amount, tip })
}

// --- v4.1 staking: /account/balance's metadata and /stats/staking ----------

/// `POST /stats/staking` (`stakingHandler`): the staking summary, which takes
/// only the network identifier.
pub fn request_staking_stats() -> Vec<u8> {
    body(&json!({ "network_identifier": network_identifier() }))
}

/// Where `/account/balance` says its stake fields came from (`stake_source`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StakeSource {
    /// `node`: one read of the node's v4.1 entry, so the spendable balance
    /// and the stake are the same ledger state.
    Node,
    /// `ledger_cache`: the node's 80-byte entry beside the middleware's
    /// cached stake fields, which can be a cache interval old.
    LedgerCache,
    /// `unavailable`: the middleware has no stake fields to give.
    Unavailable,
}

/// The stake's own terms, as `/account/balance` reports them while the tag
/// stakes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StakeTerms {
    /// `stake.commit`: the height of the block that recorded the stake.
    pub commit: u64,
    /// `stake.expiry`: the neogenesis height the lock ends at.
    pub expiry: u64,
    /// `stake.locked`, as the middleware computed it against its own tip.
    pub locked: bool,
    /// `stake.tier`, absent when no tier matches the two heights.
    pub tier: Option<u8>,
    /// `stake.coefficient`.
    pub coefficient: Option<u64>,
    /// `stake.weight`: `(staked + entitlement) x coefficient`, a decimal that
    /// can exceed 64 bits.
    pub weight: Option<u128>,
}

/// What `/account/balance` says about one tag from v4.1: the spendable
/// balance it always reported, and the stake fields its metadata carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StakeAt {
    /// The block the middleware had cached when it answered.
    pub tip: ChainTip,
    /// `balances[0].value`: the spendable balance, the only figure a send is
    /// built against. `metadata.spendable` must agree with it.
    pub spendable: u64,
    /// `None` when the reply carries no stake metadata: a middleware that
    /// predates v4.1, or one whose stake source is unavailable.
    pub stake: Option<StakeFields>,
}

/// The stake fields of [`StakeAt`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StakeFields {
    /// `metadata.staked`: the staked principal, zero for a tag that does not
    /// stake.
    pub staked: u64,
    pub source: StakeSource,
    /// `metadata.stake_block_index`: the height the stake fields were read at.
    pub block: u64,
    /// `metadata.entitlement`, reported only while the tag stakes: the
    /// stake's compounding reward. Otherwise use `/account/entitlement`,
    /// which is rate-limited to one check per ten seconds.
    pub entitlement: Option<u64>,
    /// `metadata.total`: spendable + staked + entitlement, while the tag stakes.
    pub total: Option<u64>,
    /// `metadata.stake`, while the tag stakes.
    pub terms: Option<StakeTerms>,
    /// `metadata.consent`, present only when the middleware discloses a
    /// consent the tag holds. Its absence does not mean there is none.
    pub consent: Option<ConsentReport>,
}

/// A consent the tag holds, as `metadata.consent` reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsentReport {
    /// `consent.kind`: 1 to 4, or 0 for none.
    pub kind: u8,
    /// `consent.height`: the height of the block that recorded it.
    pub height: u64,
    /// `consent.live`, as the middleware computed it against its own tip.
    pub live: bool,
}

fn optional_decimal(map: &Map<String, Value>, key: &str, what: &'static str) -> Result<Option<u64>> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => decimal(string(v, what)?, what).map(Some),
    }
}

fn optional_unsigned(map: &Map<String, Value>, key: &str, what: &'static str) -> Result<Option<u64>> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => unsigned(v, what).map(Some),
    }
}

/// A decimal string of one to thirty-nine digits as a `u128`: the weight,
/// which is a product of a supply-sized amount and a coefficient.
fn decimal_u128(s: &str, what: &'static str) -> Result<u128> {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() > 39 || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(Error::MeshResponse { what });
    }
    s.parse::<u128>().map_err(|_| Error::MeshResponse { what })
}

/// `/account/balance` from v4.1: [`parse_account_balance`]'s figure and
/// block, then the stake metadata the middleware adds (`stakeMetadata`).
/// Every field present is type-checked; an absent field is `None`.
/// `metadata.spendable`, when present, must equal `balances[0].value`, or
/// the reply is refused.
pub fn parse_account_stake(bytes: &[u8]) -> Result<StakeAt> {
    let at = parse_account_balance(bytes)?;
    let map = envelope(bytes, MAX_RECON_RESPONSE_BYTES)?;
    let Some(meta) = map.get("metadata").filter(|v| !v.is_null()) else {
        return Ok(StakeAt { tip: at.tip, spendable: at.balance, stake: None });
    };
    let meta = object(meta, "metadata")?;
    if let Some(spendable) = optional_decimal(meta, "spendable", "metadata.spendable: decimal")? {
        if spendable != at.balance {
            return Err(Error::MeshResponse {
                what: "metadata.spendable: not balances[0].value",
            });
        }
    }
    let source = match meta.get("stake_source").and_then(Value::as_str) {
        Some("node") => StakeSource::Node,
        Some("ledger_cache") => StakeSource::LedgerCache,
        Some("unavailable") | None => StakeSource::Unavailable,
        Some(_) => return Err(Error::MeshResponse { what: "metadata.stake_source" }),
    };
    let Some(staked) = optional_decimal(meta, "staked", "metadata.staked: decimal")? else {
        return Ok(StakeAt { tip: at.tip, spendable: at.balance, stake: None });
    };
    let block = optional_unsigned(meta, "stake_block_index", "metadata.stake_block_index")?
        .ok_or(Error::MeshResponse { what: "metadata.stake_block_index" })?;
    let terms = match meta.get("stake") {
        None | Some(Value::Null) => None,
        Some(v) => {
            let s = object(v, "metadata.stake")?;
            let tier = match optional_unsigned(s, "tier", "metadata.stake.tier")? {
                None => None,
                Some(t) => Some(u8::try_from(t).map_err(|_| Error::MeshResponse { what: "metadata.stake.tier" })?),
            };
            let weight = match s.get("weight") {
                None | Some(Value::Null) => None,
                Some(w) => Some(decimal_u128(string(w, "metadata.stake.weight")?, "metadata.stake.weight: decimal")?),
            };
            Some(StakeTerms {
                commit: unsigned(field(s, "commit", "metadata.stake.commit")?, "metadata.stake.commit")?,
                expiry: unsigned(field(s, "expiry", "metadata.stake.expiry")?, "metadata.stake.expiry")?,
                locked: field(s, "locked", "metadata.stake.locked")?
                    .as_bool()
                    .ok_or(Error::MeshResponse { what: "metadata.stake.locked" })?,
                tier,
                coefficient: optional_unsigned(s, "coefficient", "metadata.stake.coefficient")?,
                weight,
            })
        }
    };
    let consent = match meta.get("consent") {
        None | Some(Value::Null) => None,
        Some(v) => {
            let c = object(v, "metadata.consent")?;
            let kind = unsigned(field(c, "kind", "metadata.consent.kind")?, "metadata.consent.kind")?;
            Some(ConsentReport {
                kind: u8::try_from(kind).map_err(|_| Error::MeshResponse { what: "metadata.consent.kind" })?,
                height: unsigned(field(c, "height", "metadata.consent.height")?, "metadata.consent.height")?,
                live: field(c, "live", "metadata.consent.live")?
                    .as_bool()
                    .ok_or(Error::MeshResponse { what: "metadata.consent.live" })?,
            })
        }
    };
    Ok(StakeAt {
        tip: at.tip,
        spendable: at.balance,
        stake: Some(StakeFields {
            staked,
            source,
            block,
            entitlement: optional_decimal(meta, "entitlement", "metadata.entitlement: decimal")?,
            total: optional_decimal(meta, "total", "metadata.total: decimal")?,
            terms,
            consent,
        }),
    })
}

/// The last `STAKE_SET` the middleware saw: block `h`'s staking commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StakeSetSummary {
    /// The block that carried it.
    pub block: ChainTip,
    /// `|E_h|`: the stakers paid in that block.
    pub count: u64,
    /// `S_h = floor(B_h / 2) + F_h`: the staker pool for that block.
    pub pool: u64,
    /// `F_h`: entitlement forfeited by early unstakes in that block.
    pub forfeit: u64,
    /// `D_h`: rounding dust, credited to the founder address.
    pub dust: u64,
    /// `W`: the total weight the pool was divided by.
    pub weight: u128,
}

/// The middleware's own ledger-cache totals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StakingLedger {
    /// The block the cache was built at.
    pub block: u64,
    /// Entries with a stake.
    pub stakers: u64,
    /// The sum of every stake, nanoMCM.
    pub staked: u64,
    pub weight: u128,
}

/// `/stats/staking`: the network's staking summary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StakingStats {
    /// `block_identifier`: the middleware's tip.
    pub tip: ChainTip,
    /// `v41_trigger`, when the middleware was built with one.
    pub trigger: Option<u64>,
    /// `v41_active`: whether the tip runs the v4.1 rules.
    pub active: bool,
    /// `min_stake`: the minimum stake for the next block, nanoMCM.
    pub min_stake: u64,
    /// `stake_set`: the last `STAKE_SET` seen, if any.
    pub stake_set: Option<StakeSetSummary>,
    /// `ledger`: the cache's totals, if it has a cache.
    pub ledger: Option<StakingLedger>,
}

/// An `Amount` object (`{value, currency}`) as nanoMCM, the currency checked
/// as `/account/balance`'s is.
fn amount_object(v: &Value, what: &'static str) -> Result<u64> {
    let a = object(v, what)?;
    let value = decimal(string(field(a, "value", what)?, what)?, what)?;
    let currency = object(field(a, "currency", what)?, what)?;
    if string(field(currency, "symbol", what)?, what)? != CURRENCY_SYMBOL
        || unsigned(field(currency, "decimals", what)?, what)? != CURRENCY_DECIMALS
    {
        return Err(Error::MeshResponse { what });
    }
    Ok(value)
}

/// `/stats/staking` (`stakingHandler`): the tip, the trigger, whether v4.1 is
/// active, the minimum stake, the last `STAKE_SET` and the ledger cache's
/// totals. The last two are optional; the handler omits them when it has
/// neither.
pub fn parse_staking_stats(bytes: &[u8]) -> Result<StakingStats> {
    let map = envelope(bytes, MAX_RECON_RESPONSE_BYTES)?;
    let current = tip(&map, "block_identifier", "block_identifier.index", "block_identifier.hash")?;
    let trigger = optional_unsigned(&map, "v41_trigger", "v41_trigger")?;
    let active = field(&map, "v41_active", "v41_active")?
        .as_bool()
        .ok_or(Error::MeshResponse { what: "v41_active" })?;
    let min_stake = amount_object(field(&map, "min_stake", "min_stake")?, "min_stake")?;
    let stake_set = match map.get("stake_set") {
        None | Some(Value::Null) => None,
        Some(v) => {
            let s = object(v, "stake_set")?;
            Some(StakeSetSummary {
                block: tip(s, "block_identifier", "stake_set.block_identifier.index", "stake_set.block_identifier.hash")?,
                count: unsigned(field(s, "count", "stake_set.count")?, "stake_set.count")?,
                pool: amount_object(field(s, "pool", "stake_set.pool")?, "stake_set.pool")?,
                forfeit: amount_object(field(s, "forfeit", "stake_set.forfeit")?, "stake_set.forfeit")?,
                dust: amount_object(field(s, "dust", "stake_set.dust")?, "stake_set.dust")?,
                weight: decimal_u128(string(field(s, "weight", "stake_set.weight")?, "stake_set.weight")?, "stake_set.weight")?,
            })
        }
    };
    let ledger = match map.get("ledger") {
        None | Some(Value::Null) => None,
        Some(v) => {
            let l = object(v, "ledger")?;
            Some(StakingLedger {
                block: unsigned(field(l, "block_index", "ledger.block_index")?, "ledger.block_index")?,
                stakers: unsigned(field(l, "stakers", "ledger.stakers")?, "ledger.stakers")?,
                staked: amount_object(field(l, "staked", "ledger.staked")?, "ledger.staked")?,
                weight: decimal_u128(string(field(l, "weight", "ledger.weight")?, "ledger.weight")?, "ledger.weight")?,
            })
        }
    };
    Ok(StakingStats { tip: current, trigger, active, min_stake, stake_set, ledger })
}

/// `/construction/submit`: `transaction_identifier.hash`, bare hex (the
/// handler `hex.EncodeToString`s it with no prefix, unlike `/mempool`).
pub fn parse_submit(bytes: &[u8]) -> Result<TxId> {
    let map = envelope(bytes, MAX_RECON_RESPONSE_BYTES)?;
    let ident = object(
        field(&map, "transaction_identifier", "transaction_identifier")?,
        "transaction_identifier",
    )?;
    let hash = hex::decode_exact::<HASHLEN>(
        string(field(ident, "hash", "transaction_identifier.hash")?, "transaction_identifier.hash")?,
        "transaction_identifier.hash",
    )?;
    Ok(TxId(hash))
}

// --- the explorer endpoints' replies ---------------------------------------

/// One Rosetta operation, as both `/block` and `/search/transactions` spell
/// it.
///
/// `amount.value` is a decimal string on both endpoints and may be negative
/// (a source debit), so it is read by [`signed_decimal`] into an `i128`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operation {
    pub index: u64,
    /// `REWARD`, `DESTINATION_TRANSFER`, `SOURCE_TRANSFER`, `FEE`. Kept as
    /// sent, so an unknown value is rendered, not refused.
    pub kind: String,
    pub address: String,
    pub amount: i128,
    /// `metadata.memo` where the endpoint carries one, empty otherwise.
    pub memo: String,
}

/// The operation type the middleware gives a mining reward.
pub const OP_REWARD: &str = "REWARD";
/// The operation type for value arriving at an address.
pub const OP_DESTINATION: &str = "DESTINATION_TRANSFER";
/// The operation type for value leaving a source address.
pub const OP_SOURCE: &str = "SOURCE_TRANSFER";
/// The operation type for the fee paid to the miner.
pub const OP_FEE: &str = "FEE";

/// One transaction as an explorer endpoint renders it.
///
/// `block` and `timestamp_ms` are `Some` only on `/search/transactions`,
/// which carries them per row; inside a `/block` reply the block is the
/// enclosing one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeshTransaction {
    pub hash: [u8; HASHLEN],
    pub block: Option<ChainTip>,
    pub timestamp_ms: Option<i64>,
    pub operations: Vec<Operation>,
    /// The `metadata` map as `(key, value)` pairs in the endpoint's own
    /// spelling, sorted by key.
    ///
    /// Not parsed into numbers: the same keys come back as decimal strings
    /// from `/block` and as JSON numbers from `/search/transactions`.
    pub metadata: Vec<(String, String)>,
}

/// A whole block, as `/block` renders it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeshBlock {
    pub block: ChainTip,
    pub parent: ChainTip,
    pub timestamp_ms: i64,
    pub transactions: Vec<MeshTransaction>,
    /// The block's own figures, from its trailer; `None` when the reply
    /// carries no `block.metadata`, or carries it without one of the eight
    /// keys [`BlockMetadata`] reads.
    pub metadata: Option<BlockMetadata>,
}

/// A block's own figures, as `/block` sends them in `block.metadata`.
///
/// `getBlock` writes eight keys, all from the block's trailer except the
/// size: `block_size` (bytes), `difficulty`, `fee` (`mfee`), `haiku`,
/// `nonce`, `root` (`mroot`), `stime` (milliseconds) and `tx_count`
/// (`tcount`). Numbers are JSON numbers and the two hashes are `0x` and 64
/// hex digits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockMetadata {
    /// The block's length in bytes, as the node holds it.
    pub block_size: u64,
    /// The trailer's difficulty.
    pub difficulty: u32,
    /// The trailer's `mfee`, the least fee a transaction in it pays, in
    /// nanoMCM (`types.h:657`, "minimum transaction fee").
    pub fee: u64,
    /// The trailer's nonce expanded into words by the middleware. Sent for
    /// every block, but a haiku only for a normal one (`bup.c:98`).
    pub haiku: String,
    /// The trailer's nonce (`types.h:662`, "solving nonce of standard
    /// blocks").
    pub nonce: [u8; HASHLEN],
    /// The trailer's Merkle root over the block's contents (`mroot`).
    pub root: [u8; HASHLEN],
    /// When the block was solved, in milliseconds since the epoch: the
    /// trailer's `stime`, which `/block` also sends as the block's
    /// `timestamp`.
    pub stime_ms: i64,
    /// The trailer's transaction count, excluding the miner's reward, which
    /// `/block` lists as a transaction of its own.
    pub tx_count: u32,
}

/// What kind of block a block is, by the reference implementation's test
/// (`bup.c:88-89`): a block whose number's low byte is zero is neogenesis,
/// otherwise a block whose trailer counts no transactions is a pseudo-block.
/// A pseudo-block has no proof of work checked (`bval.c:240`, `:280`); a
/// neogenesis block carries the ledger (`bval.c:33`) and comes every 256th
/// block, including block 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockKind {
    /// Transactions, solved by proof of work.
    Normal,
    /// No transactions.
    Pseudo,
    /// The ledger, at a block number whose low byte is zero.
    Neogenesis,
}

impl MeshBlock {
    /// The block's kind, by [`BlockKind`]'s test: from its number alone for
    /// a neogenesis block, and otherwise from the transaction count in
    /// [`Self::metadata`], so `None` when the node sent none.
    pub fn kind(&self) -> Option<BlockKind> {
        if self.block.index & 0xff == 0 {
            return Some(BlockKind::Neogenesis);
        }
        let metadata = self.metadata.as_ref()?;
        Some(if metadata.tx_count == 0 { BlockKind::Pseudo } else { BlockKind::Normal })
    }
}

/// A page of `/search/transactions`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchPage {
    pub transactions: Vec<MeshTransaction>,
    pub total_count: u64,
    /// `next_offset`, set by the handler only when a full page came back and
    /// more rows exist.
    pub next_offset: Option<u64>,
}

/// The most rows this codec copies out of one reply, applied before anything
/// is allocated.
const MAX_ROWS: usize = 4096;

/// A decimal string that may carry a leading `-`, as an amount does on both
/// explorer endpoints. Stricter than `str::parse`: no `+`, no spaces, no
/// empty digit run, and a width that cannot overflow `i128`.
fn signed_decimal(s: &str, what: &'static str) -> Result<i128> {
    let digits = s.strip_prefix('-').unwrap_or(s);
    if digits.is_empty() || digits.len() > 30 || !digits.as_bytes().iter().all(u8::is_ascii_digit) {
        return Err(Error::MeshResponse { what });
    }
    s.parse::<i128>().map_err(|_| Error::MeshResponse { what })
}

/// A `metadata` value in the endpoint's own spelling: a JSON string as
/// itself, a number as its digits, a bool and null by name. An object or an
/// array is refused; no documented metadata key carries one.
fn metadata_text(v: &Value, what: &'static str) -> Result<String> {
    match v {
        Value::String(s) => Ok(s.clone()),
        Value::Number(n) => Ok(n.to_string()),
        Value::Bool(b) => Ok(b.to_string()),
        Value::Null => Ok("null".to_owned()),
        _ => Err(Error::MeshResponse { what }),
    }
}

fn parse_operations(v: &Value) -> Result<Vec<Operation>> {
    let list = v.as_array().ok_or(Error::MeshResponse { what: "operations: array" })?;
    if list.len() > MAX_ROWS {
        return Err(Error::MeshResponse { what: "operations: too many" });
    }
    let mut out = Vec::with_capacity(list.len());
    for op in list {
        let op = object(op, "operations[]")?;
        let ident = object(field(op, "operation_identifier", "operations[].operation_identifier")?, "operations[].operation_identifier")?;
        let index = unsigned(field(ident, "index", "operations[].operation_identifier.index")?, "operations[].operation_identifier.index")?;
        let kind = string(field(op, "type", "operations[].type")?, "operations[].type")?.to_owned();
        let account = object(field(op, "account", "operations[].account")?, "operations[].account")?;
        let address = string(field(account, "address", "operations[].account.address")?, "operations[].account.address")?.to_owned();
        let amount = object(field(op, "amount", "operations[].amount")?, "operations[].amount")?;
        let amount = signed_decimal(
            string(field(amount, "value", "operations[].amount.value")?, "operations[].amount.value")?,
            "operations[].amount.value",
        )?;
        // `metadata` is absent on a REWARD, and on /search it is present
        // only on a destination with a non-empty reference.
        let memo = match op.get("metadata").and_then(Value::as_object) {
            Some(m) => match m.get("memo") {
                Some(v) => string(v, "operations[].metadata.memo")?.to_owned(),
                None => String::new(),
            },
            None => String::new(),
        };
        out.push(Operation { index, kind, address, amount, memo });
    }
    Ok(out)
}

fn parse_metadata(map: &Map<String, Value>) -> Result<Vec<(String, String)>> {
    let Some(Value::Object(m)) = map.get("metadata") else {
        return Ok(Vec::new());
    };
    let mut out = Vec::with_capacity(m.len());
    for (k, v) in m {
        out.push((k.clone(), metadata_text(v, "metadata value")?));
    }
    // A map's iteration order is the serialiser's; sort so a page is stable.
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn parse_transaction(map: &Map<String, Value>, with_block: bool) -> Result<MeshTransaction> {
    let ident = object(field(map, "transaction_identifier", "transaction_identifier")?, "transaction_identifier")?;
    let hash = hex::decode_prefixed::<HASHLEN>(
        string(field(ident, "hash", "transaction_identifier.hash")?, "transaction_identifier.hash")?,
        "transaction_identifier.hash",
    )?;
    let block = if with_block {
        Some(tip(map, "block_identifier", "block_identifier.index", "block_identifier.hash")?)
    } else {
        None
    };
    let timestamp_ms = if with_block {
        Some(
            field(map, "timestamp", "timestamp")?
                .as_i64()
                .ok_or(Error::MeshResponse { what: "timestamp" })?,
        )
    } else {
        None
    };
    Ok(MeshTransaction {
        hash,
        block,
        timestamp_ms,
        operations: parse_operations(field(map, "operations", "operations")?)?,
        metadata: parse_metadata(map)?,
    })
}

/// `/block`: the block, its parent, its timestamp, every transaction in it,
/// and its own figures ([`BlockMetadata`]).
pub fn parse_block(bytes: &[u8]) -> Result<MeshBlock> {
    let map = envelope(bytes, MAX_HISTORY_RESPONSE_BYTES)?;
    let block = object(field(&map, "block", "block")?, "block")?;
    let identifier = tip(block, "block_identifier", "block_identifier.index", "block_identifier.hash")?;
    let parent = tip(
        block,
        "parent_block_identifier",
        "parent_block_identifier.index",
        "parent_block_identifier.hash",
    )?;
    let timestamp_ms = field(block, "timestamp", "timestamp")?
        .as_i64()
        .ok_or(Error::MeshResponse { what: "timestamp" })?;
    let list = field(block, "transactions", "transactions")?
        .as_array()
        .ok_or(Error::MeshResponse { what: "transactions: array" })?;
    if list.len() > MAX_ROWS {
        return Err(Error::MeshResponse { what: "transactions: too many" });
    }
    let mut transactions = Vec::with_capacity(list.len());
    for t in list {
        transactions.push(parse_transaction(object(t, "transactions[]")?, false)?);
    }
    let metadata = parse_block_metadata(block)?;
    Ok(MeshBlock { block: identifier, parent, timestamp_ms, transactions, metadata })
}

/// The eight keys `getBlock` writes into `block.metadata`.
const BLOCK_METADATA_KEYS: [&str; 8] =
    ["block_size", "difficulty", "fee", "haiku", "nonce", "root", "stime", "tx_count"];

/// The longest haiku this codec copies, applied before copying. The
/// reference implementation expands a nonce into a 256-byte buffer
/// (`bup.c:84`).
pub const MAX_HAIKU_BYTES: usize = 256;

/// `block.metadata`, read only when it carries all eight of
/// [`BLOCK_METADATA_KEYS`]; otherwise `None`, so blocks from a deployment
/// that writes fewer still parse. A present key with a malformed value is
/// refused, naming it.
fn parse_block_metadata(block: &Map<String, Value>) -> Result<Option<BlockMetadata>> {
    let m = match block.get("metadata") {
        None | Some(Value::Null) => return Ok(None),
        Some(v) => object(v, "metadata")?,
    };
    if BLOCK_METADATA_KEYS.iter().any(|k| !m.contains_key(*k)) {
        return Ok(None);
    }
    let narrow = |key: &str, what: &'static str| -> Result<u32> {
        u32::try_from(unsigned(&m[key], what)?).map_err(|_| Error::MeshResponse { what })
    };
    let haiku = string(&m["haiku"], "metadata.haiku")?;
    if haiku.len() > MAX_HAIKU_BYTES {
        return Err(Error::MeshResponse { what: "metadata.haiku: too long" });
    }
    Ok(Some(BlockMetadata {
        block_size: unsigned(&m["block_size"], "metadata.block_size")?,
        difficulty: narrow("difficulty", "metadata.difficulty")?,
        fee: unsigned(&m["fee"], "metadata.fee")?,
        haiku: haiku.to_owned(),
        nonce: hex::decode_prefixed::<HASHLEN>(string(&m["nonce"], "metadata.nonce")?, "metadata.nonce")?,
        root: hex::decode_prefixed::<HASHLEN>(string(&m["root"], "metadata.root")?, "metadata.root")?,
        stime_ms: m["stime"].as_i64().ok_or(Error::MeshResponse { what: "metadata.stime" })?,
        tx_count: narrow("tx_count", "metadata.tx_count")?,
    }))
}

/// `/block/transaction`: the one transaction, without a block identifier of
/// its own.
pub fn parse_block_transaction(bytes: &[u8]) -> Result<MeshTransaction> {
    let map = envelope(bytes, MAX_HISTORY_RESPONSE_BYTES)?;
    let t = object(field(&map, "transaction", "transaction")?, "transaction")?;
    parse_transaction(t, false)
}

/// `/mempool`: the ids of the transactions the node's queue holds, in the
/// queue's order.
///
/// An empty queue is encoded as `null` and read as no transactions. A list
/// longer than the codec's row bound is refused before anything is copied.
pub fn parse_mempool(bytes: &[u8]) -> Result<Vec<[u8; HASHLEN]>> {
    let map = envelope(bytes, MAX_HISTORY_RESPONSE_BYTES)?;
    let list = match field(&map, "transaction_identifiers", "transaction_identifiers")? {
        Value::Null => return Ok(Vec::new()),
        Value::Array(list) => list,
        _ => return Err(Error::MeshResponse { what: "transaction_identifiers: array" }),
    };
    if list.len() > MAX_ROWS {
        return Err(Error::MeshResponse { what: "transaction_identifiers: too many" });
    }
    let mut ids = Vec::with_capacity(list.len());
    for entry in list {
        let entry = object(entry, "transaction_identifiers[]")?;
        ids.push(hex::decode_prefixed::<HASHLEN>(
            string(field(entry, "hash", "transaction_identifiers[].hash")?, "transaction_identifiers[].hash")?,
            "transaction_identifiers[].hash",
        )?);
    }
    Ok(ids)
}

/// `/mempool/transaction`: one transaction from the node's queue, in
/// `/block/transaction`'s shape (status `PENDING`, the source debited net, no
/// change operation). An id the queue no longer holds is answered with code
/// 3, *Transaction not found*.
pub fn parse_mempool_transaction(bytes: &[u8]) -> Result<MeshTransaction> {
    parse_block_transaction(bytes)
}

/// `/search/transactions`: the page, each row carrying its own block and
/// timestamp.
pub fn parse_search(bytes: &[u8]) -> Result<SearchPage> {
    let map = envelope(bytes, MAX_HISTORY_RESPONSE_BYTES)?;
    let list = field(&map, "transactions", "transactions")?
        .as_array()
        .ok_or(Error::MeshResponse { what: "transactions: array" })?;
    if list.len() > MAX_ROWS {
        return Err(Error::MeshResponse { what: "transactions: too many" });
    }
    let mut transactions = Vec::with_capacity(list.len());
    for t in list {
        transactions.push(parse_transaction(object(t, "transactions[]")?, true)?);
    }
    let total_count = unsigned(field(&map, "total_count", "total_count")?, "total_count")?;
    let next_offset = match map.get("next_offset") {
        None | Some(Value::Null) => None,
        Some(v) => Some(unsigned(v, "next_offset")?),
    };
    Ok(SearchPage { transactions, total_count, next_offset })
}
