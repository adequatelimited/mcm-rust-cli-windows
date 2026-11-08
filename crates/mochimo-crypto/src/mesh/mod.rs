// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! The Mesh API client: what the wallet reads from the network and what it
//! sends. The Mesh middleware is a source of observations, never an
//! authority. The behaviour described below was captured from
//! `api.mochimo.org` into `fixtures/group_n_mesh_live.json` (one server at
//! one block).
//!
//! # What is verified here
//!
//! Request bodies are built from typed values ([`codec`]) and are byte-equal
//! to the recorded requests the server accepted. Response bodies are parsed
//! by hand, with every field's presence, type, width and range checked; the
//! address the ledger returns must begin with the tag asked for. Before
//! anything is reserved, the chain's current address for a tag must equal
//! the address of the key this keystore would sign with next
//! ([`spend::SpendPlan::new`]). Every parser is total over truncations and
//! byte flips of every captured body (`tests/mesh.rs`): a malformed reply is
//! an error, never a panic.
//!
//! # What a 200 from `submit` means
//!
//! Only that the bytes left the process. The middleware writes the
//! transaction to a set of nodes and returns as soon as one write completes,
//! without reading a reply or validating it. The `hash` in the reply is
//! computed by the middleware from the bytes it received, so
//! [`MeshClient::submit`] refuses a reply whose hash is not the id of the
//! bytes sent. Acceptance can be learned only by observing the chain, which
//! is reconciliation's job.
//!
//! # Checks only the node can make
//!
//! Offline, this crate checks a transaction's layout, `mdst_val` and
//! `tx_val__wots`. The node's `tx_val` ledger checks (exact balance
//! equality, the block-to-live window, the source/change relation as the
//! ledger sees it) run only on a node with an open ledger and are not
//! covered by any fixture or test. A transaction can pass every check here
//! and still be rejected by the node for a ledger reason.
//!
//! # What this module does not do
//!
//! It does not reconcile, settle (`persist_settled` is never called from
//! here), decide expiry, or re-sign.

use core::fmt;

use crate::addr::{Address, Tag};
use crate::consts::HASHLEN;
use crate::error::{Error, Result};

pub mod codec;
pub mod hex;
#[cfg(feature = "mesh-http")]
pub mod http;
pub mod spend;

pub use spend::{SignedTransaction, SpendPlan};

/// The middleware's request-body cap (`http.MaxBytesReader(w, r.Body,
/// 30*1024)`), enforced here too so an oversize body is a named refusal
/// rather than a dropped connection. A 256-destination signed transaction
/// (13,628 bytes, 27,256 hex characters plus the envelope) fits.
pub const MAX_REQUEST_BYTES: usize = 30 * 1024;
/// The response-body cap for every endpoint except the history endpoints.
///
/// These replies are a few hundred bytes (the widest recorded is under
/// 1 KiB). The cap stays small because it bounds an allocation whose size a
/// remote server chooses.
pub const MAX_RECON_RESPONSE_BYTES: usize = 8 * 1024;
/// The response-body cap for `/block`, `/search/transactions`, `/mempool`
/// and `/mempool/transaction`, whose replies scale with what they report.
///
/// 256 KiB holds about 214 of the widest recorded search rows (a full
/// `--count 100` page fits), 256 of the widest recorded block transactions,
/// or about 3,400 mempool ids. A block of several transactions that each pay
/// hundreds of destinations exceeds it and is refused by size.
pub const MAX_HISTORY_RESPONSE_BYTES: usize = 256 * 1024;

/// The response cap for `path`. Unknown paths get the tight cap.
#[must_use]
pub fn max_response_bytes(path: &str) -> usize {
    match path {
        "/block" | "/search/transactions" | "/mempool" | "/mempool/transaction" => MAX_HISTORY_RESPONSE_BYTES,
        _ => MAX_RECON_RESPONSE_BYTES,
    }
}

/// How bytes reach the middleware. `path` is the endpoint (`"/call"`), `body`
/// an already-serialised JSON request; the return is the body of a 200
/// response, at most [`max_response_bytes`] for that path. Not sealed, so
/// tests can supply recorded bodies; it never handles key material.
pub trait Transport {
    fn post(&self, path: &str, body: &[u8]) -> Result<Vec<u8>>;
}

/// A block the middleware named: index and hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainTip {
    pub index: u64,
    pub hash: [u8; HASHLEN],
}

/// What `/call tag_resolve` returns: the ledger's current entry for a tag,
/// the full 40-byte address (tag half, then current hash half) and the
/// balance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LedgerEntry {
    pub address: Address,
    /// nanoMochimo.
    pub balance: u64,
}

/// What `/account/balance` returns: the balance and the block the middleware
/// had cached when it answered. This endpoint does not return the address,
/// so [`LedgerEntry`] comes from `/call` instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BalanceAt {
    /// nanoMochimo.
    pub balance: u64,
    pub tip: ChainTip,
}

/// A transaction id: `TX_HASH_ID` with the nonce zero.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TxId(pub [u8; HASHLEN]);

/// What `/account/entitlement` answered: the tag's reward entitlement in
/// nanoMochimo and the block the middleware read it at. The middleware
/// serves a cached ledger, so the figure can be a block or more behind the
/// tip; entitlement only grows between claims, so a stale figure is never
/// above the ledger's own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntitlementAt {
    /// nanoMochimo.
    pub entitlement: u64,
    pub tip: ChainTip,
}

impl fmt::Debug for TxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TxId({})", hex::encode(&self.0))
    }
}

/// The Mesh client over one transport.
#[derive(Debug)]
pub struct MeshClient<T: Transport> {
    transport: T,
}

impl<T: Transport> MeshClient<T> {
    pub fn new(transport: T) -> MeshClient<T> {
        MeshClient { transport }
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// `POST /network/status`: the current block.
    pub fn network_status(&self) -> Result<ChainTip> {
        let reply = self.transport.post("/network/status", &codec::request_network_status())?;
        codec::parse_network_status(&reply)
    }

    /// The same `POST /network/status`, read for a page that shows the
    /// node: the tip, when it was solved, the genesis block and the
    /// middleware's sync state ([`codec::parse_network_status_full`]). The
    /// sync state is the middleware's view of its own node, not of the
    /// network; see [`codec::SyncStatus`].
    pub fn network_status_full(&self) -> Result<codec::NetworkStatus> {
        let reply = self.transport.post("/network/status", &codec::request_network_status())?;
        codec::parse_network_status_full(&reply)
    }

    /// `POST /network/list`: every network the middleware serves.
    pub fn networks(&self) -> Result<Vec<codec::NetworkIdentifier>> {
        let reply = self.transport.post("/network/list", &codec::request_network_list())?;
        codec::parse_network_identifiers(&reply)
    }

    /// `POST /call tag_resolve`: the ledger's current entry for `tag`. An
    /// unknown tag is [`Error::Mesh`] with the middleware's code 4.
    pub fn resolve_tag(&self, tag: &Tag) -> Result<LedgerEntry> {
        let reply = self.transport.post("/call", &codec::request_tag_resolve(tag))?;
        codec::parse_tag_resolve(&reply, tag)
    }

    /// `POST /account/entitlement`: the reward entitlement the ledger holds
    /// for `tag`, which no other endpoint reports. The middleware answers
    /// once per client address per ten seconds; a request inside that window
    /// is [`Error::RateLimited`] and is not retried.
    pub fn account_entitlement(&self, tag: &Tag) -> Result<EntitlementAt> {
        let reply = self.transport.post("/account/entitlement", &codec::request_account_entitlement(tag))?;
        codec::parse_account_entitlement(&reply, tag)
    }

    /// `POST /account/balance` for `tag`.
    pub fn balance(&self, tag: &Tag) -> Result<BalanceAt> {
        let reply = self.transport.post("/account/balance", &codec::request_account_balance(tag))?;
        codec::parse_account_balance(&reply)
    }

    /// `POST /account/balance` read for its v4.1 stake fields: the spendable
    /// balance, and the stake, its lock and the stake's entitlement as the
    /// middleware's metadata reports them ([`codec::parse_account_stake`]).
    pub fn account_stake(&self, tag: &Tag) -> Result<codec::StakeAt> {
        let reply = self.transport.post("/account/balance", &codec::request_account_balance(tag))?;
        codec::parse_account_stake(&reply)
    }

    /// `POST /stats/staking`: the network's staking summary
    /// ([`codec::parse_staking_stats`]). A deployment that blocks the endpoint
    /// answers with an HTTP error, returned as [`Error::HttpStatus`].
    pub fn staking_stats(&self) -> Result<codec::StakingStats> {
        let reply = self.transport.post("/stats/staking", &codec::request_staking_stats())?;
        codec::parse_staking_stats(&reply)
    }

    /// `POST /block` by index: the block and every transaction in it.
    ///
    /// Index 0 means the current block, not genesis; callers that mean a
    /// specific block refuse 0 before calling this.
    pub fn block_by_index(&self, index: u64) -> Result<codec::MeshBlock> {
        let reply = self.transport.post("/block", &codec::request_block_by_index(index))?;
        codec::parse_block(&reply)
    }

    /// `POST /block` by hash. The middleware reads a hash from its own
    /// archive folder, so a not-found here is about that deployment's
    /// archive rather than about the chain.
    pub fn block_by_hash(&self, hash: &[u8; HASHLEN]) -> Result<codec::MeshBlock> {
        let reply = self.transport.post("/block", &codec::request_block_by_hash(hash))?;
        codec::parse_block(&reply)
    }

    /// `POST /search/transactions` by transaction hash: the indexer's own
    /// rendering of one transaction, which differs from `/block`'s and is
    /// not reconciled with it (see [`codec::MeshTransaction::metadata`]).
    ///
    /// Served only where the deployment set `EnableIndexer`; where it did
    /// not, the handler answers an internal error rather than an empty page.
    pub fn search_by_hash(&self, hash: &[u8; HASHLEN]) -> Result<codec::SearchPage> {
        let reply = self.transport.post("/search/transactions", &codec::request_search_by_hash(hash))?;
        codec::parse_search(&reply)
    }

    /// `POST /search/transactions` by account tag, newest first,
    /// at most `limit` rows.
    ///
    /// `limit` must be in `1..=100`; outside that range the middleware
    /// silently uses its default of 10. The command line refuses other counts
    /// before calling this.
    pub fn search_by_account(&self, tag: &Tag, limit: u64) -> Result<codec::SearchPage> {
        let reply = self
            .transport
            .post("/search/transactions", &codec::request_search_by_account(tag, limit))?;
        codec::parse_search(&reply)
    }

    /// [`Self::search_by_account`] from the `offset`-th newest row on: the
    /// rows below the newest `offset`, at most `limit` of them. A page's
    /// [`codec::SearchPage::next_offset`] is the `offset` of the page after
    /// it.
    ///
    /// `limit` must be in `1..=100` as above, and `offset` in `0..=i64::MAX`;
    /// a larger offset does not decode and the middleware answers code 1.
    /// New rows arrive at the newest end, so a later page may repeat rows but
    /// never skips any.
    pub fn search_by_account_from(&self, tag: &Tag, limit: u64, offset: u64) -> Result<codec::SearchPage> {
        let reply = self.transport.post(
            "/search/transactions",
            &codec::request_search_by_account_from(tag, limit, offset),
        )?;
        codec::parse_search(&reply)
    }

    /// `POST /mempool`: the ids of every transaction the node's queue holds,
    /// in the queue's order.
    ///
    /// The middleware reads the queue from its local node's files, so a
    /// deployment without a local node answers code 2 (internal error). The
    /// list is that node's view, not the network's.
    pub fn mempool(&self) -> Result<Vec<[u8; HASHLEN]>> {
        let reply = self.transport.post("/mempool", &codec::request_mempool())?;
        codec::parse_mempool(&reply)
    }

    /// `POST /mempool/transaction`: one transaction from the node's queue,
    /// as `/block` renders one. An id the queue no longer holds is
    /// [`Error::Mesh`] with code 3, *Transaction not found*: it has been
    /// mined since the list was read, or dropped.
    pub fn mempool_transaction(&self, id: &[u8; HASHLEN]) -> Result<codec::MeshTransaction> {
        let reply = self.transport.post("/mempool/transaction", &codec::request_mempool_transaction(id))?;
        codec::parse_mempool_transaction(&reply)
    }

    /// `POST /construction/submit` with the whole wire image. `Ok` means the
    /// middleware wrote the bytes to a node's socket and echoed their id;
    /// see the module doc for what that does and does not establish. A reply
    /// naming any other id is [`Error::SubmitIdMismatch`].
    pub fn submit(&self, signed: &SignedTransaction) -> Result<TxId> {
        self.submit_wire(&signed.wire(), signed.id())
    }

    /// The same `POST /construction/submit` over a wire image the caller
    /// already holds (such as the retry artifact `send` printed), with the id
    /// the caller computed for it, which the echo must match. The bytes are
    /// not validated here; the node validates them.
    pub fn submit_wire(&self, wire: &[u8], id: TxId) -> Result<TxId> {
        let body = codec::request_submit_wire(wire)?;
        let reply = self.transport.post("/construction/submit", &body)?;
        let echoed = codec::parse_submit(&reply)?;
        if echoed != id {
            return Err(Error::SubmitIdMismatch);
        }
        Ok(echoed)
    }
}
