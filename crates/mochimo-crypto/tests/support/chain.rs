// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! A scriptable chain: a [`Transport`] whose answers are set per tag.
//!
//! Shared by `tests/recon.rs` and `tests/cli.rs` so both use the same fake.
//!
//! Faking at the transport keeps the real codec and `MeshClient` in every
//! test; only the bytes on the wire are scripted.
//!
//! The constants are from the `F-address-widths` fixture (group F): its
//! master seed, account 0, its recorded `account_tag`, and its recorded
//! `wots_address` (the key at position 1).

#![allow(dead_code)]

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;

use mochimo_crypto::account::WotsIndex;
use mochimo_crypto::addr::{Address, Tag};
use mochimo_crypto::consts::{ADDR_TAG_LEN, SEED_LEN};
use mochimo_crypto::keystore::KeyAccess;
use mochimo_crypto::mesh::Transport;
use mochimo_crypto::{derive, recon, Error, Secret};

/// `F-address-widths`' master seed (`group_f_derivation.json`), account 0.
pub const MASTER: [u8; SEED_LEN] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

/// Its recorded `account_tag`.
pub const TAG: Tag = [
    0x05, 0xff, 0x0f, 0x69, 0xd4, 0xc1, 0xcd, 0x68, 0x2e, 0xd3, 0x34, 0x1c, 0x0b, 0x77, 0x73, 0x05,
    0x4b, 0x58, 0x80, 0x0f,
];

/// Its recorded `wots_address` at the extension's `wots_index: 0`, which is
/// position 1 here.
pub const ADDRESS_AT_1: Address = [
    0x05, 0xff, 0x0f, 0x69, 0xd4, 0xc1, 0xcd, 0x68, 0x2e, 0xd3, 0x34, 0x1c, 0x0b, 0x77, 0x73, 0x05,
    0x4b, 0x58, 0x80, 0x0f, 0x25, 0x87, 0x87, 0x8a, 0xd3, 0x4d, 0x29, 0xcf, 0x2e, 0x4b, 0xe4, 0x83,
    0x86, 0xae, 0xc3, 0xa0, 0xc2, 0xa7, 0xea, 0x8c,
];

pub fn master() -> Secret<SEED_LEN> {
    Secret::new(MASTER)
}

/// The tag of a second account: `F-address-widths`' master at index 1.
///
/// `keystore_harness::imported_account()` is the same account as [`TAG`], so
/// a store cannot hold both.
pub fn tag1() -> Tag {
    derive::derive_account_tag(&master(), 1)
}

pub fn access(m: &Secret<SEED_LEN>) -> KeyAccess<'_> {
    KeyAccess::Master(m)
}

/// The address of the derived account's key at `i`, by the restore path's
/// derivation (no store involved).
pub fn addr_at(i: u32) -> Address {
    recon::derived_address_at(&master(), 0, pos(i))
}

pub fn pos(i: u32) -> WotsIndex {
    let mut p = WotsIndex::ZERO;
    for _ in 0..i {
        p = p.advanced().unwrap_or_else(|e| panic!("{e}"));
    }
    p
}

pub fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// What the chain says about one tag.
#[derive(Clone, Copy)]
pub enum ChainState {
    /// The ledger holds the tag at this address with this balance.
    At(Address, u64),
    /// The ledger has no entry: middleware error code 4, "Account not
    /// found".
    Absent,
    /// The node could not be reached.
    Unreachable,
}

/// A `Transport` scripted per tag. Records every request so a test can assert
/// how many round trips a reconciliation cost.
pub struct Chain {
    states: RefCell<BTreeMap<Tag, ChainState>>,
    /// Request count, behind an `Rc` so it stays readable after the client
    /// that owns this chain is consumed.
    calls: Rc<Cell<usize>>,
    /// What `/construction/submit` echoes back, if anything.
    ///
    /// The test supplies the id (from `SignedTransaction::id()` on a dry
    /// run) rather than the fake computing it. `MeshClient::submit` compares
    /// the echo against the id it computed, so a mismatch fails.
    submit_id: RefCell<Option<[u8; 32]>>,
    /// When set, `/construction/submit` fails at the socket instead.
    submit_fails: RefCell<bool>,
    /// When set, `/network/status` fails at the socket instead, as a node that
    /// cannot be reached does.
    tip_fails: RefCell<bool>,
    /// Every body posted to `/construction/submit`, accepted or refused,
    /// behind an `Rc` so it stays readable after `cli::run` consumes the
    /// client. Refused submissions are logged too, since they were still
    /// written to the socket.
    submits: Rc<RefCell<Vec<Vec<u8>>>>,
    /// The tip `/network/status` answers with, when a test scripts one.
    ///
    /// Unset, the endpoint returns the "must only resolve tags" error below.
    /// Set, it answers in the live endpoint's shape
    /// (`fixtures/group_n_mesh_live.json`, `N-network-status`) with a fixed,
    /// unused hash.
    tip: RefCell<Option<u64>>,
    /// What `/account/entitlement` answers, when a test scripts it: an
    /// amount at a block, or HTTP 429. Unset, the endpoint is refused.
    entitlement: RefCell<Option<Entitled>>,
    /// Every `/account/entitlement` request, counted, behind a handle the
    /// test keeps.
    entitlement_calls: Rc<Cell<usize>>,
    /// What `/account/balance`'s v4.1 metadata says per tag, when a test
    /// scripts it. Unset for a tag, the reply carries no metadata.
    staked: RefCell<BTreeMap<Tag, Staked>>,
    /// The tip `/account/balance` answers at, when a test scripts one apart
    /// from `/network/status`'s: a block landing between the two reads.
    balance_tip: RefCell<Option<u64>>,
    /// What `/stats/staking` answers, when a test scripts it.
    staking_stats: RefCell<Option<StakingStatsAnswer>>,
}

/// A scripted `/account/balance` stake answer, in the middleware's
/// stake-metadata shape. The spendable balance is the tag's `/call` balance.
#[derive(Clone, Copy)]
#[allow(dead_code)]
pub enum Staked {
    /// No stake: `staked` "0", read by the node at this block.
    Nothing { block: u64 },
    /// A stake of `staked` committed at `commit`, ending at `expiry`, with
    /// this entitlement, read at `block`.
    Stake { staked: u64, commit: u64, expiry: u64, entitlement: u64, block: u64 },
    /// A middleware with no stake metadata at all.
    Unreported,
    /// No stake, from the middleware's ledger cache read at this block.
    Cached { block: u64 },
    /// A stake of `staked` with this entitlement, read at `block`, whose
    /// reply carries no `stake` object.
    Untermed { staked: u64, entitlement: u64, block: u64 },
    /// No stake, and a disclosed consent of `kind` recorded at `height`.
    Consent { kind: u8, height: u64, block: u64 },
}

/// A scripted `/stats/staking` answer.
#[derive(Clone, Copy)]
#[allow(dead_code)]
pub enum StakingStatsAnswer {
    /// A reply at this tip, with one stake set and ledger totals.
    At { tip: u64 },
    /// HTTP 403.
    Forbidden,
}

/// A scripted `/account/entitlement` answer.
#[derive(Clone, Copy)]
pub enum Entitled {
    /// This many nanoMCM, read at this block.
    Amount(u64, u64),
    /// HTTP 429 with this `Retry-After`.
    RateLimited(Option<u64>),
}

impl Chain {
    /// Script `/account/balance`'s stake metadata for `tag`.
    #[allow(dead_code)]
    pub fn stakes(&self, tag: Tag, answer: Staked) {
        self.staked.borrow_mut().insert(tag, answer);
    }

    /// Answer `/account/balance` at tip `index`, apart from the tip
    /// `/network/status` reports.
    #[allow(dead_code)]
    pub fn balance_at(&self, index: u64) {
        *self.balance_tip.borrow_mut() = Some(index);
    }

    /// Script `/stats/staking`.
    #[allow(dead_code)]
    pub fn reports_staking(&self, answer: StakingStatsAnswer) {
        *self.staking_stats.borrow_mut() = Some(answer);
    }

    /// Script `/account/entitlement`.
    pub fn entitles(&self, answer: Entitled) {
        *self.entitlement.borrow_mut() = Some(answer);
    }

    /// A handle to the entitlement request count that outlives the chain.
    #[allow(dead_code)]
    pub fn entitlement_calls(&self) -> Rc<Cell<usize>> {
        Rc::clone(&self.entitlement_calls)
    }

    pub fn new(states: &[(Tag, ChainState)]) -> Chain {
        Chain {
            states: RefCell::new(states.iter().copied().collect()),
            calls: Rc::new(Cell::new(0)),
            submit_id: RefCell::new(None),
            submit_fails: RefCell::new(false),
            submits: Rc::new(RefCell::new(Vec::new())),
            tip: RefCell::new(None),
            entitlement: RefCell::new(None),
            entitlement_calls: Rc::new(Cell::new(0)),
            tip_fails: RefCell::new(false),
            staked: RefCell::new(BTreeMap::new()),
            balance_tip: RefCell::new(None),
            staking_stats: RefCell::new(None),
        }
    }

    /// A handle to the submit log that outlives the chain. Clone it
    /// before handing the chain to `MeshClient::new`.
    pub fn submit_log(&self) -> Rc<RefCell<Vec<Vec<u8>>>> {
        Rc::clone(&self.submits)
    }

    /// A handle to the request count that outlives the chain. Clone it
    /// before handing the chain to `MeshClient::new`.
    pub fn call_count(&self) -> Rc<Cell<usize>> {
        Rc::clone(&self.calls)
    }

    /// Script the tip `/network/status` reports.
    pub fn set_tip(&self, index: u64) {
        *self.tip.borrow_mut() = Some(index);
    }

    /// Fail the tip read at the socket, as a node that cannot be reached does.
    pub fn refuses_tip(&self) {
        *self.tip_fails.borrow_mut() = true;
    }

    /// Echo `id` from `/construction/submit`.
    pub fn accepts_submit(&self, id: [u8; 32]) {
        *self.submit_id.borrow_mut() = Some(id);
        *self.submit_fails.borrow_mut() = false;
    }

    /// Fail the submit at the socket.
    pub fn refuses_submit(&self) {
        *self.submit_fails.borrow_mut() = true;
    }

    pub fn set(&self, tag: Tag, state: ChainState) {
        self.states.borrow_mut().insert(tag, state);
    }

    /// Funds the destination string the CLI printed, as a user would copy it.
    ///
    /// Accepts only Base58 over a tag and its CRC16, so flow tests fail if
    /// the CLI prints a destination other wallets would not accept. It uses
    /// this crate's own decoder; the known-answer tests in `tests/cli.rs`
    /// check the encoding against recorded values.
    ///
    /// # Errors
    ///
    /// Returns a message if `destination` is not a valid Base58 tag.
    pub fn credit_destination(
        &self,
        destination: &str,
        address: Address,
        balance: u64,
    ) -> Result<Tag, String> {
        let tag = mochimo_crypto::addr::tag_from_base58(destination).map_err(|e| {
            format!(
                "this chain was handed `{destination}` as a destination and refuses it: {e}.\n                   It accepts only Base58 over a tag and its CRC16 -- the form `tx.c:269-271`                  composes and every Mochimo wallet takes. If the CLI printed this string, the                  CLI cannot be funded from its own output."
            )
        })?;
        self.set(tag, ChainState::At(address, balance));
        Ok(tag)
    }

    pub fn calls(&self) -> usize {
        self.calls.get()
    }
}

impl Transport for Chain {
    fn post(&self, path: &str, body: &[u8]) -> mochimo_crypto::Result<Vec<u8>> {
        self.calls.set(self.calls.get() + 1);
        if path == "/construction/submit" {
            self.submits.borrow_mut().push(body.to_vec());
            if *self.submit_fails.borrow() {
                return Err(Error::Transport {
                    op: "write",
                    kind: mochimo_crypto::TransportKind::Io(std::io::ErrorKind::BrokenPipe),
                });
            }
            return match *self.submit_id.borrow() {
                // Bare hex without `0x`, as the live endpoint returns
                // (`fixtures/group_n_mesh_live.json`); `parse_submit` refuses
                // a prefixed id.
                Some(id) => Ok(
                    format!(r#"{{"transaction_identifier":{{"hash":"{}"}}}}"#, hexs(&id))
                        .into_bytes(),
                ),
                None => Err(Error::MeshResponse {
                    what: "test: this chain was not told to accept a submission",
                }),
            };
        }
        if path == "/account/entitlement" {
            self.entitlement_calls.set(self.entitlement_calls.get() + 1);
            let req: serde_json::Value = serde_json::from_slice(body).map_err(|_| Error::MeshResponse { what: "test: request" })?;
            let address = req["account_identifier"]["address"].as_str().unwrap_or("").to_owned();
            return match *self.entitlement.borrow() {
                Some(Entitled::Amount(amount, block)) => Ok(format!(
                    r#"{{"block_identifier":{{"index":{block},"hash":"0x{}"}},"account_identifier":{{"address":"{address}"}},"entitlement":{{"value":"{amount}","currency":{{"symbol":"MCM","decimals":9}}}}}}"#,
                    "cd".repeat(32)
                )
                .into_bytes()),
                Some(Entitled::RateLimited(retry_after_secs)) => Err(Error::RateLimited { retry_after_secs }),
                None => Err(Error::MeshResponse {
                    what: "test: this chain was not told to answer /account/entitlement",
                }),
            };
        }
        if path == "/account/balance" {
            let req: serde_json::Value = serde_json::from_slice(body).map_err(|_| Error::MeshResponse { what: "test: request" })?;
            let asked = req["account_identifier"]["address"].as_str().unwrap_or("").to_owned();
            let raw: [u8; ADDR_TAG_LEN] = mochimo_crypto::mesh::hex::decode_prefixed(&asked, "test tag")?;
            let spendable = match self.states.borrow().get(&raw).copied() {
                Some(ChainState::At(_, balance)) => balance,
                Some(ChainState::Unreachable) => {
                    return Err(Error::Transport {
                        op: "connect",
                        kind: mochimo_crypto::TransportKind::Io(std::io::ErrorKind::ConnectionRefused),
                    })
                }
                Some(ChainState::Absent) | None => 0,
            };
            let staked_state = self.staked.borrow().get(&raw).copied();
            let tip = self.balance_tip.borrow().or(*self.tip.borrow()).unwrap_or(0);
            let head = format!(
                r#""block_identifier":{{"index":{tip},"hash":"0x{}"}},"balances":[{{"value":"{spendable}","currency":{{"symbol":"MCM","decimals":9}}}}]"#,
                "ef".repeat(32)
            );
            let meta = match staked_state {
                None | Some(Staked::Unreported) => String::new(),
                Some(Staked::Nothing { block }) => format!(
                    r#","metadata":{{"spendable":"{spendable}","staked":"0","stake_source":"node","stake_block_index":{block}}}"#
                ),
                Some(Staked::Cached { block }) => format!(
                    r#","metadata":{{"spendable":"{spendable}","staked":"0","stake_source":"ledger_cache","stake_block_index":{block}}}"#
                ),
                Some(Staked::Untermed { staked, entitlement, block }) => format!(
                    r#","metadata":{{"spendable":"{spendable}","staked":"{staked}","stake_source":"node","stake_block_index":{block},"entitlement":"{entitlement}"}}"#
                ),
                Some(Staked::Consent { kind, height, block }) => format!(
                    r#","metadata":{{"spendable":"{spendable}","staked":"0","stake_source":"node","stake_block_index":{block},"consent":{{"kind":{kind},"height":{height},"lapses_at":{},"live":{},"digest":"0x{}"}}}}"#,
                    height + 65_536,
                    tip < height + 65_536,
                    "cd".repeat(16)
                ),
                Some(Staked::Stake { staked, commit, expiry, entitlement, block }) => {
                    let tier = mochimo_crypto::staking::tier_of(commit, expiry);
                    let tier_fields = match tier {
                        Some(k) => format!(
                            r#","tier":{k},"coefficient":{},"weight":"{}""#,
                            u64::from(k) + 1,
                            u128::from(staked + entitlement) * (u128::from(k) + 1)
                        ),
                        None => String::new(),
                    };
                    format!(
                        r#","metadata":{{"spendable":"{spendable}","staked":"{staked}","stake_source":"node","stake_block_index":{block},"entitlement":"{entitlement}","total":"{}","stake":{{"commit":{commit},"expiry":{expiry},"locked":{}{tier_fields}}}}}"#,
                        spendable + staked + entitlement,
                        tip + 1 < expiry
                    )
                }
            };
            if spendable == 0 && !matches!(staked_state, Some(Staked::Stake { .. } | Staked::Untermed { .. })) {
                return Ok(br#"{"code":4,"message":"Account not found","retriable":false}"#.to_vec());
            }
            return Ok(format!("{{{head}{meta}}}").into_bytes());
        }
        if path == "/stats/staking" {
            return match *self.staking_stats.borrow() {
                Some(StakingStatsAnswer::At { tip }) => Ok(format!(
                    r#"{{"block_identifier":{{"index":{tip},"hash":"0x{h}"}},"v41_trigger":1136384,"v41_active":true,"min_stake":{{"value":"500000000000","currency":{{"symbol":"MCM","decimals":9}}}},"stake_set":{{"block_identifier":{{"index":{tip},"hash":"0x{h}"}},"count":2,"pool":{{"value":"2500000000","currency":{{"symbol":"MCM","decimals":9}}}},"forfeit":{{"value":"0","currency":{{"symbol":"MCM","decimals":9}}}},"dust":{{"value":"1","currency":{{"symbol":"MCM","decimals":9}}}},"weight":"3600000000000"}},"ledger":{{"block_index":{tip},"last_updated":"2026-11-01T12:00:00Z","stakers":2,"staked":{{"value":"1200000000000","currency":{{"symbol":"MCM","decimals":9}}}},"weight":"3600000000000"}}}}"#,
                    h = "aa".repeat(32)
                )
                .into_bytes()),
                Some(StakingStatsAnswer::Forbidden) => Err(Error::HttpStatus { status: 403 }),
                None => Err(Error::MeshResponse {
                    what: "test: this chain was not told to answer /stats/staking",
                }),
            };
        }
        if path == "/network/status" {
            if *self.tip_fails.borrow() {
                return Err(Error::Transport {
                    op: "connect",
                    kind: mochimo_crypto::TransportKind::Io(std::io::ErrorKind::ConnectionRefused),
                });
            }
            if let Some(index) = *self.tip.borrow() {
                return Ok(format!(
                    r#"{{"current_block_identifier":{{"index":{index},"hash":"0x{}"}},"sync_status":{{"stage":"synchronized","synced":true}}}}"#,
                    "ab".repeat(32)
                )
                .into_bytes());
            }
        }
        if path != "/call" {
            return Err(Error::MeshResponse {
                what: "test: reconciliation must only resolve tags",
            });
        }
        // Read the tag back from the request the real codec built.
        let req: serde_json::Value = serde_json::from_slice(body).map_err(|_| Error::MeshResponse {
            what: "test: request",
        })?;
        let asked = req["parameters"]["tag"].as_str().ok_or(Error::MeshResponse {
            what: "test: parameters.tag",
        })?;
        // `request_tag_resolve` sends the tag 0x-prefixed.
        let raw: [u8; ADDR_TAG_LEN] = mochimo_crypto::mesh::hex::decode_prefixed(asked, "test tag")?;
        let tag: Tag = raw;
        match self.states.borrow().get(&tag).copied() {
            Some(ChainState::At(address, balance)) => Ok(format!(
                r#"{{"result":{{"address":"0x{}","amount":{}}},"idempotent":true}}"#,
                hexs(&address),
                balance
            )
            .into_bytes()),
            Some(ChainState::Absent) | None => {
                Ok(br#"{"code":4,"message":"Account not found","retriable":false}"#.to_vec())
            }
            Some(ChainState::Unreachable) => Err(Error::Transport {
                op: "connect",
                kind: mochimo_crypto::TransportKind::Io(std::io::ErrorKind::ConnectionRefused),
            }),
        }
    }
}
