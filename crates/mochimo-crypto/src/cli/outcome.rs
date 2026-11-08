// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! What a command decided, separate from the words that report it.
//!
//! Each [`Outcome`] variant carries what the command established, in the
//! types the layers below already use ([`Settlement`], [`RestoreFailure`],
//! [`AccountStatus`], [`Divergence`], [`Error`]), so a caller can match on a
//! decision rather than on rendered text. The sibling `render` module turns
//! an outcome into a [`Report`](super::Report) and chooses the exit code;
//! nothing here knows about exit codes.
//!
//! [`super::run`] returns a [`Report`](super::Report) built this way.

use crate::account::WotsIndex;
use crate::mesh::spend::SpendPlan;
use crate::mesh::{codec, ChainTip, TxId};
use crate::tx::wire::Destination;
use crate::addr::{Address, Tag};
use crate::recon::{AccountStatus, Divergence, RestoreFailure, RestoredAccount};
use crate::wallet::{Settlement, StartupRefusal};
use crate::Error;

use super::address::Held;
use super::discover::Sweep;
use super::args::Command;
use super::reconcile::Reviewed;

/// One account's line in a listing, as the store holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountLine {
    pub tag: Tag,
    pub status: AccountStatus,
}

/// What the store said about its own format version: `Some(from)` when this
/// invocation rewrote an older version in place.
///
/// A version-3 store is re-sealed as version 4 by its first commit, after
/// which older builds can no longer read it, so the command that made the
/// change reports it. `None` for every store that was not rewritten under
/// this handle, including any store opened only by a read-only command.
///
/// Read while the store is open, since the renderer does not hold it.
pub type Upgraded = Option<u16>;

/// A spend that was signed and written to the socket, and what the socket
/// said.
///
/// `submitted` is not a verdict on the transaction: `/construction/submit`
/// writes to a node and returns before any reply, so `Ok` means only that
/// the bytes were written and the middleware echoed their id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shipped {
    pub source: Tag,
    /// In wire order, which is sorted and may differ from the order the
    /// operator typed.
    pub destinations: Vec<Destination>,
    pub blk_to_live: u64,
    /// The signed image, as it left the builder. The retry artifact is this.
    pub wire: Vec<u8>,
    pub submitted: core::result::Result<TxId, Error>,
}

/// A validator transaction as it left the builder, and what the socket said.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorShipped {
    /// The validator's cold tag.
    pub source: Tag,
    pub op: crate::mesh::spend::ValidatorOp,
    pub fee_total: u64,
    pub change_total: u64,
    pub blk_to_live: u64,
    /// The signed image. The retry artifact is this.
    pub wire: Vec<u8>,
    pub submitted: core::result::Result<TxId, Error>,
}

/// A dust-proof transaction as it left the builder -- a stake, an unstake,
/// a consent or its revoke, or from v4.1 a claim or delegate change -- and
/// what the socket said.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StakingShipped {
    pub source: Tag,
    pub op: crate::mesh::spend::DustProofOp,
    pub fee_total: u64,
    /// The signed image. The retry artifact is this.
    pub wire: Vec<u8>,
    pub submitted: core::result::Result<TxId, Error>,
    /// `--resign` reproduced the reserved transaction rather than reserving.
    pub resigned: bool,
}

/// What a staking page states beside the transaction: the observations the
/// checks were made against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StakingContext {
    pub network: crate::staking::Network,
    /// The height the wallet expects the transaction in: the tip plus one.
    pub height: u64,
    /// The spendable balance the fee comes from.
    pub spendable: u64,
    /// The stake as `/account/balance` reported it, when it was read.
    pub stake: Option<crate::mesh::codec::StakeFields>,
    /// The entitlement the checks used, and where it came from.
    pub entitlement: Option<crate::entitlement::Entitlement>,
}

/// Why a staking command signed nothing. Every arm is a check made before
/// the one-time key is reserved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StakingRefusal {
    /// The tip does not run the v4.1 rules. The node checks a new
    /// transaction against the tip, so the tip must be above the trigger.
    NotActive { height: u64, t41: u64 },
    /// The chain tip could not be read, so neither the minimum stake nor the
    /// lock can be computed.
    TipUnreadable(Error),
    /// `/account/balance` could not be read, or carried no stake fields.
    StakeUnreadable(Error),
    /// The middleware reports no stake fields for this tag: it predates
    /// v4.1, or its stake source is unavailable.
    StakeUnreported,
    /// The stake fields come from the middleware's ledger cache, read at
    /// `block`, not from the node.
    StakeFieldsCached { block: u64 },
    /// The tag stakes, but the reply carries no commit and expiry heights.
    StakeTermsUnreported,
    /// The reported commit, expiry, tier and lock state do not agree with
    /// each other or with the height.
    StakeTermsInconsistent { commit: u64, expiry: u64 },
    /// `/call tag_resolve` could not be read, for a verb that needs only the
    /// spendable balance.
    BalanceUnreadable(Error),
    /// The entitlement could not be read.
    EntitlementUnreadable(Error),
    /// A stake below `minstake(h)`.
    BelowMinimum { amount: u64, minimum: u64, height: u64 },
    /// `amount + fee` above the spendable balance.
    StakeNotCovered { amount: u64, fee: u64, spendable: u64 },
    /// `amount + fee` would leave less than one fee spendable, and a tag
    /// with nothing spendable is one the Mesh's tag resolution drops.
    StakeLeavesTooLittle { amount: u64, fee: u64, spendable: u64 },
    /// No top-ups: a stake exists already.
    AlreadyStaked { staked: u64 },
    /// A stake with unclaimed entitlement binds nothing.
    EntitlementUnclaimed { entitlement: u64 },
    /// Nothing is staked.
    NotStaked,
    /// The stake has ended by the node's report, and the operator passed
    /// neither `--forfeit` nor `--lock-ends` with the expiry the node reports.
    LockEndNotConfirmed { expiry: u64, given: Option<u64> },
    /// A stake from a tag holding a live consent is refused by the node.
    LiveConsent { kind: u8, lapses_at: u64 },
    /// The middleware does not disclose consents, and the operator did not
    /// pass `--no-live-consent`.
    ConsentUnknown,
    /// A consent from a tag holding unclaimed entitlement binds nothing.
    ConsentEntitlementUnclaimed { entitlement: u64 },
    /// A stake with a block to live from a tag whose consent the reply does
    /// not show.
    ExpiryWithUnknownConsent { blk_to_live: u64 },
    /// A consent from a tag the node reports as not staking, without
    /// `--not-staked` or `--forfeit`.
    NotStakedUnconfirmed,
    /// The stake is locked and the operator did not pass `--forfeit`.
    LockedNeedsForfeit {
        expiry: u64,
        height: u64,
        entitlement: Option<u64>,
    },
    /// A claim while locked releases nothing.
    ClaimWhileLocked { expiry: u64, height: u64 },
    /// No entitlement to claim.
    NothingToClaim,
    /// A consent from a tag whose expired stake still has entitlement binds
    /// nothing: claim first, which unstakes.
    ExpiredStakeWithEntitlement { entitlement: u64 },
    /// `balance + released` below the fee.
    FeeNotCovered { fee: u64, available: u64 },
    /// A consent of a delegate kind is signed by a delegate key, which needs
    /// `--unbound-delegate`.
    DelegateKeyNeedsFlag { kind: u8 },
    /// The consent's terms are not ones the node's designations can match.
    BadTerms(Error),
}

/// `stake-info`: the per-account view and the network view, each with what
/// failed in its place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StakeInfoPage {
    pub network: crate::staking::Network,
    pub tip: core::result::Result<ChainTip, Error>,
    /// `Some` when a tag was named.
    pub account: Option<(Tag, core::result::Result<crate::mesh::codec::StakeAt, Error>)>,
    /// `/account/entitlement`, asked only for a named tag with no stake.
    pub entitlement: Option<core::result::Result<crate::entitlement::Entitlement, Error>>,
    pub stats: core::result::Result<crate::mesh::codec::StakingStats, Error>,
}

/// A command, decided: what it established, and the accounts reconciliation
/// could not explain while it ran. The divergences are carried as values so
/// a caller can render them as it chooses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decided {
    /// Accounts `Wallet::open` could not reconcile. Empty for every command
    /// that runs before the gate, which have no wallet to ask.
    pub standing: Vec<Divergence>,
    pub outcome: Outcome,
}

/// One transaction of the node's queue, as `mempool` lists it: its id, and
/// what `/mempool/transaction` answered for it, or `None` when the queue no
/// longer held it by the time it was asked for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MempoolRow {
    pub id: [u8; crate::consts::HASHLEN],
    pub transaction: Option<Box<codec::MeshTransaction>>,
}

/// What a command established. The sibling `render` module is the only thing
/// in this crate that turns one into words.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    // ---- the store, read ------------------------------------------------
    /// Every account and what reconciliation made of it.
    Balance { accounts: Vec<AccountLine> },
    /// Every account the store holds, from records alone.
    Accounts { held: Vec<Held> },
    /// One stored account's destination and current ledger address.
    Address {
        tag: Tag,
        address: Address,
        index: WotsIndex,
    },
    /// An account derived from the master and deliberately not stored.
    UnstoredAddress {
        account: u32,
        tag: Tag,
        address: Address,
    },

    // ---- the store, written ---------------------------------------------
    /// `restore` found the index on the chain.
    Restored {
        account: u32,
        found: RestoredAccount,
        /// `Some(stored)` when the store already held the tag at `stored` and
        /// nothing was written.
        held_at: Option<WotsIndex>,
        upgraded: Upgraded,
    },
    /// `settle` asked the chain what became of a reservation.
    Settled {
        settlement: Settlement,
        upgraded: Upgraded,
    },
    /// A spend laid out and not signed, for a caller that shows the plan
    /// before signing. Built with [`Outcome::planned`]; no command-line verb
    /// produces it, since `send` signs what it plans.
    Planned {
        source: Tag,
        /// In the order that goes on the wire, as [`SpendPlan::dsts`] holds
        /// them.
        destinations: Vec<Destination>,
        send_total: u64,
        fee_total: u64,
        change_total: u64,
        blk_to_live: u64,
    },
    /// `send` planned, reserved, signed and wrote.
    Sent {
        shipped: Shipped,
        send_total: u64,
        fee_total: u64,
        change_total: u64,
        upgraded: Upgraded,
    },
    /// `resign` reproduced the reserved artifact and wrote it.
    Resigned { shipped: Shipped },
    /// `submit` wrote an artifact it was handed, having opened no store.
    Submitted {
        source: Tag,
        /// The image as it was given, after the layout check.
        bytes: Vec<u8>,
        submitted: core::result::Result<TxId, Error>,
    },

    // ---- one account, and the whole store, reconciled now ---------------
    /// `status` compared one account against the chain and got an answer.
    Status { tag: Tag, status: AccountStatus },
    /// `status` found a divergence. This answers the question rather than
    /// refusing the command, so it exits 0 with the same report a refusal
    /// prints.
    StatusDiverged { tag: Tag, divergence: Box<Divergence> },
    /// `status` could not ask the question at all.
    StatusRefused { divergence: Box<Divergence> },
    /// `reconcile` reported the store and acted, or declined to. `to` is the
    /// index named with `--advance-to` or `--rollback-to`.
    Reconciled {
        tag: Tag,
        to: u32,
        reviewed: Reviewed,
        upgraded: Upgraded,
    },
    /// `discover` asked the node about a range of derived indices.
    Discovered { sweep: Sweep },
    /// `discover` on a store with no master to derive from.
    DiscoverNeedsMaster,
    /// `discover` stopped part-way. No extent is reported for indices it never
    /// asked about, so a partial sweep is not mistaken for a complete one.
    SweepStopped {
        account: u32,
        searched: u32,
        to: u32,
        cause: Error,
    },

    // ---- the artifact refusals, before any socket -----------------------
    ArtifactNotHex { cause: Error },
    ArtifactNotATransaction { cause: Error },
    /// The bytes given are not one whole transaction image, so what reached
    /// the socket would not be what the operator holds.
    ArtifactNotWhole { given: usize, described: usize },

    // ---- the node, read -------------------------------------------------
    /// One transaction from the indexer.
    LookedUpTransaction { page: Box<codec::SearchPage> },
    /// The indexer holds no transaction with that hash, which does not prove
    /// none exists.
    TransactionNotFound { hash: [u8; crate::consts::HASHLEN] },
    /// The indexer's rows for one tag, the `from` newest skipped.
    RecentTransactions {
        tag: Tag,
        from: u64,
        page: Box<codec::SearchPage>,
    },
    /// One block.
    Block { block: Box<codec::MeshBlock> },
    /// A block that was not served. `by_hash` because a hash lookup reaches
    /// the deployment's archive rather than the chain, and the page says so.
    BlockNotServed { by_hash: bool, cause: Error },
    /// The newest blocks, walked down from the tip.
    Blocks {
        count: u64,
        tip: ChainTip,
        rows: Vec<codec::MeshBlock>,
    },
    /// The walk stopped: the tip was read and one block below it was not.
    BlocksStopped { index: u64, cause: Error },
    /// The node's queue: how many transactions it holds, and the first
    /// `count` of them read whole.
    Mempool {
        count: u64,
        total: usize,
        rows: Vec<MempoolRow>,
    },
    /// The queue's ids were read and one transaction in it was not, for a
    /// reason other than its having left the queue.
    MempoolStopped { id: [u8; crate::consts::HASHLEN], cause: Error },
    /// The node could not be asked at all.
    ExplorerFailed { cause: Error },
    /// The node's index could not be searched: `/search/transactions`
    /// refused, or the node could not be asked. Apart from
    /// [`Outcome::ExplorerFailed`] because what the middleware answers there
    /// says whether the node runs an indexer at all.
    SearchFailed { cause: Error },
    /// `resign` reproduced the artifact and stopped before submitting,
    /// because the source tag would not render.
    ///
    /// The reproduction is still rendered, since it may be the only copy of
    /// the bytes that can move those funds; the refusal is appended to it.
    ReproducedButUnrenderable {
        source: Tag,
        destinations: Vec<Destination>,
        blk_to_live: u64,
        wire: Vec<u8>,
        cause: Error,
    },
    /// `resign` rebuilt the plan and it is not the one the store reserved.
    NotTheReservedSpend,
    /// `resign` on a reservation the chain has already moved past: there is
    /// nothing left to reproduce, and `settle` is the verb.
    ReservationAlreadyLanded {
        source: Tag,
        spent_index: u32,
        settled_index: u32,
    },

    // ---- refusals that carry a shape ------------------------------------
    /// `restore` was asked for without a master seed to derive from.
    RestoreNeedsMaster,
    /// The scan ran and refused. Its `Display` is the refusal, to which
    /// `restore` appends the remedy.
    RestoreRefused { account: u32, failure: RestoreFailure },
    /// A tag this store does not hold, named by a command that needs one.
    NoSuchAccount { tag: Tag },
    /// The same state reached through `address`, which also names the two
    /// verbs that would put the account in the store.
    NoAccountToAddress { tag: Tag },
    /// A derivation was asked of a store whose accounts are all imported.
    NoMasterSeed,
    /// `address --account N` for an account the store already holds: the
    /// answer is the stored one, and position 0 is not it.
    AccountAlreadyStored {
        account: u32,
        tag: Tag,
        index: WotsIndex,
    },
    /// Reconciliation refused this account.
    Diverged(Box<Divergence>),
    /// A tag whose destination could not be rendered at all.
    CannotRender { tag: Tag, cause: Error },
    /// Any other refusal from the layers below, as their own [`Error`], with
    /// nothing added by this command.
    Failed(Error),

    // ---- the wallet never opened ----------------------------------------
    /// The store would not give up its master seed, so nothing could run.
    StoreUnreadable(Error),
    /// `Wallet::open` refused: nothing in the store reconciled.
    StartupRefused(Box<StartupRefusal>),
    /// A command that `decide` handles before opening the wallet reached the
    /// later match. Unreachable from `decide`; exists so that match is
    /// exhaustive without a panic.
    HandledBeforeTheWallet,
    /// `run_explorer` was handed a command that is not one of its four.
    NotAReadOnlyVerb { command: Box<Command> },

    // ---- the validator cold-key verbs ---------------------------------
    /// A validator transaction was reserved, signed and written. `entitlement`
    /// is the figure a claim was compared with, and `None` for the other two.
    ValidatorSent {
        shipped: ValidatorShipped,
        entitlement: Option<crate::entitlement::Entitlement>,
    },
    /// `--resign` reproduced the reserved validator transaction and wrote it.
    ValidatorResigned { shipped: ValidatorShipped },
    /// `import` reached `decide`, which has no seed to import: the binary
    /// reads it from the terminal and runs `run_import`.
    ImportNeedsTheTerminal,
    /// `import` found the SDK account on the chain and stored it, or found it
    /// already stored.
    Imported {
        account: u32,
        found: RestoredAccount,
        held_at: Option<WotsIndex>,
    },
    /// `import` could not place the account.
    ImportRefused { account: u32, failure: RestoreFailure },
    /// `import --extension-export` verified the export's account and placed
    /// it, or found it already stored.
    ExtensionImported {
        account_index: u32,
        recorded: WotsIndex,
        found: RestoredAccount,
        held_at: Option<WotsIndex>,
    },
    /// `import --extension-export` could not decrypt, verify or place it.
    ExtensionImportRefused { tag: Tag, failure: RestoreFailure },
    /// `entitlement` asked its source and the node, and these are the answers.
    EntitlementRead {
        tag: Tag,
        reading: core::result::Result<crate::entitlement::Entitlement, Error>,
        ledger: core::result::Result<crate::mesh::LedgerEntry, Error>,
    },

    // ---- the v4.1 staking verbs ---------------------------------------
    /// A dust-proof transaction was reserved, signed and written, or with
    /// `--resign` reproduced and written.
    StakingSent {
        shipped: StakingShipped,
        context: StakingContext,
    },
    /// A staking verb signed nothing, for the reason given.
    StakingRefused { tag: Tag, refusal: StakingRefusal },
    /// `stake-info`'s page.
    StakeInfo(Box<StakeInfoPage>),
}

impl Outcome {
    /// The [`Outcome::Planned`] that shows `plan` before it is signed: the
    /// source account, destinations in wire order, totals and block-to-live.
    ///
    /// The source is the plan's own [`SpendPlan::tag`], so the page cannot
    /// name a different account from the one the plan spends.
    ///
    /// Reads only the plan, so it reserves no key and moves no index.
    #[must_use]
    pub fn planned(plan: &SpendPlan) -> Outcome {
        Outcome::Planned {
            source: plan.tag(),
            destinations: plan.dsts().to_vec(),
            send_total: plan.send_total(),
            fee_total: plan.fee_total(),
            change_total: plan.change_total(),
            blk_to_live: plan.blk_to_live(),
        }
    }
}
