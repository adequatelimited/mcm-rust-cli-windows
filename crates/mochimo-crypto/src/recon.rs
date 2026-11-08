// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! Reconciliation: comparing an account's local key index with the chain,
//! and refusing to act when they disagree (invariants I4 and I5).
//!
//! **I4 fails closed.** A local index can diverge from the chain after a crash
//! between signing and persisting, after restoring a seed with incomplete
//! history, or when two wallet instances share one seed. The divergence alone
//! does not say which. Advancing to match the chain is correct for the first
//! and catastrophic for the third, where the other instance will reuse every
//! skipped key, so the wallet refuses to start and requires operator action.
//!
//! **I5's scan is target-directed.** The chain cannot report a tag's usage
//! history, but it returns the tag's current address in one query, so restore
//! derives addresses and stops on the one that matches. It never scans for
//! absence and never assumes zero.
//!
//! # Ledger facts this rests on
//!
//! 1. **A tag absent from the ledger has never been funded.** `le_update`
//!    applies no zero-balance filter, so a tag whose balance reaches zero
//!    keeps its entry.
//! 2. **Per-index usage is unobservable.** The ledger holds one entry per tag
//!    (the merge is keyed on `addr_tag_compare`), and `le_find` compares an
//!    address prefix, so a full-address query answers *"is this the tag's
//!    current address?"*, never *"was this address ever used?"*. Every index
//!    other than the current one reads as unused, so a gap scan has no
//!    stopping signal.
//! 3. **The Mesh's "account not found" is not the ledger's absence.** The
//!    Mesh returns code 4 for any `QueryTagResolve` error, and that query
//!    discards zero-balance answers and fails when no address reaches quorum.
//!    The same answer therefore arrives for a tag with no ledger entry, a tag
//!    at zero balance, and a lookup that failed. [`Divergence::TagUnresolved`]
//!    and [`RestoreFailure::TagUnresolved`] name what was observed and prefer
//!    no reading.
//!
//! # The two scans and their bounds
//!
//! **Restore** has a seed and no store, so it walks from zero up to
//! [`RECOVERY_CEILING`]: how far along an account may be before the phrase
//! alone cannot recover it without raising the ceiling. **The divergence
//! diagnostic** has the local index, so it walks [`DIVERGENCE_WINDOW`]
//! positions either side of it first and then the recovery range. The window
//! bounds how large a disagreement can be diagnosed wherever the account
//! sits. The two are separate quantities: walking `0..20` absolute would
//! misreport a store at 22 with the chain at 24 as a foreign seed.
//!
//! Either bound limits only a failing search; the ordinary case stops on the
//! match. When the walk finds nothing, the account may have spent more times
//! than the positions walked, the seed may not own the tag, or the wallet may
//! be on another chain. The report names all three and prefers none.
//!
//! # What a match establishes
//!
//! Only that the address at a derived position is the address the ledger holds
//! for the tag now. That the key there has not signed rests on this wallet's
//! change convention (`spend_addresses` names the next position as
//! `chg_addr`), which the node does not enforce: `tx_val` checks `chg_addr`
//! only against the source's tag (`EMCM_TXCHG`, `EMCM_XTXTAGMISMATCH`). Every
//! acknowledged advance in this module rests on that convention.

use core::fmt;

use crate::account::{AccountKind, AdvanceReceipt, StreamId, WotsIndex};
use crate::addr::{Address, Tag};
use crate::consts::SEED_LEN;
use crate::derive;
use crate::error::{Error, Result};
use crate::keystore::{Figures, KeyAccess, Keystore, Medium, Pending};
use crate::mesh::spend::verify_wots;
use crate::mesh::{LedgerEntry, MeshClient, Transport, TxId};
use crate::secret::Secret;
use crate::tx::wire::Transaction;

/// The recovery ceiling: how many positions a failing restore walks before
/// giving up (`0..10_000`), unless the caller raises it for one invocation
/// ([`ScanScope::with_ceiling`]).
///
/// This bounds how many spends an account has already made, not a gap of
/// unused addresses as in BIP-44. 10,000 matches the bound the Mochimo
/// browser extension uses for the same walk
/// (`MasterSeed.deriveWotsIndexFromWotsAddrHash`, `endIndex = 10000`).
///
/// It limits only failure: [`scan_for_address`] returns on the first match.
/// An exhausted walk costs about 16 s of derivation in a release build.
/// [`ScanScope::DIAGNOSTIC`] uses the same ceiling.
pub const RECOVERY_CEILING: u32 = 10_000;

/// The divergence window: how many positions either side of the local index
/// the divergence diagnostic searches first.
///
/// It bounds the size of a disagreement the report can diagnose wherever the
/// account sits, and keeps that search cheap at every startup. Reach beyond
/// the window comes from [`RECOVERY_CEILING`].
pub const DIVERGENCE_WINDOW: u32 = 20;

/// The positions a scan walks.
///
/// First a `window` either side of the local index (ignored when there is no
/// local index, as in restore), then `0..ceiling` ascending, skipping
/// positions the window covered. Position `u32::MAX` is never walked: an
/// account there could not advance.
///
/// An index named on `reconcile --advance-to N` only raises the ceiling to
/// `N + 1`; it never becomes the answer by being named.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanScope {
    /// Walk `0..ceiling`. Restore's whole scope; the diagnostic's floor.
    pub ceiling: u32,
    /// Walk `local - window ..= local + window` (clamped), when a local index
    /// exists.
    pub window: Option<u32>,
}

impl ScanScope {
    /// What restore walks: the first [`RECOVERY_CEILING`] positions.
    pub const RESTORE: ScanScope = ScanScope {
        ceiling: RECOVERY_CEILING,
        window: None,
    };

    /// What the divergence diagnostic walks: [`DIVERGENCE_WINDOW`] either side
    /// of the local index, then the recovery range.
    ///
    /// The ceiling equals [`RECOVERY_CEILING`] so that any account `restore`
    /// can place is also described by the diagnostic. An account that
    /// reconciles walks nothing, and a disagreement inside the window costs
    /// at most 41 derivations; only a larger divergence pays for a full walk,
    /// on a startup that refuses anyway.
    pub const DIAGNOSTIC: ScanScope = ScanScope {
        ceiling: RECOVERY_CEILING,
        window: Some(DIVERGENCE_WINDOW),
    };

    /// Raise (or lower) the ceiling for this scope: walk `0..ceiling`.
    #[must_use]
    pub const fn with_ceiling(self, ceiling: u32) -> ScanScope {
        ScanScope { ceiling, ..self }
    }

    /// The window's edges around `local`, inclusive, when there is a window
    /// and a local index. The high edge stops one short of `u32::MAX`.
    fn window_edges(&self, local: Option<WotsIndex>) -> Option<(u32, u32)> {
        match (self.window, local) {
            (Some(w), Some(local)) => {
                let lo = local.get().saturating_sub(w);
                let hi = local.get().saturating_add(w).min(u32::MAX - 1);
                Some((lo, hi))
            }
            _ => None,
        }
    }

    /// The positions, window first, then the recovery range ascending with
    /// the window's members skipped. Lazy: a raised ceiling is walked, never
    /// materialised.
    fn positions(&self, local: Option<WotsIndex>) -> impl Iterator<Item = WotsIndex> {
        let edges = self.window_edges(local);
        let window = edges.map(|(lo, hi)| lo..=hi);
        let ceiling = self.ceiling;
        window
            .into_iter()
            .flatten()
            .chain((0..ceiling).filter(move |i| !edges.is_some_and(|(lo, hi)| (lo..=hi).contains(i))))
            .map(WotsIndex::from_raw)
    }

    /// How many positions a walk of this scope around `local` reaches if it
    /// finds nothing: the [`Progress::ceiling`] it reports against.
    ///
    /// Computed from the scope's edges (window plus range, less their
    /// overlap) rather than by enumerating positions, since a raised ceiling
    /// can name billions of them.
    pub(crate) fn reach(&self, local: Option<WotsIndex>) -> u32 {
        let ceiling = u64::from(self.ceiling);
        let total = match self.window_edges(local) {
            None => ceiling,
            Some((lo, hi)) => {
                let (lo, hi) = (u64::from(lo), u64::from(hi));
                let window = (hi + 1).saturating_sub(lo);
                let shared = match ceiling.checked_sub(1) {
                    None => 0,
                    Some(last) => (hi.min(last) + 1).saturating_sub(lo),
                };
                window + ceiling - shared
            }
        };
        u32::try_from(total).unwrap_or(u32::MAX)
    }
}

/// The state of an account whose local index and chain agree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccountStatus {
    /// Chain and local agree and nothing is reserved.
    InSync {
        index: WotsIndex,
        address: Address,
        balance: u64,
    },
    /// A reservation is open and the chain still holds the tag at the key
    /// that signed: the spend has not landed, and may never (a successful
    /// `/construction/submit` is only a socket write). The operator resolves
    /// it with `Wallet::settle_if_landed` once it lands, or
    /// `Wallet::resign_pending`, which rebuilds the same bytes with the same
    /// key.
    SpendOutstanding {
        spent_index: WotsIndex,
        balance: u64,
        /// Whether the signed artifact can still be accepted, from the
        /// recorded figures against the entry and the tip. A dead reservation
        /// still opens the wallet so the operator can see the diagnosis.
        reservation: Reservation,
    },
    /// A reservation is open and the chain holds the tag at the change key:
    /// the spend landed. One observation is enough to settle; see
    /// `Wallet::settle_if_landed`.
    SpendLanded {
        spent_index: WotsIndex,
        settled_index: WotsIndex,
        balance: u64,
    },
}

/// What reconciliation can say about an open reservation's artifact from the
/// store and the chain alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reservation {
    /// The figures were not recorded (store format version 3 carried neither
    /// the balance nor the block-to-live), so liveness cannot be determined.
    /// No tip is read.
    Unrecorded,
    /// The figures were recorded and both comparisons were made.
    Recorded(Diagnosis),
}

/// The two comparisons a recorded reservation admits, each with what was
/// observed. Both are rendered; a reservation dead by both causes says both.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnosis {
    pub figures: Figures,
    /// `entry.balance != figures.reserved_balance`. With the spend unlanded the
    /// balance can only have risen by a deposit, and `tx_val` requires
    /// `send + change + fee` to equal the balance exactly, so the signed bytes
    /// are dead.
    pub balance_moved: bool,
    /// The balance the entry carries now.
    pub balance_now: u64,
    pub expiry: Expiry,
}

/// The block-to-live against the tip.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expiry {
    /// `blk_to_live == 0`: never expires (the node checks only non-zero
    /// values), so no tip is read.
    NoExpiry,
    /// The tip is below the block-to-live: still landable.
    Below { tip: u64 },
    /// The tip has reached the block-to-live. `txclean` drops the transaction
    /// against `Cblocknum + 1`, so it can never be included once
    /// `tip >= blk_to_live`.
    Reached { tip: u64 },
    /// `blk_to_live != 0` and `/network/status` could not be read. The expiry
    /// is reported as unchecked, never assumed live.
    Unreadable { cause: Error },
}

impl Diagnosis {
    /// Dead when the balance moved or the block-to-live was reached; an
    /// unreadable tip is neither dead nor asserted live.
    #[must_use]
    pub fn is_dead(&self) -> bool {
        self.balance_moved || matches!(self.expiry, Expiry::Reached { .. })
    }
}

impl AccountStatus {
    /// The index this account will sign with next, whatever its state.
    #[must_use]
    pub fn index(&self) -> WotsIndex {
        match self {
            AccountStatus::InSync { index, .. } => *index,
            AccountStatus::SpendOutstanding { spent_index, .. } => *spent_index,
            AccountStatus::SpendLanded { settled_index, .. } => *settled_index,
        }
    }

    /// nanoMochimo the chain holds for the tag.
    #[must_use]
    pub fn balance(&self) -> u64 {
        match self {
            AccountStatus::InSync { balance, .. }
            | AccountStatus::SpendOutstanding { balance, .. }
            | AccountStatus::SpendLanded { balance, .. } => *balance,
        }
    }
}

/// Where the chain's address for a tag sits relative to this seed's keys, as
/// the diagnostic walk found it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainPosition {
    /// The chain's address is this seed's key at a position **ahead** of the
    /// local index: a spend from this seed landed that local state does not
    /// record — this wallet's, from an older copy of its state, or a second
    /// wallet's on the same seed.
    Ahead { index: WotsIndex, gap: u32 },
    /// The chain's address is this seed's key at a position **behind** the
    /// local index: a spend has not landed, local state was advanced past the
    /// chain, or the node answers for a chain on which this account has spent
    /// fewer times.
    Behind { index: WotsIndex, gap: u32 },
    /// No position the walk reached reproduces the chain's address. `scope`
    /// is what was walked around `local`, and `stopped` is `Some` when the
    /// walk ended early. The account may have spent more times than the walk
    /// reaches, the seed may not own the tag, or the wallet may be on another
    /// chain; this variant cannot tell which.
    Unlocated {
        local: WotsIndex,
        scope: ScanScope,
        stopped: Option<Stopped>,
    },
}

impl fmt::Display for ChainPosition {
    /// The direction-neutral rendering, used by the reservation report. The
    /// index-mismatch report renders each variant with its own action.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainPosition::Ahead { index, gap } => write!(
                f,
                "the chain's address IS this seed's key at index {} -- {gap} ahead of local",
                index.get()
            ),
            ChainPosition::Behind { index, gap } => write!(
                f,
                "the chain's address IS this seed's key at index {} -- {gap} BEHIND local",
                index.get()
            ),
            ChainPosition::Unlocated {
                local,
                scope,
                stopped,
            } => {
                write!(f, "no key index this scan walked reproduces the chain's address (walked: ")?;
                walked(f, *local, scope)?;
                f.write_str(")")?;
                match stopped {
                    Some(Stopped { at, by: StoppedBy::Derivation }) => write!(
                        f,
                        "; the walk stopped at index {at} on a derivation error and did not finish"
                    )?,
                    Some(Stopped { at, by: StoppedBy::Cancelled }) => write!(
                        f,
                        "; the walk was stopped at index {at} before it finished, so this says \
                         less than a completed one would"
                    )?,
                    None => {}
                }
                Ok(())
            }
        }
    }
}

/// Writes the positions a scope walked around `local`: the window's edges,
/// then the recovery range as `0 through ceiling-1`.
fn walked(f: &mut fmt::Formatter<'_>, local: WotsIndex, scope: &ScanScope) -> fmt::Result {
    let mut wrote = false;
    if let Some((lo, hi)) = scope.window_edges(Some(local)) {
        write!(
            f,
            "indices {lo} through {hi}, {} either side of index {}",
            scope.window.unwrap_or(0),
            local.get()
        )?;
        wrote = true;
    }
    if scope.ceiling > 0 {
        if wrote {
            f.write_str(", and ")?;
        }
        write!(f, "indices 0 through {}", scope.ceiling - 1)?;
        wrote = true;
    }
    if !wrote {
        f.write_str("no positions at all")?;
    }
    Ok(())
}

/// A caller's answer to *should this walk stop now?*, asked once per key
/// position.
///
/// [`ScanScope`] says how far a walk may go; this says whether it may keep
/// going. A stopped walk returns `Err(Error::Cancelled)` normally, so every
/// `Drop` runs and the borrowed master seed (a [`Secret`]) is overwritten.
/// A process killed by a signal runs no destructors; this crate installs no
/// signal handler, and `README.md` documents that limit.
///
/// # Predicate requirements
///
/// It is called once per position on the walking thread. It must be cheap
/// (a relaxed load of a flag), must not lock anything the caller holds
/// elsewhere, and must not panic.
pub struct Cancel<'a>(Option<&'a dyn Fn() -> bool>);

impl Cancel<'static> {
    /// Never stop: the walk runs to its scope's end.
    pub const NEVER: Cancel<'static> = Cancel(None);
}

impl<'a> Cancel<'a> {
    /// Stop as soon as `asked` answers `true`.
    #[must_use]
    pub fn when(asked: &'a dyn Fn() -> bool) -> Cancel<'a> {
        Cancel(Some(asked))
    }

    /// Whether to stop. `NEVER` makes no call at all.
    ///
    /// Operations that return [`Unfinished`] also ask between their steps.
    pub(crate) fn stop(&self) -> bool {
        matches!(self.0, Some(asked) if asked())
    }
}

/// What a cancellable operation returns in place of its result: stopped by
/// its [`Cancel`], or refused for a reason of its own.
///
/// A cancel is kept separate from refusals because a refusal is a finding
/// about an account and a cancel found nothing.
///
/// **A call that returns `Cancelled` wrote nothing.** Operations that write
/// ask their `Cancel` again just before their single write, so a call that
/// changed the store always returns its result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unfinished<E> {
    /// The [`Cancel`] said to stop. Nothing was decided and nothing was
    /// written.
    Cancelled,
    /// The operation's own refusal, as the form of it that takes no `Cancel`
    /// returns it.
    Refused(E),
}

impl<E> From<E> for Unfinished<E> {
    fn from(refusal: E) -> Unfinished<E> {
        Unfinished::Refused(refusal)
    }
}

/// Runs `walk` under a [`Cancel`] that asks `cancel` and records whether it
/// ever said stop, and returns that flag beside the walk's result.
///
/// Asking the predicate again afterwards is not reliable: it may answer
/// `false` after having stopped the walk (for example a flag cleared on
/// read). `NEVER` is passed through unwrapped and reports `false`.
pub(crate) fn remembered<R>(cancel: &Cancel<'_>, walk: impl FnOnce(&Cancel<'_>) -> R) -> (R, bool) {
    if cancel.0.is_none() {
        return (walk(cancel), false);
    }
    let said_stop = core::cell::Cell::new(false);
    let asked = || {
        let stop = cancel.stop();
        if stop {
            said_stop.set(true);
        }
        stop
    };
    let result = walk(&Cancel::when(&asked));
    (result, said_stop.get())
}

/// How far a long operation has got, counted rather than estimated.
///
/// `account` of `accounts` is the current account, from zero. `position` of
/// `ceiling` is how many key positions that account's walk has reached of
/// the most it can reach; a walk that finds its target stops short, and an
/// operation that walks nothing reports a `ceiling` of zero.
///
/// Reported before each account with `position` zero, then every
/// [`PROGRESS_EVERY`] positions of a walk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    pub account: u32,
    pub accounts: u32,
    pub position: u32,
    pub ceiling: u32,
}

/// How many positions a walk reaches between two reports of its
/// [`Progress`].
pub const PROGRESS_EVERY: u32 = 256;

/// Runs `walk` under a [`Cancel`] that asks `cancel` and reports to
/// `progress` every [`PROGRESS_EVERY`] positions. With no `progress`, `walk`
/// runs under `cancel` directly.
///
/// Positions are counted by counting cancel checks, which a walk makes once
/// per position.
pub(crate) fn watched<'p, R>(
    cancel: &Cancel<'_>,
    progress: Option<&mut (dyn FnMut(Progress) + 'p)>,
    at: Progress,
    walk: impl FnOnce(&Cancel<'_>) -> R,
) -> R {
    let Some(progress) = progress else {
        return walk(cancel);
    };
    let reached = core::cell::Cell::new(0u32);
    let progress = core::cell::RefCell::new(progress);
    let asked = || {
        let n = reached.get().saturating_add(1);
        reached.set(n);
        if n.is_multiple_of(PROGRESS_EVERY) {
            (*progress.borrow_mut())(Progress { position: n, ..at });
        }
        cancel.stop()
    };
    walk(&Cancel::when(&asked))
}

/// A walk that ended before its scope did: where it stopped, and what stopped
/// it. The cause is recorded so the report never calls a cancel a fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stopped {
    /// The position the walk had reached.
    pub at: u32,
    /// What ended it.
    pub by: StoppedBy,
}

/// What ended a walk early.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoppedBy {
    /// Deriving that position's address failed.
    Derivation,
    /// A [`Cancel`] said to stop. Nothing failed.
    Cancelled,
}

/// Why the wallet will not start. Every variant renders a report naming what
/// diverged, by how much, and one action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Divergence {
    /// The chain holds this tag at an address that is not the key this store
    /// would sign with next, and no reservation explains it.
    IndexMismatch {
        tag: Tag,
        local: WotsIndex,
        local_address: Address,
        chain_address: Address,
        /// The balance the chain holds for the tag, so the operator sees what
        /// is at stake before advancing.
        balance: u64,
        stream: StreamId,
        found: ChainPosition,
        /// The retained settled block, when `found` is a `Behind` at exactly
        /// that block's `spent_index`: the store recorded a settle the node's
        /// answer does not show. `None` in every other case.
        reverted_settle: Option<Pending>,
    },
    /// A reservation is open and the chain holds the tag at neither the key
    /// that signed nor the change key. Something moved this tag that this
    /// store did not.
    ReservationUnexplained {
        tag: Tag,
        spent_index: WotsIndex,
        chain_address: Address,
        /// The balance the chain holds for the tag (see `IndexMismatch`).
        balance: u64,
        stream: StreamId,
        found: ChainPosition,
    },
    /// The node answered *account not found* for this tag. The Mesh gives
    /// that answer for a tag with no ledger entry, a tag at zero balance, and
    /// a failed lookup, without saying which (module doc, fact 3).
    TagUnresolved { tag: Tag, local: WotsIndex },
    /// The chain could not be reached. An unreconciled wallet must not sign,
    /// so this refuses like a divergence.
    ChainUnreachable { tag: Tag, cause: Error },
    /// A derived account with no master seed supplied: its addresses cannot
    /// be computed, so it cannot be reconciled.
    NoMasterForDerivedAccount { tag: Tag },
    /// Reconciliation itself failed — a store error, a response that did not
    /// parse, a key that would not derive.
    CannotReconcile { tag: Tag, cause: Error },
}

impl Divergence {
    /// The tag this is about.
    #[must_use]
    pub fn tag(&self) -> Tag {
        match self {
            Divergence::IndexMismatch { tag, .. }
            | Divergence::ReservationUnexplained { tag, .. }
            | Divergence::TagUnresolved { tag, .. }
            | Divergence::ChainUnreachable { tag, .. }
            | Divergence::NoMasterForDerivedAccount { tag }
            | Divergence::CannotReconcile { tag, .. } => *tag,
        }
    }

    /// The index an operator would acknowledge to advance past this, or
    /// `None` when advancing is not a remedy.
    ///
    /// It is the found index itself, not one past it: the chain's current
    /// address is the key that signs next, so a chain at index *i* means local
    /// state belongs at *i*.
    ///
    /// Only an [`Divergence::IndexMismatch`] with an `Ahead` position has one.
    #[must_use]
    pub fn advance_target(&self) -> Option<WotsIndex> {
        match self {
            Divergence::IndexMismatch {
                found: ChainPosition::Ahead { index, .. },
                ..
            } => Some(*index),
            _ => None,
        }
    }

    /// The index an operator would acknowledge to roll back to, or `None`
    /// when rolling back is not a remedy.
    ///
    /// It is the found index itself, as for [`Divergence::advance_target`]:
    /// the chain's current address is the key that signs next. Only an
    /// [`Divergence::IndexMismatch`] with a `Behind` position has one.
    #[must_use]
    pub fn rollback_target(&self) -> Option<WotsIndex> {
        match self {
            Divergence::IndexMismatch {
                found: ChainPosition::Behind { index, .. },
                ..
            } => Some(*index),
            _ => None,
        }
    }

    /// Whether this report's diagnostic walk was ended by a [`Cancel`]. Such a
    /// report is incomplete, so operations returning [`Unfinished`] answer it
    /// as `Cancelled`.
    pub(crate) fn stopped_by_cancel(&self) -> bool {
        match self {
            Divergence::IndexMismatch { found, .. } | Divergence::ReservationUnexplained { found, .. } => matches!(
                found,
                ChainPosition::Unlocated {
                    stopped: Some(Stopped {
                        by: StoppedBy::Cancelled,
                        ..
                    }),
                    ..
                }
            ),
            _ => false,
        }
    }
}

fn hex20(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl fmt::Display for Divergence {
    /// The operator's report. Every arm states what diverged, both indices
    /// (or why there is no second one), the size of the gap, and the action.
    /// Each names every cause that fits the observation and prefers none.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Divergence::IndexMismatch {
                tag,
                local,
                local_address,
                chain_address,
                balance,
                stream,
                found,
                reverted_settle,
            } => {
                write!(
                    f,
                    "account {}: the chain holds this tag at an address this keystore does not \
                     expect.\n  local index {} expects {}\n  the chain holds        {}\n  \
                     with a balance of      {} nanoMCM\n  key stream {}\n",
                    hex20(tag),
                    local.get(),
                    hex20(local_address),
                    hex20(chain_address),
                    balance,
                    hex20(stream.as_bytes()),
                )?;
                match found {
                    ChainPosition::Ahead { index, gap } => write!(
                        f,
                        "  the chain's address IS this seed's key at index {} -- {gap} ahead of \
                         local. A spend from this seed landed that this local state does not \
                         record: either this wallet's own, and local state is an older copy \
                         (a backup, a restore), or a SECOND WALLET on this seed spent. A crash \
                         between signing and saving cannot leave this state at any gap: the \
                         index and its reservation are written durably before a signature \
                         exists, so a spend interrupted after signing shows up as a reservation, \
                         never as this mismatch.\n  ACTION: advance to {} through the \
                         acknowledged path, naming that index. Do NOT edit local state by hand.",
                        index.get(),
                        index.get(),
                    ),
                    ChainPosition::Behind { index, gap } => {
                        write!(
                            f,
                            "  the chain's address IS this seed's key at index {} -- {gap} BEHIND \
                             local. Either a spend has not landed yet, or local state was advanced \
                             past the chain, or this node answers for a chain on which this account \
                             has spent fewer times (check the node URL if the gap is large).\n  \
                             ACTION: wait for the spend to land and reconcile again. If the chain \
                             itself rolled back and the spend will not land, roll back to {} \
                             through the acknowledged path, naming that index: the key at that \
                             index has signed before, and the next spend signs with it again.",
                            index.get(),
                            index.get(),
                        )?;
                        // The retained settled block, when the chain sits at
                        // exactly the index it settled. Added to the causes
                        // above, not replacing them.
                        if let Some(s) = reverted_settle {
                            let figures = match s.figures {
                                Some(Figures {
                                    reserved_balance,
                                    blk_to_live,
                                }) => format!(
                                    "reserved balance {reserved_balance} nanoMCM, block-to-live {blk_to_live}"
                                ),
                                None => "figures not recorded: this reservation was written before format version 4 recorded them".to_string(),
                            };
                            write!(
                                f,
                                "\n  This store recorded a SETTLE at index {} (digest {}; {figures}) and this \
                                 node's answer does not show it. Two things produce that and this report \
                                 cannot tell them apart: a reorg reverted the block that settled it, or the \
                                 settle was taken on the single observation the settle rule permits against a \
                                 node that does not share this chain or had not seen it -- in which case \
                                 the spend may be unlanded still and may yet land. The signature at that \
                                 digest is the only one key {} may ever give, and it is still acceptable \
                                 while the balance at the source has not moved and a non-zero block-to-live \
                                 has not passed, so a copy of the artifact held outside the \
                                 store can be sent again. No command rebuilds these bytes, and none may: \
                                 the store keeps the digest, the index and the figures, not the signature, \
                                 and `resign` reads only an open reservation, which this state leaves clear. \
                                 The library function `resubmit_reverted_settle` sends a saved copy only when \
                                 its signed part hashes to the retained digest, its signature recovers to the \
                                 source key, the balance at the source is the reserved one and the \
                                 block-to-live has not passed. It refuses otherwise, signs nothing and moves \
                                 no index. Keep any copy of the artifact you have.",
                                s.spent_index.get(),
                                hex20(&s.digest),
                                s.spent_index.get(),
                            )?;
                        }
                        Ok(())
                    }
                    ChainPosition::Unlocated {
                        local,
                        scope,
                        stopped,
                    } => {
                        f.write_str("  NO key index this scan walked reproduces the chain's address (walked: ")?;
                        walked(f, *local, scope)?;
                        f.write_str(").")?;
                        match stopped {
                            Some(Stopped { at, by: StoppedBy::Derivation }) => write!(
                                f,
                                " The walk did not finish: deriving index {at} failed, so this says \
                                 less than it would."
                            )?,
                            Some(Stopped { at, by: StoppedBy::Cancelled }) => write!(
                                f,
                                " The walk did not finish: it was stopped at index {at}, so this \
                                 says less than it would. Nothing failed and nothing is owed but \
                                 the search."
                            )?,
                            None => {}
                        }
                        f.write_str(
                            " Three things produce that and this report cannot tell them apart: \
                             this account has spent more times than the walk reaches -- local \
                             state is an older copy, or a second wallet on this seed has been \
                             spending; this seed does not own this tag; or this wallet is pointed \
                             at another chain.\n  ACTION: if this account may have spent more \
                             times than the walk reaches, search further along by raising the \
                             scan ceiling -- the scan finds the exact index or fails again, and \
                             searching writes nothing. Then advance through the acknowledged path, \
                             naming the index it found: the index you name is derived and compared \
                             to the chain's address, and refused if it does not match. If no \
                             ceiling you can name finds it, check the seed and the node URL.",
                        )
                    }
                }
            }
            Divergence::ReservationUnexplained {
                tag,
                spent_index,
                chain_address,
                balance,
                stream,
                found,
            } => write!(
                f,
                "account {}: a spend is reserved at index {} but the chain holds this tag at \
                 neither the key that signed nor the change key.\n  the chain holds {}\n  with a \
                 balance of {} nanoMCM\n  key stream {}\n  {found}\n  ACTION: something moved this \
                 tag that this wallet did not. Compare the key stream against every other wallet \
                 on this seed before doing anything else. Neither settling nor re-signing is \
                 correct until that is answered.",
                hex20(tag),
                spent_index.get(),
                hex20(chain_address),
                balance,
                hex20(stream.as_bytes()),
            ),
            // Three readings, none preferred (module doc, fact 3).
            Divergence::TagUnresolved { tag, local } => write!(
                f,
                "account {}: the node did not resolve this tag -- it answered \"account not \
                 found\" -- and local state is at index {}.\n  That answer does not mean what it \
                 says. The Mesh gives it in three situations it does not distinguish: the ledger \
                 has no entry for this tag, which means it has never been funded on this chain; \
                 the ledger holds this tag at ZERO balance, which the Mesh's quorum discards; or \
                 the lookup itself failed -- too few nodes answered, a node between blocks, a \
                 timeout -- which a live node was seen doing for every tag on the chain at once, \
                 funded ones included.\n  ACTION: ask again in a minute. Only if the same answer \
                 comes back from a node that reports itself synchronized is the account absent or \
                 empty: if it is new and unfunded, fund it or remove it from the store before \
                 starting; if it has spent to zero, it cannot be reconciled through this endpoint \
                 until it is paid again; if it should have funds, the wallet is pointed at the \
                 wrong chain or the seed is not the one that made it -- check both. Nothing is \
                 decided by one answer: do not create, restore or advance anything on it.",
                hex20(tag),
                local.get(),
            ),
            Divergence::ChainUnreachable { tag, cause } => write!(
                f,
                "account {}: the chain could not be reached, so this account could not be \
                 reconciled ({cause}).\n  ACTION: an unreconciled wallet must not sign -- a \
                 restored seed and a live second instance both look exactly like a healthy \
                 wallet from local state alone. Restore the connection and start again. There is \
                 no offline mode that signs.",
                hex20(tag),
            ),
            Divergence::NoMasterForDerivedAccount { tag } => write!(
                f,
                "account {}: derived, and no master seed was supplied, so its addresses cannot \
                 be computed and it cannot be reconciled.\n  ACTION: supply the master seed, or \
                 remove the account from this store.",
                hex20(tag),
            ),
            Divergence::CannotReconcile { tag, cause } => write!(
                f,
                "account {}: reconciliation failed before it could compare anything ({cause}).\n  \
                 ACTION: this is not a divergence -- it is a wallet that could not ask the \
                 question. Fix the cause and start again; do not advance local state.",
                hex20(tag),
            ),
        }
    }
}

/// An operator's acknowledgement of one specific divergence, naming the tag
/// and the index they were shown.
///
/// It can only be built from a [`Divergence`] ([`OperatorAcknowledgement::of`]),
/// and [`advance_after_operator_review`] refuses one whose tag and target do
/// not match the store's current divergence. Re-exported from `wallet`;
/// defined here because the CLI's `reconcile` runs before a `Wallet` exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperatorAcknowledgement {
    tag: Tag,
    target: WotsIndex,
}

impl OperatorAcknowledgement {
    /// Acknowledges a divergence. `None` when advancing is not a remedy (an
    /// unreachable chain, an unresolved tag, an unlocated address, an
    /// unexplained reservation). An unlocated address becomes an `Ahead` only
    /// by raising the scan ceiling ([`ScanScope::with_ceiling`]).
    #[must_use]
    pub fn of(divergence: &Divergence) -> Option<OperatorAcknowledgement> {
        divergence.advance_target().map(|target| OperatorAcknowledgement {
            tag: divergence.tag(),
            target,
        })
    }

    /// The acknowledged account's tag.
    #[must_use]
    pub fn tag(&self) -> Tag {
        self.tag
    }

    /// The acknowledged target index.
    #[must_use]
    pub fn target(&self) -> WotsIndex {
        self.target
    }
}

/// An operator's acknowledgement of a divergence whose chain position is
/// behind the local index, naming the tag and the index they were shown.
///
/// It can only be built from a [`Divergence`]
/// ([`RollbackAcknowledgement::of`]), and [`rollback_after_operator_review`]
/// refuses one whose tag and target do not match the store's current
/// divergence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RollbackAcknowledgement {
    tag: Tag,
    target: WotsIndex,
}

impl RollbackAcknowledgement {
    /// Acknowledges a divergence. `None` unless the walk found the chain's
    /// address at a key behind the local index.
    #[must_use]
    pub fn of(divergence: &Divergence) -> Option<RollbackAcknowledgement> {
        divergence.rollback_target().map(|target| RollbackAcknowledgement {
            tag: divergence.tag(),
            target,
        })
    }

    /// The acknowledged account's tag.
    #[must_use]
    pub fn tag(&self) -> Tag {
        self.tag
    }

    /// The acknowledged target index.
    #[must_use]
    pub fn target(&self) -> WotsIndex {
        self.target
    }
}

/// How one walk ended.
enum Walk {
    Found(WotsIndex),
    NotFound,
    Failed { at: u32, cause: Error },
}

/// Walk the positions `scope` names around `local`, deriving each address,
/// and stop on the one that equals `target`.
fn walk<F>(target: &Address, scope: &ScanScope, local: Option<WotsIndex>, mut address_at: F) -> Walk
where
    F: FnMut(WotsIndex) -> Result<Address>,
{
    for p in scope.positions(local) {
        match address_at(p) {
            Ok(a) if a == *target => return Walk::Found(p),
            Ok(_) => {}
            Err(cause) => return Walk::Failed { at: p.get(), cause },
        }
    }
    Walk::NotFound
}

/// Walks the positions `scope` names around `local`, deriving each address,
/// and stops on the one that equals `target`.
///
/// This is a target-directed scan, not a gap scan: per-index usage is
/// unobservable on this chain (module doc, fact 2). Returns `Ok(None)` when
/// the scope is exhausted.
///
/// `address_at` is the caller's derivation (`Keystore::address_at` for a
/// stored account, `derived_address_at` for a restore). `local` is the index
/// the window is centred on; restore has none.
///
/// # Errors
///
/// Returns the first error `address_at` returns.
pub fn scan_for_address<F>(
    target: &Address,
    scope: &ScanScope,
    local: Option<WotsIndex>,
    address_at: F,
) -> Result<Option<WotsIndex>>
where
    F: FnMut(WotsIndex) -> Result<Address>,
{
    match walk(target, scope, local, address_at) {
        Walk::Found(p) => Ok(Some(p)),
        Walk::NotFound => Ok(None),
        Walk::Failed { cause, .. } => Err(cause),
    }
}

/// The address of a derived account's key at `position`, from the master
/// seed, for restore where no store exists yet.
///
/// Agrees with [`Keystore::address_at`] for the same account
/// (`tests/recon.rs` checks this).
#[must_use]
pub fn derived_address_at(master: &Secret<SEED_LEN>, account_index: u32, position: WotsIndex) -> Address {
    let account = derive::derive_account(master, account_index);
    match position.rotation() {
        None => account.first_key().address(&account.tag()),
        Some(rotation) => derive::derive_wots_key(account.seed(), rotation).address(&account.tag()),
    }
}

/// Which access an account's kind needs: the master seed for a derived
/// account, the stored root for an imported or SDK one.
///
/// # Errors
///
/// [`Divergence::NoMasterForDerivedAccount`] for a derived account with no
/// master, and [`Divergence::CannotReconcile`] when the account is missing or
/// the store fails.
#[allow(clippy::result_large_err)]
pub fn access_for<'a, M: Medium>(
    store: &Keystore<M>,
    tag: &Tag,
    master: Option<&'a Secret<SEED_LEN>>,
) -> core::result::Result<KeyAccess<'a>, Divergence> {
    let view = match store.view(tag) {
        Ok(Some(v)) => v,
        Ok(None) => {
            return Err(Divergence::CannotReconcile {
                tag: *tag,
                cause: Error::NoSuchAccount,
            })
        }
        Err(cause) => return Err(Divergence::CannotReconcile { tag: *tag, cause }),
    };
    match view.kind {
        AccountKind::Imported | AccountKind::Sdk => Ok(KeyAccess::StoredRoot),
        AccountKind::Derived => master
            .map(KeyAccess::Master)
            .ok_or(Divergence::NoMasterForDerivedAccount { tag: *tag }),
    }
}

/// What a restore found: the tag, the index the chain puts it at, and the
/// balance there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RestoredAccount {
    pub tag: Tag,
    pub index: WotsIndex,
    pub address: Address,
    pub balance: u64,
}

/// Why a restore did not produce an index. Every variant is a failure; none
/// is a fallback, because restore never defaults to zero (I5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RestoreFailure {
    /// The chain could not be reached. Fail, never assume.
    ChainUnreachable { tag: Tag, cause: Error },
    /// The node answered *account not found* for the tag, so there is no
    /// address to derive an index from. The account may be unfunded, empty,
    /// or the lookup may have failed (module doc, fact 3).
    TagUnresolved { tag: Tag },
    /// The tag resolves, but none of the first `scanned` positions reproduces
    /// its address. The account may have spent at least `scanned` times, the
    /// seed may not own the tag, or the wallet may be on another chain. The
    /// remedy for the first is a higher ceiling ([`ScanScope::with_ceiling`]).
    NoIndexReproducesTheAddress {
        tag: Tag,
        address: Address,
        scanned: u32,
    },
    /// The scan itself failed.
    CannotScan { tag: Tag, cause: Error },
    /// The scan found the index and the store refused the account. Nothing
    /// was written: the account is stored at the found index in one commit.
    CannotStore { tag: Tag, cause: Error },
    /// A browser-extension export records the account at `recorded`, past
    /// the chain's position `chain`. The extension moves past a key when it
    /// signs with it, so the key at `chain` has already signed. Nothing was
    /// written.
    ExtensionKeyAlreadySigned { tag: Tag, chain: WotsIndex, recorded: WotsIndex },
}

impl fmt::Display for RestoreFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RestoreFailure::ChainUnreachable { tag, cause } => write!(
                f,
                "restore of account {}: the chain could not be reached ({cause}), so the key \
                 index could not be derived. ACTION: restore the connection and try again. This \
                 does NOT fall back to index zero -- a restored wallet that starts at zero \
                 re-signs with every key the original already used, which is this design's \
                 likeliest path to unrecoverable key reuse.",
                hex20(tag),
            ),
            RestoreFailure::TagUnresolved { tag } => write!(
                f,
                "restore of account {}: the node did not resolve this tag -- it answered \
                 \"account not found\" -- so there is no address to derive an index from. That \
                 answer does not mean what it says. The Mesh gives it in three situations it does \
                 not distinguish: the ledger has no entry for this tag (never funded); the ledger \
                 holds it at ZERO balance, which the Mesh's quorum discards; or the lookup itself \
                 failed -- too few nodes answered, a node between blocks, a timeout -- which a \
                 live node was seen doing for every tag on the chain at once, funded ones \
                 included.\n  ACTION: ask again in a minute. Only if the same answer comes back \
                 from a node that reports itself synchronized: an account never funded has no \
                 index to restore -- fund it, then restore it; an account that has spent to zero \
                 cannot be located through this endpoint until it is paid again; if it should \
                 have funds, check the node URL and the seed. Do NOT put this account in a store \
                 at index 0 on the strength of this answer: an account that has spent is not at 0, \
                 and a restored wallet placed at a used index re-signs with keys the original \
                 already used.",
                hex20(tag),
            ),
            RestoreFailure::NoIndexReproducesTheAddress { tag, address, scanned } => write!(
                f,
                "restore of account {}: the chain holds it at {}, and none of key indices 0 \
                 through {} reproduces that address. Three things produce that and this program \
                 cannot tell them apart from here: this account has spent {scanned} or more \
                 times, so its key is further along than the scan reached; this seed does not \
                 own this tag; or the wallet is on another chain.\n  ACTION: if the account may \
                 have spent that many times, run the restore again with a higher scan ceiling -- \
                 it finds the exact index or fails again, and no index is assumed either way. \
                 Otherwise check the seed and the node URL. Nothing here guesses: a restored \
                 wallet placed at a guessed index re-signs with keys the original already used.",
                hex20(tag),
                hex20(address),
                scanned.saturating_sub(1),
            ),
            // A cancel is not a fault and is not rendered as one.
            RestoreFailure::CannotScan { tag, cause: Error::Cancelled } => {
                write!(
                    f,
                    "restore of account {}: the scan was stopped before it found an index. \
                     ACTION: run it again to search from the start; nothing was written, no \
                     index is assumed, and stopping cost nothing but the search.",
                    hex20(tag),
                )
            }
            RestoreFailure::CannotScan { tag, cause } => write!(
                f,
                "restore of account {}: the scan could not run ({cause}). ACTION: fix the cause; \
                 no index is assumed.",
                hex20(tag),
            ),
            RestoreFailure::CannotStore { tag, cause } => write!(
                f,
                "restore of account {}: the chain named its index but the store refused the \
                 account ({cause}). Nothing was written. ACTION: fix the cause and run the \
                 restore again.",
                hex20(tag),
            ),
            RestoreFailure::ExtensionKeyAlreadySigned { tag, chain, recorded } => write!(
                f,
                "import of account {}: the chain holds it at key index {}, and the export records \
                 the extension at index {}. The extension moves to the next index when it signs, \
                 so the key at index {} has already signed a transaction the chain does not show \
                 yet. Signing with that key again would use a one-time key twice. Nothing was \
                 written.\n  ACTION: if that transaction is still pending, wait for it to land, \
                 then import again.\n  If it was dropped and will not land, this export cannot be \
                 imported, and waiting will not change that: any new transaction from this \
                 account, from the extension or from Tawara, would sign with the key at index {} \
                 a second time. Submitting the same signed transaction again, if you still have \
                 it, is safe; once it lands, import again.",
                hex20(tag),
                chain.get(),
                recorded.get(),
                chain.get(),
                chain.get(),
            ),
        }
    }
}

/// Derives a derived account's current key index from the chain (I5),
/// walking the default scope ([`ScanScope::RESTORE`]).
///
/// 1. Compute the tag from the master seed and the account index.
/// 2. Resolve the tag to its current address in one query.
/// 3. Scan positions `0..RECOVERY_CEILING`, stopping on the match.
///
/// Zero is returned only when position 0's address is the one the chain
/// holds; it is never a fallback.
///
/// # Errors
///
/// A [`RestoreFailure`] for an unreachable chain, an unresolved tag, an
/// address no position reproduces, or a scan that could not run.
pub fn restore_account_index<T: Transport>(
    client: &MeshClient<T>,
    master: &Secret<SEED_LEN>,
    account_index: u32,
) -> core::result::Result<RestoredAccount, RestoreFailure> {
    restore_account_index_with(client, master, account_index, &ScanScope::RESTORE, &Cancel::NEVER)
}

/// [`restore_account_index`] over a caller-set scope and [`Cancel`], for
/// example to raise the recovery ceiling for one invocation. The scope's
/// window is ignored: there is no local index to centre it on.
///
/// # Errors
///
/// As [`restore_account_index`]; a cancel returns
/// [`RestoreFailure::CannotScan`] with [`Error::Cancelled`].
pub fn restore_account_index_with<T: Transport>(
    client: &MeshClient<T>,
    master: &Secret<SEED_LEN>,
    account_index: u32,
    scope: &ScanScope,
    cancel: &Cancel<'_>,
) -> core::result::Result<RestoredAccount, RestoreFailure> {
    let tag = derive::derive_account_tag(master, account_index);
    let entry = match client.resolve_tag(&tag) {
        Ok(e) => e,
        // Code 4 is the Mesh's answer, not the ledger's absence (module doc,
        // fact 3).
        Err(Error::Mesh { code: 4, .. }) => return Err(RestoreFailure::TagUnresolved { tag }),
        Err(cause) => return Err(RestoreFailure::ChainUnreachable { tag, cause }),
    };
    let found = scan_for_address(&entry.address, scope, None, |p| {
        // Checked before each derivation, so a cancel costs at most one
        // position.
        if cancel.stop() {
            return Err(Error::Cancelled);
        }
        Ok(derived_address_at(master, account_index, p))
    })
    .map_err(|cause| RestoreFailure::CannotScan { tag, cause })?;
    match found {
        Some(index) => Ok(RestoredAccount {
            tag,
            index,
            address: entry.address,
            balance: entry.balance,
        }),
        None => Err(RestoreFailure::NoIndexReproducesTheAddress {
            tag,
            address: entry.address,
            scanned: scope.ceiling,
        }),
    }
}

/// The address of a Mochimo SDK account's key at `position`, from its
/// account seed: the tag (spend 0's hash) followed by spend `position`'s
/// hash. Agrees with [`Keystore::address_at`] for the same stored account.
#[must_use]
pub fn sdk_address_at(account_seed: &Secret<SEED_LEN>, position: WotsIndex) -> Address {
    let tag = derive::sdk_account_tag(account_seed);
    derive::sdk_wots_key(account_seed, position.get()).address(&tag)
}

/// [`restore_account_index_with`] for a Mochimo SDK account seed: resolves
/// the account's tag, then walks [`sdk_address_at`] over the scope and stops
/// on the chain's address. Position 0 is returned only when the chain holds
/// the implicit address, as for an SDK account that has never spent.
///
/// # Errors
///
/// As [`restore_account_index_with`].
pub fn restore_sdk_account_index_with<T: Transport>(
    client: &MeshClient<T>,
    account_seed: &Secret<SEED_LEN>,
    scope: &ScanScope,
    cancel: &Cancel<'_>,
) -> core::result::Result<RestoredAccount, RestoreFailure> {
    let tag = derive::sdk_account_tag(account_seed);
    let entry = match client.resolve_tag(&tag) {
        Ok(e) => e,
        Err(Error::Mesh { code: 4, .. }) => return Err(RestoreFailure::TagUnresolved { tag }),
        Err(cause) => return Err(RestoreFailure::ChainUnreachable { tag, cause }),
    };
    let found = scan_for_address(&entry.address, scope, None, |p| {
        if cancel.stop() {
            return Err(Error::Cancelled);
        }
        Ok(sdk_address_at(account_seed, p))
    })
    .map_err(|cause| RestoreFailure::CannotScan { tag, cause })?;
    match found {
        Some(index) => Ok(RestoredAccount {
            tag,
            index,
            address: entry.address,
            balance: entry.balance,
        }),
        None => Err(RestoreFailure::NoIndexReproducesTheAddress {
            tag,
            address: entry.address,
            scanned: scope.ceiling,
        }),
    }
}

/// Reconcile one account in a store against the chain, with the default
/// diagnostic scope ([`ScanScope::DIAGNOSTIC`]).
///
/// Returns the account's [`AccountStatus`] when local and chain agree.
/// Never advances anything: the reconciler reports and the operator acts.
///
/// `clippy::result_large_err` is allowed because [`Divergence`] is the full
/// operator report, returned once per account at startup.
///
/// # Errors
///
/// A [`Divergence`] when local and chain disagree or reconciliation cannot be
/// performed.
#[allow(clippy::result_large_err)]
pub fn reconcile_account<M: Medium, T: Transport>(
    store: &Keystore<M>,
    client: &MeshClient<T>,
    tag: &Tag,
    access: &KeyAccess<'_>,
) -> core::result::Result<AccountStatus, Divergence> {
    reconcile_account_with(store, client, tag, access, &ScanScope::DIAGNOSTIC, &Cancel::NEVER)
}

/// [`reconcile_account`] with a caller-set diagnostic scope and [`Cancel`].
/// The in-sync comparison does not depend on the scope; the scope only
/// shapes the diagnostic that runs after the comparison fails.
///
/// # Errors
///
/// As [`reconcile_account`].
#[allow(clippy::result_large_err)]
pub fn reconcile_account_with<M: Medium, T: Transport>(
    store: &Keystore<M>,
    client: &MeshClient<T>,
    tag: &Tag,
    access: &KeyAccess<'_>,
    scope: &ScanScope,
    cancel: &Cancel<'_>,
) -> core::result::Result<AccountStatus, Divergence> {
    let view = match store.view(tag) {
        Ok(Some(v)) => v,
        Ok(None) => {
            return Err(Divergence::CannotReconcile {
                tag: *tag,
                cause: Error::NoSuchAccount,
            })
        }
        Err(cause) => return Err(Divergence::CannotReconcile { tag: *tag, cause }),
    };
    let entry: LedgerEntry = match client.resolve_tag(tag) {
        Ok(e) => e,
        // Code 4 is the Mesh's answer, not the ledger's absence (module doc,
        // fact 3).
        Err(Error::Mesh { code: 4, .. }) => {
            return Err(Divergence::TagUnresolved {
                tag: *tag,
                local: view.wots_index,
            })
        }
        Err(cause) => return Err(Divergence::ChainUnreachable { tag: *tag, cause }),
    };

    let at = |p: WotsIndex| store.address_at(tag, p, access);
    let stream = match store.stream_id(tag) {
        Ok(s) => s,
        Err(cause) => return Err(Divergence::CannotReconcile { tag: *tag, cause }),
    };

    match view.pending {
        // -- no reservation: the chain must hold the key this store signs with next --
        None => {
            let local_address = match at(view.wots_index) {
                Ok(a) => a,
                Err(cause) => return Err(Divergence::CannotReconcile { tag: *tag, cause }),
            };
            if entry.address == local_address {
                return Ok(AccountStatus::InSync {
                    index: view.wots_index,
                    address: entry.address,
                    balance: entry.balance,
                });
            }
            let found = locate(&entry.address, view.wots_index, scope, cancel, at);
            // Report the retained settled block only when the chain sits at
            // exactly the index it settled.
            let reverted_settle = match (found, view.settled) {
                (ChainPosition::Behind { index, .. }, Some(s)) if s.spent_index == index => Some(s),
                _ => None,
            };
            Err(Divergence::IndexMismatch {
                tag: *tag,
                local: view.wots_index,
                local_address,
                chain_address: entry.address,
                balance: entry.balance,
                stream,
                found,
                reverted_settle,
            })
        }
        // -- a reservation is open: the chain holds the old address (not
        // landed) or the change key's (landed). Anything else is divergence.
        Some(Pending {
            spent_index, figures, ..
        }) => {
            let spent_address = match at(spent_index) {
                Ok(a) => a,
                Err(cause) => return Err(Divergence::CannotReconcile { tag: *tag, cause }),
            };
            if entry.address == spent_address {
                // Diagnose whether the reservation is dead. The tip is read
                // only for a recorded, non-zero block-to-live.
                let reservation = match figures {
                    None => Reservation::Unrecorded,
                    Some(fig) => {
                        let expiry = expiry_of(client, fig.blk_to_live);
                        Reservation::Recorded(Diagnosis {
                            figures: fig,
                            balance_moved: entry.balance != fig.reserved_balance,
                            balance_now: entry.balance,
                            expiry,
                        })
                    }
                };
                return Ok(AccountStatus::SpendOutstanding {
                    spent_index,
                    balance: entry.balance,
                    reservation,
                });
            }
            let change_address = match at(view.wots_index) {
                Ok(a) => a,
                Err(cause) => return Err(Divergence::CannotReconcile { tag: *tag, cause }),
            };
            if entry.address == change_address {
                return Ok(AccountStatus::SpendLanded {
                    spent_index,
                    settled_index: view.wots_index,
                    balance: entry.balance,
                });
            }
            // The window is centred on the change index, one past the
            // reserved key, so it covers both keys the reservation names.
            Err(Divergence::ReservationUnexplained {
                tag: *tag,
                spent_index,
                chain_address: entry.address,
                balance: entry.balance,
                stream,
                found: locate(&entry.address, view.wots_index, scope, cancel, at),
            })
        }
    }
}

/// Advances past a divergence the operator acknowledged, through
/// `Keystore::persist_advance_to`.
///
/// The acknowledgement's tag and target must equal the store's current
/// divergence under the same `scope`, so a stale acknowledgement, another
/// account's, or an index the walk did not find is refused. The target is
/// [`Divergence::advance_target`], which exists only for an `Ahead` position
/// the walk matched to the chain's address. The store also refuses any
/// target not strictly ahead of the stored index.
///
/// A free function because the CLI meets a divergence before a `Wallet` can
/// exist; `Wallet::advance_after_operator_review` delegates here.
///
/// # Errors
///
/// [`Error::AcknowledgementDoesNotMatch`] when the acknowledgement does not
/// match the current divergence, [`Error::NothingToReconcile`] when the
/// account is in sync, or the store's error from the write.
pub fn advance_after_operator_review<M: Medium, T: Transport>(
    store: &mut Keystore<M>,
    client: &MeshClient<T>,
    tag: &Tag,
    access: &KeyAccess<'_>,
    ack: OperatorAcknowledgement,
    scope: &ScanScope,
    cancel: &Cancel<'_>,
) -> Result<AdvanceReceipt> {
    // No extra check between the re-check and the write.
    guarded::advance_after_operator_review(store, client, tag, access, ack, scope, cancel, || Ok(()))
}

/// The acknowledged advance and rollback with a `before_write` check run
/// after the re-check matches and before the write, used by cancellable
/// operations. An `Err` from `before_write` is returned with nothing written.
///
/// A separate module so the calls keep the names the CLI containment scan
/// permits only in `cli/reconcile.rs`.
pub(crate) mod guarded {
    use super::{reconcile_account_with, Cancel, OperatorAcknowledgement, RollbackAcknowledgement, ScanScope};
    use crate::account::{AdvanceReceipt, WotsIndex};
    use crate::addr::Tag;
    use crate::error::{Error, Result};
    use crate::keystore::{KeyAccess, Keystore, Medium};
    use crate::mesh::{MeshClient, Transport};

    /// The advance's seven arguments plus the check run before the write.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn advance_after_operator_review<M: Medium, T: Transport>(
        store: &mut Keystore<M>,
        client: &MeshClient<T>,
        tag: &Tag,
        access: &KeyAccess<'_>,
        ack: OperatorAcknowledgement,
        scope: &ScanScope,
        cancel: &Cancel<'_>,
        before_write: impl FnOnce() -> Result<()>,
    ) -> Result<AdvanceReceipt> {
        if ack.tag != *tag {
            return Err(Error::AcknowledgementDoesNotMatch);
        }
        match reconcile_account_with(store, client, tag, access, scope, cancel) {
            Ok(_) => Err(Error::NothingToReconcile),
            Err(d) => {
                if d.advance_target() != Some(ack.target) {
                    return Err(Error::AcknowledgementDoesNotMatch);
                }
                before_write()?;
                store.persist_advance_to(tag, ack.target)
            }
        }
    }

    /// The rollback's seven arguments plus the check run before the write.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn rollback_after_operator_review<M: Medium, T: Transport>(
        store: &mut Keystore<M>,
        client: &MeshClient<T>,
        tag: &Tag,
        access: &KeyAccess<'_>,
        ack: RollbackAcknowledgement,
        scope: &ScanScope,
        cancel: &Cancel<'_>,
        before_write: impl FnOnce() -> Result<()>,
    ) -> Result<WotsIndex> {
        if ack.tag != *tag {
            return Err(Error::AcknowledgementDoesNotMatch);
        }
        match reconcile_account_with(store, client, tag, access, scope, cancel) {
            Ok(_) => Err(Error::NothingToReconcile),
            Err(d) => {
                if d.rollback_target() != Some(ack.target) {
                    return Err(Error::AcknowledgementDoesNotMatch);
                }
                before_write()?;
                store.persist_rollback_to(tag, ack.target)
            }
        }
    }
}

/// Rolls back to a divergence the operator acknowledged, through
/// `Keystore::persist_rollback_to`.
///
/// The acknowledgement's tag and target must equal the store's current
/// divergence under the same `scope`, as for [`advance_after_operator_review`].
/// The target is [`Divergence::rollback_target`], which exists only for a
/// `Behind` position the walk matched to the chain's address. The store also
/// refuses any target not strictly behind the stored index. The key at the
/// target has signed before, so the next spend signs with it again.
///
/// # Errors
///
/// [`Error::AcknowledgementDoesNotMatch`] when the acknowledgement does not
/// match the current divergence, [`Error::NothingToReconcile`] when the
/// account is in sync, or the store's error from the write.
pub fn rollback_after_operator_review<M: Medium, T: Transport>(
    store: &mut Keystore<M>,
    client: &MeshClient<T>,
    tag: &Tag,
    access: &KeyAccess<'_>,
    ack: RollbackAcknowledgement,
    scope: &ScanScope,
    cancel: &Cancel<'_>,
) -> Result<WotsIndex> {
    guarded::rollback_after_operator_review(store, client, tag, access, ack, scope, cancel, || Ok(()))
}

/// Resubmits a saved copy of a transaction whose settle the chain has
/// reverted.
///
/// A settle is taken on one observation of the change key, so a reorg can
/// revert it. The store keeps the settled block (digest, index, figures) but
/// not the signature. This sends the operator's saved copy only when every
/// check below holds. The store is never written: no index moves and no key
/// signs.
///
/// Checks, in order: the account retains a settle and has no open
/// reservation; the settle recorded its figures; the bytes parse and
/// re-serialize to themselves; the signed part hashes to the retained digest;
/// the signature recovers to the source key; the chain holds the account one
/// position behind the store; the source balance equals the reserved balance;
/// a non-zero block-to-live has not been reached.
///
/// Returns the transaction id the node echoed, which `submit_wire` checks
/// against the id computed from the bytes. The reply only means the bytes
/// reached a node, not that the transaction was accepted or included.
///
/// # Errors
///
/// The first failing check's error; nothing is sent.
pub fn resubmit_reverted_settle<M: Medium, T: Transport>(
    store: &Keystore<M>,
    client: &MeshClient<T>,
    tag: &Tag,
    access: &KeyAccess<'_>,
    saved: &[u8],
) -> Result<TxId> {
    let view = store.view(tag)?.ok_or(Error::NoSuchAccount)?;
    if let Some(open) = view.pending {
        return Err(Error::ReservationOpen {
            spent_index: open.spent_index.get(),
        });
    }
    let settled = view.settled.ok_or(Error::NotARevertedSettle {
        what: "no settle is retained",
    })?;
    let figures = settled.figures.ok_or(Error::FiguresNotRecorded)?;

    let tx =
        Transaction::from_wire(saved).map_err(|cause| Error::SavedArtifactNotATransaction {
            cause: Box::new(cause),
        })?;
    if tx.to_wire() != saved {
        return Err(Error::SavedArtifactNotWhole {
            given: saved.len(),
            described: tx.wire_len(),
        });
    }
    if tx.message_digest() != settled.digest {
        return Err(Error::NotTheSettledSpend);
    }
    verify_wots(&tx)?;

    // A reverted settle has the chain one position behind the store, at the
    // spent index. A window of one around the store's position covers
    // `spent_index` through `spent_index + 2`; anything else is refused.
    let narrow = ScanScope {
        ceiling: 0,
        window: Some(1),
    };
    let balance = match reconcile_account_with(store, client, tag, access, &narrow, &Cancel::NEVER)
    {
        Ok(_) => {
            return Err(Error::NotARevertedSettle {
                what: "the chain is in sync",
            })
        }
        Err(Divergence::IndexMismatch {
            found,
            balance,
            reverted_settle,
            ..
        }) => match found {
            ChainPosition::Behind { index, gap: 1 }
                if index == settled.spent_index && reverted_settle == Some(settled) =>
            {
                balance
            }
            ChainPosition::Ahead { .. } => {
                return Err(Error::NotARevertedSettle {
                    what: "the chain is ahead of the store",
                })
            }
            ChainPosition::Behind { .. } | ChainPosition::Unlocated { .. } => {
                return Err(Error::NotARevertedSettle {
                    what: "the chain is at another position",
                })
            }
        },
        Err(Divergence::TagUnresolved { .. }) => {
            return Err(Error::NotARevertedSettle {
                what: "tag unresolved by the node",
            })
        }
        Err(Divergence::ChainUnreachable { .. }) => {
            return Err(Error::NotARevertedSettle {
                what: "the chain could not be read",
            })
        }
        Err(_) => {
            return Err(Error::NotARevertedSettle {
                what: "the account could not be reconciled",
            })
        }
    };

    if balance != figures.reserved_balance {
        return Err(Error::SettledBalanceMoved {
            reserved: figures.reserved_balance,
            current: balance,
        });
    }
    match expiry_of(client, figures.blk_to_live) {
        Expiry::NoExpiry | Expiry::Below { .. } => {}
        Expiry::Reached { tip } => {
            return Err(Error::SettledExpired {
                blk_to_live: figures.blk_to_live,
                tip,
            })
        }
        Expiry::Unreadable { cause } => return Err(cause),
    }
    client.submit_wire(saved, TxId(tx.id_digest()))
}

/// Compares a block-to-live against the tip. Zero never expires and reads no
/// tip; a failed read is `Unreadable`, never assumed live.
fn expiry_of<T: Transport>(client: &MeshClient<T>, blk_to_live: u64) -> Expiry {
    if blk_to_live == 0 {
        return Expiry::NoExpiry;
    }
    match client.network_status() {
        Ok(tip) if tip.index >= blk_to_live => Expiry::Reached { tip: tip.index },
        Ok(tip) => Expiry::Below { tip: tip.index },
        Err(cause) => Expiry::Unreadable { cause },
    }
}

/// The cancellable diagnostic walk: where the chain's address sits relative
/// to `local`. A walk that fails to finish is reported as
/// [`ChainPosition::Unlocated`] with where it stopped, rather than
/// propagated, so the refusal it accompanies is not replaced.
fn locate<F>(
    chain: &Address,
    local: WotsIndex,
    scope: &ScanScope,
    cancel: &Cancel<'_>,
    mut address_at: F,
) -> ChainPosition
where
    F: FnMut(WotsIndex) -> Result<Address>,
{
    let walked = walk(chain, scope, Some(local), |p| {
        if cancel.stop() {
            return Err(Error::Cancelled);
        }
        address_at(p)
    });
    match walked {
        Walk::Found(i) if i.get() > local.get() => ChainPosition::Ahead {
            index: i,
            gap: i.get() - local.get(),
        },
        Walk::Found(i) => ChainPosition::Behind {
            index: i,
            gap: local.get() - i.get(),
        },
        Walk::NotFound => ChainPosition::Unlocated {
            local,
            scope: *scope,
            stopped: None,
        },
        // `ChainPosition` is `Copy` and `Error` is not, so only the kind of
        // stop is kept.
        Walk::Failed { at, cause } => ChainPosition::Unlocated {
            local,
            scope: *scope,
            stopped: Some(Stopped {
                at,
                by: match cause {
                    Error::Cancelled => StoppedBy::Cancelled,
                    _ => StoppedBy::Derivation,
                },
            }),
        },
    }
}
