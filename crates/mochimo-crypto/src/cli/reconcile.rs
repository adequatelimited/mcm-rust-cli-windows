// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! `status <tag> [--scan-to <M>]` and `reconcile <tag> --advance-to <N>` or
//! `--rollback-to <N>`: the commands that act on a divergence, and so run
//! without opening a `Wallet`.
//!
//! `Wallet::open` refuses every operation on a diverged account and refuses a
//! store in which no account reconciled (I4), so these commands could not act
//! through it. They run on the `Keystore` directly through `recon`, as
//! `restore` does. The write is still gated:
//! [`recon::advance_after_operator_review`] takes an `OperatorAcknowledgement`
//! and [`recon::rollback_after_operator_review`] a `RollbackAcknowledgement`,
//! each built only from a `Divergence`; each re-runs the comparison under the
//! same scope and refuses a target the live divergence does not name.
//!
//! [`advance_acknowledged`] and [`rollback_acknowledged`] reconcile every
//! account first and return every report with the decision.
//!
//! No CLI command holds a `Wallet` and a mutable `Keystore` at once. The
//! commands that hold a mutable store (`create`, `restore`, `reconcile`)
//! never reach a signer; `invariants.rs::the_cli_cannot_reach_around_the_wallet`
//! checks this.

use crate::addr::Tag;
use crate::consts::SEED_LEN;
use crate::keystore::{Keystore, Medium};
use crate::mesh::{MeshClient, Transport};
use crate::recon::{
    self, AccountStatus, Cancel, Divergence, OperatorAcknowledgement, Progress, RollbackAcknowledgement, ScanScope,
    Unfinished,
};
use crate::{Error, Secret};

/// The diagnostic scope for an invocation: the default, or the ceiling raised
/// to walk `0..=to` when an index is given.
///
/// `to` is inclusive, so the ceiling is `to + 1`. The parser refuses
/// `u32::MAX`; `saturating_add` avoids a panic regardless.
pub fn scope_to(to: Option<u32>) -> ScanScope {
    match to {
        Some(m) => ScanScope::DIAGNOSTIC.with_ceiling(m.saturating_add(1)),
        None => ScanScope::DIAGNOSTIC,
    }
}

/// `status`: the comparison `Wallet::open` makes, for one account, reported
/// without refusing, including when the account is diverged.
///
/// # Errors
///
/// Returns the account's [`Divergence`] when it does not reconcile.
#[allow(clippy::result_large_err)]
pub fn account_status<M: Medium, T: Transport>(
    store: &Keystore<M>,
    client: &MeshClient<T>,
    tag: &Tag,
    master: Option<&Secret<SEED_LEN>>,
    scan_to: Option<u32>,
) -> core::result::Result<AccountStatus, Divergence> {
    let access = recon::access_for(store, tag, master)?;
    recon::reconcile_account_with(store, client, tag, &access, &scope_to(scan_to), &recon::Cancel::NEVER)
}

/// Which way `reconcile` moves the named account's key index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Forward, to the index the chain shows ahead of the local index.
    Advance,
    /// Backward, to the index the chain shows behind the local index.
    Rollback,
}

/// What `reconcile --rollback-to` shows the operator before it acts, with
/// `to` the index named.
#[must_use]
pub fn rollback_warning(to: u32) -> String {
    format!(
        "Live index on the network is {to}, and the local index is ahead of it. Are you sure you \
         want to rollback your index to {to}? If the network is unstable it is usually safer to \
         wait a couple hours, as rolling the Index backward may allow a double-spend of a \
         one-time use key. A third-spend completely erodes account security. So proceed \
         cautiously."
    )
}

/// What `reconcile` decided, after reading the whole store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The store advanced the named account to the acknowledged index.
    Advanced { index: u32 },
    /// The store rolled the named account back to the acknowledged index.
    RolledBack { index: u32 },
    /// The named account reconciles cleanly; there was nothing to move.
    NothingToReconcile(AccountStatus),
    /// The named account is diverged and no advance was made. `target` is the
    /// index the live report names when it names one; `None` when advancing
    /// is not the remedy for this divergence (behind, unlocated, unreachable,
    /// a reservation the chain explains at neither key).
    NoAdvance { target: Option<u32> },
    /// The named account is diverged and no rollback was made. `target` is the
    /// index the live report names when it names one; `None` when rolling
    /// back is not the remedy for this divergence (ahead, unlocated,
    /// unreachable, a reservation the chain explains at neither key).
    NoRollback { target: Option<u32> },
    /// The store does not hold the tag.
    NotHeld,
}

/// What `reconcile` read and did: every diverged account's report before the
/// decision, in tag order, and the decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reviewed {
    /// The report of every account that did not reconcile, in tag order.
    pub reports: Vec<Divergence>,
    /// The number of accounts in the store.
    pub accounts: usize,
    /// The decision.
    pub outcome: Outcome,
}

/// `reconcile`: reconciles every account, then advances the named one only
/// if the live report names exactly `advance_to`.
///
/// `advance_to` raises the walk's ceiling to `advance_to + 1`. If the chain
/// holds the address at `advance_to`, the report is
/// `Ahead { index: advance_to }` and the acknowledgement is built from it.
/// If the chain is at another index, or the walk finds nothing, nothing is
/// written.
///
/// # Errors
///
/// Returns an error if the store cannot be read or the advance fails.
pub fn advance_acknowledged<M: Medium, T: Transport>(
    store: &mut Keystore<M>,
    client: &MeshClient<T>,
    tag: &Tag,
    master: Option<&Secret<SEED_LEN>>,
    advance_to: u32,
) -> core::result::Result<Reviewed, Error> {
    // `Cancel::NEVER` never stops, so the `cancelled` closure is never called.
    review_asking(store, client, tag, master, advance_to, Direction::Advance, &Cancel::NEVER, None, || Ok(()))
}

/// [`advance_acknowledged`] with cancellation: `cancel` is checked before
/// each account, at each position of each diagnostic walk, before the
/// write's re-check, and between that re-check's match and the write.
///
/// A cancel returns [`Unfinished::Cancelled`] and nothing has been written.
/// A cancel after the write is too late, and the call returns the advance.
///
/// # Errors
///
/// [`Unfinished::Cancelled`] on cancellation, otherwise the errors of
/// [`advance_acknowledged`].
pub fn advance_acknowledged_with<M: Medium, T: Transport>(
    store: &mut Keystore<M>,
    client: &MeshClient<T>,
    tag: &Tag,
    master: Option<&Secret<SEED_LEN>>,
    advance_to: u32,
    cancel: &Cancel<'_>,
) -> core::result::Result<Reviewed, Unfinished<Error>> {
    review_asking(store, client, tag, master, advance_to, Direction::Advance, cancel, None, || {
        Err(Unfinished::Cancelled)
    })
}

/// [`advance_acknowledged_with`], reporting [`Progress`] before each
/// account, every [`recon::PROGRESS_EVERY`] positions of each diagnostic
/// walk, and before the write's re-check walks the named account again.
///
/// # Errors
///
/// As [`advance_acknowledged_with`].
pub fn advance_acknowledged_with_progress<M: Medium, T: Transport>(
    store: &mut Keystore<M>,
    client: &MeshClient<T>,
    tag: &Tag,
    master: Option<&Secret<SEED_LEN>>,
    advance_to: u32,
    cancel: &Cancel<'_>,
    progress: &mut dyn FnMut(Progress),
) -> core::result::Result<Reviewed, Unfinished<Error>> {
    review_asking(store, client, tag, master, advance_to, Direction::Advance, cancel, Some(progress), || {
        Err(Unfinished::Cancelled)
    })
}

/// `reconcile --rollback-to`: reconciles every account, then rolls the named
/// one back only if the live report names exactly `rollback_to`, behind the
/// local index.
///
/// `rollback_to` sets the walk's ceiling to `rollback_to + 1`, as
/// `advance_to` does for an advance. The key at `rollback_to` has signed
/// before, so the account's next spend signs with it again.
///
/// # Errors
///
/// Returns an error if the store cannot be read or the rollback fails.
pub fn rollback_acknowledged<M: Medium, T: Transport>(
    store: &mut Keystore<M>,
    client: &MeshClient<T>,
    tag: &Tag,
    master: Option<&Secret<SEED_LEN>>,
    rollback_to: u32,
) -> core::result::Result<Reviewed, Error> {
    review_asking(store, client, tag, master, rollback_to, Direction::Rollback, &Cancel::NEVER, None, || Ok(()))
}

/// [`rollback_acknowledged`] with cancellation, checked where
/// [`advance_acknowledged_with`] checks it.
///
/// # Errors
///
/// [`Unfinished::Cancelled`] on cancellation, otherwise the errors of
/// [`rollback_acknowledged`].
pub fn rollback_acknowledged_with<M: Medium, T: Transport>(
    store: &mut Keystore<M>,
    client: &MeshClient<T>,
    tag: &Tag,
    master: Option<&Secret<SEED_LEN>>,
    rollback_to: u32,
    cancel: &Cancel<'_>,
) -> core::result::Result<Reviewed, Unfinished<Error>> {
    review_asking(store, client, tag, master, rollback_to, Direction::Rollback, cancel, None, || {
        Err(Unfinished::Cancelled)
    })
}

/// [`rollback_acknowledged_with`], reporting [`Progress`] as
/// [`advance_acknowledged_with_progress`] does.
///
/// # Errors
///
/// As [`rollback_acknowledged_with`].
pub fn rollback_acknowledged_with_progress<M: Medium, T: Transport>(
    store: &mut Keystore<M>,
    client: &MeshClient<T>,
    tag: &Tag,
    master: Option<&Secret<SEED_LEN>>,
    rollback_to: u32,
    cancel: &Cancel<'_>,
    progress: &mut dyn FnMut(Progress),
) -> core::result::Result<Reviewed, Unfinished<Error>> {
    review_asking(store, client, tag, master, rollback_to, Direction::Rollback, cancel, Some(progress), || {
        Err(Unfinished::Cancelled)
    })
}

/// The acknowledgement for the direction asked, built from the named
/// account's divergence.
#[derive(Clone, Copy)]
enum Acknowledged {
    Advance(OperatorAcknowledgement),
    Rollback(RollbackAcknowledgement),
}

impl Acknowledged {
    fn of(divergence: &Divergence, direction: Direction) -> Option<Acknowledged> {
        match direction {
            Direction::Advance => OperatorAcknowledgement::of(divergence).map(Acknowledged::Advance),
            Direction::Rollback => RollbackAcknowledgement::of(divergence).map(Acknowledged::Rollback),
        }
    }

    fn target(&self) -> u32 {
        match self {
            Acknowledged::Advance(a) => a.target().get(),
            Acknowledged::Rollback(a) => a.target().get(),
        }
    }
}

/// The review shared by the public forms of both directions. `to` is the
/// index named; `cancelled` produces the result returned on cancellation and
/// is called only after `cancel` has said stop.
///
/// `clippy::result_large_err` is allowed because the error is the
/// divergence report.
#[allow(clippy::too_many_arguments, clippy::result_large_err)]
fn review_asking<M: Medium, T: Transport, E: From<Error>>(
    store: &mut Keystore<M>,
    client: &MeshClient<T>,
    tag: &Tag,
    master: Option<&Secret<SEED_LEN>>,
    to: u32,
    direction: Direction,
    cancel: &Cancel<'_>,
    mut progress: Option<&mut dyn FnMut(Progress)>,
    cancelled: impl Fn() -> core::result::Result<(), E>,
) -> core::result::Result<Reviewed, E> {
    let tags = store.tags()?;
    let accounts = tags.len();
    let mut reviewed = Reviewed {
        reports: Vec::new(),
        accounts,
        outcome: Outcome::NotHeld,
    };
    if !tags.contains(tag) {
        return Ok(reviewed);
    }
    let scope = scope_to(Some(to));

    // Reconcile the whole store: the named account under the raised ceiling,
    // every other under the default scope.
    let mut named: Option<core::result::Result<AccountStatus, Divergence>> = None;
    let of = u32::try_from(accounts).unwrap_or(u32::MAX);
    // The ceiling needs a store read, so it is computed only when progress
    // is reported.
    let watching = progress.is_some();
    let at = |n: usize, t: &Tag, walked: &ScanScope| Progress {
        account: u32::try_from(n).unwrap_or(u32::MAX),
        accounts: of,
        position: 0,
        ceiling: match watching {
            true => walked.reach(store.view(t).ok().flatten().map(|v| v.wots_index)),
            false => 0,
        },
    };
    for (n, t) in tags.iter().enumerate() {
        if cancel.stop() {
            cancelled()?;
        }
        let this = t == tag;
        let walked = if this { &scope } else { &ScanScope::DIAGNOSTIC };
        let here = at(n, t, walked);
        if let Some(report) = progress.as_deref_mut() {
            report(here);
        }
        let result = match recon::access_for(store, t, master) {
            Err(d) => Err(d),
            Ok(access) => recon::watched(cancel, progress.as_deref_mut(), here, |cancel| {
                recon::reconcile_account_with(store, client, t, &access, walked, cancel)
            }),
        };
        if let Err(d) = &result {
            if d.stopped_by_cancel() {
                cancelled()?;
            }
            reviewed.reports.push(d.clone());
        }
        if this {
            named = Some(result);
        }
    }
    let divergence = match named {
        Some(Ok(status)) => {
            reviewed.outcome = Outcome::NothingToReconcile(status);
            return Ok(reviewed);
        }
        Some(Err(d)) => d,
        // Unreachable: `tags.contains(tag)` was checked above.
        None => return Ok(reviewed),
    };

    let refused = |target: Option<u32>| match direction {
        Direction::Advance => Outcome::NoAdvance { target },
        Direction::Rollback => Outcome::NoRollback { target },
    };
    let Some(ack) = Acknowledged::of(&divergence, direction) else {
        reviewed.outcome = refused(None);
        return Ok(reviewed);
    };
    if ack.target() != to {
        reviewed.outcome = refused(Some(ack.target()));
        return Ok(reviewed);
    }
    let access = match recon::access_for(store, tag, master) {
        Ok(a) => a,
        // Unreachable in practice: the same call succeeded above.
        Err(d) => {
            reviewed.reports.push(d);
            reviewed.outcome = refused(None);
            return Ok(reviewed);
        }
    };
    if cancel.stop() {
        cancelled()?;
    }
    let here = at(tags.iter().position(|t| t == tag).unwrap_or(0), tag, &scope);
    if let Some(report) = progress.as_deref_mut() {
        report(here);
    }
    // Cancellation is checked once more after the re-check matches and
    // before the write, since the walk checks only before each position.
    // This extra check is not counted as a walk position.
    let before_write = || match cancel.stop() {
        true => Err(Error::Cancelled),
        false => Ok(()),
    };
    let (moved, stopped) = recon::watched(cancel, progress, here, |counted| {
        recon::remembered(counted, |walking| match ack {
            Acknowledged::Advance(ack) => {
                recon::guarded::advance_after_operator_review(store, client, tag, &access, ack, &scope, walking, before_write)
                    .map(|receipt| Outcome::Advanced {
                        index: receipt.index().get(),
                    })
            }
            Acknowledged::Rollback(ack) => {
                recon::guarded::rollback_after_operator_review(store, client, tag, &access, ack, &scope, walking, before_write)
                    .map(|index| Outcome::RolledBack { index: index.get() })
            }
        })
    });
    let outcome = match moved {
        Ok(outcome) => outcome,
        // A cancel during the re-check walk leaves the account unlocated,
        // so the acknowledgement does not match; report it as a cancel.
        // Nothing was written.
        Err(Error::AcknowledgementDoesNotMatch) if stopped => {
            cancelled()?;
            return Err(Error::AcknowledgementDoesNotMatch.into());
        }
        // The check between the re-check's match and the write said stop.
        Err(Error::Cancelled) => {
            cancelled()?;
            return Err(Error::Cancelled.into());
        }
        Err(e) => return Err(e.into()),
    };
    reviewed.outcome = outcome;
    Ok(reviewed)
}
