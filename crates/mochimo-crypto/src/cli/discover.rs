// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! `discover`: which account indices this seed's tags resolve to on the
//! chain, and the range that was searched.
//!
//! `create` derives only account 0, and `restore --account N` adds an
//! account once the chain resolves its tag. This verb asks the node about
//! accounts `0..=N` so a restored seed's other accounts can be found; it adds
//! nothing to the store.
//!
//! # It never asserts that an account does not exist
//!
//! Mesh code 4 covers several states it does not distinguish (see the
//! specification's *emptied-account window*): no ledger entry for the tag, a
//! zero balance discarded by the middleware's quorum, and a failed lookup.
//! No ledger entry is also what a never-funded account, a node on another
//! chain and a different seed all produce. So a [`Sighting`] records what the
//! node said, and the output reports how many of the searched indices
//! resolved rather than a count of accounts.
//!
//! # It writes nothing
//!
//! The store is borrowed immutably. No wallet is constructed and nothing is
//! reserved or signed, so like `address` and `restore` it does not go
//! through `Wallet::open`.

use crate::account::{AccountKind, WotsIndex};
use crate::addr::Tag;
use crate::consts::SEED_LEN;
use crate::derive;
use crate::keystore::{Keystore, Medium};
use crate::mesh::{LedgerEntry, MeshClient, Transport};
use crate::recon::{Cancel, Progress, Unfinished};
use crate::{Error, Secret};

/// What the node said about one account index, and what this store holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sighting {
    pub account: u32,
    pub tag: Tag,
    /// `Some` with the ledger address and balance when the node resolved the
    /// tag. `None` when the node answered code 4, which does not mean the
    /// account does not exist (see the module doc).
    pub entry: Option<LedgerEntry>,
    /// The kind and index this store records for the tag, if it holds it.
    /// Held accounts are reported, not omitted.
    pub held: Option<(AccountKind, WotsIndex)>,
}

/// One sweep's result. `to` is the last index actually searched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sweep {
    /// Indices `0..=to` were searched.
    pub to: u32,
    pub sightings: Vec<Sighting>,
}

impl Sweep {
    /// How many indices the node resolved.
    #[must_use]
    pub fn resolved(&self) -> usize {
        self.sightings.iter().filter(|s| s.entry.is_some()).count()
    }
}

/// Why a sweep stopped before its last index.
///
/// An unreachable node says nothing about an index, so the sweep fails
/// rather than returning a partial range. Mesh code 4 is an answer, not a
/// failure: it becomes a [`Sighting`] with no entry.
#[derive(Debug)]
pub enum SweepFailure {
    ChainUnreachable {
        /// The index the node failed on.
        account: u32,
        /// How many indices were searched before it, `0..account`.
        searched: u32,
        cause: Error,
    },
}

/// Derive the tags of accounts `0..=to` from `master` and ask the node about
/// each, in order.
///
/// One `/call` per index; `tag_resolve` already returns the balance. The
/// store is only read, for [`Sighting::held`].
pub fn sweep<M: Medium, T: Transport>(
    store: &Keystore<M>,
    client: &MeshClient<T>,
    master: &Secret<SEED_LEN>,
    to: u32,
) -> core::result::Result<Sweep, SweepFailure> {
    // `Cancel::NEVER` never stops, so `cancelled` is never called.
    sweep_asking(store, client, master, to, &Cancel::NEVER, None, || Ok(()))
}

/// [`sweep`], with `cancel` checked before each index's node call.
///
/// A cancel returns [`Unfinished::Cancelled`], never a partial [`Sweep`].
pub fn sweep_with<M: Medium, T: Transport>(
    store: &Keystore<M>,
    client: &MeshClient<T>,
    master: &Secret<SEED_LEN>,
    to: u32,
    cancel: &Cancel<'_>,
) -> core::result::Result<Sweep, Unfinished<SweepFailure>> {
    sweep_asking(store, client, master, to, cancel, None, || Err(Unfinished::Cancelled))
}

/// [`sweep_with`], reporting each index to `progress` before asking the
/// node. `position` and `ceiling` in [`Progress`] are always zero.
pub fn sweep_with_progress<M: Medium, T: Transport>(
    store: &Keystore<M>,
    client: &MeshClient<T>,
    master: &Secret<SEED_LEN>,
    to: u32,
    cancel: &Cancel<'_>,
    progress: &mut dyn FnMut(Progress),
) -> core::result::Result<Sweep, Unfinished<SweepFailure>> {
    sweep_asking(store, client, master, to, cancel, Some(progress), || Err(Unfinished::Cancelled))
}

/// The sweep shared by the three public forms. `cancelled` supplies the
/// result returned when `cancel` says stop.
fn sweep_asking<M: Medium, T: Transport, E: From<SweepFailure>>(
    store: &Keystore<M>,
    client: &MeshClient<T>,
    master: &Secret<SEED_LEN>,
    to: u32,
    cancel: &Cancel<'_>,
    mut progress: Option<&mut dyn FnMut(Progress)>,
    cancelled: impl Fn() -> core::result::Result<(), E>,
) -> core::result::Result<Sweep, E> {
    let mut sightings = Vec::new();
    for account in 0..=to {
        if cancel.stop() {
            cancelled()?;
        }
        if let Some(report) = progress.as_deref_mut() {
            report(Progress {
                account,
                accounts: to.saturating_add(1),
                position: 0,
                ceiling: 0,
            });
        }
        let tag = derive::derive_account_tag(master, account);
        let entry = match client.resolve_tag(&tag) {
            Ok(e) => Some(e),
            // Code 4 is recorded as unresolved, not as absent.
            Err(Error::Mesh { code: 4, .. }) => None,
            Err(cause) => {
                return Err(SweepFailure::ChainUnreachable {
                    account,
                    searched: account,
                    cause,
                }
                .into())
            }
        };
        sightings.push(Sighting {
            account,
            tag,
            entry,
            held: held_in(store, &tag),
        });
    }
    Ok(Sweep { to, sightings })
}

/// What the store records for `tag`, if anything. A store error is reported
/// as not held rather than aborting the sweep.
fn held_in<M: Medium>(store: &Keystore<M>, tag: &Tag) -> Option<(AccountKind, WotsIndex)> {
    match store.view(tag) {
        Ok(Some(v)) => Some((v.kind, v.wots_index)),
        Ok(None) | Err(_) => None,
    }
}
