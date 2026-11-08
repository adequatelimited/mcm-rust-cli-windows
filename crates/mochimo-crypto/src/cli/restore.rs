// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! `restore --account <N> [--scan-to <M>]`: builds a store entry from a seed.
//!
//! Restore needs [`Keystore::add`], which takes `&mut`, and `Wallet` exposes
//! only a shared store, so restore runs on the `Keystore` directly, without
//! opening a `Wallet`. It signs nothing; the next command's `Wallet::open`
//! reconciles the account it adds.
//!
//! The account is built at the index found on the chain and committed once,
//! so a failure never leaves it on disk at index zero (I5). An account the
//! store already holds is reported and not touched; advancing a held
//! account is `reconcile`'s job (I4).
//!
//! No CLI command holds a `Wallet` and a mutable `Keystore` at once. The
//! commands that hold a mutable store (`create`, `restore`, `reconcile`)
//! never reach a signer; this one writes only through `add`, and
//! `invariants.rs::the_cli_cannot_reach_around_the_wallet` checks this.

use crate::account::{Account, WotsIndex};
use crate::keystore::{Keystore, Medium};
use crate::mesh::{MeshClient, Transport};
use crate::recon::{self, Cancel, Progress, RestoreFailure, RestoredAccount, ScanScope, Unfinished};

use crate::consts::SEED_LEN;
use crate::{Error, Secret};

/// What [`import_extension_account`] found: the restore outcome, and the
/// position the export recorded, which may differ from the chain's.
pub struct ExtensionImported {
    /// The restore outcome.
    pub restored: Restored,
    /// The account index the extension derived the account at.
    pub account_index: u32,
    /// The export's `wotsIndex + 1`.
    pub recorded: WotsIndex,
}

/// Imports the account a browser-extension export holds for `tag`.
///
/// Decrypts the export with `password`, selects and verifies the account
/// (`ExtensionExport::account`), then places it at the position the chain
/// holds: the export's recorded position if it matches, otherwise a scan as
/// restore does (I5: the position comes from the chain). A chain position
/// below the recorded one is refused, because the extension has already
/// signed with the key there. The account is stored as an imported root in
/// one commit. The master seed and decrypted records never leave memory.
///
/// # Errors
///
/// A [`RestoreFailure`] if the export cannot be read or does not hold
/// `tag`, the chain cannot be reached or does not know the tag, no position
/// reproduces the chain's address, the chain is behind the export's recorded
/// position, or the store cannot be written.
pub fn import_extension_account<M: Medium, T: Transport>(
    store: &mut Keystore<M>,
    client: &MeshClient<T>,
    export_text: &str,
    password: &[u8],
    tag: &crate::addr::Tag,
    scan_to: Option<u32>,
) -> core::result::Result<ExtensionImported, RestoreFailure> {
    let cannot = |cause| RestoreFailure::CannotScan { tag: *tag, cause };
    let export = crate::extension_export::ExtensionExport::parse(export_text).map_err(cannot)?;
    let master = export.master_seed(password).map_err(cannot)?;
    let found_in_export = export.account(&master, tag).map_err(cannot)?;
    drop(master);
    let crate::extension_export::ExtensionAccount { account, index, position } = found_in_export;

    let entry = match client.resolve_tag(tag) {
        Ok(e) => e,
        Err(Error::Mesh { code: 4, .. }) => return Err(RestoreFailure::TagUnresolved { tag: *tag }),
        Err(cause) => return Err(RestoreFailure::ChainUnreachable { tag: *tag, cause }),
    };
    let at = |p: WotsIndex| {
        account.address_at_without_master(p).ok_or(Error::ExtensionExportMismatch {
            what: "the export's account did not import as an imported root",
        })
    };
    let index_on_chain = if at(position).map_err(cannot)? == entry.address {
        position
    } else {
        let scope = match scan_to {
            Some(m) => ScanScope::RESTORE.with_ceiling(m.saturating_add(1)),
            None => ScanScope::RESTORE,
        };
        match recon::scan_for_address(&entry.address, &scope, None, at).map_err(cannot)? {
            Some(p) => p,
            None => {
                return Err(RestoreFailure::NoIndexReproducesTheAddress {
                    tag: *tag,
                    address: entry.address,
                    scanned: scope.ceiling,
                })
            }
        }
    };
    if index_on_chain.get() < position.get() {
        return Err(RestoreFailure::ExtensionKeyAlreadySigned { tag: *tag, chain: index_on_chain, recorded: position });
    }
    let found = RestoredAccount {
        tag: *tag,
        index: index_on_chain,
        address: entry.address,
        balance: entry.balance,
    };
    let cannot_store = |cause| RestoreFailure::CannotStore { tag: *tag, cause };
    if let Some(view) = store.view(tag).map_err(cannot_store)? {
        return Ok(ExtensionImported {
            restored: Restored { found, held_at: Some(view.wots_index) },
            account_index: index,
            recorded: position,
        });
    }
    let mut account = account;
    if index_on_chain.get() > WotsIndex::ZERO.get() {
        account.advance_to(index_on_chain).map_err(cannot_store)?;
    }
    store.add(account).map_err(cannot_store)?;
    Ok(ExtensionImported {
        restored: Restored { found, held_at: None },
        account_index: index,
        recorded: position,
    })
}

/// Imports account `account_index` of a Mochimo SDK master seed: derives its
/// account seed (`Derivation.deriveAccountSeed`), finds the position the
/// chain holds, and adds it to the store at that position in one commit, as
/// [`restore_account`] does for the extension's scheme.
///
/// Only the account seed is stored, as an SDK record; the master seed is not
/// kept. A tag the store already holds is reported at its stored position
/// and nothing is written.
///
/// # Errors
///
/// A [`RestoreFailure`] if the scan fails or the store cannot be written.
pub fn import_sdk_account<M: Medium, T: Transport>(
    store: &mut Keystore<M>,
    client: &MeshClient<T>,
    sdk_master: &Secret<SEED_LEN>,
    account_index: u32,
    scan_to: Option<u32>,
) -> core::result::Result<Restored, RestoreFailure> {
    let scope = match scan_to {
        Some(m) => ScanScope::RESTORE.with_ceiling(m.saturating_add(1)),
        None => ScanScope::RESTORE,
    };
    let account_seed = crate::derive::sdk_account_seed(sdk_master, account_index);
    let found = recon::restore_sdk_account_index_with(client, &account_seed, &scope, &Cancel::NEVER)?;
    let cannot_store = |cause| RestoreFailure::CannotStore {
        tag: found.tag,
        cause,
    };
    if let Some(view) = store.view(&found.tag).map_err(cannot_store)? {
        return Ok(Restored {
            found,
            held_at: Some(view.wots_index),
        });
    }
    let mut account = Account::import_sdk(account_seed);
    if found.index.get() > WotsIndex::ZERO.get() {
        account.advance_to(found.index).map_err(cannot_store)?;
    }
    store.add(account).map_err(cannot_store)?;
    Ok(Restored { found, held_at: None })
}

/// What a restore did, for rendering.
pub struct Restored {
    /// The account as found on the chain.
    pub found: RestoredAccount,
    /// `Some(stored)` when the store already held the tag, at `stored`: the
    /// scan still ran and its index is still reported, but nothing was
    /// written. `None` when the account was added at `found.index`.
    pub held_at: Option<WotsIndex>,
}

/// Derives account `account_index`, asks the chain where its tag is, and
/// adds it to the store at that index, scanning `0..=scan_to` if given and
/// the default recovery range otherwise.
///
/// The index always comes from the chain (I5); [`RestoreFailure`] has no
/// fallback variant.
///
/// # Errors
///
/// A [`RestoreFailure`] if the scan fails or the store cannot be written.
pub fn restore_account<M: Medium, T: Transport>(
    store: &mut Keystore<M>,
    client: &MeshClient<T>,
    master: &Secret<SEED_LEN>,
    account_index: u32,
    scan_to: Option<u32>,
) -> core::result::Result<Restored, RestoreFailure> {
    // `Cancel::NEVER` never stops, so the `cancelled` closure is never called.
    restore_asking(store, client, master, account_index, scan_to, &Cancel::NEVER, None, || Ok(()))
}

/// [`restore_account`] with cancellation: `cancel` is checked before the
/// node is queried, at each scan position, and before the commit.
///
/// A cancel returns [`Unfinished::Cancelled`] and nothing has been written.
/// A cancel after the commit is too late, and the call returns the account
/// added.
///
/// # Errors
///
/// [`Unfinished::Cancelled`] on cancellation, otherwise the errors of
/// [`restore_account`].
pub fn restore_account_with<M: Medium, T: Transport>(
    store: &mut Keystore<M>,
    client: &MeshClient<T>,
    master: &Secret<SEED_LEN>,
    account_index: u32,
    scan_to: Option<u32>,
    cancel: &Cancel<'_>,
) -> core::result::Result<Restored, Unfinished<RestoreFailure>> {
    restore_asking(store, client, master, account_index, scan_to, cancel, None, || Err(Unfinished::Cancelled))
}

/// [`restore_account_with`], reporting [`Progress`] once before the node is
/// queried and every [`recon::PROGRESS_EVERY`] scan positions.
///
/// # Errors
///
/// As [`restore_account_with`].
pub fn restore_account_with_progress<M: Medium, T: Transport>(
    store: &mut Keystore<M>,
    client: &MeshClient<T>,
    master: &Secret<SEED_LEN>,
    account_index: u32,
    scan_to: Option<u32>,
    cancel: &Cancel<'_>,
    progress: &mut dyn FnMut(Progress),
) -> core::result::Result<Restored, Unfinished<RestoreFailure>> {
    restore_asking(store, client, master, account_index, scan_to, cancel, Some(progress), || Err(Unfinished::Cancelled))
}

/// The restore shared by the three public forms. `cancelled` produces the
/// result returned on cancellation and is called only after `cancel` has
/// said stop.
#[allow(clippy::too_many_arguments)]
fn restore_asking<M: Medium, T: Transport, E: From<RestoreFailure>>(
    store: &mut Keystore<M>,
    client: &MeshClient<T>,
    master: &Secret<SEED_LEN>,
    account_index: u32,
    scan_to: Option<u32>,
    cancel: &Cancel<'_>,
    mut progress: Option<&mut dyn FnMut(Progress)>,
    cancelled: impl Fn() -> core::result::Result<(), E>,
) -> core::result::Result<Restored, E> {
    if cancel.stop() {
        cancelled()?;
    }
    let scope = match scan_to {
        // `scan_to` is inclusive; the parser refuses `u32::MAX`.
        Some(m) => ScanScope::RESTORE.with_ceiling(m.saturating_add(1)),
        None => ScanScope::RESTORE,
    };
    let at = Progress {
        account: 0,
        accounts: 1,
        position: 0,
        ceiling: scope.reach(None),
    };
    if let Some(report) = progress.as_deref_mut() {
        report(at);
    }
    let scanned = recon::watched(cancel, progress, at, |cancel| {
        recon::restore_account_index_with(client, master, account_index, &scope, cancel)
    });
    let found = match scanned {
        Ok(found) => found,
        // The scan was cancelled. Returned unchanged if `cancelled` returns
        // `Ok`, which only the non-cancellable form does.
        Err(failure @ RestoreFailure::CannotScan { cause: Error::Cancelled, .. }) => {
            cancelled()?;
            return Err(failure.into());
        }
        Err(failure) => return Err(failure.into()),
    };

    let cannot_store = |cause| RestoreFailure::CannotStore {
        tag: found.tag,
        cause,
    };

    if let Some(view) = store.view(&found.tag).map_err(cannot_store)? {
        return Ok(Restored {
            found,
            held_at: Some(view.wots_index),
        });
    }

    // Build the account at the found index in memory, then commit once.
    // `advance_to` refuses a target not strictly ahead, so it is skipped at
    // position 0.
    let mut account = Account::derive(master, account_index);
    if found.index.get() > WotsIndex::ZERO.get() {
        account.advance_to(found.index).map_err(cannot_store)?;
    }
    if cancel.stop() {
        cancelled()?;
    }
    store.add(account).map_err(cannot_store)?;
    Ok(Restored { found, held_at: None })
}
