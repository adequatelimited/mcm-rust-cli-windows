// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

#![cfg(all(feature = "native", not(miri)))]
//! Reconciliation: every divergence case against a scriptable chain, the
//! settle and re-sign policies, the acknowledgement gate, and the restore
//! scan's shape and bound.
//!
//! Requires `native` for the keystore and derivation; skipped under Miri for
//! WOTS+ cost and filesystem access.
//!
//! # The fake chain
//!
//! The fake is a `Transport`, so the real codec and `MeshClient` parse every
//! response; only the chain state (a tag at an address, absent, or
//! unreachable) is scripted.
//!
//! # Fixture values
//!
//! From fixture `F-address-widths` (group F): its master seed, account index
//! 0, its recorded `account_tag`, and its recorded `wots_address` (the key at
//! position 1).

#[path = "support/keystore_harness.rs"]
mod keystore_harness;
#[path = "support/chain.rs"]
mod chain;
#[path = "support/extension_export.rs"]
mod extension_export;

use chain::{access, addr_at, hexs, master, pos, tag1, Chain, ChainState, ADDRESS_AT_1, TAG};
use keystore_harness::{reopen, ScratchDir};
use mochimo_crypto::account::{Account, WotsIndex};
use mochimo_crypto::consts::{ADDR_TAG_LEN, MFEE};
use mochimo_crypto::keystore::{Disk, Figures, KeyAccess, Keystore, Pending};
use mochimo_crypto::mesh::{MeshClient, TxId};
use mochimo_crypto::recon::{
    self, AccountStatus, Cancel, ChainPosition, Diagnosis, Divergence, Expiry, Reservation,
    RestoreFailure, RollbackAcknowledgement, ScanScope, StoppedBy, Unfinished, DIVERGENCE_WINDOW,
    RECOVERY_CEILING,
};
use mochimo_crypto::tx::wire::{Destination, Transaction};
use mochimo_crypto::wallet::{OperatorAcknowledgement, Refused, Settlement, StartupRefusal, Unopened, Wallet};
use mochimo_crypto::{addr, derive, Error, Secret};

/// A store holding `F-address-widths`' derived account 0, at position 0.
fn store(name: &str) -> (ScratchDir, Keystore) {
    let dir = ScratchDir::new(name);
    let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(Account::derive(&master(), 0)).unwrap_or_else(|e| panic!("{e}"));
    (dir, ks)
}

// ---------------------------------------------------------------------------
// The two derivations agree
// ---------------------------------------------------------------------------

/// `Keystore::address_at` (through the store's `key_at`) and
/// `recon::derived_address_at` (from the master, no store) produce the same
/// addresses, anchored on group F's recorded `wots_address` at position 1.
#[test]
fn the_scan_and_the_store_derive_the_same_addresses() {
    let (_dir, ks) = store("recon-agree");
    let m = master();
    assert_eq!(
        ks.address_at(&TAG, pos(1), &access(&m)).unwrap_or_else(|e| panic!("{e}")),
        ADDRESS_AT_1,
        "position 1 is not group F's recorded wots_address"
    );
    for i in 0..6 {
        assert_eq!(
            ks.address_at(&TAG, pos(i), &access(&m)).unwrap_or_else(|e| panic!("{e}")),
            addr_at(i),
            "the store and the scan disagree at position {i}"
        );
    }
    // Position 0 is the implicit first address: tag half equal to hash half.
    assert_eq!(addr_at(0), addr::from_implicit(&TAG));
}

// ---------------------------------------------------------------------------
// I5 -- the restore scan
// ---------------------------------------------------------------------------

/// The explicit ceiling these tests walk. Walking the default ceiling in a
/// debug build would take minutes per exhausted scan; the default's value is
/// checked separately without walking it.
const WALKED: u32 = 20;

#[test]
fn the_restore_scan_stops_on_the_match_at_every_position_in_the_bound() {
    let scope = ScanScope::RESTORE.with_ceiling(WALKED);
    for i in 0..WALKED {
        let chain = Chain::new(&[(TAG, ChainState::At(addr_at(i), 1_000 + u64::from(i)))]);
        let client = MeshClient::new(chain);
        let found = recon::restore_account_index_with(&client, &master(), 0, &scope, &Cancel::NEVER)
            .unwrap_or_else(|e| panic!("position {i}: {e}"));
        assert_eq!(found.index, pos(i), "the scan found the wrong index for position {i}");
        assert_eq!(found.tag, TAG);
        assert_eq!(found.balance, 1_000 + u64::from(i));
        // One resolve, and the scan is local from there.
        assert_eq!(client.transport().calls(), 1, "position {i}: more than one query");
    }
}

/// `Cancel::NEVER` and a predicate that always answers `false` reach the same
/// result.
#[test]
fn a_cancel_that_never_fires_leaves_the_scan_exactly_as_it_was() {
    let scope = ScanScope::RESTORE.with_ceiling(WALKED);

    let client = MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(3), 1_003))]));
    let found = recon::restore_account_index_with(&client, &master(), 0, &scope, &Cancel::NEVER)
        .expect("a scan nobody cancels must find the index");

    let never = || false;
    let client = MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(3), 1_003))]));
    let same =
        recon::restore_account_index_with(&client, &master(), 0, &scope, &Cancel::when(&never))
            .expect("a predicate that never says stop must not stop the scan");

    assert_eq!(found.index, pos(3));
    assert_eq!(same.index, found.index, "the two forms of not cancelling disagree");
    assert_eq!(same.balance, found.balance);
    assert_eq!(same.tag, found.tag);
}

/// A cancel that fires stops the scan with `Error::Cancelled`, even though the
/// address is within the bound, and is not rendered as a fault.
#[test]
fn a_cancel_that_fires_stops_the_scan_and_reports_that_nothing_was_decided() {
    let scope = ScanScope::RESTORE.with_ceiling(WALKED);
    let client = MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(3), 1_003))]));
    let stop = || true;
    let err = recon::restore_account_index_with(&client, &master(), 0, &scope, &Cancel::when(&stop))
        .expect_err("a cancel that fires must not return an index");

    match &err {
        RestoreFailure::CannotScan { cause, .. } => assert_eq!(
            *cause,
            Error::Cancelled,
            "a cancel was reported under another cause"
        ),
        other => panic!("{other:?}"),
    }

    // A cancel is not rendered with the generic `CannotScan` wording.
    let text = err.to_string();
    assert!(text.contains("stopped before it found an index"), "{text}");
    assert!(!text.contains("fix the cause"), "a cancel is rendered as a fault: {text}");
    assert!(!text.contains("could not run"), "a cancel is rendered as a fault: {text}");
}

/// An exhausted bound and a cancel are reported differently: only the first
/// is `NoIndexReproducesTheAddress`.
#[test]
fn a_cancelled_scan_is_never_reported_as_a_bound_that_found_nothing() {
    let scope = ScanScope::RESTORE.with_ceiling(WALKED);
    let mut alien = ADDRESS_AT_1;
    alien[ADDR_TAG_LEN] ^= 0x01;

    let client = MeshClient::new(Chain::new(&[(TAG, ChainState::At(alien, 7))]));
    let exhausted =
        recon::restore_account_index_with(&client, &master(), 0, &scope, &Cancel::NEVER)
            .expect_err("an address no index reproduces must fail");
    assert!(
        matches!(exhausted, RestoreFailure::NoIndexReproducesTheAddress { .. }),
        "{exhausted:?}"
    );

    let stop = || true;
    let client = MeshClient::new(Chain::new(&[(TAG, ChainState::At(alien, 7))]));
    let cancelled =
        recon::restore_account_index_with(&client, &master(), 0, &scope, &Cancel::when(&stop))
            .expect_err("a cancel must fail");
    assert!(
        !matches!(cancelled, RestoreFailure::NoIndexReproducesTheAddress { .. }),
        "a cancelled scan was reported as an exhausted bound: {cancelled:?}"
    );
}

/// The predicate is asked once per position, and the walk ends where it says.
/// The address is at the last position in the bound, so a walk that ignored
/// the predicate would return an index.
#[test]
fn the_cancel_is_asked_once_per_position_and_the_walk_ends_where_it_says() {
    let scope = ScanScope::RESTORE.with_ceiling(WALKED);
    let client = MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(WALKED - 1), 5))]));

    let asked = std::cell::Cell::new(0u32);
    const STOP_AFTER: u32 = 4;
    let predicate = || {
        let n = asked.get();
        asked.set(n + 1);
        n >= STOP_AFTER
    };
    let err =
        recon::restore_account_index_with(&client, &master(), 0, &scope, &Cancel::when(&predicate))
            .expect_err("the walk must stop before the position holding the address");

    assert!(
        matches!(err, RestoreFailure::CannotScan { cause: Error::Cancelled, .. }),
        "{err:?}"
    );
    assert_eq!(
        asked.get(),
        STOP_AFTER + 1,
        "the predicate is asked once per position, up to and including the one that says stop"
    );
}

/// A cancelled diagnostic walk still reports the divergence, with the
/// position `Unlocated`.
#[test]
fn a_cancelled_diagnostic_still_reports_the_divergence_it_had_already_found() {
    let (_d, ks) = store("recon-cancel-diagnostic");
    let m = master();
    let mut alien = addr_at(0);
    alien[ADDR_TAG_LEN] ^= 0x01;
    let scope = ScanScope::DIAGNOSTIC.with_ceiling(WALKED);

    let stop = || true;
    let d = recon::reconcile_account_with(
        &ks,
        &MeshClient::new(Chain::new(&[(TAG, ChainState::At(alien, 1))])),
        &TAG,
        &access(&m),
        &scope,
        &Cancel::when(&stop),
    )
    .expect_err("a diverged account must be reported whether or not the diagnostic finished");

    assert!(
        matches!(
            d,
            Divergence::IndexMismatch {
                found: ChainPosition::Unlocated { .. },
                ..
            }
        ),
        "{d:?}"
    );
}

/// A stopped walk records what stopped it, and the report's wording follows
/// that record rather than assuming a derivation error.
#[test]
fn a_stopped_diagnostic_records_the_cause_rather_than_leaving_it_to_the_report() {
    let (_d, ks) = store("recon-stop-cause");
    let m = master();
    let mut alien = addr_at(0);
    alien[ADDR_TAG_LEN] ^= 0x01;
    let scope = ScanScope::DIAGNOSTIC.with_ceiling(WALKED);

    // (1) The control: a walk that reaches the scope's end records no stop.
    let finished = recon::reconcile_account_with(
        &ks,
        &MeshClient::new(Chain::new(&[(TAG, ChainState::At(alien, 1))])),
        &TAG,
        &access(&m),
        &scope,
        &Cancel::NEVER,
    )
    .expect_err("an alien address must diverge");
    match &finished {
        Divergence::IndexMismatch {
            found: ChainPosition::Unlocated { stopped, .. },
            ..
        } => assert_eq!(*stopped, None, "a walk that finished recorded a stop"),
        other => panic!("{other:?}"),
    }

    // (2) The same chain and scope, cancelled: the record says so.
    let stop = || true;
    let cancelled = recon::reconcile_account_with(
        &ks,
        &MeshClient::new(Chain::new(&[(TAG, ChainState::At(alien, 1))])),
        &TAG,
        &access(&m),
        &scope,
        &Cancel::when(&stop),
    )
    .expect_err("an alien address must diverge");
    match &cancelled {
        Divergence::IndexMismatch {
            found: ChainPosition::Unlocated { stopped, .. },
            ..
        } => {
            let s = stopped.expect("a cancelled walk must record that it stopped");
            assert_eq!(s.by, StoppedBy::Cancelled, "a cancel was recorded as another cause");
        }
        other => panic!("{other:?}"),
    }

    // (3) The wording follows the record: only `Derivation` is a failure.
    let text = cancelled.to_string();
    assert!(!text.contains("deriving index"), "a cancel rendered as a fault: {text}");
    assert!(!text.contains("derivation error"), "a cancel rendered as a fault: {text}");
    assert!(
        text.contains("stopped at index"),
        "a stopped diagnostic does not say it stopped: {text}"
    );
}

#[test]
fn restore_fails_rather_than_assuming_zero_on_every_unavailable_path() {
    // (1) the chain cannot be reached
    let client = MeshClient::new(Chain::new(&[(TAG, ChainState::Unreachable)]));
    let err = recon::restore_account_index(&client, &master(), 0).expect_err("unreachable must fail");
    assert!(matches!(err, RestoreFailure::ChainUnreachable { .. }), "{err:?}");

    // (2) the ledger has no entry for the tag
    let client = MeshClient::new(Chain::new(&[(TAG, ChainState::Absent)]));
    let err = recon::restore_account_index(&client, &master(), 0).expect_err("absent must fail");
    assert!(matches!(err, RestoreFailure::TagUnresolved { .. }), "{err:?}");

    // (3) the tag resolves to an address no index reproduces: the walked
    // bound is reported, and the answer is not index zero. Walked at an
    // explicit ceiling; the default's value is checked in
    // `the_recovery_ceiling_is_the_extensions_own_number`.
    let mut alien = ADDRESS_AT_1;
    alien[ADDR_TAG_LEN] ^= 0x01;
    let client = MeshClient::new(Chain::new(&[(TAG, ChainState::At(alien, 7))]));
    let err = recon::restore_account_index_with(&client, &master(), 0, &ScanScope::RESTORE.with_ceiling(WALKED), &Cancel::NEVER)
        .expect_err("alien must fail");
    match err {
        RestoreFailure::NoIndexReproducesTheAddress { scanned, .. } => {
            assert_eq!(scanned, WALKED, "the bound reported is not the bound walked");
        }
        other => panic!("{other:?}"),
    }

    // (4) control: with a reproducible address, the same call succeeds.
    let client = MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(3), 7))]));
    assert_eq!(
        recon::restore_account_index(&client, &master(), 0)
            .unwrap_or_else(|e| panic!("{e}"))
            .index,
        pos(3)
    );
}

/// A position one past the bound is not found, and the failure reports the
/// bound rather than guessing; the last position inside the bound is found.
/// The seed does own this tag, which is why the failure must not claim
/// otherwise.
#[test]
fn a_position_past_the_bound_fails_rather_than_being_guessed_at() {
    let scope = ScanScope::RESTORE.with_ceiling(WALKED);
    let past = addr_at(WALKED);
    let client = MeshClient::new(Chain::new(&[(TAG, ChainState::At(past, 1))]));
    let err = recon::restore_account_index_with(&client, &master(), 0, &scope, &Cancel::NEVER).expect_err("past the bound must fail");
    assert!(matches!(
        err,
        RestoreFailure::NoIndexReproducesTheAddress { scanned, .. } if scanned == WALKED
    ));
    // The last position inside the bound is found: no off-by-one.
    let last = addr_at(WALKED - 1);
    let client = MeshClient::new(Chain::new(&[(TAG, ChainState::At(last, 1))]));
    assert_eq!(
        recon::restore_account_index_with(&client, &master(), 0, &scope, &Cancel::NEVER)
            .unwrap_or_else(|e| panic!("{e}"))
            .index,
        pos(WALKED - 1)
    );
}

/// The recovery ceiling is 10,000, the browser extension's bound, checked as
/// a value and as rendered text without walking it.
///
/// A full walk at the default takes minutes in a debug build, so the walk is
/// exercised at smaller ceilings elsewhere in this file. Not covered: a clamp
/// inside the walk that capped large ceilings. The failure value is
/// constructed directly; its `scanned` field is `scope.ceiling`, which the
/// bounded tests check.
#[test]
fn the_recovery_ceiling_is_the_extensions_own_number() {
    assert_eq!(
        RECOVERY_CEILING, 10_000,
        "the recovery ceiling is the bound the shipped browser extension walks for the same \
         quantity (MasterSeed.deriveWotsIndexFromWotsAddrHash, endIndex = 10000); it is not \
         BIP-44's 20, which bounds unused addresses and not spends already made"
    );
    assert_eq!(ScanScope::RESTORE.ceiling, RECOVERY_CEILING, "restore's default scope is not the recovery ceiling");
    assert_eq!(ScanScope::RESTORE.window, None, "restore has no local index to centre a window on");
    // The window and the ceiling are separate quantities.
    assert_eq!(DIVERGENCE_WINDOW, 20, "the divergence window moved; only the ceiling was raised");
    assert_ne!(RECOVERY_CEILING, DIVERGENCE_WINDOW, "the two bounds coincide again, and the claim they differ is back to being untestable");

    // What a failing restore at the default ceiling says.
    let text = format!(
        "{}",
        RestoreFailure::NoIndexReproducesTheAddress {
            tag: TAG,
            address: ADDRESS_AT_1,
            scanned: RECOVERY_CEILING,
        }
    );
    assert!(text.contains("none of key indices 0 through 9999"), "the default walk is not counted:\n{text}");
    assert!(text.contains("spent 10000 or more times"), "the far-along cause does not carry the default:\n{text}");
    assert!(text.contains("does not own this tag"), "the wrong-seed cause is not named:\n{text}");
    assert!(text.contains("another chain"), "the wrong-chain cause is not named:\n{text}");
    println!("  recovery ceiling: {RECOVERY_CEILING} (the extension's endIndex), divergence window {DIVERGENCE_WINDOW}, 0 positions walked to pin either");
}

/// [`ScanScope::DIAGNOSTIC`]'s ceiling equals [`RECOVERY_CEILING`].
///
/// A chain address one past the window's high edge (71 with a local index of
/// 50) is found as `Ahead 21` through the ceiling. The walk covers the window
/// (41 derivations), then 30 more of the range: 72 in all.
#[test]
fn the_diagnostics_ceiling_follows_the_recovery_ceiling() {
    assert_eq!(
        ScanScope::DIAGNOSTIC.ceiling, RECOVERY_CEILING,
        "the diagnostic's ceiling no longer follows the recovery ceiling; a store restored at a \
         far-along index would then be described as Unlocated by the wallet that placed it"
    );
    assert_eq!(ScanScope::DIAGNOSTIC.window, Some(DIVERGENCE_WINDOW));

    // One past the window's high edge, found through the ceiling.
    let div = diagnose("recon-hazard2-ahead", 50, 71, &ScanScope::DIAGNOSTIC);
    match &div {
        Divergence::IndexMismatch { found: ChainPosition::Ahead { index, gap }, .. } => {
            assert_eq!(*index, pos(71), "{div:?}");
            assert_eq!(*gap, 21, "{div:?}");
        }
        other => panic!("the default diagnostic did not reach index 71: {other:?}"),
    }
    // The report names the direction.
    assert!(format!("{div}").contains("21 ahead of local"), "{div}");
    println!("  diagnostic ceiling: follows the recovery ceiling at {}, window {DIVERGENCE_WINDOW}; index 71 under a local of 50 is Ahead 21, not Unlocated", ScanScope::DIAGNOSTIC.ceiling);
}

// ---------------------------------------------------------------------------
// I4 -- reconciliation and the wallet gate
// ---------------------------------------------------------------------------

/// The healthy case: the chain holds the tag at the key the store would sign
/// with, so the wallet opens.
#[test]
fn a_wallet_opens_when_every_account_reconciles() {
    let (_dir, ks) = store("recon-ok");
    let client = MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(0), 9_000))]));
    let m = master();
    let w = Wallet::open(ks, client, Some(&m)).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(w.accounts().len(), 1);
    // By reference: `AccountStatus` is not `Copy`.
    match &w.accounts()[0].1 {
        AccountStatus::InSync { index, balance, .. } => {
            assert_eq!(*index, WotsIndex::ZERO);
            assert_eq!(*balance, 9_000);
        }
        other => panic!("{other:?}"),
    }
}

/// Every refusal path the constructor has, each by its own variant. Four go
/// through `Wallet::open`; the unlocatable-address case goes through the
/// reconciler `open` calls, at a small ceiling.
#[test]
fn the_wallet_refuses_to_open_on_every_unreconcilable_account() {
    let m = master();
    let mut refusals = 0usize;

    // local behind: the chain is at position 3, the store at 0
    let (_d1, ks) = store("recon-behind");
    let refusal = Wallet::open(
        ks,
        MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(3), 1))])),
        Some(&m),
    )
    .expect_err("local behind must refuse");
    assert!(matches!(
        refusal.diverged[0],
        Divergence::IndexMismatch {
            found: ChainPosition::Ahead { gap: 3, .. },
            ..
        }
    ), "{:?}", refusal.diverged[0]);
    refusals += 1;

    // The chain holds an address no index reproduces. `Wallet::open` always
    // uses `ScanScope::DIAGNOSTIC`, whose full walk is too slow for a debug
    // test, so this calls `reconcile_account_with` (which `open` calls) at a
    // small ceiling. `open` reaching `Unlocated` end to end is not covered.
    let (_d2, ks) = store("recon-alien");
    let mut alien = addr_at(0);
    alien[ADDR_TAG_LEN] ^= 0x01;
    let div = recon::reconcile_account_with(
        &ks,
        &MeshClient::new(Chain::new(&[(TAG, ChainState::At(alien, 1))])),
        &TAG,
        &access(&m),
        &ScanScope::DIAGNOSTIC.with_ceiling(WALKED),
        &Cancel::NEVER,
    )
    .expect_err("an alien address must diverge");
    assert!(matches!(
        div,
        Divergence::IndexMismatch {
            found: ChainPosition::Unlocated { .. },
            ..
        }
    ), "{div:?}");
    refusals += 1;

    // the ledger has no entry for the tag
    let (_d3, ks) = store("recon-absent");
    let refusal3 = Wallet::open(
        ks,
        MeshClient::new(Chain::new(&[(TAG, ChainState::Absent)])),
        Some(&m),
    )
    .expect_err("an absent tag must refuse");
    assert!(matches!(refusal3.diverged[0], Divergence::TagUnresolved { .. }));
    refusals += 1;

    // the chain cannot be reached
    let (_d4, ks) = store("recon-unreachable");
    let refusal4 = Wallet::open(
        ks,
        MeshClient::new(Chain::new(&[(TAG, ChainState::Unreachable)])),
        Some(&m),
    )
    .expect_err("an unreachable chain must refuse");
    assert!(matches!(refusal4.diverged[0], Divergence::ChainUnreachable { .. }));
    refusals += 1;

    // a derived account with no master to derive it from
    let (_d5, ks) = store("recon-nomaster");
    let refusal5 = Wallet::open(
        ks,
        MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(0), 1))])),
        None,
    )
    .expect_err("a derived account with no master must refuse");
    assert!(matches!(refusal5.diverged[0], Divergence::NoMasterForDerivedAccount { .. }));
    refusals += 1;

    assert_eq!(refusals, 5);
}

/// The refusal names every failing account, not only the first.
#[test]
fn the_refusal_reports_every_failing_account_not_the_first() {
    let dir = ScratchDir::new("recon-many");
    let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(Account::derive(&master(), 0)).unwrap_or_else(|e| panic!("{e}"));
    // Account 1, not `imported_account()`: the harness's imported account is
    // the same account derived at index 0, which the store would refuse.
    ks.add(Account::derive(&master(), 1)).unwrap_or_else(|e| panic!("{e}"));
    let tag1 = derive::derive_account_tag(&master(), 1);
    let m = master();
    let refusal = Wallet::open(
        ks,
        MeshClient::new(Chain::new(&[
            (TAG, ChainState::At(addr_at(3), 1)),
            (tag1, ChainState::Absent),
        ])),
        Some(&m),
    )
    .expect_err("two bad accounts must refuse");
    assert_eq!(refusal.diverged.len(), 2, "only one account was reported");
    assert_eq!(refusal.accounts, 2);
}

/// The rendered report names what diverged, both indices, the gap and the
/// action.
#[test]
fn the_divergence_report_names_what_diverged_by_how_much_and_what_to_do() {
    let (_dir, ks) = store("recon-message");
    let m = master();
    let refusal: StartupRefusal = Wallet::open(
        ks,
        MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(4), 1))])),
        Some(&m),
    )
    .expect_err("must refuse");
    let text = format!("{refusal}");

    // what diverged: the account, and both addresses
    assert!(text.contains(&hexs(&TAG)), "no tag in the report:\n{text}");
    assert!(text.contains(&hexs(&addr_at(0))), "the local address is not printed");
    assert!(text.contains(&hexs(&addr_at(4))), "the chain's address is not printed");
    // both indices, and the size of the gap
    assert!(text.contains("local index 0"), "the local index is not named");
    assert!(text.contains("key at index 4"), "the chain's index is not named");
    assert!(text.contains("4 ahead of local"), "the gap is not stated");
    // the stream identity, so two stores on one seed can be compared
    let stream = hexs(
        Keystore::open(_dir.path(), &keystore_harness::unlock())
            .map(|k| *k.stream_id(&TAG).unwrap_or_else(|e| panic!("{e}")).as_bytes())
            .unwrap_or_else(|e| panic!("{e}"))
            .as_slice(),
    );
    assert!(text.contains(&stream), "the key stream identity is not printed");
    // the action
    assert!(text.contains("ACTION:"), "no action is named");
    assert!(text.contains("Do NOT edit local state by hand"), "the action does not warn off hand edits");
    // Both causes an `Ahead` fits: older local state, or a second wallet.
    assert!(text.contains("SECOND WALLET"), "the ahead arm no longer names the second-wallet cause:\n{text}");
    assert!(text.contains("older copy"), "the ahead arm no longer names the older-local-state cause:\n{text}");
    // and the refusal explains itself rather than only refusing
    assert!(text.contains("WALLET WILL NOT START"), "the refusal does not say so");
    assert!(text.contains("three causes"), "the reason is not given");
    assert!(
        text.contains("Do not delete local state"),
        "the workaround I4's decision names is not warned against"
    );
}

/// Local ahead of the chain refuses and reports the direction.
#[test]
fn local_ahead_of_the_chain_refuses_and_says_which_direction() {
    let (dir, mut ks) = store("recon-ahead");
    // advance the store to 3 with no spend: local is now ahead of a chain
    // that still holds position 0.
    let _ = ks.persist_advance_to(&TAG, pos(3)).unwrap_or_else(|e| panic!("{e}"));
    drop(ks);
    let ks = reopen("recon ahead", dir.path())
        .result
        .unwrap_or_else(|e| panic!("{e}"));
    let m = master();
    let refusal = Wallet::open(
        ks,
        MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(0), 1))])),
        Some(&m),
    )
    .expect_err("local ahead must refuse");
    let text = format!("{refusal}");
    assert!(matches!(
        refusal.diverged[0],
        Divergence::IndexMismatch {
            found: ChainPosition::Behind { gap: 3, .. },
            ..
        }
    ), "{:?}", refusal.diverged[0]);
    assert!(text.contains("3 BEHIND local"), "the direction is not stated:\n{text}");
    assert!(text.contains("roll back to 0 through the acknowledged path"), "the rollback is not named:\n{text}");
    assert!(text.contains("has signed before"), "the rollback's cost is not named:\n{text}");
}

// ---------------------------------------------------------------------------
// The reservation states, settling, and re-signing
// ---------------------------------------------------------------------------

/// A store with a reservation open at position 0. The figures match the
/// balance of 5 its callers script, so the reservation reads live.
fn reserved(name: &str) -> (ScratchDir, Keystore) {
    let (dir, mut ks) = store(name);
    let _ = ks
        .persist_advance(&TAG, &[0xD1; 32], Figures { reserved_balance: 5, blk_to_live: 0 })
        .unwrap_or_else(|e| panic!("{e}"));
    (dir, ks)
}

/// The live diagnosis `reserved()`'s reservation reads as, against the
/// balance of 5 its callers script.
fn live_at_five() -> Reservation {
    Reservation::Recorded(Diagnosis {
        figures: Figures { reserved_balance: 5, blk_to_live: 0 },
        balance_moved: false,
        balance_now: 5,
        expiry: Expiry::NoExpiry,
    })
}

/// A reservation with the chain still at the old address is `SpendOutstanding`
/// — not divergence. The wallet opens: a spend in flight is a known state.
#[test]
fn a_reservation_with_the_spend_not_landed_is_outstanding_not_divergence() {
    let (_dir, ks) = reserved("recon-outstanding");
    let m = master();
    let w = Wallet::open(
        ks,
        MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(0), 5))])),
        Some(&m),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    assert!(matches!(
        w.accounts()[0].1,
        AccountStatus::SpendOutstanding { .. }
    ));
}

/// A reservation with the chain at the **change** key's address is
/// `SpendLanded`, and `settle_if_landed` clears it on that one observation.
#[test]
fn settling_takes_one_observation_of_the_change_address() {
    let (_dir, ks) = reserved("recon-settle");
    let m = master();
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5))]);
    let mut w = Wallet::open(ks, MeshClient::new(chain), Some(&m)).unwrap_or_else(|e| panic!("{e}"));

    // Not landed yet: nothing is cleared, and the verdict rides with it.
    assert_eq!(
        w.settle_if_landed(&TAG, &access(&m)).unwrap_or_else(|e| panic!("{e}")),
        Settlement::StillOutstanding {
            spent_index: WotsIndex::ZERO,
            reservation: live_at_five(),
        }
    );

    // The chain moves to the change key: one observation settles it.
    w.client().transport().set(TAG, ChainState::At(addr_at(1), 4));
    assert_eq!(
        w.settle_if_landed(&TAG, &access(&m)).unwrap_or_else(|e| panic!("{e}")),
        Settlement::Settled {
            spent_index: WotsIndex::ZERO,
            index: pos(1)
        }
    );
    // The store agrees: no reservation, index 1, and the settled block
    // retained with its figures.
    let v = w.store().view(&TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("gone"));
    assert_eq!(v.wots_index, pos(1));
    assert!(v.pending.is_none());
    assert_eq!(
        v.settled,
        Some(Pending {
            spent_index: WotsIndex::ZERO,
            digest: [0xD1; 32],
            figures: Some(Figures { reserved_balance: 5, blk_to_live: 0 }),
        }),
        "memory: the settled block was not retained with its figures"
    );
}

/// A retained settled block does not block the next spend, and the next
/// reservation replaces it.
#[test]
fn a_settled_block_does_not_block_the_next_spend_and_is_overwritten_by_it() {
    let (_dir, ks) = store("recon-freeze");
    let m = master();
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    let mut w = Wallet::open(ks, MeshClient::new(chain), Some(&m)).unwrap_or_else(|e| panic!("{e}"));
    let dsts = vec![Destination {
        tag: [0x6b; ADDR_TAG_LEN],
        reference: [0; 16],
        amount: 1_000_000,
    }];
    let plan = w.plan(&TAG, &access(&m), dsts.clone(), MFEE, 0).unwrap_or_else(|e| panic!("plan: {e}"));
    let first = plan.figures();
    let _signed = w.reserve_and_sign(&plan, access(&m)).unwrap_or_else(|e| panic!("reserve_and_sign: {e}"));
    w.client().transport().set(TAG, ChainState::At(addr_at(1), 4_000_000));
    assert!(matches!(
        w.settle_if_landed(&TAG, &access(&m)).unwrap_or_else(|e| panic!("{e}")),
        Settlement::Settled { .. }
    ));
    let v = w.store().view(&TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("gone"));
    assert_eq!(v.pending, None);
    assert_eq!(v.settled.map(|s| s.figures), Some(Some(first)), "the settle did not retain the block with the plan's figures");

    // The next spend is NOT refused.
    let plan2 = w
        .plan(&TAG, &access(&m), dsts, MFEE, 0)
        .unwrap_or_else(|e| panic!("a retained settled block blocked the next spend: {e} (the freeze the retained block must not cause)"));
    let _signed2 = w
        .reserve_and_sign(&plan2, access(&m))
        .unwrap_or_else(|e| panic!("a retained settled block blocked the next reservation: {e}"));
    let v = w.store().view(&TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("gone"));
    assert_eq!(v.wots_index, pos(2));
    assert_eq!(
        v.pending.map(|p| (p.spent_index, p.figures)),
        Some((pos(1), Some(plan2.figures()))),
        "the second reservation is not at index 1 with the second plan's figures"
    );
    assert_eq!(v.settled, None, "the new reservation did not release the retained block");
    println!("  settled block: spend, settle, spend again -- the second reservation overwrote the retained block");
}

/// A reverted settle is reported as `Behind` with the retained block.
///
/// The main case settles, reopens the store from disk, then meets a chain
/// back at the spent address: `Behind { index: 0, gap: 1 }` carrying the
/// block, and a report naming the digest, both figures, both causes (a reorg,
/// or a settle observed on a node not sharing this chain) and the actions.
/// Three controls carry `reverted_settle: None` and none of those sentences:
/// a `Behind` with no retained block, a retained block with the chain ahead,
/// and a retained block at a different index than the chain's.
#[test]
fn a_reverted_settle_is_reported_behind_with_the_retained_block_and_every_cause() {
    const SENTENCES: [&str; 4] = ["recorded a SETTLE", "may yet land", "resubmit", "Keep any copy"];
    let m = master();
    let dsts = || {
        vec![Destination {
            tag: [0x6b; ADDR_TAG_LEN],
            reference: [0; 16],
            amount: 1_000_000,
        }]
    };
    // Reserve at the store's index with block-to-live 4242 and settle on one
    // observation of the change key; hand back what was reserved.
    let reserve_and_settle = |w: &mut Wallet<Disk, Chain>, at: u32| -> Pending {
        w.client().transport().set_tip(4_241);
        let plan = w.plan(&TAG, &access(&m), dsts(), MFEE, 4_242).unwrap_or_else(|e| panic!("plan: {e}"));
        let block = Pending {
            spent_index: pos(at),
            digest: plan.digest(),
            figures: Some(plan.figures()),
        };
        let _ = w.reserve_and_sign(&plan, access(&m)).unwrap_or_else(|e| panic!("reserve_and_sign: {e}"));
        w.client().transport().set(TAG, ChainState::At(addr_at(at + 1), 4_000_000));
        assert!(matches!(w.settle_if_landed(&TAG, &access(&m)).unwrap_or_else(|e| panic!("{e}")), Settlement::Settled { .. }));
        block
    };

    // The main arm.
    let (dir, ks) = store("recon-reverted");
    let mut w = Wallet::open(ks, MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))])), Some(&m))
        .unwrap_or_else(|e| panic!("{e}"));
    let block = reserve_and_settle(&mut w, 0);
    drop(w);
    let ks = reopen("recon reverted", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let refusal = Wallet::open(ks, MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))])), Some(&m))
        .expect_err("a reverted settle must refuse");
    match &refusal.diverged[0] {
        Divergence::IndexMismatch {
            found: ChainPosition::Behind { index, gap },
            reverted_settle,
            ..
        } => {
            assert_eq!((index.get(), *gap), (0, 1));
            assert_eq!(*reverted_settle, Some(block), "the retained block is not on the report");
        }
        other => panic!("not a Behind with the retained block: {other:?}"),
    }
    let text = format!("{refusal}");
    let digest_hex = hexs(&block.digest);
    for needle in [
        "recorded a SETTLE at index 0",
        digest_hex.as_str(),
        "reserved balance 5000000 nanoMCM, block-to-live 4242",
        "reorg",
        "does not share this chain",
        "may yet land",
        "only one key 0 may ever give",
        "resubmit_reverted_settle",
        "Keep any copy",
        "wait for the spend to land and reconcile again",
        "1 BEHIND local",
    ] {
        assert!(text.contains(needle), "the reverted-settle report does not say {needle:?}:\n{text}");
    }

    // Control 1: a Behind with no retained block.
    let (d1, mut ks1) = store("recon-reverted-none");
    let _ = ks1.persist_advance_to(&TAG, pos(3)).unwrap_or_else(|e| panic!("{e}"));
    drop(ks1);
    let ks1 = reopen("recon reverted none", d1.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let r1 = Wallet::open(ks1, MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(0), 1))])), Some(&m))
        .expect_err("local ahead must refuse");
    assert!(matches!(
        r1.diverged[0],
        Divergence::IndexMismatch { found: ChainPosition::Behind { gap: 3, .. }, reverted_settle: None, .. }
    ), "{:?}", r1.diverged[0]);
    let t1 = format!("{r1}");
    for s in SENTENCES {
        assert!(!t1.contains(s), "control 1 (no retained block) says {s:?}:\n{t1}");
    }

    // Control 2: a retained block with the chain AHEAD.
    let (d2, ks2) = store("recon-reverted-ahead");
    let mut w2 = Wallet::open(ks2, MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))])), Some(&m))
        .unwrap_or_else(|e| panic!("{e}"));
    let _ = reserve_and_settle(&mut w2, 0);
    drop(w2);
    let ks2 = reopen("recon reverted ahead", d2.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let r2 = Wallet::open(ks2, MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(5), 1))])), Some(&m))
        .expect_err("chain ahead must refuse");
    assert!(matches!(
        r2.diverged[0],
        Divergence::IndexMismatch { found: ChainPosition::Ahead { gap: 4, .. }, reverted_settle: None, .. }
    ), "{:?}", r2.diverged[0]);
    let t2 = format!("{r2}");
    for s in SENTENCES {
        assert!(!t2.contains(s), "control 2 (chain ahead of a retained block) says {s:?}:\n{t2}");
    }

    // Control 3: a retained block at index 1, the chain at index 0: a
    // Behind by two, not at the block's index.
    let (d3, mut ks3) = store("recon-reverted-other-index");
    let _ = ks3.persist_advance_to(&TAG, pos(1)).unwrap_or_else(|e| panic!("{e}"));
    let mut w3 = Wallet::open(ks3, MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(1), 5_000_000))])), Some(&m))
        .unwrap_or_else(|e| panic!("{e}"));
    let block3 = reserve_and_settle(&mut w3, 1);
    assert_eq!(block3.spent_index, pos(1));
    drop(w3);
    let ks3 = reopen("recon reverted other", d3.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let r3 = Wallet::open(ks3, MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))])), Some(&m))
        .expect_err("chain two behind must refuse");
    assert!(matches!(
        r3.diverged[0],
        Divergence::IndexMismatch { found: ChainPosition::Behind { gap: 2, .. }, reverted_settle: None, .. }
    ), "the retained block at index 1 was reported for a chain at index 0: {:?}", r3.diverged[0]);
    let t3 = format!("{r3}");
    for s in SENTENCES {
        assert!(!t3.contains(s), "control 3 (retained block at another index) says {s:?}:\n{t3}");
    }
    println!("  reverted settle: Behind by one carries the retained block, its digest and both figures, both causes, both halves; three controls carry none");
}

/// A reservation is dead when the balance moved or the tip reached the
/// block-to-live. Each reservation is made through `plan` and
/// `reserve_and_sign`. Scenario E is an unreadable tip (neither dead nor
/// live), H is dead by both causes, and F/G check chain call counts: one read
/// after `open` for a zero block-to-live, two for a non-zero one.
#[test]
fn a_reservation_is_dead_when_the_balance_moved_or_the_tip_reached_the_block_to_live() {
    let m = master();
    // A store with a reservation made through the wallet at `btl`, against a
    // chain holding 5,000,000 at the spent address.
    let reserve = |name: &str, btl: u64| -> ScratchDir {
        let (dir, ks) = store(name);
        let mut w = Wallet::open(ks, MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))])), Some(&m))
            .unwrap_or_else(|e| panic!("{e}"));
        let plan = w
            .plan(&TAG, &access(&m), vec![Destination { tag: [0x6b; ADDR_TAG_LEN], reference: [0; 16], amount: 1_000_000 }], MFEE, btl)
            .unwrap_or_else(|e| panic!("plan: {e}"));
        if btl != 0 {
            w.client().transport().set_tip(btl - 1);
        }
        assert_eq!(plan.figures(), Figures { reserved_balance: 5_000_000, blk_to_live: btl });
        let _ = w.reserve_and_sign(&plan, access(&m)).unwrap_or_else(|e| panic!("{e}"));
        dir
    };
    struct Case {
        name: &'static str,
        btl: u64,
        balance_after: u64,
        tip_after: Option<u64>,
        dead: bool,
        calls_after_open: usize,
    }
    let cases = [
        Case { name: "A", btl: 0, balance_after: 6_000_000, tip_after: Some(100), dead: true, calls_after_open: 1 },
        Case { name: "B", btl: 4_242, balance_after: 5_000_000, tip_after: Some(4_242), dead: true, calls_after_open: 2 },
        Case { name: "C", btl: 0, balance_after: 5_000_000, tip_after: Some(100), dead: false, calls_after_open: 1 },
        Case { name: "D", btl: 4_242, balance_after: 5_000_000, tip_after: Some(4_241), dead: false, calls_after_open: 2 },
        Case { name: "E", btl: 4_242, balance_after: 5_000_000, tip_after: None, dead: false, calls_after_open: 2 },
        Case { name: "H", btl: 4_242, balance_after: 6_000_000, tip_after: Some(4_242), dead: true, calls_after_open: 2 },
    ];
    let mut driven = 0usize;
    for c in &cases {
        let dir = reserve(&format!("recon-dead-{}", c.name), c.btl);
        let ks = reopen("recon dead", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
        let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), c.balance_after))]);
        if let Some(tip) = c.tip_after {
            chain.set_tip(tip);
        }
        let mut w = Wallet::open(ks, MeshClient::new(chain), Some(&m)).unwrap_or_else(|e| panic!("{}: a dead reservation is still an Ok state, and open refused: {e}", c.name));
        assert_eq!(w.client().transport().calls(), c.calls_after_open, "{}: chain calls after open", c.name);
        let AccountStatus::SpendOutstanding { reservation, .. } = &w.accounts()[0].1 else {
            panic!("{}: not outstanding: {:?}", c.name, w.accounts()[0].1)
        };
        let Reservation::Recorded(d) = reservation else { panic!("{}: figures not recorded", c.name) };
        let d = d.clone();
        assert_eq!(d.figures, Figures { reserved_balance: 5_000_000, blk_to_live: c.btl }, "{}", c.name);
        assert_eq!(d.balance_moved, c.balance_after != 5_000_000, "{}: balance_moved", c.name);
        assert_eq!(d.balance_now, c.balance_after, "{}", c.name);
        let expected_expiry = match (c.btl, c.tip_after) {
            (0, _) => Expiry::NoExpiry,
            (btl, Some(tip)) if tip >= btl => Expiry::Reached { tip },
            (_, Some(tip)) => Expiry::Below { tip },
            (_, None) => match &d.expiry {
                // The cause is the fake's own refusal; what is asserted is the arm.
                Expiry::Unreadable { cause } => Expiry::Unreadable { cause: cause.clone() },
                other => panic!("{}: an unreadable tip was read as {other:?}", c.name),
            },
        };
        assert_eq!(d.expiry, expected_expiry, "{}: expiry", c.name);
        assert_eq!(d.is_dead(), c.dead, "{}: is_dead", c.name);
        // settle carries the same verdict and moves nothing.
        match w.settle_if_landed(&TAG, &access(&m)).unwrap_or_else(|e| panic!("{}: {e}", c.name)) {
            Settlement::StillOutstanding { spent_index, reservation } => {
                assert_eq!(spent_index, WotsIndex::ZERO);
                assert_eq!(reservation, Reservation::Recorded(d), "{}: settle's verdict differs from open's", c.name);
            }
            other => panic!("{}: settle did something with a reservation the chain never confirmed: {other:?}", c.name),
        }
        let v = w.store().view(&TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("gone"));
        assert!(v.wots_index == pos(1) && v.pending.is_some(), "{}: settle moved the store", c.name);
        driven += 1;
    }
    assert_eq!(driven, 6);
    println!("  dead reservations: 6 scenarios -- moved balance, tip reached, two live controls, an unreadable tip, both causes -- classified from the store and the chain alone");
}

/// A version-3 reservation opens as `SpendOutstanding` with
/// `Reservation::Unrecorded`, makes no tip read, and `settle_if_landed`
/// neither settles nor writes, so the store stays version 3 on disk.
#[test]
fn a_migrated_reservation_declines_to_classify() {
    const IMAGE: &[u8] = include_bytes!("../testdata/keystore_v3_reserved_snapshot.bin");
    let m = master();
    let dir = ScratchDir::new("recon-migrated");
    drop(keystore_harness::create(dir.path()).unwrap_or_else(|e| panic!("{e}")));
    dir.write_snapshot(IMAGE);
    let ks = reopen("recon migrated", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    let mut w = Wallet::open(ks, MeshClient::new(chain), Some(&m)).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        matches!(&w.accounts()[0].1, AccountStatus::SpendOutstanding { reservation: Reservation::Unrecorded, .. }),
        "a version-3 reservation was classified: {:?}",
        w.accounts()[0].1
    );
    assert_eq!(w.client().transport().calls(), 1, "an unrecorded expiry must not read the tip");
    assert!(matches!(
        w.settle_if_landed(&TAG, &access(&m)).unwrap_or_else(|e| panic!("{e}")),
        Settlement::StillOutstanding { reservation: Reservation::Unrecorded, .. }
    ));
    assert_eq!(w.store().upgraded_from(), None, "settle wrote when nothing settled");
    drop(w);
    assert_eq!(dir.snapshot_bytes(), IMAGE, "the version-3 store moved on disk under read-only commands");
    println!("  migrated reservation: outstanding, unclassified, one chain read, nothing written");
}

/// `resign_pending` recovers a lost retry artifact.
///
/// After reserving at index 0 and losing the artifact, the index is at 1
/// while the funds are still at address(0), reachable only by the key at 0,
/// so re-signing the same plan is the only way to move them.
///
/// Asserts:
///  * the rebuilt bytes are byte-identical to the lost ones (WOTS+ signing
///    is deterministic, so this is one signature produced twice);
///  * a plan that does not hash to the reserved digest is refused;
///  * it needs no receipt and persists nothing.
#[test]
fn resigning_a_reservation_reproduces_the_lost_artifact_byte_for_byte() {
    let (_dir, ks) = store("recon-resign");
    let m = master();
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    let mut w = Wallet::open(ks, MeshClient::new(chain), Some(&m)).unwrap_or_else(|e| panic!("{e}"));

    let dsts = vec![Destination {
        tag: [0x6b; ADDR_TAG_LEN],
        reference: [0; 16],
        amount: 1_000_000,
    }];
    let plan = w
        .plan(&TAG, &access(&m), dsts.clone(), MFEE, 0)
        .unwrap_or_else(|e| panic!("plan: {e}"));
    let original = w
        .reserve_and_sign(&plan, access(&m))
        .unwrap_or_else(|e| panic!("reserve_and_sign: {e}"));
    let lost = original.wire().to_vec();
    drop(original); // the artifact is lost

    // Recover from the same plan parameters alone.
    let recovered = w
        .resign_pending(&TAG, &access(&m), dsts.clone(), MFEE, 0)
        .unwrap_or_else(|e| panic!("resign_pending: {e}"));
    assert_eq!(
        recovered.wire(),
        &lost[..],
        "the recovered artifact is not byte-identical to the lost one; the whole safety \
         argument is that this is ONE signature produced twice"
    );

    // It persisted nothing and needed no receipt: the reservation is still
    // open and the index has not moved.
    let v = w.store().view(&TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("gone"));
    assert_eq!(v.wots_index, pos(1));
    assert_eq!(v.pending.map(|p| p.spent_index), Some(WotsIndex::ZERO));

    // And it is idempotent -- a third call is the same bytes again.
    let again = w
        .resign_pending(&TAG, &access(&m), dsts, MFEE, 0)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(again.wire(), &lost[..]);
}

/// A plan that is not the reserved one is refused, so `resign_pending` can
/// never produce a second signature under the reserved key.
#[test]
fn resigning_refuses_a_plan_that_is_not_the_reserved_one() {
    let (_dir, ks) = store("recon-resign-wrong");
    let m = master();
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    let mut w = Wallet::open(ks, MeshClient::new(chain), Some(&m)).unwrap_or_else(|e| panic!("{e}"));

    let plan = w
        .plan(
            &TAG,
            &access(&m),
            vec![Destination { tag: [0x6b; ADDR_TAG_LEN], reference: [0; 16], amount: 1_000_000 }],
            MFEE,
            0,
        )
        .unwrap_or_else(|e| panic!("{e}"));
    let _ = w.reserve_and_sign(&plan, access(&m)).unwrap_or_else(|e| panic!("{e}"));

    // A different AMOUNT -- everything else identical.
    assert!(
        matches!(
            w.resign_pending(
                &TAG,
                &access(&m),
                vec![Destination { tag: [0x6b; ADDR_TAG_LEN], reference: [0; 16], amount: 2_000_000 }],
                MFEE,
                0,
            ),
            Err(Error::DigestMismatch)
        ),
        "a spend that was never reserved borrowed the reserved key"
    );
    // A different DESTINATION.
    assert!(matches!(
        w.resign_pending(
            &TAG,
            &access(&m),
            vec![Destination { tag: [0x6c; ADDR_TAG_LEN], reference: [0; 16], amount: 1_000_000 }],
            MFEE,
            0,
        ),
        Err(Error::DigestMismatch)
    ));
    // And with nothing reserved at all.
    let (_d2, ks2) = store("recon-resign-none");
    let chain2 = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    let mut w2 = Wallet::open(ks2, MeshClient::new(chain2), Some(&m)).unwrap_or_else(|e| panic!("{e}"));
    assert!(matches!(
        w2.resign_pending(
            &TAG,
            &access(&m),
            vec![Destination { tag: [0x6b; ADDR_TAG_LEN], reference: [0; 16], amount: 1 }],
            MFEE,
            0,
        ),
        Err(Error::NothingPending)
    ));
}

/// A reservation with the chain at neither address is divergence, not a
/// spend state: something moved this tag that this wallet did not.
#[test]
fn a_reservation_with_the_chain_at_neither_address_is_divergence() {
    let (_dir, ks) = reserved("recon-unexplained");
    let m = master();
    let refusal = Wallet::open(
        ks,
        MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(5), 5))])),
        Some(&m),
    )
    .expect_err("must refuse");
    assert!(matches!(refusal.diverged[0], Divergence::ReservationUnexplained { .. }));
    let text = format!("{refusal}");
    assert!(text.contains("Compare the key stream"), "no action:\n{text}");
    // The position is rendered, not `{:?}`: reserved at 0, so the window
    // is centred on the change index 1, and the chain at 5 is 4 ahead of it.
    assert!(
        text.contains("the chain's address IS this seed's key at index 5 -- 4 ahead of local"),
        "the reservation report does not render where the chain's address sits:\n{text}"
    );
    assert!(!text.contains("Ahead {"), "the reservation report renders the derived Debug:\n{text}");
}

/// The node's "account not found" is not treated as the ledger's absence at
/// either the reconcile or the restore site (`recon`'s module doc, fact 3):
/// both reports name the three readings and prefer none.
#[test]
fn a_node_that_does_not_resolve_a_tag_is_not_reported_as_never_funded() {
    let m = master();

    // The reconcile site, through the wallet's refusal.
    let (_d, ks) = store("recon-unresolved");
    let refusal = Wallet::open(
        ks,
        MeshClient::new(Chain::new(&[(TAG, ChainState::Absent)])),
        Some(&m),
    )
    .expect_err("an unresolved tag must refuse");
    assert!(
        matches!(refusal.diverged[0], Divergence::TagUnresolved { local: WotsIndex::ZERO, .. }),
        "{:?}",
        refusal.diverged[0]
    );
    let text = format!("{refusal}");
    for needle in ["did not resolve this tag", "ZERO balance", "lookup itself failed", "ask again"] {
        assert!(text.contains(needle), "the refusal does not carry {needle:?}:\n{text}");
    }
    for stale in ["NEVER been funded", "absence means", "create it rather than"] {
        assert!(
            !text.contains(stale),
            "the refusal still asserts {stale:?} -- the node's answer is read as the ledger's \
             absence:\n{text}"
        );
    }

    // The restore site.
    let client = MeshClient::new(Chain::new(&[(TAG, ChainState::Absent)]));
    let err = recon::restore_account_index(&client, &m, 0).expect_err("an unresolved tag must fail");
    assert!(matches!(err, RestoreFailure::TagUnresolved { tag: TAG }), "{err:?}");
    let text = format!("{err}");
    for needle in ["did not resolve this tag", "ZERO balance", "lookup itself failed", "ask again", "not at 0"] {
        assert!(text.contains(needle), "restore's failure does not carry {needle:?}:\n{text}");
    }
    for stale in ["so it has never been funded", "create it rather than restoring it"] {
        assert!(!text.contains(stale), "restore's failure still says {stale:?}:\n{text}");
    }
}

/// The `Ahead` report excludes a crash between signing and saving at every
/// gap. The index and its reservation are written durably before a
/// signature exists (I2), so an interrupted spend shows up as a reservation
/// state, never as an `IndexMismatch`. Checked at gaps 1 and 3.
#[test]
fn the_ahead_arm_excludes_the_crash_cause_at_every_gap() {
    let one = diagnose("recon-ahead-gap1", 0, 1, &ScanScope::DIAGNOSTIC);
    let three = diagnose("recon-ahead-gap3", 0, 3, &ScanScope::DIAGNOSTIC);
    for (d, gap) in [(&one, 1u32), (&three, 3)] {
        assert!(
            matches!(d, Divergence::IndexMismatch { found: ChainPosition::Ahead { gap: g, .. }, .. } if *g == gap),
            "{d:?}"
        );
        let text = format!("{d}");
        assert!(
            text.contains("cannot leave this state at any gap"),
            "gap {gap}: the crash cause is not excluded:\n{text}"
        );
        assert!(
            !text.contains("more than one cannot be a crash"),
            "gap {gap}: the gap-conditional sentence is back, and at gap 1 it is irrelevant:\n{text}"
        );
    }
}

/// A divergence report names the balance at stake. Two accounts with
/// distinct non-zero balances, so a constant cannot pass.
#[test]
fn a_divergence_report_names_the_balance_at_stake() {
    let m = master();
    let (_d1, ks) = store("recon-balance-mismatch");
    let refusal = Wallet::open(
        ks,
        MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(3), 123_456))])),
        Some(&m),
    )
    .expect_err("must refuse");
    assert!(
        matches!(refusal.diverged[0], Divergence::IndexMismatch { balance: 123_456, .. }),
        "{:?}",
        refusal.diverged[0]
    );
    let text = format!("{refusal}");
    assert!(
        text.contains("123456 nanoMCM"),
        "the index-mismatch report does not name the balance at stake:\n{text}"
    );

    let (_d2, ks2) = reserved("recon-balance-reservation");
    let refusal2 = Wallet::open(
        ks2,
        MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(5), 654_321))])),
        Some(&m),
    )
    .expect_err("must refuse");
    assert!(
        matches!(refusal2.diverged[0], Divergence::ReservationUnexplained { balance: 654_321, .. }),
        "{:?}",
        refusal2.diverged[0]
    );
    let text2 = format!("{refusal2}");
    assert!(
        text2.contains("654321 nanoMCM"),
        "the reservation report does not name the balance at stake:\n{text2}"
    );
}

// ---------------------------------------------------------------------------
// The divergence window, the raised ceiling, and the verified index
// ---------------------------------------------------------------------------

/// A store holding `F-address-widths`' derived account 0 at position `local`,
/// reopened, so the diagnostic reads the index off disk as the wallet would.
/// A rollback acknowledgement exists only for a divergence the walk found
/// behind the local index. It is refused for another tag, refused when the
/// chain has moved since, and otherwise moves the store back to exactly the
/// found index, durably.
#[test]
fn a_rollback_is_acknowledged_only_behind_local_and_rechecked_at_the_write() {
    let m = master();
    let scope = ScanScope::DIAGNOSTIC;
    let (dir, mut ks) = store_at("recon-rollback", 22);
    let at = |i: u32| MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(i), 1))]));
    let client = at(20);
    let d = recon::reconcile_account_with(&ks, &client, &TAG, &access(&m), &scope, &Cancel::NEVER).expect_err("diverged");
    assert!(OperatorAcknowledgement::of(&d).is_none(), "a behind divergence produced an advance");
    let ack = RollbackAcknowledgement::of(&d).unwrap_or_else(|| panic!("behind has a rollback target: {d:?}"));
    assert_eq!((ack.tag(), ack.target()), (TAG, pos(20)));

    let other = derive::derive_account_tag(&m, 1);
    assert!(
        matches!(
            recon::rollback_after_operator_review(&mut ks, &client, &other, &access(&m), ack, &scope, &Cancel::NEVER),
            Err(Error::AcknowledgementDoesNotMatch)
        ),
        "another tag's acknowledgement was applied"
    );
    assert!(
        matches!(
            recon::rollback_after_operator_review(&mut ks, &at(21), &TAG, &access(&m), ack, &scope, &Cancel::NEVER),
            Err(Error::AcknowledgementDoesNotMatch)
        ),
        "a stale acknowledgement was applied after the chain moved"
    );
    let view = |ks: &Keystore| ks.view(&TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("gone"));
    assert_eq!(view(&ks).wots_index, pos(22), "a refused rollback moved the index");

    let back = recon::rollback_after_operator_review(&mut ks, &client, &TAG, &access(&m), ack, &scope, &Cancel::NEVER)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(back, pos(20));
    assert!(matches!(recon::reconcile_account(&ks, &client, &TAG, &access(&m)), Ok(AccountStatus::InSync { .. })));
    assert!(matches!(
        recon::rollback_after_operator_review(&mut ks, &client, &TAG, &access(&m), ack, &scope, &Cancel::NEVER),
        Err(Error::NothingToReconcile)
    ));
    drop(ks);
    let ks = reopen("recon rollback reopen", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(view(&ks).wots_index, pos(20), "the rollback did not reach disk");

    // The chain ahead of local has an advance and no rollback.
    let (_d2, ks2) = store_at("recon-rollback-ahead", 0);
    let da = recon::reconcile_account_with(&ks2, &at(3), &TAG, &access(&m), &scope, &Cancel::NEVER).expect_err("diverged");
    assert!(OperatorAcknowledgement::of(&da).is_some());
    assert!(RollbackAcknowledgement::of(&da).is_none(), "an ahead divergence produced a rollback");
}

fn store_at(name: &str, local: u32) -> (ScratchDir, Keystore) {
    let (dir, mut ks) = store(name);
    if local > 0 {
        let _ = ks.persist_advance_to(&TAG, pos(local)).unwrap_or_else(|e| panic!("{e}"));
    }
    drop(ks);
    let ks = reopen(name, dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    (dir, ks)
}

/// The diagnostic against a chain holding the tag at `chain`, for a store at
/// `local`, under `scope`.
fn diagnose(name: &str, local: u32, chain: u32, scope: &ScanScope) -> Divergence {
    let (_dir, ks) = store_at(name, local);
    let client = MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(chain), 1))]));
    recon::reconcile_account_with(&ks, &client, &TAG, &access(&master()), scope, &Cancel::NEVER)
        .expect_err("local and chain differ, so this must be a divergence")
}

/// The diagnostic is a window around the local index, not a walk from zero:
/// a store at 22 with the chain at 24 is found as a gap of two.
///
/// Both window edges are checked in both directions, the recovery range is
/// shown to be unioned in (a chain at 3 under a store at 50 is `Behind`), and
/// the unlocated text names what was walked and all three causes.
///
/// Two scopes are used because the default ceiling hides the window's
/// edges: `w` is the window with a ceiling of zero, so only the window finds
/// anything, and `d` is the window over a ceiling of [`WALKED`].
#[test]
fn the_divergence_diagnostic_is_a_window_around_local_not_a_walk_from_zero() {
    assert_eq!(DIVERGENCE_WINDOW, 20, "the cases below are written for a window of 20");
    assert_eq!(RECOVERY_CEILING, 10_000, "the ceiling moved; the union cases below assume the old 20 explicitly");
    let w = &ScanScope::DIAGNOSTIC.with_ceiling(0);
    let d = &ScanScope::DIAGNOSTIC.with_ceiling(WALKED);
    let cases: [(u32, u32, &str, &ScanScope); 11] = [
        (22, 24, "ahead 2", d),   // a gap of two away from zero
        (22, 20, "behind 2", d),
        (50, 70, "ahead 20", w),  // the window's high edge, inside -- the window alone
        (50, 71, "unlocated", w), // one past it, with no ceiling behind it to rescue it
        (50, 30, "behind 20", w), // the window's low edge, inside
        (50, 29, "unlocated", w), // one below it
        (50, 71, "unlocated", d), // one past the high edge and past a ceiling of 20 too
        (50, 29, "unlocated", d), // and 29 is not in 0..20 either
        (50, 3, "behind 47", d),  // found through the recovery range, not the window
        (50, 19, "behind 31", d), // the recovery range's last position
        (0, 2, "ahead 2", d),     // control
    ];
    let mut walked = 0usize;
    for (i, (local, chain, expect, scope)) in cases.iter().enumerate() {
        let div = diagnose(&format!("recon-window-{i}"), *local, *chain, scope);
        let Divergence::IndexMismatch { found, .. } = &div else {
            panic!("case {i}: not an index mismatch: {div:?}");
        };
        let got = match found {
            ChainPosition::Ahead { gap, .. } => format!("ahead {gap}"),
            ChainPosition::Behind { gap, .. } => format!("behind {gap}"),
            ChainPosition::Unlocated { .. } => "unlocated".to_string(),
        };
        assert_eq!(&got, expect, "case {i}: local {local}, chain {chain}: {div:?}");
        walked += 1;
    }
    assert_eq!(walked, cases.len());

    // The unlocated text: what was walked, the three causes, the remedy.
    let text = format!("{}", diagnose("recon-window-text", 50, 71, d));
    // `d`'s ceiling is 20; rendering at the default would need a full walk.
    assert!(text.contains("indices 30 through 70, 20 either side of index 50"), "the window is not named:\n{text}");
    assert!(text.contains("indices 0 through 19"), "the recovery range is not named:\n{text}");
    assert!(text.contains("Three things produce that"), "the three causes are not named:\n{text}");
    assert!(text.contains("second wallet"), "the second-wallet cause is missing:\n{text}");
    assert!(text.contains("raising the scan ceiling"), "the remedy is not named:\n{text}");
    assert!(!text.contains("confirm no second wallet"), "a second install is asked to be ruled out:\n{text}");
    assert!(!text.contains("does not own this tag, or"), "the closed disjunction is back:\n{text}");
    assert!(!text.contains("not 'further along"), "the denial is back:\n{text}");
    // And the Behind arm reached through the recovery range names the
    // wrong-node cause, which a gap of 47 makes the likeliest.
    let behind = format!("{}", diagnose("recon-window-behind", 50, 3, d));
    assert!(behind.contains("47 BEHIND local"), "{behind}");
    assert!(behind.contains("spent fewer times"), "the behind arm does not name the wrong-node cause:\n{behind}");

    // A raised ceiling reaches what the window does not: 100 is found under a
    // ceiling of 101 and not under a ceiling of 100 (half-open, like restore's).
    match diagnose("recon-window-raised", 50, 100, &d.with_ceiling(101)) {
        Divergence::IndexMismatch { found: ChainPosition::Ahead { gap: 50, .. }, .. } => {}
        other => panic!("a ceiling of 101 did not find index 100: {other:?}"),
    }
    assert!(matches!(
        diagnose("recon-window-raised-edge", 50, 100, &d.with_ceiling(100)),
        Divergence::IndexMismatch { found: ChainPosition::Unlocated { .. }, .. }
    ), "a ceiling of 100 walked index 100; the ceiling is not half-open");
    println!("  divergence window: {walked} placement(s) diagnosed around the local index");
}

/// An operator-named index only raises the walk's ceiling; the
/// acknowledgement is built from what the walk found. Naming 99 with the
/// chain at 100 yields nothing, naming 5000 yields an acknowledgement for
/// 100, and an index below local yields a `Behind` that cannot be advanced
/// past. Only the confirmed index moves the store.
#[test]
fn an_operator_named_index_is_verified_against_the_chain_never_trusted() {
    let m = master();
    let chain_at_100 = || MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(100), 1))]));

    // A scope that does not reach index 100: unlocated, and nothing to
    // acknowledge. (The default scope would reach it.)
    let (dir, mut ks) = store_at("recon-named-default", 0);
    let client = chain_at_100();
    let short = ScanScope::DIAGNOSTIC.with_ceiling(WALKED);
    let d = recon::reconcile_account_with(&ks, &client, &TAG, &access(&m), &short, &Cancel::NEVER).expect_err("diverged");
    assert!(matches!(d, Divergence::IndexMismatch { found: ChainPosition::Unlocated { .. }, .. }), "{d:?}");
    assert!(OperatorAcknowledgement::of(&d).is_none(), "an unlocated address produced an acknowledgement");

    // Naming 99: the walk covers 0..=99, the chain is at 100, nothing found,
    // nothing acknowledged, nothing written.
    let named_99 = ScanScope::DIAGNOSTIC.with_ceiling(100);
    let d99 = recon::reconcile_account_with(&ks, &client, &TAG, &access(&m), &named_99, &Cancel::NEVER).expect_err("diverged");
    assert!(matches!(d99, Divergence::IndexMismatch { found: ChainPosition::Unlocated { .. }, .. }), "{d99:?}");
    assert!(OperatorAcknowledgement::of(&d99).is_none(), "naming 99 produced an acknowledgement");
    assert!(format!("{d99}").contains("indices 0 through 99"), "the raised walk is not reported:\n{d99}");

    // Naming 5000: the walk finds 100 on its way and the acknowledgement it
    // yields names 100 -- the typed number is not the answer.
    let named_5000 = ScanScope::DIAGNOSTIC.with_ceiling(5001);
    let d5000 =
        recon::reconcile_account_with(&ks, &client, &TAG, &access(&m), &named_5000, &Cancel::NEVER).expect_err("diverged");
    let ack5000 = OperatorAcknowledgement::of(&d5000).unwrap_or_else(|| panic!("100 lies under 5000: {d5000:?}"));
    assert_eq!(ack5000.target(), pos(100), "the acknowledgement names the typed number, not the found index");

    // Naming 100: found, acknowledged, advanced, and the account reconciles.
    let named_100 = ScanScope::DIAGNOSTIC.with_ceiling(101);
    let d100 =
        recon::reconcile_account_with(&ks, &client, &TAG, &access(&m), &named_100, &Cancel::NEVER).expect_err("diverged");
    assert!(matches!(d100, Divergence::IndexMismatch { found: ChainPosition::Ahead { gap: 100, .. }, .. }), "{d100:?}");
    let ack = OperatorAcknowledgement::of(&d100).unwrap_or_else(|| panic!("ahead has a target"));
    assert_eq!(ack.target(), pos(100));
    // The acknowledgement is checked against the live divergence under the
    // scope it is applied with: under a scope too narrow to reach index 100
    // there is no live target, so it is refused.
    assert!(matches!(
        recon::advance_after_operator_review(&mut ks, &client, &TAG, &access(&m), ack, &short, &Cancel::NEVER),
        Err(Error::AcknowledgementDoesNotMatch)
    ), "an acknowledgement was applied under a scope that cannot re-confirm its index");
    let r = recon::advance_after_operator_review(&mut ks, &client, &TAG, &access(&m), ack, &named_100, &Cancel::NEVER)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(r.index(), pos(100));
    assert!(matches!(
        recon::reconcile_account(&ks, &client, &TAG, &access(&m)),
        Ok(AccountStatus::InSync { .. })
    ));
    drop(ks);
    let ks = reopen("recon named reopen", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let v = ks.view(&TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("gone"));
    assert_eq!(v.wots_index, pos(100), "the advance did not reach disk");

    // A foreign address under any ceiling: still unlocated, still nothing.
    let mut alien = addr_at(0);
    alien[ADDR_TAG_LEN] ^= 0x01;
    let (_d2, ks2) = store_at("recon-named-alien", 0);
    let client2 = MeshClient::new(Chain::new(&[(TAG, ChainState::At(alien, 1))]));
    let da = recon::reconcile_account_with(&ks2, &client2, &TAG, &access(&m), &ScanScope::DIAGNOSTIC.with_ceiling(200), &Cancel::NEVER)
        .expect_err("diverged");
    assert!(matches!(da, Divergence::IndexMismatch { found: ChainPosition::Unlocated { .. }, .. }), "{da:?}");
    assert!(OperatorAcknowledgement::of(&da).is_none());

    // A confirmed index BELOW local: `Behind`, no acknowledgement, and the
    // report says which way it is -- not that the number failed to match.
    let (_d3, ks3) = store_at("recon-named-behind", 22);
    let client3 = MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(20), 1))]));
    let db = recon::reconcile_account_with(&ks3, &client3, &TAG, &access(&m), &ScanScope::DIAGNOSTIC.with_ceiling(21), &Cancel::NEVER)
        .expect_err("diverged");
    assert!(matches!(db, Divergence::IndexMismatch { found: ChainPosition::Behind { gap: 2, .. }, .. }), "{db:?}");
    assert!(OperatorAcknowledgement::of(&db).is_none(), "a behind divergence produced an acknowledgement");
    assert!(format!("{db}").contains("2 BEHIND local"));
}

/// Raising restore's ceiling finds the exact index or fails again. The
/// failure text counts the positions walked (`0 through 19` at a ceiling of
/// 20) and names all three causes. Uses [`WALKED`]; the default's rendering
/// is checked in `the_recovery_ceiling_is_the_extensions_own_number`.
#[test]
fn restore_finds_a_far_along_index_only_when_the_ceiling_is_raised() {
    let client = MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(30), 5))]));
    let err = recon::restore_account_index_with(&client, &master(), 0, &ScanScope::RESTORE.with_ceiling(WALKED), &Cancel::NEVER)
        .expect_err("30 is past a ceiling of 20");
    match &err {
        RestoreFailure::NoIndexReproducesTheAddress { scanned, .. } => assert_eq!(*scanned, WALKED),
        other => panic!("{other:?}"),
    }
    let text = format!("{err}");
    assert!(text.contains("none of key indices 0 through 19"), "the walk is not counted as walked:\n{text}");
    assert!(text.contains("spent 20 or more times"), "the far-along cause is not named:\n{text}");
    assert!(text.contains("does not own this tag"), "the wrong-seed cause is not named:\n{text}");
    assert!(text.contains("another chain"), "the wrong-chain cause is not named:\n{text}");
    assert!(text.contains("higher scan ceiling"), "the remedy is not named:\n{text}");
    assert!(!text.contains("within 20"), "the off-by-one phrasing is back:\n{text}");
    assert!(!text.contains("not 'further along"), "the denial is back:\n{text}");

    // Raised to walk 0..=30: found. Raised to walk 0..=29: still not.
    let found = recon::restore_account_index_with(&client, &master(), 0, &ScanScope::RESTORE.with_ceiling(31), &Cancel::NEVER)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(found.index, pos(30));
    assert_eq!(found.balance, 5);
    assert!(matches!(
        recon::restore_account_index_with(&client, &master(), 0, &ScanScope::RESTORE.with_ceiling(30), &Cancel::NEVER),
        Err(RestoreFailure::NoIndexReproducesTheAddress { scanned: 30, .. })
    ), "a ceiling of 30 walked index 30");

    // A foreign address under a raised ceiling: the ceiling does not invent a
    // match, and the report counts what it walked.
    let mut alien = addr_at(0);
    alien[ADDR_TAG_LEN] ^= 0x01;
    let client2 = MeshClient::new(Chain::new(&[(TAG, ChainState::At(alien, 7))]));
    match recon::restore_account_index_with(&client2, &master(), 0, &ScanScope::RESTORE.with_ceiling(60), &Cancel::NEVER) {
        Err(e @ RestoreFailure::NoIndexReproducesTheAddress { scanned: 60, .. }) => {
            assert!(format!("{e}").contains("0 through 59"), "{e}");
        }
        other => panic!("{other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The acknowledgement gate
// ---------------------------------------------------------------------------

/// Advancing past a divergence requires an acknowledgement built from the
/// divergence itself, checked against the live state.
#[test]
fn advancing_requires_an_acknowledgement_of_the_live_divergence() {
    let (dir, ks) = store("recon-ack");
    let m = master();
    // The wallet will not open while diverged, so the report comes from
    // `reconcile_account` directly, as the CLI's `status` and `reconcile` do.
    let client = MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(2), 1))]));
    let d = recon::reconcile_account(&ks, &client, &TAG, &access(&m)).expect_err("diverged");
    let ack = OperatorAcknowledgement::of(&d).unwrap_or_else(|| panic!("ahead has a target"));
    assert_eq!(ack.tag(), TAG);
    // The target is the chain's index, not one past it: the chain's current
    // address is the key that signs next.
    assert_eq!(ack.target(), pos(2), "the target is the chain's index");

    // A divergence advancing cannot remedy yields no acknowledgement at all.
    assert!(OperatorAcknowledgement::of(&Divergence::TagUnresolved {
        tag: TAG,
        local: WotsIndex::ZERO
    })
    .is_none());
    assert!(OperatorAcknowledgement::of(&Divergence::ChainUnreachable {
        tag: TAG,
        cause: Error::NoSuchAccount
    })
    .is_none());

    // Now open a wallet over a chain that agrees, and show the advance path
    // refuses when there is nothing to reconcile.
    drop(ks);
    let ks = reopen("recon ack", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let mut w = Wallet::open(
        ks,
        MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(0), 1))])),
        Some(&m),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    match w.advance_after_operator_review(&TAG, &access(&m), ack) {
        Err(Error::NothingToReconcile) => {}
        Err(other) => panic!("a healthy account must refuse an advance by name: {other:?}"),
        Ok(_) => panic!("a healthy account was advanced by a stale acknowledgement"),
    }

    // Point the chain at position 2 and the same acknowledgement applies.
    w.client().transport().set(TAG, ChainState::At(addr_at(2), 1));
    let r = w
        .advance_after_operator_review(&TAG, &access(&m), ack)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(r.index(), pos(2));
    // The wallet now reconciles: the store is exactly where the chain is.
    assert!(matches!(
        w.status(&TAG, &access(&m)),
        Ok(AccountStatus::InSync { .. })
    ));
    // And a second application is refused: the divergence is gone.
    assert!(matches!(
        w.advance_after_operator_review(&TAG, &access(&m), ack),
        Err(Error::NothingToReconcile)
    ));
}

/// An acknowledgement of one account cannot be applied to another.
#[test]
fn an_acknowledgement_is_bound_to_the_account_it_names() {
    let dir = ScratchDir::new("recon-ack-bound");
    let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(Account::derive(&master(), 0)).unwrap_or_else(|e| panic!("{e}"));
    ks.add(Account::derive(&master(), 1)).unwrap_or_else(|e| panic!("{e}"));
    let m = master();
    let other = tag1();
    let other_at_0 = recon::derived_address_at(&master(), 1, WotsIndex::ZERO);
    drop(ks);
    let ks = reopen("ack bound", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));

    let mut w = Wallet::open(
        ks,
        MeshClient::new(Chain::new(&[
            (TAG, ChainState::At(addr_at(0), 1)),
            (other, ChainState::At(other_at_0, 1)),
        ])),
        Some(&m),
    )
    .unwrap_or_else(|e| panic!("{e}"));

    // Diverge the FIRST account and take an acknowledgement of it.
    w.client().transport().set(TAG, ChainState::At(addr_at(2), 1));
    let d = w.status(&TAG, &access(&m)).expect_err("diverged");
    let ack = OperatorAcknowledgement::of(&d).unwrap_or_else(|| panic!("target"));

    // It cannot be applied to the second account, which is not diverged at
    // all -- the tag is checked before anything else.
    assert!(matches!(
        w.advance_after_operator_review(&other, &access(&m), ack),
        Err(Error::AcknowledgementDoesNotMatch)
    ));

    // Diverge the second account too, to a DIFFERENT index, and the first
    // account's acknowledgement is still refused: the target is checked
    // against the live divergence, not merely the tag.
    w.client()
        .transport()
        .set(other, ChainState::At(recon::derived_address_at(&master(), 1, pos(5)), 1));
    assert!(matches!(
        w.advance_after_operator_review(&other, &access(&m), ack),
        Err(Error::AcknowledgementDoesNotMatch)
    ));

    // Same account, wrong target: the acknowledgement names index 2 and the
    // chain has moved to 4. Refused, because the target is checked against
    // the live divergence, not only the tag.
    w.client().transport().set(TAG, ChainState::At(addr_at(4), 1));
    assert!(
        matches!(
            w.advance_after_operator_review(&TAG, &access(&m), ack),
            Err(Error::AcknowledgementDoesNotMatch)
        ),
        "an acknowledgement of a divergence the store has moved past was accepted"
    );

    // And with the chain back where the acknowledgement was taken, it applies.
    w.client().transport().set(TAG, ChainState::At(addr_at(2), 1));
    let r = w
        .advance_after_operator_review(&TAG, &access(&m), ack)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(r.index(), pos(2));
}

// ---------------------------------------------------------------------------
// The wallet's spend path
// ---------------------------------------------------------------------------

/// The CLI's `send` flow through the wallet: plan, reserve-and-sign, submit.
/// The signed bytes are returned as the retry artifact, which the wallet
/// does not keep; if lost, `resign_pending` rebuilds them with the same key.
#[test]
fn the_wallet_spend_path_hands_the_retry_artifact_to_the_caller() {
    let (_dir, ks) = store("recon-spend");
    let m = master();
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    let mut w = Wallet::open(ks, MeshClient::new(chain), Some(&m)).unwrap_or_else(|e| panic!("{e}"));

    let plan = w
        .plan(
            &TAG,
            &access(&m),
            vec![Destination {
                tag: [0x6b; ADDR_TAG_LEN],
                reference: [0; 16],
                amount: 1_000_000,
            }],
            MFEE,
            0,
        )
        .unwrap_or_else(|e| panic!("plan: {e}"));
    assert_eq!(plan.tag(), TAG, "the plan does not name the account it was built for");
    assert_eq!(plan.position(), WotsIndex::ZERO);

    let signed = w
        .reserve_and_sign(&plan, access(&m))
        .unwrap_or_else(|e| panic!("reserve_and_sign: {e}"));
    assert!(!signed.wire().is_empty(), "no artifact was handed back");

    // The store advanced and the reservation is open; nothing in it holds
    // the bytes.
    let v = w.store().view(&TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("gone"));
    assert_eq!(v.wots_index, pos(1), "the reservation did not advance the index");
    assert!(v.pending.is_some(), "the reservation is open until it resolves");

    // A second spend is refused while it is open -- the account is not
    // spendable again until the operator settles or re-signs.
    assert!(matches!(
        w.plan(
            &TAG,
            &access(&m),
            vec![Destination {
                tag: [0x6b; ADDR_TAG_LEN],
                reference: [0; 16],
                amount: 1,
            }],
            MFEE,
            0,
        ),
        Err(Error::PendingUnresolved { .. })
    ));
}

/// A changed observation must be refused while the key is still unused.
/// Retrying after a fresh plan remains safe because no reservation exists.
#[test]
fn reservation_preflight_refuses_changed_chain_state_without_writing() {
    let (_dir, ks) = store("preflight-chain");
    let m = master();
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    let mut w = Wallet::open(ks, MeshClient::new(chain), Some(&m)).unwrap_or_else(|e| panic!("{e}"));
    let dsts = vec![Destination { tag: [0x6b; ADDR_TAG_LEN], reference: [0; 16], amount: 1_000_000 }];
    let plan = w.plan(&TAG, &access(&m), dsts.clone(), MFEE, 0).unwrap_or_else(|e| panic!("{e}"));
    let generation = w.store().generation().unwrap_or_else(|e| panic!("{e}"));
    let state = w.store().view(&TAG).unwrap_or_else(|e| panic!("{e}"));
    for (observation, expected) in [
        (ChainState::At(addr_at(0), 6_000_000), Error::BalanceChanged { planned: 5_000_000, current: 6_000_000 }),
        (ChainState::At(addr_at(0), 4_000_000), Error::BalanceChanged { planned: 5_000_000, current: 4_000_000 }),
        (ChainState::At(addr_at(1), 5_000_000), Error::ChainAddressMismatch { position: 0 }),
        (ChainState::Absent, Error::Mesh { code: 4, retriable: false }),
        (ChainState::Unreachable, Error::Transport {
            op: "connect",
            kind: mochimo_crypto::TransportKind::Io(std::io::ErrorKind::ConnectionRefused),
        }),
    ] {
        w.client().transport().set(TAG, observation);
        assert_eq!(w.reserve_and_sign(&plan, access(&m)).err(), Some(expected));
        assert_eq!(w.store().generation().unwrap_or_else(|e| panic!("{e}")), generation);
        assert_eq!(w.store().view(&TAG).unwrap_or_else(|e| panic!("{e}")), state);
    }
    w.client().transport().set(TAG, ChainState::At(addr_at(0), 6_000_000));
    let fresh = w.plan(&TAG, &access(&m), dsts, MFEE, 0).unwrap_or_else(|e| panic!("{e}"));
    let signed = w.reserve_and_sign(&fresh, access(&m)).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(signed.wire().len(), 2_408);
    let view = w.store().view(&TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("gone"));
    assert_eq!(view.wots_index, pos(1));
    assert_eq!(view.pending.map(|p| p.digest), Some(fresh.digest()));
}

/// Both the local key position and the full address pair are checked before
/// reserving. A failed plan cannot consume a different key or redirect change.
#[test]
fn reservation_preflight_binds_plan_to_current_store_keys() {
    let (_dir, ks) = store("preflight-keys");
    let m = master();
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    let mut w = Wallet::open(ks, MeshClient::new(chain), Some(&m)).unwrap_or_else(|e| panic!("{e}"));
    let dsts = vec![Destination { tag: [0x6b; ADDR_TAG_LEN], reference: [0; 16], amount: 1_000_000 }];
    let original = w.plan(&TAG, &access(&m), dsts.clone(), MFEE, 0).unwrap_or_else(|e| panic!("{e}"));
    let generation = w.store().generation().unwrap_or_else(|e| panic!("{e}"));
    let state = w.store().view(&TAG).unwrap_or_else(|e| panic!("{e}"));
    for change_only in [false, true] {
        let mut addresses = w.spend_addresses(&TAG, &access(&m)).unwrap_or_else(|e| panic!("{e}"));
        if change_only {
            addresses.change[20] ^= 1;
        } else {
            addresses.source[20] ^= 1;
        }
        let plan = mochimo_crypto::mesh::spend::SpendPlan::new(
            &addresses,
            &mochimo_crypto::mesh::LedgerEntry { address: addresses.source, balance: 5_000_000 },
            dsts.clone(), MFEE, 0,
        ).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(w.reserve_and_sign(&plan, access(&m)).err(), Some(Error::SpendPlanAddressMismatch));
        assert_eq!(w.store().generation().unwrap_or_else(|e| panic!("{e}")), generation);
        assert_eq!(w.store().view(&TAG).unwrap_or_else(|e| panic!("{e}")), state);
    }
    let wrong = mochimo_crypto::Secret::new([0x77; 32]);
    assert!(w.reserve_and_sign(&original, access(&wrong)).is_err());
    assert_eq!(w.store().generation().unwrap_or_else(|e| panic!("{e}")), generation);
    assert_eq!(w.store().view(&TAG).unwrap_or_else(|e| panic!("{e}")), state);
    let _signed = w.reserve_and_sign(&original, access(&m)).unwrap_or_else(|e| panic!("{e}"));
    w.client().transport().set(TAG, ChainState::At(addr_at(1), 4_000_000));
    assert!(matches!(w.settle_if_landed(&TAG, &access(&m)), Ok(Settlement::Settled { .. })));
    let generation = w.store().generation().unwrap_or_else(|e| panic!("{e}"));
    let state = w.store().view(&TAG).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(w.reserve_and_sign(&original, access(&m)).err(), Some(Error::StaleSpendPlan { planned: 0, stored: 1 }));
    assert_eq!(w.store().generation().unwrap_or_else(|e| panic!("{e}")), generation);
    assert_eq!(w.store().view(&TAG).unwrap_or_else(|e| panic!("{e}")), state);
    let fresh = w.plan(&TAG, &access(&m), dsts, MFEE, 0).unwrap_or_else(|e| panic!("{e}"));
    let _signed = w.reserve_and_sign(&fresh, access(&m)).unwrap_or_else(|e| panic!("{e}"));
}

/// Non-zero expiry needs a readable tip and a remaining inclusion window.
/// Boundary arithmetic must not wrap near the largest representable block.
#[test]
fn reservation_preflight_checks_expiry_before_writing() {
    let m = master();
    for (tip, expiry, accepted) in [
        (None, 101, false),
        (Some(100), 99, false),
        (Some(100), 100, false),
        (Some(100), 101, true),
        (Some(100), 356, true),
        (Some(100), 357, false),
        (Some(u64::MAX), u64::MAX, false),
        (Some(u64::MAX - 1), u64::MAX, true),
        (None, 0, true),
    ] {
        let (_dir, ks) = store("preflight-expiry");
        let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
        if let Some(tip) = tip {
            chain.set_tip(tip);
        }
        let mut w = Wallet::open(ks, MeshClient::new(chain), Some(&m)).unwrap_or_else(|e| panic!("{e}"));
        let dsts = vec![Destination { tag: [0x6b; ADDR_TAG_LEN], reference: [0; 16], amount: 1_000_000 }];
        let plan = w.plan(&TAG, &access(&m), dsts.clone(), MFEE, expiry).unwrap_or_else(|e| panic!("{e}"));
        let generation = w.store().generation().unwrap_or_else(|e| panic!("{e}"));
        let state = w.store().view(&TAG).unwrap_or_else(|e| panic!("{e}"));
        let result = w.reserve_and_sign(&plan, access(&m));
        if accepted {
            assert!(result.is_ok(), "tip {tip:?}, expiry {expiry}: {result:?}");
        } else {
            match tip {
                Some(tip) => assert_eq!(result.err(), Some(Error::InvalidExpiry { expiry, tip })),
                None => assert!(matches!(result, Err(Error::MeshResponse { .. }))),
            }
            assert_eq!(w.store().generation().unwrap_or_else(|e| panic!("{e}")), generation);
            assert_eq!(w.store().view(&TAG).unwrap_or_else(|e| panic!("{e}")), state);
            let fresh = w.plan(&TAG, &access(&m), dsts, MFEE, 0).unwrap_or_else(|e| panic!("{e}"));
            assert!(w.reserve_and_sign(&fresh, access(&m)).is_ok());
        }
    }
}

// ---------------------------------------------------------------------------
// Cancelling an open
// ---------------------------------------------------------------------------

/// A store holding derived accounts 0 and 1, both at position 0, and a chain
/// that holds each at that position, so an open nobody cancels succeeds.
fn two_in_sync(name: &str) -> (ScratchDir, Keystore, Chain) {
    let (dir, mut ks) = store(name);
    ks.add(Account::derive(&master(), 1)).unwrap_or_else(|e| panic!("{e}"));
    let chain = Chain::new(&[
        (TAG, ChainState::At(addr_at(0), 9_000)),
        (tag1(), ChainState::At(recon::derived_address_at(&master(), 1, WotsIndex::ZERO), 4_000)),
    ]);
    (dir, ks, chain)
}

/// A cancel raised before `open_with` stops it before the node is asked
/// anything, returning `Cancelled`; the snapshot is unchanged. The control
/// opens with a predicate that never fires and asks the node once per
/// account, so the zero request count is meaningful.
#[test]
fn an_open_cancelled_before_it_starts_asks_the_node_nothing() {
    let m = master();
    let (dir, ks, chain) = two_in_sync("recon-open-cancel-first");
    let before = dir.snapshot_bytes();
    let calls = chain.call_count();
    let stop = || true;
    let result = Wallet::open_with(ks, MeshClient::new(chain), Some(&m), &Cancel::when(&stop));
    assert_eq!(result.err(), Some(Unfinished::Cancelled), "a cancel raised first did not end the open as Cancelled");
    assert_eq!(calls.get(), 0, "a cancelled open asked the node {} time(s)", calls.get());
    assert_eq!(dir.snapshot_bytes(), before, "a cancelled open changed the snapshot");

    let (_dir, ks, chain) = two_in_sync("recon-open-cancel-first-control");
    let calls = chain.call_count();
    let never = || false;
    let w = Wallet::open_with(ks, MeshClient::new(chain), Some(&m), &Cancel::when(&never))
        .unwrap_or_else(|e| panic!("a predicate that never fires stopped the open: {e:?}"));
    assert_eq!(w.accounts().len(), 2);
    assert_eq!(calls.get(), 2, "the control open did not ask once per account");
}

/// A cancel between two accounts stops the open there: the first account was
/// asked about, the second was not, and the result is `Cancelled`.
#[test]
fn an_open_cancelled_between_accounts_stops_before_the_next_one() {
    let m = master();
    let (dir, ks, chain) = two_in_sync("recon-open-cancel-between");
    let before = dir.snapshot_bytes();
    let calls = chain.call_count();
    // Asked once before each account, and no walk runs: both are in sync.
    let asked = std::cell::Cell::new(0u32);
    let second = || {
        let n = asked.get();
        asked.set(n + 1);
        n >= 1
    };
    let result = Wallet::open_with(ks, MeshClient::new(chain), Some(&m), &Cancel::when(&second));
    assert_eq!(result.err(), Some(Unfinished::Cancelled));
    assert_eq!(asked.get(), 2, "the cancel was not asked once before each account");
    assert_eq!(calls.get(), 1, "the open asked the node about an account after the cancel");
    assert_eq!(dir.snapshot_bytes(), before, "a cancelled open changed the snapshot");
}

/// A cancel that ends a diagnostic walk ends the open as `Cancelled`, not as
/// a refusal built from the incomplete walk.
///
/// The store is at 0 and the chain at 3, and the cancel stops the walk at
/// its second position. This holds whether the cancel stays raised or fires
/// once, since the open reads the walk's record. The control, with no
/// cancel, is refused by the divergence found at 3.
#[test]
fn an_open_cancelled_inside_a_walk_is_cancelled_and_not_a_refusal() {
    let m = master();
    let chain = || Chain::new(&[(TAG, ChainState::At(addr_at(3), 1))]);
    // Asked once before the account, then once per position. The first run
    // keeps the cancel raised from the second position on; the second run
    // raises it at that position only.
    let (dir, _) = store("recon-open-cancel-walk-control");
    for stays_raised in [true, false] {
        let (walked, ks) = store("recon-open-cancel-walk");
        let before = walked.snapshot_bytes();
        let asked = std::cell::Cell::new(0u32);
        let at_the_second_position = || {
            let n = asked.get();
            asked.set(n + 1);
            if stays_raised {
                n >= 2
            } else {
                n == 2
            }
        };
        let result = Wallet::open_with(ks, MeshClient::new(chain()), Some(&m), &Cancel::when(&at_the_second_position));
        assert_eq!(
            result.err(),
            Some(Unfinished::Cancelled),
            "a cancelled walk reached the caller as something else (stays raised: {stays_raised})"
        );
        assert_eq!(asked.get(), 3, "the walk was not stopped at the position the cancel fired on");
        assert_eq!(walked.snapshot_bytes(), before, "a cancelled open changed the snapshot");
    }

    let ks = reopen("open control", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    match Wallet::open_with(ks, MeshClient::new(chain()), Some(&m), &Cancel::NEVER).err() {
        Some(Unfinished::Refused(refusal)) => assert!(
            matches!(
                refusal.diverged[0],
                Divergence::IndexMismatch {
                    found: ChainPosition::Ahead { gap: 3, .. },
                    ..
                }
            ),
            "{:?}",
            refusal.diverged[0]
        ),
        other => panic!("the uncancelled control was not refused by its divergence: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Progress through an open
// ---------------------------------------------------------------------------

/// `open_with_progress` reports each account, at position zero, before
/// asking the node about it, and nothing else when no walk runs. The
/// reported ceiling is what a diagnostic walk would reach.
#[test]
fn an_open_reports_each_account_before_it_asks_the_node_about_it() {
    use mochimo_crypto::recon::Progress;
    let m = master();
    let (_dir, ks, chain) = two_in_sync("recon-open-progress");
    let calls = chain.call_count();
    let mut seen: Vec<(Progress, usize)> = Vec::new();
    let w = Wallet::open_with_progress(ks, MeshClient::new(chain), Some(&m), &Cancel::NEVER, &mut |p| {
        seen.push((p, calls.get()));
    })
    .unwrap_or_else(|e| panic!("an uncancelled open failed: {e:?}"));
    assert_eq!(w.accounts().len(), 2);
    let ceiling = ScanScope::DIAGNOSTIC.ceiling;
    assert_eq!(
        seen,
        vec![
            (Progress { account: 0, accounts: 2, position: 0, ceiling }, 0),
            (Progress { account: 1, accounts: 2, position: 0, ceiling }, 1),
        ],
        "the open did not report each account, once, before asking about it"
    );
}

/// The reported ceiling is computed from the scope's edges, not by
/// enumerating it, for each way the window can sit against the recovery
/// range and for a range of about four billion positions.
///
/// Each store is in sync, so only the first report is made. Shapes: the
/// window around 50 overlapping `0..40` (41 + 40 - 10); the window around 100
/// above `0..10` (41 + 10); and the window around 0 inside
/// `0..u32::MAX - 1` (`u32::MAX`).
#[test]
fn a_reconcile_reports_its_ceiling_from_the_scopes_edges() {
    use mochimo_crypto::cli::reconcile;
    use mochimo_crypto::recon::Progress;
    let m = master();
    for (local, advance_to, ceiling) in [(50, 39, 71), (100, 9, 51), (0, u32::MAX - 1, u32::MAX)] {
        let (_dir, mut ks) = store_at("recon-progress-reach", local);
        let client = MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(local), 1_000))]));
        let mut seen: Vec<Progress> = Vec::new();
        let reviewed = reconcile::advance_acknowledged_with_progress(
            &mut ks,
            &client,
            &TAG,
            Some(&m),
            advance_to,
            &Cancel::NEVER,
            &mut |p| seen.push(p),
        )
        .unwrap_or_else(|e| panic!("store at {local}, target {advance_to}: {e:?}"));
        assert!(
            matches!(reviewed.outcome, reconcile::Outcome::NothingToReconcile(_)),
            "store at {local}: {:?}",
            reviewed.outcome
        );
        assert_eq!(
            seen,
            vec![Progress { account: 0, accounts: 1, position: 0, ceiling }],
            "store at {local}, target {advance_to}: the reported ceiling is not the scope's reach"
        );
    }
}

// ---------------------------------------------------------------------------
// A refused open hands the store back
// ---------------------------------------------------------------------------

/// A refused `open_or_return` hands back the store and client, the store
/// still open and locked, with the same refusal `open` makes.
///
/// Checked three ways: the refusal equals `open`'s; the store still holds its
/// lock (a second handle is refused `Locked`) over the same snapshot bytes;
/// and once the node answers at the stored position, the returned parts open
/// with no second unlock.
#[test]
fn a_refused_open_hands_back_the_store_and_the_client_it_was_given() {
    let m = master();
    let behind = || Chain::new(&[(TAG, ChainState::At(addr_at(3), 1))]);
    let (dir, ks) = store("recon-open-return");
    let before = dir.snapshot_bytes();
    let refused = match Wallet::open_or_return(ks, MeshClient::new(behind()), Some(&m)) {
        Ok(w) => panic!("a store whose one account diverges opened: {w:?}"),
        Err(r) => r,
    };

    let (_control, ks) = store("recon-open-return-control");
    let plain = Wallet::open(ks, MeshClient::new(behind()), Some(&m)).expect_err("the control opened");
    assert_eq!(refused.refusal, plain, "open_or_return refused differently from open");

    assert_eq!(
        Keystore::open(dir.path(), &keystore_harness::unlock()).err(),
        Some(Error::Locked),
        "the store came back without its lock"
    );
    assert_eq!(dir.snapshot_bytes(), before, "a refused open changed the snapshot");
    let view = refused.store.view(&TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("the account is gone"));
    assert_eq!(view.wots_index, WotsIndex::ZERO);

    let Refused { store, client, .. } = refused;
    client.transport().set(TAG, ChainState::At(addr_at(0), 9_000));
    let w = Wallet::open_or_return(store, client, Some(&m))
        .unwrap_or_else(|r| panic!("the store that came back did not open: {}", r.refusal));
    assert_eq!(w.accounts().len(), 1);
    assert!(w.diverged().is_empty());
}

/// A cancelled open hands the store and client back, as a refused one does.
///
/// 1. A cancel raised first: `Cancelled`, the node asked nothing, the store
///    still locked over the same snapshot bytes; the same parts then open
///    with no cancel.
/// 2. A cancel at the second position of a diagnostic walk, through the
///    progress-reporting form: `Cancelled`, after the account's one report.
/// 3. Opened again with no cancel: the divergence at 3 refuses as `open`
///    does; once the node answers at the stored position, the parts open
///    with no second unlock.
#[test]
fn a_cancelled_open_hands_back_the_store_and_the_client_as_a_refused_one_does() {
    use mochimo_crypto::recon::Progress;
    let m = master();

    let (dir, ks, chain) = two_in_sync("recon-open-return-cancel");
    let before = dir.snapshot_bytes();
    let calls = chain.call_count();
    let stop = || true;
    let unopened = match Wallet::open_or_return_with(ks, MeshClient::new(chain), Some(&m), &Cancel::when(&stop)) {
        Ok(w) => panic!("a cancel raised first opened the wallet: {w:?}"),
        Err(u) => u,
    };
    assert_eq!(unopened.why, Unfinished::Cancelled);
    assert_eq!(calls.get(), 0, "a cancelled open asked the node");
    assert_eq!(
        Keystore::open(dir.path(), &keystore_harness::unlock()).err(),
        Some(Error::Locked),
        "the store came back from a cancel without its lock"
    );
    assert_eq!(dir.snapshot_bytes(), before, "a cancelled open changed the snapshot");
    let Unopened { store: kept, client: kept_client, .. } = unopened;
    let w = Wallet::open_or_return_with(kept, kept_client, Some(&m), &Cancel::NEVER)
        .unwrap_or_else(|u| panic!("the parts a cancel handed back did not open: {:?}", u.why));
    assert_eq!(w.accounts().len(), 2);

    let behind = || Chain::new(&[(TAG, ChainState::At(addr_at(3), 1))]);
    let (_dir, ks) = store("recon-open-return-cancel-walk");
    let asked = std::cell::Cell::new(0u32);
    let once_at_the_second_position = || {
        let n = asked.get();
        asked.set(n + 1);
        n == 2
    };
    let mut seen: Vec<Progress> = Vec::new();
    let unopened = match Wallet::open_or_return_with_progress(
        ks,
        MeshClient::new(behind()),
        Some(&m),
        &Cancel::when(&once_at_the_second_position),
        &mut |p| seen.push(p),
    ) {
        Ok(w) => panic!("a cancelled walk opened the wallet: {w:?}"),
        Err(u) => u,
    };
    assert_eq!(unopened.why, Unfinished::Cancelled, "a cancelled walk came back as something else");
    assert_eq!(seen.len(), 1, "the open did not report its one account once: {seen:?}");

    let Unopened { store: kept, client: kept_client, .. } = unopened;
    let (kept, kept_client) = match Wallet::open_or_return_with(kept, kept_client, Some(&m), &Cancel::NEVER) {
        Err(Unopened { why: Unfinished::Refused(refusal), store: back, client: back_client }) => {
            let (_control, ks) = store("recon-open-return-cancel-control");
            let plain = Wallet::open(ks, MeshClient::new(behind()), Some(&m)).expect_err("the control opened");
            assert_eq!(refusal, plain, "the cancellable open refused differently from open");
            (back, back_client)
        }
        Err(other) => panic!("the uncancelled open of a diverged store was not refused: {:?}", other.why),
        Ok(w) => panic!("a diverged store opened: {w:?}"),
    };
    kept_client.transport().set(TAG, ChainState::At(addr_at(0), 9_000));
    let w = Wallet::open_or_return_with(kept, kept_client, Some(&m), &Cancel::NEVER)
        .unwrap_or_else(|u| panic!("the parts a refusal handed back did not open: {:?}", u.why));
    assert_eq!(w.accounts().len(), 1);
}

/// A validator transaction goes through the same reserve, sign, re-sign and
/// settle path as a transfer. `plan_validator` lays out a claim from
/// position 0; `resign_pending` reproduces it byte for byte; a different
/// amount, operation, or a transfer is refused as a different digest; and
/// one observation of the change key settles it.
#[test]
fn a_validator_transaction_goes_through_the_one_gate_and_resigns_byte_for_byte() {
    use mochimo_crypto::mesh::spend::ValidatorOp;
    use mochimo_crypto::tx::wire::Transaction;
    let (_dir, ks) = store("recon-validator");
    let m = master();
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 4 * MFEE))]);
    let mut w = Wallet::open(ks, MeshClient::new(chain), Some(&m)).unwrap_or_else(|e| panic!("{e}"));

    let claim = ValidatorOp::Claim { amount: 1_234_567 };
    let plan = w
        .plan_validator(&TAG, &access(&m), claim.clone(), MFEE, 0)
        .unwrap_or_else(|e| panic!("plan_validator: {e}"));
    assert_eq!(plan.change_total(), 3 * MFEE);
    let lost = w
        .reserve_and_sign(&plan, access(&m))
        .unwrap_or_else(|e| panic!("reserve_and_sign: {e}"))
        .wire();
    let v = w.store().view(&TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("gone"));
    assert_eq!(v.wots_index, pos(1));
    assert_eq!(v.pending.as_ref().map(|p| p.digest), Some(plan.digest()), "the reservation is for the claim's digest");

    // A second plan of any kind is refused while the first is unresolved.
    assert_eq!(
        w.plan_validator(&TAG, &access(&m), ValidatorOp::ClearDelegate, MFEE, 0).err(),
        Some(Error::PendingUnresolved { spent_index: 0 })
    );

    let again = w
        .resign_pending(&TAG, &access(&m), claim, MFEE, 0)
        .unwrap_or_else(|e| panic!("resign_pending: {e}"));
    assert_eq!(again.wire(), lost, "the re-signed claim is not the lost one, byte for byte");
    let tx = Transaction::from_wire(&lost).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(tx.body(), &mochimo_crypto::tx::wire::Body::Claim { amount: 1_234_567 });

    for other in [
        mochimo_crypto::mesh::spend::PlanBody::from(ValidatorOp::Claim { amount: 1_234_568 }),
        ValidatorOp::ClearDelegate.into(),
        ValidatorOp::SetDelegate { delegate: [0x6b; ADDR_TAG_LEN] }.into(),
        vec![Destination { tag: [0x6b; ADDR_TAG_LEN], reference: [0; 16], amount: 1 }].into(),
    ] {
        assert_eq!(
            w.resign_pending(&TAG, &access(&m), other.clone(), MFEE, 0).err(),
            Some(Error::DigestMismatch),
            "{other:?} borrowed the key reserved for a claim"
        );
    }

    // The claim lands: the chain stands at the change key with the released
    // amount added to the change, and one observation settles it.
    w.client().transport().set(TAG, ChainState::At(addr_at(1), 3 * MFEE + 1_234_567));
    assert_eq!(
        w.settle_if_landed(&TAG, &access(&m)).unwrap_or_else(|e| panic!("{e}")),
        Settlement::Settled {
            spent_index: WotsIndex::ZERO,
            index: pos(1)
        }
    );
    // And the account plans its next validator transaction from position 1.
    let next = w
        .plan_validator(&TAG, &access(&m), ValidatorOp::SetDelegate { delegate: [0x6b; ADDR_TAG_LEN] }, MFEE, 0)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(next.position(), pos(1));
    assert_eq!(next.source(), &addr_at(1));
    assert_eq!(next.change(), &addr_at(2));
}

/// An SDK account is imported at the position the chain holds it at,
/// survives a reopen, and signs its first spend from the stored account seed.
///
/// The SDK master is a throwaway seed from `tests/derive.rs`. The chain holds
/// the tag at spend 0's implicit address; `import_sdk_account` finds position
/// 0 and stores the account seed (not the master). The store and
/// `recon::sdk_address_at` agree, the record round-trips through the file,
/// and a claim verifies against the implicit source with spend 1 as change.
/// A chain one key further on is found at position 1.
#[test]
fn an_sdk_account_imports_at_the_chains_position_and_signs_its_first_spend() {
    use mochimo_crypto::account::AccountKind;
    use mochimo_crypto::cli::restore::import_sdk_account;
    use mochimo_crypto::mesh::spend::{verify_wots, ValidatorOp};
    use mochimo_crypto::keystore::KeyAccess;
    use mochimo_crypto::recon::sdk_address_at;
    use mochimo_crypto::tx::wire::Transaction;
    use mochimo_crypto::Secret;

    let sdk_master = Secret::new([
        0x9e, 0xf4, 0xb8, 0x60, 0x1f, 0x0c, 0x8a, 0xc6, 0xbe, 0xa6, 0x00, 0xd8, 0xb2, 0x6b, 0xc9, 0x9d, 0xb5, 0x9f,
        0x45, 0xce, 0xe2, 0x58, 0xed, 0x18, 0x3a, 0xed, 0x60, 0xc6, 0x12, 0xa2, 0x68, 0xa9,
    ]);
    let seed = derive::sdk_account_seed(&sdk_master, 0);
    let tag = derive::sdk_account_tag(&seed);
    let at0 = sdk_address_at(&seed, pos(0));
    assert_eq!(&at0[..ADDR_TAG_LEN], &at0[ADDR_TAG_LEN..], "spend 0 is the implicit address");
    assert_eq!(
        hexs(&tag),
        "204741cd11dbec971a90e182e74936e3f405d403",
        "the tag is not the one SDK 2.1.1 printed for this seed"
    );

    let dir = ScratchDir::new("recon-sdk-import");
    let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    let chain = Chain::new(&[(tag, ChainState::At(at0, 10 * MFEE))]);
    let client = MeshClient::new(chain);
    let r = import_sdk_account(&mut ks, &client, &sdk_master, 0, None).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(r.found.index, pos(0));
    assert_eq!(r.held_at, None);
    let v = ks.view(&tag).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("not stored"));
    assert_eq!(v.kind, AccountKind::Sdk);
    for p in 0..3 {
        assert_eq!(
            ks.address_at(&tag, pos(p), &KeyAccess::StoredRoot).unwrap_or_else(|e| panic!("{e}")),
            sdk_address_at(&seed, pos(p)),
            "the store and the scan disagree at position {p}"
        );
    }
    // Imported again: found, held, nothing written.
    let again = import_sdk_account(&mut ks, &client, &sdk_master, 0, None).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(again.held_at, Some(pos(0)));
    drop(ks);

    // Through the file and back, then the first spend.
    let ks = reopen("recon-sdk-import", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let m = master();
    let mut w = Wallet::open(ks, client, Some(&m)).unwrap_or_else(|e| panic!("{e}"));
    let plan = w
        .plan_validator(&tag, &KeyAccess::StoredRoot, ValidatorOp::Claim { amount: 7 }, MFEE, 0)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(plan.source(), &at0);
    assert_eq!(plan.change(), &sdk_address_at(&seed, pos(1)));
    let signed = w.reserve_and_sign(&plan, KeyAccess::StoredRoot).unwrap_or_else(|e| panic!("{e}"));
    let tx = Transaction::from_wire(&signed.wire()).unwrap_or_else(|e| panic!("{e}"));
    verify_wots(&tx).unwrap_or_else(|e| panic!("the SDK spend 0 signature does not verify: {e}"));
    // The master seed is refused as this account's key access.
    assert!(matches!(
        w.store().address_at(&tag, pos(0), &KeyAccess::Master(&m)),
        Err(Error::KeyAccessMismatch { kind: AccountKind::Sdk })
    ));

    // A chain one key on is found there, never assumed at zero.
    let dir2 = ScratchDir::new("recon-sdk-import-ahead");
    let mut ks2 = Keystore::create(dir2.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    let ahead = MeshClient::new(Chain::new(&[(tag, ChainState::At(sdk_address_at(&seed, pos(1)), 5))]));
    let r2 = import_sdk_account(&mut ks2, &ahead, &sdk_master, 0, None).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(r2.found.index, pos(1));
    let v2 = ks2.view(&tag).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("not stored"));
    assert_eq!(v2.wots_index, pos(1));
}

/// A claim is compared with its entitlement before anything is reserved,
/// whether the figure comes from `/account/entitlement` or the operator. An
/// amount above it is refused as `ClaimExceedsEntitlement`, an equal amount
/// plans and carries the figure's source, and a rate-limited endpoint
/// refuses with the wait after one request.
#[test]
fn a_claim_above_its_entitlement_is_refused_before_the_key_is_reserved() {
    use chain::Entitled;
    use mochimo_crypto::entitlement::{OperatorSupplied, Origin};
    let (_dir, ks) = store("recon-claim-ceiling");
    let m = master();
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 10 * MFEE))]);
    chain.entitles(Entitled::Amount(1_000, 77));
    let calls = chain.entitlement_calls();
    let w = Wallet::open(ks, MeshClient::new(chain), Some(&m)).unwrap_or_else(|e| panic!("{e}"));

    assert_eq!(
        w.plan_claim(&TAG, &access(&m), 1_001, MFEE, 0, w.client()).err(),
        Some(Error::ClaimExceedsEntitlement { amount: 1_001, entitlement: 1_000 })
    );
    let (plan, e) = w.plan_claim(&TAG, &access(&m), 1_000, MFEE, 0, w.client()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(e.origin, Origin::Endpoint { block: 77 });
    assert_eq!(plan.body(), &mochimo_crypto::tx::wire::Body::Claim { amount: 1_000 });
    assert_eq!(calls.get(), 2, "one endpoint request per plan");

    let supplied = OperatorSupplied { amount: 5 };
    assert_eq!(
        w.plan_claim(&TAG, &access(&m), 6, MFEE, 0, &supplied).err(),
        Some(Error::ClaimExceedsEntitlement { amount: 6, entitlement: 5 })
    );
    let (_, e) = w.plan_claim(&TAG, &access(&m), 5, MFEE, 0, &supplied).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(e.origin, Origin::OperatorSupplied);
    assert_eq!(calls.get(), 2, "a supplied figure asks the endpoint nothing");

    w.client().transport().entitles(Entitled::RateLimited(Some(10)));
    assert_eq!(
        w.plan_claim(&TAG, &access(&m), 1, MFEE, 0, w.client()).err(),
        Some(Error::RateLimited { retry_after_secs: Some(10) })
    );
    assert_eq!(calls.get(), 3, "a rate-limited source is asked once and not again");
    let v = w.store().view(&TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("gone"));
    assert_eq!(v.wots_index, pos(0), "a refused claim moved the position");
    assert!(v.pending.is_none());
}

/// An SDK account claims, sends part of its balance, and claims again,
/// settling each as its address rotates: import at position 0; claim with
/// spend 1 as change; settle; transfer from spend 1 with spend 2 as change;
/// settle; claim from spend 2. Every signed image verifies against its
/// source, and the stored position equals the number of spends.
#[test]
fn an_sdk_cold_account_claims_sends_and_claims_again_settling_each() {
    use chain::Entitled;
    use mochimo_crypto::cli::restore::import_sdk_account;
    use mochimo_crypto::keystore::KeyAccess;
    use mochimo_crypto::mesh::spend::verify_wots;
    use mochimo_crypto::recon::sdk_address_at;
    use mochimo_crypto::tx::wire::{Body, Transaction};
    use mochimo_crypto::Secret;

    let sdk_master = Secret::new([0x3a; 32]);
    let seed = derive::sdk_account_seed(&sdk_master, 0);
    let tag = derive::sdk_account_tag(&seed);
    let at = |p: u32| sdk_address_at(&seed, pos(p));
    let stored = KeyAccess::StoredRoot;

    let dir = ScratchDir::new("recon-sdk-claim-send-claim");
    let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    let chain = Chain::new(&[(tag, ChainState::At(at(0), 2 * MFEE))]);
    chain.entitles(Entitled::Amount(1_000_000, 10));
    let client = MeshClient::new(chain);
    import_sdk_account(&mut ks, &client, &sdk_master, 0, None).unwrap_or_else(|e| panic!("{e}"));
    let m = master();
    let mut w = Wallet::open(ks, client, Some(&m)).unwrap_or_else(|e| panic!("{e}"));
    let verify = |wire: &[u8], source: &[u8; 40]| {
        let tx = Transaction::from_wire(wire).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(&tx.src_addr, source);
        verify_wots(&tx).unwrap_or_else(|e| panic!("{e}"));
        tx
    };

    // 1. claim 600,000 from the implicit key.
    let (plan, _) = w.plan_claim(&tag, &stored, 600_000, MFEE, 0, w.client()).unwrap_or_else(|e| panic!("{e}"));
    let tx = verify(&w.reserve_and_sign(&plan, KeyAccess::StoredRoot).unwrap_or_else(|e| panic!("{e}")).wire(), &at(0));
    assert_eq!(tx.body(), &Body::Claim { amount: 600_000 });
    assert_eq!(tx.chg_addr, at(1));
    w.client().transport().set(tag, ChainState::At(at(1), MFEE + 600_000));
    assert_eq!(
        w.settle_if_landed(&tag, &stored).unwrap_or_else(|e| panic!("{e}")),
        Settlement::Settled { spent_index: pos(0), index: pos(1) }
    );

    // 2. send part of the balance to another tag.
    let dsts = vec![Destination { tag: [0x6b; ADDR_TAG_LEN], reference: [0; 16], amount: 400_000 }];
    let plan = w.plan(&tag, &stored, dsts, MFEE, 0).unwrap_or_else(|e| panic!("{e}"));
    let tx = verify(&w.reserve_and_sign(&plan, KeyAccess::StoredRoot).unwrap_or_else(|e| panic!("{e}")).wire(), &at(1));
    assert_eq!(tx.chg_addr, at(2));
    assert_eq!(tx.change_total, MFEE + 600_000 - 400_000 - MFEE);
    w.client().transport().set(tag, ChainState::At(at(2), tx.change_total));
    assert_eq!(
        w.settle_if_landed(&tag, &stored).unwrap_or_else(|e| panic!("{e}")),
        Settlement::Settled { spent_index: pos(1), index: pos(2) }
    );

    // 3. claim again, from spend 2.
    let (plan, e) = w.plan_claim(&tag, &stored, 400_000, MFEE, 0, w.client()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(e.amount, 1_000_000);
    let tx = verify(&w.reserve_and_sign(&plan, KeyAccess::StoredRoot).unwrap_or_else(|e| panic!("{e}")).wire(), &at(2));
    assert_eq!(tx.chg_addr, at(3));
    w.client().transport().set(tag, ChainState::At(at(3), tx.change_total + 400_000));
    assert_eq!(
        w.settle_if_landed(&tag, &stored).unwrap_or_else(|e| panic!("{e}")),
        Settlement::Settled { spent_index: pos(2), index: pos(3) }
    );
    let v = w.store().view(&tag).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("gone"));
    assert_eq!(v.wots_index, pos(3), "three spends, three positions");
    println!("  sdk cold account: claim, send, claim -- positions 0 -> 1 -> 2 -> 3, each settled by rotation");
}

/// An account from a browser-extension export imports where the chain holds
/// it, checked against everything the file provides.
///
/// A synthetic export (`support/extension_export.rs`) holds two accounts.
/// The one requested decrypts, is checked against its record, first address
/// and master seed, and is stored as an imported root at position 0. The
/// wallet then opens and a transfer verifies from the implicit address. A
/// record whose `wotsIndex` says 2 (position 3) is stored where the chain is
/// when the chain is at or past that position.
#[test]
fn an_extension_export_account_imports_at_the_chains_position() {
    use mochimo_crypto::account::AccountKind;
    use mochimo_crypto::cli::restore::import_extension_account;
    use mochimo_crypto::keystore::KeyAccess;
    use mochimo_crypto::mesh::spend::verify_wots;
    use mochimo_crypto::tx::wire::Transaction;
    use mochimo_crypto::Secret;

    let ext_master = Secret::new([0x21; 32]);
    let records = [extension_export::record(&ext_master, 2, -1), extension_export::record(&ext_master, 9, 2)];
    let text = extension_export::export(&ext_master, extension_export::PASSWORD, &records);
    let tag2 = derive::derive_account_tag(&ext_master, 2);
    let tag9 = derive::derive_account_tag(&ext_master, 9);
    let first2 = derive::derive_account(&ext_master, 2).first_key().implicit_address();

    let dir = ScratchDir::new("recon-ext-import");
    let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    let chain = Chain::new(&[(tag2, ChainState::At(first2, 10 * MFEE))]);
    let client = MeshClient::new(chain);
    let r = import_extension_account(&mut ks, &client, &text, extension_export::PASSWORD.as_bytes(), &tag2, None)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(r.account_index, 2);
    assert_eq!(r.recorded, pos(0));
    assert_eq!(r.restored.found.index, pos(0));
    assert_eq!(r.restored.held_at, None);
    let v = ks.view(&tag2).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("not stored"));
    assert_eq!(v.kind, AccountKind::Imported);
    assert_eq!(
        ks.address_at(&tag2, pos(0), &KeyAccess::StoredRoot).unwrap_or_else(|e| panic!("{e}")),
        first2,
        "the stored account's position 0 is not the implicit address"
    );
    let m = master();
    let mut w = Wallet::open(ks, client, Some(&m)).unwrap_or_else(|e| panic!("{e}"));
    let plan = w
        .plan(&tag2, &KeyAccess::StoredRoot, vec![Destination { tag: [0x6b; ADDR_TAG_LEN], reference: [0; 16], amount: 7 }], MFEE, 0)
        .unwrap_or_else(|e| panic!("{e}"));
    let signed = w.reserve_and_sign(&plan, KeyAccess::StoredRoot).unwrap_or_else(|e| panic!("{e}"));
    let tx = Transaction::from_wire(&signed.wire()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(tx.src_addr, first2);
    verify_wots(&tx).unwrap_or_else(|e| panic!("a send from the imported account does not verify: {e}"));

    // The second record says wotsIndex 2, position 3.
    let at9 = |p: u32| {
        let acct = derive::derive_account(&ext_master, 9);
        match pos(p).rotation() {
            None => acct.first_key().address(&acct.tag()),
            Some(r) => derive::derive_wots_key(acct.seed(), r).address(&acct.tag()),
        }
    };
    for (chain_at, want) in [(3u32, 3u32), (5, 5)] {
        let dir = ScratchDir::new(&format!("recon-ext-import-at-{chain_at}"));
        let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
        let client = MeshClient::new(Chain::new(&[(tag9, ChainState::At(at9(chain_at), 5))]));
        let r = import_extension_account(&mut ks, &client, &text, extension_export::PASSWORD.as_bytes(), &tag9, None)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(r.recorded, pos(3));
        assert_eq!(r.restored.found.index, pos(want));
        let v = ks.view(&tag9).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("not stored"));
        assert_eq!(v.wots_index, pos(want), "the chain's position is not the one stored");
    }
}

/// An extension export whose recorded position is past the chain's is
/// refused and nothing is stored: the extension has already signed with the
/// key at the chain's position, so storing the account there would let the
/// next send sign with that key a second time.
#[test]
fn an_extension_export_account_behind_on_the_chain_is_refused() {
    use mochimo_crypto::cli::restore::import_extension_account;
    use mochimo_crypto::recon::RestoreFailure;
    use mochimo_crypto::Secret;

    let ext_master = Secret::new([0x23; 32]);
    let records = [extension_export::record(&ext_master, 9, 2)];
    let text = extension_export::export(&ext_master, extension_export::PASSWORD, &records);
    let tag9 = derive::derive_account_tag(&ext_master, 9);
    let at9 = |p: u32| {
        let acct = derive::derive_account(&ext_master, 9);
        match pos(p).rotation() {
            None => acct.first_key().address(&acct.tag()),
            Some(r) => derive::derive_wots_key(acct.seed(), r).address(&acct.tag()),
        }
    };
    for chain_at in [0u32, 1, 2] {
        let dir = ScratchDir::new(&format!("recon-ext-import-behind-{chain_at}"));
        let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
        let client = MeshClient::new(Chain::new(&[(tag9, ChainState::At(at9(chain_at), 5))]));
        match import_extension_account(&mut ks, &client, &text, extension_export::PASSWORD.as_bytes(), &tag9, None) {
            Err(e @ RestoreFailure::ExtensionKeyAlreadySigned { .. }) => {
                if let RestoreFailure::ExtensionKeyAlreadySigned { tag, chain, recorded } = &e {
                    assert_eq!(*tag, tag9);
                    assert_eq!(*chain, pos(chain_at));
                    assert_eq!(*recorded, pos(3));
                }
                let message = e.to_string();
                assert!(message.contains("still pending, wait for it to land"), "{message}");
                assert!(message.contains("If it was dropped and will not land"), "{message}");
                assert!(message.contains("waiting will not change that"), "{message}");
                assert!(message.contains("Submitting the same signed transaction again"), "{message}");
            }
            Err(other) => panic!("chain at {chain_at}: refused for the wrong reason: {other}"),
            Ok(_) => panic!("chain at {chain_at}: imported an account whose key the export shows has signed"),
        }
        assert!(
            ks.view(&tag9).unwrap_or_else(|e| panic!("{e}")).is_none(),
            "chain at {chain_at}: a refused import stored the account"
        );
    }
}

/// The extension import refuses, storing nothing: a wrong password; a tag
/// the export does not hold; a record whose tag is not the one requested; a
/// record whose account seed the master does not derive at its index; a
/// first address its seed does not regenerate; and a tag the node does not
/// resolve.
#[test]
fn an_extension_export_account_is_refused_on_every_mismatch() {
    use mochimo_crypto::cli::restore::import_extension_account;
    use mochimo_crypto::recon::RestoreFailure;
    use mochimo_crypto::Secret;

    let ext_master = Secret::new([0x22; 32]);
    let tag = derive::derive_account_tag(&ext_master, 4);
    let first = derive::derive_account(&ext_master, 4).first_key().implicit_address();
    let try_import = |name: &str, text: &str, password: &str, chain_has_tag: bool| {
        let dir = ScratchDir::new(name);
        let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
        let state = if chain_has_tag { ChainState::At(first, 5) } else { ChainState::Absent };
        let client = MeshClient::new(Chain::new(&[(tag, state)]));
        let got = import_extension_account(&mut ks, &client, text, password.as_bytes(), &tag, None).err();
        assert!(ks.view(&tag).unwrap_or_else(|e| panic!("{e}")).is_none(), "{name}: a refused import stored the account");
        got.unwrap_or_else(|| panic!("{name}: the import was not refused"))
    };
    let cause = |f: RestoreFailure| match f {
        RestoreFailure::CannotScan { cause, .. } => cause,
        other => panic!("not a decryption or verification refusal: {other}"),
    };

    let good = extension_export::export(&ext_master, extension_export::PASSWORD, &[extension_export::record(&ext_master, 4, -1)]);
    assert_eq!(cause(try_import("ext-wrong-password", &good, "not it", true)), Error::ExtensionExportPassword);

    let other = extension_export::export(&ext_master, extension_export::PASSWORD, &[extension_export::record(&ext_master, 5, -1)]);
    assert!(matches!(
        cause(try_import("ext-absent", &other, extension_export::PASSWORD, true)),
        Error::ExtensionExportMismatch { what } if what.contains("holds no account")
    ));

    let mut wrong_tag = extension_export::record(&ext_master, 4, -1);
    wrong_tag.tag = "11".repeat(20);
    let t = extension_export::export(&ext_master, extension_export::PASSWORD, &[wrong_tag]);
    assert!(matches!(
        cause(try_import("ext-record-tag", &t, extension_export::PASSWORD, true)),
        Error::ExtensionExportMismatch { what } if what.contains("record's own tag")
    ));

    let mut wrong_seed = extension_export::record(&ext_master, 4, -1);
    let five = extension_export::record(&ext_master, 5, -1);
    wrong_seed.seed = five.seed;
    wrong_seed.faddress = five.faddress;
    let t = extension_export::export(&ext_master, extension_export::PASSWORD, &[wrong_seed]);
    assert!(matches!(
        cause(try_import("ext-seed", &t, extension_export::PASSWORD, true)),
        Error::ExtensionExportMismatch { what } if what.contains("does not derive the record's account seed")
    ));

    let mut wrong_faddress = extension_export::record(&ext_master, 4, -1);
    wrong_faddress.faddress.replace_range(0..2, if wrong_faddress.faddress.starts_with("00") { "01" } else { "00" });
    let t = extension_export::export(&ext_master, extension_export::PASSWORD, &[wrong_faddress]);
    assert!(matches!(
        cause(try_import("ext-faddress", &t, extension_export::PASSWORD, true)),
        Error::ExtensionExportMismatch { what } if what.contains("does not regenerate its first address")
    ));

    assert!(matches!(
        try_import("ext-unresolved", &good, extension_export::PASSWORD, false),
        RestoreFailure::TagUnresolved { .. }
    ));
}

// ---------------------------------------------------------------------------
// Sending a saved copy of a reverted settle again
// ---------------------------------------------------------------------------

/// Pay `amount` nanoMCM to the destination every spend in this section uses.
fn pay(amount: u64) -> Vec<Destination> {
    vec![Destination {
        tag: [0x6b; ADDR_TAG_LEN],
        reference: [0; 16],
        amount,
    }]
}

/// A store named `name` whose one account sits at position `at`, with a spend
/// of `amount` reserved from it at block-to-live `btl`. The chain holds the
/// account at `at` with 5,000,000 nanoMCM and its tip at 4,241. Returns the
/// store's directory, the wallet still holding the store, and the artifact the
/// wallet signed with the id it computed for it.
fn reserved_spend(
    name: &str,
    at: u32,
    btl: u64,
    amount: u64,
) -> (ScratchDir, Wallet<Disk, Chain>, Vec<u8>, [u8; 32]) {
    let m = master();
    let (dir, mut ks) = store(name);
    if at > 0 {
        let _ = ks
            .persist_advance_to(&TAG, pos(at))
            .unwrap_or_else(|e| panic!("{e}"));
    }
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(at), 5_000_000))]);
    chain.set_tip(4_241);
    let mut w =
        Wallet::open(ks, MeshClient::new(chain), Some(&m)).unwrap_or_else(|e| panic!("{e}"));
    let plan = w
        .plan(&TAG, &access(&m), pay(amount), MFEE, btl)
        .unwrap_or_else(|e| panic!("plan: {e}"));
    let signed = w
        .reserve_and_sign(&plan, access(&m))
        .unwrap_or_else(|e| panic!("reserve_and_sign: {e}"));
    (dir, w, signed.wire(), signed.id().0)
}

/// [`reserved_spend`], then settled: the chain moves to the change key, which
/// takes one observation. The wallet is dropped, so the store is closed and
/// the caller reopens it from disk, as a later process would.
fn settled_spend(name: &str, at: u32, btl: u64, amount: u64) -> (ScratchDir, Vec<u8>, [u8; 32]) {
    let m = master();
    let (dir, mut w, saved, id) = reserved_spend(name, at, btl, amount);
    w.client()
        .transport()
        .set(TAG, ChainState::At(addr_at(at + 1), 4_000_000));
    let settled = w
        .settle_if_landed(&TAG, &access(&m))
        .unwrap_or_else(|e| panic!("settle: {e}"));
    assert!(
        matches!(settled, Settlement::Settled { .. }),
        "the change key did not settle: {settled:?}"
    );
    drop(w);
    (dir, saved, id)
}

/// The chain as a reverted settle leaves it: the account back at `at`.
fn reverted(at: u32, balance: u64) -> Chain {
    Chain::new(&[(TAG, ChainState::At(addr_at(at), balance))])
}

/// A reverted settle with every check holding is sent once, as the saved
/// bytes, and nothing else moves: the account reads the same afterwards, the
/// snapshot on disk is the same, and the chain was asked three things, the
/// resolve, the tip and the submit.
#[test]
fn a_reverted_settle_is_resubmitted_as_the_saved_bytes_and_nothing_else_moves() {
    let m = master();
    let (dir, saved, id) = settled_spend("recon-resubmit-ok", 0, 4_242, 1_000_000);
    let ks = reopen("recon resubmit ok", dir.path())
        .result
        .unwrap_or_else(|e| panic!("{e}"));
    let view = ks.view(&TAG).unwrap_or_else(|e| panic!("{e}"));
    let on_disk = dir.snapshot_bytes();

    let chain = reverted(0, 5_000_000);
    chain.set_tip(4_241);
    chain.accepts_submit(id);
    let calls = chain.call_count();
    let log = chain.submit_log();
    let client = MeshClient::new(chain);

    let sent = recon::resubmit_reverted_settle(&ks, &client, &TAG, &access(&m), &saved)
        .unwrap_or_else(|e| panic!("every check holds, and the saved copy was refused: {e}"));
    assert_eq!(
        sent,
        TxId(id),
        "the node echoed an id other than the one the copy carries"
    );

    let bodies = log.borrow();
    assert_eq!(
        bodies.len(),
        1,
        "the socket saw {} write(s); one saved copy is one write",
        bodies.len()
    );
    let body: serde_json::Value =
        serde_json::from_slice(&bodies[0]).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        body["signed_transaction"].as_str(),
        Some(hexs(&saved).as_str()),
        "the body on the socket is not the saved bytes"
    );
    drop(bodies);
    assert_eq!(
        calls.get(),
        3,
        "the chain was asked {} time(s); the resolve, the tip and the submit are three",
        calls.get()
    );
    assert_eq!(
        ks.view(&TAG).unwrap_or_else(|e| panic!("{e}")),
        view,
        "the store's account moved"
    );
    assert_eq!(
        dir.snapshot_bytes(),
        on_disk,
        "the store's snapshot changed on disk"
    );
}

/// A copy of another spend, valid on its own terms and signed from this seed,
/// is refused as not the settled spend, and nothing reaches the chain.
#[test]
fn a_valid_copy_of_another_spend_is_refused_as_not_the_settled_spend_before_the_chain_is_asked() {
    let m = master();
    let (dir, _saved, _id) = settled_spend("recon-resubmit-other", 0, 4_242, 1_000_000);
    let (_other_dir, _other_wallet, other, _other_id) =
        reserved_spend("recon-resubmit-other-spend", 0, 4_242, 2_000_000);
    let ks = reopen("recon resubmit other", dir.path())
        .result
        .unwrap_or_else(|e| panic!("{e}"));

    let chain = reverted(0, 5_000_000);
    chain.set_tip(4_241);
    let calls = chain.call_count();
    let log = chain.submit_log();
    let client = MeshClient::new(chain);

    let r = recon::resubmit_reverted_settle(&ks, &client, &TAG, &access(&m), &other);
    assert_eq!(
        r,
        Err(Error::NotTheSettledSpend),
        "another spend was not refused as not the settled one"
    );
    assert_eq!(
        calls.get(),
        0,
        "the chain was asked about a copy that was refused locally"
    );
    assert!(
        log.borrow().is_empty(),
        "a copy of another spend reached the socket"
    );
}

/// A copy whose signature has one byte flipped keeps its layout and its
/// digest, so the signature check is the one that refuses it, before the
/// chain is asked anything.
#[test]
fn a_flipped_signature_byte_is_refused_by_the_signature_check_and_nothing_is_sent() {
    let m = master();
    let (dir, saved, id) = settled_spend("recon-resubmit-signature", 0, 4_242, 1_000_000);
    let tx = Transaction::from_wire(&saved).unwrap_or_else(|e| panic!("{e}"));
    let mut flipped = saved.clone();
    flipped[tx.dsa_off() + 7] ^= 0x01;
    let ks = reopen("recon resubmit signature", dir.path())
        .result
        .unwrap_or_else(|e| panic!("{e}"));

    let chain = reverted(0, 5_000_000);
    chain.set_tip(4_241);
    chain.accepts_submit(id);
    let calls = chain.call_count();
    let log = chain.submit_log();
    let client = MeshClient::new(chain);

    let r = recon::resubmit_reverted_settle(&ks, &client, &TAG, &access(&m), &flipped);
    assert!(
        matches!(&r, Err(Error::SignatureDoesNotRecover { .. })),
        "a flipped signature byte was not refused by the signature check: {r:?}"
    );
    assert_eq!(
        calls.get(),
        0,
        "the chain was asked about a copy whose signature does not recover"
    );
    assert!(
        log.borrow().is_empty(),
        "a copy whose signature does not recover reached the socket"
    );
}

/// Bytes that are not the whole image of their transaction are refused as
/// not whole, and bytes that do not parse at all as not a transaction. Both
/// refusals come before the chain is asked and before anything is sent.
#[test]
fn saved_bytes_that_are_not_a_whole_transaction_are_refused_before_the_chain_is_asked() {
    let m = master();
    let (dir, saved, id) = settled_spend("recon-resubmit-whole", 0, 4_242, 1_000_000);
    let ks = reopen("recon resubmit whole", dir.path())
        .result
        .unwrap_or_else(|e| panic!("{e}"));

    let chain = reverted(0, 5_000_000);
    chain.set_tip(4_241);
    chain.accepts_submit(id);
    let calls = chain.call_count();
    let log = chain.submit_log();
    let client = MeshClient::new(chain);

    let truncated = &saved[..saved.len() - 2];
    match recon::resubmit_reverted_settle(&ks, &client, &TAG, &access(&m), truncated) {
        Err(Error::SavedArtifactNotWhole { given, described }) => {
            assert_eq!(
                (given, described),
                (saved.len() - 2, saved.len()),
                "the lengths named are not the copy's"
            );
        }
        other => panic!("a truncated copy was not refused as not whole: {other:?}"),
    }
    let junk: [u8; 2] = [0x00, 0xff];
    let r = recon::resubmit_reverted_settle(&ks, &client, &TAG, &access(&m), &junk);
    assert!(
        matches!(&r, Err(Error::SavedArtifactNotATransaction { .. })),
        "bytes that are not a transaction were not refused as such: {r:?}"
    );
    assert_eq!(
        calls.get(),
        0,
        "the chain was asked about bytes refused locally"
    );
    assert!(
        log.borrow().is_empty(),
        "bytes refused locally reached the socket"
    );
}

/// A settle recorded under format version 3 carries no figures, so the copy
/// is refused before anything is read.
#[test]
fn a_settle_recorded_before_format_version_4_is_refused_for_want_of_figures() {
    const IMAGE: &[u8] = include_bytes!("../testdata/keystore_v3_reserved_snapshot.bin");
    let master = Secret::new(keystore_harness::IMPORTED_MASTER);
    let dir = ScratchDir::new("recon-resubmit-v3");
    drop(keystore_harness::create(dir.path()).unwrap_or_else(|e| panic!("{e}")));
    dir.write_snapshot(IMAGE);
    let mut ks = keystore_harness::open(dir.path()).unwrap_or_else(|e| panic!("{e}"));
    ks.persist_settled(&keystore_harness::IMPORTED_TAG)
        .unwrap_or_else(|e| panic!("{e}"));
    let settled = ks
        .view(&keystore_harness::IMPORTED_TAG)
        .unwrap_or_else(|e| panic!("{e}"))
        .and_then(|v| v.settled);
    assert!(
        matches!(settled, Some(Pending { figures: None, .. })),
        "the migrated settle is not retained without figures: {settled:?}"
    );

    let chain = Chain::new(&[]);
    let calls = chain.call_count();
    let client = MeshClient::new(chain);
    let junk: [u8; 2] = [0x00, 0xff];
    let r = recon::resubmit_reverted_settle(
        &ks,
        &client,
        &keystore_harness::IMPORTED_TAG,
        &KeyAccess::Master(&master),
        &junk,
    );
    assert_eq!(
        r,
        Err(Error::FiguresNotRecorded),
        "a settle without figures was not refused for want of them"
    );
    assert_eq!(
        calls.get(),
        0,
        "the chain was asked about a settle with no figures"
    );
}

/// The balance at the source moved after the spend was built: the copy can no
/// longer be accepted, the refusal names both balances, and nothing is sent.
#[test]
fn a_balance_that_moved_at_the_source_refuses_and_nothing_moves() {
    let m = master();
    let (dir, saved, id) = settled_spend("recon-resubmit-balance", 0, 4_242, 1_000_000);
    let ks = reopen("recon resubmit balance", dir.path())
        .result
        .unwrap_or_else(|e| panic!("{e}"));
    let on_disk = dir.snapshot_bytes();

    // One nanoMCM more than the 5,000,000 the spend was built against.
    let chain = reverted(0, 5_000_001);
    chain.set_tip(4_241);
    chain.accepts_submit(id);
    let log = chain.submit_log();
    let client = MeshClient::new(chain);

    let r = recon::resubmit_reverted_settle(&ks, &client, &TAG, &access(&m), &saved);
    assert_eq!(
        r,
        Err(Error::SettledBalanceMoved {
            reserved: 5_000_000,
            current: 5_000_001,
        })
    );
    assert!(
        log.borrow().is_empty(),
        "a copy the balance refuses reached the socket"
    );
    assert_eq!(
        dir.snapshot_bytes(),
        on_disk,
        "the refusal wrote to the store"
    );
}

/// The balance at the source fell after the spend was built: the copy is
/// refused with both balances named, as a rise is, and nothing is sent.
#[test]
fn a_balance_that_fell_at_the_source_refuses_and_nothing_moves() {
    let m = master();
    let (dir, saved, id) = settled_spend("recon-resubmit-fell", 0, 4_242, 1_000_000);
    let ks = reopen("recon resubmit fell", dir.path())
        .result
        .unwrap_or_else(|e| panic!("{e}"));
    let on_disk = dir.snapshot_bytes();

    // One nanoMCM less than the 5,000,000 the spend was built against.
    let chain = reverted(0, 4_999_999);
    chain.set_tip(4_241);
    chain.accepts_submit(id);
    let log = chain.submit_log();
    let client = MeshClient::new(chain);

    let r = recon::resubmit_reverted_settle(&ks, &client, &TAG, &access(&m), &saved);
    assert_eq!(
        r,
        Err(Error::SettledBalanceMoved {
            reserved: 5_000_000,
            current: 4_999_999,
        })
    );
    assert!(
        log.borrow().is_empty(),
        "a copy the balance refuses reached the socket"
    );
    assert_eq!(
        dir.snapshot_bytes(),
        on_disk,
        "the refusal wrote to the store"
    );
}

/// An unreadable tip refuses a copy whose block-to-live is not zero, and the
/// refusal is the read's own cause. Nothing reaches the socket.
#[test]
fn an_unreadable_tip_refuses_the_copy_with_its_cause_and_nothing_is_sent() {
    let m = master();
    let (dir, saved, id) = settled_spend("recon-resubmit-tip", 0, 4_242, 1_000_000);
    let ks = reopen("recon resubmit tip", dir.path())
        .result
        .unwrap_or_else(|e| panic!("{e}"));
    let on_disk = dir.snapshot_bytes();

    let chain = reverted(0, 5_000_000);
    chain.refuses_tip();
    chain.accepts_submit(id);
    let log = chain.submit_log();
    let client = MeshClient::new(chain);

    let r = recon::resubmit_reverted_settle(&ks, &client, &TAG, &access(&m), &saved);
    assert_eq!(
        r,
        Err(Error::Transport {
            op: "connect",
            kind: mochimo_crypto::TransportKind::Io(std::io::ErrorKind::ConnectionRefused),
        }),
        "a copy whose tip could not be read was refused with another cause"
    );
    assert!(
        log.borrow().is_empty(),
        "a copy whose tip could not be read reached the socket"
    );
    assert_eq!(
        dir.snapshot_bytes(),
        on_disk,
        "the refusal wrote to the store"
    );
}

/// The copy is sent only while the tip is below the block-to-live.
#[test]
fn block_to_live_is_live_below_the_tip_and_dead_at_it() {
    let m = master();
    let (dir, saved, id) = settled_spend("recon-resubmit-expiry", 0, 4_242, 1_000_000);
    let ks = reopen("recon resubmit expiry", dir.path())
        .result
        .unwrap_or_else(|e| panic!("{e}"));

    let chain = reverted(0, 5_000_000);
    chain.accepts_submit(id);
    let log = chain.submit_log();
    let client = MeshClient::new(chain);

    client.transport().set_tip(4_241);
    let live = recon::resubmit_reverted_settle(&ks, &client, &TAG, &access(&m), &saved);
    assert_eq!(
        live,
        Ok(TxId(id)),
        "a tip one below the block-to-live refused the copy: {live:?}"
    );

    client.transport().set_tip(4_242);
    let dead = recon::resubmit_reverted_settle(&ks, &client, &TAG, &access(&m), &saved);
    assert_eq!(
        dead,
        Err(Error::SettledExpired {
            blk_to_live: 4_242,
            tip: 4_242
        })
    );
    assert_eq!(
        log.borrow().len(),
        1,
        "the expired copy reached the socket: {} write(s) in all",
        log.borrow().len()
    );
}

/// A zero block-to-live never expires, so the copy is sent without a tip being
/// read: the chain is given no tip here, and a read of one would be refused.
#[test]
fn a_zero_block_to_live_reads_no_tip() {
    let m = master();
    let (dir, saved, id) = settled_spend("recon-resubmit-no-expiry", 0, 0, 1_000_000);
    let ks = reopen("recon resubmit no expiry", dir.path())
        .result
        .unwrap_or_else(|e| panic!("{e}"));

    let chain = reverted(0, 5_000_000);
    chain.accepts_submit(id);
    let calls = chain.call_count();
    let client = MeshClient::new(chain);

    let r = recon::resubmit_reverted_settle(&ks, &client, &TAG, &access(&m), &saved);
    assert_eq!(
        r,
        Ok(TxId(id)),
        "a zero block-to-live refused the copy: {r:?}"
    );
    assert_eq!(
        calls.get(),
        2,
        "a zero block-to-live read the tip: the resolve and the submit are two"
    );
}

/// An open reservation is the state `resign` rebuilds from, not one a saved
/// copy is sent for. It is refused before the chain is asked.
#[test]
fn an_open_reservation_is_resign_not_resubmission() {
    let m = master();
    let (_dir, ks) = reserved("recon-resubmit-open");
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5))]);
    let calls = chain.call_count();
    let client = MeshClient::new(chain);

    let junk: [u8; 2] = [0x00, 0xff];
    let r = recon::resubmit_reverted_settle(&ks, &client, &TAG, &access(&m), &junk);
    assert_eq!(r, Err(Error::ReservationOpen { spent_index: 0 }));
    assert_eq!(calls.get(), 0, "an open reservation asked the chain");
}

/// A chain that is not behind the settled position by exactly one is not a
/// reverted settle, and nothing is sent. In sync means the change key holds
/// the tag; ahead means a spend this store does not record; two behind is a
/// settle at position 1 with the chain back at 0.
#[test]
fn a_chain_in_sync_ahead_or_two_behind_is_not_a_reverted_settle_and_nothing_is_sent() {
    let m = master();

    let (dir, saved, id) = settled_spend("recon-resubmit-in-sync", 0, 4_242, 1_000_000);
    let ks = reopen("recon resubmit in sync", dir.path())
        .result
        .unwrap_or_else(|e| panic!("{e}"));
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(1), 4_000_000))]);
    chain.set_tip(4_241);
    chain.accepts_submit(id);
    let log = chain.submit_log();
    let client = MeshClient::new(chain);
    let r = recon::resubmit_reverted_settle(&ks, &client, &TAG, &access(&m), &saved);
    assert_eq!(
        r,
        Err(Error::NotARevertedSettle {
            what: "the chain is in sync"
        })
    );
    client
        .transport()
        .set(TAG, ChainState::At(addr_at(2), 3_000_000));
    let r = recon::resubmit_reverted_settle(&ks, &client, &TAG, &access(&m), &saved);
    assert_eq!(
        r,
        Err(Error::NotARevertedSettle {
            what: "the chain is ahead of the store"
        })
    );
    assert!(
        log.borrow().is_empty(),
        "a chain that is not reverted received a copy"
    );
    drop(client);
    drop(ks);

    let (dir2, saved2, id2) = settled_spend("recon-resubmit-two-behind", 1, 4_242, 1_000_000);
    let ks2 = reopen("recon resubmit two behind", dir2.path())
        .result
        .unwrap_or_else(|e| panic!("{e}"));
    let chain2 = reverted(0, 5_000_000);
    chain2.set_tip(4_241);
    chain2.accepts_submit(id2);
    let log2 = chain2.submit_log();
    let client2 = MeshClient::new(chain2);
    let r = recon::resubmit_reverted_settle(&ks2, &client2, &TAG, &access(&m), &saved2);
    assert_eq!(
        r,
        Err(Error::NotARevertedSettle {
            what: "the chain is at another position"
        })
    );
    assert!(
        log2.borrow().is_empty(),
        "a chain two behind received a copy"
    );
}

/// A socket write that fails leaves the store as it was: the refusal is the
/// transport's, and the account and its snapshot read the same afterwards.
#[test]
fn a_failed_socket_write_leaves_the_store_as_it_was() {
    let m = master();
    let (dir, saved, id) = settled_spend("recon-resubmit-socket", 0, 4_242, 1_000_000);
    let ks = reopen("recon resubmit socket", dir.path())
        .result
        .unwrap_or_else(|e| panic!("{e}"));
    let view = ks.view(&TAG).unwrap_or_else(|e| panic!("{e}"));
    let on_disk = dir.snapshot_bytes();

    let chain = reverted(0, 5_000_000);
    chain.set_tip(4_241);
    chain.accepts_submit(id);
    chain.refuses_submit();
    let client = MeshClient::new(chain);

    let r = recon::resubmit_reverted_settle(&ks, &client, &TAG, &access(&m), &saved);
    assert!(
        matches!(&r, Err(Error::Transport { .. })),
        "a refused socket write did not come back as a transport refusal: {r:?}"
    );
    assert_eq!(
        ks.view(&TAG).unwrap_or_else(|e| panic!("{e}")),
        view,
        "the failed write moved the account"
    );
    assert_eq!(
        dir.snapshot_bytes(),
        on_disk,
        "the failed write changed the snapshot"
    );
}

/// The copy lands: the chain then shows the change key, the account reads in
/// sync, and the wallet opens on it as it does for any settled spend.
#[test]
fn a_saved_copy_that_lands_brings_the_account_back_in_sync_and_the_wallet_opens() {
    let m = master();
    let (dir, saved, id) = settled_spend("recon-resubmit-lands", 0, 4_242, 1_000_000);
    let ks = reopen("recon resubmit lands", dir.path())
        .result
        .unwrap_or_else(|e| panic!("{e}"));

    let chain = reverted(0, 5_000_000);
    chain.set_tip(4_241);
    chain.accepts_submit(id);
    let client = MeshClient::new(chain);

    let sent = recon::resubmit_reverted_settle(&ks, &client, &TAG, &access(&m), &saved)
        .unwrap_or_else(|e| panic!("the copy was refused: {e}"));
    assert_eq!(sent, TxId(id));

    client
        .transport()
        .set(TAG, ChainState::At(addr_at(1), 4_000_000));
    let w = Wallet::open(ks, client, Some(&m))
        .unwrap_or_else(|e| panic!("the account did not reopen after the copy landed: {e}"));
    assert_eq!(w.accounts().len(), 1);
    assert!(
        matches!(w.accounts()[0].1, AccountStatus::InSync { .. }),
        "the landed account is not in sync: {:?}",
        w.accounts()[0].1
    );
    assert_eq!(w.accounts()[0].1.index(), pos(1));
}

/// The wallet's own route reproduces the `stake-tx.mjs` fixture images.
///
/// Three group S vectors (a testnet stake, a mainnet full claim, a mainnet
/// delegate consent) are rebuilt end to end: the vector's throwaway SDK
/// master seed is imported at the vector's spend index, then
/// `plan_dust_proof` and `reserve_and_sign`. The signed region and signature
/// must match byte for byte; only the trailer differs, which the fixture
/// leaves zero and the wallet seals.
#[test]
fn the_wallet_route_reproduces_group_s_through_the_keystore() {
    use mochimo_crypto::cli::restore::import_sdk_account;
    use mochimo_crypto::mesh::spend::DustProofOp;
    use mochimo_crypto::recon::sdk_address_at;
    use mochimo_crypto::staking::ConsentTerms;

    const GROUP_S: &str = include_str!("../../../fixtures/group_s_stake_tx.json");
    let file: serde_json::Value = serde_json::from_str(GROUP_S).unwrap_or_else(|e| panic!("{e}"));
    let seed_hex = file["sdk_master_seed"].as_str().unwrap_or_else(|| panic!("no seed"));
    let mut seed = [0u8; 32];
    for (i, b) in seed.iter_mut().enumerate() {
        *b = u8::from_str_radix(&seed_hex[2 * i..2 * i + 2], 16).unwrap_or_else(|e| panic!("{e}"));
    }
    let wire_of = |id: &str| -> Vec<u8> {
        let v = file["vectors"]
            .as_array()
            .and_then(|a| a.iter().find(|v| v["id"] == id))
            .unwrap_or_else(|| panic!("{id} is not in group S"));
        let h = v["wire"].as_str().unwrap_or_else(|| panic!("{id}: wire"));
        (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap_or_else(|e| panic!("{e}"))).collect()
    };
    let consent = ConsentTerms { kind: 1, peer: [0xc0; 20], ..ConsentTerms::revoke(0xACA1) };
    let cases: [(&str, u32, DustProofOp); 3] = [
        ("S-stake-testnet", 1, DustProofOp::Stake { amount: 600_000_000_000, tier: 2, network: 7357 }),
        ("S-claim-all-dustproof", 7, DustProofOp::Claim { amount: u64::MAX }),
        ("S-accept-delegate-mainnet", 11, DustProofOp::Accept(consent)),
    ];
    let master_seed = Secret::new(seed);
    let account_seed = derive::sdk_account_seed(&master_seed, 0);
    let tag = derive::sdk_account_tag(&account_seed);
    for (id, spend, op) in cases {
        let dir = ScratchDir::new(&format!("recon-group-s-{spend}"));
        let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
        let balance = 1_000_000_000_000;
        let chain = Chain::new(&[(tag, ChainState::At(sdk_address_at(&account_seed, pos(spend)), balance))]);
        let client = MeshClient::new(chain);
        import_sdk_account(&mut ks, &client, &master_seed, 0, None).unwrap_or_else(|e| panic!("{id}: {e}"));
        let mut w = Wallet::open(ks, client, None).unwrap_or_else(|e| panic!("{id}: {e}"));
        let plan = w.plan_dust_proof(&tag, &KeyAccess::StoredRoot, op, MFEE, 0).unwrap_or_else(|e| panic!("{id}: {e}"));
        let ours = w.reserve_and_sign(&plan, KeyAccess::StoredRoot).unwrap_or_else(|e| panic!("{id}: {e}")).wire();
        let theirs = wire_of(id);
        assert_eq!(ours.len(), theirs.len(), "{id}: length");
        let body = ours.len() - 40;
        assert!(ours[..body] == theirs[..body], "{id}: the wallet's image differs from stake-tx.mjs's");
        assert!(theirs[body..].iter().all(|b| *b == 0), "{id}: stake-tx.mjs's trailer is not zero");
    }
    println!("  group S through the keystore: stake, claim all, delegate consent -- byte for byte");
}
