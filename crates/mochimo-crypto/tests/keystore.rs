// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

#![cfg(all(feature = "native", not(miri)))]
//! Keystore tests: the lock, monotonic indices, records keyed by tag, every
//! corrupt-file refusal by exact variant, stale and temp files and their
//! modes, the poisoned handle, format migration, and `Debug` redaction. See
//! `src/keystore/mod.rs` for what each enforces. The crash-durability proofs
//! are in `tests/invariants.rs`.
//!
//! Gated on `native`, as the keystore module is, and on `not(miri)` because
//! Miri forbids file I/O. Not gated on `ffi-oracle`: the keystore has no C
//! side.

#[path = "support/keystore_harness.rs"]
mod keystore_harness;

use std::os::unix::fs::PermissionsExt;

use keystore_harness::{
    derived_account, derived_account_0_of_the_imported_master, imported_account, reopen, ScratchDir,
    DERIVED_POSITION, DERIVED_TAG, DIGEST, FIGURES, IMPORTED_MASTER, IMPORTED_TAG, REOPEN_TRIES,
    REOPEN_WAIT, ROOT,
};
use mochimo_crypto::account::{Account, AccountKind, AccountRecord, WotsIndex};
use mochimo_crypto::consts::SEED_LEN;
use mochimo_crypto::keystore::{
    Call, Disk, Init, Instrumented, Kdf, KeyAccess, Keystore, Pending, Unlock, NONCE_SEED_LEN, SALT_LEN,
};
use mochimo_crypto::{Error, Secret};

fn read_snapshot(dir: &ScratchDir) -> Vec<u8> {
    dir.snapshot_bytes()
}

fn write_snapshot(dir: &ScratchDir, bytes: &[u8]) {
    std::fs::write(dir.path().join("accounts.mks"), bytes).unwrap_or_else(|e| panic!("{e}"));
}

/// Position `i`, reached by advancing from zero (`WotsIndex::from_raw` is
/// crate-private).
fn pos(i: u32) -> WotsIndex {
    let mut p = WotsIndex::ZERO;
    for _ in 0..i {
        p = p.advanced().unwrap_or_else(|e| panic!("{e}"));
    }
    p
}


#[test]
fn create_then_open_round_trips_both_kinds() {
    let dir = ScratchDir::new("roundtrip");
    let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(derived_account()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(ks.tags().unwrap_or_else(|e| panic!("{e}")), vec![IMPORTED_TAG, DERIVED_TAG]);
    drop(ks);

    let ks = Keystore::open(dir.path(), &keystore_harness::unlock()).unwrap_or_else(|e| panic!("{e}"));
    let v = ks.view(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("missing"));
    assert_eq!(v.kind, AccountKind::Imported);
    assert_eq!(v.wots_index, WotsIndex::ZERO);
    let mut roots = 0;
    for r in ks.into_records().unwrap_or_else(|e| panic!("{e}")) {
        match r {
            AccountRecord::Imported { tag, root, .. } => {
                assert_eq!(tag, IMPORTED_TAG);
                assert_eq!(root.expose(), &ROOT);
                roots += 1;
            }
            AccountRecord::Derived { tag, account_index, .. } => {
                assert_eq!(tag, DERIVED_TAG);
                assert_eq!(account_index, DERIVED_POSITION);
            }
            AccountRecord::Sdk { .. } => panic!("no SDK account was stored"),
        }
    }
    assert_eq!(roots, 1);
}

/// `adopt_master` refuses to replace a seed, and the refusal changes nothing.
///
/// A replaced master would leave every derived account pointing at a key
/// stream the store can no longer produce. Checked: the refusal's variant and
/// field; the generation, snapshot bytes and in-memory seed unchanged; the
/// handle still usable; and the first seed on disk after a reopen.
#[test]
fn adopt_master_refuses_to_replace_a_seed_and_leaves_the_store_untouched() {
    let dir = ScratchDir::new("adopt-twice");
    let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    let first = Secret::new([0x11u8; SEED_LEN]);
    let second = Secret::new([0x22u8; SEED_LEN]);
    assert!(
        ks.master().unwrap_or_else(|e| panic!("{e}")).is_none(),
        "a fresh store already holds a master seed"
    );
    let _durable = ks
        .adopt_master(&first)
        .unwrap_or_else(|e| panic!("the first adoption, into a store with no seed, was refused: {e}"));
    let generation = ks.generation().unwrap_or_else(|e| panic!("{e}"));
    let bytes = read_snapshot(&dir);

    let err = ks.adopt_master(&second).err();
    assert!(
        matches!(err, Some(Error::Exists { what: "master seed" })),
        "the second seed REPLACED the first, or the refusal came under another name than \
         Exists {{ what: \"master seed\" }}: {err:?}. Replacing the master leaves every derived \
         account pointing at a key stream the store can no longer produce (I5 through a setter)"
    );
    assert_eq!(
        ks.generation().unwrap_or_else(|e| panic!("{e}")),
        generation,
        "the refusal advanced the generation: the store is not untouched, something was \
         committed before the check"
    );
    assert_eq!(
        read_snapshot(&dir),
        bytes,
        "the refusal rewrote the snapshot: the store is not untouched"
    );
    assert_eq!(
        ks.master()
            .unwrap_or_else(|e| panic!("{e}"))
            .unwrap_or_else(|| panic!("the seed in memory is gone after a refusal"))
            .expose(),
        first.expose(),
        "the seed in memory is no longer the first adoption's"
    );
    // Not poisoned: a refusal is not a failed commit.
    ks.add(Account::derive(&first, 0))
        .unwrap_or_else(|e| panic!("the handle was poisoned by a refusal: {e}"));
    drop(ks);
    let ks = reopen("adopt twice", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        ks.master()
            .unwrap_or_else(|e| panic!("{e}"))
            .unwrap_or_else(|| panic!("the seed on disk is gone"))
            .expose(),
        first.expose(),
        "the seed on disk is not the first adoption's"
    );
    println!("  adopt_master: a second seed refused as Exists {{ master seed }}; generation, bytes and seed unchanged; handle live");
}

/// A store sealed by an earlier build opens under its password, and this
/// build reproduces the current-format bytes exactly.
///
/// `testdata/keystore_v3_snapshot.bin` and `testdata/keystore_v4_snapshot.bin`
/// were each written by `Keystore::create` at `Kdf::RECOMMENDED`, then
/// `adopt_master`, then `add(Account::derive(master, 0))`, under the fixed
/// inputs below, by the build that wrote that format version. Four checks:
///
/// 1. The v3 file opens through `Keystore::open` with the master and account
///    0 as written, and `open` does not rewrite it.
/// 2. The same calls reproduce the v4 file byte for byte, covering the whole
///    sealed path including `nonce_for`.
/// 3. The opened v3 store and the fresh v4 store agree on master, account,
///    index, reservation, retained block and generation.
/// 4. The first write re-seals the v3 store as version 4, the handle reports
///    the upgrade from 3, and a reopen reads it.
///
/// This checks compatibility, not correctness (see
/// `argon2id_v13_matches_the_rfc9106_vector`). It catches a change to the
/// production KDF parameters that tests at `CHEAP_FOR_TESTS` cannot see.
///
/// If this fails, do not re-capture either file: a failure means the
/// derivation, nonce or layout changed and every existing store is affected.
/// Re-capture only after a deliberate format change, keeping the old file.
#[test]
fn a_store_sealed_by_an_earlier_build_opens_and_is_reproduced_byte_for_byte() {
    const V3_IMAGE: &[u8] = include_bytes!("../testdata/keystore_v3_snapshot.bin");
    const V4_IMAGE: &[u8] = include_bytes!("../testdata/keystore_v4_snapshot.bin");
    const PASSWORD: &[u8] = b"pinned-store-password-not-for-real-use";
    const SALT: [u8; SALT_LEN] = [0x3C; SALT_LEN];
    const NONCE_SEED: [u8; NONCE_SEED_LEN] = [0xC3; NONCE_SEED_LEN];
    const MASTER: [u8; SEED_LEN] = [0x7E; SEED_LEN];
    let unlock = Unlock {
        password: PASSWORD,
        nonce_seed: NONCE_SEED,
    };

    // Both plaintext headers must carry the production KDF parameters.
    for (what, image, version, record) in [("v3", V3_IMAGE, V3_VERSION, V3_RECORD), ("v4", V4_IMAGE, VERSION, RECORD)] {
        assert_eq!(&image[..8], b"MCMKSTOR");
        assert_eq!(u16::from_le_bytes([image[8], image[9]]), version, "the {what} pin is not version {version}");
        let field = |at: usize| u32::from_le_bytes([image[at], image[at + 1], image[at + 2], image[at + 3]]);
        assert_eq!(
            (field(11), field(15), field(19)),
            (65536, 3, 1),
            "the {what} pin's header is not at Kdf::RECOMMENDED (65536/3/1); a cheaper capture would \
             pin a point no shipped store is sealed at"
        );
        assert_eq!(image.len(), HEADER + BODY_HEADER + record + TRAILER, "{what}: one derived record");
    }

    // 1: the v3 file opens and holds what was written; the read writes nothing.
    let dir = ScratchDir::new("v3-pinned-open");
    drop(Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}")));
    write_snapshot(&dir, V3_IMAGE);
    let ks = Keystore::open(dir.path(), &unlock).unwrap_or_else(|e| {
        panic!(
            "a version-3 store sealed by an earlier build no longer opens under its own password: {e}. \
             Every version-3 store on disk is affected. If derive_key, the AEAD or the v3 parser \
             arm changed, that is the cause; do NOT re-capture the file (this test's doc says why)"
        )
    });
    let m = Secret::new(MASTER);
    assert_eq!(
        ks.master()
            .unwrap_or_else(|e| panic!("{e}"))
            .unwrap_or_else(|| panic!("the opened store holds no master seed"))
            .expose(),
        &MASTER,
        "the master seed read back is not the one the earlier build sealed"
    );
    let tag = mochimo_crypto::derive::derive_account_tag(&m, 0);
    assert_eq!(
        ks.tags().unwrap_or_else(|e| panic!("{e}")),
        vec![tag],
        "the earlier build's store does not hold account 0 of its master (as this build derives it)"
    );
    let view = ks
        .view(&tag)
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("account 0 is not viewable"));
    assert_eq!(view.wots_index, WotsIndex::ZERO);
    assert_eq!(view.pending, None);
    assert_eq!(view.settled, None, "a version-3 record has no retained block to read");
    assert_eq!(ks.generation().unwrap_or_else(|e| panic!("{e}")), 2, "create, adopt, add: two commits after the empty image");
    assert_eq!(ks.upgraded_from(), None, "open reported a crossing before any write");
    drop(ks);
    assert_eq!(
        read_snapshot(&dir),
        V3_IMAGE,
        "open re-sealed the version-3 snapshot; the read path must not write"
    );

    // 2: this build writes the same bytes as the v4 file.
    let dir2 = ScratchDir::new("v4-pinned-recreate");
    {
        let mut ks = Keystore::create(
            dir2.path(),
            &Init {
                password: PASSWORD,
                salt: SALT,
                nonce_seed: NONCE_SEED,
                kdf: Kdf::RECOMMENDED,
            },
        )
        .unwrap_or_else(|e| panic!("{e}"));
        let _durable = ks.adopt_master(&m).unwrap_or_else(|e| panic!("{e}"));
        ks.add(Account::derive(&m, 0)).unwrap_or_else(|e| panic!("{e}"));
    }
    let fresh = read_snapshot(&dir2);
    let first_difference = fresh.iter().zip(V4_IMAGE.iter()).position(|(a, b)| a != b);
    assert!(
        fresh.len() == V4_IMAGE.len() && first_difference.is_none(),
        "this build does not reproduce, byte for byte, the version-4 store its own earlier build \
         sealed under the same password, salt, nonce seed and master at Kdf::RECOMMENDED: {} \
         bytes against {}, first difference at byte {:?}. The sealed path moved -- derive_key, \
         nonce_for, encode or the AEAD. Do NOT re-capture the file to make this green",
        fresh.len(),
        V4_IMAGE.len(),
        first_difference
    );

    // 3: the opened v3 store and the fresh v4 store hold the same state.
    let a = Keystore::open(dir.path(), &unlock).unwrap_or_else(|e| panic!("{e}"));
    let b = Keystore::open(dir2.path(), &unlock).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        a.master().unwrap_or_else(|e| panic!("{e}")).map(|s| *s.expose()),
        b.master().unwrap_or_else(|e| panic!("{e}")).map(|s| *s.expose()),
        "the v3 file and the v4 store disagree on the master"
    );
    assert_eq!(a.tags().unwrap_or_else(|e| panic!("{e}")), b.tags().unwrap_or_else(|e| panic!("{e}")));
    assert_eq!(
        a.view(&tag).unwrap_or_else(|e| panic!("{e}")),
        b.view(&tag).unwrap_or_else(|e| panic!("{e}")),
        "the v3 file and the v4 store disagree on account 0's index, reservation or retained block"
    );
    assert_eq!(a.generation().unwrap_or_else(|e| panic!("{e}")), b.generation().unwrap_or_else(|e| panic!("{e}")));
    drop(b);

    // 4: the first write re-seals as version 4.
    let mut a = a;
    a.add(Account::derive(&m, 1)).unwrap_or_else(|e| panic!("the first write over a version-3 store was refused: {e}"));
    assert_eq!(
        a.upgraded_from(),
        Some(V3_VERSION),
        "the handle does not report the crossing after the first write"
    );
    drop(a);
    let crossed = read_snapshot(&dir);
    assert_eq!(u16::from_le_bytes([crossed[8], crossed[9]]), VERSION, "the first write did not re-seal the store as version 4");
    assert_eq!(crossed.len(), HEADER + BODY_HEADER + 2 * RECORD + TRAILER, "the re-sealed store is not two version-4 records long");
    // Opened directly: `reopen` uses the harness password, not this one.
    let again = Keystore::open(dir.path(), &unlock).unwrap_or_else(|e| panic!("the re-sealed store does not reopen: {e}"));
    assert_eq!(again.tags().unwrap_or_else(|e| panic!("{e}")).len(), 2);
    assert_eq!(again.upgraded_from(), None, "a store opened at version 4 reports a crossing");
    println!(
        "  pinned images: v3 ({} bytes) opens under its password with master and account 0 intact \
         and is left on disk as written; v4 ({} bytes) is reproduced byte for byte; the two agree on \
         state; the v3 store's first write re-seals it as version {VERSION}",
        V3_IMAGE.len(),
        V4_IMAGE.len()
    );
}

/// A version-3 reservation is read with its figures absent, and the reserved
/// key still re-signs.
///
/// `testdata/keystore_v3_reserved_snapshot.bin` was written by a version-3
/// build for the harness's imported master at account 0 (`create` at
/// `CHEAP_FOR_TESTS`, `adopt_master`, `add`, `persist_advance`): a
/// reservation at 0, index 1, no figures. Checked: it opens; the reservation
/// reads back with `figures: None`, not zero; the open writes nothing;
/// `resign_reserved` produces the same signature a fresh version-4 store
/// does for the same reservation (WOTS+ is deterministic); and the first
/// write, a settle, re-seals as version 4 with the block retained and its
/// figures still absent, also after a reopen.
#[test]
fn a_version_3_reservation_is_read_with_its_figures_absent_and_still_resigns() {
    const IMAGE: &[u8] = include_bytes!("../testdata/keystore_v3_reserved_snapshot.bin");
    assert_eq!(u16::from_le_bytes([IMAGE[8], IMAGE[9]]), V3_VERSION, "the reservation capture is not version 3");
    assert_eq!(IMAGE.len(), HEADER + BODY_HEADER + V3_RECORD + TRAILER, "one version-3 record");
    let master = Secret::new(IMPORTED_MASTER);
    assert_eq!(derived_account_0_of_the_imported_master().tag(), IMPORTED_TAG);
    let migrated_block = Pending {
        spent_index: WotsIndex::ZERO,
        digest: DIGEST,
        figures: None,
    };

    let dir = ScratchDir::new("v3-reserved-read");
    drop(keystore_harness::create(dir.path()).unwrap_or_else(|e| panic!("{e}")));
    write_snapshot(&dir, IMAGE);
    let ks = keystore_harness::open(dir.path()).unwrap_or_else(|e| {
        panic!("the captured version-3 reservation no longer opens under the harness's password: {e}")
    });
    assert_eq!(ks.tags().unwrap_or_else(|e| panic!("{e}")), vec![IMPORTED_TAG]);
    let view = ks
        .view(&IMPORTED_TAG)
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("the capture's account is not viewable"));
    assert_eq!(view.wots_index.get(), 1, "the capture's reservation advanced the index to 1");
    assert_eq!(
        view.pending,
        Some(migrated_block),
        "a version-3 reservation must read back with figures: None -- declared absent, not zero"
    );
    assert_eq!(view.settled, None);
    assert_eq!(ks.upgraded_from(), None, "open reported a crossing before any write");
    let migrated = ks
        .resign_reserved(&IMPORTED_TAG, &KeyAccess::Master(&master))
        .unwrap_or_else(|e| panic!("the reserved key of a migrated reservation no longer re-signs: {e} -- the capability the migration exists to preserve"));
    assert_eq!(migrated.spent_index, WotsIndex::ZERO);
    drop(ks);
    assert_eq!(read_snapshot(&dir), IMAGE, "open or resign_reserved rewrote the version-3 snapshot");

    // Byte-identical to what a fresh version-4 store signs over the same reservation.
    let dir2 = ScratchDir::new("v3-reserved-fresh-v4");
    let mut fresh = keystore_harness::create(dir2.path()).unwrap_or_else(|e| panic!("{e}"));
    let _durable = fresh.adopt_master(&master).unwrap_or_else(|e| panic!("{e}"));
    fresh.add(derived_account_0_of_the_imported_master()).unwrap_or_else(|e| panic!("{e}"));
    let _receipt = fresh.persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES).unwrap_or_else(|e| panic!("{e}"));
    let native = fresh
        .resign_reserved(&IMPORTED_TAG, &KeyAccess::Master(&master))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(native.spent_index, WotsIndex::ZERO);
    assert_eq!(
        &migrated.signature[..],
        &native.signature[..],
        "the migrated reservation and a fresh version-4 store signed DIFFERENT bytes over one key, one \
         digest and one position; the read arm changed what resign_reserved signs"
    );
    assert_eq!(migrated.pub_seed, native.pub_seed);
    assert_eq!(&migrated.public_key[..], &native.public_key[..]);
    drop(fresh);

    // The first write re-seals as version 4 with the block retained and its
    // figures still absent -- on the live handle and after a reopen.
    let mut ks = reopen("v3 reserved settle", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    ks.persist_settled(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(ks.upgraded_from(), Some(V3_VERSION), "the first write did not report the crossing");
    let live = ks.view(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("gone"));
    assert_eq!(live.pending, None);
    assert_eq!(live.settled, Some(migrated_block), "memory: the settled block was not retained with its figures absent");
    drop(ks);
    let after = read_snapshot(&dir);
    assert_eq!(u16::from_le_bytes([after[8], after[9]]), VERSION, "the first write did not re-seal the store as version 4");
    assert_eq!(after.len(), HEADER + BODY_HEADER + RECORD + TRAILER, "one version-4 record");
    let ks = reopen("v3 reserved reopened", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let disk = ks.view(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("gone"));
    assert_eq!(disk.pending, None);
    assert_eq!(disk.settled, Some(migrated_block), "disk: the settled block was not retained with its figures absent");
    assert_eq!(ks.upgraded_from(), None, "a store opened at version 4 reports a crossing");
    println!(
        "  version-3 reservation capture: {} bytes read with figures absent, the reserved key re-signs \
         byte-identically to a fresh version-4 store, and the first write re-seals as version {VERSION} \
         with the block retained",
        IMAGE.len()
    );
}

/// A settled block is retained through a reopen, released by the next
/// reservation and cleared by an acknowledged advance, each checked in memory
/// and after a reopen.
///
/// The retained block never blocks `persist_advance`. `persist_advance_to`
/// clears it because the advance breaks the relation between the block and
/// the index that the encoder requires.
#[test]
fn a_settled_block_is_retained_through_a_reopen_and_released_by_the_next_reservation_or_advance() {
    const DIGEST_2: [u8; 32] = [0xD2; 32];
    let dir = ScratchDir::new("retained-block");
    let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    let first = Pending {
        spent_index: WotsIndex::ZERO,
        digest: DIGEST,
        figures: Some(FIGURES),
    };
    let view = |ks: &Keystore| ks.view(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("gone"));

    let _r = ks.persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(view(&ks).pending, Some(first));
    assert_eq!(view(&ks).settled, None);

    // Settle: the block moves, on the live handle and on disk.
    ks.persist_settled(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}"));
    let v = view(&ks);
    assert_eq!(v.pending, None, "memory: settle left the reservation open");
    assert_eq!(v.settled, Some(first), "memory: the settled block was not retained with its figures");
    drop(ks);
    let mut ks = reopen("retained block", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let v = view(&ks);
    assert_eq!(v.pending, None, "disk: settle left the reservation open");
    assert_eq!(v.settled, Some(first), "disk: the settled block was not retained with its figures");

    // Released by the next reservation, which is NOT refused.
    let r2 = ks
        .persist_advance(&IMPORTED_TAG, &DIGEST_2, FIGURES)
        .unwrap_or_else(|e| panic!("a retained settled block blocked the next reservation -- the freeze the retained block must not cause: {e}"));
    assert_eq!(r2.index().get(), 2);
    let second = Pending {
        spent_index: pos(1),
        digest: DIGEST_2,
        figures: Some(FIGURES),
    };
    let v = view(&ks);
    assert_eq!(v.pending, Some(second), "memory: the second reservation is not what was sealed");
    assert_eq!(v.settled, None, "memory: the new reservation did not release the retained block");
    drop(ks);
    let mut ks = reopen("released block", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let v = view(&ks);
    assert_eq!(v.pending, Some(second), "disk: the second reservation is not what was sealed");
    assert_eq!(v.settled, None, "disk: the new reservation did not release the retained block");

    // Cleared by an acknowledged advance: settle again, then advance to 3.
    ks.persist_settled(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(view(&ks).settled, Some(second));
    let three = pos(3);
    let _r3 = ks.persist_advance_to(&IMPORTED_TAG, three).unwrap_or_else(|e| panic!("{e}"));
    let v = view(&ks);
    assert_eq!(v.wots_index, three);
    assert_eq!(v.settled, None, "memory: persist_advance_to left the retained block in the live handle");
    assert_eq!(v.pending, None);
    drop(ks);
    let ks = reopen("cleared block", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let v = view(&ks);
    assert_eq!(v.wots_index, three);
    assert_eq!(v.settled, None, "disk: persist_advance_to left the retained block");
    assert_eq!(v.pending, None);
    println!("  retained block: kept through settle and reopen (memory and disk), released by the next reservation, cleared by persist_advance_to");
}

/// A retained block survives writes about other accounts: `add`, another
/// account's reservation, and `adopt_master`.
#[test]
fn a_retained_block_survives_a_write_that_does_not_override_its_account() {
    let block = Pending {
        spent_index: WotsIndex::ZERO,
        digest: DIGEST,
        figures: Some(FIGURES),
    };
    let settled_imported = |ks: &Keystore| {
        ks.view(&IMPORTED_TAG)
            .unwrap_or_else(|e| panic!("{e}"))
            .unwrap_or_else(|| panic!("gone"))
            .settled
    };

    // Store A: settle on the imported account, then `add` and `adopt_master`.
    let a = ScratchDir::new("retained-add");
    let mut ks = Keystore::create(a.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    let _r = ks.persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES).unwrap_or_else(|e| panic!("{e}"));
    ks.persist_settled(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}"));
    ks.add(derived_account()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(settled_imported(&ks), Some(block), "memory: `add` of another account dropped the retained block");
    let _durable = ks.adopt_master(&Secret::new([0x11u8; SEED_LEN])).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(settled_imported(&ks), Some(block), "memory: adopt_master dropped the retained block");
    drop(ks);
    let ks = reopen("retained add", a.path()).result.unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(settled_imported(&ks), Some(block), "disk: a write that did not override the account dropped its retained block");
    assert_eq!(ks.tags().unwrap_or_else(|e| panic!("{e}")).len(), 2);
    drop(ks);

    // Store B: both accounts; settle on the imported one; reserve on the OTHER.
    let b = ScratchDir::new("retained-other-reservation");
    let mut ks = Keystore::create(b.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(derived_account()).unwrap_or_else(|e| panic!("{e}"));
    let _r = ks.persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES).unwrap_or_else(|e| panic!("{e}"));
    ks.persist_settled(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}"));
    let _r = ks.persist_advance(&DERIVED_TAG, &DIGEST, FIGURES).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(settled_imported(&ks), Some(block), "memory: another account's reservation dropped the retained block");
    drop(ks);
    let ks = reopen("retained other", b.path()).result.unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(settled_imported(&ks), Some(block), "disk: another account's reservation dropped the retained block");
    let other = ks.view(&DERIVED_TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("gone"));
    assert!(other.pending.is_some() && other.settled.is_none());
    println!("  retained block: survives `add`, `adopt_master` and another account's reservation, in memory and on disk");
}

#[test]
fn second_open_in_process_is_refused_while_the_first_is_held() {
    let dir = ScratchDir::new("lock");
    let a = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    let b = Keystore::open(dir.path(), &keystore_harness::unlock()).err();
    assert_eq!(b, Some(Error::Locked), "a second handle opened while the first was held");
    drop(a);
    let b = Keystore::open(dir.path(), &keystore_harness::unlock());
    assert!(b.is_ok(), "the lock did not release on drop: {:?}", b.err());
    // The lock file is never unlinked; the kernel releases the lock.
    assert!(dir.listing().iter().any(|n| n == "keystore.lock"));
}

/// Test binaries that spawn child processes reopen a keystore only through
/// the harness's bounded retry helper: a child inherits lock descriptions
/// until its exec, so a just-released lock can briefly look held. This
/// binary spawns nothing and opens directly on purpose. Line comments are
/// stripped before the search; the helper's own call sites in
/// `invariants.rs` are the positive control.
#[test]
fn crash_proofs_reopen_only_through_the_bounded_helper() {
    // `invariants.rs` spawns children and must use the helper at least four
    // times; `spend.rs` and `mesh.rs` must not open a keystore directly.
    const FILES: &[(&str, usize)] = &[("tests/invariants.rs", 4), ("tests/spend.rs", 0), ("tests/mesh.rs", 0)];
    let mut files_read = 0usize;
    for (rel, min_helper_uses) in FILES {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        files_read += 1;
        let code: String = text
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");
        let bare: Vec<&str> = ["Keystore::open(", "Keystore::open_with("]
            .into_iter()
            .filter(|needle| code.contains(needle))
            .collect();
        assert!(
            bare.is_empty(),
            "{rel} reopens a keystore with a bare {bare:?}. A test binary that spawns processes \
             shares its lock descriptions with each child until its exec, and a just-released \
             flock can look held for ~200 µs there; route the reopen through \
             keystore_harness::reopen / reopen_with, which retries Error::Locked alone, bounded."
        );
        let through_helper = code.matches("keystore_harness::reopen").count();
        assert!(
            through_helper >= *min_helper_uses,
            "found {through_helper} reopen(s) through the helper in {rel}, fewer than {min_helper_uses}; \
             for invariants.rs the I2 proof has three and the I3 proof one, so fewer than four means \
             the search is not reading the file it thinks it is"
        );
    }
    assert_eq!(files_read, FILES.len());
}

/// The bounded reopen helper still reports `Locked` for a live holder: it
/// retries exactly the bound, the waits happen, and once the holder drops the
/// call opens with no retry.
#[test]
fn reopen_helper_still_refuses_a_genuine_second_holder_at_the_bound() {
    let dir = ScratchDir::new("reopen-bound");
    let holder = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));

    let started = std::time::Instant::now();
    let r = reopen("genuine holder", dir.path());
    let elapsed = started.elapsed();
    assert!(
        matches!(r.result, Err(Error::Locked)),
        "a live handle was still held and the helper opened anyway: {:?}",
        r.result.as_ref().err()
    );
    assert_eq!(
        r.retries, REOPEN_TRIES,
        "the helper gave up after {} retries, not at the bound of {REOPEN_TRIES}",
        r.retries
    );
    let floor = REOPEN_WAIT * u32::try_from(REOPEN_TRIES).unwrap_or(u32::MAX);
    assert!(
        elapsed >= floor,
        "{REOPEN_TRIES} retries of {REOPEN_WAIT:?} took {elapsed:?}: the waits did not happen"
    );
    assert!(
        elapsed < floor * 200,
        "{REOPEN_TRIES} retries of {REOPEN_WAIT:?} took {elapsed:?}: the bound is not the bound"
    );

    drop(holder);
    let r = reopen("holder released", dir.path());
    assert!(r.result.is_ok(), "after the holder dropped: {:?}", r.result.as_ref().err());
    assert_eq!(r.retries, 0, "no child is being spawned here, so nothing should have retried");
}

/// Only `Locked` is retried: a missing snapshot returns `Missing` with zero
/// retries.
#[test]
fn reopen_helper_returns_every_other_error_immediately() {
    let dir = ScratchDir::new("reopen-missing");
    std::fs::DirBuilder::new()
        .mode_0700()
        .create(dir.path())
        .unwrap_or_else(|e| panic!("{e}"));
    let r = reopen("missing snapshot", dir.path());
    assert!(matches!(r.result, Err(Error::Missing)), "{:?}", r.result.as_ref().err());
    assert_eq!(r.retries, 0, "a non-Locked error was retried {} time(s)", r.retries);
}

#[test]
fn open_refuses_a_missing_snapshot_and_create_refuses_an_existing_store() {
    let dir = ScratchDir::new("missing");
    std::fs::DirBuilder::new()
        .mode_0700()
        .create(dir.path())
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(Keystore::open(dir.path(), &keystore_harness::unlock()).err(), Some(Error::Missing));
    let ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    drop(ks);
    assert_eq!(
        Keystore::create(dir.path(), &keystore_harness::init()).err(),
        Some(Error::Exists { what: "snapshot" })
    );
}

trait Mode0700 {
    fn mode_0700(&mut self) -> &mut Self;
}
impl Mode0700 for std::fs::DirBuilder {
    fn mode_0700(&mut self) -> &mut Self {
        use std::os::unix::fs::DirBuilderExt;
        self.mode(0o700)
    }
}

#[test]
fn persist_advance_to_refuses_non_increasing_targets_and_writes_nothing() {
    let dir = ScratchDir::new("monotonic");
    let mut ks = Keystore::create_with(dir.path(), Instrumented::new(Disk), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    let mut a = imported_account();
    for _ in 0..3 {
        a.advance().unwrap_or_else(|e| panic!("{e}"));
    }
    ks.add(a).unwrap_or_else(|e| panic!("{e}"));
    let before = read_snapshot(&dir);
    ks.medium_mut().reset_calls();

    let stored = ks.view(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("missing")).wots_index;
    assert_eq!(stored.get(), 3);
    let lower = ks.persist_advance_to(&IMPORTED_TAG, WotsIndex::ZERO).err();
    assert_eq!(
        lower,
        Some(Error::Range { what: "wots index for tag", min: 4, max: u64::from(u32::MAX), got: 0 }),
        "persist_advance_to accepted a target below the stored index"
    );
    let equal = ks.persist_advance_to(&IMPORTED_TAG, stored).err();
    assert_eq!(
        equal,
        Some(Error::Range { what: "wots index for tag", min: 4, max: u64::from(u32::MAX), got: 3 }),
        "persist_advance_to accepted a target equal to the stored index"
    );
    assert_eq!(read_snapshot(&dir), before, "a refusal rewrote the snapshot");
    assert!(ks.medium().calls().is_empty(), "a refusal touched the medium: {:?}", ks.medium().calls());

    let next = stored.advanced().unwrap_or_else(|e| panic!("{e}"));
    let r = ks.persist_advance_to(&IMPORTED_TAG, next).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(r.index(), next);
    drop(ks);
    let ks = Keystore::open(dir.path(), &keystore_harness::unlock()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(ks.view(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("missing")).wots_index, next);
}

/// `persist_rollback_to` refuses while a reservation is open and for a
/// target at or ahead of the stored index, writing nothing; to a target
/// behind it, it writes the index and clears the retained settled block, in
/// memory and on disk.
#[test]
fn persist_rollback_to_moves_only_backward_with_no_reservation_open() {
    let dir = ScratchDir::new("rollback");
    let mut ks = Keystore::create_with(dir.path(), Instrumented::new(Disk), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    let _r = ks.persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES).unwrap_or_else(|e| panic!("{e}"));

    let before = read_snapshot(&dir);
    ks.medium_mut().reset_calls();
    assert_eq!(
        ks.persist_rollback_to(&IMPORTED_TAG, WotsIndex::ZERO).err(),
        Some(Error::PendingUnresolved { spent_index: 0 }),
        "persist_rollback_to moved an account with a reservation open"
    );
    assert_eq!(read_snapshot(&dir), before, "a refusal rewrote the snapshot");
    assert!(ks.medium().calls().is_empty(), "a refusal touched the medium: {:?}", ks.medium().calls());

    ks.persist_settled(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}"));
    let view = |ks: &Keystore<Instrumented<Disk>>| {
        ks.view(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("missing"))
    };
    assert_eq!(view(&ks).wots_index, pos(1));
    assert!(view(&ks).settled.is_some(), "premise: the settle retained its block");

    let before = read_snapshot(&dir);
    ks.medium_mut().reset_calls();
    let range = |got: u64| Some(Error::Range { what: "wots index for tag", min: 0, max: 0, got });
    assert_eq!(ks.persist_rollback_to(&IMPORTED_TAG, pos(1)).err(), range(1), "a target equal to the stored index was accepted");
    assert_eq!(ks.persist_rollback_to(&IMPORTED_TAG, pos(2)).err(), range(2), "a target ahead of the stored index was accepted");
    assert_eq!(read_snapshot(&dir), before, "a refusal rewrote the snapshot");
    assert!(ks.medium().calls().is_empty(), "a refusal touched the medium: {:?}", ks.medium().calls());

    let back = ks.persist_rollback_to(&IMPORTED_TAG, WotsIndex::ZERO).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(back, WotsIndex::ZERO);
    let v = view(&ks);
    assert_eq!(v.wots_index, WotsIndex::ZERO, "memory: the rollback did not move the index");
    assert_eq!(v.settled, None, "memory: the rollback left the retained block");
    assert_eq!(v.pending, None);
    drop(ks);
    let ks = Keystore::open(dir.path(), &keystore_harness::unlock()).unwrap_or_else(|e| panic!("{e}"));
    let v = ks.view(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("missing"));
    assert_eq!(v.wots_index, WotsIndex::ZERO, "disk: the rollback did not reach the snapshot");
    assert_eq!(v.settled, None, "disk: the rollback left the retained block");
}

#[test]
fn records_are_addressed_by_tag_not_position() {
    let d1 = ScratchDir::new("bytag-1");
    let d2 = ScratchDir::new("bytag-2");
    let mut k1 = Keystore::create(d1.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    k1.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    k1.add(derived_account()).unwrap_or_else(|e| panic!("{e}"));
    let mut k2 = Keystore::create(d2.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    k2.add(derived_account()).unwrap_or_else(|e| panic!("{e}"));
    k2.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    // The image is `header | ciphertext | tag`, and the harness fixes the
    // password, salt, nonce seed and KDF, so byte equality also requires the
    // same key, AAD, nonce and tag. It catches a salt or nonce that varies
    // with insertion order or anything else it must not. This holds because
    // the crate has no RNG: the caller supplies the salt and nonce seed.
    let (f1, f2) = (read_snapshot(&d1), read_snapshot(&d2));
    assert_eq!(f1, f2, "insertion order leaked into the image");
    // The header and tag regions, compared explicitly.
    assert_eq!(f1[..HEADER], f2[..HEADER], "the plaintext headers differ: salt or nonce varied");
    assert_eq!(
        f1[f1.len() - TRAILER..],
        f2[f2.len() - TRAILER..],
        "the AEAD tags differ, so the two stores did not seal identical plaintext under an \
         identical key and nonce"
    );
    let target = WotsIndex::ZERO.advanced().unwrap_or_else(|e| panic!("{e}"));
    let _receipt = k1.persist_advance_to(&DERIVED_TAG, target).unwrap_or_else(|e| panic!("{e}"));
    let _receipt = k2.persist_advance_to(&DERIVED_TAG, target).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(read_snapshot(&d1), read_snapshot(&d2));
    for k in [&k1, &k2] {
        assert_eq!(k.view(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("missing")).wots_index, WotsIndex::ZERO);
        assert_eq!(k.view(&DERIVED_TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("missing")).wots_index, target);
    }
}

#[test]
fn medium_sequence_is_exactly_the_four_steps_with_their_arguments() {
    let dir = ScratchDir::new("sequence");
    let mut ks = Keystore::create_with(dir.path(), Instrumented::new(Disk), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    ks.medium_mut().reset_calls();
    let _receipt = ks.persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES).unwrap_or_else(|e| panic!("{e}"));
    let tmp = dir.path().join("accounts.mks.tmp");
    let snap = dir.path().join("accounts.mks");
    let len = read_snapshot(&dir).len();
    assert_eq!(
        ks.medium().calls(),
        &[
            Call::WriteTemp { path: tmp.clone(), len },
            Call::FsyncFile { path: tmp.clone() },
            Call::Rename { from: tmp, to: snap.clone() },
            Call::FsyncDir { dir: dir.path().to_path_buf() },
        ]
    );
    drop(ks);
    let ks = keystore_harness::reopen_with("sequence", dir.path(), || Instrumented::new(Disk))
        .result
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        ks.medium().calls(),
        &[Call::FlushStanding { path: snap }],
        "open did not flush the snapshot and its directory before the handle existed"
    );
}

/// `open` refuses a store whose snapshot and directory it cannot flush, with
/// the flush's error, and opens it once the flush succeeds. No handle exists
/// over an image that may still be only in the cache, so `resign`, which
/// signs without committing, never signs from one. The instrument performs
/// the flush and then reports it failed.
#[test]
fn open_refuses_a_store_whose_snapshot_it_cannot_flush() {
    let dir = ScratchDir::new("open-flush");
    let mut ks = keystore_harness::create(dir.path()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    drop(ks);
    let refused = keystore_harness::reopen_with("open flush", dir.path(), || {
        let mut medium = Instrumented::new(Disk);
        medium.stop_after(Some(1));
        medium
    })
    .result
    .err();
    assert_eq!(
        refused,
        Some(Error::Io {
            op: "flush_standing",
            kind: std::io::ErrorKind::Interrupted
        }),
        "an open whose flush of the snapshot failed was not refused by that flush"
    );
    assert!(keystore_harness::open(dir.path()).is_ok(), "the store does not open once the flush succeeds");
}

/// `create` flushes the store directory's parent once before its first
/// commit, whether it made the directory or found it, then runs the commit's
/// four steps.
#[test]
fn create_flushes_the_store_directory_parent_before_its_first_commit() {
    let made = ScratchDir::new("parent-flush-made");
    let found = ScratchDir::new("parent-flush-found");
    std::fs::create_dir(found.path()).unwrap_or_else(|e| panic!("cannot make {}: {e}", found.path().display()));
    for (dir, how) in [(&made, "a directory create made"), (&found, "a directory create found")] {
        let ks = Keystore::create_with(dir.path(), Instrumented::new(Disk), &keystore_harness::init()).unwrap_or_else(|e| panic!("{how}: {e}"));
        let parent = dir.path().parent().unwrap_or_else(|| panic!("{how}: a scratch directory has a parent")).to_path_buf();
        let tmp = dir.path().join("accounts.mks.tmp");
        let snap = dir.path().join("accounts.mks");
        let len = read_snapshot(dir).len();
        assert_eq!(
            ks.medium().calls(),
            &[
                Call::FsyncParent { dir: parent },
                Call::WriteTemp { path: tmp.clone(), len },
                Call::FsyncFile { path: tmp.clone() },
                Call::Rename { from: tmp, to: snap },
                Call::FsyncDir { dir: dir.path().to_path_buf() },
            ],
            "{how}: create's recorded sequence"
        );
    }
}

/// The image header width, from the layout in `src/keystore/format.rs`
/// (whose constants are crate-private). Checked against a written file in
/// `corrupt_snapshots_are_refused_by_exact_variant_and_never_panic`.
const HEADER: usize = 8 + 2 + 1 + 4 + 4 + 4 + 16 + 12;
/// `generation | count | master_present | master`, inside the ciphertext.
const BODY_HEADER: usize = 8 + 4 + 1 + 32;
/// The version-4 record: tag 20, kind 1, body 32, first 64, stream 20,
/// index 4, pending 1, spent 4, digest 32, figures 1, reserved balance 8,
/// block-to-live 8.
const RECORD: usize = 20 + 1 + 32 + 64 + 20 + 4 + 1 + 4 + 32 + 1 + 8 + 8;
/// The Poly1305 tag.
const TRAILER: usize = 16;
/// The version this build writes.
const VERSION: u16 = 4;
/// The version-3 record (without the 17 figures bytes) and version word, for
/// the captured version-3 files.
const V3_RECORD: usize = 20 + 1 + 32 + 64 + 20 + 4 + 1 + 4 + 32;
const V3_VERSION: u16 = 3;
/// Version 1's header and trailer widths, for the captured version-1 file.
const V1_HEADER: usize = 22;
const V1_TRAILER: usize = 32;

#[test]
fn corrupt_snapshots_are_refused_by_exact_variant_and_never_panic() {
    let dir = ScratchDir::new("corrupt");
    let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(derived_account()).unwrap_or_else(|e| panic!("{e}"));
    drop(ks);
    let good = read_snapshot(&dir);

    // Two records fix the length, and the version word is at offset 8.
    assert_eq!(
        good.len(),
        HEADER + BODY_HEADER + 2 * RECORD + TRAILER,
        "the offsets below are derived from these widths; one of them moved"
    );
    assert_eq!(u16::from_le_bytes([good[8], good[9]]), VERSION);

    // A flipped byte is `WrongPassword`, not `Corrupt`: the AEAD refuses it
    // before any record is read and deliberately does not distinguish damage
    // from a wrong password.
    let mut flipped = good.clone();
    flipped[HEADER + 5] ^= 1;
    write_snapshot(&dir, &flipped);
    assert_eq!(
        Keystore::open(dir.path(), &keystore_harness::unlock()).err(),
        Some(Error::WrongPassword),
        "a flipped byte loaded"
    );

    let mut newer = good.clone();
    newer[8..10].copy_from_slice(&(VERSION + 1).to_le_bytes());
    write_snapshot(&dir, &newer);
    assert_eq!(
        Keystore::open(dir.path(), &keystore_harness::unlock()).err(),
        Some(Error::UnsupportedVersion { got: VERSION + 1, supported: VERSION, first_account: None }),
        "an unknown version must say upgrade, not corrupt"
    );
    // A newer version is reported as written by a newer build, without the
    // migration advice meant for older stores.
    let Err(newer_refusal) = Keystore::open(dir.path(), &keystore_harness::unlock()) else {
        panic!("refused above")
    };
    let newer_text = format!("{newer_refusal}");
    for needle in [format!("format version {}", VERSION + 1), "NEWER build".to_owned(), "at least that new".to_owned()] {
        assert!(newer_text.contains(&needle), "the newer-version refusal does not say {needle:?}:\n{newer_text}");
    }
    assert!(
        !newer_text.contains("FRESH directory"),
        "a store a NEWER build wrote was given the older-store migration advice:\n{newer_text}"
    );

    // The duplicate-tag rule is tested in `format.rs`, which can re-seal the
    // plaintext. From here, an edited record is refused by the AEAD.
    let mut dup = good.clone();
    dup.copy_within(HEADER..HEADER + 20, HEADER + RECORD);
    write_snapshot(&dir, &dup);
    assert_eq!(
        Keystore::open(dir.path(), &keystore_harness::unlock()).err(),
        Some(Error::WrongPassword),
        "an edited record loaded"
    );

    // every prefix truncation, and one trailing byte: an Err, never a panic
    for n in 0..good.len() {
        write_snapshot(&dir, &good[..n]);
        assert!(Keystore::open(dir.path(), &keystore_harness::unlock()).is_err(), "prefix {n} opened");
    }
    let mut longer = good.clone();
    longer.push(0);
    write_snapshot(&dir, &longer);
    assert!(Keystore::open(dir.path(), &keystore_harness::unlock()).is_err());

    write_snapshot(&dir, &good);
    assert!(Keystore::open(dir.path(), &keystore_harness::unlock()).is_ok());
}

/// A format-version-1 store is refused through `open` as needing migration,
/// not as damaged.
///
/// The file was written by a version-1 build. Checked:
///
/// * it reports `UnsupportedVersion`;
/// * with its trailer destroyed it still reports the version, showing the
///   version is checked before the trailer;
/// * the rendered message says to migrate into a fresh directory.
#[test]
fn a_version_1_store_is_refused_with_upgrade_not_damage() {
    // Shared with `src/keystore/format.rs`; see `testdata/README.md`.
    const V1: &[u8] = include_bytes!("../testdata/keystore_v1_snapshot.bin");
    // Version 1 has 94-byte records.
    assert_eq!(V1.len(), V1_HEADER + 2 * 94 + V1_TRAILER);
    assert_eq!(u16::from_le_bytes([V1[8], V1[9]]), 1);

    let dir = ScratchDir::new("v1-refused");
    let ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    drop(ks);
    write_snapshot(&dir, V1);
    let err = Keystore::open(dir.path(), &keystore_harness::unlock()).err();
    // It names its first account: an imported record with tag `0x1a * 20`.
    let first = Some(([0x1a; 20], AccountKind::Imported));
    assert_eq!(
        err,
        Some(Error::UnsupportedVersion { got: 1, supported: VERSION, first_account: first }),
        "a version-1 store must report its version"
    );

    let mut broken = V1.to_vec();
    let last = broken.len() - 1;
    broken[last] ^= 0xff;
    write_snapshot(&dir, &broken);
    assert_eq!(
        Keystore::open(dir.path(), &keystore_harness::unlock()).err(),
        Some(Error::UnsupportedVersion { got: 1, supported: VERSION, first_account: first }),
        "the version must be dispatched BEFORE the trailer is verified"
    );

    let rendered = format!("{}", err.expect("checked above"));
    // The message names the current version and that a version-3 store is
    // read and re-sealed.
    for needle in ["format version 1", "reads version 4", "re-sealing it as version 4", "FRESH directory", "never by rewriting it in place"] {
        assert!(rendered.contains(needle), "the message does not say {needle:?}: {rendered}");
    }
}

#[test]
fn stale_temp_is_unlinked_and_never_adopted() {
    let dir = ScratchDir::new("stale-temp");
    let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    drop(ks);
    let target = read_snapshot(&dir);
    // A valid image of a different state, left as the temp.
    let other = ScratchDir::new("stale-temp-other");
    let mut o = Keystore::create(other.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    o.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    let _receipt = o.persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES).unwrap_or_else(|e| panic!("{e}"));
    drop(o);
    let advanced_image = other.snapshot_bytes();
    assert_ne!(advanced_image, target);
    std::fs::write(dir.path().join("accounts.mks.tmp"), &advanced_image).unwrap_or_else(|e| panic!("{e}"));

    let ks = Keystore::open(dir.path(), &keystore_harness::unlock()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        ks.view(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("missing")).wots_index,
        WotsIndex::ZERO,
        "open adopted the stale temp"
    );
    assert!(!dir.listing().iter().any(|n| n == "accounts.mks.tmp"), "open left the stale temp");
    assert_eq!(read_snapshot(&dir), target);
}

#[test]
fn temp_file_is_created_mode_0600_and_the_directory_0700() {
    let dir = ScratchDir::new("modes");
    let mut ks = Keystore::create_with(dir.path(), Instrumented::new(Disk), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    let dmode = std::fs::metadata(dir.path()).unwrap_or_else(|e| panic!("{e}")).permissions().mode() & 0o777;
    assert_eq!(dmode, 0o700);
    ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    ks.medium_mut().stop_after(Some(1));
    let _ = ks.persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES);
    let tmode = std::fs::metadata(dir.path().join("accounts.mks.tmp")).unwrap_or_else(|e| panic!("{e}")).permissions().mode() & 0o777;
    assert_eq!(tmode, 0o600, "the temp holds plaintext roots and must not be group/other readable");
}

#[test]
fn open_refuses_a_group_writable_directory() {
    let dir = ScratchDir::new("perms");
    let ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    drop(ks);
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o775)).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(Keystore::open(dir.path(), &keystore_harness::unlock()).err(), Some(Error::UnsafePermissions { mode: 0o775 }));
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap_or_else(|e| panic!("{e}"));
    assert!(Keystore::open(dir.path(), &keystore_harness::unlock()).is_ok());
}

#[test]
fn poisoned_handle_refuses_to_launder_a_rollback() {
    // advance_to(k+5) fails at the directory fsync (disk = k+5, memory = k).
    // A later advance on the same handle would write k+1 over disk's k+5, so
    // the handle is poisoned and its message says drop and reopen.
    let dir = ScratchDir::new("poison");
    let mut ks = Keystore::create_with(dir.path(), Instrumented::new(Disk), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    let mut target = WotsIndex::ZERO;
    for _ in 0..5 {
        target = target.advanced().unwrap_or_else(|e| panic!("{e}"));
    }
    ks.medium_mut().stop_after(Some(4));
    let err = ks.persist_advance_to(&IMPORTED_TAG, target).err().unwrap_or_else(|| panic!("expected the injected error"));
    assert_eq!(err, Error::Io { op: "fsync_dir", kind: std::io::ErrorKind::Interrupted });
    ks.medium_mut().stop_after(None);
    let later = ks.persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES).err().unwrap_or_else(|| panic!("a poisoned handle wrote"));
    assert!(matches!(later, Error::Poisoned { .. }), "{later:?}");
    let msg = later.to_string();
    assert!(msg.contains("drop this handle and reopen"), "{msg}");
    assert!(msg.contains("do not retry"), "{msg}");
    drop(ks);
    let ks = Keystore::open(dir.path(), &keystore_harness::unlock()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        ks.view(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("missing")).wots_index,
        target,
        "disk's committed k+5 was overwritten"
    );
}

#[test]
fn pending_gates_a_second_advance_until_settled() {
    let dir = ScratchDir::new("pending");
    let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(ks.persist_settled(&IMPORTED_TAG).err(), Some(Error::NothingPending));
    let _receipt = ks.persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        ks.persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES).err(),
        Some(Error::PendingUnresolved { spent_index: 0 })
    );
    let v = ks.view(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("missing"));
    assert_eq!(v.pending.map(|p| p.spent_index.get()), Some(0));
    ks.persist_settled(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}"));
    let r = ks.persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(r.index().get(), 2);
    drop(ks);
    let ks = Keystore::open(dir.path(), &keystore_harness::unlock()).unwrap_or_else(|e| panic!("{e}"));
    let v = ks.view(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("missing"));
    assert_eq!(v.wots_index.get(), 2);
    assert_eq!(v.pending.map(|p| p.spent_index.get()), Some(1));
}

/// The `Keystore`'s `Debug` never renders an imported root.
///
/// The needles are derived from `ROOT`, so they track the harness, and are
/// searched in the rendering after the directory path, which contains a
/// timestamp that could match a short needle by chance.
#[test]
fn debug_never_reveals_keystore_roots() {
    let dir = ScratchDir::new("debug");
    let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    let rendered = format!("{ks:?}");
    assert!(rendered.starts_with("Keystore { dir:"), "{rendered}");
    assert!(rendered.contains("accounts: 1"), "{rendered}");

    // Everything after the directory field; the path is not searched.
    let after_dir = rendered
        .split_once("\", generation")
        .map(|(_, rest)| rest.to_owned())
        .unwrap_or_else(|| panic!("the Debug shape moved; re-read what it renders: {rendered}"));

    // The root's hex in both cases, and its decimal bytes.
    let hex_lower: String = ROOT.iter().map(|b| format!("{b:02x}")).collect();
    let hex_upper = hex_lower.to_ascii_uppercase();
    for needle in [&hex_lower, &hex_upper] {
        assert!(
            !after_dir.contains(needle.as_str()),
            "the root's hex reached the rendering: {rendered}"
        );
        // ...and any four-hex-digit prefix of it, so a partial leak is caught.
        assert!(
            !after_dir.contains(&needle[..4]),
            "a prefix of the root's hex reached the rendering: {rendered}"
        );
    }
    // The decimal form as `[u8; N]`'s `Debug` renders it, matched as a
    // sequence: a single byte's decimal could collide with the generation.
    let decimals = format!("{:?}", &ROOT[..]);
    let inner = decimals.trim_start_matches('[').trim_end_matches(']');
    assert!(
        !after_dir.contains(inner),
        "the root's decimal rendering reached the Debug output: {rendered}"
    );
    let head = inner.split(", ").take(4).collect::<Vec<_>>().join(", ");
    assert!(
        !after_dir.contains(&head),
        "a prefix of the root's decimal rendering reached the Debug output: {rendered}"
    );
}

// ---------------------------------------------------------------------------
// Imported roots are encrypted at rest
// ---------------------------------------------------------------------------

/// The imported root is not in the snapshot file, and it is restored exactly.
///
/// Both are checked, since a store that zeroed the root would pass the
/// absence check alone. Absence is checked at offset 43, where the
/// version-2 plaintext format placed the root, and anywhere in the file.
#[test]
fn snapshot_bytes_never_contain_the_imported_root() {
    use keystore_harness::{imported_account, ScratchDir, ROOT};

    let dir = ScratchDir::new("i6-at-rest-proof");
    let mut ks = keystore_harness::create(dir.path()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    drop(ks);

    let bytes = dir.snapshot_bytes();

    // 1. Absent: not at the version-2 offset, and not anywhere else.
    const V2_ROOT_OFFSET: usize = 43;
    if bytes.len() > V2_ROOT_OFFSET + ROOT.len() {
        assert_ne!(
            &bytes[V2_ROOT_OFFSET..V2_ROOT_OFFSET + ROOT.len()],
            &ROOT[..],
            "the imported root is at byte {V2_ROOT_OFFSET}, where the version-2 plaintext format \
             put it"
        );
    }
    assert!(
        bytes.windows(ROOT.len()).all(|w| w != ROOT),
        "the imported root's 32 bytes appear somewhere in the snapshot. The whole point of \
         version 3 is that they do not."
    );

    // 2. Restored after a reopen.
    let ks = keystore_harness::open(dir.path()).unwrap_or_else(|e| panic!("{e}"));
    let tag = keystore_harness::IMPORTED_TAG;
    let view = ks
        .view(&tag)
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("the imported account did not survive the round trip"));
    assert_eq!(view.tag, tag);
    // The root is not exposed, so the restore is checked through the key
    // stream's identity, which is derived from it. `open` would also have
    // failed: `Account::restore_from_record` recomputes the tag and stream
    // identity from the root and refuses a mismatch.
    assert_eq!(
        ks.stream_id(&tag)
            .unwrap_or_else(|e| panic!("{e}"))
            .as_bytes(),
        &keystore_harness::IMPORTED_STREAM,
        "the imported account's key-stream identity changed across the round trip, so the root \
         did not come back byte-identical"
    );
    drop(ks);

    // 3. A flipped bit in the AEAD tag is refused.
    let mut flipped = bytes.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x01;
    dir.write_snapshot(&flipped);
    match keystore_harness::open(dir.path()) {
        Err(Error::WrongPassword) => {}
        other => panic!("a flipped tag byte was not refused: {other:?}"),
    }

    // 4. The store is refused under a different password.
    dir.write_snapshot(&bytes);
    match Keystore::open(
        dir.path(),
        &keystore_harness::unlock_with(keystore_harness::OTHER_PASSWORD),
    ) {
        Err(Error::WrongPassword) => {}
        other => panic!("a store opened under a password it was not created with: {other:?}"),
    }
    // Control: it still opens under the right password.
    let _reopened = keystore_harness::open(dir.path())
        .unwrap_or_else(|e| panic!("the store stopped opening: {e}"));

    println!(
        "  I6 at rest: root absent from {} snapshot bytes, restored byte-identical, bit flip \
         refused, wrong password refused",
        bytes.len()
    );
}

/// A lock file alone is inert; only a live holder of the lock refuses.
///
/// 1. `open` on a directory with no snapshot refuses `Missing` and leaves no
///    lock file.
/// 2. `open` on a snapshot it cannot read (a version-2 file) refuses and does
///    leave `keystore.lock`, because the lock is taken before the read. The
///    keystore module doc states this side effect.
/// 3. With the snapshot present, `create` refuses on the snapshot.
/// 4. With only the lock file present, `create` proceeds.
/// 5. A live holder makes `create` fail with `Locked`, and the lock is
///    released on drop.
#[test]
fn a_lock_file_with_no_snapshot_is_inert_and_only_a_live_holder_refuses_create() {
    use mochimo_crypto::keystore::occupied;
    let dir = ScratchDir::new("lock-inert");
    std::fs::DirBuilder::new()
        .mode_0700()
        .create(dir.path())
        .unwrap_or_else(|e| panic!("{e}"));
    let has_lock = |d: &ScratchDir| d.listing().iter().any(|n| n == "keystore.lock");

    // 1.
    assert_eq!(Keystore::open(dir.path(), &keystore_harness::unlock()).err(), Some(Error::Missing));
    assert!(
        !has_lock(&dir),
        "the Missing refusal left keystore.lock behind: the lock was taken before the snapshot \
         check, which the lock design fixed. Listing: {:?}",
        dir.listing()
    );

    // 2.
    let ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    drop(ks);
    let mut v2 = read_snapshot(&dir);
    // Forged to version 2, which this build cannot read (version 3 it can).
    v2[8..10].copy_from_slice(&(V3_VERSION - 1).to_le_bytes());
    write_snapshot(&dir, &v2);
    std::fs::remove_file(dir.path().join("keystore.lock")).unwrap_or_else(|e| panic!("{e}"));
    assert!(!has_lock(&dir), "premise: the copy has no lock");
    assert_eq!(
        Keystore::open(dir.path(), &keystore_harness::unlock()).err(),
        // A v4 image under a version-2 word fits no v2 layout, so no account
        // is named.
        Some(Error::UnsupportedVersion { got: V3_VERSION - 1, supported: VERSION, first_account: None })
    );
    assert!(
        has_lock(&dir),
        "a failed open at the version word did NOT leave keystore.lock behind. That is a \
         change to what `open_with` does before it reads, and the keystore module doc's \
         sentence recording the side effect (\"The lock\") now says something false -- update \
         it with this arm. Listing: {:?}",
        dir.listing()
    );

    // 3.
    assert_eq!(occupied(dir.path()), Some("snapshot"));
    assert_eq!(
        Keystore::create(dir.path(), &keystore_harness::init()).err(),
        Some(Error::Exists { what: "snapshot" }),
        "create over a directory holding a snapshot it cannot read must refuse on the snapshot"
    );

    // 4.
    std::fs::remove_file(dir.path().join("accounts.mks")).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(dir.listing(), vec!["keystore.lock".to_string()], "premise: only the lock remains");
    assert_eq!(
        occupied(dir.path()),
        None,
        "a lock file with no snapshot beside it reads as an occupied directory. Nothing holds \
         it -- the flock is what says whether anything does -- so refusing here is the \
         stale-lock design the lock design rejected, and the refusal's advice (run another command) \
         is contradicted by every other command's `Missing`."
    );
    let held = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| {
        panic!("create refused a directory holding only an UNHELD keystore.lock: {e}")
    });

    // 5.
    std::fs::remove_file(dir.path().join("accounts.mks")).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        Keystore::create(dir.path(), &keystore_harness::init()).err(),
        Some(Error::Locked),
        "a LIVE holder of keystore.lock was not refused by create; the flock is the only thing \
         standing between two processes writing one directory"
    );
    drop(held);
    let released = Keystore::create(dir.path(), &keystore_harness::init());
    assert!(released.is_ok(), "the lock did not release on drop: {:?}", released.err());

    println!("  lock file inert: 5 arms -- Missing leaves none, a failed read leaves one, the snapshot refuses, the file alone does not, a live holder does");
}

/// The salt in the header is the salt the key was derived from.
///
/// Round trips cannot show this: a writer and reader that both ignored the
/// header salt would still agree. Two stores under the same password, nonce
/// seed and KDF but different salts must seal different ciphertext, since
/// `nonce_for` does not depend on the salt.
#[test]
fn the_header_salt_is_the_salt_the_key_was_derived_from() {
    let d1 = ScratchDir::new("salt-1");
    let d2 = ScratchDir::new("salt-2");
    let mut init1 = keystore_harness::init();
    init1.salt = [0x11; 16];
    let mut init2 = keystore_harness::init();
    init2.salt = [0x22; 16];
    let k1 = Keystore::create(d1.path(), &init1).unwrap_or_else(|e| panic!("{e}"));
    let k2 = Keystore::create(d2.path(), &init2).unwrap_or_else(|e| panic!("{e}"));
    drop((k1, k2));
    let (f1, f2) = (read_snapshot(&d1), read_snapshot(&d2));
    assert_eq!(f1.len(), f2.len(), "two empty stores differ in length");
    assert_ne!(
        f1[HEADER - 12 - 16..HEADER - 12],
        f2[HEADER - 12 - 16..HEADER - 12],
        "the two headers carry the same salt; the test's premise is broken"
    );
    assert_ne!(
        f1[HEADER..f1.len() - TRAILER],
        f2[HEADER..f2.len() - TRAILER],
        "two stores whose headers carry different salts sealed identical ciphertext: the KDF did \
         not consume the salt the header carries, so the salt is decoration and two stores under \
         one password share a key"
    );
}

// ---------------------------------------------------------------------------
// The version refusal names the refused store's first account
// ---------------------------------------------------------------------------

/// Bytes `[22..42)` and `[42]` of a version-1 or version-2 image: the first
/// record's tag and kind. Both layouts are
/// `magic[8] | version u16 | generation u64 | count u32`, then records sorted
/// by tag, each `tag[20] | kind u8 | …` (94 bytes in v1, 178 in v2).
fn first_record_of_an_older_image(image: &[u8]) -> ([u8; 20], u8) {
    let mut tag = [0u8; 20];
    tag.copy_from_slice(&image[22..42]);
    (tag, image[42])
}

/// The version refusal names the refused store's first account and how to
/// check whether this store holds it.
///
/// In a version-1 or version-2 file the first record's tag is unencrypted at
/// bytes 22..42, so the refusal can name it in hex, name the record's kind,
/// and suggest `address 0x<tag>` on the current store. The kind matters: a
/// derived tag identifies a master seed and index, an imported tag only one
/// root's key stream.
///
/// Driven with a captured version-1 file and a captured version-2 file (the
/// latter holding the harness's two accounts), each opened through
/// `Keystore::open`.
///
/// # Controls
///
/// * The tag read from the v2 file equals `IMPORTED_TAG`, its known first
///   account, and the v1 file's tag (`0x1a` twenty times) appears only for
///   the v1 file.
/// * A newer image with its version word forged to 2, and one with an
///   unknown KDF id, render no procedure: a tag is read only from an image
///   whose length fits that version's layout.
/// * Every proper prefix of the v2 file is refused without a procedure.
#[test]
fn the_version_refusal_names_the_refused_stores_first_account_and_how_to_compare_it() {
    const V1: &[u8] = include_bytes!("../testdata/keystore_v1_snapshot.bin");
    const V2: &[u8] = include_bytes!("../testdata/keystore_v2_snapshot.bin");
    const V2_RECORD: usize = 20 + 1 + 32 + 64 + 20 + 4 + 1 + 4 + 32;
    const PROCEDURE: &str = "address 0x";
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();

    // The captured v2 file's geometry, checked before anything reads it.
    assert_eq!(V2.len(), V1_HEADER + 2 * V2_RECORD + V1_TRAILER, "the v2 capture is not two records long");
    assert_eq!(&V2[..8], b"MCMKSTOR");
    assert_eq!(u16::from_le_bytes([V2[8], V2[9]]), 2, "the v2 capture's version word is not 2");
    assert_eq!(u32::from_le_bytes([V2[18], V2[19], V2[20], V2[21]]), 2, "the v2 capture's count is not 2");
    let (v2_tag, v2_kind) = first_record_of_an_older_image(V2);
    assert_eq!(
        v2_tag, IMPORTED_TAG,
        "the v2 capture's first record is not the imported account it was built with: either the \
         layout reading (tag at 22..42) or the capture is wrong"
    );
    assert_eq!(v2_kind, 1, "the v2 capture's first record is not marked imported");
    let (v1_tag, v1_kind) = first_record_of_an_older_image(V1);
    assert_eq!(v1_tag, [0x1a; 20], "the v1 capture's first record is not the 0x1a tag it was written with");
    assert_eq!(v1_kind, 1);
    assert_ne!(v1_tag, v2_tag);

    let render = |dir: &ScratchDir, bytes: &[u8], want_got: u16| -> String {
        write_snapshot(dir, bytes);
        let err = Keystore::open(dir.path(), &keystore_harness::unlock()).err();
        assert!(
            matches!(err, Some(Error::UnsupportedVersion { got, .. }) if got == want_got),
            "premise: the file was not refused as version {want_got}: {err:?}"
        );
        format!("{}", err.expect("checked"))
    };

    let mut failures: Vec<String> = Vec::new();
    // 1. The genuine version-2 store.
    let dir = ScratchDir::new("format2-store");
    drop(Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}")));
    let v2_text = render(&dir, V2, 2);
    for needle in [hex(&v2_tag), format!("{PROCEDURE}{}", hex(&v2_tag)), "imported".to_owned()] {
        if !v2_text.contains(&needle) {
            failures.push(format!("the v2 refusal does not say {needle:?}"));
        }
    }
    // 2. The genuine version-1 store: its own tag, not the other file's.
    let v1_text = render(&dir, V1, 1);
    for needle in [hex(&v1_tag), format!("{PROCEDURE}{}", hex(&v1_tag)), "imported".to_owned()] {
        if !v1_text.contains(&needle) {
            failures.push(format!("the v1 refusal does not say {needle:?}"));
        }
    }
    assert!(!v1_text.contains(&hex(&v2_tag)), "the v1 refusal names the v2 file's tag: a constant, not a reading:\n{v1_text}");

    // 3. A v3 store under a forged version word: no tag can be read from it.
    let v3_dir = ScratchDir::new("format3-image");
    drop(Keystore::create(v3_dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}")));
    let good = read_snapshot(&v3_dir);
    assert_eq!(u16::from_le_bytes([good[8], good[9]]), VERSION);
    let mut forged = good.clone();
    forged[8..10].copy_from_slice(&2u16.to_le_bytes());
    let forged_text = render(&v3_dir, &forged, 2);
    assert!(
        !forged_text.contains(PROCEDURE),
        "a v3 image under a forged version word was told to run `{PROCEDURE}` over bytes that are its salt:\n{forged_text}"
    );
    // 4. An unknown KDF id: the same variant, and no tag named.
    let mut kdf = good.clone();
    kdf[10] ^= 0x7f;
    let kdf_text = render(&v3_dir, &kdf, u16::from(kdf[10]));
    assert!(!kdf_text.contains(PROCEDURE), "an unknown-KDF refusal names a procedure over ciphertext:\n{kdf_text}");
    // The KDF-id refusal reuses the variant (`got` = the id, `supported` = 1)
    // and must not carry the version refusal's sentences.
    for needle in ["NEWER build", "at least that new", "version-3 store", "re-sealing"] {
        assert!(
            !kdf_text.contains(needle),
            "the KDF-id refusal renders the version arm's sentence {needle:?} -- the Display's \
             guard on which producer made the variant is gone:\n{kdf_text}"
        );
    }

    // 5. Every proper prefix of the v2 file is refused without a panic or a
    //    procedure.
    let mut prefixes = 0usize;
    for n in 0..V2.len() {
        write_snapshot(&dir, &V2[..n]);
        let err = Keystore::open(dir.path(), &keystore_harness::unlock()).err().unwrap_or_else(|| panic!("a {n}-byte prefix of the v2 capture OPENED"));
        assert!(
            !format!("{err}").contains(PROCEDURE),
            "a {n}-byte prefix of the v2 capture was told a procedure: {err}"
        );
        prefixes += 1;
    }
    assert_eq!(prefixes, V2.len());

    if failures.is_empty() {
        // Print the rendered refusal on success too.
        println!(
            "  version refusal names the refused store's first account: v1 and v2 captures, {prefixes} prefixes refused without a procedure\n  v2 refusal as rendered:\n    {v2_text}"
        );
        return;
    }
    panic!(
        "THE VERSION REFUSAL DOES NOT SAY HOW TO TELL WHETHER THE REFUSED STORE IS ON THE SEED OF THE \
         STORE IN HAND. An operator holding an old format-2 store over the seed they use \
         is told to migrate into a fresh directory and nothing about whether the refused store IS the \
         wallet they are running -- while the `Ahead` arm tells them to compare key streams with a \
         report that store cannot print. {} thing(s) missing:\n\x20 - {}\n\
         \n\
         The condition: \"Green when the `UnsupportedVersion` refusal says how to tell \
         whether the refused store is on the seed of the store in hand.\"\n\
         \n\
         What clears it: the refusal names the first record's tag, read from bytes 22..42 of a file \
         whose length fits its version's closed formula (v1: 22 + n*94 + 32; v2: 22 + n*178 + 32) and \
         nothing else, names the record's kind, and tells the operator to run `address 0x<tag>` on the \
         store in hand -- an answer means the same account is held in both (for a derived record one \
         master seed; for an imported one, one root, which says nothing about the master) and one WOTS+ \
         key stream can sign from each store; a refusal means that account is not held here, which does \
         not prove a different seed.\n\
         \n\
         v2 refusal as rendered:\n{v2_text}\n\nv1 refusal as rendered:\n{v1_text}",
        failures.len(),
        failures.join("\n  - ")
    );
}

// ---------------------------------------------------------------------------
// Range refusals name their own bounds
// ---------------------------------------------------------------------------

/// `open`'s size check and the parser's length check name the same range
/// for `keystore image length`: 112 (the empty store) to 12,779,632 (the
/// cap). A snapshot one byte over the cap is refused by the size check
/// before the file is read.
#[test]
fn the_image_length_range_names_one_minimum_at_both_gates() {
    let dir = ScratchDir::new("length-range");
    let ks = keystore_harness::create(dir.path()).unwrap_or_else(|e| panic!("{e}"));
    drop(ks);
    let mut image = read_snapshot(&dir);
    image.resize(12_779_632 + 1, 0);
    dir.write_snapshot(&image);
    let err = keystore_harness::open(dir.path()).err();
    assert_eq!(
        err,
        Some(Error::Range {
            what: "keystore image length",
            min: 112,
            max: 12_779_632,
            got: 12_779_633,
        }),
        "the stat gate did not name the parser's range for an oversized snapshot: {err:?}"
    );
    println!("  image length: the stat gate names 112..=12779632, the parser's own range, for a 12779633-byte snapshot");
}

/// `Kdf::checked` names the parameter it refused, with that parameter's
/// bounds and value: memory below Argon2's floor of 8 KiB or above the
/// format's ceiling of 1 GiB, passes below 1 or above the smaller of 64 and
/// 4,194,304 KiB-passes over the memory, lanes outside 1..=16. A `t_cost` of
/// 0 is reported against passes, not memory.
#[test]
fn kdf_refusals_name_the_parameter_they_are_about() {
    let refused = |kdf: Kdf| kdf.checked().err();
    assert_eq!(
        refused(Kdf { m_cost_kib: 1_048_577, t_cost: 1, p_cost: 1 }),
        Some(Error::Range { what: "keystore kdf m_cost", min: 8, max: 1_048_576, got: 1_048_577 }),
        "the ceiling refusal"
    );
    assert_eq!(
        refused(Kdf { m_cost_kib: 4, t_cost: 1, p_cost: 1 }),
        Some(Error::Range { what: "keystore kdf m_cost", min: 8, max: 1_048_576, got: 4 }),
        "memory below Argon2's floor"
    );
    assert_eq!(
        refused(Kdf { m_cost_kib: 8, t_cost: 0, p_cost: 1 }),
        Some(Error::Range { what: "keystore kdf t_cost", min: 1, max: 64, got: 0 }),
        "zero passes is a t_cost refusal, not a memory one"
    );
    assert_eq!(
        refused(Kdf { m_cost_kib: 8, t_cost: 65, p_cost: 1 }),
        Some(Error::Range { what: "keystore kdf t_cost", min: 1, max: 64, got: 65 }),
        "more than 64 passes"
    );
    assert_eq!(
        refused(Kdf { m_cost_kib: 65536, t_cost: u32::MAX, p_cost: 1 }),
        Some(Error::Range { what: "keystore kdf t_cost", min: 1, max: 64, got: u64::from(u32::MAX) }),
        "the most passes a header can name"
    );
    assert_eq!(
        refused(Kdf { m_cost_kib: 1_048_576, t_cost: 5, p_cost: 1 }),
        Some(Error::Range { what: "keystore kdf t_cost", min: 1, max: 4, got: 5 }),
        "passes over the largest memory are bounded by the work ceiling"
    );
    assert_eq!(refused(Kdf { m_cost_kib: 1_048_576, t_cost: 4, p_cost: 1 }), None, "the work ceiling itself is accepted");
    assert_eq!(refused(Kdf { m_cost_kib: 65536, t_cost: 64, p_cost: 1 }), None, "64 passes over 64 MiB is accepted");
    assert_eq!(
        refused(Kdf { m_cost_kib: 8, t_cost: 1, p_cost: 0 }),
        Some(Error::Range { what: "keystore kdf p_cost", min: 1, max: 16, got: 0 }),
        "zero lanes is a p_cost refusal"
    );
    assert_eq!(
        refused(Kdf { m_cost_kib: 1_048_576, t_cost: 1, p_cost: 17 }),
        Some(Error::Range { what: "keystore kdf p_cost", min: 1, max: 16, got: 17 }),
        "more than 16 lanes"
    );
    assert_eq!(refused(Kdf::CHEAP_FOR_TESTS), None, "the cheap point is accepted");
    assert_eq!(refused(Kdf::RECOMMENDED), None, "the shipped point is accepted");
    println!("  kdf refusals: m_cost (ceiling and floor), t_cost (floor, ceiling and work) and p_cost each named with their own bounds and value");
}

/// A store whose plaintext header names an unbounded pass count or too many
/// lanes is refused at `open` by name, before the key is derived, instead of
/// running the derivation it names.
#[test]
fn open_refuses_a_header_whose_kdf_costs_exceed_the_ceilings() {
    let dir = ScratchDir::new("kdf-cost-header");
    drop(keystore_harness::create(dir.path()).unwrap_or_else(|e| panic!("{e}")));
    let good = read_snapshot(&dir);
    for (at, value, what) in [(15usize, u32::MAX, "keystore kdf t_cost"), (19, 0xFF_FFFF, "keystore kdf p_cost")] {
        let mut forged = good.clone();
        forged[at..at + 4].copy_from_slice(&value.to_le_bytes());
        write_snapshot(&dir, &forged);
        let started = std::time::Instant::now();
        let err = Keystore::open(dir.path(), &keystore_harness::unlock()).err();
        assert!(
            matches!(err, Some(Error::Range { what: w, got, .. }) if w == what && got == u64::from(value)),
            "a header naming {value} for {what} was not refused by name: {err:?}"
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(5), "the refusal of {what} took {:?}", started.elapsed());
    }
    write_snapshot(&dir, &good);
    assert!(keystore_harness::open(dir.path()).is_ok(), "the restored header does not open");
}

// ---------------------------------------------------------------------------
// A stale temp keeps no mode
// ---------------------------------------------------------------------------

/// A leftover `accounts.mks.tmp` with looser permissions does not pass its
/// mode to the snapshot. A mode given at open applies only to a newly
/// created file, so the temp is unlinked before it is created. The mode is
/// read back from disk after the commit.
#[test]
fn a_stale_temp_with_loose_permissions_does_not_reach_the_snapshot() {
    let dir = ScratchDir::new("stale-temp-mode");
    let mut ks = keystore_harness::create(dir.path()).unwrap_or_else(|e| panic!("{e}"));
    let tmp = dir.path().join("accounts.mks.tmp");
    std::fs::write(&tmp, b"a leftover from an interrupted commit").unwrap_or_else(|e| panic!("{e}"));
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).unwrap_or_else(|e| panic!("{e}"));
    let before = std::fs::metadata(&tmp).unwrap_or_else(|e| panic!("{e}")).permissions().mode() & 0o777;
    assert_eq!(before, 0o644, "premise: the stale temp reads back as 0644 (a filesystem that honours mode bits)");

    ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    let snap = std::fs::metadata(dir.path().join("accounts.mks")).unwrap_or_else(|e| panic!("{e}")).permissions().mode() & 0o777;
    assert_eq!(
        snap,
        0o600,
        "THE SNAPSHOT INHERITED THE STALE TEMP'S MODE: accounts.mks reads back as {snap:o} after a \
         commit over a 0644 leftover"
    );
    assert!(!dir.listing().iter().any(|n| n == "accounts.mks.tmp"), "the temp outlived the commit");
    drop(ks);
    let reopened = keystore_harness::open(dir.path()).unwrap_or_else(|e| panic!("the store written over the leftover does not open: {e}"));
    assert_eq!(reopened.tags().unwrap_or_else(|e| panic!("{e}")), vec![IMPORTED_TAG]);
    println!("  stale temp: a 0644 leftover was unlinked before the commit; the snapshot reads back 0600");
}

// ---------------------------------------------------------------------------
// A derived record's identity is checked at the door
// ---------------------------------------------------------------------------

/// When the store holds the master, `add` refuses a derived account whose
/// stored key-stream identity the master does not reproduce
/// (`StreamIdNotReproduced`, as `sign_spend` does), and a derived account
/// from another master (`DerivedTagNotReproduced`). Honest derived and
/// imported accounts still add.
#[test]
fn a_derived_record_with_a_forged_stream_identity_is_refused_at_add() {
    let master = Secret::new(IMPORTED_MASTER);
    let honest = derived_account_0_of_the_imported_master();
    let forged = match honest.to_record() {
        AccountRecord::Derived {
            tag,
            account_index,
            wots_index,
            ..
        } => Account::restore_from_record(AccountRecord::Derived {
            tag,
            account_index,
            stream_id: mochimo_crypto::account::StreamId::from_bytes([0x5Eu8; 20]),
            wots_index,
        })
        .unwrap_or_else(|e| panic!("a derived record restores without a master to check it: {e}")),
        other => panic!("the honest account is not a derived record: {other:?}"),
    };

    let dir = ScratchDir::new("forged-stream-at-add");
    let mut ks = keystore_harness::create(dir.path()).unwrap_or_else(|e| panic!("{e}"));
    let _durable = ks.adopt_master(&master).unwrap_or_else(|e| panic!("{e}"));
    let generation = ks.generation().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        ks.add(forged).err(),
        Some(Error::StreamIdNotReproduced),
        "A DERIVED RECORD WITH A FORGED STREAM IDENTITY WAS ADDED to a store holding the master \
         that could have checked it"
    );
    assert_eq!(ks.generation().unwrap_or_else(|e| panic!("{e}")), generation, "the refusal wrote");
    assert_eq!(
        ks.add(derived_account()).err(),
        Some(Error::DerivedTagNotReproduced { account_index: DERIVED_POSITION }),
        "a derived account from ANOTHER master was added to a store whose master does not derive it"
    );
    ks.add(derived_account_0_of_the_imported_master()).unwrap_or_else(|e| panic!("the honest derived account was refused: {e}"));
    let dir2 = ScratchDir::new("forged-stream-at-add-imported");
    let mut ks2 = keystore_harness::create(dir2.path()).unwrap_or_else(|e| panic!("{e}"));
    let _durable = ks2.adopt_master(&Secret::new(keystore_harness::DERIVED_MASTER)).unwrap_or_else(|e| panic!("{e}"));
    ks2.add(imported_account()).unwrap_or_else(|e| panic!("an imported account was refused by the derived check: {e}"));
    ks2.add(derived_account()).unwrap_or_else(|e| panic!("the honest derived account was refused beside an imported one: {e}"));
    println!("  forged identity: refused at add by StreamIdNotReproduced; a foreign master's account by DerivedTagNotReproduced; honest accounts of both kinds add");
}

/// A store with no master cannot check a derived record at `add`; once a
/// master is supplied, signing re-derives the identity and refuses the
/// forged record with `StreamIdNotReproduced`.
#[test]
fn a_forged_derived_record_that_got_in_without_a_master_is_still_refused_at_signing_time() {
    let honest = derived_account_0_of_the_imported_master();
    let forged = match honest.to_record() {
        AccountRecord::Derived {
            tag,
            account_index,
            wots_index,
            ..
        } => Account::restore_from_record(AccountRecord::Derived {
            tag,
            account_index,
            stream_id: mochimo_crypto::account::StreamId::from_bytes([0x5Eu8; 20]),
            wots_index,
        })
        .unwrap_or_else(|e| panic!("{e}")),
        other => panic!("not a derived record: {other:?}"),
    };
    let dir = ScratchDir::new("forged-stream-no-master");
    let mut ks = keystore_harness::create(dir.path()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(forged).unwrap_or_else(|e| panic!("with no master in the store nothing can check the identity, and add refused: {e}"));
    let master = Secret::new(IMPORTED_MASTER);
    assert_eq!(
        ks.spend_addresses(&IMPORTED_TAG, &KeyAccess::Master(&master)).err(),
        Some(Error::StreamIdNotReproduced),
        "the forged record was acted on at signing time"
    );
    println!("  forged identity, no master at add: stored as carried, refused at signing time by StreamIdNotReproduced");
}

// ---------------------------------------------------------------------------
// Two refusals that say what to do
// ---------------------------------------------------------------------------

/// `Exists { what: "snapshot" }` renders with the next step -- a different
/// `--dir` for a new store, `restore --account N` into this one -- rather
/// than as a bare "already exists". The other `what`s keep the short form.
#[test]
fn an_existing_snapshot_is_refused_with_the_next_step() {
    let text = format!("{}", Error::Exists { what: "snapshot" });
    assert!(text.contains("use a different --dir"), "no next step for a new store: {text}");
    assert!(text.contains("restore --account N"), "no next step for an account in this store: {text}");
    assert!(text.contains("Nothing was changed"), "the refusal does not say nothing was changed: {text}");
    assert_eq!(format!("{}", Error::Exists { what: "account tag" }), "keystore: account tag already exists");
    println!("  existing snapshot: the refusal names a different --dir and restore --account N");
}

/// `WrongPassword` says it cannot tell a wrong password from a damaged file
/// and what to try: the password, a backup, the phrase. One variant covers
/// both so the error is not a decryption oracle.
#[test]
fn a_store_that_does_not_decrypt_says_it_cannot_tell_why_and_what_to_try() {
    let text = format!("{}", Error::WrongPassword);
    assert!(text.contains("did not decrypt"), "{text}");
    assert!(text.contains("cannot tell you which, by design"), "the refusal does not say it cannot tell, by design: {text}");
    assert!(text.contains("What to try"), "the refusal names nothing to try: {text}");
    assert!(text.contains("create --from-phrase") && text.contains("restore --account N"), "the refusal does not name the recovery from the phrase: {text}");
    // The store returns the variant on a wrong password.
    let dir = ScratchDir::new("wrong-password-text");
    let ks = keystore_harness::create(dir.path()).unwrap_or_else(|e| panic!("{e}"));
    drop(ks);
    let err = Keystore::open(dir.path(), &keystore_harness::unlock_with(b"not-the-password-either")).err();
    assert_eq!(err, Some(Error::WrongPassword));
    println!("  wrong password: the refusal says by design and names three things to try; the variant is unchanged");
}

/// A snapshot or lock that group or others may read or write is refused at
/// `open` with `UnsafeFileMode` naming the file, even inside a directory the
/// directory check accepts, and the store opens again once the file is
/// `0600`. Execute bits alone are not refused.
#[cfg(unix)]
#[test]
fn open_refuses_a_store_file_group_or_others_can_read_or_write() {
    use std::os::unix::fs::PermissionsExt;
    let dir = ScratchDir::new("file-mode");
    drop(keystore_harness::create(dir.path()).unwrap_or_else(|e| panic!("{e}")));
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap_or_else(|e| panic!("{e}"));
    for name in ["accounts.mks", "keystore.lock"] {
        let path = dir.path().join(name);
        for mode in [0o640, 0o604, 0o620, 0o602, 0o644] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(
                Keystore::open(dir.path(), &keystore_harness::unlock()).err(),
                Some(Error::UnsafeFileMode { file: name, mode }),
                "{name} at {mode:o} was not refused"
            );
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o711)).unwrap_or_else(|e| panic!("{e}"));
        assert!(keystore_harness::open(dir.path()).is_ok(), "{name} with execute bits alone was refused");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap_or_else(|e| panic!("{e}"));
    }
    assert!(keystore_harness::open(dir.path()).is_ok(), "the store does not open once both files are 0600");
    let text = Error::UnsafeFileMode { file: "accounts.mks", mode: 0o644 }.to_string();
    assert!(text.contains("chmod 600 accounts.mks"), "{text}");
    assert!(text.contains("fmask=077"), "{text}");
    assert!(text.contains("move the store"), "{text}");
}

/// An ancestor rename must never separate the lock from the signing state.
#[cfg(unix)]
#[test]
fn unix_commit_keeps_the_locked_directory_after_path_replacement() {
    use std::os::unix::fs::PermissionsExt;
    let root = ScratchDir::new("held-directory");
    std::fs::create_dir(root.path()).unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    let path = root.path().join("store");
    let moved = root.path().join("moved");
    let mut ks = Keystore::create(&path, &keystore_harness::init()).unwrap();
    ks.add(imported_account()).unwrap();
    std::fs::rename(&path, &moved).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(matches!(Keystore::open(&moved, &keystore_harness::unlock()), Err(Error::Locked)));
    let receipt = ks.persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES).unwrap();
    let signed = ks.sign_spend(&DIGEST, receipt, KeyAccess::StoredRoot).unwrap();
    assert_eq!(signed.spent_index, WotsIndex::ZERO);
    assert_eq!(std::fs::read_dir(&path).unwrap().count(), 0, "replacement directory received store data");
    drop(ks);
    let mut reopened = Keystore::open(&moved, &keystore_harness::unlock()).unwrap();
    let view = reopened.view(&IMPORTED_TAG).unwrap().unwrap();
    assert_eq!(view.wots_index, pos(1));
    assert_eq!(view.pending.unwrap().digest, DIGEST);
    assert!(reopened.persist_advance(&IMPORTED_TAG, &[0x99; 32], FIGURES).is_err());
}

/// Store entry opens must not follow links outside the verified directory.
#[cfg(unix)]
#[test]
fn unix_store_lock_and_snapshot_symbolic_links_are_refused() {
    use std::os::unix::fs::symlink;
    let root = ScratchDir::new("store-links");
    std::fs::create_dir(root.path()).unwrap();
    let path = root.path().join("store");
    drop(Keystore::create(&path, &keystore_harness::init()).unwrap());
    let alias = root.path().join("alias");
    symlink(&path, &alias).unwrap();
    for spelling in [alias.clone(), alias.join("."), alias.join("")] {
        assert_eq!(Keystore::open(&spelling, &keystore_harness::unlock()).err(), Some(Error::StoreDirectoryIsLink));
        assert_eq!(Keystore::create(&spelling, &keystore_harness::init()).err(), Some(Error::StoreDirectoryIsLink));
    }
    // Links to an empty directory and to nothing are refused the same way.
    let empty = root.path().join("empty");
    std::fs::create_dir(&empty).unwrap();
    for (name, target) in [("to-empty", empty.clone()), ("dangling", root.path().join("absent"))] {
        let link = root.path().join(name);
        symlink(&target, &link).unwrap();
        assert_eq!(Keystore::create(&link, &keystore_harness::init()).err(), Some(Error::StoreDirectoryIsLink));
    }
    assert_eq!(std::fs::read_dir(&empty).unwrap().count(), 0, "a store was created through a link");
    assert!(Error::StoreDirectoryIsLink.to_string().contains("Pass the directory the link points to"));
    for name in ["keystore.lock", "accounts.mks"] {
        let entry = path.join(name);
        let outside = root.path().join(name);
        std::fs::rename(&entry, &outside).unwrap();
        let before = std::fs::read(&outside).unwrap();
        symlink(&outside, &entry).unwrap();
        assert!(Keystore::open(&path, &keystore_harness::unlock()).is_err());
        assert_eq!(std::fs::read(&outside).unwrap(), before);
        std::fs::remove_file(&entry).unwrap();
        std::fs::rename(&outside, &entry).unwrap();
    }
    drop(Keystore::open(&path, &keystore_harness::unlock()).unwrap());
}

#[cfg(unix)]
#[test]
fn unix_directory_handles_preserve_dot_and_parent_path_meaning() {
    let root = ScratchDir::new("store-path-components");
    std::fs::create_dir(root.path()).unwrap();
    let path = root.path().join("store");
    drop(Keystore::create(&path, &keystore_harness::init()).unwrap());
    std::fs::create_dir(path.join("child")).unwrap();
    for alias in [path.join("."), path.join("child/.."), path.join("")] {
        drop(Keystore::open(&alias, &keystore_harness::unlock()).unwrap());
    }
}

/// Opening an existing store needs traversal, not a listing of its parent.
#[cfg(unix)]
#[test]
fn unix_existing_store_opens_under_an_execute_only_parent() {
    use std::os::unix::fs::PermissionsExt;
    let root = ScratchDir::new("execute-only-parent");
    std::fs::create_dir(root.path()).unwrap();
    let path = root.path().join("store");
    drop(Keystore::create(&path, &keystore_harness::init()).unwrap());
    let original = std::fs::metadata(root.path()).unwrap().permissions();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o111)).unwrap();
    let opened = Keystore::open(&path, &keystore_harness::unlock());
    // Restore access before checking the result so cleanup also works on failure.
    std::fs::set_permissions(root.path(), original).unwrap();
    assert_eq!(opened.unwrap().generation().unwrap(), 0);
}
