// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! Shared helpers for the keystore tests: a self-cleaning scratch directory,
//! the fixture accounts the tests are seeded with, and a reopen helper that
//! retries a transient lock conflict.
//!
//! Scratch directories live under `CARGO_TARGET_TMPDIR`, named by test, pid,
//! a process-wide counter and a nanosecond timestamp. The guard removes the
//! directory on `Drop` unless the thread is panicking, so a failing test
//! leaves its files for inspection.

#![allow(dead_code)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use mochimo_crypto::account::Account;
use mochimo_crypto::consts::{PK_LEN, SEED_LEN, WOTS_ADDR_LEN};
use mochimo_crypto::keystore::{Disk, Figures, Keystore, Medium};
use mochimo_crypto::{Error, Result, Secret};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

pub struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    pub fn new(test: &str) -> ScratchDir {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let root = Path::new(env!("CARGO_TARGET_TMPDIR"));
        let path = root.join(format!("{test}-{}-{n}-{nanos}", std::process::id()));
        std::fs::create_dir_all(root).unwrap_or_else(|e| panic!("cannot create {}: {e}", root.display()));
        // The keystore creates the leaf itself, mode 0700; the parent exists.
        ScratchDir { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The file names in the directory, sorted.
    pub fn listing(&self) -> Vec<String> {
        let mut out: Vec<String> = std::fs::read_dir(&self.path)
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        out.sort();
        out
    }

    pub fn snapshot_bytes(&self) -> Vec<u8> {
        std::fs::read(self.path.join("accounts.mks"))
            .unwrap_or_else(|e| panic!("read snapshot in {}: {e}", self.path.display()))
    }

    /// Overwrites the snapshot, for tests that damage the file on purpose.
    ///
    /// Writes directly rather than through `Medium`, so it can produce a file
    /// the keystore never would.
    pub fn write_snapshot(&self, bytes: &[u8]) {
        std::fs::write(self.path.join("accounts.mks"), bytes)
            .unwrap_or_else(|e| panic!("write snapshot in {}: {e}", self.path.display()));
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

// ---------------------------------------------------------------------------
// Store encryption under fixed entropy
// ---------------------------------------------------------------------------
//
// `mochimo-crypto` has no RNG: the caller supplies the salt and nonce seed.
// Fixed values here give a deterministic store image, so byte-level tests
// remain possible. Production supplies OS randomness.

/// The password every harness-built store is created and opened under.
///
/// Long enough to pass `create::MIN_PASSWORD_LEN`, and deliberately not a
/// realistic password.
pub const TEST_PASSWORD_STR: &str = "harness-password-not-for-real-use";
/// [`TEST_PASSWORD_STR`] as bytes, for `Init`/`Unlock`.
pub const TEST_PASSWORD: &[u8] = TEST_PASSWORD_STR.as_bytes();

/// A second password, for tests that a store is refused under another
/// password.
pub const OTHER_PASSWORD: &[u8] = b"a-different-harness-password";

pub const TEST_SALT: [u8; mochimo_crypto::keystore::SALT_LEN] = [0x5A; mochimo_crypto::keystore::SALT_LEN];
pub const TEST_NONCE_SEED: [u8; mochimo_crypto::keystore::NONCE_SEED_LEN] =
    [0x4E; mochimo_crypto::keystore::NONCE_SEED_LEN];

/// Store creation parameters using the cheap test KDF.
///
/// `Kdf::RECOMMENDED` costs about 70 ms per create or open, which makes the
/// suite slow and widens lock windows between processes. The KDF parameters
/// are stored in each file's header, so the format code path is the same.
pub fn init() -> mochimo_crypto::keystore::Init<'static> {
    mochimo_crypto::keystore::Init {
        password: TEST_PASSWORD,
        salt: TEST_SALT,
        nonce_seed: TEST_NONCE_SEED,
        kdf: mochimo_crypto::keystore::Kdf::CHEAP_FOR_TESTS,
    }
}

pub fn unlock() -> mochimo_crypto::keystore::Unlock<'static> {
    mochimo_crypto::keystore::Unlock {
        password: TEST_PASSWORD,
        nonce_seed: TEST_NONCE_SEED,
    }
}

pub fn unlock_with(password: &[u8]) -> mochimo_crypto::keystore::Unlock<'_> {
    mochimo_crypto::keystore::Unlock {
        password,
        nonce_seed: TEST_NONCE_SEED,
    }
}

/// `Keystore::create` under the harness's fixed entropy.
pub fn create(dir: &Path) -> mochimo_crypto::Result<Keystore<Disk>> {
    Keystore::create(dir, &init())
}

/// `Keystore::open` under the harness's fixed entropy.
pub fn open(dir: &Path) -> mochimo_crypto::Result<Keystore<Disk>> {
    Keystore::open(dir, &unlock())
}

/// How many times [`reopen_with`] retries `Error::Locked` before returning
/// it.
pub const REOPEN_TRIES: usize = 50;
/// The wait between [`reopen_with`] retries (5 ms in total).
pub const REOPEN_WAIT: Duration = Duration::from_micros(100);

/// The result of [`reopen_with`] and how many `Error::Locked` results it
/// retried.
pub struct Reopen<M: Medium> {
    pub result: Result<Keystore<M>>,
    pub retries: usize,
}

/// Reopens a keystore a test has just dropped, retrying only
/// `Error::Locked`, at most [`REOPEN_TRIES`] times.
///
/// `flock` belongs to the open file description, and a child process
/// spawned by another test holds a copy of the parent's descriptors until it
/// calls `exec`. A reopen during that window briefly sees a real second
/// holder.
///
/// * This is test-only: `Keystore::open` never retries, because `Locked`
///   must mean a genuine second holder.
/// * Every other error returns immediately with `retries == 0`.
/// * A genuine second holder is still refused after [`REOPEN_TRIES`].
/// * When any retry happened, one line is written directly to stderr
///   (bypassing libtest's output capture) so frequent retries stay visible.
pub fn reopen_with<M: Medium>(label: &str, dir: &Path, mut medium: impl FnMut() -> M) -> Reopen<M> {
    let mut retries = 0usize;
    loop {
        match Keystore::open_with(dir, medium(), &unlock()) {
            Err(Error::Locked) if retries < REOPEN_TRIES => {
                retries += 1;
                std::thread::sleep(REOPEN_WAIT);
            }
            result => {
                if retries > 0 {
                    let verdict = if result.is_ok() { "opened" } else { "still refused at the bound" };
                    // Leading newline: this write bypasses libtest's capture and
                    // could otherwise land mid-line beside another test's output.
                    let line = format!(
                        "\n  keystore reopen [{label}]: {retries} retry(ies) on Error::Locked, then {verdict} \
                         (written outside the censused block on purpose)\n"
                    );
                    // Not `eprintln!`, which libtest captures per test.
                    let _ = std::io::stderr().write_all(line.as_bytes());
                }
                return Reopen { result, retries };
            }
        }
    }
}

/// [`reopen_with`] over the real filesystem.
pub fn reopen(label: &str, dir: &Path) -> Reopen<Disk> {
    reopen_with(label, dir, || Disk)
}

/// The root of the imported test account, from the group F fixtures
/// (`fixtures/group_f_derivation.json`).
///
/// * The imported account is `F-address-widths`: its `account_seed` as the
///   root, its embedded 2208-byte first address, and its recorded
///   `account_tag`.
/// * The derived account is `F-derive-account-1`, whose tag is
///   `DERIVED_TAG`.
///
/// The two accounts come from different master seeds, so they share no key
/// stream. `IMPORTED_TAG` sorts before `DERIVED_TAG`, which the ordering
/// assertions rely on.
pub const ROOT: [u8; SEED_LEN] = [
    0x66, 0x4e, 0xdd, 0x3d, 0x3b, 0xf1, 0xa0, 0xe2, 0x9c, 0x93, 0x98, 0xdd, 0xc1, 0x61, 0x14,
    0xab, 0xc6, 0xd6, 0xb4, 0x32, 0xb1, 0xe5, 0xe4, 0xde, 0x26, 0x7c, 0x7e, 0x2a, 0xe5, 0x3f,
    0x58, 0x0b,
];
pub const IMPORTED_FIRST_ADDRESS: &[u8; WOTS_ADDR_LEN] =
    include_bytes!("../../../../fixtures/F-widths_account_address.bin");
pub const IMPORTED_TAG: [u8; 20] = [
    0x05, 0xff, 0x0f, 0x69, 0xd4, 0xc1, 0xcd, 0x68, 0x2e, 0xd3, 0x34, 0x1c, 0x0b, 0x77, 0x73,
    0x05, 0x4b, 0x58, 0x80, 0x0f,
];
/// The key stream `ROOT` defines: `F-address-widths.wots_address[20..40]`,
/// the recorded rotation-0 address hash.
pub const IMPORTED_STREAM: [u8; 20] = [
    0x25, 0x87, 0x87, 0x8a, 0xd3, 0x4d, 0x29, 0xcf, 0x2e, 0x4b, 0xe4, 0x83, 0x86, 0xae, 0xc3,
    0xa0, 0xc2, 0xa7, 0xea, 0x8c,
];
/// The master seed `F-address-widths` derives `ROOT` from at index 0, for
/// the cross-kind key-stream tests.
pub const IMPORTED_MASTER: [u8; SEED_LEN] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
    0x1e, 0x1f,
];
pub const DERIVED_MASTER: [u8; SEED_LEN] = [
    0x40, 0x8b, 0x28, 0x5c, 0x12, 0x38, 0x36, 0x00, 0x4f, 0x4b, 0x88, 0x42, 0xc8, 0x93, 0x24,
    0xc1, 0xf0, 0x13, 0x82, 0x45, 0x0c, 0x0d, 0x43, 0x9a, 0xf3, 0x45, 0xba, 0x7f, 0xc4, 0x9a,
    0xcf, 0x70,
];
pub const DERIVED_TAG: [u8; 20] = [
    0x4d, 0x9b, 0x31, 0xe4, 0x78, 0x74, 0x66, 0x8e, 0x45, 0x89, 0x5a, 0x1b, 0x93, 0x38, 0x8e,
    0x5a, 0xa9, 0xb6, 0xfb, 0xe9,
];
pub const DERIVED_POSITION: u32 = 1;
pub const DIGEST: [u8; 32] = [0xD1; 32];
/// The figures recorded by hand-built reservations in tests that do not
/// consult a chain. Tests that script a chain choose figures matching it.
pub const FIGURES: Figures = Figures {
    reserved_balance: 5_000_000,
    blk_to_live: 0,
};

/// Account 0 of `IMPORTED_MASTER`, derived: the same account
/// `imported_account()` holds by its root. Asserted to sit under
/// `IMPORTED_TAG`, because the captured version-3 reservation
/// (`testdata/keystore_v3_reserved_snapshot.bin`) was written for it.
pub fn derived_account_0_of_the_imported_master() -> Account {
    let acct = Account::derive(&Secret::new(IMPORTED_MASTER), 0);
    assert_eq!(
        acct.tag(),
        IMPORTED_TAG,
        "Account::derive(IMPORTED_MASTER, 0) is no longer F-address-widths' tag; the version-3 \
         reservation capture describes an account this harness no longer derives"
    );
    acct
}

pub fn imported_account() -> Account {
    let acct = Account::import(Secret::new(ROOT), IMPORTED_FIRST_ADDRESS)
        .unwrap_or_else(|e| panic!("F-address-widths' root and first address are a pair: {e}"));
    assert_eq!(
        acct.tag(),
        IMPORTED_TAG,
        "Account::import no longer computes F-address-widths' recorded account tag; every \
         keystore proof seeded from this harness would otherwise run on an account the \
         fixture does not describe"
    );
    acct
}

/// A 2208-byte first address for `root` built from chosen public components.
///
/// The pair is valid (`Account::import` verifies that the root reproduces
/// the public key), so tests can build an imported account for any root.
/// Any `(pub_seed, adrs)` gives another valid pair, and so another tag, over
/// the same rotation keys; import verification alone does not prevent
/// key-stream aliasing.
pub fn synthetic_first_address(root: &Secret<SEED_LEN>, salt: u8) -> Box<[u8; WOTS_ADDR_LEN]> {
    let pub_seed = [salt; SEED_LEN];
    let image = [salt ^ 0xFF; 32];
    let key = mochimo_crypto::derive::first_key_from_components(
        root.duplicate(),
        &pub_seed,
        mochimo_crypto::wots::Adrs::from_le_image(&image),
    );
    let mut out = Box::new([0u8; WOTS_ADDR_LEN]);
    out[..PK_LEN].copy_from_slice(&key.public_key()[..]);
    out[PK_LEN..PK_LEN + SEED_LEN].copy_from_slice(&pub_seed);
    out[PK_LEN + SEED_LEN..].copy_from_slice(&image);
    out
}

/// An imported account over `root`, through [`synthetic_first_address`].
/// The fixture-recorded one is [`imported_account`].
pub fn synthetic_imported_account(root: Secret<SEED_LEN>, salt: u8) -> Account {
    let address = synthetic_first_address(&root, salt);
    Account::import(root, &address).unwrap_or_else(|e| panic!("a computed pair must verify: {e}"))
}

/// An imported account over the same key stream as [`imported_account`]
/// under a different tag (key-stream aliasing). The keystore refuses it by
/// stream identity, not by tag.
pub fn aliased_imported_account() -> Account {
    let acct = synthetic_imported_account(Secret::new(ROOT), 0x5E);
    assert_ne!(acct.tag(), IMPORTED_TAG, "the alias must carry another tag");
    acct
}

pub fn derived_account() -> Account {
    let acct = Account::derive(&Secret::new(DERIVED_MASTER), DERIVED_POSITION);
    assert_eq!(
        acct.tag(),
        DERIVED_TAG,
        "Account::derive no longer reproduces F-derive-account-1's tag; every \
         keystore proof seeded from this harness would otherwise run on an \
         account the fixture does not describe"
    );
    acct
}
