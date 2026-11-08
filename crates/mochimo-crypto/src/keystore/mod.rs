// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! The keystore: durable, encrypted storage for account records, and the only
//! minter of [`AdvanceReceipt`].
//!
//! # Layout
//!
//! One directory holds one snapshot file with every account. Each commit
//! rewrites it atomically in four steps: write a temp file, fsync it, rename it
//! over the target, fsync the directory. A receipt is minted only after the
//! fourth. On Windows the snapshot is instead two slot files written in place;
//! `slots` defines their frame and the rule by which `open` takes the newer
//! image. The format is in `format` and the steps in `medium`. A single
//! snapshot puts every member of a commit in one write (I3), at a cost of
//! O(n) bytes per spend, dominated at wallet scale by the fsyncs.
//!
//! # Invariants
//!
//! **Monotonic per tag.** No public API moves an index except forward:
//! [`Keystore::persist_advance`] computes stored + 1, and
//! [`Keystore::persist_advance_to`] refuses any target not strictly ahead
//! (`Error::Range`). After any commit error, memory and disk are unknown
//! relative to each other (the rename may have succeeded and the directory
//! fsync failed), so the handle is poisoned: every later call returns
//! [`Error::Poisoned`], and the remedy is to drop and reopen, never to retry.
//! Memory is never changed before a commit returns `Ok`.
//!
//! **One key stream, one account.** Every record carries its stream's public
//! identity (the rotation-0 public key's hash), and [`Keystore::add`] refuses
//! a duplicate across kinds. The identity of an account being added is
//! recomputed from its key material, never read from the record.
//!
//! **Keyed by tag, never by position.** A `BTreeMap<Tag, _>` in memory,
//! records sorted by tag on disk with a strict order check on load, and every
//! API takes `&Tag`.
//!
//! **Durability (I2).** The four steps return typestate tokens, so reordering
//! them is a type error. [`Durable`], the witness `AdvanceReceipt::attesting`
//! requires, is constructed at exactly one expression: the `Ok` arm after
//! `fsync_dir` in [`Keystore::commit`]
//! (`tests/invariants.rs::durable_witness_has_one_construction_site`).
//!
//! **The store directory's own entry.** It lives in the parent directory,
//! which the four steps do not touch, so [`Keystore::create`] flushes the
//! parent through [`Medium::fsync_parent`] before its first commit and refuses
//! if the flush fails. Otherwise a power loss could lose the whole store after
//! a key had signed. Directories above the parent are the operator's
//! responsibility, and whether a returned flush is durable is up to the
//! filesystem, as with every `fsync` here.
//!
//! On Windows, [`Medium::fsync_parent`] flushes nothing: Win32 documents no
//! flush an unprivileged process can make that commits a directory's entry in
//! its parent (`medium` cites the pages). A power cut before the file system
//! commits the store directory's creation can therefore still lose the whole
//! store. The call stays in `create` on both platforms so the order is the
//! same (checked by
//! `tests/keystore.rs::medium_sequence_is_exactly_the_slot_steps_with_their_arguments`).
//!
//! # The lock
//!
//! `keystore.lock` is created once, never unlinked, and held with
//! `File::try_lock` (`flock(2)`; `LockFileEx` on Windows) for the handle's
//! life. The kernel releases it on process death, including `SIGKILL`, so a
//! held lock always means a live holder and there is no stale-lock state.
//! Unlinking it would allow two holders on different inodes. Two opens in one
//! process also conflict (`flock` is per open file description). Local
//! filesystems only: NFS lock emulation may not honour it.
//!
//! On Windows the lock is `LockFileEx`, exclusive and failing immediately,
//! over the whole file. Windows enforces it against other handles: while the
//! store is open, another handle's read of `keystore.lock` fails with
//! `ERROR_LOCK_VIOLATION` (33); nothing in the library reads the file's
//! contents. The system releases a terminated process's locks after a time
//! that "depends upon available system resources" (Microsoft's
//! documentation), so `Locked` can briefly be reported for a process that has
//! already exited; a retry succeeds. Whether an SMB share honours the lock
//! between machines is not established.
//!
//! The lock file's existence means nothing. A refused `open` past the
//! `Missing` check leaves the file behind, because the read must happen under
//! the lock; [`occupied`] reports only the snapshot (on Windows, also slot 1),
//! and a live holder is refused with [`Error::Locked`]. A `create` killed
//! between writing the temp file and the rename leaves `accounts.mks.tmp`,
//! which the next commit replaces rather than adopts.
//!
//! # What `open` refuses
//!
//! - A directory owned by another user or writable by group or others (see
//!   `perms`). On Unix the check is made on the opened directory, which is
//!   kept for every later operation.
//! - A lock or snapshot file owned by another user or readable or writable
//!   by group or others (on Unix `Error::UnsafeFileMode`; on Windows the
//!   file's own access list is checked instead).
//! - A store directory that is a symbolic link or, on Windows, a junction
//!   ([`Error::StoreDirectoryIsLink`]). The lock and snapshot are opened
//!   without following links and must be regular files.
//! - A missing snapshot ([`Error::Missing`]): an absent file is not an empty
//!   store (I5). New stores go through [`Keystore::create`].
//!
//! A stale temp file is unlinked after the lock is taken and never adopted,
//! so only one file is ever authoritative. Before returning a handle, `open`
//! flushes what it read to the device: on Unix the snapshot and the store
//! directory, on Windows the newest slot. A store that cannot be flushed is
//! refused, because `resign` signs from what `open` read. On Windows `open`
//! reads both slot files and takes one by `slots`' rule: the older slot is
//! the state before the newer, never a second history, and is never taken
//! while the newer one reads. A stale temp on Windows was left by a build
//! using the rename layout and is unlinked the same way.
//!
//! # Signing
//!
//! [`Keystore::sign_spend`] (in `sign`) is the public route to a fresh WOTS+
//! signature, and `resign_reserved` reproduces one a reservation already
//! released. It consumes the [`AdvanceReceipt`], re-checks the store's live
//! state, derives the key at the reserved position from the master seed or the
//! stored root, and signs. It persists nothing.
//!
//! # Encryption at rest
//!
//! The record body, which holds imported roots and the master seed, is sealed
//! with ChaCha20-Poly1305 under an Argon2id key derived from the password. A
//! stolen `accounts.mks` alone yields nothing.
//!
//! Every rewrite copies the store into a new inode, and old inodes, journals
//! and filesystem snapshots may keep superseded copies. Those are ciphertext
//! under the same key (the salt does not change across rewrites; only the
//! nonce does), so they are readable by whoever has the password.
//!
//! # Limits of the crash tests
//!
//! The crash tests kill at syscall boundaries through
//! [`medium::Instrumented`]. They cannot simulate power loss, an fsync that
//! lies, or dirty pages lost after `EIO` (hence poisoning, never retry).
//! Rename atomicity is relied on for ext4, APFS, XFS and btrfs, and cannot be
//! detected from `std` on FAT, exFAT or FUSE.
//!
//! On Windows there is no rename, because Win32 documents no call that
//! commits the directory entry a rename writes. A commit writes the slot file
//! not holding the newest image, in place, and flushes it with
//! `FlushFileBuffers` before [`Durable`] is minted; `open` takes the newer of
//! the two intact images. A power cut can undo only a write not yet flushed,
//! which no receipt attests, and cannot bring back a state older than one a
//! receipt attested. That a returned flush is on the device rests on
//! Microsoft's documentation and the device, as `fsync` does on Unix
//! (`medium` cites the pages). On a Windows runner the same instrument drives
//! kills at syscall boundaries and writes torn in any mix of sectors, in tests
//! with the same names as the Unix ones. The store directory's own entry in
//! its parent is not flushed on Windows (see above).

// The keystore's storage guarantees rest on Unix's rename(2), directory fsync
// and flock(2), and on Windows' two slot files flushed in place with
// FlushFileBuffers and LockFileEx. Any other target is refused at compile
// time.
#[cfg(not(any(unix, windows)))]
compile_error!(
    "the keystore's storage guarantees are stated for Unix (rename atomicity, \
     directory fsync, flock) and for Windows (two slot files flushed in place, \
     LockFileEx); this target is neither"
);

pub(crate) mod crypt;
#[cfg(unix)]
mod directory;
#[cfg(unix)]
pub use directory::Directory;
pub mod format;
pub mod medium;
pub(crate) mod perms;
pub mod sign;
#[cfg(any(windows, test))]
mod slots;
pub mod spend;

use std::collections::BTreeMap;
use std::fs::{File, TryLockError};
#[cfg(windows)]
use std::fs;
use std::io::Read;
#[cfg(windows)]
use std::io::{Seek, SeekFrom};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::account::{Account, AccountKind, AccountRecord, AdvanceReceipt, WotsIndex};
use crate::addr::Tag;
use crate::consts::SEED_LEN;
use crate::error::{Error, Result};
use crate::secret::Secret;

pub use crypt::{Kdf, KEY_LEN, NONCE_SEED_LEN, SALT_LEN};
pub use format::{Figures, Pending};
pub use medium::{Call, Disk, Instrumented, Medium};
pub use sign::{KeyAccess, SpendSignature};
pub use spend::SpendAddresses;

use format::{RecordRef, Slot};
#[cfg(windows)]
use medium::SLOT1_NAME;
use medium::{SNAPSHOT_NAME, TEMP_NAME};

pub(crate) const LOCK_NAME: &str = "keystore.lock";

/// Evidence that the commit's durable steps completed: on Unix all four,
/// ending with the directory fsync; on Windows the slot writes, ending with
/// the flush of the slot just written. Constructed only in the `Ok` arm of
/// [`Keystore::commit`] (checked by
/// `durable_witness_has_one_construction_site`). The private field keeps code
/// outside the crate from forging one (`ui/fail/durable_is_not_constructible.rs`).
#[must_use]
pub struct Durable(());

impl Durable {
    /// Test-only witness for unit tests of the receipt. The one-site check
    /// skips `cfg(test)` items.
    #[cfg(test)]
    pub(crate) fn for_test() -> Durable {
        Durable(())
    }
}

/// A non-secret view of one account for callers that must not hold the
/// account itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountView {
    pub tag: Tag,
    pub kind: AccountKind,
    pub wots_index: WotsIndex,
    /// The open reservation, if one is open.
    pub pending: Option<Pending>,
    /// The last settled reservation, kept until the index moves: replaced by
    /// the next `persist_advance`, cleared by `persist_advance_to`. Never
    /// `Some` together with `pending`, because `format::encode` refuses that
    /// pair.
    pub settled: Option<Pending>,
}

enum State {
    Live {
        generation: u64,
        slots: BTreeMap<Tag, Slot>,
    },
    Poisoned(Error),
}

/// The keystore handle. Exclusive writer: by the lock across processes and by
/// `&mut self` within one. No `Clone` (two handles would be two writers), no
/// `Default`, no `PartialEq`.
#[must_use]
pub struct Keystore<M: Medium = Disk> {
    dir: PathBuf,
    #[cfg(unix)]
    directory: Directory,
    _lock: File,
    medium: M,
    state: State,
    /// The master seed the store holds, if any. Held for the handle's life,
    /// which is one command, and zeroized on drop.
    master: Option<Secret<SEED_LEN>>,
    /// The store key and its derivation inputs. Derived once at open, because
    /// Argon2id costs about seventy milliseconds per derivation.
    crypto: StoreCrypto,
    /// The format version the snapshot had when this handle opened it
    /// (`format::VERSION` for a store this handle created), and the version
    /// on disk now. Every commit seals `format::VERSION`, so the two differ
    /// once this handle has rewritten an older store; `open` never writes.
    /// See [`Keystore::upgraded_from`].
    opened_version: u16,
    on_disk_version: u16,
    /// On Windows, the two slot files and what this handle knows of them.
    #[cfg(windows)]
    slots: Slots,
}

/// On Windows, the slot files a handle holds, and what it knows of them.
#[cfg(windows)]
struct Slots {
    /// Slot 0 and slot 1, held for the handle's life and shared for reading
    /// alone (`perms::open_slot`); `None` for a slot file not there yet.
    held: [Option<File>; 2],
    /// The slot holding the newest image, which no commit writes, and which
    /// is on the device: `open` flushes it before the handle exists, and a
    /// commit flushes what it writes before that becomes the newest. `None`
    /// only inside `create`, before its commit.
    newest: Option<usize>,
    /// Whether slot 0 has yet to become a frame: it holds a store in the
    /// rename layout, or nothing yet. Until it is one, a build that reads
    /// only that layout would read it as the snapshot.
    vacate: bool,
}

#[cfg(windows)]
impl Slots {
    /// Nothing held and nothing to protect: `create`'s state before its
    /// commit, which creates both files.
    fn fresh() -> Slots {
        Slots {
            held: [None, None],
            newest: None,
            vacate: true,
        }
    }
}

/// What a handle needs to read and write its own store. No `Debug` or
/// `Clone`, because it holds a key.
struct StoreCrypto {
    key: Zeroizing<[u8; crypt::KEY_LEN]>,
    kdf: crypt::Kdf,
    salt: [u8; crypt::SALT_LEN],
    /// Per-open entropy the per-commit nonce is derived from (see
    /// `crypt::nonce_for`).
    nonce_seed: [u8; crypt::NONCE_SEED_LEN],
}

/// What a caller supplies to open an existing store.
///
/// `nonce_seed` is entropy supplied by the caller because this crate has no
/// RNG dependency. The binary reads `/dev/urandom`; tests pass a constant to
/// get deterministic images.
pub struct Unlock<'a> {
    pub password: &'a [u8],
    pub nonce_seed: [u8; crypt::NONCE_SEED_LEN],
}

/// What a caller supplies to create a store. The salt makes two stores under
/// one password different files.
pub struct Init<'a> {
    pub password: &'a [u8],
    pub salt: [u8; crypt::SALT_LEN],
    pub nonce_seed: [u8; crypt::NONCE_SEED_LEN],
    /// The KDF cost this store is created with, recorded in its header. The
    /// binary passes `Kdf::RECOMMENDED` (64 MiB, about seventy milliseconds);
    /// tests pass a cheap setting so suites that create many stores stay
    /// fast.
    pub kdf: crypt::Kdf,
}

fn io(op: &'static str) -> impl Fn(std::io::Error) -> Error {
    move |e| Error::Io { op, kind: e.kind() }
}

#[cfg(unix)]
fn take_lock(dir: &Directory) -> Result<File> {
    let file = dir.open_lock(LOCK_NAME).map_err(io("open lock"))?;
    // Anyone who can open the lock file can hold it, so its mode is checked
    // before it is locked, as its access list is on Windows.
    perms::refuse_unsafe_file(&file, LOCK_NAME)?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(Error::Locked),
        Err(TryLockError::Error(e)) => Err(Error::Io {
            op: "flock",
            kind: e.kind(),
        }),
    }
}

#[cfg(windows)]
fn take_lock(dir: &Path) -> Result<File> {
    let file = perms::open_private_lock(&dir.join(LOCK_NAME)).map_err(io("open lock"))?;
    // Anyone who can open the lock file can hold it, so on Windows its own
    // access list is checked before it is locked (see `perms`), as its mode
    // is on Unix.
    #[cfg(windows)]
    perms::refuse_unsafe_file(&file, LOCK_NAME)?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(Error::Locked),
        Err(TryLockError::Error(e)) => Err(Error::Io {
            op: "flock",
            kind: e.kind(),
        }),
    }
}

/// What [`Keystore::create`] would refuse `dir` for, checked early.
///
/// Returns `Some("snapshot")` when a snapshot is present, the same `Exists`
/// refusal `create` makes. `cli::create` asks this before prompting, so a
/// mistyped `--dir` is refused before a password is chosen or a phrase shown.
/// The check inside `create`, made under the lock, is authoritative; this
/// probe covers only file existence.
///
/// A lock file without a snapshot is not reported, because it says nothing
/// about a holder. A live holder is refused with `Locked` when the lock is
/// taken.
///
/// On Windows slot 1 is checked too. `create` writes it before
/// `accounts.mks`, so slot 1 without the snapshot is what an interrupted
/// `create` leaves, or the last copy of a store whose snapshot was deleted by
/// hand; it is refused rather than overwritten.
pub fn occupied(dir: &Path) -> Option<&'static str> {
    if dir.join(SNAPSHOT_NAME).exists() {
        return Some("snapshot");
    }
    #[cfg(windows)]
    if dir.join(SLOT1_NAME).exists() {
        return Some("snapshot");
    }
    None
}

/// Every byte of a slot file, read through the handle held for it. A file
/// longer than any frame this build writes is refused, without allocating for
/// it, with the same image-length `Range` error the Unix arm gives an
/// over-long snapshot.
#[cfg(windows)]
fn read_slot(file: &mut File) -> Result<Zeroizing<Vec<u8>>> {
    let len = file.metadata().map_err(io("stat slot"))?.len();
    let over = || Error::Range {
        what: "keystore image length",
        min: format::MIN_IMAGE_LEN as u64,
        max: format::MAX_IMAGE_LEN as u64,
        got: len,
    };
    let len = usize::try_from(len)
        .ok()
        .filter(|&len| len <= slots::MAX_FRAME_LEN)
        .ok_or_else(over)?;
    let mut bytes: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; len]);
    file.seek(SeekFrom::Start(0)).map_err(io("read slot"))?;
    file.read_exact(&mut bytes).map_err(io("read slot"))?;
    Ok(bytes)
}

/// The image `open` would take from `dir`, read without the lock and without
/// holding the slots. Tests compare a Windows store by it, as they compare a
/// Unix store by its snapshot's bytes; the wallet does not call it.
///
/// Windows only. Public because the integration tests are a separate crate,
/// as with `medium::Instrumented`. It takes the password because ordering the
/// two slots needs the key: the generation is inside the ciphertext.
#[cfg(windows)]
pub fn newest_image(dir: &Path, password: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let read = |name: &str| -> Result<Option<Zeroizing<Vec<u8>>>> {
        match fs::read(dir.join(name)) {
            Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io("read slot")(e)),
        }
    };
    let slot0 = slots::sort(read(SNAPSHOT_NAME)?)?;
    let slot1 = slots::sort(read(SLOT1_NAME)?)?;
    let newest = if slots::take(&slot0, &slot1, password)?.newest == 0 {
        slot0
    } else {
        slot1
    };
    match newest {
        slots::Content::Image(image) | slots::Content::Other(image) => Ok(image),
        _ => Err(Error::Corrupt {
            what: "neither slot holds an intact image",
            offset: 0,
        }),
    }
}

#[cfg(unix)]
fn occupied_at(dir: &Directory) -> Result<Option<&'static str>> {
    Ok(dir.exists(SNAPSHOT_NAME).map_err(io("stat snapshot"))?.then_some("snapshot"))
}

#[cfg(windows)]
fn occupied_at(dir: &Path) -> Result<Option<&'static str>> { Ok(occupied(dir)) }

impl Keystore<Disk> {
    /// Create a new keystore in `dir` (created `0700` if absent).
    ///
    /// Refuses a directory that already holds a snapshot and a live holder of
    /// its lock (`Locked`); an unheld lock file is ignored. Flushes `dir`'s
    /// parent before the first commit so `dir`'s own entry is durable. On
    /// Windows there is no documented parent flush, and that call does
    /// nothing.
    pub fn create(dir: &Path, init: &Init<'_>) -> Result<Self> {
        Self::create_with(dir, Disk, init)
    }

    /// Open an existing keystore. Refuses an unsafe directory, a held lock, and
    /// a missing snapshot.
    pub fn open(dir: &Path, unlock: &Unlock<'_>) -> Result<Self> {
        Self::open_with(dir, Disk, unlock)
    }
}

impl<M: Medium> Keystore<M> {
    /// [`Keystore::create`] over an explicit medium (tests inject
    /// [`Instrumented`]).
    pub fn create_with(dir: &Path, medium: M, init: &Init<'_>) -> Result<Self> {
        #[cfg(unix)]
        let directory = Directory::open(dir, true)?;
        #[cfg(unix)]
        let store_dir = &directory;
        #[cfg(windows)]
        let store_dir = {
            // Asked without following a link, so a link to nothing is
            // refused below rather than created through.
            let absent = matches!(fs::symlink_metadata(dir), Err(e) if e.kind() == std::io::ErrorKind::NotFound);
            if absent {
                perms::create_private_dir(dir).map_err(io("create directory"))?;
            }
            perms::refuse_unsafe_dir(dir)?;
            dir
        };
        if let Some(what) = occupied_at(store_dir)? {
            return Err(Error::Exists { what });
        }
        let lock = take_lock(store_dir)?;
        // Checked again under the lock: a second `create` could pass the
        // check above while a first holds the lock with its snapshot not yet
        // renamed in, then take the lock and seal an empty store over it.
        if let Some(what) = occupied_at(store_dir)? {
            return Err(Error::Exists { what });
        }
        // Derive the key before the first write, so a store that exists has a
        // derivable key.
        let kdf = init.kdf.checked()?;
        let key = crypt::derive_key(init.password, &init.salt, kdf)?;
        let mut ks = Keystore {
            dir: dir.to_path_buf(),
            #[cfg(unix)]
            directory,
            _lock: lock,
            medium,
            state: State::Live {
                generation: 0,
                slots: BTreeMap::new(),
            },
            master: None,
            crypto: StoreCrypto {
                key,
                kdf,
                salt: init.salt,
                nonce_seed: init.nonce_seed,
            },
            opened_version: format::VERSION,
            on_disk_version: format::VERSION,
            #[cfg(windows)]
            slots: Slots::fresh(),
        };
        let image = ks.seal(&[], 0)?;
        // Flush `dir`'s entry in its parent before the first commit, whether
        // or not this call created `dir`. A failure refuses `create`. On
        // Windows the medium's `fsync_parent` flushes nothing, as Win32
        // documents no such call; it is called on both platforms so `create`
        // runs the same steps in the same order.
        #[cfg(unix)]
        ks.medium.fsync_parent(&ks.directory)?;
        #[cfg(windows)]
        ks.medium.fsync_parent(dir)?;
        let _durable: Durable = ks.commit(&image)?;
        Ok(ks)
    }

    /// [`Keystore::open`] over an explicit medium.
    #[cfg(unix)]
    pub fn open_with(dir: &Path, mut medium: M, unlock: &Unlock<'_>) -> Result<Self> {
        let directory = Directory::open(dir, false)?;
        // Check for the snapshot before touching the lock file, so a `Missing`
        // refusal leaves no lock file behind. Later refusals do leave one,
        // because the authoritative read must happen under the lock; the
        // leftover is inert (see "The lock" in the module doc).
        if !directory.exists(SNAPSHOT_NAME).map_err(io("stat snapshot"))? {
            return Err(Error::Missing);
        }
        let lock = take_lock(&directory)?;
        // A stale temp is a partial or complete image from an interrupted
        // commit. Never adopted; unlinked so it cannot leak. If unlinking
        // fails, a later rename would fail too.
        directory.remove_temp(TEMP_NAME).map_err(io("remove stale temp"))?;
        let mut file = match directory.open_snapshot(SNAPSHOT_NAME) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(Error::Missing),
            Err(e) => return Err(io("open snapshot")(e)),
        };
        // The snapshot is the ciphertext, and anyone who can read it can try
        // passwords against it offline. A directory that is not `0700`, or a
        // file copied in from elsewhere, can leave it readable by others.
        perms::refuse_unsafe_file(&file, SNAPSHOT_NAME)?;
        let meta = file.metadata().map_err(io("stat snapshot"))?;
        // The same range `format::read_header` reports for the same refusal.
        let len = usize::try_from(meta.len()).map_err(|_| Error::Range {
            what: "keystore image length",
            min: format::MIN_IMAGE_LEN as u64,
            max: format::MAX_IMAGE_LEN as u64,
            got: meta.len(),
        })?;
        if len > format::MAX_IMAGE_LEN {
            return Err(Error::Range {
                what: "keystore image length",
                min: format::MIN_IMAGE_LEN as u64,
                max: format::MAX_IMAGE_LEN as u64,
                got: meta.len(),
            });
        }
        let mut image: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; len]);
        file.read_exact(&mut image).map_err(io("read snapshot"))?;
        let mut extra = [0u8; 1];
        let n = file.read(&mut extra).map_err(io("read snapshot"))?;
        if n != 0 {
            return Err(Error::Corrupt {
                what: "snapshot grew while being read",
                offset: len,
            });
        }
        // The header is plaintext and read first, so an unsupported version
        // is refused before the key is derived. A version-3 store is read as
        // is; the first commit re-seals it in the current version.
        let framed = format::read_header(&image)?;
        let (salt, kdf, version) = (framed.header.salt, framed.header.kdf, framed.version);
        let key = crypt::derive_key(unlock.password, &salt, kdf)?;
        let parsed = format::parse_with_key(&image, &key)?;
        // Flush the snapshot read and its directory entry before the handle
        // exists. A commit whose `fsync_dir` failed, or whose process ended
        // between its rename and that flush, leaves a snapshot that may be
        // only in the cache, and no receipt attests it. `resign` signs the
        // reservation it finds without committing, so without this flush a
        // key could sign from a state a power cut could take back. A failure
        // refuses the open.
        medium.flush_standing(&directory, &file)?;
        Ok(Keystore {
            dir: dir.to_path_buf(),
            directory,
            _lock: lock,
            medium,
            state: State::Live {
                generation: parsed.generation,
                slots: parsed.slots,
            },
            master: parsed.master,
            crypto: StoreCrypto {
                key,
                kdf,
                salt,
                nonce_seed: unlock.nonce_seed,
            },
            opened_version: version,
            on_disk_version: version,
        })
    }

    /// [`Keystore::open`] over an explicit medium, on Windows: the same
    /// refusals in the same order as the Unix arm, then both slots read
    /// through the handles kept for the handle's life, and the newer image
    /// taken by `slots`' rule.
    ///
    /// The Unix arm refuses a snapshot that grows while it is read. Here the
    /// held handles share read access only, so nothing else can write a slot
    /// while it is read or while the handle lives.
    ///
    /// The image taken is flushed to the device before the handle exists, and
    /// a store whose newest slot cannot be flushed is refused.
    #[cfg(windows)]
    pub fn open_with(dir: &Path, mut medium: M, unlock: &Unlock<'_>) -> Result<Self> {
        perms::refuse_unsafe_dir(dir)?;
        // Same order as the Unix arm: check the snapshot before touching the
        // lock file, read under the lock, and unlink a stale temp without
        // adopting it.
        let path = dir.join(SNAPSHOT_NAME);
        if !path.exists() {
            return Err(Error::Missing);
        }
        let lock = take_lock(dir)?;
        let temp = dir.join(TEMP_NAME);
        if temp.exists() {
            fs::remove_file(&temp).map_err(io("remove stale temp"))?;
        }
        let mut held0 = perms::open_slot(&path)?.ok_or(Error::Missing)?;
        let mut held1 = perms::open_slot(&dir.join(SLOT1_NAME))?;
        // Check each file's own access list before reading it: on Windows
        // the directory's list does not decide who can reach a file (see
        // `perms`).
        perms::refuse_unsafe_file(&held0, SNAPSHOT_NAME)?;
        if let Some(file) = held1.as_ref() {
            perms::refuse_unsafe_file(file, SLOT1_NAME)?;
        }
        let slot0 = slots::sort(Some(read_slot(&mut held0)?))?;
        // A slot 1 longer than any frame is treated as torn rather than
        // refused: it is never read while slot 0 holds the store, and never
        // allocated for.
        let slot1 = match held1.as_mut() {
            None => slots::Content::Absent,
            Some(file) => match read_slot(file) {
                Err(Error::Range { .. }) => slots::Content::Torn,
                read => slots::sort(Some(read?))?,
            },
        };
        let taken = slots::take(&slot0, &slot1, unlock.password)?;
        let vacate = matches!(slot0, slots::Content::Other(_));
        // Flush the image taken to the device before the handle exists.
        // `take` reads what the cache holds, which after a commit whose flush
        // failed, or whose process ended between its write and its flush, can
        // be an image the device never received and no receipt attests.
        // `resign` signs the reservation it finds without committing, so
        // without this flush a key could sign from a state a power cut could
        // take back. Flushing here covers every command, and a failure refuses
        // the open, since an image that cannot be made durable must not be
        // signed from. It also lets a commit overwrite the other slot at once,
        // because the newest is on the device before any write.
        let newest = taken.newest;
        let standing = if newest == 0 { Some(&held0) } else { held1.as_ref() };
        let standing = standing.ok_or(Error::Io {
            op: "flush_standing",
            kind: std::io::ErrorKind::NotFound,
        })?;
        medium.flush_standing(dir, newest, standing)?;
        Ok(Keystore {
            dir: dir.to_path_buf(),
            _lock: lock,
            medium,
            state: State::Live {
                generation: taken.parsed.generation,
                slots: taken.parsed.slots,
            },
            master: taken.parsed.master,
            crypto: StoreCrypto {
                key: taken.key,
                kdf: taken.kdf,
                salt: taken.salt,
                nonce_seed: unlock.nonce_seed,
            },
            opened_version: taken.version,
            on_disk_version: taken.version,
            slots: Slots {
                held: [Some(held0), held1],
                newest: Some(newest),
                vacate,
            },
        })
    }

    /// The store directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The medium, for instrument inspection in tests.
    pub fn medium(&self) -> &M {
        &self.medium
    }

    /// The medium, mutably, for instrument control in tests.
    pub fn medium_mut(&mut self) -> &mut M {
        &mut self.medium
    }

    /// Encode and seal one image, deriving the nonce from `generation`.
    fn seal(&self, records: &[RecordRef<'_>], generation: u64) -> Result<Zeroizing<Vec<u8>>> {
        let nonce = crypt::nonce_for(&self.crypto.nonce_seed, generation);
        format::encode(
            records,
            generation,
            self.master.as_ref(),
            self.crypto.kdf,
            &self.crypto.salt,
            &self.crypto.key,
            &nonce,
        )
    }

    fn live(&self) -> Result<(u64, &BTreeMap<Tag, Slot>)> {
        match &self.state {
            State::Live { generation, slots } => Ok((*generation, slots)),
            State::Poisoned(first) => Err(Error::Poisoned {
                first: Box::new(first.clone()),
            }),
        }
    }

    fn live_mut(&mut self) -> Result<(&mut u64, &mut BTreeMap<Tag, Slot>)> {
        match &mut self.state {
            State::Live { generation, slots } => Ok((generation, slots)),
            State::Poisoned(first) => Err(Error::Poisoned {
                first: Box::new(first.clone()),
            }),
        }
    }

    /// The store-level commit counter, committed with the index and the
    /// pending record (I3).
    pub fn generation(&self) -> Result<u64> {
        self.live().map(|(g, _)| g)
    }

    /// A non-secret view of the account with `tag`, if the store holds it.
    pub fn view(&self, tag: &Tag) -> Result<Option<AccountView>> {
        let (_, slots) = self.live()?;
        Ok(slots.get(tag).map(|s| AccountView {
            tag: *tag,
            kind: s.account.kind(),
            wots_index: s.account.wots_index(),
            pending: s.pending,
            settled: s.settled,
        }))
    }

    /// The format version this handle opened, once a commit under this
    /// handle has rewritten the store in the current version. `None` for a
    /// store created by this build, a current-version store, or an older
    /// store not yet written (`open` never rewrites).
    pub fn upgraded_from(&self) -> Option<u16> {
        (self.opened_version != self.on_disk_version).then_some(self.opened_version)
    }

    /// The stored identity of this account's key stream (the rotation-0
    /// public key's hash).
    ///
    /// Read, not recomputed; `add` and `sign_spend` verify it. A divergence
    /// report uses it to compare two stores on one seed without exposing key
    /// material.
    pub fn stream_id(&self, tag: &Tag) -> Result<crate::account::StreamId> {
        let (_, slots) = self.live()?;
        let slot = slots.get(tag).ok_or(Error::NoSuchAccount)?;
        Ok(Self::stored_stream_id(&slot.account))
    }

    /// The master seed this store holds, if any. `Wallet::open` and
    /// `sign_spend` take the seed from here; it is in memory only because the
    /// password decrypted the store, and it is dropped with the handle.
    pub fn master(&self) -> Result<Option<&Secret<SEED_LEN>>> {
        self.live()?;
        Ok(self.master.as_ref())
    }

    /// Put a master seed into a store that has none, and commit.
    ///
    /// # Errors
    ///
    /// `Error::Exists` if the store already holds a master seed. Replacing it
    /// would leave every derived account pointing at a key stream the store
    /// can no longer produce (I5).
    pub fn adopt_master(&mut self, master: &Secret<SEED_LEN>) -> Result<Durable> {
        let (generation, slots) = self.live()?;
        if self.master.is_some() {
            return Err(Error::Exists {
                what: "master seed",
            });
        }
        let next_gen = generation.checked_add(1).ok_or(Error::Range {
            what: "keystore generation",
            min: 0,
            max: u64::MAX,
            got: u64::MAX,
        })?;
        let records = Self::records_with(slots, None, None);
        let nonce = crypt::nonce_for(&self.crypto.nonce_seed, next_gen);
        let image = format::encode(
            &records,
            next_gen,
            Some(master),
            self.crypto.kdf,
            &self.crypto.salt,
            &self.crypto.key,
            &nonce,
        )?;
        let durable = self.commit(&image)?;
        self.master = Some(master.duplicate());
        if let State::Live { generation, .. } = &mut self.state {
            *generation = next_gen;
        }
        Ok(durable)
    }

    /// Every tag, ascending.
    pub fn tags(&self) -> Result<Vec<Tag>> {
        let (_, slots) = self.live()?;
        Ok(slots.keys().copied().collect())
    }

    /// The four steps, in order, and the only constructor of [`Durable`]. On
    /// any error the handle is poisoned and no further filesystem operation
    /// is performed, so the disk holds what the interrupted step left. On
    /// Windows the steps are the slot writes in `Keystore::write_slots`,
    /// which return into the same arms.
    fn commit(&mut self, image: &[u8]) -> Result<Durable> {
        #[cfg(windows)]
        let dir = self.dir.clone();
        #[cfg(windows)]
        let outcome = self.write_slots(&dir, image);
        #[cfg(unix)]
        let outcome = (|| -> Result<()> {
            let written = self.medium.write_temp(&self.directory, image)?;
            let synced = self.medium.fsync_file(written)?;
            let renamed = self.medium.rename(synced, &self.directory)?;
            self.medium.fsync_dir(renamed, &self.directory)
        })();
        match outcome {
            Ok(()) => {
                // Every image this handle seals is `format::VERSION`, so an
                // older store is upgraded by its first commit.
                self.on_disk_version = format::VERSION;
                Ok(Durable(()))
            }
            Err(e) => {
                self.state = State::Poisoned(e.clone());
                Err(e)
            }
        }
    }

    /// The Windows commit: `image` framed, written into the slot that does not
    /// hold the newest image, and flushed.
    ///
    /// Crash safety rests on three rules. The newest slot is on the device
    /// before the other is written: `open` flushed it before the handle
    /// existed, and each commit flushes what it writes before that becomes the
    /// newest. The write is flushed before this returns, so before `Durable`
    /// exists. A plain image in slot 0 is overwritten, with the vacant frame,
    /// only once slot 1 holds a flushed frame; from then on a build that reads
    /// only the rename layout refuses the store.
    ///
    /// When neither slot holds anything yet (`create`), the image goes to
    /// slot 1 and slot 0 is made vacant after it, so an existing
    /// `accounts.mks` means an image is on the device.
    #[cfg(windows)]
    fn write_slots(&mut self, dir: &Path, image: &[u8]) -> Result<()> {
        let target = if self.slots.newest == Some(1) { 0 } else { 1 };
        let framed = slots::frame(image)?;
        let written = self.medium.write_slot(dir, target, &mut self.slots.held[target], &framed)?;
        let _flushed = self.medium.flush_slot(written)?;
        if target == 1 && self.slots.vacate {
            let vacant = slots::frame(&[])?;
            let written = self.medium.write_slot(dir, 0, &mut self.slots.held[0], &vacant)?;
            let _flushed = self.medium.flush_slot(written)?;
        }
        self.slots.vacate = false;
        self.slots.newest = Some(target);
        Ok(())
    }

    /// Build the record list for an image: the current slots, optionally with
    /// one record's index and both reservation blocks overridden and one
    /// extra account appended, sorted by tag. Slots the override does not
    /// name keep their own `pending` and `settled`.
    fn records_with<'a>(
        slots: &'a BTreeMap<Tag, Slot>,
        over: Option<(&Tag, WotsIndex, Option<Pending>, Option<Pending>)>,
        extra: Option<(&'a Account, Tag)>,
    ) -> Vec<RecordRef<'a>> {
        let mut out: Vec<RecordRef<'a>> = slots
            .iter()
            .map(|(tag, slot)| {
                let (wots_index, pending, settled) = match over {
                    Some((t, i, p, s)) if t == tag => (i, p, s),
                    _ => (slot.account.wots_index(), slot.pending, slot.settled),
                };
                RecordRef {
                    tag: *tag,
                    account: &slot.account,
                    wots_index,
                    pending,
                    settled,
                }
            })
            .collect();
        if let Some((account, tag)) = extra {
            out.push(RecordRef {
                tag,
                account,
                wots_index: account.wots_index(),
                pending: None,
                settled: None,
            });
            out.sort_by_key(|r| r.tag);
        }
        out
    }

    /// Add an account and make it durable. Insert-only. Returns no receipt:
    /// receipts attest advances.
    ///
    /// # Errors
    ///
    /// `Error::Exists` when the store already holds:
    ///
    /// * the same tag;
    /// * the same imported or SDK root, compared in constant time
    ///   (`Secret::ct_eq`) and checked first so the refusal names the key
    ///   material;
    /// * the same key stream, across kinds. A rotation key depends only on the
    ///   32-byte seed, so one seed under two tags would let one key sign
    ///   twice. The incoming identity is recomputed from the account's key
    ///   material (the root, or for a derived account the store's master
    ///   seed), so a forged record cannot pass.
    ///
    /// A derived account whose tag or identity does not match the master seed
    /// is refused with `DerivedTagNotReproduced` or `StreamIdNotReproduced`.
    /// A store with no master seed accepts a derived account's stored
    /// identity; it cannot sign for that account until a master is present,
    /// and `sign_spend` re-derives it then.
    pub fn add(&mut self, account: Account) -> Result<()> {
        let tag = account.tag();
        let (generation, slots) = self.live()?;
        if slots.contains_key(&tag) {
            return Err(Error::Exists { what: "account tag" });
        }
        // Check the root first so the refusal names the key material; equal
        // roots also imply equal stream identities.
        if let crate::account::KeyMaterial::Imported { root, .. } | crate::account::KeyMaterial::Sdk { root, .. } =
            account.key_material()
        {
            if self.imported_roots(slots).any(|stored| stored.ct_eq(root.secret())) {
                return Err(Error::Exists { what: "imported root" });
            }
        }
        let incoming = self.recomputed_stream_id(&account)?;
        if slots
            .values()
            .any(|s| Self::stored_stream_id(&s.account) == incoming)
        {
            return Err(Error::Exists { what: "key stream" });
        }
        let next_gen = generation.checked_add(1).ok_or(Error::Range {
            what: "keystore generation",
            min: 0,
            max: u64::MAX - 1,
            got: generation,
        })?;
        let image = self.seal(&Self::records_with(slots, None, Some((&account, tag))), next_gen)?;
        let _durable: Durable = self.commit(&image)?;
        let (g, slots) = self.live_mut()?;
        *g = next_gen;
        slots.insert(
            tag,
            Slot {
                account,
                pending: None,
                settled: None,
            },
        );
        Ok(())
    }

    /// The stream identity an account's key material produces: from the root
    /// for an imported or SDK account, or from this store's master seed for a
    /// derived one, with the same checks and errors `key_at` uses. Without a
    /// master seed the stored value is returned; such a store cannot sign for
    /// the account either.
    fn recomputed_stream_id(&self, account: &Account) -> Result<crate::account::StreamId> {
        match account.key_material() {
            crate::account::KeyMaterial::Imported { root, .. } | crate::account::KeyMaterial::Sdk { root, .. } => {
                Ok(crate::derive::stream_id(root.secret()))
            }
            crate::account::KeyMaterial::Derived {
                account_index,
                stream,
            } => match &self.master {
                Some(master) => {
                    let derived = crate::derive::derive_account(master, *account_index);
                    if derived.tag() != account.tag() {
                        return Err(Error::DerivedTagNotReproduced {
                            account_index: *account_index,
                        });
                    }
                    let recomputed = crate::derive::stream_id(derived.seed());
                    if recomputed != *stream {
                        return Err(Error::StreamIdNotReproduced);
                    }
                    Ok(recomputed)
                }
                None => Ok(*stream),
            },
        }
    }

    /// The stream identity a stored slot carries.
    fn stored_stream_id(account: &Account) -> crate::account::StreamId {
        match account.key_material() {
            crate::account::KeyMaterial::Imported { stream, .. }
            | crate::account::KeyMaterial::Sdk { stream, .. }
            | crate::account::KeyMaterial::Derived { stream, .. } => *stream,
        }
    }

    /// Reserve the account's current key for `digest` and advance the index
    /// by one, durably, in one write. The receipt attests the new index.
    ///
    /// `figures` (the balance the plan was built against and its
    /// block-to-live) are recorded with the digest, so a later reader can
    /// tell a dead reservation from a live one. A retained settled block is
    /// overwritten.
    ///
    /// # Errors
    ///
    /// `Error::NoSuchAccount` for an unknown tag; `Error::PendingUnresolved`
    /// while a reservation is open.
    pub fn persist_advance(&mut self, tag: &Tag, digest: &[u8; 32], figures: Figures) -> Result<AdvanceReceipt> {
        let (generation, slots) = self.live()?;
        let slot = slots.get(tag).ok_or(Error::NoSuchAccount)?;
        if let Some(p) = slot.pending {
            return Err(Error::PendingUnresolved {
                spent_index: p.spent_index.get(),
            });
        }
        let current = slot.account.wots_index();
        let next = current.advanced()?;
        let pending = Some(Pending {
            spent_index: current,
            digest: *digest,
            figures: Some(figures),
        });
        self.advance_committed(tag, generation, next, pending, None, Account::advance_to)
    }

    /// Move the index forward to `target` without reserving a key (the
    /// reconciliation path). Clears a retained settled block, because
    /// `spent_index + 1 == wots_index` would no longer hold.
    ///
    /// # Errors
    ///
    /// `Error::Range` unless `target` is strictly ahead;
    /// `Error::PendingUnresolved` while a reservation is open.
    pub fn persist_advance_to(&mut self, tag: &Tag, target: WotsIndex) -> Result<AdvanceReceipt> {
        let (generation, slots) = self.live()?;
        let slot = slots.get(tag).ok_or(Error::NoSuchAccount)?;
        if let Some(p) = slot.pending {
            return Err(Error::PendingUnresolved {
                spent_index: p.spent_index.get(),
            });
        }
        let stored = slot.account.wots_index();
        if target.get() <= stored.get() {
            return Err(Error::Range {
                what: "wots index for tag",
                min: u64::from(stored.get()) + 1,
                max: u64::from(u32::MAX),
                got: u64::from(target.get()),
            });
        }
        self.advance_committed(tag, generation, target, None, None, Account::advance_to)
    }

    /// Move the index back to `target` without reserving a key (the
    /// acknowledged rollback). Clears a retained settled block, as
    /// `persist_advance_to` does. Returns the index now stored.
    ///
    /// # Errors
    ///
    /// `Error::Range` unless `target` is strictly behind;
    /// `Error::PendingUnresolved` while a reservation is open.
    pub fn persist_rollback_to(&mut self, tag: &Tag, target: WotsIndex) -> Result<WotsIndex> {
        let (generation, slots) = self.live()?;
        let slot = slots.get(tag).ok_or(Error::NoSuchAccount)?;
        if let Some(p) = slot.pending {
            return Err(Error::PendingUnresolved {
                spent_index: p.spent_index.get(),
            });
        }
        let stored = slot.account.wots_index();
        if target.get() >= stored.get() {
            return Err(Error::Range {
                what: "wots index for tag",
                min: 0,
                max: u64::from(stored.get().saturating_sub(1)),
                got: u64::from(target.get()),
            });
        }
        self.advance_committed(tag, generation, target, None, None, Account::rollback_to)
            .map(|receipt| receipt.index())
    }

    /// One commit that moves the index and sets both reservation blocks to
    /// what the caller passes, then applies the same state in memory through
    /// `apply` (`Account::advance_to` or `Account::rollback_to`).
    fn advance_committed(
        &mut self,
        tag: &Tag,
        generation: u64,
        next: WotsIndex,
        pending: Option<Pending>,
        settled: Option<Pending>,
        apply: fn(&mut Account, WotsIndex) -> Result<()>,
    ) -> Result<AdvanceReceipt> {
        let next_gen = generation.checked_add(1).ok_or(Error::Range {
            what: "keystore generation",
            min: 0,
            max: u64::MAX - 1,
            got: generation,
        })?;
        let image = {
            let (_, slots) = self.live()?;
            self.seal(&Self::records_with(slots, Some((tag, next, pending, settled)), None), next_gen)?
        };
        let durable = self.commit(&image)?;
        // Apply in memory exactly what disk now holds. An error here would
        // leave disk ahead of memory, so it poisons the handle as `commit`
        // does. Unreachable from current callers, which validate before
        // sealing; the unit test below drives it directly.
        let applied = (|| -> Result<AdvanceReceipt> {
            let (g, slots) = self.live_mut()?;
            *g = next_gen;
            let slot = slots.get_mut(tag).ok_or(Error::NoSuchAccount)?;
            apply(&mut slot.account, next)?;
            slot.pending = pending;
            slot.settled = settled;
            Ok(AdvanceReceipt::attesting(*tag, next, durable))
        })();
        self.poison_on(applied)
    }

    /// Poison the handle if applying a durable commit in memory failed, since
    /// memory no longer matches disk.
    fn poison_on<T>(&mut self, applied: Result<T>) -> Result<T> {
        match applied {
            Ok(v) => Ok(v),
            Err(e) => {
                self.state = State::Poisoned(e.clone());
                Err(e)
            }
        }
    }

    /// Move the open reservation to the retained settled block, durably,
    /// which lets the account spend again.
    ///
    /// The block (index, digest and figures) is kept until the next
    /// `persist_advance` overwrites it or `persist_advance_to` or
    /// `persist_rollback_to` clears it, because the chain can revert the
    /// observation a settle was based on, and the block is the only record of
    /// the signature that key gave.
    ///
    /// # Errors
    ///
    /// `Error::NothingPending` when no reservation is open.
    pub fn persist_settled(&mut self, tag: &Tag) -> Result<()> {
        let (generation, slots) = self.live()?;
        let slot = slots.get(tag).ok_or(Error::NoSuchAccount)?;
        let block = slot.pending.ok_or(Error::NothingPending)?;
        let index = slot.account.wots_index();
        let next_gen = generation.checked_add(1).ok_or(Error::Range {
            what: "keystore generation",
            min: 0,
            max: u64::MAX - 1,
            got: generation,
        })?;
        let image = self.seal(&Self::records_with(slots, Some((tag, index, None, Some(block))), None), next_gen)?;
        let _durable: Durable = self.commit(&image)?;
        // Apply in memory what disk now holds; an error here poisons, as in
        // `advance_committed`.
        let applied = (|| -> Result<()> {
            let (g, slots) = self.live_mut()?;
            *g = next_gen;
            let slot = slots.get_mut(tag).ok_or(Error::NoSuchAccount)?;
            slot.pending = None;
            slot.settled = Some(block);
            Ok(())
        })();
        self.poison_on(applied)
    }

    /// Consume the handle into its records: the only path by which key
    /// material leaves a keystore, like `Account::to_record`. The lock is
    /// released when the handle drops.
    pub fn into_records(self) -> Result<Vec<AccountRecord>> {
        match self.state {
            State::Live { slots, .. } => Ok(slots.into_values().map(|s| s.account.to_record()).collect()),
            State::Poisoned(first) => Err(Error::Poisoned {
                first: Box::new(first),
            }),
        }
    }
}

impl<M: Medium> core::fmt::Debug for Keystore<M> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut d = f.debug_struct("Keystore");
        d.field("dir", &self.dir);
        match &self.state {
            State::Live { generation, slots } => {
                d.field("generation", generation).field("accounts", &slots.len())
            }
            State::Poisoned(e) => d.field("poisoned", e),
        };
        d.finish()
    }
}

#[cfg(test)]
mod tests {
    //! Tests for what only this module can reach: `advance_committed` is
    //! private, and every public caller validates its arguments before
    //! sealing.
    // Not under Miri: the only test here is skipped under Miri.
    #[cfg(not(miri))]
    use super::*;

    // Not under Miri: only used by the test skipped under Miri.
    #[cfg(not(miri))]
    fn scratch(name: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("mcm-keystore-unit-{name}-{}-{nanos}", std::process::id()))
    }

    // Not under Miri: only used by the test skipped under Miri.
    #[cfg(not(miri))]
    const PASSWORD: &[u8] = b"unit-test-password-not-for-use";
    // Not under Miri: only used by the test skipped under Miri.
    #[cfg(not(miri))]
    const NONCE_SEED: [u8; NONCE_SEED_LEN] = [4u8; NONCE_SEED_LEN];

    /// Disk ahead of memory poisons the handle.
    ///
    /// `advance_committed` with `next` equal to the current position: the
    /// commit writes generation 2, then `advance_to` refuses the target. The
    /// handle must answer its next call as poisoned, and a reopen must read
    /// generation 2.
    ///
    /// Not under Miri: it reads the wall clock and writes a real store, which
    /// Miri's isolation refuses.
    #[cfg(not(miri))]
    #[test]
    fn a_failed_application_after_a_durable_commit_poisons_the_handle() {
        let dir = scratch("poison-after-commit");
        let init = Init {
            password: PASSWORD,
            salt: [3u8; SALT_LEN],
            nonce_seed: NONCE_SEED,
            kdf: Kdf::CHEAP_FOR_TESTS,
        };
        let mut ks = Keystore::create(&dir, &init).unwrap_or_else(|e| panic!("{e}"));
        let master = Secret::new([7u8; SEED_LEN]);
        let account = Account::derive(&master, 0);
        let tag = account.tag();
        ks.add(account).unwrap_or_else(|e| panic!("{e}"));
        let generation = ks.generation().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(generation, 1, "premise: create then add is generation 1");

        let err = ks.advance_committed(&tag, generation, WotsIndex::ZERO, None, None, Account::advance_to).err();
        assert!(
            matches!(err, Some(Error::Range { .. })),
            "premise: advance_to must refuse a target equal to the current position, after the \
             commit: {err:?}"
        );
        let next_call = ks.generation().err();
        assert!(
            matches!(next_call, Some(Error::Poisoned { .. })),
            "THE HANDLE ANSWERED AS IF NOTHING HAPPENED after a durable commit whose application \
             failed: {next_call:?}. Disk is ahead of memory and the handle is live."
        );
        drop(ks);
        let reopened = Keystore::open(
            &dir,
            &Unlock {
                password: PASSWORD,
                nonce_seed: NONCE_SEED,
            },
        )
        .unwrap_or_else(|e| panic!("reopen: {e}"));
        assert_eq!(
            reopened.generation().unwrap_or_else(|e| panic!("{e}")),
            2,
            "the image on disk does not carry the generation the commit wrote"
        );
        let view = reopened
            .view(&tag)
            .unwrap_or_else(|e| panic!("{e}"))
            .unwrap_or_else(|| panic!("the account is gone from disk"));
        assert_eq!(view.wots_index, WotsIndex::ZERO, "the image on disk moved the position");
        drop(reopened);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
