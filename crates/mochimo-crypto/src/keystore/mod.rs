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
//! fourth. The format is in `format` and the steps in `medium`. A single
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
//! # The lock
//!
//! `keystore.lock` is created once, never unlinked, and held with
//! `File::try_lock` (`flock(2)`) for the handle's life. The kernel releases it
//! on process death, including `SIGKILL`, so a held lock always means a live
//! holder and there is no stale-lock state. Unlinking it would allow two
//! holders on different inodes. Two opens in one process also conflict
//! (`flock` is per open file description). Local filesystems only: NFS lock
//! emulation may not honour it.
//!
//! The lock file's existence means nothing. A refused `open` past the
//! `Missing` check leaves the file behind, because the read must happen under
//! the lock; [`occupied`] reports only the snapshot, and a live holder is
//! refused with [`Error::Locked`]. A `create` killed between writing the temp
//! file and the rename leaves `accounts.mks.tmp`, which the next commit
//! replaces rather than adopts.
//!
//! # What `open` refuses
//!
//! - A directory owned by another user or writable by group or others (see
//!   `perms`). The check is made on the opened directory, which is kept for
//!   every later operation.
//! - A lock or snapshot file owned by another user or readable or writable
//!   by group or others ([`Error::UnsafeFileMode`]).
//! - A store directory that is a symbolic link
//!   ([`Error::StoreDirectoryIsLink`]). The lock and snapshot are opened
//!   without following links and must be regular files.
//! - A missing snapshot ([`Error::Missing`]): an absent file is not an empty
//!   store (I5). New stores go through [`Keystore::create`].
//!
//! A stale temp file is unlinked after the lock is taken and never adopted,
//! so only one file is ever authoritative. Before returning a handle, `open`
//! flushes the snapshot it read and the store directory to the device. A
//! store that cannot be flushed is refused, because `resign` signs from what
//! `open` read.
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

#[cfg(not(unix))]
compile_error!(
    "the keystore relies on POSIX rename atomicity, directory fsync and flock; \
     no non-unix target is supported"
);

pub(crate) mod crypt;
mod directory;
pub use directory::Directory;
pub mod format;
pub mod medium;
pub(crate) mod perms;
pub mod sign;
pub mod spend;

use std::collections::BTreeMap;
use std::fs::{File, TryLockError};
use std::io::Read;
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
use medium::{SNAPSHOT_NAME, TEMP_NAME};

pub(crate) const LOCK_NAME: &str = "keystore.lock";

/// Evidence that all four durable steps completed. Constructed only in the
/// `Ok` arm of [`Keystore::commit`] (checked by
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

fn take_lock(dir: &Directory) -> Result<File> {
    let file = dir.open_lock(LOCK_NAME).map_err(io("open lock"))?;
    // Anyone who can open the lock file can hold it, so its mode is checked
    // before it is locked.
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
pub fn occupied(dir: &Path) -> Option<&'static str> {
    if dir.join(SNAPSHOT_NAME).exists() {
        return Some("snapshot");
    }
    None
}

fn occupied_at(dir: &Directory) -> Result<Option<&'static str>> {
    Ok(dir.exists(SNAPSHOT_NAME).map_err(io("stat snapshot"))?.then_some("snapshot"))
}

impl Keystore<Disk> {
    /// Create a new keystore in `dir` (created `0700` if absent).
    ///
    /// Refuses a directory that already holds a snapshot and a live holder of
    /// its lock (`Locked`); an unheld lock file is ignored. Flushes `dir`'s
    /// parent before the first commit so `dir`'s own entry is durable.
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
        let directory = Directory::open(dir, true)?;
        if let Some(what) = occupied_at(&directory)? {
            return Err(Error::Exists { what });
        }
        let lock = take_lock(&directory)?;
        // Checked again under the lock: a second `create` could pass the
        // check above while a first holds the lock with its snapshot not yet
        // renamed in, then take the lock and seal an empty store over it.
        if let Some(what) = occupied_at(&directory)? {
            return Err(Error::Exists { what });
        }
        // Derive the key before the first write, so a store that exists has a
        // derivable key.
        let kdf = init.kdf.checked()?;
        let key = crypt::derive_key(init.password, &init.salt, kdf)?;
        let mut ks = Keystore {
            dir: dir.to_path_buf(),
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
        };
        let image = ks.seal(&[], 0)?;
        // Flush `dir`'s entry in its parent before the first commit, whether
        // or not this call created `dir`. A failure refuses `create`.
        ks.medium.fsync_parent(&ks.directory)?;
        let _durable: Durable = ks.commit(&image)?;
        Ok(ks)
    }

    /// [`Keystore::open`] over an explicit medium.
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
    /// is performed, so the disk holds what the interrupted step left.
    fn commit(&mut self, image: &[u8]) -> Result<Durable> {
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
