// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! The four durable commit steps as primitives, and the typestate that fixes
//! their order.
//!
//! The keystore's commit is: write the temp file, fsync it, rename it over
//! the snapshot, fsync the directory. A [`Medium`] supplies the steps; the
//! order is fixed by `Keystore::commit`. The trait is `pub` so integration
//! tests can use the instrumented medium, and sealed so nothing outside this
//! crate can implement it (invariant I2).
//!
//! [`Medium::fsync_parent`] flushes the directory holding the store
//! directory, where the store directory's own entry lives. `Keystore::create`
//! calls it once before its first commit; it is not a commit step and takes
//! no token. [`Instrumented`] records it with the parent's path, so a flush
//! of the wrong directory is visible.
//!
//! On Unix, `Medium::flush_standing` flushes the snapshot `open` read and
//! then the store directory, before `open` returns a handle. A commit that
//! renamed its temp and then failed or was killed before `fsync_dir` leaves
//! a snapshot whose entry may exist only in the cache; `resign` signs the
//! reservation it finds without committing, so that entry must be on the
//! device before anything is signed from it. Like `fsync_parent`, it is not
//! a commit step and takes no token.
//!
//! On Windows `fsync_parent` flushes nothing. The Win32 documentation
//! (`FlushFileBuffers`, `CreateFile`, File Caching) describes flushing files
//! and volumes, and a volume handle needs administrative privileges; it
//! documents no call an unprivileged process can make that commits a
//! directory's entry in its parent. The call is still made and recorded, so
//! the sequence has the same shape as on Unix. The parent directory's entry
//! is therefore not flushed on Windows.
//!
//! # Typestate
//!
//! Each step returns a token the next consumes: `write_temp -> Written`,
//! `fsync_file(Written) -> Synced`, `rename(Synced) -> Renamed`,
//! `fsync_dir(Renamed)`. Reordering is a type error
//! (`ui/fail/medium_steps_are_not_reorderable.rs`), and the tokens have
//! private fields so they cannot be forged outside the crate.
//!
//! # Windows slot steps
//!
//! A Windows store is two slot files rewritten in place (`super::slots`
//! defines the frame and how `open` picks the newer slot), because Win32
//! documents no way to make a rename's directory entry durable. On Windows
//! the trait has different steps, under the same seal:
//! `write_slot -> SlotWritten`, `flush_slot(SlotWritten) -> Flushed`, and
//! `flush_standing`, which flushes a slot as it currently stands. The order
//! is fixed by `Keystore::open_with` and `Keystore::commit`:
//! - `open` flushes the slot holding the newest image before returning a
//!   handle, so it is on the device before the other slot is written and
//!   before anything is signed from it;
//! - a write is flushed before `Durable` is created;
//! - a plain image in slot 0 is overwritten only once slot 1 holds a flushed
//!   frame.
//!
//! `ui/fail/medium_slot_steps_are_not_reorderable.rs` checks that a flush
//! accepts only a write's token.
//!
//! No step renames or deletes. The only directory entry a step creates is a
//! new slot file's, on a store's first commit or a migrating store's commit.
//! The flush that follows stores that entry: the `CreateFile` and File
//! Caching documentation name `FlushFileBuffers` as the call that writes a
//! file's cached metadata to disk, and `sync_all` makes that call on Windows.
//! Durability across a power cut depends on the device honouring the flush,
//! as `fsync` does on Unix.
//!
//! # Instrumented medium
//!
//! [`Instrumented`] records every call with its arguments and can be told to
//! fail after call `k`: it performs the primitive and then returns an error,
//! modelling a process killed after the syscall completed. It does not model
//! power loss (a dropped page cache, a truncated journal, or an `fsync` that
//! lies). Recording arguments catches an fsync on the wrong path, which
//! counts and byte comparisons alone would miss.
//!
//! On Windows it can also tear a `write_slot`: after the `k`-th call it
//! leaves the slot holding the bytes a `Tear` computes from the slot's
//! previous contents and the requested frame (or no file, if the write was
//! creating it), then returns an error. This models what a power cut before
//! the flush can leave of an unflushed write. It cannot model the loss of a
//! write that was already flushed; the slot layout assumes that does not
//! happen.

use std::fs::File;
#[cfg(windows)]
use std::fs;
use std::io::Write;
#[cfg(windows)]
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

#[cfg(windows)]
use super::perms;
#[cfg(unix)]
use super::Directory;
use crate::error::{Error, Result};

pub(crate) const SNAPSHOT_NAME: &str = "accounts.mks";
pub(crate) const TEMP_NAME: &str = "accounts.mks.tmp";
/// Slot 1's file name on Windows; slot 0's is [`SNAPSHOT_NAME`].
#[cfg(windows)]
pub(crate) const SLOT1_NAME: &str = "accounts.mks.1";

mod sealed {
    pub trait Sealed {}
}

/// The temp file has been written in full (not yet flushed).
#[cfg(unix)]
pub struct Written {
    file: File,
    path: PathBuf,
}

/// The temp file's bytes and metadata have reached the device (`sync_all`,
/// not `sync_data`: a new inode's size and block map are metadata, which
/// `fdatasync` may omit).
#[cfg(unix)]
pub struct Synced {
    path: PathBuf,
}

/// The temp has been renamed over the target; the directory entry may still
/// be in an uncommitted journal transaction until `fsync_dir`.
#[cfg(unix)]
pub struct Renamed {
    _private: (),
}

/// The commit primitives. The order is fixed by the token types and by
/// `Keystore::commit`.
#[cfg(unix)]
pub trait Medium: sealed::Sealed {
    /// Writes `image` to a new temp file in `dir`, replacing any leftover.
    fn write_temp(&mut self, dir: &Directory, image: &[u8]) -> Result<Written>;
    /// Flushes the temp file's data and metadata to the device.
    fn fsync_file(&mut self, written: Written) -> Result<Synced>;
    /// Renames the temp file over the snapshot.
    fn rename(&mut self, synced: Synced, dir: &Directory) -> Result<Renamed>;
    /// Flushes `dir` so the rename is durable.
    fn fsync_dir(&mut self, renamed: Renamed, dir: &Directory) -> Result<()>;
    /// Flushes the directory holding `dir`, where `dir`'s own entry lives.
    /// Not a commit step.
    fn fsync_parent(&mut self, dir: &Directory) -> Result<()>;
    /// Flushes the snapshot `open` read, through `snapshot`, and then `dir`,
    /// so the snapshot and its entry are on the device before a handle
    /// exists. Not a commit step.
    fn flush_standing(&mut self, dir: &Directory, snapshot: &File) -> Result<()>;
}

/// A slot has been written in full at its new length (not yet flushed).
#[cfg(windows)]
pub struct SlotWritten {
    file: File,
    path: PathBuf,
}

/// The slot just written is on the device, data and metadata
/// (`FlushFileBuffers`, which writes both and then flushes the device's own
/// cache).
#[cfg(windows)]
pub struct Flushed {
    _private: (),
}

/// The Windows slot primitives. The order is fixed by the token types and by
/// `Keystore::open_with` and `Keystore::commit`.
///
/// A slot is identified by its number, 0 or 1, and passed as the handle the
/// keystore holds for it: `None` when no file exists yet, in which case
/// `write_slot` creates the file and stores its handle there.
#[cfg(windows)]
pub trait Medium: sealed::Sealed {
    /// Flushes slot `slot` as it currently stands.
    fn flush_standing(&mut self, dir: &Path, slot: usize, held: &File) -> Result<()>;
    /// Overwrites slot `slot` with `frame`, creating the file if `held` is
    /// `None`.
    fn write_slot(&mut self, dir: &Path, slot: usize, held: &mut Option<File>, frame: &[u8]) -> Result<SlotWritten>;
    /// Flushes the slot just written, data and metadata.
    fn flush_slot(&mut self, written: SlotWritten) -> Result<Flushed>;
    /// Counterpart of the Unix `fsync_parent`; flushes nothing, since Win32
    /// documents no call for it. Not a commit step.
    fn fsync_parent(&mut self, dir: &Path) -> Result<()>;
}

fn io(op: &'static str) -> impl Fn(std::io::Error) -> Error {
    move |e| Error::Io { op, kind: e.kind() }
}

/// The directory holding `dir`: its parent, `.` for a bare relative name, and
/// `dir` itself for a root.
///
/// `Path::parent` returns `Some("")` for `wallet` and `wallet/`, and the
/// empty path cannot be opened, so it is mapped to `.`.
pub(crate) fn parent_of(dir: &Path) -> &Path {
    match dir.parent() {
        Some(p) if p.as_os_str().is_empty() => Path::new("."),
        Some(p) => p,
        None => dir,
    }
}

/// The real filesystem.
pub struct Disk;

impl sealed::Sealed for Disk {}

#[cfg(unix)]
impl Medium for Disk {
    fn write_temp(&mut self, dir: &Directory, image: &[u8]) -> Result<Written> {
        let path = dir.path().join(TEMP_NAME);
        // Unlink any leftover temp, then create it new. The unlink stops a
        // temp left by a crash from blocking commits. Creating rather than
        // truncating ensures the file gets `perms::FILE_MODE` (0600): a mode
        // passed to `open` applies only on creation, and a truncated leftover
        // would carry its own permissions through the rename. The temp holds
        // a plaintext header (KDF parameters, salt, nonce) over an encrypted
        // body.
        dir.remove_temp(TEMP_NAME).map_err(io("write_temp unlink stale temp"))?;
        let mut file = dir.create_temp(TEMP_NAME).map_err(io("write_temp open"))?;
        file.write_all(image).map_err(io("write_temp write"))?;
        Ok(Written { file, path })
    }

    fn fsync_file(&mut self, written: Written) -> Result<Synced> {
        written.file.sync_all().map_err(io("fsync_file"))?;
        Ok(Synced { path: written.path })
    }

    fn rename(&mut self, synced: Synced, dir: &Directory) -> Result<Renamed> {
        let _ = synced;
        dir.replace(TEMP_NAME, SNAPSHOT_NAME).map_err(io("rename"))?;
        Ok(Renamed { _private: () })
    }

    fn fsync_dir(&mut self, _renamed: Renamed, dir: &Directory) -> Result<()> {
        // `File::sync_all` on the held directory descriptor. On Apple targets
        // this is fcntl(F_FULLFSYNC), which succeeds on a directory on APFS.
        dir.sync_all().map_err(io("fsync_dir"))
    }

    fn fsync_parent(&mut self, dir: &Directory) -> Result<()> {
        // As `fsync_dir`, one directory up.
        dir.sync_parent().map_err(io("fsync_parent"))
    }

    fn flush_standing(&mut self, dir: &Directory, snapshot: &File) -> Result<()> {
        snapshot.sync_all().map_err(io("flush_standing"))?;
        dir.sync_all().map_err(io("flush_standing"))
    }
}

/// The slot layout's steps, over the files themselves.
///
/// `write_slot` writes the frame from offset 0 and then sets the file's
/// length to the frame's, so a slot is intact only when both the bytes and the
/// length are the new ones; `super::slots` reads a slot of any other length as
/// torn. A slot that does not exist yet is created under the protected list
/// `perms` gives every store file, sharing read access only, like the handles
/// `open` holds.
#[cfg(windows)]
impl Medium for Disk {
    fn flush_standing(&mut self, _dir: &Path, _slot: usize, held: &File) -> Result<()> {
        held.sync_all().map_err(io("flush_standing"))
    }

    fn write_slot(&mut self, dir: &Path, slot: usize, held: &mut Option<File>, frame: &[u8]) -> Result<SlotWritten> {
        let path = slot_path(dir, slot);
        let file = match held {
            Some(file) => file,
            None => held.insert(perms::create_slot(&path).map_err(io("write_slot create"))?),
        };
        overwrite(file, frame).map_err(io("write_slot"))?;
        let file = file.try_clone().map_err(io("write_slot"))?;
        Ok(SlotWritten { file, path })
    }

    fn flush_slot(&mut self, written: SlotWritten) -> Result<Flushed> {
        written.file.sync_all().map_err(io("flush_slot"))?;
        Ok(Flushed { _private: () })
    }

    fn fsync_parent(&mut self, _dir: &Path) -> Result<()> {
        // Nothing to call: Win32 documents no flush an unprivileged process
        // can make that commits a directory's entry in its parent. See the
        // module doc.
        Ok(())
    }
}

/// Slot `slot`'s file in `dir`: 0 is the snapshot's own name.
#[cfg(windows)]
fn slot_path(dir: &Path, slot: usize) -> PathBuf {
    dir.join(if slot == 0 { SNAPSHOT_NAME } else { SLOT1_NAME })
}

/// `bytes` from offset 0, and then the length set to theirs.
#[cfg(windows)]
fn overwrite(file: &mut File, bytes: &[u8]) -> std::io::Result<()> {
    file.seek(SeekFrom::Start(0))?;
    file.write_all(bytes)?;
    file.set_len(bytes.len() as u64)
}

/// One recorded primitive call, with the arguments that matter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Call {
    /// The temp file written and its length.
    #[cfg(unix)]
    WriteTemp { path: PathBuf, len: usize },
    /// The file flushed.
    #[cfg(unix)]
    FsyncFile { path: PathBuf },
    /// The rename's source and target.
    #[cfg(unix)]
    Rename { from: PathBuf, to: PathBuf },
    /// The store directory flushed.
    #[cfg(unix)]
    FsyncDir { dir: PathBuf },
    /// The file `open` took the store from, flushed as it stood: the
    /// snapshot on Unix (with the store directory after it), the newest slot
    /// on Windows.
    FlushStanding { path: PathBuf },
    /// The slot file written and the frame's length.
    #[cfg(windows)]
    WriteSlot { path: PathBuf, len: usize },
    /// The slot file flushed after a write.
    #[cfg(windows)]
    FlushSlot { path: PathBuf },
    /// The store directory's parent passed to `fsync_parent`: flushed on
    /// Unix, recorded without a flush on Windows.
    FsyncParent { dir: PathBuf },
}

/// Computes what a torn `write_slot` leaves. Given the slot's previous
/// contents (`None` if the write was creating it) and the requested frame, it
/// returns the bytes the slot holds afterwards, or `None` for no file.
#[cfg(windows)]
pub type Tear = Box<dyn FnMut(Option<&[u8]>, &[u8]) -> Option<Vec<u8>>>;

/// A medium wrapper that records every call and can inject a failure (and,
/// on Windows, a torn slot write).
pub struct Instrumented<M: Medium> {
    inner: M,
    calls: Vec<Call>,
    /// `(k, calls.len() when armed)`: the failure fires on the k-th call
    /// after arming, so calls recorded earlier do not shift it.
    stop_after: Option<(usize, usize)>,
    /// `(k, calls.len() when armed, what the slot is left holding)`, counted
    /// as `stop_after` counts.
    #[cfg(windows)]
    tear: Option<(usize, usize, Tear)>,
}

impl<M: Medium> Instrumented<M> {
    /// Wraps `inner` with an empty call log and no failure armed.
    pub fn new(inner: M) -> Self {
        Instrumented {
            inner,
            calls: Vec::new(),
            stop_after: None,
            #[cfg(windows)]
            tear: None,
        }
    }

    /// After the `k`-th call (1-based, counted from this arming) performs its
    /// primitive, return an error instead of its result. `None` disarms.
    pub fn stop_after(&mut self, k: Option<usize>) {
        self.stop_after = k.map(|k| (k, self.calls.len()));
    }

    /// Tears the `k`-th call (1-based, counted from this arming), which must
    /// be a `write_slot`: after the write, the slot is left holding what
    /// `tear` returns, and an error is returned instead of the result. `None`
    /// disarms.
    #[cfg(windows)]
    pub fn tear_after(&mut self, k: Option<usize>, tear: Tear) {
        self.tear = k.map(|k| (k, self.calls.len(), tear));
    }

    /// The calls recorded so far.
    pub fn calls(&self) -> &[Call] {
        &self.calls
    }

    /// Clears the call log.
    pub fn reset_calls(&mut self) {
        self.calls.clear();
    }

    fn interrupt_here(&self, op: &'static str) -> Result<()> {
        match self.stop_after {
            Some((k, armed_at)) if self.calls.len() == armed_at + k => Err(Error::Io {
                op,
                kind: std::io::ErrorKind::Interrupted,
            }),
            _ => Ok(()),
        }
    }
}

impl<M: Medium> sealed::Sealed for Instrumented<M> {}

#[cfg(unix)]
impl<M: Medium> Medium for Instrumented<M> {
    fn write_temp(&mut self, dir: &Directory, image: &[u8]) -> Result<Written> {
        self.calls.push(Call::WriteTemp {
            path: dir.path().join(TEMP_NAME),
            len: image.len(),
        });
        let out = self.inner.write_temp(dir, image)?;
        self.interrupt_here("write_temp")?;
        Ok(out)
    }

    fn fsync_file(&mut self, written: Written) -> Result<Synced> {
        self.calls.push(Call::FsyncFile {
            path: written.path.clone(),
        });
        let out = self.inner.fsync_file(written)?;
        self.interrupt_here("fsync_file")?;
        Ok(out)
    }

    fn rename(&mut self, synced: Synced, dir: &Directory) -> Result<Renamed> {
        self.calls.push(Call::Rename {
            from: synced.path.clone(),
            to: dir.path().join(SNAPSHOT_NAME),
        });
        let out = self.inner.rename(synced, dir)?;
        self.interrupt_here("rename")?;
        Ok(out)
    }

    fn fsync_dir(&mut self, renamed: Renamed, dir: &Directory) -> Result<()> {
        self.calls.push(Call::FsyncDir {
            dir: dir.path().to_path_buf(),
        });
        self.inner.fsync_dir(renamed, dir)?;
        self.interrupt_here("fsync_dir")
    }

    fn fsync_parent(&mut self, dir: &Directory) -> Result<()> {
        self.calls.push(Call::FsyncParent {
            dir: dir.parent_path().to_path_buf(),
        });
        self.inner.fsync_parent(dir)?;
        self.interrupt_here("fsync_parent")
    }

    fn flush_standing(&mut self, dir: &Directory, snapshot: &File) -> Result<()> {
        self.calls.push(Call::FlushStanding {
            path: dir.path().join(SNAPSHOT_NAME),
        });
        self.inner.flush_standing(dir, snapshot)?;
        self.interrupt_here("flush_standing")
    }
}

#[cfg(windows)]
impl<M: Medium> Medium for Instrumented<M> {
    fn flush_standing(&mut self, dir: &Path, slot: usize, held: &File) -> Result<()> {
        self.calls.push(Call::FlushStanding {
            path: slot_path(dir, slot),
        });
        self.inner.flush_standing(dir, slot, held)?;
        self.interrupt_here("flush_standing")
    }

    fn write_slot(&mut self, dir: &Path, slot: usize, held: &mut Option<File>, frame: &[u8]) -> Result<SlotWritten> {
        let path = slot_path(dir, slot);
        self.calls.push(Call::WriteSlot {
            path: path.clone(),
            len: frame.len(),
        });
        let calls = self.calls.len();
        let tear = match &mut self.tear {
            Some((k, armed_at, tear)) if calls == *armed_at + *k => Some(tear),
            _ => None,
        };
        let Some(tear) = tear else {
            let out = self.inner.write_slot(dir, slot, held, frame)?;
            self.interrupt_here("write_slot")?;
            return Ok(out);
        };
        let stood = match held.as_mut() {
            Some(file) => Some(read_all(file).map_err(io("write_slot tear"))?),
            None => None,
        };
        drop(self.inner.write_slot(dir, slot, held, frame)?);
        match tear(stood.as_deref(), frame) {
            Some(bytes) => {
                if let Some(file) = held.as_mut() {
                    overwrite(file, &bytes).map_err(io("write_slot tear"))?;
                }
            }
            None => {
                *held = None;
                fs::remove_file(&path).map_err(io("write_slot tear"))?;
            }
        }
        Err(Error::Io {
            op: "write_slot",
            kind: std::io::ErrorKind::Interrupted,
        })
    }

    fn flush_slot(&mut self, written: SlotWritten) -> Result<Flushed> {
        self.calls.push(Call::FlushSlot {
            path: written.path.clone(),
        });
        let out = self.inner.flush_slot(written)?;
        self.interrupt_here("flush_slot")?;
        Ok(out)
    }

    fn fsync_parent(&mut self, dir: &Path) -> Result<()> {
        self.calls.push(Call::FsyncParent {
            dir: parent_of(dir).to_path_buf(),
        });
        self.inner.fsync_parent(dir)?;
        self.interrupt_here("fsync_parent")
    }
}

/// Every byte of a slot file, from offset 0.
#[cfg(windows)]
fn read_all(file: &mut File) -> std::io::Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::parent_of;
    use std::path::Path;

    /// The directory `create` flushes, for each form of `--dir`. A bare name,
    /// with or without a trailing slash, maps to `.`.
    #[test]
    fn parent_of_names_the_directory_holding_the_store_in_every_shape() {
        assert_eq!(parent_of(Path::new("wallet")), Path::new("."));
        assert_eq!(parent_of(Path::new("wallet/")), Path::new("."));
        assert_eq!(parent_of(Path::new("./wallet")), Path::new("."));
        assert_eq!(parent_of(Path::new("stores/wallet")), Path::new("stores"));
        assert_eq!(parent_of(Path::new("/home/op/wallet")), Path::new("/home/op"));
        assert_eq!(parent_of(Path::new("/")), Path::new("/"));
    }
}
