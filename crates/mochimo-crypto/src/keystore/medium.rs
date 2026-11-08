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
//! `Medium::flush_standing` flushes the snapshot `open` read and then the
//! store directory, before `open` returns a handle. A commit that renamed
//! its temp and then failed or was killed before `fsync_dir` leaves a
//! snapshot whose entry may exist only in the cache; `resign` signs the
//! reservation it finds without committing, so that entry must be on the
//! device before anything is signed from it. Like `fsync_parent`, it is not
//! a commit step and takes no token.
//!
//! # Typestate
//!
//! Each step returns a token the next consumes: `write_temp -> Written`,
//! `fsync_file(Written) -> Synced`, `rename(Synced) -> Renamed`,
//! `fsync_dir(Renamed)`. Reordering is a type error
//! (`ui/fail/medium_steps_are_not_reorderable.rs`), and the tokens have
//! private fields so they cannot be forged outside the crate.
//!
//! # Instrumented medium
//!
//! [`Instrumented`] records every call with its arguments and can be told to
//! fail after call `k`: it performs the primitive and then returns an error,
//! modelling a process killed after the syscall completed. It does not model
//! power loss (a dropped page cache, a truncated journal, or an `fsync` that
//! lies). Recording arguments catches an fsync on the wrong path, which
//! counts and byte comparisons alone would miss.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use super::Directory;
use crate::error::{Error, Result};

pub(crate) const SNAPSHOT_NAME: &str = "accounts.mks";
pub(crate) const TEMP_NAME: &str = "accounts.mks.tmp";

mod sealed {
    pub trait Sealed {}
}

/// The temp file has been written in full (not yet flushed).
pub struct Written {
    file: File,
    path: PathBuf,
}

/// The temp file's bytes and metadata have reached the device (`sync_all`,
/// not `sync_data`: a new inode's size and block map are metadata, which
/// `fdatasync` may omit).
pub struct Synced {
    path: PathBuf,
}

/// The temp has been renamed over the target; the directory entry may still
/// be in an uncommitted journal transaction until `fsync_dir`.
pub struct Renamed {
    _private: (),
}

/// The commit primitives. The order is fixed by the token types and by
/// `Keystore::commit`.
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

/// One recorded primitive call, with the arguments that matter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Call {
    /// The temp file written and its length.
    WriteTemp { path: PathBuf, len: usize },
    /// The file flushed.
    FsyncFile { path: PathBuf },
    /// The rename's source and target.
    Rename { from: PathBuf, to: PathBuf },
    /// The store directory flushed.
    FsyncDir { dir: PathBuf },
    /// The snapshot `open` took the store from, flushed as it stood, with
    /// the store directory after it.
    FlushStanding { path: PathBuf },
    /// The directory flushed, which is the store directory's parent.
    FsyncParent { dir: PathBuf },
}

/// A medium wrapper that records every call and can inject a failure.
pub struct Instrumented<M: Medium> {
    inner: M,
    calls: Vec<Call>,
    /// `(k, calls.len() when armed)`: the failure fires on the k-th call
    /// after arming, so calls recorded earlier do not shift it.
    stop_after: Option<(usize, usize)>,
}

impl<M: Medium> Instrumented<M> {
    /// Wraps `inner` with an empty call log and no failure armed.
    pub fn new(inner: M) -> Self {
        Instrumented {
            inner,
            calls: Vec::new(),
            stop_after: None,
        }
    }

    /// After the `k`-th call (1-based, counted from this arming) performs its
    /// primitive, return an error instead of its result. `None` disarms.
    pub fn stop_after(&mut self, k: Option<usize>) {
        self.stop_after = k.map(|k| (k, self.calls.len()));
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
