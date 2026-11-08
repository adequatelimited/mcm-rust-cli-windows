// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! The Unix permission model.
//!
//! Every mode bit this crate sets or reads is defined here: `0600` for the
//! lock file and temp snapshot, `0700` for a store directory this crate
//! creates, the group- and other-writable bits that cause a directory to be
//! refused, the group and other read and write bits that cause a store file
//! to be refused, and the required owner of both. [`super::Directory`] opens
//! every file and directory the store uses with these constants.
//!
//! This is not a portability layer: a non-Unix build fails at `lib.rs`'s
//! and [`crate::keystore`]'s `compile_error!`.
//!
//! The rule is that the directory and files are reachable only by their
//! owner: a directory owned or writable by another local user is refused, as
//! is a store file another local user owns or can read or write. The file
//! check is needed as well as the directory check: the store directory need
//! only refuse others write, so it can be `0755`, and a file restored from a
//! copy that kept no modes can be `0644`. Such a snapshot lets every local
//! user try passwords against the ciphertext offline.
//!
//! [`Error::UnsafePermissions`] carries the offending Unix `mode: u32`,
//! displayed in octal, so callers matching on it see mode bits.

use std::fs::File;
use std::os::unix::fs::MetadataExt;

use crate::error::{Error, Result};

/// The mode for every file this crate creates: owner read and write only.
///
/// The temp snapshot holds a plaintext header over a sealed body and the
/// lock file holds no bytes; neither is key material, but neither should be
/// readable by other users.
pub(crate) const FILE_MODE: rustix::fs::Mode = rustix::fs::Mode::from_bits_retain(0o600);

/// The mode for a store directory this crate creates: owner only.
///
/// An existing directory keeps its mode and is checked by
/// [`refuse_unsafe_dir`] instead.
pub(crate) const DIR_MODE: rustix::fs::Mode = rustix::fs::Mode::from_bits_retain(0o700);

/// Bits that cause a lock or snapshot file to be refused: group read and
/// write (`0o060`) and other read and write (`0o006`).
#[cfg(unix)]
const REFUSED_FILE_BITS: u32 = 0o066;

/// Bits that cause the store directory to be refused: group-write (`0o020`)
/// and other-write (`0o002`).
///
/// Only write bits are refused. A writable directory lets another local user
/// rename the snapshot under a live handle, which breaks commit atomicity; a
/// readable one only discloses file names.
const REFUSED_WRITE_BITS: u32 = 0o022;

/// Refuse a store directory another local user could write to.
///
/// Called by [`crate::keystore::Keystore::create_with`] and
/// [`crate::keystore::Keystore::open_with`], through [`super::Directory`],
/// before the lock is taken. It checks the opened directory handle, not a
/// path, so the checked directory is the one later operations use.
///
/// # Errors
///
/// - [`Error::Io`] with `NotADirectory` if the handle is not a directory.
/// - [`Error::Io`] with `PermissionDenied` if the directory is not owned by
///   the effective user. The owner is checked first because another owner
///   could change the mode at any time.
/// - [`Error::UnsafePermissions`] if group- or other-write is set.
pub(crate) fn refuse_unsafe_dir(dir: &File) -> Result<()> {
    let meta = dir.metadata().map_err(|e| Error::Io { op: "stat directory", kind: e.kind() })?;
    if !meta.is_dir() {
        return Err(Error::Io { op: "stat directory", kind: std::io::ErrorKind::NotADirectory });
    }
    if meta.uid() != rustix::process::geteuid().as_raw() {
        return Err(Error::Io { op: "directory owner", kind: std::io::ErrorKind::PermissionDenied });
    }
    let mode = meta.mode() & 0o777;
    if mode & REFUSED_WRITE_BITS != 0 {
        return Err(Error::UnsafePermissions { mode });
    }
    Ok(())
}

/// Refuse a lock or snapshot file another local user owns or could read or
/// write.
///
/// Called by [`crate::keystore::Keystore::open_with`] on the snapshot, and
/// on the lock file whenever the lock is taken. It checks the opened handle,
/// so the file checked is the one then read or locked.
///
/// # Errors
///
/// - [`Error::Io`] with `PermissionDenied` if the file is not owned by the
///   effective user.
/// - [`Error::UnsafeFileMode`] if group or others may read or write it.
#[cfg(unix)]
pub(crate) fn refuse_unsafe_file(file: &File, name: &'static str) -> Result<()> {
    let meta = file.metadata().map_err(|e| Error::Io {
        op: "stat a store file",
        kind: e.kind(),
    })?;
    if meta.uid() != rustix::process::geteuid().as_raw() {
        return Err(Error::Io {
            op: "store file owner",
            kind: std::io::ErrorKind::PermissionDenied,
        });
    }
    let mode = meta.mode() & 0o777;
    if mode & REFUSED_FILE_BITS != 0 {
        return Err(Error::UnsafeFileMode { file: name, mode });
    }
    Ok(())
}
