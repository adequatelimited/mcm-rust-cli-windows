// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! The Windows permission model: the Windows arm of [`super`]. This file and
//! the binary's console module are the only files under `src/` that contain
//! `unsafe`.
//!
//! # The Unix standards, expressed as access-control lists
//!
//! The Unix arm creates directories at `0700` and files at `0600`, refuses a
//! directory that another local user owns or can write to, and refuses a store
//! file that another local user owns or can read or write. This arm enforces
//! the same standards with Windows access lists.
//!
//! | Unix arm | this arm |
//! | --- | --- |
//! | directory created `0700` | directory created with a protected access list granting this user full control and nobody else anything, inherited by what is created inside it |
//! | file created `0600` | file created with a protected access list granting this user full control and nobody else anything |
//! | refuse group- or other-write, and a directory owned by another user | refuse an access list that lets anyone but this user, `SYSTEM` or the Administrators group write, and refuse a directory owned by anyone else |
//! | refuse a snapshot or lock that group or others may read or write, or which another user owns, because a directory check that refuses only write bits leaves a readable file readable | refuse a slot file or the lock whose own list lets anyone but those three read or write it, or which anyone else owns, because a file's own list decides who reaches it |
//!
//! **The descriptor is passed to `CreateFileW` and `CreateDirectoryW`, not set
//! afterwards.** Access is checked when a handle is opened, so a file created
//! with an inherited access list and restricted a moment later can already be
//! open for writing in another user's process, and that handle keeps its
//! rights after the list changes. The Unix arm passes the mode to `open` for
//! the same reason. `std`'s `OpenOptions` takes no security descriptor on
//! Windows, so this file calls `CreateFileW` directly.
//!
//! **The descriptor is protected, so nothing is inherited.** A descriptor
//! without the protected flag merges the parent's inheritable entries into the
//! given list, and a parent can carry an entry that applies to children only
//! (for example, `Authenticated Users` with modify rights on everything
//! created under `C:\`). The file's list would then differ from the given one.
//!
//! # Accepted trustees
//!
//! This user, because the store belongs to them. `SYSTEM` and the
//! Administrators group, because they correspond to `root` on the Unix arm:
//! the mode check does not consider `root`, since no permission bit binds it,
//! and on Windows the Administrators group can take ownership of any object
//! regardless of its list. Refusing a directory because an administrator could
//! write to it would refuse every home directory on the platform without
//! protecting against anyone who could not take the file anyway. `OWNER
//! RIGHTS` (`S-1-3-4`) is accepted because it names the owner, and the owner
//! is checked separately.
//!
//! The strings are Windows' well-known security identifiers in the form
//! `ConvertSidToStringSidW` produces, and are compared as strings with that
//! function's output for each entry. They are written as literals because they
//! are fixed by the documented Windows interface, not by this protocol.
//!
//! **The owner counts as a writer.** An object's owner may rewrite its access
//! list regardless of what the list says, so another user who owns the
//! directory can grant themselves any access. Such a directory is refused as a
//! grant of `WRITE_DAC` to that user, the right an owner holds implicitly.
//!
//! # Rights that count as write
//!
//! The rights that change what the directory contains or who may change it:
//! adding a file or a subdirectory, deleting a child, deleting or renaming the
//! directory itself, rewriting its list or its owner, and the two generic
//! rights that map onto those. **Write, not read**, as on the Unix arm: a
//! co-user who can list the directory learns only that a store exists, which
//! is metadata, while a co-user who can delete a child can move the snapshot
//! out from under a live handle, which breaks the commit's atomicity.
//! `FILE_WRITE_ATTRIBUTES` and `FILE_WRITE_EA` are excluded: they change the
//! directory's own attributes, not its contents.
//!
//! Entries that apply only to children are skipped. On a directory, a child's
//! access is decided by the child's own list, which [`refuse_unsafe_file`]
//! reads for every store file; on a file, an entry for children applies to
//! nothing. Denying entries are also skipped, which makes the check stricter
//! than the effective access it approximates: a denial followed by a grant of
//! the same right is refused here, although Windows reads the list in order,
//! meets the denial first and never honours that grant. That errs on the
//! fail-closed side; computing effective access exactly would require
//! `AuthzAccessCheck` and a resource manager, for a case no default access
//! list produces. An entry of a type this check does not read is refused
//! rather than skipped, for the same reason.
//!
//! **A missing access list is a refusal.** A null DACL grants every right to
//! everyone, and it is what a volume without access control reports (FAT and
//! exFAT, typically removable media). It is refused as a grant to Everyone.
//!
//! # Why the `unsafe` is here
//!
//! `std` has no interface for any of this: it neither reads a security
//! descriptor nor creates a file under one. Every call below is a plain Win32
//! function through `windows-sys`, and every `unsafe` block states the
//! condition it relies on. The test `unsafe_is_confined_to_declared_files`
//! names this file as one of the library's only `unsafe` locations. Miri cannot
//! interpret foreign calls and does not reach this file: on a Unix host the
//! file is not compiled, and for the Windows target every test that reaches it
//! performs file I/O, which Miri's isolation refuses.
//!
//! # Test coverage
//!
//! On Windows, every store the tests open is checked by this file, the
//! keystore creates its lock through it, and the slot layout creates and opens
//! every store file through `create_slot` and `open_slot`. Five tests in
//! `tests/keystore.rs` target this file:
//! `windows_store_junctions_and_entry_links_are_refused`, which checks the
//! link refusals of [`refuse_unsafe_dir`], `open_slot` and
//! `open_private_lock`,
//! `open_refuses_a_directory_everyone_can_write_to`,
//! `a_store_created_under_a_writable_parent_inherits_nothing_from_it`,
//! `a_slot_held_open_without_write_sharing_refuses_the_open_by_name`, which
//! checks the refusal `open_slot` makes, and
//! `open_refuses_a_store_file_another_user_can_read_or_write`, which checks
//! [`refuse_unsafe_file`]: Everyone granted read, then write, on either slot or
//! the lock is refused, naming that file.
//!
//! **Not covered by tests:** when run as an elevated administrator, a created
//! directory is owned by the Administrators group, so the owner check is not
//! exercised against the user's own SID, which is the owner an unelevated
//! session gives a directory. A null list, an entry type the check refuses as
//! unread, and a denying entry are also not exercised. The behaviour in those
//! cases follows Microsoft's documentation and `std`'s source.

use std::ffi::c_void;
use std::fs::{self, File};
use std::io;
use std::marker::PhantomData;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr;

use windows_sys::Win32::Foundation::{
    LocalFree, ERROR_SHARING_VIOLATION, ERROR_SUCCESS, GENERIC_ALL, GENERIC_READ, GENERIC_WRITE, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
    GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetAce, GetTokenInformation, TokenUser, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION,
    INHERIT_ONLY_ACE, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, CREATE_NEW, DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY,
    FILE_APPEND_DATA, FILE_ATTRIBUTE_NORMAL, FILE_DELETE_CHILD, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_READ_DATA, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_DATA, OPEN_ALWAYS,
    READ_CONTROL, WRITE_DAC, WRITE_OWNER,
};
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE, ACCESS_DENIED_ACE_TYPE,
    ACCESS_DENIED_CALLBACK_ACE_TYPE, ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_DENIED_OBJECT_ACE_TYPE,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::error::{Error, Result};

/// `NT AUTHORITY\SYSTEM`.
const SYSTEM: &str = "S-1-5-18";
/// `BUILTIN\Administrators`.
const ADMINISTRATORS: &str = "S-1-5-32-544";
/// `OWNER RIGHTS`: whoever owns the object, which is checked separately.
const OWNER_RIGHTS: &str = "S-1-3-4";
/// `Everyone`, named in a refusal when the directory has no access list.
const EVERYONE: &str = "S-1-1-0";

/// The rights whose grant to anyone else is a refusal. See the module doc.
const WRITE_RIGHTS: u32 = FILE_ADD_FILE
    | FILE_ADD_SUBDIRECTORY
    | FILE_DELETE_CHILD
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | GENERIC_WRITE
    | GENERIC_ALL;

/// The rights on a store file whose grant to anyone else is a refusal:
/// reading its data, and the rights [`WRITE_RIGHTS`] names as a file has
/// them -- writing and appending where the directory adds a file or a
/// subdirectory, and no counterpart to deleting a child. See
/// [`refuse_unsafe_file`] for why reading counts here and not there.
const FILE_RIGHTS: u32 = FILE_READ_DATA
    | FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | GENERIC_READ
    | GENERIC_WRITE
    | GENERIC_ALL;

/// The share mode `std`'s `OpenOptions` opens with by default, so the lock
/// file is shared exactly as one created through `std` would be.
const STD_SHARE_MODE: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

/// The share mode a slot file is held with: read, and nothing else. While a
/// handle holds its slots no other process can write, rename or delete one --
/// the way a flushed write could stop being the file the next `open` reads --
/// and a reader, a scanner or a backup that only reads, still can.
const SLOT_SHARE_MODE: u32 = FILE_SHARE_READ;

/// Refuse a store directory another local user could write to, or that is
/// a symbolic link or a junction.
///
/// The Windows arm of the function by this name in [`super`]; the stat and
/// the not-a-directory refusal are that arm's, under the same `op`, so the
/// two platforms refuse a non-directory identically.
///
/// The last path component is read without following it, as the Unix arm
/// opens it, and a symbolic link or junction there is refused with
/// [`Error::StoreDirectoryIsLink`]: followed, it could point the wallet at
/// any directory this user owns, such as an older copy of the store, and
/// every check below would pass it. Trailing separators and `.` components
/// are dropped first so the check is made on the store's own name.
pub(crate) fn refuse_unsafe_dir(dir: &Path) -> Result<()> {
    let normalized: PathBuf = dir.components().collect();
    let meta = fs::symlink_metadata(&normalized).map_err(|e| Error::Io {
        op: "stat directory",
        kind: e.kind(),
    })?;
    if meta.file_type().is_symlink() {
        return Err(Error::StoreDirectoryIsLink);
    }
    if !meta.is_dir() {
        return Err(Error::Io {
            op: "stat directory",
            kind: io::ErrorKind::NotADirectory,
        });
    }
    let user = current_user().map_err(|e| Error::Io {
        op: "read the process token",
        kind: e.kind(),
    })?;
    let security = Security::of(dir).map_err(|e| Error::Io {
        op: "read the directory's access list",
        kind: e.kind(),
    })?;
    // The list before the owner. A volume with no access control -- FAT and
    // exFAT -- reports a null list and may report no owner, and the refusal
    // an operator can act on is "anyone can write here", not a failure to
    // read an owner that volume does not keep.
    match security.foreign_grant(&user, WRITE_RIGHTS) {
        Ok(None) => {}
        Ok(Some((trustee, rights))) => return Err(Error::UnsafeAcl { trustee, rights }),
        Err(e) => {
            return Err(Error::Io {
                op: "read the directory's access list",
                kind: e.kind(),
            })
        }
    }
    let owner = sid_string(security.owner).map_err(|e| Error::Io {
        op: "read the directory's owner",
        kind: e.kind(),
    })?;
    if !accepted(&owner, &user) {
        return Err(Error::UnsafeAcl {
            trustee: owner,
            rights: WRITE_DAC | READ_CONTROL,
        });
    }
    Ok(())
}

/// Refuse a store file another local user could read or write: a slot, or
/// the lock.
///
/// **The directory's list does not reach its files.** Windows decides who
/// may open a file by the file's own list: Microsoft's *File Security and
/// Access Rights* page says that "the security descriptor of a parent
/// directory is not used to control access to any child file or
/// directory", and the right that would make the directory matter,
/// `FILE_TRAVERSE`, is enforced only once the bypass-traverse privilege is
/// taken from users, which the same page advises against. So a store
/// directory this user alone can open can still hold a file anyone may
/// read. This module never makes one, but a file moved in from elsewhere
/// on the same volume keeps the list it had, and the slot layout rewrites
/// its files in place, so nothing ever replaces that list. The Unix arm
/// makes the same check on the file's mode and owner.
///
/// **Reading counts here, and not on the directory.** A slot file is the
/// ciphertext, and a co-user who can read it can try passwords against it
/// offline; the lock holds nothing, but a co-user who can open it can hold
/// the lock. So the rights refused are [`FILE_RIGHTS`]. The owner is
/// refused as on the directory, since an owner may rewrite the list.
///
/// **Through the handle the keystore holds**, with `GetSecurityInfo`, not by
/// path: the list checked is the one of the file then read and written,
/// and nothing at the path can put another file's list in front of it.
pub(crate) fn refuse_unsafe_file(file: &File, name: &'static str) -> Result<()> {
    let user = current_user().map_err(|e| Error::Io {
        op: "read the process token",
        kind: e.kind(),
    })?;
    let security = Security::of_file(file).map_err(|e| Error::Io {
        op: "read a store file's access list",
        kind: e.kind(),
    })?;
    match security.foreign_grant(&user, FILE_RIGHTS) {
        Ok(None) => {}
        Ok(Some((trustee, rights))) => {
            return Err(Error::UnsafeFileAcl {
                file: name,
                trustee,
                rights,
            })
        }
        Err(e) => {
            return Err(Error::Io {
                op: "read a store file's access list",
                kind: e.kind(),
            })
        }
    }
    let owner = sid_string(security.owner).map_err(|e| Error::Io {
        op: "read a store file's owner",
        kind: e.kind(),
    })?;
    if !accepted(&owner, &user) {
        return Err(Error::UnsafeFileAcl {
            file: name,
            trustee: owner,
            rights: WRITE_DAC | READ_CONTROL,
        });
    }
    Ok(())
}

/// Create the store directory under a protected list granting this user
/// full control, inherited by every file and directory created inside it.
///
/// What `Directory::open(path, true)` does on Unix, where `mkdirat` creates
/// the directory at `perms::DIR_MODE`. Like the mode on Unix, the list applies
/// only on creation, which is why the caller asks this only when the directory
/// is absent and asks [`refuse_unsafe_dir`] either way.
pub(crate) fn create_private_dir(dir: &Path) -> io::Result<()> {
    let descriptor = Private::descriptor(Inherit::Children)?;
    let attributes = descriptor.attributes();
    let path = wide(dir)?;
    // SAFETY: `path` is a NUL-terminated UTF-16 buffer that outlives the call,
    // and `attributes` borrows `descriptor`, so the descriptor it points at
    // outlives the call too.
    if unsafe { CreateDirectoryW(path.as_ptr(), &attributes.raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Create a slot file under a protected list granting this user full
/// control, failing if it already exists, held for reading and writing and
/// shared for reading alone.
///
/// Where the Unix arm has `Directory::create_temp` for the temp a rename
/// replaces the snapshot with, this arm has the slot files the layout writes
/// in place, and no temp. `CREATE_NEW`, and `FILE_FLAG_OPEN_REPARSE_POINT`
/// because that is what `std` adds for `create_new` -- a link at the path is
/// not followed.
pub(crate) fn create_slot(path: &Path) -> io::Result<File> {
    open_under_private_list(
        path,
        GENERIC_READ | GENERIC_WRITE,
        SLOT_SHARE_MODE,
        CREATE_NEW,
        FILE_FLAG_OPEN_REPARSE_POINT,
    )
}

/// Open a slot file that exists, for reading and writing, shared for reading
/// alone; `None` when there is no such file.
///
/// A slot that is a symbolic link is refused before it is opened, as the
/// Unix arm opens the snapshot without following links. The directory has
/// already been checked to admit no other writer, so nobody else can put a
/// link there between the check and the open.
///
/// A program already holding the file without sharing write -- an antivirus
/// scanner, an indexer, a backup or sync agent -- makes the open fail with
/// `ERROR_SHARING_VIOLATION`, and that is `Error::HeldOpen`, met at `open`,
/// before anything is read or reserved. Every other failure is `Io`. The list
/// the file already has is not changed here; `open` checks it through the
/// handle this returns, with [`refuse_unsafe_file`].
pub(crate) fn open_slot(path: &Path) -> Result<Option<File>> {
    let refused = |e: io::Error| match e.raw_os_error() {
        Some(code) if code == ERROR_SHARING_VIOLATION as i32 => Error::HeldOpen { code },
        _ => Error::Io {
            op: "open slot",
            kind: e.kind(),
        },
    };
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() || !meta.is_file() => {
            return Err(Error::Io {
                op: "open slot",
                kind: io::ErrorKind::InvalidInput,
            })
        }
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(refused(e)),
    }
    match fs::OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(SLOT_SHARE_MODE)
        .open(path)
    {
        Ok(file) => Ok(Some(file)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(refused(e)),
    }
}

/// Open the lock file, creating it under a protected list granting this user
/// full control if absent, and **never** truncating it: what
/// `Directory::open_lock` does on Unix, at `perms::FILE_MODE`.
///
/// `OPEN_ALWAYS` is Win32's create-if-absent without truncation, and the list
/// applies only when it creates -- the Unix arm's mode rule, unchanged.
/// `FILE_FLAG_OPEN_REPARSE_POINT` opens a link at the path itself rather than
/// what it points to, and anything that is not a regular file is refused, as
/// the Unix arm refuses a lock that is a link.
pub(crate) fn open_private_lock(path: &Path) -> io::Result<File> {
    let file = open_under_private_list(
        path,
        GENERIC_READ | GENERIC_WRITE,
        STD_SHARE_MODE,
        OPEN_ALWAYS,
        FILE_FLAG_OPEN_REPARSE_POINT,
    )?;
    let kind = file.metadata()?.file_type();
    if kind.is_symlink() || !kind.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "store entry is not a regular file",
        ));
    }
    Ok(file)
}

fn open_under_private_list(path: &Path, access: u32, share: u32, disposition: u32, flags: u32) -> io::Result<File> {
    let descriptor = Private::descriptor(Inherit::Nothing)?;
    let attributes = descriptor.attributes();
    let path = wide(path)?;
    // SAFETY: `path` is a NUL-terminated UTF-16 buffer that outlives the call,
    // `attributes` borrows the descriptor it points at, which therefore
    // outlives the call too, and the template handle is null, which the
    // function accepts.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            share,
            &attributes.raw,
            disposition,
            FILE_ATTRIBUTE_NORMAL | flags,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `handle` is a valid file handle this call just opened and that
    // nothing else owns, so `OwnedHandle` may close it exactly once.
    Ok(File::from(unsafe { OwnedHandle::from_raw_handle(handle) }))
}

fn accepted(sid: &str, user: &str) -> bool {
    sid == user || sid == SYSTEM || sid == ADMINISTRATORS || sid == OWNER_RIGHTS
}

/// A path as the NUL-terminated UTF-16 a `W` function takes.
///
/// A path containing U+0000 is refused rather than truncated: the function
/// would read up to the first one and act on a different path.
fn wide(path: &Path) -> io::Result<Vec<u16>> {
    let mut out: Vec<u16> = path.as_os_str().encode_wide().collect();
    if out.contains(&0) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    out.push(0);
    Ok(out)
}

/// Memory Win32 allocated and handed over, released with `LocalFree`.
struct Local(*mut c_void);

impl Drop for Local {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: every `Local` is built from a pointer a Win32 function
            // documents as `LocalAlloc`ed and owned by the caller, and this is
            // the only place it is freed.
            unsafe { LocalFree(self.0) };
        }
    }
}

/// A SID in its `S-1-...` string form.
fn sid_string(sid: PSID) -> io::Result<String> {
    if sid.is_null() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut text: *mut u16 = ptr::null_mut();
    // SAFETY: `sid` is non-null and points at a SID inside a buffer the caller
    // keeps alive for this call; `text` receives a `LocalAlloc`ed string.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let owned = Local(text.cast());
    let mut len = 0usize;
    // SAFETY: the function returned a NUL-terminated string at `text`, so
    // every offset up to and including the terminator is in bounds.
    while unsafe { *text.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `len` units starting at `text` were just read one by one.
    let units = unsafe { std::slice::from_raw_parts(text, len) };
    let out = String::from_utf16(units).map_err(|_| io::Error::from(io::ErrorKind::InvalidData));
    drop(owned);
    out
}

/// This process's user, as a SID string.
fn current_user() -> io::Result<String> {
    let mut raw: HANDLE = ptr::null_mut();
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle that needs no
    // closing, and `raw` is a valid place for the token handle.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a token handle this call just opened and owns.
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let handle: HANDLE = std::os::windows::io::AsRawHandle::as_raw_handle(&token);
    let mut len = 0u32;
    // SAFETY: a null buffer of length zero is the documented size query; the
    // call fails and writes the size needed to `len`.
    unsafe { GetTokenInformation(handle, TokenUser, ptr::null_mut(), 0, &mut len) };
    if len == 0 {
        return Err(io::Error::last_os_error());
    }
    // `u64` elements so the `TOKEN_USER` at the front, which holds a pointer,
    // is aligned for it.
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: `buf` holds at least `len` bytes, which is the size the query
    // above asked for.
    if unsafe { GetTokenInformation(handle, TokenUser, buf.as_mut_ptr().cast(), len, &mut len) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the call succeeded, so `buf` begins with a `TOKEN_USER` whose
    // SID pointer points inside `buf`, which outlives this borrow.
    let user = unsafe { &*buf.as_ptr().cast::<TOKEN_USER>() };
    sid_string(user.User.Sid)
}

/// A directory's or a file's owner and access list, and the descriptor that
/// holds both.
struct Security {
    owner: PSID,
    dacl: *const ACL,
    _descriptor: Local,
}

impl Security {
    fn of(dir: &Path) -> io::Result<Security> {
        let path = wide(dir)?;
        let mut owner: PSID = ptr::null_mut();
        let mut dacl: *mut ACL = ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: `path` is NUL-terminated and outlives the call; the group
        // and SACL outputs are null, which the function accepts when their
        // information is not requested; the descriptor it returns is
        // `LocalAlloc`ed and owned here, and `owner` and `dacl` point into it.
        let rc = unsafe {
            GetNamedSecurityInfoW(
                path.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                &mut dacl,
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        // Owned only once the call has succeeded. Microsoft documents the
        // descriptor as what a successful call returns and says nothing of the
        // pointer after a failed one, so a failure leaves it alone: the worst a
        // failed call can cost is a leak, never a free of something that is not
        // an allocation.
        if rc != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        Ok(Security {
            owner,
            dacl,
            _descriptor: Local(descriptor),
        })
    }

    /// The same, for the file an open handle is, read with `GetSecurityInfo`.
    fn of_file(file: &File) -> io::Result<Security> {
        let mut owner: PSID = ptr::null_mut();
        let mut dacl: *mut ACL = ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: the handle is the one `file` owns, open for the whole call,
        // and was opened with `GENERIC_READ`, which includes the
        // `READ_CONTROL` the function needs to read an owner and a list; the
        // group and SACL outputs are null, which the function accepts when
        // their information is not requested; the descriptor it returns is
        // `LocalAlloc`ed and owned here, and `owner` and `dacl` point into it.
        let rc = unsafe {
            GetSecurityInfo(
                std::os::windows::io::AsRawHandle::as_raw_handle(file),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                &mut dacl,
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        // Owned only once the call has succeeded, as in `Security::of`.
        if rc != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        Ok(Security {
            owner,
            dacl,
            _descriptor: Local(descriptor),
        })
    }

    /// The first entry granting any of `rights` to a trustee [`accepted`]
    /// does not name, as that trustee and the rights the entry grants.
    fn foreign_grant(&self, user: &str, rights: u32) -> io::Result<Option<(String, u32)>> {
        if self.dacl.is_null() {
            return Ok(Some((EVERYONE.to_string(), GENERIC_ALL)));
        }
        // SAFETY: a non-null DACL from `GetNamedSecurityInfoW` points at a
        // valid `ACL` inside the descriptor `self` keeps alive.
        let count = unsafe { (*self.dacl).AceCount };
        for index in 0..u32::from(count) {
            let mut ace: *mut c_void = ptr::null_mut();
            // SAFETY: `index` is below the list's own count, and `ace`
            // receives a pointer into the same descriptor.
            if unsafe { GetAce(self.dacl, index, &mut ace) } == 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: every ACE begins with an `ACE_HEADER`.
            let header = unsafe { &*ace.cast::<ACE_HEADER>() };
            if u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0 {
                continue;
            }
            let kind = u32::from(header.AceType);
            if kind == ACCESS_ALLOWED_ACE_TYPE || kind == ACCESS_ALLOWED_CALLBACK_ACE_TYPE {
                // SAFETY: both types lay out `Mask` and then the SID directly
                // after the header, which is `ACCESS_ALLOWED_ACE`'s layout;
                // the callback type's application data follows the SID and
                // is not read.
                let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
                if allowed.Mask & rights == 0 {
                    continue;
                }
                // The SID starts at `SidStart` and runs past the end of the
                // struct, so its pointer is taken from `ace`, which covers the
                // whole entry, and not through `allowed`, a reference to the
                // struct's twelve bytes. The offset is the field's own.
                let sid: PSID = ace.wrapping_byte_add(std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart));
                let trustee = sid_string(sid)?;
                if !accepted(&trustee, user) {
                    return Ok(Some((trustee, allowed.Mask)));
                }
            } else if [
                ACCESS_DENIED_ACE_TYPE,
                ACCESS_DENIED_CALLBACK_ACE_TYPE,
                ACCESS_DENIED_OBJECT_ACE_TYPE,
                ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE,
            ]
            .contains(&kind)
            {
                continue;
            } else {
                return Err(io::ErrorKind::Unsupported.into());
            }
        }
        Ok(None)
    }
}

/// Whether a created directory's list reaches what is created inside it.
enum Inherit {
    Children,
    Nothing,
}

/// A self-relative security descriptor granting this user full control and
/// nobody else anything, protected from inheritance.
struct Private(Local);

impl Private {
    /// Built from SDDL, because the string is the one form of an access list
    /// a reader can check by eye: `D:P` is a protected DACL, `A` an allow
    /// entry, `FA` full file access, `OICI` inherited by files and
    /// directories created inside, and the last field this user's SID.
    fn descriptor(inherit: Inherit) -> io::Result<Private> {
        let user = current_user()?;
        let flags = match inherit {
            Inherit::Children => "OICI",
            Inherit::Nothing => "",
        };
        let sddl: Vec<u16> = format!("D:P(A;{flags};FA;;;{user})")
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: `sddl` is NUL-terminated and outlives the call; the size
        // output is optional and null; `descriptor` receives a `LocalAlloc`ed
        // descriptor this function then owns.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            )
        };
        // Owned only once the call has succeeded, as in `Security::of`.
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Private(Local(descriptor)))
    }

    /// The attributes a create call takes; see [`Attributes`].
    fn attributes(&self) -> Attributes<'_> {
        Attributes {
            raw: SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: self.0 .0,
                bInheritHandle: 0,
            },
            _descriptor: PhantomData,
        }
    }
}

/// The attributes a create call takes, borrowing the descriptor they point
/// into.
///
/// `raw` holds a raw pointer into a [`Private`], which by itself ties it to
/// nothing. The borrow is what does: an `Attributes` cannot outlive the
/// descriptor it came from, so the compiler, and not the order of the lines
/// that use it, keeps the descriptor alive for the call it is passed to.
struct Attributes<'a> {
    raw: SECURITY_ATTRIBUTES,
    _descriptor: PhantomData<&'a Private>,
}
