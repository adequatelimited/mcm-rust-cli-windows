// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

use core::fmt;

pub type Result<T> = core::result::Result<T, Error>;

/// How a Mesh transport failed, without the message.
///
/// The transport's own error can carry hostnames, certificate subjects and
/// system text, so only the class is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    /// The host name did not resolve.
    Resolve,
    /// The TCP connection was refused or reset before a response.
    Connect,
    /// A connect or global timeout elapsed.
    Timeout,
    /// TLS could not be established, or `https://` was asked of a transport
    /// built without a TLS provider (`mesh-https` off).
    Tls,
    /// The bytes on the wire were not HTTP the client understood, or the URL
    /// did not parse.
    Protocol,
    /// The server answered with a redirect. Never followed: following it
    /// would re-send a signed transaction to a host the caller did not name.
    Redirect,
    /// An I/O error of the given kind, mid-request.
    Io(std::io::ErrorKind),
    /// Any other class; the transport's error enum is non-exhaustive.
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A reference function returned a failure code.
    Reference {
        function: &'static str,
        rc: core::ffi::c_int,
    },
    /// A reference function returned a failure code and set `errno`.
    ReferenceErrno {
        function: &'static str,
        rc: core::ffi::c_int,
        errno: i32,
    },
    /// A slice was not the length the reference requires.
    Length {
        what: &'static str,
        expected: usize,
        got: usize,
    },
    /// A value outside the range the protocol can encode.
    ///
    /// Unlike [`Error::Length`] (a buffer of the wrong size), this is a number
    /// that would be read back as a different number: a destination count of
    /// 257 encodes as 1.
    Range {
        what: &'static str,
        min: u64,
        max: u64,
        got: u64,
    },
    /// A Base58 string contained an interior NUL and cannot be handed to a C
    /// `const char *`.
    InteriorNul,
    /// A Base58 string was not ASCII. The reference indexes its alphabet table
    /// with a `char`, so non-ASCII input is out of contract.
    NotAscii,
    /// A keystore I/O step failed. Carries the step's name and the kind,
    /// never file bytes.
    Io {
        op: &'static str,
        kind: std::io::ErrorKind,
    },
    /// The snapshot did not parse. `offset` is where the parser stopped; no
    /// snapshot bytes are included, since they may be key material.
    Corrupt {
        what: &'static str,
        offset: usize,
    },
    /// A snapshot format version (or KDF id) this build does not read.
    /// Distinct from `Corrupt` so a newer file reports "upgrade", not
    /// "damaged".
    ///
    /// `first_account` is the first record's tag and kind, read from the
    /// cleartext bytes 22..42 and 42 of a version-1 or version-2 image whose
    /// length fits that version's layout (`format::older_first_account`).
    /// `None` for any other version, for the KDF-id refusal (which reuses this
    /// variant with `got` = the id), and for an image whose length fits no
    /// older layout, where those bytes may be salt.
    UnsupportedVersion {
        got: u16,
        supported: u16,
        first_account: Option<(crate::addr::Tag, crate::account::AccountKind)>,
    },
    /// Another live process holds the keystore lock.
    Locked,
    /// The keystore directory has no snapshot. An absent file is never
    /// treated as an empty store.
    Missing,
    /// `create` on a directory that already holds a keystore, or `add` of a tag
    /// already present.
    Exists {
        what: &'static str,
    },
    /// `cli::create::create` was given a password shorter than
    /// `cli::create::MIN_PASSWORD_LEN`. `chars` and `min` count Unicode
    /// scalar values, not bytes.
    PasswordTooShort {
        chars: usize,
        min: usize,
    },
    /// No account under that tag.
    NoSuchAccount,
    /// The keystore directory is group- or other-writable.
    UnsafePermissions {
        mode: u32,
    },
    /// A keystore file, the snapshot or the lock, is readable or writable by
    /// group or others. The file counterpart of
    /// [`Error::UnsafePermissions`]; on Windows the same refusal is
    /// `UnsafeFileAcl`.
    #[cfg(unix)]
    UnsafeFileMode { file: &'static str, mode: u32 },
    /// The keystore directory's access list lets a trustee other than this
    /// user, `SYSTEM` or the Administrators group write to it. This is the
    /// Windows counterpart of [`Error::UnsafePermissions`]; it is a separate
    /// variant because a Windows directory has no mode to report.
    ///
    /// `trustee` is the security identifier granted the write, in `S-1-...`
    /// form; it is `S-1-1-0` (Everyone) when the directory has no access list,
    /// since a null list grants everyone access. `rights` is the access mask
    /// of the granting entry, or `WRITE_DAC | READ_CONTROL` for a directory
    /// owned by someone else. The accepted trustees and the rights that count
    /// as write are defined in the Windows arm of `keystore::perms`.
    #[cfg(windows)]
    UnsafeAcl {
        trustee: String,
        rights: u32,
    },
    /// A store file (`file`: a slot file or the lock) whose own access list
    /// lets a trustee other than this user, `SYSTEM` or the Administrators
    /// group read or write it, or which someone else owns.
    ///
    /// Separate from [`Error::UnsafeAcl`] because a file is refused for read
    /// access as well as write (a slot file holds the ciphertext), and the
    /// remedy is to fix that file's own list. `trustee` and `rights` are as in
    /// `UnsafeAcl`.
    #[cfg(windows)]
    UnsafeFileAcl {
        file: &'static str,
        trustee: String,
        rights: u32,
    },
    /// Windows refused to open one of the store's two slot files with system
    /// error `code`, typically `ERROR_SHARING_VIOLATION`: another process
    /// holds the file open without sharing write access.
    ///
    /// On Windows `open` holds both slot files for the handle's lifetime,
    /// sharing read access only, so a program that already holds one without
    /// sharing write (an antivirus scanner, search indexer, or backup or sync
    /// agent) makes the open fail. The error is raised at `open`, before
    /// anything is read or reserved, so nothing is changed and no handle is
    /// poisoned. Once a handle holds its slots, no commit can meet this error.
    /// The code indicates the usual cause but does not prove it; every other
    /// code is reported as `Io`.
    #[cfg(windows)]
    HeldOpen {
        code: i32,
    },
    /// The store path's last component is a symbolic link. Refused rather
    /// than followed, so a planted link cannot redirect the wallet to another
    /// directory.
    StoreDirectoryIsLink,
    /// A key is reserved for an unsettled spend; no further advance until
    /// `persist_settled`.
    PendingUnresolved {
        spent_index: u32,
    },
    /// `persist_settled` with nothing pending.
    NothingPending,
    /// A commit failed part-way, so memory and disk may disagree. Every later
    /// call is refused; drop the handle and reopen from disk. The write is
    /// never retried: after an fsync error the kernel may have discarded the
    /// dirty pages, and a retry could report success for data that never
    /// reached disk.
    Poisoned {
        first: Box<Error>,
    },
    /// The store did not decrypt: the password is wrong, or the file is
    /// damaged or tampered with.
    ///
    /// One variant for every cause on purpose: distinguishing them would be a
    /// decryption oracle. It carries no offset or byte.
    WrongPassword,
    /// A BIP39 phrase or entropy was refused. `what` names the rule, never a
    /// word or a byte: a phrase is the master seed spelled out.
    Mnemonic {
        what: &'static str,
    },
    /// A browser-extension `wotsIndex` with no position in this crate.
    /// Positions are the extension's index plus one: `-1` is position 0, and
    /// values below `-1` or above `u32::MAX - 1` name nothing.
    ShippedIndex {
        got: i64,
    },
    /// `sign_spend`: the receipt attests an index other than the one the
    /// store holds. A receipt is valid only for the state it was minted for.
    StaleReceipt {
        attested: u32,
        stored: u32,
    },
    /// `sign_spend`: the account has no key reserved, because the receipt came
    /// from `persist_advance_to` (which moves the index without reserving) or
    /// its reservation was settled.
    NoReservation,
    /// `sign_spend`: the digest is not the one the key was reserved for. The
    /// durable pending record must name what was signed, so a transaction
    /// rebuilt between reserve and sign is refused.
    DigestMismatch,
    /// `sign_spend`: the key access does not match the account's kind. A
    /// derived account needs the master seed; an imported account needs only
    /// its stored root.
    KeyAccessMismatch {
        kind: crate::account::AccountKind,
    },
    /// `sign_spend`: the supplied master seed does not derive this account's
    /// tag at its recorded position (wrong master, index or tag).
    DerivedTagNotReproduced {
        account_index: u32,
    },
    /// `sign_spend` (derived path): this account's seed is also held as an
    /// imported root in the same store. The two would share one key stream
    /// with independent indices, letting one key sign twice.
    KeyStreamSharedWithImportedAccount,
    /// `Account::import`: `wots::pkgen(root, pub_seed, adrs)` over the first
    /// address's own tail does not reproduce its public key, so the root and
    /// the 2208-byte address are not a pair. Also returned by
    /// `Account::restore_from_record` when the stored components and root do
    /// not produce the stored tag. Carries no key bytes.
    FirstAddressNotReproduced,
    /// The key-stream identity a record carries is not the one its key
    /// material produces (recomputed by `Account::restore_from_record` from an
    /// imported root, or by `sign_spend` from the master).
    StreamIdNotReproduced,
    /// A wallet operation needed a reconciled account and reconciliation
    /// refused. `what` names the divergence; the full report is
    /// `recon::Divergence`'s `Display`.
    ReconciliationRefused {
        what: &'static str,
    },
    /// An `OperatorAcknowledgement` does not name the tag and index the store
    /// is currently diverged by.
    AcknowledgementDoesNotMatch,
    /// `advance_after_operator_review` on an account that reconciles cleanly.
    NothingToReconcile,
    /// A caller's [`crate::recon::Cancel`] stopped a key-position walk.
    ///
    /// Not a failure. It is an `Error` rather than `Ok(None)` because
    /// `Ok(None)` means the walk reached its ceiling without a match, while
    /// this means nothing was learned. It carries no position; the caller
    /// driving the walk already counts.
    Cancelled,
    /// The Mesh transport failed before a response body arrived. `op` names
    /// the step (`"connect"`, `"send"`, `"read body"`), `kind` the class. The
    /// transport's message is dropped, since it can carry a host or a
    /// certificate subject.
    Transport {
        op: &'static str,
        kind: TransportKind,
    },
    /// The Mesh answered with an HTTP status other than 200. The middleware
    /// reports its own failures as 200s with an error object, so a non-200
    /// comes from a proxy, a missing route or the request-size limit.
    HttpStatus {
        status: u16,
    },
    /// The Mesh answered HTTP 429. `retry_after_secs` is the `Retry-After`
    /// header when it is a whole number of seconds. This crate never retries.
    RateLimited {
        retry_after_secs: Option<u64>,
    },
    /// The Mesh returned its error object `{code, message, retriable}`.
    /// `code` is the middleware's (1 invalid request, 4 account not found,
    /// 5 wrong network, 8 invalid account format, ...); the server-authored
    /// message is dropped.
    Mesh {
        code: u64,
        retriable: bool,
    },
    /// A Mesh response body did not have the documented shape. `what` names
    /// the field or expectation (`"result.address"`,
    /// `"balances[0].value: decimal"`), never the response bytes.
    MeshResponse {
        what: &'static str,
    },
    /// A request body over the middleware's cap, or a response body over this
    /// crate's, refused before it is sent or buffered.
    PayloadTooLarge {
        what: &'static str,
        max: usize,
        got: usize,
    },
    /// A hex field did not decode. `offset` is the position in the string of
    /// the first character the decoder refused.
    Hex {
        what: &'static str,
        offset: usize,
    },
    /// The chain's current address for the tag is not the address of the key
    /// this keystore would sign with next. Refused before anything is
    /// reserved and not resolved automatically: an unsettled broadcast spend,
    /// a restored seed with incomplete history and a second wallet on the same
    /// seed all look like this, and each needs a different recovery.
    ChainAddressMismatch {
        position: u32,
    },
    /// The plan names a key position other than the store's current one.
    /// Refused before a reservation is written.
    StaleSpendPlan {
        planned: u32,
        stored: u32,
    },
    /// The plan's source or change is not the store's derived address pair.
    SpendPlanAddressMismatch,
    /// The ledger balance changed between planning and reservation.
    BalanceChanged {
        planned: u64,
        current: u64,
    },
    /// The node reports a balance other than the one the operator expects.
    /// Nothing is reserved.
    BalanceNotExpected {
        expected: u64,
        reported: u64,
    },
    /// An expected balance was given with a resign. A resign reproduces the
    /// reserved transaction, whose digest already fixes the balance. Nothing
    /// is signed.
    ExpectedBalanceOnResign,
    /// A non-zero expiry cannot reach the next block or exceeds the node's
    /// 256-block arrival window. Nothing is reserved.
    InvalidExpiry {
        expiry: u64,
        tip: u64,
    },
    /// `resign` was asked to reproduce a reservation the chain has already
    /// moved past: the ledger holds the tag at that reservation's change key.
    /// Nothing was signed.
    ///
    /// Separate from [`Error::ChainAddressMismatch`], which comes from the
    /// same comparison, because this state is resolved by `settle`. The state
    /// is classified by `recon::reconcile_account`. A change address follows
    /// the key position, not the transaction, so this says the balance at the
    /// reserved key moved on, not which transaction moved it.
    ReservationLanded {
        /// The reserved position -- the key that signed.
        spent_index: u32,
        /// The change key's position, which is where the chain stands.
        settled_index: u32,
    },
    /// `send + fee` exceeds the balance the chain reports.
    InsufficientBalance {
        balance: u64,
        needed: u64,
    },
    /// `fee_total` is below the protocol floor of one `MFEE` per destination
    /// (`mdst_val`).
    FeeBelowMinimum {
        fee: u64,
        min: u64,
    },
    /// A transaction-data type byte this codec does not build.
    UnknownTxType {
        dat_type: u8,
    },
    /// A browser-extension export that is not in the extension's format.
    /// `what` names the field; no file bytes are included.
    ExtensionExport { what: &'static str },
    /// The export's master seed did not decrypt: a wrong export password or
    /// a damaged blob. The two are not distinguished.
    ExtensionExportPassword,
    /// The export decrypted, but its account fails one of the import's
    /// checks; `what` names which.
    ExtensionExportMismatch { what: &'static str },
    /// A set-delegate naming the all-zero tag, which the node refuses
    /// (`EMCM_BAD_DELEGATE`).
    DelegateIsZero,
    /// A set-delegate naming the source's own tag, which the node refuses
    /// (`EMCM_DELEGATE_IS_SELF`).
    DelegateIsSource,
    /// A claim of zero, which the node refuses (`EMCM_CLAIM_ZERO`).
    ClaimZero,
    /// A staking payload whose reserved bytes are not zero.
    ReservedNotZero {
        what: &'static str,
    },
    /// Consent terms the node's designations cannot match: a term the kind
    /// does not carry, a missing one, or a peer that is the consenting tag.
    ConsentTerms {
        why: &'static str,
    },
    /// A stake of zero or above tier 5, which the node refuses.
    StakeFields {
        amount: u64,
        tier: u8,
    },
    /// A claim above the entitlement the caller's source reported. The node
    /// would refuse it too (`EMCM_CLAIM_EXCEEDS`), but only after the
    /// one-time key had signed.
    ClaimExceedsEntitlement {
        amount: u64,
        entitlement: u64,
    },
    /// A destination amount of zero (`mdst_val`).
    ZeroAmount {
        index: usize,
    },
    /// A destination whose tag is the source's (`mdst_val`).
    DestinationIsSource {
        index: usize,
    },
    /// A destination reference the node's rule refuses (`mdst_val`,
    /// `EMCM_XTXREF`); see `mesh::spend::reference_is_valid`.
    InvalidReference {
        index: usize,
    },
    /// A 64-bit total overflowed while being tallied.
    Overflow {
        what: &'static str,
    },
    /// The signature the keystore released is for a different position than
    /// the plan was built for.
    PositionMismatch {
        planned: u32,
        signed: u32,
    },
    /// The signature does not recover to the key it claims, or that key does
    /// not own the source address. `what` names which comparison failed:
    /// `"public key"`, `"address scheme"` or `"source address hash"`.
    SignatureDoesNotRecover {
        what: &'static str,
    },
    /// The Mesh acknowledged a submission with a transaction id that is not
    /// the id of the bytes sent.
    SubmitIdMismatch,
    /// `resubmit_reverted_settle`: the saved bytes do not parse as a
    /// transaction. Nothing was submitted.
    SavedArtifactNotATransaction { cause: Box<Error> },
    /// `resubmit_reverted_settle`: the saved bytes parse, but are not the
    /// whole image of the transaction they describe. A partial trailer is
    /// zero-extended on decode, so the bytes sent would differ from the bytes
    /// held.
    SavedArtifactNotWhole { given: usize, described: usize },
    /// `resubmit_reverted_settle`: the signed part of the saved bytes does not
    /// hash to the digest the store retained at settle.
    NotTheSettledSpend,
    /// `resubmit_reverted_settle`: the settle was recorded before format
    /// version 4 kept the balance and the block-to-live, so the store cannot
    /// tell whether the saved bytes can still land.
    FiguresNotRecorded,
    /// `resubmit_reverted_settle` on an account with an open reservation.
    /// There is no retained settle to send again; `resign` rebuilds the open
    /// reservation.
    ReservationOpen { spent_index: u32 },
    /// `resubmit_reverted_settle`: the chain does not show the retained settle
    /// reverted. `what` names what the chain shows instead.
    NotARevertedSettle { what: &'static str },
    /// `resubmit_reverted_settle`: the balance at the source is not the one the
    /// settled spend was built against, so the saved bytes can no longer be
    /// accepted.
    SettledBalanceMoved { reserved: u64, current: u64 },
    /// `resubmit_reverted_settle`: the tip has reached the block-to-live of the
    /// settled spend, so the saved bytes can no longer be included.
    SettledExpired { blk_to_live: u64, tip: u64 },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Reference { function, rc } => {
                write!(f, "reference {function}() returned {rc}")
            }
            Error::ReferenceErrno { function, rc, errno } => {
                write!(f, "reference {function}() returned {rc}, errno {errno}")
            }
            Error::Length {
                what,
                expected,
                got,
            } => write!(f, "{what}: expected {expected} bytes, got {got}"),
            Error::Range {
                what,
                min,
                max,
                got,
            } => write!(f, "{what}: {got} is outside {min}..={max}"),
            Error::InteriorNul => f.write_str("base58 input contains an interior NUL"),
            Error::NotAscii => f.write_str("base58 input is not ASCII"),
            Error::Io { op, kind } => write!(f, "keystore {op}: {kind:?}"),
            Error::Corrupt { what, offset } => {
                write!(f, "keystore snapshot corrupt: {what} at byte offset {offset}")
            }
            Error::UnsupportedVersion { got, supported, first_account } => {
                // `read_header` produces this variant for an unknown version
                // (`supported == format::VERSION`) and for an unknown KDF id
                // (`supported == 1`); only the former gets the
                // version-specific text.
                let version_arm = *supported == crate::keystore::format::VERSION;
                if version_arm && got > supported {
                    write!(
                        f,
                        "keystore snapshot is format version {got}; this build reads versions {} \
                         and {supported} and writes version {supported}. A version this build does \
                         not read is not damage: a NEWER build of this wallet wrote this store. Open \
                         it with a build at least that new, and do not rewrite it or re-add its \
                         accounts elsewhere -- a reservation open in it can be re-signed only from \
                         it.",
                        crate::keystore::format::V3_VERSION
                    )?;
                } else if version_arm {
                    write!(
                        f,
                        "keystore snapshot is format version {got}; this build reads version \
                         {supported} (and reads a version-3 store, re-sealing it as version \
                         {supported} on its first write). A version this \
                         build does not read is not damage: an older store is migrated by \
                         re-adding its accounts into a FRESH directory (from the master seed, and \
                         from each imported account's root and first address), never by rewriting \
                         it in place."
                    )?;
                } else {
                    write!(
                        f,
                        "keystore snapshot is format version {got}; this build reads version \
                         {supported}. A version this build does not read is not damage: an older \
                         store is migrated by re-adding its accounts into a FRESH directory (from \
                         the master seed, and from each imported account's root and first address), \
                         never by rewriting it in place."
                    )?;
                }
                // Names the refused store's first account so the operator can
                // check whether the current store holds it. Hex rather than
                // the payable Base58 form, since this is a value to compare,
                // not a destination.
                match first_account {
                    Some((tag, kind)) => {
                        let hex: String = tag.iter().map(|b| format!("{b:02x}")).collect();
                        let kind_word = match kind {
                            crate::account::AccountKind::Derived => "derived",
                            crate::account::AccountKind::Imported => "imported",
                            crate::account::AccountKind::Sdk => "an SDK account",
                        };
                        write!(
                            f,
                            " This file's first account (its records sort by tag) is {kind_word} and \
                             has the tag 0x{hex}, which a version-{got} file stores unencrypted at \
                             bytes 22..42. To learn whether the refused store is on the SEED of the \
                             store in hand, run `address 0x{hex}` against the store in hand: an \
                             answer means the store in hand derives that same account -- one account \
                             seed, one WOTS+ key stream -- so a spend from each store is one key \
                             signing twice; destroy one before either spends. `no \
                             account for the tag` means that account is not held here, which does \
                             not prove a different seed. {}",
                            match kind {
                                crate::account::AccountKind::Derived =>
                                    "The refused store derived it from a master seed at an account \
                                     index, so a match is one master seed.",
                                crate::account::AccountKind::Imported =>
                                    "The refused store holds it as an imported root; the master \
                                     behind that root, if any, is not recorded there.",
                                crate::account::AccountKind::Sdk =>
                                    "The refused store holds it as a Mochimo SDK account seed; the \
                                     SDK master behind that seed is not recorded there.",
                            }
                        )
                    }
                    None => f.write_str(
                        " No account tag was read from this file: one is named only for a \
                         version-1 or version-2 file whose length fits that version's layout, \
                         where the first account's tag stands unencrypted at bytes 22..42.",
                    ),
                }
            }
            Error::Locked => f.write_str(
                "another wallet process holds keystore.lock; the lock releases when that \
                 process exits -- do not delete the file",
            ),
            Error::Missing => f.write_str(
                "keystore directory has no snapshot; an absent file is not an empty store \
                 (use create only for a genuinely new keystore)",
            ),
            // An existing snapshot: point at a different directory or at
            // `restore`.
            Error::Exists { what: "snapshot" } => f.write_str(
                "keystore: a snapshot already exists in this directory. To make a new store, use \
                 a different --dir; to add an account to this one, run `restore --account N` \
                 against it (`address` lists what it holds). Nothing was changed",
            ),
            Error::Exists { what } => write!(f, "keystore: {what} already exists"),
            Error::PasswordTooShort { chars, min } => write!(
                f,
                "password is {chars} character(s); this wallet will not seal a store under fewer \
                 than {min} (cli::create::MIN_PASSWORD_LEN -- a floor under the search space, \
                 counted in characters and not bytes). Nothing was \
                 created"
            ),
            Error::NoSuchAccount => f.write_str("keystore: no account under that tag"),
            Error::UnsafePermissions { mode } => write!(
                f,
                "keystore directory mode {mode:o} is group- or other-writable; refusing to \
                 hold key material there"
            ),
            #[cfg(unix)]
            Error::UnsafeFileMode { file, mode } => write!(
                f,
                "keystore file {file} has mode {mode:o}, which lets other users read or write it; \
                 refusing to use it. Anyone who can read the store can try passwords against it \
                 offline: run `chmod 600 {file}` in the keystore directory, and run the command \
                 again. On a filesystem that keeps no Unix modes, such as FAT or exFAT, `chmod` \
                 has no effect: remount it with `fmask=077` (or `umask=077`), or move the store \
                 to a filesystem that keeps them"
            ),
            #[cfg(windows)]
            Error::UnsafeAcl { trustee, rights } => write!(
                f,
                "keystore directory lets {trustee} write to it (access mask {rights:#010x}), and \
                 {trustee} is neither this user, SYSTEM nor the Administrators group; refusing to \
                 hold key material there"
            ),
            #[cfg(windows)]
            Error::UnsafeFileAcl { file, trustee, rights } => write!(
                f,
                "keystore file {file} lets {trustee} read or write it (access mask {rights:#010x}), \
                 and {trustee} is neither this user, SYSTEM nor the Administrators group; refusing \
                 to use it. On Windows a file's own access list decides who may open it, whatever \
                 the directory's says, and a file moved or copied into the store directory can \
                 bring or inherit one that admits others: give {file} a list granting this user \
                 alone, and run the command again"
            ),
            #[cfg(windows)]
            Error::HeldOpen { code } => write!(
                f,
                "keystore: Windows refused to open accounts.mks or accounts.mks.1 (system error \
                 {code}). The usual cause is another program holding the file open without \
                 sharing write -- an antivirus scanner, a search indexer, a backup or sync agent. \
                 Nothing was read or changed; run the command again, and if the refusal persists, \
                 exclude the keystore directory from that program"
            ),
            Error::StoreDirectoryIsLink => f.write_str(
                "keystore directory is a symbolic link; a store is never opened through one, so \
                 that a link planted at the store's name cannot point the wallet at another \
                 directory. Pass the directory the link points to",
            ),
            Error::PendingUnresolved { spent_index } => write!(
                f,
                "key {spent_index} is reserved for an unsettled spend; settle it before \
                 advancing again"
            ),
            Error::NothingPending => f.write_str("keystore: nothing is pending for that tag"),
            Error::Poisoned { first } => write!(
                f,
                "keystore poisoned by an earlier failure ({first}); memory and disk may \
                 disagree -- drop this handle and reopen from disk, and do not retry the \
                 write: after an fsync error the kernel may have discarded the dirty pages, \
                 and a retry can report success for data that never reached disk"
            ),
            Error::WrongPassword => write!(
                f,
                "the keystore did not decrypt. Either the password is wrong, or the file has \
                 been damaged or altered -- this cannot tell you which, by design: an error that \
                 distinguished them would tell an attacker which of his guesses was closer. What \
                 to try, in order: the password again, minding the keyboard layout and caps \
                 lock; a backup copy of the store, if one exists; and then `create --from-phrase` \
                 into a fresh directory and `restore --account N` for each account, from the \
                 recovery phrase -- a damaged file cannot be repaired here, and nothing in it \
                 can be read without the key"
            ),
            Error::Mnemonic { what } => write!(f, "bip39: {what}"),
            Error::ShippedIndex { got } => write!(
                f,
                "shipped wotsIndex {got} has no position in this crate: -1 is the first \
                 key (position 0) and n >= 0 is position n + 1, up to u32::MAX"
            ),
            Error::StaleReceipt { attested, stored } => write!(
                f,
                "the receipt attests index {attested} but the store holds {stored}; a receipt \
                 names the state it was minted for, and this one is stale"
            ),
            Error::NoReservation => f.write_str(
                "no key is reserved for that account: the receipt came from a reconciliation \
                 advance or its reservation was settled, and neither names a key to sign with",
            ),
            Error::DigestMismatch => f.write_str(
                "the digest is not the one this key was reserved for; the pending record \
                 must name what was signed. Reproduce the original transaction exactly; never \
                 reuse this key for a different transaction",
            ),
            Error::KeyAccessMismatch { kind } => write!(
                f,
                "key access does not match the account: a {kind:?} account needs {}",
                match kind {
                    crate::account::AccountKind::Derived => "KeyAccess::Master, the master seed it derives from",
                    crate::account::AccountKind::Imported => "KeyAccess::StoredRoot, nothing beyond its stored root",
                    crate::account::AccountKind::Sdk => "KeyAccess::StoredRoot, nothing beyond its stored SDK account seed",
                }
            ),
            Error::DerivedTagNotReproduced { account_index } => write!(
                f,
                "the master seed supplied does not derive this account's tag at position \
                 {account_index}; wrong seed, wrong position or wrong tag, and none of them signs"
            ),
            Error::KeyStreamSharedWithImportedAccount => f.write_str(
                "this derived account's seed is also held as an imported root in this store; \
                 two accounts over one key stream would let one key sign twice, so neither signs \
                 (duplicate_key_streams_are_refused_within_one_keystore_not_across_stores)",
            ),
            Error::FirstAddressNotReproduced => f.write_str(
                "the root does not reproduce this first address: wots_pkgen over the address's \
                 own public seed and hash address gives a different public key, so the pair did \
                 not come from one account and position 0 would sign under an address nobody \
                 funded",
            ),
            Error::StreamIdNotReproduced => f.write_str(
                "the stored key-stream identity is not the one this account's key material \
                 produces; the identity is what stops two accounts sitting over one key stream, \
                 so a record that disagrees with itself is refused",
            ),
            Error::ReconciliationRefused { what } => write!(
                f,
                "this account is not reconciled with the chain ({what}), so no spend operation \
                 on it is permitted. Read the divergence report and act on it; the wallet fails closed \
                 because the three causes of divergence have three different correct recoveries"
            ),
            Error::AcknowledgementDoesNotMatch => f.write_str(
                "this acknowledgement does not name the divergence this store is in now. An \
                 acknowledgement carries the tag and the index the report printed, and it is \
                 checked against the live state, so a stale report or another account's cannot \
                 be used to advance this one",
            ),
            Error::NothingToReconcile => f.write_str(
                "this account reconciles cleanly against the chain; there is no key index to \
                 move",
            ),
            Error::Cancelled => f.write_str(
                "the key-position walk was stopped before it reached a conclusion; nothing was \
                 decided and no index is assumed",
            ),
            Error::Transport { op, kind } => write!(f, "mesh transport {op}: {kind:?}"),
            Error::HttpStatus { status } => write!(
                f,
                "mesh answered HTTP {status}; the middleware's own failures are 200s with an \
                 error object, so this is a proxy, a route miss or its request-size gate"
            ),
            Error::Mesh { code, retriable } => write!(
                f,
                "mesh error code {code}{}",
                if *retriable { " (retriable)" } else { "" }
            ),
            Error::RateLimited { retry_after_secs } => match retry_after_secs {
                Some(s) => write!(
                    f,
                    "the node is rate-limiting this request (HTTP 429) and asks for {s} second(s) \
                     before the next one; this program does not retry, so wait that long and run \
                     the command again"
                ),
                None => f.write_str(
                    "the node is rate-limiting this request (HTTP 429) and named no wait; this \
                     program does not retry, so wait at least ten seconds and run the command again",
                ),
            },
            Error::MeshResponse { what } => write!(f, "mesh response is not the documented shape: {what}"),
            Error::PayloadTooLarge { what, max, got } => {
                write!(f, "{what}: {got} bytes exceeds the cap of {max}")
            }
            Error::Hex { what, offset } => write!(f, "{what}: not hex at byte offset {offset}"),
            Error::ChainAddressMismatch { position } => write!(
                f,
                "the chain's current address for this tag is not the address of the key at \
                 position {position}, which is the key this keystore would sign with next. \
                 Nothing was reserved. This is an index divergence and it has three causes with \
                 three different remedies -- a broadcast spend that never settled, a restored \
                 seed with incomplete history, or a second wallet live on this seed -- so do \
                 not advance the index by hand; reconcile"
            ),
            Error::StaleSpendPlan { planned, stored } => write!(
                f,
                "the plan names key position {planned} but the store now holds {stored}; \
                 nothing was reserved. Build a new plan from the current store"
            ),
            Error::SpendPlanAddressMismatch => f.write_str(
                "the plan's source or change address does not match this store's current keys; \
                 nothing was reserved. Build a new plan from this store",
            ),
            Error::BalanceChanged { planned, current } => write!(
                f,
                "the balance changed from {planned} to {current} nanoMCM after planning; \
                 nothing was reserved. Review the balance and build a new plan"
            ),
            Error::BalanceNotExpected { expected, reported } => write!(
                f,
                "the node reports a balance of {reported} nanoMCM, not the expected {expected}; \
                 nothing was reserved. Check the balance against another source before signing"
            ),
            Error::ExpectedBalanceOnResign => f.write_str(
                "an expected balance applies to a new signature; a resign reproduces the reserved \
                 transaction, whose balance the reservation recorded. Nothing was signed",
            ),
            Error::InvalidExpiry { expiry, tip } => write!(
                f,
                "block-to-live {expiry} must be later than the observed tip {tip} and at most \
                 256 blocks ahead; nothing was reserved. Use 0 for no expiry or review the tip"
            ),
            Error::ReservationLanded {
                spent_index,
                settled_index,
            } => write!(
                f,
                "the chain holds this tag at the key at position {settled_index}, which is the \
                 change key of the reservation at position {spent_index}: the reserved spend has \
                 landed and there is nothing left to reproduce. Nothing was signed. `settle` is \
                 the verb that resolves this state"
            ),
            Error::InsufficientBalance { balance, needed } => write!(
                f,
                "the chain reports a balance of {balance} nanoMCM and the spend needs {needed} \
                 (send plus fee)"
            ),
            Error::FeeBelowMinimum { fee, min } => write!(
                f,
                "fee {fee} is under the protocol floor of {min} (one MFEE per destination, \
                 mdst_val; one MFEE in all for a validator transaction, tx_val)"
            ),
            Error::UnknownTxType { dat_type } => write!(
                f,
                "transaction-data type {dat_type:#04x} is not one this wallet builds: it knows \
                 a transfer (0x00), a set-delegate (0x01), a clear-delegate (0x02) and a claim \
                 (0x06)"
            ),
            Error::ExtensionExport { what } => {
                write!(f, "the file is not a Mochimo browser-extension export the way this wallet reads one: {what}")
            }
            Error::ExtensionExportPassword => f.write_str(
                "the export's master seed did not decrypt: the password is not the one the export was \
                 made with, or the file is damaged. The two cannot be told apart",
            ),
            Error::ExtensionExportMismatch { what } => write!(
                f,
                "the export does not hold the account asked for as this wallet checks it: {what}. Nothing \
                 was imported"
            ),
            Error::DelegateIsZero => {
                f.write_str("the delegate tag is all zero, which the node refuses (EMCM_BAD_DELEGATE)")
            }
            Error::DelegateIsSource => f.write_str(
                "the delegate tag is the validator's own tag, which the node refuses \
                 (EMCM_DELEGATE_IS_SELF)",
            ),
            Error::ClaimZero => f.write_str("a claim of zero, which the node refuses (EMCM_CLAIM_ZERO)"),
            Error::ReservedNotZero { what } => {
                write!(f, "{what}: a reserved byte is not zero, which this codec refuses")
            }
            Error::ConsentTerms { why } => write!(f, "consent terms refused: {why}"),
            Error::StakeFields { amount, tier } => write!(
                f,
                "a stake of {amount} nanoMCM at tier {tier} is refused by the node: the amount must be \
                 above zero and the tier 0 to 5"
            ),
            Error::ClaimExceedsEntitlement { amount, entitlement } => write!(
                f,
                "a claim of {amount} nanoMCM is above the entitlement of {entitlement} nanoMCM \
                 the entitlement source reported; the node would refuse it (EMCM_CLAIM_EXCEEDS) \
                 only after the one-time key had signed, so nothing was reserved"
            ),
            Error::ZeroAmount { index } => {
                write!(f, "destination {index} has a zero amount, which mdst_val rejects")
            }
            Error::DestinationIsSource { index } => write!(
                f,
                "destination {index} carries the source's own tag, which mdst_val rejects"
            ),
            Error::InvalidReference { index } => write!(
                f,
                "destination {index} carries a reference the node's rule refuses (mdst_val, \
                 EMCM_XTXREF): uppercase letters and digits in groups, each group all one kind, \
                 neighbouring groups of different kinds, single dashes between groups and none \
                 at either end, NUL-terminated with nothing after the first NUL"
            ),
            Error::Overflow { what } => write!(f, "{what} overflows 64 bits"),
            Error::PositionMismatch { planned, signed } => write!(
                f,
                "the plan was built for the key at position {planned} but the signature came \
                 from position {signed}"
            ),
            Error::SignatureDoesNotRecover { what } => write!(
                f,
                "the signature does not validate against the transaction it is attached to: \
                 {what} does not match. Nothing was broadcast"
            ),
            Error::SubmitIdMismatch => f.write_str(
                "the mesh acknowledged a transaction id that is not the id of the bytes sent; \
                 the server parsed something else, and its acknowledgement says nothing about \
                 this transaction",
            ),
            Error::SavedArtifactNotATransaction { cause } => write!(
                f,
                "the saved artifact does not parse as a transaction: {cause}. Nothing was submitted."
            ),
            Error::SavedArtifactNotWhole { given, described } => write!(
                f,
                "the saved artifact is {given} bytes but the transaction it describes is {described}: \
                 a partial trailer is zero-extended on decode, so the bytes sent would not be the bytes \
                 held. Nothing was submitted."
            ),
            Error::NotTheSettledSpend => f.write_str(
                "the saved artifact's signed part is not the spend this account settled: its digest is \
                 not the one this store retained at settle. A copy of another spend, or one from another \
                 store on this seed, is refused here. Nothing was submitted and nothing was signed."
            ),
            Error::FiguresNotRecorded => f.write_str(
                "this settle was recorded before format version 4 kept its balance and block-to-live, so \
                 this store cannot tell whether the saved artifact can still land. Nothing was submitted."
            ),
            Error::ReservationOpen { spent_index } => write!(
                f,
                "key {spent_index} is reserved for a spend that has not settled, so there is no retained \
                 settle to send again. `resign` rebuilds the artifact of an open reservation. Nothing was \
                 submitted."
            ),
            Error::NotARevertedSettle { what } => write!(
                f,
                "the chain does not show this account's retained settle reverted ({what}). Nothing was \
                 submitted."
            ),
            Error::SettledBalanceMoved { reserved, current } => write!(
                f,
                "the balance at the source is {current} nanoMCM, not the {reserved} the settled spend was \
                 built against, so the saved artifact can no longer be accepted. Nothing was submitted. \
                 This store will not sign with that key again, so the funds at its address cannot move \
                 from this store."
            ),
            Error::SettledExpired { blk_to_live, tip } => write!(
                f,
                "block-to-live {blk_to_live} has been reached at tip {tip}, so the saved artifact can no \
                 longer be included. Nothing was submitted. This store will not sign with that key again."
            ),
        }
    }
}

impl std::error::Error for Error {}

// --- reference validator outcomes ----------------------------------------

/// A reference validator's outcome: the code it returned and the `errno` it
/// left.
///
/// Not a `Result`: `mdst_val` and `tx_val__wots` report through both
/// channels, and the fixtures pin both, including the success code and
/// failures that set no `errno` (`mdst_val__reference` fails without touching
/// `errno`; its caller supplies `EMCM_XTXREF`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    /// The `int` the reference returned.
    pub rc: core::ffi::c_int,
    /// `errno` immediately after the call, cleared immediately before it.
    /// Zero means the reference set none, not that nothing failed.
    pub errno: i32,
}

impl Verdict {
    /// Whether the code is `VEOK`.
    #[must_use]
    pub fn is_ok(self) -> bool {
        self.rc == crate::consts::VEOK
    }

    /// The reference's own spelling of [`Self::rc`] — `ve2str`.
    #[must_use]
    pub fn rc_name(self) -> String {
        ve2str(self.rc)
    }
}

/// `ve2str`: the reference's name for a `VE*` return code.
///
/// # Panics
///
/// Always. The reference's diagnostic strings are not ported: the fixtures'
/// names came from the reference's own function, so a Rust copy could only be
/// checked against itself. Nothing on the wallet path calls this.
#[must_use]
pub fn ve2str(_rc: core::ffi::c_int) -> String {
    unimplemented!("{}", NO_NATIVE_DIAGNOSTIC_STRINGS)
}

/// The panic message shared by the three unported diagnostic-string
/// functions.
const NO_NATIVE_DIAGNOSTIC_STRINGS: &str = "the reference's diagnostic strings \
     are deliberately not ported: a Rust restatement of upstream's own spelling \
     would compare our naming to our naming, so no version of it could be \
     checked. This is knowledge, not debt: no condition can turn it green, so it \
     is deliberately absent from \
     invariants.rs::every_unimplemented_site_is_knowledge_not_debt, whose entries \
     are all dischargeable.";

/// `mcm_strerrorname`: the symbolic name of an `errno` value, including the
/// reference's `EMCM_*` extensions.
///
/// # Panics
///
/// Always; see [`ve2str`].
#[must_use]
pub fn errno_name(_errnum: i32) -> String {
    unimplemented!("{}", NO_NATIVE_DIAGNOSTIC_STRINGS)
}

/// `mcm_strerror`: the human-readable text for an `errno` value, including
/// the reference's `EMCM_*` extensions.
///
/// # Panics
///
/// Always; see [`ve2str`].
#[must_use]
pub fn errno_text(_errnum: i32) -> String {
    unimplemented!("{}", NO_NATIVE_DIAGNOSTIC_STRINGS)
}
