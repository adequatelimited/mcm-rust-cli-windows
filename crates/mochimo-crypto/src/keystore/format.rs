// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! The keystore snapshot format: one whole-state image, little-endian,
//! fixed-width, canonical and encrypted at rest.
//!
//! # Layout (all integers little-endian)
//!
//! ```text
//! PLAINTEXT HEADER, 51 bytes, all of it the AEAD's associated data (AAD):
//!   magic[8] = "MCMKSTOR" | version u16 = 4 | kdf_id u8 = 1 (Argon2id v1.3)
//!   | m_cost_kib u32 | t_cost u32 | p_cost u32 | salt[16] | nonce[12]
//!
//! CIPHERTEXT, 45 + 195*count bytes (ChaCha20 is a stream cipher, so the
//! ciphertext is as long as the plaintext):
//!   generation u64 | count u32 | master_present u8 | master[32]
//!     (zero when master_present == 0)
//!   records[count], sorted by tag ascending, no duplicates, 195 bytes each
//!   (178 in version 3, which is also read):
//!     tag[20] | kind u8 (0 derived / 1 imported / 2 SDK)
//!     | body[32]  (derived: account_index u32 then 28 zero bytes;
//!                  imported, SDK: the root)
//!     | first[64] (imported: the first key's public seed and hash-address
//!                  image; derived, SDK: zero)
//!     | stream[20] (hash of the rotation-0 public key: the key stream's
//!                   public identity)
//!     | wots_index u32
//!     | pending u8      0 none / 1 reserved / 2 settled, retained
//!     | spent_index u32 | digest[32]
//!     | figures u8      0 not recorded / 1 recorded
//!     | reserved_balance u64 | blk_to_live u64
//!       (every field after wots_index is zero when pending == 0; the two
//!        u64 are zero when figures == 0; spent_index + 1 == wots_index
//!        when pending != 0)
//!
//! AEAD TAG, 16 bytes: Poly1305 over the ciphertext with the header as AAD.
//! (Not a record's `tag[20]`, which is an account identifier.)
//! ```
//!
//! `HEADER_LEN`, `BODY_HEADER_LEN`, `RECORD_LEN` and `TRAILER_LEN` are the
//! four sizes above and `image_len` is the closed formula;
//! `known_answer_image_for_two_accounts` asserts the decomposition.
//! `MIN_IMAGE_LEN` and `MAX_IMAGE_LEN` bound the lengths `read_header`
//! admits.
//!
//! # Plaintext, ciphertext and the tag
//!
//! `generation`, `count` and the master seed are encrypted, so a stolen file
//! does not reveal how many accounts a wallet holds or how often it has been
//! written. The header holds only what a reader needs before it can decrypt:
//! the KDF's identity and parameters, the salt and the nonce. As AAD they are
//! authenticated, so rewriting `m_cost` down to make guessing cheap derives a
//! different key and the tag fails. `read_header` bounds `m_cost`, `t_cost`
//! and `p_cost` before anything allocates or derives, because the tag can be
//! checked only after the derivation those fields describe.
//!
//! The tag detects changes by anyone without the key. It is not rollback
//! protection: an older valid snapshot copied back verifies under the same
//! password, because the salt does not change across rewrites.
//!
//! A flipped bit, a truncated file, a forged header field and a wrong
//! password all produce one `WrongPassword`, before any record byte is read.
//! Distinguishing damage from a wrong password would be a decryption oracle.
//!
//! # Versions
//!
//! * **Version 4** is written and read.
//! * **Version 3** is read, with 178-byte records and reservation figures
//!   declared absent (`figures: None`); nothing else is reinterpreted. `open`
//!   never rewrites the file; the next `commit` seals version 4 under the
//!   next generation, so the nonce is fresh, and `Keystore::upgraded_from`
//!   reports the upgrade. Older builds then refuse the file as a newer
//!   version.
//! * **Versions 1 and 2** are refused with `UnsupportedVersion`, not
//!   upgraded. A v1 file lacks the first-key components and stream identity
//!   an upgrade would need; a v2 file lacks the master seed, which only the
//!   recovery phrase can supply. Migration is `create --from-phrase` into a
//!   fresh directory.
//!
//! An unknown KDF id is also `UnsupportedVersion`, not `Corrupt`.
//!
//! A reservation's signed transaction is not stored: WOTS+ signing is
//! deterministic, so it can be rebuilt from the store, the key and the wire
//! inputs.
//!
//! # Canonical encoding
//!
//! Fixed widths make the image length a closed formula of `count`, so the
//! parser bounds every read before it happens and never indexes. Zero
//! padding, zero absent fields and tag order are enforced, so one state has
//! exactly one image. Entropy (the salt and the nonce seed) enters only as
//! parameters, so the image is deterministic for fixed entropy and tests can
//! pin its bytes.
//!
//! # Order of checks
//!
//! The version is read and dispatched before the KDF runs or the tag is
//! checked, so an unsupported file reports `UnsupportedVersion` rather than
//! `WrongPassword`, without paying for Argon2
//! (`an_older_format_reports_unsupported_version_before_anything_else`).
//! `count` is bounded before any allocation. Checks after `crypt::open` run
//! on authenticated bytes and catch writer bugs, keeping the format
//! canonical. `Corrupt` carries an offset, never a byte (I6). Code outside
//! `#[cfg(test)]` contains no panicking construct.
//!
//! The sealed path uses the pure-Rust `argon2` and `chacha20poly1305`
//! crates, so a plaintext image never passes through C; see `super::crypt`.

use core::fmt;
use std::collections::BTreeMap;

use zeroize::Zeroizing;

use crate::account::{Account, AccountKind, AccountRecord, KeyMaterial, StreamId, WotsIndex, FIRST_KEY_LEN};
use crate::addr::Tag;
use super::crypt::{self, Kdf};
use crate::consts::{ADDR_TAG_LEN, SEED_LEN};
use crate::error::{Error, Result};
use crate::secret::Secret;

pub(crate) const MAGIC: [u8; 8] = *b"MCMKSTOR";
/// The version this build writes, and the newest it reads. It also reads
/// [`V3_VERSION`].
pub(crate) const VERSION: u16 = 4;
/// The one older version this build reads. A version-3 image uses the same
/// key derivation, AEAD and header offsets, with 178-byte records and no
/// reservation figures. The store's next commit, never `open`, re-seals it
/// as [`VERSION`].
pub(crate) const V3_VERSION: u16 = 3;
/// The plaintext header, all of it also the AEAD's additional authenticated
/// data: `magic[8] | version u16 | kdf_id u8 | m_cost u32 | t_cost u32 |
/// p_cost u32 | salt[16] | nonce[12]`.
///
/// It is plaintext because a reader needs every field to derive the key. It
/// is authenticated so that rewriting a field, for example lowering `m_cost`,
/// derives a different key and the tag fails.
pub(crate) const HEADER_LEN: usize =
    8 + 2 + 1 + 4 + 4 + 4 + crypt::SALT_LEN + crypt::NONCE_LEN;
/// `generation u64 | count u32 | master_present u8 | master[32]`, inside the
/// ciphertext. When `master_present` is 0 the 32 bytes must be zero.
pub(crate) const BODY_HEADER_LEN: usize = 8 + 4 + 1 + SEED_LEN;
/// The version-4 record: version 3's 178 bytes in v3's order, then
/// `figures u8 | reserved_balance u64 | blk_to_live u64`.
///
/// The v3 prefix is kept on one line and not written through
/// [`V3_RECORD_LEN`]:
/// `tests/invariants.rs::duplicate_key_streams_are_refused_within_one_keystore_not_across_stores`
/// matches that exact text to check that the record still carries the
/// key-stream identity.
pub(crate) const RECORD_LEN: usize =
    ADDR_TAG_LEN + 1 + 32 + FIRST_KEY_LEN + ADDR_TAG_LEN + 4 + 1 + 4 + 32 + 1 + 8 + 8;
/// A version-3 record's width, a literal so the old geometry never follows
/// the live [`RECORD_LEN`].
pub(crate) const V3_RECORD_LEN: usize = 178;
/// The AEAD tag's length (16 bytes), which ends the image.
pub(crate) const TRAILER_LEN: usize = crypt::TAG_LEN;
/// The most accounts one snapshot holds. The cap exists so `count` from an
/// untrusted file bounds the allocation.
pub(crate) const MAX_ACCOUNTS: usize = 1 << 16;
/// The longest image `read_header` admits: `image_len(MAX_ACCOUNTS)`,
/// written out as its own sum so the two can be checked against each other
/// (`max_image_len_is_the_cap_image_and_one_record_more_is_refused`).
pub(crate) const MAX_IMAGE_LEN: usize =
    HEADER_LEN + BODY_HEADER_LEN + MAX_ACCOUNTS * RECORD_LEN + TRAILER_LEN;
/// The shortest image either read version produces: `image_len(0)`, an empty
/// store. `read_header` reports it as the `min` of its length `Range`.
pub(crate) const MIN_IMAGE_LEN: usize = HEADER_LEN + BODY_HEADER_LEN + TRAILER_LEN;

const KIND_DERIVED: u8 = 0;
const KIND_IMPORTED: u8 = 1;
/// A Mochimo SDK account (`KeyMaterial::Sdk`): the body is the SDK account
/// seed and the first-key field must be zero, because the SDK's first key is
/// a function of the seed alone. A build that predates this kind refuses the
/// record as `kind`.
const KIND_SDK: u8 = 2;

/// The two figures of a reserved spend stored beside its digest (version 4
/// and later). Not secret. Both are the plan's inputs to `SpendPlan::new`:
/// the balance is `LedgerEntry::balance` at plan time, which the node
/// requires to equal `send + change + fee` exactly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Figures {
    /// The ledger balance the plan was built against, in nanoMochimo.
    pub reserved_balance: u64,
    /// The plan's block-to-live; zero never expires.
    pub blk_to_live: u64,
}

/// A key reserved for a spend that has not been settled or, in a [`Slot`]'s
/// `settled` field, the last settled reservation, retained until the index
/// moves.
///
/// A reservation is written in the same commit that advances `wots_index`
/// to `spent_index + 1`; settling moves the block without advancing
/// anything. The parser refuses any other relation. Not secret: the digest
/// is the message being signed and the index is public state. `figures` is
/// `None` only for a reservation read from a version-3 record, which stored
/// no figures; settling carries that `None` forward.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pending {
    pub spent_index: WotsIndex,
    pub digest: [u8; 32],
    pub figures: Option<Figures>,
}

/// One account's slot in the live state. No `Debug`: it holds an `Account`,
/// which may hold key material.
///
/// `pending` and `settled` are separate fields so a retained settled block
/// is never mistaken for an open reservation: `persist_advance` refuses on
/// `pending` alone. Both `Some` is illegal; the file cannot express it and
/// [`encode`] refuses it.
pub(crate) struct Slot {
    pub(crate) account: Account,
    pub(crate) pending: Option<Pending>,
    pub(crate) settled: Option<Pending>,
}

/// What the encoder reads per record: the account by reference plus the
/// values the caller may override for the record being committed. No
/// `Debug`, for the same reason as [`Slot`].
pub(crate) struct RecordRef<'a> {
    pub(crate) tag: Tag,
    pub(crate) account: &'a Account,
    pub(crate) wots_index: WotsIndex,
    pub(crate) pending: Option<Pending>,
    pub(crate) settled: Option<Pending>,
}

/// The parsed state: generation and the sorted slots.
pub(crate) struct Parsed {
    pub(crate) generation: u64,
    pub(crate) slots: BTreeMap<Tag, Slot>,
    /// The master seed, when the store holds one.
    pub(crate) master: Option<Secret<SEED_LEN>>,
}

/// The exact image length for `count` records, or `None` on overflow.
pub(crate) fn image_len(count: usize) -> Option<usize> {
    body_len(count)?
        .checked_add(HEADER_LEN)?
        .checked_add(TRAILER_LEN)
}

/// The plaintext (and so ciphertext) body length for `count` records at
/// [`VERSION`]. The parser uses [`body_len_at`] with the version it read.
pub(crate) fn body_len(count: usize) -> Option<usize> {
    body_len_at(VERSION, count)
}

/// The record width for a read version: 178 for version 3, [`RECORD_LEN`]
/// otherwise.
pub(crate) fn record_len_at(version: u16) -> usize {
    if version == V3_VERSION {
        V3_RECORD_LEN
    } else {
        RECORD_LEN
    }
}

/// [`body_len`] for a given read version.
pub(crate) fn body_len_at(version: u16, count: usize) -> Option<usize> {
    count.checked_mul(record_len_at(version))?.checked_add(BODY_HEADER_LEN)
}

/// Encode a sorted, duplicate-free record list into a canonical image.
///
/// The image lives in a `Zeroizing` buffer allocated at exact capacity, so
/// it never reallocates and leaves no unzeroed copy behind. The caller
/// builds from a `BTreeMap`, so order and uniqueness hold; they are checked
/// anyway, because a wrong image is a corrupt store.
///
/// # Errors
///
/// `Range` when there are more than [`MAX_ACCOUNTS`] records; `Corrupt` when
/// records are out of order, a record holds both an open and a settled
/// reservation, or a reservation's `spent_index + 1 != wots_index`; and any
/// error from the KDF parameter check or the AEAD.
pub(crate) fn encode(
    records: &[RecordRef<'_>],
    generation: u64,
    master: Option<&Secret<SEED_LEN>>,
    kdf: Kdf,
    salt: &[u8; crypt::SALT_LEN],
    key: &[u8; crypt::KEY_LEN],
    nonce: &[u8; crypt::NONCE_LEN],
) -> Result<Zeroizing<Vec<u8>>> {
    if records.len() > MAX_ACCOUNTS {
        return Err(Error::Range {
            what: "keystore account count",
            min: 0,
            max: MAX_ACCOUNTS as u64,
            got: records.len() as u64,
        });
    }
    let count = u32::try_from(records.len()).map_err(|_| Error::Range {
        what: "keystore account count",
        min: 0,
        max: u64::from(u32::MAX),
        got: records.len() as u64,
    })?;
    let len = image_len(records.len()).ok_or(Error::Corrupt {
        what: "image length overflow",
        offset: 0,
    })?;
    let kdf = kdf.checked()?;
    // The plaintext header, which is also the AAD.
    let mut image: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(len));
    image.extend_from_slice(&MAGIC);
    image.extend_from_slice(&VERSION.to_le_bytes());
    image.push(crypt::KDF_ARGON2ID_V13);
    image.extend_from_slice(&kdf.m_cost_kib.to_le_bytes());
    image.extend_from_slice(&kdf.t_cost.to_le_bytes());
    image.extend_from_slice(&kdf.p_cost.to_le_bytes());
    image.extend_from_slice(salt);
    image.extend_from_slice(nonce);
    debug_len_matches(image.len(), HEADER_LEN)?;

    // The body: everything from here to the tag is encrypted.
    image.extend_from_slice(&generation.to_le_bytes());
    image.extend_from_slice(&count.to_le_bytes());
    match master {
        None => {
            image.push(0);
            image.extend_from_slice(&[0u8; SEED_LEN]);
        }
        Some(m) => {
            image.push(1);
            image.extend_from_slice(m.expose());
        }
    }

    let mut prev: Option<Tag> = None;
    for r in records {
        let record_offset = image.len();
        if let Some(p) = prev {
            if r.tag <= p {
                return Err(Error::Corrupt {
                    what: "records not strictly ascending by tag",
                    offset: record_offset,
                });
            }
        }
        prev = Some(r.tag);
        // Both an open and a settled block has no encoding (one `pending u8`
        // with three values), so it is refused here. Choosing either would
        // lose data: `settled` would seal an open reservation and strand its
        // balance; `pending` would drop the block the reverted-settle report
        // reads.
        if r.pending.is_some() && r.settled.is_some() {
            return Err(Error::Corrupt {
                what: "both an open and a settled reservation in one record",
                offset: record_offset,
            });
        }
        let (state, block) = match (r.pending, r.settled) {
            (Some(p), None) => (1u8, Some(p)),
            (None, Some(s)) => (2u8, Some(s)),
            _ => (0u8, None),
        };
        // The parser's relation, `spent_index + 1 == wots_index` for any
        // occupied block, checked before sealing so a writer bug is not
        // sealed as authenticated garbage. `RecordRef` carries the two
        // fields independently; every other canonicality rule is built here
        // from a sum type and cannot be violated. Same `what` as the parser.
        if let Some(p) = block {
            if p.spent_index.get().checked_add(1) != Some(r.wots_index.get()) {
                return Err(Error::Corrupt {
                    what: "pending index does not precede wots_index by one",
                    offset: record_offset,
                });
            }
        }
        image.extend_from_slice(&r.tag);
        let stream = match r.account.key_material() {
            KeyMaterial::Derived {
                account_index,
                stream,
            } => {
                image.push(KIND_DERIVED);
                image.extend_from_slice(&account_index.to_le_bytes());
                image.extend_from_slice(&[0u8; 28]);
                // A derived account's first key comes from the master seed,
                // so the field is zero.
                image.extend_from_slice(&[0u8; FIRST_KEY_LEN]);
                stream
            }
            KeyMaterial::Imported {
                root,
                first,
                stream,
            } => {
                image.push(KIND_IMPORTED);
                image.extend_from_slice(root.secret().expose());
                image.extend_from_slice(&first.to_bytes());
                stream
            }
            KeyMaterial::Sdk { root, stream } => {
                image.push(KIND_SDK);
                image.extend_from_slice(root.secret().expose());
                image.extend_from_slice(&[0u8; FIRST_KEY_LEN]);
                stream
            }
        };
        image.extend_from_slice(stream.as_bytes());
        image.extend_from_slice(&r.wots_index.get().to_le_bytes());
        match block {
            None => {
                image.push(0);
                image.extend_from_slice(&[0u8; 4]);
                image.extend_from_slice(&[0u8; 32]);
                // Figures flag and both values are zero when no block is
                // occupied.
                image.push(0);
                image.extend_from_slice(&[0u8; 8]);
                image.extend_from_slice(&[0u8; 8]);
            }
            Some(p) => {
                image.push(state);
                image.extend_from_slice(&p.spent_index.get().to_le_bytes());
                image.extend_from_slice(&p.digest);
                match p.figures {
                    // A block read from a version-3 image has no figures;
                    // it is written as "not recorded".
                    None => {
                        image.push(0);
                        image.extend_from_slice(&[0u8; 8]);
                        image.extend_from_slice(&[0u8; 8]);
                    }
                    Some(f) => {
                        image.push(1);
                        image.extend_from_slice(&f.reserved_balance.to_le_bytes());
                        image.extend_from_slice(&f.blk_to_live.to_le_bytes());
                    }
                }
            }
        }
    }
    // Seal the body in place, with the header as AAD, and append the tag.
    let (header, body) = image.split_at_mut(HEADER_LEN);
    let aad: Vec<u8> = header.to_vec();
    let tag = crypt::seal(key, nonce, &aad, body)?;
    image.extend_from_slice(&tag);
    debug_len_matches(image.len(), len)?;
    Ok(image)
}

/// The closed formula and the bytes written must agree; a disagreement is a
/// bug in this file, reported as `Corrupt` rather than trusted.
fn debug_len_matches(written: usize, expected: usize) -> Result<()> {
    if written == expected {
        Ok(())
    } else {
        Err(Error::Corrupt {
            what: "encoded length disagrees with the closed formula",
            offset: written,
        })
    }
}

/// A bounded cursor: every read goes through `take`, which fails closed with
/// the offset it stopped at. There is no indexing anywhere in the parser.
struct Cursor<'a> {
    rest: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn take<const N: usize>(&mut self, what: &'static str) -> Result<&'a [u8; N]> {
        match self.rest.split_first_chunk::<N>() {
            Some((head, tail)) => {
                self.rest = tail;
                self.offset += N;
                Ok(head)
            }
            None => Err(Error::Corrupt {
                what,
                offset: self.offset,
            }),
        }
    }
}

/// An image split into its regions, with the header already parsed and
/// bounded.
pub(crate) struct Framed<'a> {
    /// The file's version word: [`VERSION`] or [`V3_VERSION`]. The body
    /// parser takes its record width from it.
    pub(crate) version: u16,
    pub(crate) header: Header,
    /// The plaintext header bytes, verbatim, which are also the AAD.
    pub(crate) aad: &'a [u8],
    pub(crate) ciphertext: &'a [u8],
    pub(crate) tag: &'a [u8; TRAILER_LEN],
}

/// The first record's tag and kind from a version-1 or version-2 image, read
/// only when the image length matches that version's closed formula exactly.
///
/// Both unencrypted layouts have a 22-byte plaintext header
/// (`magic[8] | version u16 | generation u64 | count u32`), a 32-byte sha3
/// trailer, and records beginning `tag[20] | kind u8`; record widths are 94
/// and 178. The exact length check stops an encrypted image under a forged
/// version word, whose bytes at 22..42 are KDF parameters, salt and nonce,
/// from being reported as an account. The widths are literals so the old
/// geometry never follows the live constants. A short read is `None`, never
/// `Corrupt`: the version is already the answer.
///
/// Exercised against `testdata/keystore_v1_snapshot.bin` and
/// `testdata/keystore_v2_snapshot.bin`.
fn older_first_account(version: u16, image: &[u8]) -> Option<(Tag, AccountKind)> {
    const OLD_HEADER_LEN: usize = 8 + 2 + 8 + 4;
    const OLD_TRAILER_LEN: usize = 32;
    const V1_RECORD_LEN: usize = 94;
    const V2_RECORD_LEN: usize = 178;
    let record_len = match version {
        1 => V1_RECORD_LEN,
        2 => V2_RECORD_LEN,
        _ => return None,
    };
    let mut c = Cursor { rest: image, offset: 0 };
    c.take::<8>("magic").ok()?;
    c.take::<2>("version").ok()?;
    c.take::<8>("generation").ok()?;
    let count = usize::try_from(u32::from_le_bytes(*c.take::<4>("count").ok()?)).ok()?;
    let expected = count
        .checked_mul(record_len)?
        .checked_add(OLD_HEADER_LEN)?
        .checked_add(OLD_TRAILER_LEN)?;
    if count == 0 || image.len() != expected {
        return None;
    }
    let tag: Tag = *c.take::<ADDR_TAG_LEN>("first tag").ok()?;
    let kind = match c.take::<1>("first kind").ok()?[0] {
        0 => AccountKind::Derived,
        1 => AccountKind::Imported,
        _ => return None,
    };
    Some((tag, kind))
}

/// The plaintext header, as read off disk.
pub(crate) struct Header {
    pub(crate) kdf: Kdf,
    pub(crate) salt: [u8; crypt::SALT_LEN],
    pub(crate) nonce: [u8; crypt::NONCE_LEN],
}

/// Reads and dispatches the plaintext header. Needs no key, and bounds every
/// value before trusting it.
///
/// Checks the length, then the magic, then the version, then the rest.
/// [`VERSION`] and [`V3_VERSION`] are accepted; their headers share one
/// layout.
///
/// # Errors
///
/// `Range` for an image longer than [`MAX_IMAGE_LEN`]; `Corrupt` for a bad
/// magic or a short image; `UnsupportedVersion` for any other version
/// (older or newer) or an unknown KDF id; and the KDF parameter check's
/// error for out-of-range costs.
pub(crate) fn read_header(image: &[u8]) -> Result<Framed<'_>> {
    if image.len() > MAX_IMAGE_LEN {
        return Err(Error::Range {
            what: "keystore image length",
            min: MIN_IMAGE_LEN as u64,
            max: MAX_IMAGE_LEN as u64,
            got: image.len() as u64,
        });
    }
    let Some((body_and_header, tag)) = image.split_last_chunk::<TRAILER_LEN>() else {
        return Err(Error::Corrupt {
            what: "tag",
            offset: image.len(),
        });
    };
    let mut c = Cursor {
        rest: body_and_header,
        offset: 0,
    };
    let magic = c.take::<8>("magic")?;
    if *magic != MAGIC {
        return Err(Error::Corrupt {
            what: "magic",
            offset: 0,
        });
    }
    let version = u16::from_le_bytes(*c.take::<2>("version")?);
    if version != VERSION && version != V3_VERSION {
        return Err(Error::UnsupportedVersion {
            got: version,
            supported: VERSION,
            first_account: older_first_account(version, image),
        });
    }
    let kdf_id = c.take::<1>("kdf id")?[0];
    if kdf_id != crypt::KDF_ARGON2ID_V13 {
        // An unknown KDF needs an upgrade, not repair. No account is named:
        // `got` is a KDF id here, and bytes 22..42 are the salt.
        return Err(Error::UnsupportedVersion {
            got: u16::from(kdf_id),
            supported: u16::from(crypt::KDF_ARGON2ID_V13),
            first_account: None,
        });
    }
    let kdf = Kdf {
        m_cost_kib: u32::from_le_bytes(*c.take::<4>("kdf m_cost")?),
        t_cost: u32::from_le_bytes(*c.take::<4>("kdf t_cost")?),
        p_cost: u32::from_le_bytes(*c.take::<4>("kdf p_cost")?),
    }
    // Bounded before anything allocates: `m_cost` is a KiB count read from
    // an untrusted file.
    .checked()?;
    let salt = *c.take::<{ crypt::SALT_LEN }>("kdf salt")?;
    let nonce = *c.take::<{ crypt::NONCE_LEN }>("nonce")?;
    debug_len_matches(c.offset, HEADER_LEN)?;
    let (header, ciphertext) = body_and_header.split_at(HEADER_LEN);
    if ciphertext.len() < BODY_HEADER_LEN {
        return Err(Error::Corrupt {
            what: "ciphertext shorter than a body header",
            offset: HEADER_LEN,
        });
    }
    Ok(Framed {
        version,
        header: Header { kdf, salt, nonce },
        aad: header,
        ciphertext,
        tag,
    })
}

/// Parses an image read from disk, with the key already derived.
///
/// Fails closed at every step: version first, bounds before allocation, and
/// decryption before any record byte is trusted.
///
/// # Errors
///
/// Any [`read_header`] error; `WrongPassword` (from `crypt::open`) when the
/// tag does not verify; `Range` when `count` exceeds [`MAX_ACCOUNTS`]; and
/// `Corrupt`, with an offset, for any non-canonical field or a record that
/// does not reproduce its stored identity.
pub(crate) fn parse_with_key(image: &[u8], key: &[u8; crypt::KEY_LEN]) -> Result<Parsed> {
    let f = read_header(image)?;
    let aad: Vec<u8> = f.aad.to_vec();
    let mut body: Zeroizing<Vec<u8>> = Zeroizing::new(f.ciphertext.to_vec());
    // One error for a wrong password, a flipped bit and a tampered header;
    // see `crypt::open`.
    crypt::open(key, &f.header.nonce, &aad, &mut body, f.tag)?;

    // The bytes are authenticated from here on. The checks below catch
    // writer bugs and keep one image per state.
    let mut c = Cursor {
        rest: &body,
        offset: 0,
    };
    let generation = u64::from_le_bytes(*c.take::<8>("generation")?);
    let count = u32::from_le_bytes(*c.take::<4>("count")?);
    let count = usize::try_from(count).map_err(|_| Error::Corrupt {
        what: "count",
        offset: c.offset,
    })?;
    let master_present = c.take::<1>("master present")?[0];
    let master_bytes = c.take::<{ SEED_LEN }>("master seed")?;
    let master = match master_present {
        0 => {
            if master_bytes.iter().any(|&b| b != 0) {
                return Err(Error::Corrupt {
                    what: "master seed present flag is 0 with non-zero bytes",
                    offset: c.offset,
                });
            }
            None
        }
        1 => Some(Secret::new(*master_bytes)),
        _ => {
            return Err(Error::Corrupt {
                what: "master seed present flag is not 0 or 1",
                offset: c.offset,
            })
        }
    };
    if count > MAX_ACCOUNTS {
        return Err(Error::Range {
            what: "keystore account count",
            min: 0,
            max: MAX_ACCOUNTS as u64,
            got: count as u64,
        });
    }
    // A version-3 body is `45 + 178 * count`, a version-4 body
    // `45 + 195 * count`.
    let expected = body_len_at(f.version, count).ok_or(Error::Corrupt {
        what: "image length overflow",
        offset: c.offset,
    })?;
    if body.len() != expected {
        return Err(Error::Corrupt {
            what: "image length disagrees with count",
            offset: c.offset,
        });
    }

    let mut slots: BTreeMap<Tag, Slot> = BTreeMap::new();
    let mut prev: Option<Tag> = None;
    for _ in 0..count {
        let record_offset = c.offset;
        let tag: Tag = *c.take::<ADDR_TAG_LEN>("tag")?;
        if let Some(p) = prev {
            if tag <= p {
                return Err(Error::Corrupt {
                    what: "records not strictly ascending by tag",
                    offset: record_offset,
                });
            }
        }
        prev = Some(tag);
        let kind = c.take::<1>("kind")?[0];
        // For an imported or SDK record these 32 bytes are the root, so the
        // stack copy is zeroized after `Secret::new` copies it (I6).
        let body: Zeroizing<[u8; 32]> = Zeroizing::new(*c.take::<32>("body")?);
        let first = *c.take::<FIRST_KEY_LEN>("first key components")?;
        let stream_id = StreamId::from_bytes(*c.take::<ADDR_TAG_LEN>("stream identity")?);
        let wots_index = WotsIndex::from_raw(u32::from_le_bytes(*c.take::<4>("wots_index")?));
        let pending_flag = c.take::<1>("pending flag")?[0];
        let spent_index = u32::from_le_bytes(*c.take::<4>("spent_index")?);
        let digest = *c.take::<32>("digest")?;
        // Figures exist only in a version-4 record. A version-3 record ends
        // at the digest; its figures are absent (`None`), not zero.
        let figures_bytes = if f.version == V3_VERSION {
            None
        } else {
            let flag = c.take::<1>("figures flag")?[0];
            let reserved_balance = u64::from_le_bytes(*c.take::<8>("reserved_balance")?);
            let blk_to_live = u64::from_le_bytes(*c.take::<8>("blk_to_live")?);
            Some((flag, reserved_balance, blk_to_live))
        };

        // Canonical rules: the state byte is 0, 1 or 2 (2 only in version 4);
        // every block field is zero when no block is occupied;
        // `spent_index + 1 == wots_index` when one is; the figures flag is 0
        // or 1, with zero figures when 0.
        let figures = match figures_bytes {
            None => None,
            Some((0, 0, 0)) => None,
            Some((0, _, _)) => {
                return Err(Error::Corrupt {
                    what: "figures not zero while figures == 0",
                    offset: record_offset,
                })
            }
            Some((1, reserved_balance, blk_to_live)) => Some(Figures {
                reserved_balance,
                blk_to_live,
            }),
            Some(_) => {
                return Err(Error::Corrupt {
                    what: "figures flag",
                    offset: record_offset,
                })
            }
        };
        let (pending, settled) = match pending_flag {
            0 => {
                if spent_index != 0 || digest != [0u8; 32] || figures_bytes.is_some_and(|(fl, _, _)| fl != 0) {
                    return Err(Error::Corrupt {
                        what: "pending fields not zero while pending == 0",
                        offset: record_offset,
                    });
                }
                (None, None)
            }
            1 | 2 if pending_flag == 1 || f.version != V3_VERSION => {
                if spent_index.checked_add(1) != Some(wots_index.get()) {
                    return Err(Error::Corrupt {
                        what: "pending index does not precede wots_index by one",
                        offset: record_offset,
                    });
                }
                let block = Pending {
                    spent_index: WotsIndex::from_raw(spent_index),
                    digest,
                    figures,
                };
                if pending_flag == 1 {
                    (Some(block), None)
                } else {
                    (None, Some(block))
                }
            }
            _ => {
                return Err(Error::Corrupt {
                    what: "pending flag",
                    offset: record_offset,
                })
            }
        };

        let record = match kind {
            KIND_DERIVED => {
                let (idx, pad) = body.split_first_chunk::<4>().ok_or(Error::Corrupt {
                    what: "body",
                    offset: record_offset,
                })?;
                if pad.iter().any(|b| *b != 0) {
                    return Err(Error::Corrupt {
                        what: "derived body padding not zero",
                        offset: record_offset,
                    });
                }
                if first.iter().any(|b| *b != 0) {
                    return Err(Error::Corrupt {
                        what: "derived first-key field not zero",
                        offset: record_offset,
                    });
                }
                AccountRecord::Derived {
                    tag,
                    account_index: u32::from_le_bytes(*idx),
                    stream_id,
                    wots_index,
                }
            }
            KIND_IMPORTED => AccountRecord::Imported {
                tag,
                root: Secret::<SEED_LEN>::new(*body),
                first_key: first,
                stream_id,
                wots_index,
            },
            KIND_SDK => {
                if first.iter().any(|b| *b != 0) {
                    return Err(Error::Corrupt {
                        what: "sdk first-key field not zero",
                        offset: record_offset,
                    });
                }
                AccountRecord::Sdk {
                    tag,
                    root: Secret::<SEED_LEN>::new(*body),
                    stream_id,
                    wots_index,
                }
            }
            _ => {
                return Err(Error::Corrupt {
                    what: "kind",
                    offset: record_offset,
                })
            }
        };
        // The verifying constructor: a record whose stored components or
        // identity disagree with its root is refused, reported as `Corrupt`
        // at this record's offset.
        let account = Account::restore_from_record(record).map_err(|e| match e {
            Error::FirstAddressNotReproduced => Error::Corrupt {
                what: "imported record: the root does not reproduce the stored tag",
                offset: record_offset,
            },
            Error::StreamIdNotReproduced => Error::Corrupt {
                what: "imported record: the root does not reproduce the stored key-stream identity",
                offset: record_offset,
            },
            other => other,
        })?;
        slots.insert(
            tag,
            Slot {
                account,
                pending,
                settled,
            },
        );
    }
    if !c.rest.is_empty() {
        // Unreachable given the length check above; kept as a backstop.
        return Err(Error::Corrupt {
            what: "trailing bytes",
            offset: c.offset,
        });
    }
    Ok(Parsed {
        generation,
        slots,
        master,
    })
}

impl fmt::Debug for Parsed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Parsed")
            .field("generation", &self.generation)
            .field("accounts", &self.slots.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    //! The format known-answer tests: a hand-assembled image equals `encode`'s
    //! output and parses back. Runs under Miri, which can reach implicit panic
    //! paths in the parser.
    //!
    //! # Where the expected values come from
    //!
    //! The encoder computes every tag and stream identity from the account.
    //! The hand-assembled side uses group F's fixture literals, so the two are
    //! independent:
    //!
    //! | value | this side | fixture |
    //! | --- | --- | --- |
    //! | imported tag | `05ff…800f` | `F-address-widths.account_tag` |
    //! | imported stream | `2587…ea8c` | `F-address-widths.wots_address[20..40]` at `wots_index: 0` |
    //! | imported components | `include_bytes!` tail | `F-widths_account_address.bin[2144..2208]` |
    //! | derived tag | `4d9b…fbe9` | `F-derive-account-1.tag` |
    //! | derived stream | computed from `F-derive-account-1.seed` | not recorded — see below |
    //!
    //! Group F records no stream identity for `F-derive-account-1`, so this
    //! side computes it by a different route: `derive_wots_key` on the
    //! fixture's account `seed`, where the encoder goes through
    //! `Account::derive` from the master. `tests/derive.rs` pins
    //! `derive_wots_key` itself against the fixture.
    use super::*;
    use crate::consts::WOTS_ADDR_LEN;
    // Not under Miri: its only readers are gated out under Miri.
    #[cfg(not(miri))]
    use crate::consts::PK_LEN;

    /// `F-derive-account-1`'s master seed (`group_f_derivation.json`),
    /// account position 1. The hand-assembled side uses the fixture's tag
    /// literal, independent of `Account::derive`.
    const DERIVED_MASTER: [u8; SEED_LEN] = [
        0x40, 0x8b, 0x28, 0x5c, 0x12, 0x38, 0x36, 0x00, 0x4f, 0x4b, 0x88, 0x42, 0xc8, 0x93,
        0x24, 0xc1, 0xf0, 0x13, 0x82, 0x45, 0x0c, 0x0d, 0x43, 0x9a, 0xf3, 0x45, 0xba, 0x7f,
        0xc4, 0x9a, 0xcf, 0x70,
    ];
    // Not under Miri: read only by `expected_body`, whose caller is gated
    // out under Miri.
    #[cfg(not(miri))]
    const DERIVED_TAG: [u8; ADDR_TAG_LEN] = [
        0x4d, 0x9b, 0x31, 0xe4, 0x78, 0x74, 0x66, 0x8e, 0x45, 0x89, 0x5a, 0x1b, 0x93, 0x38,
        0x8e, 0x5a, 0xa9, 0xb6, 0xfb, 0xe9,
    ];
    /// `F-derive-account-1`'s account seed, for the independent route to its
    /// stream identity.
    // Not under Miri: read only by `expected_body`.
    #[cfg(not(miri))]
    const DERIVED_SEED: [u8; SEED_LEN] = [
        0xdc, 0x91, 0x7b, 0x56, 0x7b, 0x86, 0x0a, 0xfb, 0xb3, 0x6d, 0x0c, 0xcd, 0x87, 0xd0,
        0x4c, 0xac, 0x46, 0x63, 0x52, 0x24, 0x50, 0xee, 0xc8, 0x13, 0x7f, 0xe2, 0xdd, 0x04,
        0xd0, 0xff, 0x93, 0xb1,
    ];

    /// `F-address-widths`: the account seed, the 2208-byte first address, its
    /// account tag and its rotation-0 address hash. The address is embedded
    /// from the fixture file rather than transcribed.
    const IMPORTED_ROOT: [u8; SEED_LEN] = [
        0x66, 0x4e, 0xdd, 0x3d, 0x3b, 0xf1, 0xa0, 0xe2, 0x9c, 0x93, 0x98, 0xdd, 0xc1, 0x61,
        0x14, 0xab, 0xc6, 0xd6, 0xb4, 0x32, 0xb1, 0xe5, 0xe4, 0xde, 0x26, 0x7c, 0x7e, 0x2a,
        0xe5, 0x3f, 0x58, 0x0b,
    ];
    const IMPORTED_ADDRESS: &[u8; WOTS_ADDR_LEN] =
        include_bytes!("../../../../fixtures/F-widths_account_address.bin");
    const IMPORTED_TAG: [u8; ADDR_TAG_LEN] = [
        0x05, 0xff, 0x0f, 0x69, 0xd4, 0xc1, 0xcd, 0x68, 0x2e, 0xd3, 0x34, 0x1c, 0x0b, 0x77,
        0x73, 0x05, 0x4b, 0x58, 0x80, 0x0f,
    ];
    // Not under Miri: read only by `expected_body`.
    #[cfg(not(miri))]
    const IMPORTED_STREAM: [u8; ADDR_TAG_LEN] = [
        0x25, 0x87, 0x87, 0x8a, 0xd3, 0x4d, 0x29, 0xcf, 0x2e, 0x4b, 0xe4, 0x83, 0x86, 0xae,
        0xc3, 0xa0, 0xc2, 0xa7, 0xea, 0x8c,
    ];

    fn two_accounts() -> Vec<(Tag, Account, Option<Pending>)> {
        let imported = Account::import(Secret::new(IMPORTED_ROOT), IMPORTED_ADDRESS)
            .expect("F-address-widths' root and first address are a pair");
        let derived = Account::derive(&Secret::new(DERIVED_MASTER), 1);
        let derived_tag = derived.tag();
        vec![
            (imported.tag(), imported, None),
            (derived_tag, derived, None),
        ]
    }

    fn refs(accts: &[(Tag, Account, Option<Pending>)]) -> Vec<RecordRef<'_>> {
        accts
            .iter()
            .map(|(tag, a, p)| RecordRef {
                tag: *tag,
                account: a,
                wots_index: a.wots_index(),
                pending: *p,
                settled: None,
            })
            .collect()
    }

    /// The plaintext header, assembled by hand, independent of the encoder.
    // Not under Miri: used only by the gated
    // `known_answer_image_for_two_accounts`.
    #[cfg(not(miri))]
    fn expected_header(nonce: &[u8; crypt::NONCE_LEN]) -> Vec<u8> {
        let mut h: Vec<u8> = Vec::new();
        h.extend_from_slice(b"MCMKSTOR");
        h.extend_from_slice(&4u16.to_le_bytes());
        h.push(1); // kdf id: Argon2id v0x13
        h.extend_from_slice(&65536u32.to_le_bytes());
        h.extend_from_slice(&3u32.to_le_bytes());
        h.extend_from_slice(&1u32.to_le_bytes());
        h.extend_from_slice(&TEST_SALT);
        h.extend_from_slice(nonce);
        h
    }

    /// The plaintext body, assembled by hand, independent of the encoder.
    ///
    /// The ciphertext cannot be hand-assembled, so the test compares this
    /// canonical plaintext with the encoder's output after decryption. The
    /// cipher and KDF themselves are checked against published vectors:
    /// `chacha20poly1305_matches_rfc8439` (RFC 8439 §2.8.2) and
    /// `argon2id_v13_matches_the_rfc9106_vector` (RFC 9106 §5.3, which pins
    /// the algorithm, version and parameter mapping but not the parameter
    /// point `test_key` uses).
    // Not under Miri: used only by the gated
    // `known_answer_image_for_two_accounts`.
    #[cfg(not(miri))]
    fn expected_body(generation: u64) -> Vec<u8> {
        let mut expected: Vec<u8> = Vec::new();
        expected.extend_from_slice(&generation.to_le_bytes());
        expected.extend_from_slice(&2u32.to_le_bytes());
        expected.push(0);
        expected.extend_from_slice(&[0u8; SEED_LEN]);
        // record 1: imported (tag 05ff.. sorts first), root, the faddress
        // tail as components, the recorded stream, index 0, no pending
        expected.extend_from_slice(&IMPORTED_TAG);
        expected.push(1);
        expected.extend_from_slice(&IMPORTED_ROOT);
        expected.extend_from_slice(&IMPORTED_ADDRESS[PK_LEN..]);
        expected.extend_from_slice(&IMPORTED_STREAM);
        expected.extend_from_slice(&0u32.to_le_bytes());
        expected.push(0);
        expected.extend_from_slice(&[0u8; 4]);
        expected.extend_from_slice(&[0u8; 32]);
        // Version 4's tail: figures flag, reserved_balance and blk_to_live,
        // all zero with no block.
        expected.push(0);
        expected.extend_from_slice(&[0u8; 8]);
        expected.extend_from_slice(&[0u8; 8]);
        // record 2: derived, the fixture tag, account_index 1 + 28 zeros, a
        // zero first-key field, and the stream reached from the fixture seed
        expected.extend_from_slice(&DERIVED_TAG);
        expected.push(0);
        expected.extend_from_slice(&1u32.to_le_bytes());
        expected.extend_from_slice(&[0u8; 28]);
        expected.extend_from_slice(&[0u8; FIRST_KEY_LEN]);
        // Written as `derive_wots_key(seed, 0).tag()`, not `stream_id(seed)`,
        // so the expected value does not share the encoder's wrapper and the
        // rotation (0) is stated explicitly.
        expected.extend_from_slice(&crate::derive::derive_wots_key(&Secret::new(DERIVED_SEED), 0).tag());
        expected.extend_from_slice(&0u32.to_le_bytes());
        expected.push(0);
        expected.extend_from_slice(&[0u8; 4]);
        expected.extend_from_slice(&[0u8; 32]);
        // Version 4's tail: figures flag, reserved_balance and blk_to_live,
        // all zero with no block.
        expected.push(0);
        expected.extend_from_slice(&[0u8; 8]);
        expected.extend_from_slice(&[0u8; 8]);
        expected
    }

    pub(super) const TEST_SALT: [u8; crypt::SALT_LEN] = [0x5A; crypt::SALT_LEN];
    // There is no test nonce seed: the KAT uses the literal `KAT_NONCE`, so
    // the expected header does not depend on `crypt::nonce_for`.

    /// The key these tests encrypt under, derived once and cached.
    ///
    /// Derived at `CHEAP_FOR_TESTS` because Miri takes hours per derivation
    /// at `Kdf::RECOMMENDED`. Every assertion reaches the image through
    /// `parse_with_key`, which takes the key directly and never re-derives it
    /// from the header.
    ///
    /// `seal_at` still writes `Kdf::RECOMMENDED` into the header, so the
    /// header's parameters do not match this key. That is safe only while no
    /// test here derives a key from a header it read.
    fn test_key() -> &'static Zeroizing<[u8; crypt::KEY_LEN]> {
        use std::sync::OnceLock;
        static KEY: OnceLock<Zeroizing<[u8; crypt::KEY_LEN]>> = OnceLock::new();
        KEY.get_or_init(|| {
            crypt::derive_key(b"format-module-test-password", &TEST_SALT, Kdf::CHEAP_FOR_TESTS)
                .expect("derive")
        })
    }

    /// The KAT's nonce, a literal rather than `nonce_for(seed, generation)`,
    /// so the expected header is independent of the encoder. `nonce_for` is
    /// checked by `the_nonce_does_not_repeat_across_a_forked_store`.
    const KAT_NONCE: [u8; crypt::NONCE_LEN] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
    ];

    /// Seals `records` under the test key and `KAT_NONCE`.
    ///
    /// The header field must stay `Kdf::RECOMMENDED`, not `CHEAP_FOR_TESTS`:
    /// `encode` takes the parameters and the key separately, so this costs
    /// nothing. The `cheapened` row in
    /// `parser_refuses_each_malformation_with_the_right_variant` writes
    /// `m_cost = 8` and expects `WrongPassword`; with `CHEAP_FOR_TESTS`
    /// (`m_cost_kib` 8) that write would change nothing.
    fn seal_at(records: &[RecordRef<'_>], generation: u64) -> Zeroizing<Vec<u8>> {
        let nonce = KAT_NONCE;
        encode(
            records,
            generation,
            None,
            Kdf::RECOMMENDED,
            &TEST_SALT,
            test_key(),
            &nonce,
        )
        .expect("encode")
    }

    /// The nonce does not repeat across a forked store.
    ///
    /// Two copies of a store (for example a restored backup) share a salt and
    /// therefore a key, and both can advance from generation *N* with
    /// different contents. A bare generation counter would then reuse a
    /// nonce under one key, which leaks the XOR of the two bodies and the
    /// Poly1305 key.
    #[test]
    fn the_nonce_does_not_repeat_across_a_forked_store() {
        let fork_a = [0x01u8; crypt::NONCE_SEED_LEN];
        let fork_b = [0x02u8; crypt::NONCE_SEED_LEN];
        // The fork: same generation, different opens.
        assert_ne!(
            crypt::nonce_for(&fork_a, 7),
            crypt::nonce_for(&fork_b, 7),
            "two opens of a forked store produced the SAME nonce at one generation. Under a \
             shared key that is keystream reuse -- the one way to break this AEAD with correct \
             code everywhere else. A bare generation counter does exactly this."
        );
        // Within one open the generation is what moves it.
        assert_ne!(
            crypt::nonce_for(&fork_a, 7),
            crypt::nonce_for(&fork_a, 8),
            "the nonce does not change with the generation"
        );
        // And it is deterministic.
        assert_eq!(crypt::nonce_for(&fork_a, 7), crypt::nonce_for(&fork_a, 7));
    }

    // ---- Published test vectors ------------------------------------------
    //
    // `published_vector_literals_match_the_vendored_rfc_text` compares every
    // byte below with the vendored standard's text, and each vendored file
    // with its recorded SHA-256. Whether the vendored copy matches the
    // publisher's is checked by hand (`docs/standards/README.md`).

    /// RFC 9106 §5.3, "Argon2id version number 19": the inputs.
    const RFC9106_PASSWORD: [u8; 32] = [0x01; 32];
    const RFC9106_SALT: [u8; 16] = [0x02; 16];
    const RFC9106_SECRET: [u8; 8] = [0x03; 8];
    const RFC9106_ASSOCIATED_DATA: [u8; 12] = [0x04; 12];
    /// "Memory: 32 KiB, Passes: 3, Parallelism: 4 lanes", in the header
    /// struct's roles, so the vector runs through the same mapping a store
    /// does.
    const RFC9106_KDF: Kdf = Kdf {
        m_cost_kib: 32,
        t_cost: 3,
        p_cost: 4,
    };
    /// RFC 9106 §5.3's 32-byte tag.
    const RFC9106_TAG: [u8; 32] = [
        0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53, 0xc9,
        0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01, 0xe6, 0x59,
    ];
    /// RFC 8439 §2.8.2's AEAD test vector. The nonce is the RFC's "32-bit
    /// fixed-common part" followed by its "IV".
    const RFC8439_KEY: [u8; 32] = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    ];
    const RFC8439_NONCE: [u8; 12] = [
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    ];
    const RFC8439_AAD: [u8; 12] = [
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    ];
    const RFC8439_PLAINTEXT: &[u8; 114] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const RFC8439_CIPHERTEXT: [u8; 114] = [
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
        0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16,
    ];
    const RFC8439_TAG: [u8; 16] = [
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
    ];

    /// The vendored standards, byte for byte (`docs/standards/README.md`
    /// gives each one's URL and hash). `include_bytes!` so the hash covers
    /// the raw file, including RFC 9106's UTF-8 byte-order mark; compile-time
    /// inclusion also works under Miri, which forbids filesystem access.
    const RFC9106_BYTES: &[u8] =
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/standards/rfc9106.txt"));
    const RFC8439_BYTES: &[u8] =
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/standards/rfc8439.txt"));
    const STANDARDS_README: &str =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/standards/README.md"));
    /// SHA-256 of each vendored file. The README states the same values, and
    /// the provenance test checks that they agree.
    const RFC9106_SHA256: [u8; 32] = [
        0x85, 0x5c, 0x06, 0xf0, 0x60, 0x37, 0x9e, 0x34, 0x28, 0x5e, 0x83, 0xa2, 0x17, 0xe9, 0x06, 0x9b,
        0x5c, 0x72, 0xe1, 0x61, 0xa1, 0xe5, 0x4d, 0xf9, 0xaf, 0x5c, 0xd8, 0x8d, 0xbb, 0x23, 0x1f, 0x31,
    ];
    const RFC8439_SHA256: [u8; 32] = [
        0x25, 0xbe, 0xf7, 0x0f, 0xbf, 0x7a, 0x07, 0xff, 0x45, 0xc2, 0xfe, 0x4c, 0xb7, 0xc6, 0xce, 0x95,
        0x4e, 0xac, 0x68, 0x74, 0x13, 0xd8, 0x61, 0x06, 0x03, 0x26, 0x8b, 0x4e, 0x44, 0x15, 0x32, 0x4c,
    ];

    fn lower_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The body of one numbered section of an RFC text, from its heading to
    /// the named next heading, both matched at column zero (the table of
    /// contents repeats them indented).
    ///
    /// # Panics
    ///
    /// If either heading does not occur exactly once at column zero.
    fn rfc_section<'a>(text: &'a str, heading: &str, next_heading: &str) -> &'a str {
        let start = format!("\n{heading}\n");
        let end = format!("\n{next_heading}\n");
        assert_eq!(
            text.matches(&start).count(),
            1,
            "heading {heading:?} does not occur exactly once at column zero; the section \
             extractor would read the wrong span"
        );
        assert_eq!(
            text.matches(&end).count(),
            1,
            "heading {next_heading:?} does not occur exactly once at column zero; the section \
             extractor would read the wrong span"
        );
        let i = text.find(&start).expect("counted above");
        let j = text[i..].find(&end).expect("counted above") + i;
        &text[i..j]
    }

    /// Collapses all whitespace, including RFC 8439's form feeds, to single
    /// spaces. Page headers remain; every needle is anchored on a label.
    fn normalize_whitespace(s: &str) -> String {
        s.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// The bytes between two labels in normalized RFC text.
    ///
    /// # Panics
    ///
    /// If either label is not unique in the section, or any token between
    /// them is not exactly two hex digits.
    fn hex_run_between(ws: &str, label: &str, next_label: &str) -> Vec<u8> {
        assert_eq!(ws.matches(label).count(), 1, "label {label:?} is not unique in the section");
        assert_eq!(
            ws.matches(next_label).count(),
            1,
            "label {next_label:?} is not unique in the section"
        );
        let i = ws.find(label).expect("counted") + label.len();
        let j = ws[i..].find(next_label).expect("counted") + i;
        hex_tokens(&ws[i..j], label)
    }

    /// As [`hex_run_between`], to the end of the section.
    fn hex_run_to_end(ws: &str, label: &str) -> Vec<u8> {
        assert_eq!(ws.matches(label).count(), 1, "label {label:?} is not unique in the section");
        let i = ws.find(label).expect("counted") + label.len();
        hex_tokens(&ws[i..], label)
    }

    fn hex_tokens(run: &str, label: &str) -> Vec<u8> {
        let bytes: Vec<u8> = run
            .split_whitespace()
            .map(|tok| {
                assert!(
                    tok.len() == 2 && tok.chars().all(|c| c.is_ascii_hexdigit()),
                    "after {label:?}: token {tok:?} is not two hex digits -- the run is not a \
                     bare hex dump, so the section or the label is wrong"
                );
                u8::from_str_radix(tok, 16).expect("two hex digits, checked")
            })
            .collect();
        assert!(!bytes.is_empty(), "after {label:?}: no hex at all");
        bytes
    }

    /// The RFC 8439 hexdump rows (`NNN` offset, up to sixteen bytes) that
    /// `bytes` would produce, the first prefixed with the table's label. The
    /// ASCII gutter after the bytes is not reproduced.
    fn hexdump_rows(label: &str, bytes: &[u8]) -> Vec<String> {
        bytes
            .chunks(16)
            .enumerate()
            .map(|(i, row)| {
                let hex: Vec<String> = row.iter().map(|b| format!("{b:02x}")).collect();
                let hex = hex.join(" ");
                if i == 0 {
                    format!("{label} 000 {hex}")
                } else {
                    format!("{:03} {hex}", i * 16)
                }
            })
            .collect()
    }

    /// The KDF reproduces RFC 9106 §5.3's Argon2id tag through
    /// `crypt::argon2id_v13`, the same parameter mapping `derive_key` uses.
    ///
    /// A wrong parameter role, version or algorithm, a dropped secret or
    /// associated data, or an `argon2` crate that disagrees with the RFC
    /// each give a different tag. It does not pin `Kdf::RECOMMENDED`'s
    /// values; `expected_header` does.
    ///
    /// If this fails, do not edit `RFC9106_TAG` to match: the literal is
    /// checked against the vendored RFC text separately.
    #[test]
    fn argon2id_v13_matches_the_rfc9106_vector() {
        let mut out = [0u8; 32];
        crypt::argon2id_v13(
            RFC9106_KDF,
            &RFC9106_SECRET,
            &RFC9106_ASSOCIATED_DATA,
            &RFC9106_PASSWORD,
            &RFC9106_SALT,
            &mut out,
        )
        .expect("argon2id at RFC 9106's parameters");
        assert_eq!(
            out,
            RFC9106_TAG,
            "Argon2id disagrees with RFC 9106 §5.3's recorded tag at m=32 KiB, t=3, p=4, an \
             8-byte secret and 12 bytes of associated data. Three things can cause this and only \
             one is fixed by editing code: the literal was transcribed wrong (then \
             published_vector_literals_match_the_vendored_rfc_text is red too -- start there); \
             crypt::argon2id_v13's mapping from Kdf to Argon2's parameters, its algorithm or its \
             version is wrong (this red alone); or argon2 0.5.3 disagrees with the standard \
             (report it upstream). Do NOT edit RFC9106_TAG to match this build: an expectation \
             derived from the observed value certifies the observation, which this anchor exists \
             to prevent."
        );
        println!(
            "  KDF: RFC 9106 §5.3 Argon2id tag reproduced through crypt::argon2id_v13 (32 KiB, 3 \
             passes, 4 lanes, v0x13, secret and associated data driven)"
        );
    }

    /// `derive_key` agrees with `crypt::argon2id_v13` at one cheap parameter
    /// point, with an empty secret and no associated data.
    ///
    /// This checks only that `derive_key` still goes through the function
    /// the RFC 9106 test covers. Whether the mapping is right is
    /// `argon2id_v13_matches_the_rfc9106_vector`'s check; that there is only
    /// one route to Argon2 is checked in `tests/invariants.rs`.
    #[test]
    fn derive_key_agrees_with_the_anchored_argon2id_at_cheap_parameters() {
        let password = b"a password long enough to pass the floor";
        let mut direct = [0u8; crypt::KEY_LEN];
        crypt::argon2id_v13(Kdf::CHEAP_FOR_TESTS, &[], &[], password, &TEST_SALT, &mut direct)
            .expect("argon2id");
        let via = crypt::derive_key(password, &TEST_SALT, Kdf::CHEAP_FOR_TESTS).expect("derive");
        assert_eq!(
            *via,
            direct,
            "derive_key no longer routes through crypt::argon2id_v13, so the RFC 9106 anchor no \
             longer says anything about the wallet's entry point. This check owns ONLY that call \
             structure -- it compares derive_key to argon2id_v13 at the same parameters and stays \
             green if the mapping inside argon2id_v13 is wrong; \
             argon2id_v13_matches_the_rfc9106_vector owns whether that mapping is right."
        );
    }

    /// The vector literals above match the vendored RFC texts, and each
    /// vendored file matches its recorded SHA-256.
    ///
    /// Every replayed byte is parsed back out of its RFC section with needles
    /// built from the literals. The hash shows only that the vendored copy
    /// has not changed, not that it matches the publisher's copy.
    ///
    /// RFC 9106 §5's three vectors share every input and differ only in the
    /// variant line and the tag, so the section is pinned to §5.3 first.
    #[test]
    fn published_vector_literals_match_the_vendored_rfc_text() {
        // 1. The vendored files match their recorded hashes, and the README
        //    states the same values.
        assert_eq!(
            crate::backend::native::sha256(RFC9106_BYTES),
            RFC9106_SHA256,
            "docs/standards/rfc9106.txt no longer hashes to the value recorded when it was \
             fetched (see docs/standards/README.md). That says the vendored copy moved, \
             NOT that it is or is not what rfc-editor.org serves -- this literal was typed from \
             the same fetch, so a wrong fetch is wrong on both sides and green here. Re-verify \
             by hand: curl -s https://www.rfc-editor.org/rfc/rfc9106.txt | shasum -a 256. Do \
             not update this literal to the file's new hash."
        );
        assert_eq!(
            crate::backend::native::sha256(RFC8439_BYTES),
            RFC8439_SHA256,
            "docs/standards/rfc8439.txt no longer hashes to the value recorded when it was \
             fetched (see docs/standards/README.md). The vendored copy moved; re-verify \
             against the publisher by hand and do not update this literal to the file's new \
             hash."
        );
        for (name, hash) in [("rfc9106", RFC9106_SHA256), ("rfc8439", RFC8439_SHA256)] {
            assert!(
                STANDARDS_README.contains(&lower_hex(&hash)),
                "docs/standards/README.md does not carry the {name} hash this test asserts; the \
                 copy a reader follows has drifted from the asserted one"
            );
        }
        let rfc9106 = core::str::from_utf8(RFC9106_BYTES).expect("vendored rfc9106.txt is UTF-8");
        let rfc8439 = core::str::from_utf8(RFC8439_BYTES).expect("vendored rfc8439.txt is UTF-8");

        // 2. RFC 9106 §5.3: the version, the parameters in their roles, the
        //    four inputs and the tag.
        let ws = normalize_whitespace(rfc_section(
            rfc9106,
            "5.3.  Argon2id Test Vectors",
            "6.  IANA Considerations",
        ));
        let version = format!("Argon2id version number {}", u32::from(argon2::Version::V0x13));
        assert!(
            ws.contains(&version),
            "the extracted RFC 9106 section does not say {version:?}: either the section \
             extractor read the wrong span or the vector is not for the version this wallet \
             drives"
        );
        assert_eq!(
            ws.matches("version number").count(),
            1,
            "the extracted RFC 9106 section carries more than one vector; the span is wider than \
             §5.3 and the input comparisons below could pass on a neighbouring variant's bytes"
        );
        assert_eq!(
            ws.matches("Tag:").count(),
            1,
            "the extracted RFC 9106 section carries more than one tag; the span is wider than §5.3"
        );
        let params = format!(
            "Memory: {} KiB, Passes: {}, Parallelism: {} lanes, Tag length: {} bytes",
            RFC9106_KDF.m_cost_kib,
            RFC9106_KDF.t_cost,
            RFC9106_KDF.p_cost,
            RFC9106_TAG.len()
        );
        assert!(
            ws.contains(&params),
            "RFC 9106 §5.3 does not state the parameters as {params:?}; a field of RFC9106_KDF is \
             in the wrong role or has the wrong value"
        );
        assert_eq!(
            hex_run_between(&ws, "Password[32]:", "Salt[16]:"),
            RFC9106_PASSWORD,
            "RFC9106_PASSWORD is not the password RFC 9106 §5.3 records (transcription)"
        );
        assert_eq!(
            hex_run_between(&ws, "Salt[16]:", "Secret[8]:"),
            RFC9106_SALT,
            "RFC9106_SALT is not the salt RFC 9106 §5.3 records (transcription)"
        );
        assert_eq!(
            hex_run_between(&ws, "Secret[8]:", "Associated data[12]:"),
            RFC9106_SECRET,
            "RFC9106_SECRET is not the secret RFC 9106 §5.3 records (transcription)"
        );
        assert_eq!(
            hex_run_between(&ws, "Associated data[12]:", "Pre-hashing digest:"),
            RFC9106_ASSOCIATED_DATA,
            "RFC9106_ASSOCIATED_DATA is not the associated data RFC 9106 §5.3 records \
             (transcription)"
        );
        assert_eq!(
            hex_run_to_end(&ws, "Tag:"),
            RFC9106_TAG,
            "RFC9106_TAG is not the tag RFC 9106 §5.3 records -- a transcription error in the \
             literal, not a defect in the KDF; argon2id_v13_matches_the_rfc9106_vector will be \
             red for the same reason"
        );

        // 3. RFC 8439 §2.8.2: every value as the RFC's hexdump rows, the tag
        //    as its colon-separated line, and the nonce as its two labelled
        //    parts.
        let ws = normalize_whitespace(rfc_section(
            rfc8439,
            "2.8.2.  Example and Test Vector for AEAD_CHACHA20_POLY1305",
            "3.  Implementation Advice",
        ));
        for (label, bytes) in [
            ("Plaintext:", &RFC8439_PLAINTEXT[..]),
            ("AAD:", &RFC8439_AAD[..]),
            ("Key:", &RFC8439_KEY[..]),
            ("Ciphertext:", &RFC8439_CIPHERTEXT[..]),
            ("32-bit fixed-common part:", &RFC8439_NONCE[..4]),
            ("IV:", &RFC8439_NONCE[4..]),
        ] {
            for row in hexdump_rows(label, bytes) {
                assert!(
                    ws.contains(&row),
                    "RFC 8439 §2.8.2's {label} table does not carry the row {row:?}; the RFC8439_* \
                     literal for it is not the RFC's (transcription), or the nonce is not \
                     fixed-common-part followed by IV"
                );
            }
        }
        assert_eq!(ws.matches("Tag:").count(), 1, "RFC 8439 §2.8.2 does not carry exactly one Tag:");
        let tag_line = ws[ws.find("Tag:").expect("counted") + "Tag:".len()..]
            .split_whitespace()
            .next()
            .expect("a token after Tag:");
        let tag: Vec<u8> = tag_line
            .split(':')
            .map(|tok| {
                assert!(
                    tok.len() == 2 && tok.chars().all(|c| c.is_ascii_hexdigit()),
                    "RFC 8439's tag line token {tok:?} is not two hex digits"
                );
                u8::from_str_radix(tok, 16).expect("two hex digits, checked")
            })
            .collect();
        assert_eq!(
            tag,
            RFC8439_TAG,
            "RFC8439_TAG is not the tag RFC 8439 §2.8.2 records -- a transcription error in the \
             literal, not a defect in the AEAD"
        );
        println!(
            "  provenance: both vendored RFC texts hash as recorded at fetch; RFC 9106 §5.3 and \
             RFC 8439 §2.8.2 each parsed back byte for byte against the literals replayed"
        );
    }

    /// The AEAD reproduces RFC 8439 §2.8.2's test vector.
    ///
    /// The format round trip cannot detect a primitive that is consistently
    /// wrong; a published vector can.
    #[test]
    fn chacha20poly1305_matches_rfc8439() {
        let mut buf = RFC8439_PLAINTEXT.to_vec();
        let tag = crypt::seal(&RFC8439_KEY, &RFC8439_NONCE, &RFC8439_AAD, &mut buf).expect("seal");
        // The RFC's 114-byte ciphertext and its tag.
        assert_eq!(
            buf.as_slice(),
            &RFC8439_CIPHERTEXT[..],
            "ChaCha20-Poly1305 disagrees with RFC 8439's recorded ciphertext"
        );
        assert_eq!(tag, RFC8439_TAG, "ChaCha20-Poly1305 disagrees with RFC 8439's recorded tag");
        // It opens again, and a flipped AAD byte is rejected.
        crypt::open(&RFC8439_KEY, &RFC8439_NONCE, &RFC8439_AAD, &mut buf, &tag).expect("open");
        let mut bad_aad = RFC8439_AAD;
        bad_aad[0] ^= 0x01;
        let mut sealed = RFC8439_PLAINTEXT.to_vec();
        let t2 = crypt::seal(&RFC8439_KEY, &RFC8439_NONCE, &RFC8439_AAD, &mut sealed).expect("seal");
        assert!(
            crypt::open(&RFC8439_KEY, &RFC8439_NONCE, &bad_aad, &mut sealed, &t2).is_err(),
            "a flipped AAD byte was accepted; the header is not authenticated"
        );
        println!("  AEAD: RFC 8439 §2.8.2 ciphertext and tag reproduced, AAD tamper refused");
    }

    /// The password, the salt and the parameters each change the derived
    /// key, and the same inputs give the same key. Which function the KDF is
    /// is checked by `argon2id_v13_matches_the_rfc9106_vector`.
    ///
    /// Each arm catches a defect a round trip would miss: ignoring the
    /// password (every store shares a key), the salt (stores under one
    /// password share a key) or the parameters (raising `m_cost` buys
    /// nothing).
    #[test]
    fn the_kdf_is_a_function_of_its_password_salt_and_parameters() {
        let p1 = b"password one, long enough to pass";
        let p2 = b"password two, long enough to pass";
        let s1 = [0x11u8; crypt::SALT_LEN];
        let s2 = [0x22u8; crypt::SALT_LEN];
        // Cheap parameters: only which inputs matter is tested here.
        let cheap = Kdf {
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
        };
        let cheaper = Kdf {
            m_cost_kib: 16,
            t_cost: 1,
            p_cost: 1,
        };
        let k = |pw: &[u8], salt: &[u8; crypt::SALT_LEN], kdf: Kdf| {
            *crypt::derive_key(pw, salt, kdf).expect("derive")
        };
        assert_eq!(k(p1, &s1, cheap), k(p1, &s1, cheap), "the KDF is not a function");
        assert_ne!(k(p1, &s1, cheap), k(p2, &s1, cheap), "the KDF ignores the password");
        assert_ne!(k(p1, &s1, cheap), k(p1, &s2, cheap), "the KDF ignores the salt");
        assert_ne!(
            k(p1, &s1, cheap),
            k(p1, &s1, cheaper),
            "the KDF ignores its parameters, so raising m_cost would buy nothing"
        );
        // An `m_cost` above the cap is refused before allocating.
        assert!(
            Kdf {
                m_cost_kib: crypt::MAX_M_COST_KIB + 1,
                t_cost: 1,
                p_cost: 1,
            }
            .checked()
            .is_err(),
            "an m_cost above the cap was accepted; a hostile file could name 64 GiB"
        );
        println!(
            "  KDF: password, salt and parameters each change the key; the function's identity \
             is argon2id_v13_matches_the_rfc9106_vector's claim, at 32 KiB/t=3/p=4 with a secret \
             and AD -- not at the shipped point"
        );
    }

    /// The encoder's image for two accounts matches the hand-assembled header
    /// and body, and parses back to the same accounts.
    ///
    /// Not under Miri: eight WOTS+ key generations are too slow under the
    /// interpreter. The same `seal_at` call is still interpreted through
    /// `good_image()`.
    #[cfg(not(miri))]
    #[test]
    fn known_answer_image_for_two_accounts() {
        let accts = two_accounts();
        let image = seal_at(&refs(&accts), 7);
        let nonce = KAT_NONCE;

        // 1. The plaintext header, byte for byte.
        let expected_header = expected_header(&nonce);
        assert_eq!(expected_header.len(), HEADER_LEN);
        assert_eq!(&image[..HEADER_LEN], &expected_header[..], "the plaintext header");

        // 2. The length, a closed formula of the record count.
        assert_eq!(image.len(), HEADER_LEN + BODY_HEADER_LEN + 2 * RECORD_LEN + TRAILER_LEN);
        assert_eq!(image.len(), 502, "51 header + (45 + 2*195) body + 16 tag");

        // 3. The decrypted body against the hand-assembled body, byte for
        //    byte.
        let f = read_header(&image).expect("header");
        let mut plain: Zeroizing<Vec<u8>> = Zeroizing::new(f.ciphertext.to_vec());
        crypt::open(test_key(), &f.header.nonce, f.aad, &mut plain, f.tag).expect("decrypt");
        assert_eq!(&plain[..], &expected_body(7)[..], "the canonical plaintext body");

        // 4. The ciphertext is not the plaintext, so the body was encrypted.
        assert_ne!(&image[HEADER_LEN..HEADER_LEN + plain.len()], &plain[..]);

        let parsed = parse_with_key(&image, test_key()).expect("parse");
        assert_eq!(parsed.generation, 7);
        assert_eq!(parsed.slots.len(), 2);
        let mut roots = 0;
        let mut sdk_records = 0;
        for (tag, slot) in parsed.slots {
            match slot.account.to_record() {
                AccountRecord::Imported {
                    root,
                    first_key,
                    stream_id,
                    ..
                } => {
                    assert_eq!(tag, IMPORTED_TAG);
                    assert_eq!(root.expose(), &IMPORTED_ROOT);
                    assert_eq!(&first_key[..], &IMPORTED_ADDRESS[PK_LEN..]);
                    assert_eq!(stream_id.as_bytes(), &IMPORTED_STREAM);
                    roots += 1;
                }
                AccountRecord::Derived {
                    account_index,
                    stream_id,
                    ..
                } => {
                    assert_eq!(tag, DERIVED_TAG);
                    assert_eq!(account_index, 1);
                    assert_eq!(
                        stream_id.as_bytes(),
                        &crate::derive::derive_wots_key(&Secret::new(DERIVED_SEED), 0).tag()
                    );
                }
                AccountRecord::Sdk { .. } => sdk_records += 1,
            }
        }
        assert_eq!(sdk_records, 0, "the image holds no SDK account");
        assert_eq!(roots, 1);
    }

    /// A real version-1 `accounts.mks` written by a version-1 encoder
    /// (`testdata/README.md`): an imported root `0xB7 * 32` under the
    /// unverified tag `0x1A * 20`, and `F-derive-account-1`. 242 bytes:
    /// `22 + 2*94 + 32`. Shared with `tests/keystore.rs`.
    const V1_SNAPSHOT: &[u8; 242] =
        include_bytes!("../../testdata/keystore_v1_snapshot.bin");

    /// A real version-2 `accounts.mks` written by a version-2 encoder with the
    /// two group F accounts (`testdata/README.md`). 410 bytes:
    /// `22 + 2*178 + 32`. The imported account sorts first, so bytes 22..42
    /// are `IMPORTED_TAG` and byte 42 is `1`. Shared with
    /// `tests/keystore.rs`.
    const V2_SNAPSHOT: &[u8; 410] =
        include_bytes!("../../testdata/keystore_v2_snapshot.bin");

    /// A pinned version-3 image, 290 bytes at `Kdf::RECOMMENDED`. Only its
    /// header is read here, because decrypting it takes hours under Miri;
    /// `tests/keystore.rs` opens it end to end.
    const V3_SNAPSHOT: &[u8; 290] = include_bytes!("../../testdata/keystore_v3_snapshot.bin");

    /// A version-3 `accounts.mks` with a reservation open, written by a
    /// version-3 encoder at `Kdf::CHEAP_FOR_TESTS` (`testdata/README.md`):
    /// `Keystore::create`, `adopt_master` (`F-address-widths`' master,
    /// `00..1f`), `add(Account::derive(master, 0))` and
    /// `persist_advance(&tag, &[0xD1; 32])`. 290 bytes:
    /// `51 + (45 + 178) + 16`, generation 3, index 1, a reservation at 0.
    /// Also read by `tests/keystore.rs`, `tests/recon.rs` and `tests/cli.rs`.
    const V3_RESERVED_SNAPSHOT: &[u8; 290] =
        include_bytes!("../../testdata/keystore_v3_reserved_snapshot.bin");

    /// The key the captured v3 reservation was sealed under: the test
    /// harness's password and salt at `CHEAP_FOR_TESTS`. Derived once and
    /// cached.
    fn captured_key() -> &'static Zeroizing<[u8; crypt::KEY_LEN]> {
        use std::sync::OnceLock;
        static KEY: OnceLock<Zeroizing<[u8; crypt::KEY_LEN]>> = OnceLock::new();
        KEY.get_or_init(|| {
            crypt::derive_key(b"harness-password-not-for-real-use", &TEST_SALT, Kdf::CHEAP_FOR_TESTS)
                .expect("derive the captured file's key")
        })
    }

    /// A version this build does not read is reported as
    /// `UnsupportedVersion` (upgrade), not as damage, and before the KDF or
    /// the tag check runs.
    ///
    /// Versions 1 and 2 are refused rather than migrated: a v2 file holds no
    /// master seed and an upgrade cannot compute one, so a migrated store
    /// would refuse every command that needs the seed. Migration is
    /// `create --from-phrase` into a fresh directory.
    #[test]
    fn an_older_format_reports_unsupported_version_before_anything_else() {
        // v1's own constants, independent of the current ones.
        const V1_HEADER_LEN: usize = 22; // magic 8 | version 2 | generation 8 | count 4
        const V1_RECORD_LEN: usize = 94;
        const V1_TRAILER_LEN: usize = 32; // sha3_256
        assert_eq!(&V1_SNAPSHOT[..8], b"MCMKSTOR");
        assert_eq!(u16::from_le_bytes([V1_SNAPSHOT[8], V1_SNAPSHOT[9]]), 1);
        assert_eq!(
            V1_SNAPSHOT.len(),
            V1_HEADER_LEN + 2 * V1_RECORD_LEN + V1_TRAILER_LEN
        );

        // The error names the first record: the imported account under tag
        // `0x1a * 20`, kind byte `1` at offset 42.
        let v1_first = Some(([0x1a; ADDR_TAG_LEN], AccountKind::Imported));
        assert_eq!(
            parse_with_key(V1_SNAPSHOT, test_key()).err(),
            Some(Error::UnsupportedVersion {
                got: 1,
                supported: VERSION,
                first_account: v1_first,
            }),
            "a v1 file must report its version, not corruption"
        );

        // The same file with its last byte destroyed still reports the
        // version, so the version is dispatched before the KDF and the AEAD.
        let mut broken = *V1_SNAPSHOT;
        let last = broken.len() - 1;
        broken[last] ^= 0xff;
        assert_eq!(
            parse_with_key(&broken, test_key()).err(),
            Some(Error::UnsupportedVersion {
                got: 1,
                supported: VERSION,
                first_account: v1_first,
            }),
            "version must be dispatched BEFORE the body is authenticated"
        );

        // A genuine version-2 file names its first account. A v1 body under
        // a forged v2 word (242 bytes, where a v2 image is 22 + n*178 + 32)
        // fails the length check and names none.
        assert_eq!(
            parse_with_key(V2_SNAPSHOT, test_key()).err(),
            Some(Error::UnsupportedVersion {
                got: 2,
                supported: VERSION,
                first_account: Some((IMPORTED_TAG, AccountKind::Imported)),
            }),
            "a version-2 store must be told to upgrade, not that it is damaged, and must name \
             its first account. It is refused rather than migrated because a v2 file holds no \
             master seed and an upgrade cannot compute one -- see this test's note."
        );
        let mut v2 = *V1_SNAPSHOT;
        v2[8..10].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(
            parse_with_key(&v2, test_key()).err(),
            Some(Error::UnsupportedVersion {
                got: 2,
                supported: VERSION,
                first_account: None,
            }),
            "a v1 body under a v2 version word fits no v2 layout and must name no account"
        );

        // Controls: with the version word forged to a version this build
        // reads, the same bytes are refused for another reason, never as
        // `UnsupportedVersion` naming that version. Both reach the KDF-id
        // refusal: byte 10 of the v1 capture is 2, not a known KDF id.
        let mut forged = broken;
        forged[8..10].copy_from_slice(&VERSION.to_le_bytes());
        let err = parse_with_key(&forged, test_key()).err();
        assert!(
            !matches!(err, Some(Error::UnsupportedVersion { got, .. }) if got == VERSION) && err.is_some(),
            "a v1 body under the current version word was refused as UnsupportedVersion naming \
             {VERSION}: the parser calls the version it writes unsupported: {err:?}"
        );
        let mut forged3 = broken;
        forged3[8..10].copy_from_slice(&V3_VERSION.to_le_bytes());
        let err3 = parse_with_key(&forged3, test_key()).err();
        assert!(
            !matches!(err3, Some(Error::UnsupportedVersion { got, .. }) if got == V3_VERSION) && err3.is_some(),
            "a v1 body under a version-3 word was refused as UnsupportedVersion naming 3: the \
             version-3 read arm is gone: {err3:?}"
        );

        // A version-4 image under a forged version-3 word fails the tag: the
        // version word is part of the AAD.
        let mut downgraded = good_image().to_vec();
        downgraded[8..10].copy_from_slice(&V3_VERSION.to_le_bytes());
        assert_eq!(
            parse_with_key(&downgraded, test_key()).err(),
            Some(Error::WrongPassword),
            "a version-4 image under a forged version-3 word was not refused by the tag; the \
             version word is part of the AAD and a downgrade must fail there"
        );

        // The version-3 pin's header is accepted; nothing is decrypted.
        let framed = read_header(V3_SNAPSHOT).expect("the version-3 pin's header is read");
        assert_eq!(framed.version, V3_VERSION, "the pinned image is not version 3");
        assert_eq!(framed.header.kdf, Kdf::RECOMMENDED, "the pin advertises the shipped parameter point");

        // The captured version-3 reservation reads with `figures: None` and
        // no settled block.
        let parsed = parse_with_key(V3_RESERVED_SNAPSHOT, captured_key())
            .expect("the captured version-3 reservation no longer parses: the v3 read arm moved");
        assert_eq!(parsed.generation, 3, "create, adopt, add, reserve: three commits after the empty image");
        assert_eq!(parsed.slots.len(), 1);
        let slot = parsed
            .slots
            .get(&IMPORTED_TAG)
            .expect("the capture's one account is F-address-widths' master at index 0, tag 05ff..");
        assert_eq!(slot.account.kind(), AccountKind::Derived);
        assert_eq!(slot.account.wots_index().get(), 1, "the reservation advanced the index to 1");
        assert_eq!(
            slot.pending,
            Some(Pending {
                spent_index: WotsIndex::from_raw(0),
                digest: [0xD1; 32],
                figures: None,
            }),
            "a version-3 reservation must read back with figures: None -- declared absent, not zero"
        );
        assert_eq!(slot.settled, None, "a version-3 record has no settled block to read");
        println!(
            "  version dispatch: v1 and v2 report upgrade before the KDF runs; forged words {VERSION} and \
             {V3_VERSION} over a v1 body are refused as {err:?} / {err3:?}; a v4 image under a v3 word \
             fails the tag; the v3 pin's header and the v3 reservation capture (figures: None) both read"
        );
    }

    /// The canonical image at generation 1, built once because
    /// `two_accounts()` runs four WOTS+ key generations, which are slow under
    /// Miri. The malformation rows mutate copies.
    fn good_image() -> &'static [u8] {
        static IMAGE: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
        IMAGE.get_or_init(|| {
            let accts = two_accounts();
            seal_at(&refs(&accts), 1).to_vec()
        })
    }

    /// The parser refuses each malformation with the right error.
    ///
    /// * A change nobody authenticated (a flipped bit, a truncated file, a
    ///   forged header field, a wrong password) is refused by the tag before
    ///   any record byte is read, always as [`Error::WrongPassword`], so the
    ///   error is not a decryption oracle (see `crypt::open`).
    /// * A change a key holder could have made (the plaintext edited and
    ///   re-sealed) reaches the canonicality checks and gets the `Corrupt`
    ///   variant naming the field.
    #[test]
    fn parser_refuses_each_malformation_with_the_right_variant() {
        let good = good_image();

        // --- Group A: refused by the AEAD, all with one answer -------------
        type Edit = Box<dyn Fn(&mut Vec<u8>)>;
        let unauthenticated: [(&str, Edit); 4] = [
            ("a flipped byte inside a record", Box::new(|v: &mut Vec<u8>| v[HEADER_LEN + 5] ^= 1) as Edit),
            ("a flipped byte in the tag", Box::new(|v: &mut Vec<u8>| { let n = v.len() - 1; v[n] ^= 1 })),
            // Salt at 8+2+1+4+4+4 = 23, nonce at 39, both inside the AAD.
            ("a forged salt in the header", Box::new(|v: &mut Vec<u8>| v[23] ^= 0xff)),
            ("a forged nonce in the header", Box::new(|v: &mut Vec<u8>| v[HEADER_LEN - 1] ^= 0xff)),
        ];
        for (what, edit) in unauthenticated {
            let mut bad = good.to_vec();
            edit(&mut bad);
            assert_eq!(
                parse_with_key(&bad, test_key()).err(),
                Some(Error::WrongPassword),
                "{what}: an unauthenticated change must be refused by the tag, as one answer"
            );
        }
        // A forged KDF parameter out of range is refused by `Kdf::checked`
        // before anything allocates, as `Range` naming the field. Only an
        // in-bounds forgery reaches the tag.
        let mut absurd = good.to_vec();
        absurd[11..15].copy_from_slice(&(crypt::MAX_M_COST_KIB + 1).to_le_bytes());
        assert!(
            matches!(parse_with_key(&absurd, test_key()), Err(Error::Range { what: "keystore kdf m_cost", .. })),
            "an m_cost above the cap must be refused before anything allocates, by name"
        );
        let mut cheapened = good.to_vec();
        cheapened[11..15].copy_from_slice(&8u32.to_le_bytes());
        assert_eq!(
            parse_with_key(&cheapened, test_key()).err(),
            Some(Error::WrongPassword),
            "an in-bounds forged m_cost must reach the tag and fail there"
        );

        // The right file under the wrong key gives the same answer. The
        // parameters must match `test_key`'s so only the password differs.
        let other = crypt::derive_key(
            b"a different password entirely",
            &TEST_SALT,
            Kdf::CHEAP_FOR_TESTS,
        )
        .expect("derive");
        assert_eq!(
            parse_with_key(good, &other).err(),
            Some(Error::WrongPassword),
            "the wrong key must give the same answer as a damaged file"
        );

        // --- Group B: refused by canonicality, reached by re-sealing -------

        // pending == 1 but spent_index does not precede wots_index by one
        let bad_pending = reseal(good, |p| p[BODY_HEADER_LEN + PENDING_FLAG_OFF] = 1);
        assert!(matches!(
            parse_with_key(&bad_pending, test_key()),
            Err(Error::Corrupt { what: "pending index does not precede wots_index by one", .. })
        ));

        // duplicate tag: copy record 1's tag over record 2's
        let dup = reseal(good, |p| {
            p.copy_within(BODY_HEADER_LEN..BODY_HEADER_LEN + ADDR_TAG_LEN, BODY_HEADER_LEN + RECORD_LEN)
        });
        assert!(matches!(
            parse_with_key(&dup, test_key()),
            Err(Error::Corrupt { what: "records not strictly ascending by tag", .. })
        ));

        // a derived record whose first-key field is not zero
        let dirty = reseal(good, |p| p[BODY_HEADER_LEN + RECORD_LEN + FIRST_OFF] = 1);
        assert!(matches!(
            parse_with_key(&dirty, test_key()),
            Err(Error::Corrupt { what: "derived first-key field not zero", .. })
        ));

        // The master-seed flag is 0 but the bytes are not, and a flag
        // outside 0..=1.
        let dirty_master = reseal(good, |p| p[8 + 4 + 1] = 0xff);
        assert!(matches!(
            parse_with_key(&dirty_master, test_key()),
            Err(Error::Corrupt { what: "master seed present flag is 0 with non-zero bytes", .. })
        ));
        let bad_flag = reseal(good, |p| p[8 + 4] = 2);
        assert!(matches!(
            parse_with_key(&bad_flag, test_key()),
            Err(Error::Corrupt { what: "master seed present flag is not 0 or 1", .. })
        ));

        // Version 4 fields: the state byte's domain, the settled relation,
        // the figures flag's domain and zero rule, and the state-0 zero rule
        // over the figures. Record 1 is at wots_index 0, so rows that must
        // pass the relation first set it to 1.
        let bad_state = reseal(good, |p| p[BODY_HEADER_LEN + PENDING_FLAG_OFF] = 3);
        assert!(
            matches!(parse_with_key(&bad_state, test_key()), Err(Error::Corrupt { what: "pending flag", .. })),
            "bad_state: a pending byte of 3 was not refused as an unknown state"
        );
        let settled_relation = reseal(good, |p| p[BODY_HEADER_LEN + PENDING_FLAG_OFF] = 2);
        assert!(
            matches!(
                parse_with_key(&settled_relation, test_key()),
                Err(Error::Corrupt { what: "pending index does not precede wots_index by one", .. })
            ),
            "settled_relation: a settled block whose spent_index does not precede wots_index by one \
             was not refused -- the relation must hold in BOTH occupied states"
        );
        let bad_figures = reseal(good, |p| {
            p[BODY_HEADER_LEN + WOTS_INDEX_OFF] = 1;
            p[BODY_HEADER_LEN + PENDING_FLAG_OFF] = 1;
            p[BODY_HEADER_LEN + FIGURES_FLAG_OFF] = 2;
        });
        assert!(
            matches!(parse_with_key(&bad_figures, test_key()), Err(Error::Corrupt { what: "figures flag", .. })),
            "bad_figures: a figures byte of 2 was not refused"
        );
        let zero_flag_balance = reseal(good, |p| {
            p[BODY_HEADER_LEN + WOTS_INDEX_OFF] = 1;
            p[BODY_HEADER_LEN + PENDING_FLAG_OFF] = 1;
            p[BODY_HEADER_LEN + RESERVED_BALANCE_OFF] = 7;
        });
        assert!(
            matches!(
                parse_with_key(&zero_flag_balance, test_key()),
                Err(Error::Corrupt { what: "figures not zero while figures == 0", .. })
            ),
            "figures_zero_dirty: a reserved balance under figures == 0 was not refused"
        );
        let zero_flag_btl = reseal(good, |p| {
            p[BODY_HEADER_LEN + WOTS_INDEX_OFF] = 1;
            p[BODY_HEADER_LEN + PENDING_FLAG_OFF] = 1;
            p[BODY_HEADER_LEN + BTL_OFF] = 7;
        });
        assert!(
            matches!(
                parse_with_key(&zero_flag_btl, test_key()),
                Err(Error::Corrupt { what: "figures not zero while figures == 0", .. })
            ),
            "figures_zero_dirty: a block-to-live under figures == 0 was not refused"
        );
        let figures_without_block = reseal(good, |p| p[BODY_HEADER_LEN + FIGURES_FLAG_OFF] = 1);
        assert!(
            matches!(
                parse_with_key(&figures_without_block, test_key()),
                Err(Error::Corrupt { what: "pending fields not zero while pending == 0", .. })
            ),
            "figures_without_block: a figures flag under pending == 0 was not refused by the \
             state-0 zero rule"
        );
        // A version-3 record never has state 2, so the v3 read arm refuses
        // it. Reached by re-sealing the captured v3 file under its own key.
        let v3_state_2 = reseal_with(captured_key(), V3_RESERVED_SNAPSHOT, |p| {
            p[BODY_HEADER_LEN + PENDING_FLAG_OFF] = 2
        });
        assert!(
            matches!(parse_with_key(&v3_state_2, captured_key()), Err(Error::Corrupt { what: "pending flag", .. })),
            "a version-3 image never carries pending state 2, and the v3 read arm accepted one"
        );

        // --- Group C: every prefix, and one byte too many ------------------
        //
        // None of these may panic.
        for n in 0..good.len() {
            assert!(parse_with_key(&good[..n], test_key()).is_err(), "prefix {n} parsed");
        }
        let mut longer = good.to_vec();
        longer.push(0);
        assert!(parse_with_key(&longer, test_key()).is_err());

        // Control: the untouched image still parses.
        assert!(parse_with_key(good, test_key()).is_ok(), "the good image stopped parsing");
        println!(
            "  malformations: 5 refused by the tag as one answer, 12 by canonicality (5 older, 7 \
             added with version 4 -- one of them the version-3 arm's), {} prefixes",
            good.len()
        );
    }

    /// Field offsets inside one record, derived from the layout.
    /// `BTL_OFF + 8` is the record length.
    const FIRST_OFF: usize = ADDR_TAG_LEN + 1 + 32;
    const STREAM_OFF: usize = FIRST_OFF + FIRST_KEY_LEN;
    const WOTS_INDEX_OFF: usize = STREAM_OFF + ADDR_TAG_LEN;
    const PENDING_FLAG_OFF: usize = WOTS_INDEX_OFF + 4;
    const SPENT_OFF: usize = PENDING_FLAG_OFF + 1;
    const DIGEST_OFF: usize = SPENT_OFF + 4;
    const FIGURES_FLAG_OFF: usize = DIGEST_OFF + 32;
    const RESERVED_BALANCE_OFF: usize = FIGURES_FLAG_OFF + 1;
    const BTL_OFF: usize = RESERVED_BALANCE_OFF + 8;

    /// Decrypts an image, passes its plaintext to `edit`, and re-seals it, so
    /// a test can reach the canonicality checks behind the AEAD.
    fn reseal(image: &[u8], edit: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
        reseal_with(test_key(), image, edit)
    }

    /// [`reseal`] under a given key.
    fn reseal_with(key: &[u8; crypt::KEY_LEN], image: &[u8], edit: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
        let f = read_header(image).expect("header");
        let aad = f.aad.to_vec();
        let mut plain: Zeroizing<Vec<u8>> = Zeroizing::new(f.ciphertext.to_vec());
        crypt::open(key, &f.header.nonce, &aad, &mut plain, f.tag).expect("decrypt");
        // A copy of decrypted plaintext, so it is `Zeroizing` too.
        let mut edited: Zeroizing<Vec<u8>> = Zeroizing::new(plain.to_vec());
        edit(&mut edited);
        let new_tag = crypt::seal(key, &f.header.nonce, &aad, &mut edited).expect("seal");
        let mut out = aad;
        out.extend_from_slice(&edited);
        out.extend_from_slice(&new_tag);
        out
    }

    /// `MAX_IMAGE_LEN` is the image length at the account cap, and one record
    /// more is refused. Checked on the length functions and the gate rather
    /// than by building a full-size image.
    ///
    /// * `image_len(MAX_ACCOUNTS) == MAX_IMAGE_LEN`: the hand-written sum and
    ///   the formula agree, including `BODY_HEADER_LEN`.
    /// * `image_len(MAX_ACCOUNTS + 1) > MAX_IMAGE_LEN`.
    /// * `read_header` lets a zeroed buffer of exactly `MAX_IMAGE_LEN` bytes
    ///   past its length gate (it then fails at the magic) and refuses one
    ///   byte more as `Range` naming both bounds.
    /// * `image_len(0) == MIN_IMAGE_LEN`.
    ///
    /// Not covered: the `count > MAX_ACCOUNTS` refusals in `encode` and
    /// `parse_with_key`.
    #[test]
    fn max_image_len_is_the_cap_image_and_one_record_more_is_refused() {
        assert_eq!(
            image_len(MAX_ACCOUNTS),
            Some(MAX_IMAGE_LEN),
            "MAX_IMAGE_LEN is not image_len(MAX_ACCOUNTS): a store at the account cap encodes \
             and is then refused on read by the length gate. This is the defect the audit \
             found -- the constant and the formula disagree, by BODY_HEADER_LEN \
             ({BODY_HEADER_LEN}) when the body header is what was forgotten -- and nothing \
             below the cap can show it"
        );
        let one_more =
            image_len(MAX_ACCOUNTS + 1).expect("one record past the cap does not overflow usize");
        assert!(
            one_more > MAX_IMAGE_LEN,
            "one record more than the cap ({one_more} bytes) is admitted by MAX_IMAGE_LEN \
             ({MAX_IMAGE_LEN}); the cap no longer means one record more is refused"
        );
        assert_eq!(
            image_len(0),
            Some(MIN_IMAGE_LEN),
            "MIN_IMAGE_LEN is not image_len(0): the Range read_header reports names a minimum \
             no version-3 writer produces"
        );
        // The gate itself, on zeroed buffers.
        let at_cap = vec![0u8; MAX_IMAGE_LEN];
        let verdict = read_header(&at_cap).err();
        assert!(
            matches!(verdict, Some(Error::Corrupt { what: "magic", offset: 0 })),
            "a buffer of exactly MAX_IMAGE_LEN bytes did not get past read_header's length gate \
             to the magic check: {verdict:?}. The gate refuses the cap's own image"
        );
        let over = vec![0u8; MAX_IMAGE_LEN + 1];
        let verdict = read_header(&over).err();
        assert!(
            matches!(
                verdict,
                Some(Error::Range { what: "keystore image length", min, max, got })
                    if got == (MAX_IMAGE_LEN + 1) as u64
                        && min == MIN_IMAGE_LEN as u64
                        && max == MAX_IMAGE_LEN as u64
            ),
            "a buffer one byte over MAX_IMAGE_LEN was not refused by the length gate as Range \
             naming both bounds: {verdict:?}"
        );
        println!(
            "  image cap: image_len({MAX_ACCOUNTS}) == MAX_IMAGE_LEN == {MAX_IMAGE_LEN}; one \
             record more is {one_more} and refused; the gate admits exactly the cap; \
             image_len(0) == MIN_IMAGE_LEN == {MIN_IMAGE_LEN}"
        );
    }

    /// `encode` refuses the same pending relation `parse_with_key` refuses, in
    /// both occupied states, and round-trips consistent blocks.
    ///
    /// * An open reservation with figures, built as `persist_advance` builds
    ///   one, round-trips intact.
    /// * `figures: None` round-trips as `None`, not as recorded zeros.
    /// * A settled block round-trips as settled, with no open reservation.
    /// * Four inconsistent relations, including one whose `+ 1` overflows,
    ///   are refused in each state before sealing, as `Corrupt` with the
    ///   parser's `what`.
    ///
    /// Not under Miri: the WOTS+ key generations and parses are too slow
    /// under the interpreter.
    #[cfg(not(miri))]
    #[test]
    fn encode_refuses_the_pending_relation_the_parser_refuses() {
        let accts = two_accounts();
        let (tag, account, _) = &accts[0];
        let digest = [0xD1u8; 32];
        let figures = Figures {
            reserved_balance: 5_000_000,
            blk_to_live: 4_242,
        };
        let at_zero = |figures: Option<Figures>| Pending {
            spent_index: WotsIndex::from_raw(0),
            digest,
            figures,
        };

        // 1. An open reservation with its figures, as persist_advance builds one.
        let consistent = [RecordRef {
            tag: *tag,
            account,
            wots_index: WotsIndex::from_raw(1),
            pending: Some(at_zero(Some(figures))),
            settled: None,
        }];
        let image = seal_at(&consistent, 3);
        let parsed = parse_with_key(&image, test_key()).expect(
            "encode or parse refused a reservation built as persist_advance builds one \
             (spent_index 0 under wots_index 1, figures recorded)",
        );
        let slot = parsed
            .slots
            .get(tag)
            .expect("the record is in the parsed state");
        assert_eq!(
            slot.account.wots_index().get(),
            1,
            "wots_index did not round-trip beside a reservation"
        );
        assert_eq!(
            slot.pending,
            Some(at_zero(Some(figures))),
            "the reservation, figures included, did not round-trip through encode and parse"
        );
        assert_eq!(slot.settled, None, "an open reservation came back with a settled block beside it");

        // 2. The migrated shape: figures absent stays absent.
        let migrated = [RecordRef {
            tag: *tag,
            account,
            wots_index: WotsIndex::from_raw(1),
            pending: Some(at_zero(None)),
            settled: None,
        }];
        let parsed = parse_with_key(&seal_at(&migrated, 4), test_key()).expect("the migrated shape seals and parses");
        assert_eq!(
            parsed.slots.get(tag).expect("in the parsed state").pending,
            Some(at_zero(None)),
            "figures: None did not round-trip as None. An encoder that writes the flag as 1 over \
             zeros fabricates a recorded zero balance for a migrated reservation, which the \
             declared-absent state exists to avoid"
        );

        // 3. The settled block, retained with its figures.
        let settled = [RecordRef {
            tag: *tag,
            account,
            wots_index: WotsIndex::from_raw(1),
            pending: None,
            settled: Some(at_zero(Some(figures))),
        }];
        let parsed = parse_with_key(&seal_at(&settled, 5), test_key()).expect("a settled block seals and parses");
        let slot = parsed.slots.get(tag).expect("in the parsed state");
        assert_eq!(
            slot.settled,
            Some(at_zero(Some(figures))),
            "the retained settled block did not round-trip with its figures"
        );
        assert_eq!(slot.pending, None, "a settled block came back as an open reservation");

        // 4. The relation, refused in both occupied states.
        let mut refused = 0usize;
        for (spent, wots, why) in [
            (1u32, 1u32, "spent_index equal to wots_index"),
            (0, 2, "spent_index two behind wots_index"),
            (1, 0, "spent_index ahead of wots_index"),
            (u32::MAX, 0, "spent_index at u32::MAX, where the + 1 overflows"),
        ] {
            let block = Pending {
                spent_index: WotsIndex::from_raw(spent),
                digest,
                figures: Some(figures),
            };
            for (state, pending, settled) in [("open", Some(block), None), ("settled", None, Some(block))] {
                let bad = [RecordRef {
                    tag: *tag,
                    account,
                    wots_index: WotsIndex::from_raw(wots),
                    pending,
                    settled,
                }];
                let err = encode(&bad, 3, None, Kdf::RECOMMENDED, &TEST_SALT, test_key(), &KAT_NONCE).err();
                assert!(
                    matches!(
                        err,
                        Some(Error::Corrupt {
                            what: "pending index does not precede wots_index by one",
                            ..
                        })
                    ),
                    "encode sealed a {state} block with {why} ({spent} under {wots}), or refused it \
                     under another name: {err:?}. The parser refuses exactly this relation, so an \
                     image encode emits here is authenticated garbage -- refused after the tag \
                     verifies, indistinguishable to an operator from a damaged file"
                );
                refused += 1;
            }
        }
        assert_eq!(refused, 8);
        println!(
            "  encode: a reservation with figures, the migrated shape and a settled block each \
             round-trip; {refused} inconsistent blocks refused before sealing, under the parser's own \
             name"
        );
    }

    /// One derived account, built once and cached, for tests that need any
    /// record.
    // Not under Miri: its only caller is gated out under Miri.
    #[cfg(not(miri))]
    fn one_account() -> &'static (Tag, Account) {
        static ACCOUNT: std::sync::OnceLock<(Tag, Account)> = std::sync::OnceLock::new();
        ACCOUNT.get_or_init(|| {
            let a = Account::derive(&Secret::new(DERIVED_MASTER), 1);
            (a.tag(), a)
        })
    }

    /// `encode` refuses a record with both an open and a settled block, a
    /// state the file cannot express. Controls: each half alone seals and
    /// reads back.
    ///
    /// Not under Miri: the WOTS+ key generations are too slow under the
    /// interpreter.
    #[cfg(not(miri))]
    #[test]
    fn encode_refuses_both_an_open_and_a_settled_block_in_one_record() {
        let (tag, account) = one_account();
        let block = Pending {
            spent_index: WotsIndex::from_raw(1),
            digest: [0xD2; 32],
            figures: Some(Figures {
                reserved_balance: 1,
                blk_to_live: 0,
            }),
        };
        let record = |pending: Option<Pending>, settled: Option<Pending>| {
            [RecordRef {
                tag: *tag,
                account,
                wots_index: WotsIndex::from_raw(2),
                pending,
                settled,
            }]
        };
        let err = encode(&record(Some(block), Some(block)), 3, None, Kdf::RECOMMENDED, &TEST_SALT, test_key(), &KAT_NONCE).err();
        assert!(
            matches!(
                err,
                Some(Error::Corrupt {
                    what: "both an open and a settled reservation in one record",
                    ..
                })
            ),
            "encode sealed a record carrying both an open and a settled block, or refused it under \
             another name: {err:?}. The record's one pending byte cannot express both, so whichever \
             the encoder picked would be a silent default over the other"
        );
        // Controls: either half alone seals and reads back.
        for (what, pending, settled) in [("open", Some(block), None), ("settled", None, Some(block))] {
            let image = encode(&record(pending, settled), 3, None, Kdf::RECOMMENDED, &TEST_SALT, test_key(), &KAT_NONCE)
                .unwrap_or_else(|e| panic!("the {what} half alone did not seal: {e}"));
            let parsed = parse_with_key(&image, test_key()).unwrap_or_else(|e| panic!("the {what} half alone did not parse: {e}"));
            let slot = parsed.slots.get(tag).expect("in the parsed state");
            assert_eq!((slot.pending, slot.settled), (pending, settled), "the {what} half did not round-trip");
        }
        println!("  encode: both blocks in one record refused before sealing; each half alone round-trips");
    }
}
