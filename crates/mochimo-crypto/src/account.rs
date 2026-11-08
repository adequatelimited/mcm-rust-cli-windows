// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! The account model: a permanent tag over a rotating WOTS+ key, and how
//! derived, imported and SDK key material is held.
//!
//! A Mochimo account is a permanent 20-byte tag over a rotating WOTS+ key:
//! every spend commits the next key's address hash into `chg_addr`, so the
//! index advance is the spend, expressed on-chain. This module holds the
//! types only; storage and signing live in `crate::keystore`.
//!
//! # Key material
//!
//! [`KeyMaterial`] has one variant per kind, each carrying exactly what that
//! kind needs. A derived account carries no secret, so a restore over
//! [`AccountRecord`] cannot fabricate imported key material, and an
//! exhaustive `match` must handle the `Imported` arm (I8: an imported account
//! is never silently dropped). The enum is not `#[non_exhaustive]`, because
//! that would force wildcard arms downstream.
//!
//! # `wots_index`
//!
//! Every kind rotates, so the index is a field of [`Account`]. Its meaning
//! depends on the variant: a position in the master seed's derivation stream
//! for a derived account, a count of rotations from the root otherwise.
//!
//! [`WotsIndex`] is a `u32` with no sentinel values: it is the browser
//! extension's `wotsIndex` plus one. [`WotsIndex::ZERO`] is the extension's
//! `-1`, the first key, whose secret is the account seed and whose public
//! seed and hash address come from `deriveSeed(master, account_index)`;
//! position `n >= 1` is the key `deriveSeed(account_seed, n - 1)` produces.
//! [`WotsIndex::rotation`] applies the shift, and [`WotsIndex::to_shipped`] /
//! [`WotsIndex::from_shipped`] convert to and from the extension's JSON
//! representation.
//!
//! An imported account's first key cannot be rebuilt from its root, because
//! its public seed and hash address came from a generator seeded by the
//! master seed. [`KeyMaterial::Imported`] therefore stores them as
//! [`FirstKey`], and no constructor omits them.
//!
//! # Signing contract
//!
//! ```text
//! fn sign_spend(&mut self, digest: &[u8; 32], receipt: AdvanceReceipt)
//!     -> Result<wots::Signature>
//! ```
//!
//! The receipt must satisfy `receipt.tag() == self.tag()` and name this
//! account's index after the advance it attests. [`AdvanceReceipt`] has
//! private fields, no public constructor and no `Clone`, and it is bound to a
//! tag and index so it cannot be spent against another account or replayed.
//! Only the keystore mints one, after a durable commit.
//!
//! `keystore::sign::sign_spend` implements the contract: it consumes the
//! receipt and re-checks the store's live state. The raw signers are
//! crate-private (except to tests under the `raw-backend` feature).
//! One signature per key (I1) is enforced per keystore: the same seed under
//! two tags is one key stream, so every record carries a [`StreamId`] and
//! `Keystore::add` refuses a duplicate.
//!
//! Every constructor computes the tag from key material; none accepts a
//! caller-supplied tag.
//!
//! # Exposure
//!
//! Importing confers no exclusivity: whoever supplied a root still holds it.
//! The only public path that hands key material back out is the consuming
//! [`Account::to_record`], the same convention as [`Secret::expose`].
//!
//! [`Account`], [`KeyMaterial`], [`ImportedRoot`] and [`AdvanceReceipt`]
//! implement no `Clone`, `Copy`, `Default` or `PartialEq` (a clone is two
//! spend paths over one index, a default is a fabricated key at index zero,
//! and equality over key material is variable-time), and nothing here
//! implements serde. The compile-fail cases `ui/fail/account_*.rs` pin these
//! absences.

use crate::addr::Tag;
use crate::consts::SEED_LEN;
use crate::error::{Error, Result};
use crate::secret::Secret;
use crate::wots::Adrs;
use core::fmt;


/// A Mochimo account: a permanent tag, key material, and the rotation index.
///
/// Fields are private, so external code can neither build one by literal nor
/// write the index (pinned by the compile-fail cases
/// `account_literal_is_not_constructible` and
/// `account_wots_index_is_not_assignable`). `#[must_use]` because discarding
/// an imported account discards its root.
#[must_use]
pub struct Account {
    tag: Tag,
    key: KeyMaterial,
    wots_index: WotsIndex,
}

/// How an account's key material is held.
///
/// `pub(crate)` because a public enum's variant fields are public, which
/// would let external code fabricate `Derived` values. External code uses
/// [`AccountKind`], which carries no payload.
pub(crate) enum KeyMaterial {
    /// Recomputable from the master seed at this position. Holds no secret.
    Derived {
        account_index: u32,
        stream: StreamId,
    },
    /// An imported root, the only copy of this key material. Change keys
    /// derive from it, and it is never replaced.
    ///
    /// `first` is required, so the position-0 key can always be rebuilt (I8).
    Imported {
        root: ImportedRoot,
        first: FirstKey,
        stream: StreamId,
    },
    /// An account under the Mochimo SDK's scheme
    /// (`crate::derive::sdk_wots_key`), held by its SDK account seed. Every
    /// position, including 0, derives from the seed, so no first-key
    /// components are stored.
    Sdk {
        root: ImportedRoot,
        stream: StreamId,
    },
}

/// An imported account's first-key public components: the 64 bytes at the
/// tail of the extension's `faddress` (`pub_seed` then the hash-address
/// image), used for the key at `wotsIndex === -1`.
///
/// No public constructor: only [`Account::import`] and
/// [`Account::restore_from_record`] build one, and both refuse components the
/// root does not reproduce. The components are public, but `Debug` is
/// hand-written to keep them out of logs.
///
/// The 2208-byte public key is not stored because `wots::pkgen(root,
/// pub_seed, adrs)` determines it. The 12 bytes the extension overlays on the
/// address image do not matter: WOTS+ writes address words 5, 6 and 7
/// (`set_chain_addr`, `set_hash_addr`, `set_key_and_mask`) before every use,
/// so their incoming values never reach a hash.
pub struct FirstKey {
    pub_seed: [u8; SEED_LEN],
    adrs: Adrs,
}

impl FirstKey {
    /// The 64 bytes as they sit in a `faddress` and in the keystore record:
    /// `pub_seed ‖ adrs.le_image()`.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; FIRST_KEY_LEN] {
        let mut out = [0u8; FIRST_KEY_LEN];
        out[..SEED_LEN].copy_from_slice(&self.pub_seed);
        out[SEED_LEN..].copy_from_slice(&self.adrs.le_image());
        out
    }

    pub(crate) fn pub_seed(&self) -> &[u8; SEED_LEN] {
        &self.pub_seed
    }

    pub(crate) fn adrs(&self) -> Adrs {
        self.adrs
    }
}

/// The width of [`FirstKey`]'s byte form: a WOTS+ public seed and a hash
/// address image, the tail of a 2208-byte WOTS+ address.
pub const FIRST_KEY_LEN: usize = SEED_LEN + 32;

/// The payload-free public face of [`KeyMaterial`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountKind {
    /// Derived from the master seed: [`Account::derive`].
    Derived,
    /// Imported from a root and first address: [`Account::import`].
    Imported,
    /// Held by a Mochimo SDK account seed: [`Account::import_sdk`].
    Sdk,
}

/// The public identity of a key stream (a 32-byte seed and every rotation key
/// it produces), computed by [`crate::derive::stream_id`].
///
/// Defined here because it is a field of [`AccountRecord`]. It is public data,
/// the address hash of a key, so `Debug` renders hex and comparison is
/// derived.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StreamId([u8; crate::consts::ADDR_TAG_LEN]);

impl StreamId {
    /// From the twenty bytes a record carries. Public because a record is
    /// data, not authority: `Keystore::add`, `Account::restore_from_record`
    /// and `Keystore::sign_spend` each recompute it where they can and refuse
    /// a mismatch.
    #[must_use]
    pub fn from_bytes(bytes: [u8; crate::consts::ADDR_TAG_LEN]) -> StreamId {
        StreamId(bytes)
    }

    /// The twenty bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; crate::consts::ADDR_TAG_LEN] {
        &self.0
    }
}

impl fmt::Debug for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StreamId(")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

/// An imported or SDK account's retained root.
///
/// Holds a [`Secret`], so `Debug` is hand-written and redacts it
/// (`no_holder_of_key_material_derives_debug` checks for a derived one).
pub struct ImportedRoot {
    secret: Secret<SEED_LEN>,
}

impl ImportedRoot {
    /// Crate-private borrow for the keystore's encoder.
    pub(crate) fn secret(&self) -> &Secret<SEED_LEN> {
        &self.secret
    }
}

/// The rotation position. Forward-only; no sentinel values.
///
/// `Debug` is derived: the index is public state and divergence reports (I4)
/// print it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct WotsIndex(u32);

/// Evidence that an account's advanced index is durable.
///
/// Private fields, no public constructor and no `Clone`, and bound to the
/// `(tag, index)` it attests. Only the keystore mints one, after a durable
/// commit ([`AdvanceReceipt::attesting`] is `pub(crate)`).
#[must_use]
pub struct AdvanceReceipt {
    tag: Tag,
    index: WotsIndex,
}

/// The persistent content of an account: what a keystore must hold. Not an
/// on-disk format; encoding and encryption belong to the keystore.
///
/// `Derived` has no root field, so a restore over records cannot fabricate
/// imported key material and must handle the `Imported` arm. Fields are
/// public because a record is data, not authority:
/// [`Account::restore_from_record`] re-checks everything it can recompute.
pub enum AccountRecord {
    Derived {
        tag: Tag,
        account_index: u32,
        /// The key stream this account's seed defines
        /// ([`crate::derive::stream_id`]). Stored because recomputing it
        /// needs the master seed; `Keystore::add` (when the store holds its
        /// master) and `Keystore::sign_spend` re-derive and compare it.
        stream_id: StreamId,
        wots_index: WotsIndex,
    },
    Imported {
        tag: Tag,
        root: Secret<SEED_LEN>,
        /// [`FirstKey::to_bytes`]. Verified against `root` and `tag` by
        /// [`Account::restore_from_record`].
        first_key: [u8; FIRST_KEY_LEN],
        /// Recomputed from `root` on restore; a mismatch is refused.
        stream_id: StreamId,
        wots_index: WotsIndex,
    },
    Sdk {
        tag: Tag,
        /// The SDK account seed every position derives from.
        root: Secret<SEED_LEN>,
        /// [`crate::derive::stream_id`] of `root`, recomputed and compared
        /// by [`Account::restore_from_record`].
        stream_id: StreamId,
        wots_index: WotsIndex,
    },
}

impl Account {
    /// Build an account under the Mochimo SDK's scheme from its account seed
    /// (`Derivation.deriveAccountSeed(master, index)`,
    /// [`crate::derive::sdk_account_seed`]). The tag is computed as the
    /// address hash of the SDK's spend 0 (`deriveAccountTag`). The account
    /// starts at [`WotsIndex::ZERO`]; a caller that finds it further along
    /// the chain advances it before storing it.
    ///
    /// The stream identity is [`crate::derive::stream_id`] of the seed, as
    /// for the other kinds, so `Keystore::add` refuses one seed held under
    /// two kinds.
    #[cfg(feature = "native")]
    pub fn import_sdk(account_seed: Secret<SEED_LEN>) -> Account {
        let tag = crate::derive::sdk_account_tag(&account_seed);
        let stream = crate::derive::stream_id(&account_seed);
        Account {
            tag,
            key: KeyMaterial::Sdk {
                root: ImportedRoot { secret: account_seed },
                stream,
            },
            wots_index: WotsIndex::ZERO,
        }
    }

    /// Build an imported account from the pair a `.mcm` entry carries: the
    /// 32-byte root and the 2208-byte first address (`faddress`).
    ///
    /// The address's public key must equal `wots::pkgen(root, pub_seed, adrs)`
    /// over its own tail; the tag is then the tag half of that key's implicit
    /// address. Parsing `.mcm` files is not done here.
    ///
    /// # Errors
    ///
    /// [`Error::FirstAddressNotReproduced`] if the root does not reproduce
    /// the address's public key.
    #[cfg(feature = "native")]
    pub fn import(
        root: Secret<SEED_LEN>,
        first_address: &[u8; crate::consts::WOTS_ADDR_LEN],
    ) -> Result<Account> {
        let mut components = [0u8; FIRST_KEY_LEN];
        components.copy_from_slice(&first_address[crate::consts::PK_LEN..]);
        let (pk, tag) = imported_parts(&root, &components);
        if pk[..] != first_address[..crate::consts::PK_LEN] {
            return Err(Error::FirstAddressNotReproduced);
        }
        let stream = crate::derive::stream_id(&root);
        Ok(Account {
            tag,
            key: KeyMaterial::Imported {
                root: ImportedRoot { secret: root },
                first: first_key_from(&components),
                stream,
            },
            wots_index: WotsIndex::ZERO,
        })
    }

    /// Build a derived account at `account_index` in the master seed's
    /// stream, computing its tag (`deriveAccountTag(master, account_index)`,
    /// `crate::derive::derive_account_tag`). The account starts at
    /// [`WotsIndex::ZERO`]. The master seed is not retained.
    ///
    /// Also computes the account's [`StreamId`], which costs a second WOTS+
    /// key generation.
    #[cfg(feature = "native")]
    pub fn derive(master: &Secret<SEED_LEN>, account_index: u32) -> Account {
        let derived = crate::derive::derive_account(master, account_index);
        Account {
            tag: derived.tag(),
            key: KeyMaterial::Derived {
                account_index,
                stream: crate::derive::stream_id(derived.seed()),
            },
            wots_index: WotsIndex::ZERO,
        }
    }

    /// The account's permanent 20-byte tag.
    pub fn tag(&self) -> Tag {
        self.tag
    }

    /// The address this account presents at `position`, from its own key
    /// material: an imported account's first key from its stored components
    /// and its rotations from its root, an SDK account's spends from its
    /// seed. `None` for a derived account, whose keys need the master seed.
    #[cfg(feature = "native")]
    pub(crate) fn address_at_without_master(&self, position: WotsIndex) -> Option<crate::addr::Address> {
        match &self.key {
            KeyMaterial::Derived { .. } => None,
            KeyMaterial::Imported { root, first, .. } => Some(match position.rotation() {
                None => crate::derive::first_key_from_components(root.secret().duplicate(), first.pub_seed(), first.adrs())
                    .address(&self.tag),
                Some(rotation) => crate::derive::derive_wots_key(root.secret(), rotation).address(&self.tag),
            }),
            KeyMaterial::Sdk { root, .. } => Some(crate::derive::sdk_wots_key(root.secret(), position.get()).address(&self.tag)),
        }
    }

    /// Which kind of key material this account holds.
    pub fn kind(&self) -> AccountKind {
        match self.key {
            KeyMaterial::Derived { .. } => AccountKind::Derived,
            KeyMaterial::Imported { .. } => AccountKind::Imported,
            KeyMaterial::Sdk { .. } => AccountKind::Sdk,
        }
    }

    /// The current rotation position.
    pub fn wots_index(&self) -> WotsIndex {
        self.wots_index
    }

    /// Crate-private borrow for the keystore's encoder;
    /// [`Account::to_record`] is the public, consuming path.
    pub(crate) fn key_material(&self) -> &KeyMaterial {
        &self.key
    }

    /// Move the rotation position forward to `target`, for the keystore's
    /// reconciliation path (I4/I5).
    ///
    /// # Errors
    ///
    /// `Error::Range` unless `target` is strictly ahead of the current index.
    pub(crate) fn advance_to(&mut self, target: WotsIndex) -> Result<()> {
        if target.get() <= self.wots_index.get() {
            return Err(Error::Range {
                what: "wots index",
                min: u64::from(self.wots_index.get()) + 1,
                max: u64::from(u32::MAX),
                got: u64::from(target.get()),
            });
        }
        self.wots_index = target;
        Ok(())
    }

    /// Move the rotation position back to `target`, for the keystore's
    /// acknowledged rollback.
    ///
    /// # Errors
    ///
    /// `Error::Range` unless `target` is strictly behind the current index.
    pub(crate) fn rollback_to(&mut self, target: WotsIndex) -> Result<()> {
        if target.get() >= self.wots_index.get() {
            return Err(Error::Range {
                what: "wots index",
                min: 0,
                max: u64::from(self.wots_index.get().saturating_sub(1)),
                got: u64::from(target.get()),
            });
        }
        self.wots_index = target;
        Ok(())
    }

    /// Advance the rotation position in memory, returning the new index. The
    /// keystore orders this against durability and mints the receipt.
    ///
    /// # Errors
    ///
    /// `Error::Range` on overflow. The index never wraps, because a wrap is a
    /// rollback to zero.
    pub fn advance(&mut self) -> Result<WotsIndex> {
        self.wots_index = self.wots_index.advanced()?;
        Ok(self.wots_index)
    }

    /// Consume the account into its persistent content. This is the only
    /// public path by which key material leaves an account.
    pub fn to_record(self) -> AccountRecord {
        match self.key {
            KeyMaterial::Derived {
                account_index,
                stream,
            } => AccountRecord::Derived {
                tag: self.tag,
                account_index,
                stream_id: stream,
                wots_index: self.wots_index,
            },
            KeyMaterial::Imported {
                root,
                first,
                stream,
            } => AccountRecord::Imported {
                tag: self.tag,
                root: root.secret,
                first_key: first.to_bytes(),
                stream_id: stream,
                wots_index: self.wots_index,
            },
            KeyMaterial::Sdk { root, stream } => AccountRecord::Sdk {
                tag: self.tag,
                root: root.secret,
                stream_id: stream,
                wots_index: self.wots_index,
            },
        }
    }

    /// Rebuild an account from its persistent content.
    ///
    /// Imported and SDK records are verified: the tag and stream identity are
    /// recomputed from the root (and, for an imported record, its first-key
    /// components) and must match. A derived record's tag and stream need the
    /// master seed, so they are trusted here and re-checked by
    /// `Keystore::sign_spend` and by `Keystore::add` when the store holds its
    /// master.
    ///
    /// # Errors
    ///
    /// [`Error::FirstAddressNotReproduced`] if the tag does not match the key
    /// material; [`Error::StreamIdNotReproduced`] if the stream identity does
    /// not.
    #[cfg(feature = "native")]
    pub fn restore_from_record(record: AccountRecord) -> Result<Account> {
        match record {
            AccountRecord::Derived {
                tag,
                account_index,
                stream_id,
                wots_index,
            } => Ok(Account {
                tag,
                key: KeyMaterial::Derived {
                    account_index,
                    stream: stream_id,
                },
                wots_index,
            }),
            AccountRecord::Imported {
                tag,
                root,
                first_key,
                stream_id,
                wots_index,
            } => {
                let (_pk, computed_tag) = imported_parts(&root, &first_key);
                if computed_tag != tag {
                    return Err(Error::FirstAddressNotReproduced);
                }
                let computed_stream = crate::derive::stream_id(&root);
                if computed_stream != stream_id {
                    return Err(Error::StreamIdNotReproduced);
                }
                Ok(Account {
                    tag,
                    key: KeyMaterial::Imported {
                        root: ImportedRoot { secret: root },
                        first: first_key_from(&first_key),
                        stream: computed_stream,
                    },
                    wots_index,
                })
            }
            AccountRecord::Sdk {
                tag,
                root,
                stream_id,
                wots_index,
            } => {
                if crate::derive::sdk_account_tag(&root) != tag {
                    return Err(Error::FirstAddressNotReproduced);
                }
                let computed_stream = crate::derive::stream_id(&root);
                if computed_stream != stream_id {
                    return Err(Error::StreamIdNotReproduced);
                }
                Ok(Account {
                    tag,
                    key: KeyMaterial::Sdk {
                        root: ImportedRoot { secret: root },
                        stream: computed_stream,
                    },
                    wots_index,
                })
            }
        }
    }
}

/// The 64 bytes as a [`FirstKey`]. Any 64 bytes parse; callers verify the
/// pair with [`imported_parts`] first.
#[cfg(feature = "native")]
fn first_key_from(components: &[u8; FIRST_KEY_LEN]) -> FirstKey {
    let mut pub_seed = [0u8; SEED_LEN];
    pub_seed.copy_from_slice(&components[..SEED_LEN]);
    let mut image = [0u8; 32];
    image.copy_from_slice(&components[SEED_LEN..]);
    FirstKey {
        pub_seed,
        adrs: Adrs::from_le_image(&image),
    }
}

/// The position-0 public key and account tag a `(root, components)` pair
/// determines. Shared by [`Account::import`] and
/// [`Account::restore_from_record`] so the two cannot drift apart.
///
/// The stream identity is not computed here: it costs a second WOTS+ key
/// generation, and both callers check the tag first.
#[cfg(feature = "native")]
fn imported_parts(
    root: &Secret<SEED_LEN>,
    components: &[u8; FIRST_KEY_LEN],
) -> (crate::wots::PublicKey, Tag) {
    let first = first_key_from(components);
    let mut working = first.adrs;
    let pk = crate::wots::pkgen(root, &first.pub_seed, &mut working);
    let implicit = crate::addr::from_wots(&pk);
    let mut tag = [0u8; crate::consts::ADDR_TAG_LEN];
    tag.copy_from_slice(crate::addr::tag_of(&implicit));
    (pk, tag)
}

impl WotsIndex {
    /// The first position: the account's first key, the extension's `-1`.
    /// `to_shipped()` is `-1` and `rotation()` is `None`.
    pub const ZERO: WotsIndex = WotsIndex(0);

    /// The position as a number, for display and comparison.
    pub fn get(self) -> u32 {
        self.0
    }

    /// Crate-private constructor for the keystore's parser. Not public,
    /// because a public constructor from `u32` would be an index setter.
    pub(crate) const fn from_raw(raw: u32) -> WotsIndex {
        WotsIndex(raw)
    }

    /// The next position.
    ///
    /// # Errors
    ///
    /// `Error::Range` at `u32::MAX`, the last valid position. Never wraps.
    pub fn advanced(self) -> Result<WotsIndex> {
        match self.0.checked_add(1) {
            Some(next) => Ok(WotsIndex(next)),
            None => Err(Error::Range {
                what: "wots index",
                min: 0,
                max: u64::from(u32::MAX),
                got: u64::from(self.0),
            }),
        }
    }

    /// The rotation this position names, or `None` for the first key:
    /// position `n >= 1` is `deriveSeed(account_seed, n - 1)`
    /// (`crate::derive::derive_wots_key`).
    pub fn rotation(self) -> Option<u32> {
        self.0.checked_sub(1)
    }

    /// The extension's `wotsIndex` for this position: `self - 1`, so
    /// [`WotsIndex::ZERO`] is `-1`.
    pub fn to_shipped(self) -> i64 {
        i64::from(self.0) - 1
    }

    /// From the extension's `wotsIndex`: `-1` is [`WotsIndex::ZERO`] and
    /// `n >= 0` is position `n + 1`.
    ///
    /// # Errors
    ///
    /// `Error::ShippedIndex` for a value below `-1` or above `u32::MAX - 1`.
    pub fn from_shipped(shipped: i64) -> Result<WotsIndex> {
        let ours = shipped
            .checked_add(1)
            .ok_or(Error::ShippedIndex { got: shipped })?;
        u32::try_from(ours)
            .map(WotsIndex)
            .map_err(|_| Error::ShippedIndex { got: shipped })
    }
}

impl AdvanceReceipt {
    /// Mint a receipt attesting that `tag`'s advance to `index` is durable.
    ///
    /// Requires a [`crate::keystore::Durable`] witness, which is constructed
    /// only after the keystore's directory fsync succeeds, so no path that
    /// did not complete the durable commit can mint a receipt.
    #[cfg(feature = "native")]
    pub(crate) fn attesting(
        tag: Tag,
        index: WotsIndex,
        _witness: crate::keystore::Durable,
    ) -> AdvanceReceipt {
        AdvanceReceipt { tag, index }
    }

    /// The tag whose advance this receipt attests.
    pub fn tag(&self) -> Tag {
        self.tag
    }

    /// The index this receipt attests as durable.
    pub fn index(&self) -> WotsIndex {
        self.index
    }
}

impl AccountRecord {
    /// The record's tag, whichever kind it is.
    pub fn tag(&self) -> Tag {
        match self {
            AccountRecord::Derived { tag, .. } => *tag,
            AccountRecord::Imported { tag, .. } => *tag,
            AccountRecord::Sdk { tag, .. } => *tag,
        }
    }
}

// Every Debug below is hand-written so key material never reaches a log.
// `no_holder_of_key_material_derives_debug` checks for derived Debug, and unit
// tests pin the renderings.

impl fmt::Debug for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Account")
            .field("tag", &TagHex(&self.tag))
            .field("key", &self.key)
            .field("wots_index", &self.wots_index)
            .finish()
    }
}

impl fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyMaterial::Derived {
                account_index,
                stream,
            } => f
                .debug_struct("Derived")
                .field("account_index", account_index)
                .field("stream", stream)
                .finish(),
            KeyMaterial::Imported { root, first, stream } => f
                .debug_struct("Imported")
                .field("root", root)
                .field("first", first)
                .field("stream", stream)
                .finish(),
            KeyMaterial::Sdk { root, stream } => f
                .debug_struct("Sdk")
                .field("root", root)
                .field("stream", stream)
                .finish(),
        }
    }
}

/// Renders a placeholder: the components are public, and the account tag
/// already identifies the key.
impl fmt::Debug for FirstKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FirstKey(<64 public bytes>)")
    }
}



impl fmt::Debug for ImportedRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ImportedRoot(<redacted>)")
    }
}

impl fmt::Debug for AdvanceReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdvanceReceipt")
            .field("tag", &TagHex(&self.tag))
            .field("index", &self.index)
            .finish()
    }
}

impl fmt::Debug for AccountRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccountRecord::Derived {
                tag,
                account_index,
                stream_id,
                wots_index,
            } => f
                .debug_struct("Derived")
                .field("tag", &TagHex(tag))
                .field("account_index", account_index)
                .field("stream_id", stream_id)
                .field("wots_index", wots_index)
                .finish(),
            AccountRecord::Imported {
                tag,
                stream_id,
                wots_index,
                ..
            } => f
                .debug_struct("Imported")
                .field("tag", &TagHex(tag))
                .field("root", &"<redacted>")
                .field("stream_id", stream_id)
                .field("wots_index", wots_index)
                .finish(),
            AccountRecord::Sdk {
                tag,
                stream_id,
                wots_index,
                ..
            } => f
                .debug_struct("Sdk")
                .field("tag", &TagHex(tag))
                .field("root", &"<redacted>")
                .field("stream_id", stream_id)
                .field("wots_index", wots_index)
                .finish(),
        }
    }
}

/// Lowercase-hex rendering for the (non-secret) tag in Debug output.
struct TagHex<'a>(&'a Tag);

impl fmt::Debug for TagHex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    /// `u32::MAX` is the last position: advancing from it is refused, and the
    /// refusal names `u32::MAX` as the maximum.
    #[test]
    fn advanced_at_the_ceiling_names_u32_max_as_the_last_position() {
        let last = super::WotsIndex::from_raw(u32::MAX);
        let err = last.advanced().err();
        assert_eq!(
            err,
            Some(crate::Error::Range {
                what: "wots index",
                min: 0,
                max: u64::from(u32::MAX),
                got: u64::from(u32::MAX),
            }),
            "advanced() at the ceiling did not name u32::MAX as the last position: {err:?}"
        );
        let one_below = super::WotsIndex::from_raw(u32::MAX - 1).advanced().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(one_below.get(), u32::MAX, "u32::MAX is a position, reachable by advancing from the one below it");
    }

    use super::*;

    fn tag_of(byte: u8) -> Tag {
        [byte; 20]
    }

    /// `F-address-widths`' account seed and its 2208-byte first address, a
    /// real pair. The address is embedded from the fixture file.
    // Not under Miri: only read by tests skipped under Miri.
    #[cfg(not(miri))]
    #[cfg(feature = "native")]
    const WIDTHS_ROOT: [u8; SEED_LEN] = [
        0x66, 0x4e, 0xdd, 0x3d, 0x3b, 0xf1, 0xa0, 0xe2, 0x9c, 0x93, 0x98, 0xdd, 0xc1, 0x61,
        0x14, 0xab, 0xc6, 0xd6, 0xb4, 0x32, 0xb1, 0xe5, 0xe4, 0xde, 0x26, 0x7c, 0x7e, 0x2a,
        0xe5, 0x3f, 0x58, 0x0b,
    ];
    // Not under Miri: only read by tests skipped under Miri.
    #[cfg(not(miri))]
    #[cfg(feature = "native")]
    const WIDTHS_ADDRESS: &[u8; crate::consts::WOTS_ADDR_LEN] =
        include_bytes!("../../../fixtures/F-widths_account_address.bin");
    /// The tag that pair produces: the fixture's
    /// `F-address-widths.account_tag`, independent of `import`.
    // Not under Miri: only read by tests skipped under Miri.
    #[cfg(not(miri))]
    #[cfg(feature = "native")]
    const WIDTHS_TAG: Tag = [
        0x05, 0xff, 0x0f, 0x69, 0xd4, 0xc1, 0xcd, 0x68, 0x2e, 0xd3, 0x34, 0x1c, 0x0b, 0x77,
        0x73, 0x05, 0x4b, 0x58, 0x80, 0x0f,
    ];

    // Not under Miri: only called by tests skipped under Miri.
    #[cfg(not(miri))]
    #[cfg(feature = "native")]
    fn widths_import() -> Account {
        Account::import(Secret::new(WIDTHS_ROOT), WIDTHS_ADDRESS).expect("a real pair")
    }

    /// `Debug` output names the tag, kind and index and redacts key material.
    ///
    /// Not under Miri: WOTS+ key generation is too slow under the
    /// interpreter. `tests/miri.rs` covers the primitives.
    #[cfg(feature = "native")]
    #[cfg(not(miri))]
    #[test]
    fn debug_never_reveals_key_material() {
        let acct = widths_import();
        assert_eq!(acct.tag(), WIDTHS_TAG, "import must compute the fixture's tag");

        let rendered = format!("{acct:?}");
        assert_eq!(
            rendered,
            "Account { tag: 05ff0f69d4c1cd682ed3341c0b7773054b58800f, \
             key: Imported { root: ImportedRoot(<redacted>), \
             first: FirstKey(<64 public bytes>), \
             stream: StreamId(2587878ad34d29cf2e4be48386aec3a0c2a7ea8c) }, \
             wots_index: WotsIndex(0) }"
        );
        let alternate = format!("{acct:#?}");
        // The root's first bytes, in both hex spellings, must appear nowhere.
        for out in [&rendered, &alternate] {
            assert!(!out.contains("664edd") && !out.contains("664EDD"));
        }

        let record = acct.to_record();
        let rec_rendered = format!("{record:?}");
        assert_eq!(
            rec_rendered,
            "Imported { tag: 05ff0f69d4c1cd682ed3341c0b7773054b58800f, \
             root: \"<redacted>\", \
             stream_id: StreamId(2587878ad34d29cf2e4be48386aec3a0c2a7ea8c), \
             wots_index: WotsIndex(0) }"
        );
        assert!(!rec_rendered.contains("664edd"));

        let receipt =
            AdvanceReceipt::attesting(tag_of(0x11), WotsIndex::ZERO, crate::keystore::Durable::for_test());
        assert_eq!(
            format!("{receipt:?}"),
            "AdvanceReceipt { tag: 1111111111111111111111111111111111111111, \
             index: WotsIndex(0) }"
        );
    }

    /// An imported account is constructible only from a pair the root
    /// reproduces, so the tag cannot be forged and position 0 is always
    /// available.
    ///
    /// Not under Miri: WOTS+ key generation is too slow under the
    /// interpreter.
    #[cfg(feature = "native")]
    #[cfg(not(miri))]
    #[test]
    fn import_refuses_a_first_address_the_root_does_not_reproduce() {
        // One byte of the public key, flipped: everything else is the real
        // pair, so only the reproduction check can fail.
        let mut forged = *WIDTHS_ADDRESS;
        forged[0] ^= 0x01;
        assert_eq!(
            Account::import(Secret::new(WIDTHS_ROOT), &forged).err(),
            Some(Error::FirstAddressNotReproduced)
        );

        // And a different root against the real address.
        let mut other = WIDTHS_ROOT;
        other[31] ^= 0x01;
        assert_eq!(
            Account::import(Secret::new(other), WIDTHS_ADDRESS).err(),
            Some(Error::FirstAddressNotReproduced)
        );

        // A self-consistent junk pair is accepted: any (pub_seed, adrs)
        // yields some public key under this root, giving a different tag over
        // the same key stream. `Keystore::add` refuses it by stream identity.
        let mut junk = *WIDTHS_ADDRESS;
        junk[crate::consts::PK_LEN] ^= 0x01; // one byte of the public seed
        let pk = {
            let mut components = [0u8; FIRST_KEY_LEN];
            components.copy_from_slice(&junk[crate::consts::PK_LEN..]);
            imported_parts(&Secret::new(WIDTHS_ROOT), &components).0
        };
        junk[..crate::consts::PK_LEN].copy_from_slice(&pk[..]);
        let aliased = Account::import(Secret::new(WIDTHS_ROOT), &junk).expect("a valid pair");
        assert_ne!(aliased.tag(), WIDTHS_TAG, "a junk first key gives another tag");
        assert_eq!(
            crate::derive::stream_id(&Secret::new(WIDTHS_ROOT)),
            match aliased.key_material() {
                KeyMaterial::Imported { stream, .. } => *stream,
                KeyMaterial::Derived { .. } | KeyMaterial::Sdk { .. } => unreachable!(),
            },
            "and the same key stream, which is what the identity names"
        );
    }

    /// A forged record does not restore: the imported arm recomputes the tag
    /// and the stream identity from the root and refuses a mismatch.
    ///
    /// Not under Miri: WOTS+ key generation is too slow under the
    /// interpreter.
    #[cfg(feature = "native")]
    #[cfg(not(miri))]
    #[test]
    fn restore_refuses_a_record_that_disagrees_with_its_own_root() {
        let good = widths_import().to_record();
        let (tag, root, first_key, stream_id, wots_index) = match good {
            AccountRecord::Imported {
                tag,
                root,
                first_key,
                stream_id,
                wots_index,
            } => (tag, root, first_key, stream_id, wots_index),
            AccountRecord::Derived { .. } | AccountRecord::Sdk { .. } => unreachable!(),
        };

        let mut wrong_tag = tag;
        wrong_tag[0] ^= 0x01;
        assert_eq!(
            Account::restore_from_record(AccountRecord::Imported {
                tag: wrong_tag,
                root: root.duplicate(),
                first_key,
                stream_id,
                wots_index,
            })
            .err(),
            Some(Error::FirstAddressNotReproduced)
        );

        let mut wrong_stream = *stream_id.as_bytes();
        wrong_stream[0] ^= 0x01;
        assert_eq!(
            Account::restore_from_record(AccountRecord::Imported {
                tag,
                root: root.duplicate(),
                first_key,
                stream_id: StreamId::from_bytes(wrong_stream),
                wots_index,
            })
            .err(),
            Some(Error::StreamIdNotReproduced)
        );

        // The untouched record restores, so the refusals above come from the
        // checks.
        assert!(Account::restore_from_record(AccountRecord::Imported {
            tag,
            root,
            first_key,
            stream_id,
            wots_index,
        })
        .is_ok());
    }

    #[test]
    fn wots_index_debug_prints_the_number() {
        // The index is public state; divergence reports (I4) print it.
        assert_eq!(format!("{:?}", WotsIndex::ZERO), "WotsIndex(0)");
    }

    #[test]
    fn wots_index_maps_onto_the_shipped_numbering_totally() {
        // ours = extension + 1, in both directions, at the edges.
        assert_eq!(WotsIndex::ZERO.to_shipped(), -1);
        assert_eq!(WotsIndex::ZERO.rotation(), None);
        assert_eq!(WotsIndex(1).to_shipped(), 0);
        assert_eq!(WotsIndex(1).rotation(), Some(0));
        assert_eq!(WotsIndex(u32::MAX).rotation(), Some(u32::MAX - 1));
        assert_eq!(WotsIndex::from_shipped(-1).ok(), Some(WotsIndex::ZERO));
        assert_eq!(WotsIndex::from_shipped(0).ok(), Some(WotsIndex(1)));
        assert_eq!(
            WotsIndex::from_shipped(i64::from(u32::MAX) - 1).ok(),
            Some(WotsIndex(u32::MAX))
        );
        for shipped in [-2i64, i64::MIN, i64::from(u32::MAX), i64::MAX] {
            assert_eq!(
                WotsIndex::from_shipped(shipped).err(),
                Some(Error::ShippedIndex { got: shipped }),
                "shipped {shipped} must name no position"
            );
        }
        for ours in [0u32, 1, 2, u32::MAX - 1, u32::MAX] {
            let back = WotsIndex::from_shipped(WotsIndex(ours).to_shipped()).ok();
            assert_eq!(back, Some(WotsIndex(ours)), "round trip at {ours}");
        }
    }

    /// Not under Miri: WOTS+ key generation is too slow under the
    /// interpreter; `advanced_at_the_ceiling_names_u32_max_as_the_last_position`
    /// covers the arithmetic there.
    #[cfg(feature = "native")]
    #[cfg(not(miri))]
    #[test]
    fn advance_is_monotonic_and_overflow_is_an_error_not_a_wrap() {
        let mut acct = Account::derive(&Secret::new([0x5Au8; SEED_LEN]), 3);
        assert_eq!(acct.wots_index().get(), 0);
        let first = acct.advance();
        assert_eq!(first.ok().map(WotsIndex::get), Some(1));
        let second = acct.advance();
        assert_eq!(second.ok().map(WotsIndex::get), Some(2));
        assert_eq!(acct.wots_index().get(), 2);

        // Overflow is an error, never a wrap to zero.
        let max = WotsIndex(u32::MAX);
        assert_eq!(
            max.advanced().err(),
            Some(Error::Range {
                what: "wots index",
                min: 0,
                // `u32::MAX` itself: the last position.
                max: u64::from(u32::MAX),
                got: u64::from(u32::MAX),
            })
        );
    }

    #[test]
    fn receipt_binds_the_tag_and_index_it_attests() {
        let receipt =
            AdvanceReceipt::attesting(tag_of(0x33), WotsIndex(7), crate::keystore::Durable::for_test());
        assert_eq!(receipt.tag(), tag_of(0x33));
        assert_eq!(receipt.index().get(), 7);
    }

    /// Not under Miri: WOTS+ key generation is too slow under the
    /// interpreter.
    #[cfg(feature = "native")]
    #[cfg(not(miri))]
    #[test]
    fn records_round_trip_both_kinds_in_crate() {
        // In-module smoke test; the external round trip is
        // tests/invariants.rs::imported_account_restores_from_stored_seed.
        let mut imported = widths_import();
        let advanced = imported.advance();
        assert_eq!(advanced.ok().map(WotsIndex::get), Some(1));
        let restored = Account::restore_from_record(imported.to_record()).expect("restore");
        assert_eq!(restored.kind(), AccountKind::Imported);
        assert_eq!(restored.tag(), WIDTHS_TAG);
        assert_eq!(restored.wots_index().get(), 1);
        match restored.to_record() {
            AccountRecord::Imported { root, .. } => {
                assert_eq!(root.expose(), &WIDTHS_ROOT);
            }
            AccountRecord::Derived { .. } | AccountRecord::Sdk { .. } => {
                panic!("imported account restored as another kind");
            }
        }

        let derived = Account::derive(&Secret::new([0x5Au8; SEED_LEN]), 9);
        let restored = Account::restore_from_record(derived.to_record()).expect("restore");
        assert_eq!(restored.kind(), AccountKind::Derived);
        match restored.to_record() {
            AccountRecord::Derived { account_index, .. } => {
                assert_eq!(account_index, 9);
            }
            AccountRecord::Imported { .. } | AccountRecord::Sdk { .. } => {
                panic!("derived account restored as another kind");
            }
        }
    }
}
