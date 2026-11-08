// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! The signing path: [`Keystore::sign_spend`] produces a fresh WOTS+
//! signature behind the receipt the keystore mints (invariant I1), and
//! [`Keystore::resign_reserved`] reproduces the one already released.
//!
//! # Design
//!
//! * **The receipt names the account.** `sign_spend` takes no tag; the
//!   account is `receipt.tag()`. The receipt is consumed by value and is not
//!   `Clone`, and it is minted only after the keystore's four-step durable
//!   commit (I2), so a signature is released only after its index is on
//!   disk.
//! * **The live state is re-checked.** The store must still hold the
//!   receipt's index, a reservation, and the supplied digest, so a stale
//!   receipt, a reconciliation receipt (`persist_advance_to` sets no
//!   reservation) and a settled one are each refused.
//! * **Keys are derived, never stored.** A derived account signs from the
//!   caller's master seed ([`KeyAccess::Master`]), and its tag is recomputed
//!   and must match. An imported account signs from its stored root
//!   ([`KeyAccess::StoredRoot`]). The wrong variant for the account's kind is
//!   refused.
//! * **One key stream, one account.** Rotation keys depend only on the
//!   32-byte seed, so a seed stored under two accounts would sign one key
//!   twice. `Keystore::add` refuses a duplicate stream identity across
//!   kinds, and this path re-derives a derived record's identity from the
//!   master and refuses a mismatch.
//! * **Nothing is persisted here.** `persist_advance` already persisted the
//!   advance, so "reserved" and "signed" are one on-disk state. The chain
//!   settles it (I4 reconciliation); until then the account cannot spend
//!   again.
//! * **A refusal has no side effect**, but an `Err` from `sign_spend` still
//!   consumes the receipt, so the reserved key is skipped, not reused.
//!   [`Keystore::check_spend`] runs the same checks on a borrowed receipt.
//!
//! # Key material
//!
//! The master seed stays with the caller as a [`Secret`], zeroized on drop
//! and borrowed for one call. Every derived intermediate is dropped before
//! this module returns. The store body is encrypted under an Argon2id-derived
//! key, so `KeyAccess::StoredRoot` requires the keystore directory and the
//! password.
//!
//! # The imported first key
//!
//! Position 0 of an imported account signs from the stored public seed and
//! hash address. Those components come from the master seed's generator and
//! cannot be derived from the root; a substitute would produce a valid
//! signature under an unfunded address. `Account::import` refuses a pair the
//! root does not reproduce.

use core::fmt;

use crate::account::{AccountKind, AdvanceReceipt, KeyMaterial, WotsIndex};
use crate::addr::{self, Tag};
use crate::consts::SEED_LEN;
use crate::derive::{self, WotsKey};
use crate::error::{Error, Result};
use crate::secret::Secret;
use crate::wots::{self, Adrs, PublicKey, Signature};

use super::format::Slot;
use super::{Keystore, Medium};

/// How `sign_spend` reaches an account's key material.
///
/// A derived account needs the caller's master seed; an imported or SDK
/// account uses the root the store holds. The wrong variant for the
/// account's kind is refused with [`Error::KeyAccessMismatch`].
///
/// `Debug` redacts the borrowed [`Secret`].
pub enum KeyAccess<'a> {
    /// The master seed a derived account was derived from.
    Master(&'a Secret<SEED_LEN>),
    /// Nothing: the account's key material is its stored root.
    StoredRoot,
}

impl fmt::Debug for KeyAccess<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyAccess::Master(_) => f.write_str("Master(<redacted>)"),
            KeyAccess::StoredRoot => f.write_str("StoredRoot"),
        }
    }
}

/// The output of `sign_spend`: the signature and the public parts of the
/// signing key, as carried in a transaction's `WOTSVAL`. Contains only
/// public data. `Debug` prints the position and the key's address hash.
pub struct SpendSignature {
    /// The position of the key that signed: the reservation's `spent_index`.
    pub spent_index: WotsIndex,
    /// The 2144-byte WOTS+ signature over the reserved digest.
    pub signature: Signature,
    /// The signing key's public seed.
    pub pub_seed: [u8; SEED_LEN],
    /// The hash address signing and `pkgen` start from, before either
    /// mutates it.
    pub adrs: Adrs,
    /// The signing key's public key, so a caller can recover it from the
    /// signature with `wots::pk_from_sig` and compare.
    pub public_key: PublicKey,
}

impl fmt::Debug for SpendSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let address = addr::from_wots(&self.public_key);
        let hash: String = addr::hash_of(&address).iter().map(|b| format!("{b:02x}")).collect();
        f.debug_struct("SpendSignature")
            .field("spent_index", &self.spent_index)
            .field("address_hash", &hash)
            .finish_non_exhaustive()
    }
}

impl<M: Medium> Keystore<M> {
    /// Runs every check `sign_spend` runs on a borrowed receipt, deriving and
    /// dropping the signing key. `Ok(())` means the same `sign_spend` call on
    /// this handle, with nothing done in between, will sign, so a caller can
    /// confirm a passphrase before consuming the receipt.
    ///
    /// # Errors
    ///
    /// The same errors `sign_spend` returns.
    pub fn check_spend(&self, digest: &[u8; 32], receipt: &AdvanceReceipt, access: &KeyAccess<'_>) -> Result<()> {
        self.resolve(digest, receipt, access).map(|_| ())
    }

    /// Reproduces the signature an outstanding reservation already released,
    /// from the store's own record. This recovers a lost signed transaction.
    ///
    /// There is no digest parameter: the digest and position are read from
    /// the reservation. WOTS+ signing is deterministic, so the output is
    /// byte-identical to the original signature and the key still signs only
    /// one message (I1).
    ///
    /// Rolling the index back is forbidden, so a signature from the reserved
    /// key is the only way to move the funds at its address; without this,
    /// losing the signed transaction would strand the balance.
    ///
    /// Nothing advances or persists. Only the open reservation is read, never
    /// a retained settled block; `recon::resubmit_reverted_settle` resends
    /// those from their saved bytes.
    ///
    /// # Errors
    ///
    /// [`Error::NoSuchAccount`] if the store has no account `tag`,
    /// [`Error::NothingPending`] if it has no open reservation, and the
    /// key-access errors of `sign_spend`.
    pub fn resign_reserved(&self, tag: &Tag, access: &KeyAccess<'_>) -> Result<SpendSignature> {
        let (_, slots) = self.live()?;
        let slot: &Slot = slots.get(tag).ok_or(Error::NoSuchAccount)?;
        let pending = slot.pending.ok_or(Error::NothingPending)?;
        let key = self.key_at(slots, slot, pending.spent_index, access)?;
        let mut working = key.adrs();
        let signature = wots::sign(&pending.digest, key.secret(), key.pub_seed(), &mut working);
        Ok(SpendSignature {
            spent_index: pending.spent_index,
            signature,
            pub_seed: *key.pub_seed(),
            adrs: key.adrs(),
            public_key: Box::new(*key.public_key()),
        })
    }

    /// Signs `digest` with the key `receipt` reserved for it, consuming the
    /// receipt. See the module documentation for the checks.
    ///
    /// # Errors
    ///
    /// Each refusal is an [`Error`] variant naming its reason. A refusal has
    /// no side effect but still consumes the receipt.
    pub fn sign_spend(
        &mut self,
        digest: &[u8; 32],
        receipt: AdvanceReceipt,
        access: KeyAccess<'_>,
    ) -> Result<SpendSignature> {
        let (spent_index, key) = self.resolve(digest, &receipt, &access)?;
        // The signer mutates its own copy of the starting address words. The
        // receipt is dropped here whichever way this returns.
        let mut working = key.adrs();
        let signature = wots::sign(digest, key.secret(), key.pub_seed(), &mut working);
        Ok(SpendSignature {
            spent_index,
            signature,
            pub_seed: *key.pub_seed(),
            adrs: key.adrs(),
            public_key: Box::new(*key.public_key()),
        })
    }

    /// Runs the receipt checks and returns the key at the reserved position.
    fn resolve(&self, digest: &[u8; 32], receipt: &AdvanceReceipt, access: &KeyAccess<'_>) -> Result<(WotsIndex, WotsKey)> {
        let (_, slots) = self.live()?;
        // (a) the receipt names an account this store holds.
        let slot: &Slot = slots.get(&receipt.tag()).ok_or(Error::NoSuchAccount)?;
        // (b) it names the store's live index; an older receipt is stale.
        let stored = slot.account.wots_index();
        if stored != receipt.index() {
            return Err(Error::StaleReceipt {
                attested: receipt.index().get(),
                stored: stored.get(),
            });
        }
        // (c) a key is reserved. `persist_advance_to` reserves none, and
        // `persist_settled` clears `slot.pending`, so both receipts stop here.
        let pending = slot.pending.ok_or(Error::NoReservation)?;
        // (c') defensive: the reservation is the position just before the
        // live index. `persist_advance` writes both in one commit and the
        // parser enforces the relation, so no public-API input reaches this.
        if pending.spent_index.advanced().ok() != Some(receipt.index()) {
            return Err(Error::NoReservation);
        }
        let spent_index = pending.spent_index;
        // (d) the digest is the reserved one.
        if pending.digest != *digest {
            return Err(Error::DigestMismatch);
        }
        // (e), (f), (f'), (g): the key, by kind.
        let key = self.key_at(slots, slot, spent_index, access)?;
        Ok((spent_index, key))
    }

    /// The key at `position` for `slot`'s account under `access`, after the
    /// key-access and key-stream checks.
    ///
    /// Shared by [`Keystore::sign_spend`] and
    /// [`Keystore::spend_addresses`](super::spend), so the address a spend is
    /// built for and the key that signs it come from one derivation. Every
    /// `Secret` made here is in the returned key, which the caller drops.
    pub(super) fn key_at(
        &self,
        slots: &std::collections::BTreeMap<crate::addr::Tag, Slot>,
        slot: &Slot,
        position: WotsIndex,
        access: &KeyAccess<'_>,
    ) -> Result<WotsKey> {
        let key = match (slot.account.key_material(), access) {
            (KeyMaterial::Derived { .. }, KeyAccess::StoredRoot) => {
                return Err(Error::KeyAccessMismatch {
                    kind: AccountKind::Derived,
                })
            }
            (KeyMaterial::Imported { .. }, KeyAccess::Master(_)) => {
                return Err(Error::KeyAccessMismatch {
                    kind: AccountKind::Imported,
                })
            }
            (KeyMaterial::Sdk { .. }, KeyAccess::Master(_)) => {
                return Err(Error::KeyAccessMismatch { kind: AccountKind::Sdk })
            }
            // The SDK's spend `n` is position `n`. Spend 0 is the implicit
            // key the account tag hashes, so there is no first-key case.
            (KeyMaterial::Sdk { root, .. }, KeyAccess::StoredRoot) => derive::sdk_wots_key(root.secret(), position.get()),
            (
                KeyMaterial::Derived {
                    account_index,
                    stream,
                },
                KeyAccess::Master(master),
            ) => {
                // (f) the master derives this account's tag at its index.
                let derived = derive::derive_account(master, *account_index);
                if derived.tag() != slot.account.tag() {
                    return Err(Error::DerivedTagNotReproduced {
                        account_index: *account_index,
                    });
                }
                // (f') defensive: the seed is not also an imported root in
                // this store. `Keystore::add` already refuses that, so only a
                // hand-edited snapshot with a forged identity reaches this.
                // Checked before (f'') so the more specific error wins.
                if self.imported_roots(slots).any(|root| root.ct_eq(derived.seed())) {
                    return Err(Error::KeyStreamSharedWithImportedAccount);
                }
                // (f'') the record's key-stream identity matches this seed.
                // A derived record's identity needs the master, so this is the
                // only place it can be checked.
                if derive::stream_id(derived.seed()) != *stream {
                    return Err(Error::StreamIdNotReproduced);
                }
                match position.rotation() {
                    None => derived.into_parts().2,
                    Some(rotation) => derive::derive_wots_key(derived.seed(), rotation),
                }
            }
            (KeyMaterial::Imported { root, first, .. }, KeyAccess::StoredRoot) => {
                match position.rotation() {
                    // (g) the first key, rebuilt from the stored public seed
                    // and address, as the browser extension does at
                    // `wotsIndex === -1`.
                    None => derive::first_key_from_components(
                        root.secret().duplicate(),
                        first.pub_seed(),
                        first.adrs(),
                    ),
                    Some(rotation) => derive::derive_wots_key(root.secret(), rotation),
                }
            }
        };
        Ok(key)
    }

    /// Every imported root the store holds, for the stream checks.
    pub(super) fn imported_roots<'s>(
        &'s self,
        slots: &'s std::collections::BTreeMap<crate::addr::Tag, Slot>,
    ) -> impl Iterator<Item = &'s Secret<SEED_LEN>> + 's {
        slots.values().filter_map(|s| match s.account.key_material() {
            KeyMaterial::Imported { root, .. } | KeyMaterial::Sdk { root, .. } => Some(root.secret()),
            KeyMaterial::Derived { .. } => None,
        })
    }
}
