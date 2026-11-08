// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! The two addresses a spend needs, derived from the store and dropped:
//! the current key's (the source) and the next key's (the change), under the
//! same kind, tag and stream checks [`Keystore::sign_spend`] runs.
//!
//! This reads the store, not the chain. The chain-side check, that the
//! ledger holds [`SpendAddresses::source`] for this tag, is
//! `mesh::spend::SpendPlan::new`'s [`Error::ChainAddressMismatch`]. It is a
//! spend-time guard, separate from the startup reconciliation in
//! `Wallet::open`: a store reconciled at open can be overtaken by the chain
//! before a spend is built. A mismatch always stops the spend, because
//! several causes look the same and only one is safe to advance through.
//!
//! # Positions
//!
//! `position` is the account's stored index, the key `sign_spend` signs
//! with. The source address is the key at `position` and the change address
//! the key at `position + 1`, both under the account tag: the tag half stays
//! constant across a spend and the hash half rotates (`tx_val` requires
//! equal tags and different hashes). Both keys come from
//! [`Keystore::key_at`], the derivation `sign_spend` uses.
//!
//! An account with an outstanding reservation is refused with
//! [`Error::PendingUnresolved`] before any network round trip.

use crate::account::WotsIndex;
use crate::addr::{Address, Tag};
use crate::error::{Error, Result};

use super::sign::KeyAccess;
use super::{Keystore, Medium};

/// What a spend is built for: the tag, the position that will sign, and the
/// two addresses. Public data with no key material.
///
/// Constructible only through the keystore: by
/// [`Keystore::spend_addresses`], or inside the crate from addresses
/// [`Keystore::address_at`] derived. `#[non_exhaustive]` prevents building
/// one from arbitrary addresses outside the crate, which could pay change to
/// a key nobody holds. `SpendAddresses::unverified` exists only under the
/// `raw-backend` feature, for tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SpendAddresses {
    /// The account tag; the tag half of both addresses.
    pub tag: Tag,
    /// The stored index: the key that will sign. `persist_advance` reserves
    /// exactly this position and mints a receipt attesting `position + 1`.
    pub position: WotsIndex,
    /// `tag ‖ hash(pk at position)`: the address the chain must currently
    /// hold for the tag, and `src_addr` on the wire.
    pub source: Address,
    /// `tag ‖ hash(pk at position + 1)`: `chg_addr` on the wire, which
    /// receives the balance minus send and fee.
    pub change: Address,
}

impl SpendAddresses {
    /// Addresses that did not come from a keystore. Test-only, under
    /// `raw-backend`. `SpendPlan::new` still refuses a `source` the chain
    /// does not hold, but nothing checks that `change` belongs to a held
    /// key, so a wrong change address sends the remainder to nobody.
    #[cfg(feature = "raw-backend")]
    pub fn unverified(tag: Tag, position: WotsIndex, source: Address, change: Address) -> SpendAddresses {
        SpendAddresses {
            tag,
            position,
            source,
            change,
        }
    }

    /// Addresses the keystore derived one at a time with
    /// [`Keystore::address_at`], used to rebuild a reserved spend.
    /// Crate-private so that outside callers only get keystore-derived plans.
    pub(crate) fn of_derived_addresses(tag: Tag, position: WotsIndex, source: Address, change: Address) -> SpendAddresses {
        SpendAddresses {
            tag,
            position,
            source,
            change,
        }
    }
}

impl<M: Medium> Keystore<M> {
    /// The address of this account's key at `position`, under the account
    /// tag: `tag ‖ hash(pk at position)`.
    ///
    /// Used by reconciliation. It uses the same derivation as `sign_spend`
    /// ([`Keystore::key_at`], with its kind, tag and stream refusals), so the
    /// address compared against the chain matches the key that would sign.
    ///
    /// Unlike `spend_addresses` this does not refuse an outstanding
    /// reservation, since reconciling a spend in flight needs the addresses
    /// at `spent_index` and `spent_index + 1`. The derived key is dropped
    /// before this returns.
    pub fn address_at(&self, tag: &Tag, position: WotsIndex, access: &KeyAccess<'_>) -> Result<Address> {
        let (_, slots) = self.live()?;
        let slot = slots.get(tag).ok_or(Error::NoSuchAccount)?;
        Ok(self.key_at(slots, slot, position, access)?.address(tag))
    }

    /// The addresses a spend from `tag` is built for. Refuses an unknown
    /// tag, an outstanding reservation, an index at its ceiling, and every
    /// kind/tag/stream mismatch `sign_spend` refuses, by the same names.
    /// Every derived key is dropped before this returns.
    pub fn spend_addresses(&self, tag: &Tag, access: &KeyAccess<'_>) -> Result<SpendAddresses> {
        let (_, slots) = self.live()?;
        let slot = slots.get(tag).ok_or(Error::NoSuchAccount)?;
        if let Some(p) = slot.pending {
            return Err(Error::PendingUnresolved {
                spent_index: p.spent_index.get(),
            });
        }
        let position = slot.account.wots_index();
        let next = position.advanced()?;
        let source = self.key_at(slots, slot, position, access)?.address(tag);
        let change = self.key_at(slots, slot, next, access)?.address(tag);
        Ok(SpendAddresses {
            tag: *tag,
            position,
            source,
            change,
        })
    }
}
