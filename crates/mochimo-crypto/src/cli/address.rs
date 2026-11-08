// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! `address`: the address to fund, available before the account has funds.
//!
//! # Outside `Wallet::open`
//!
//! `Wallet::open` reconciles every account and refuses when the node does not
//! resolve a tag, which is always the case for a tag never paid. So, like
//! `create` and `restore`, this command opens no wallet, signs nothing and
//! asks the chain nothing.
//!
//! # Seed requirement
//!
//! The store holds account records, not addresses, and a record's `first[64]`
//! is populated for imported accounts only. A derived account's address is
//! therefore computed from the master seed, which is prompted for; an imported
//! account's comes from its stored root without a prompt.
//!
//! # Which address
//!
//! The one at the account's stored `wots_index`, derived through the same
//! `key_at` that `sign_spend` uses. For a new store this is position 0, where
//! the tag half equals the hash half.
//!
//! # Listing without a seed
//!
//! [`accounts_in`] lists destinations, which depend only on the tag stored in
//! each record, so it derives nothing and needs no seed. [`address_of`]
//! computes an address and needs one.

use crate::addr::{Address, Tag};
use crate::keystore::{KeyAccess, Keystore, Medium};
use crate::{Error, Result};

/// One account as the store records it.
///
/// Every field is a public identifier or a position, so deriving `Debug` and
/// the comparisons exposes no key material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Held {
    pub tag: Tag,
    pub kind: crate::account::AccountKind,
    pub index: crate::account::WotsIndex,
}

/// Every account the store holds, in the store's own order.
///
/// Reads records only: computes no address, needs no [`KeyAccess`], and
/// makes no node call.
pub fn accounts_in<M: Medium>(store: &Keystore<M>) -> Result<Vec<Held>> {
    let mut out = Vec::new();
    for tag in store.tags()? {
        if let Some(v) = store.view(&tag)? {
            out.push(Held {
                tag: v.tag,
                kind: v.kind,
                index: v.wots_index,
            });
        }
    }
    Ok(out)
}

/// The address `tag` will next present, and the index it sits at.
pub struct Where {
    pub address: Address,
    pub index: crate::account::WotsIndex,
}

/// Look up `tag` in the store and compute its current address.
///
/// Returns [`Error::NoSuchAccount`] for a tag the store does not hold. The
/// chain is not consulted.
pub fn address_of<M: Medium>(
    store: &Keystore<M>,
    tag: &Tag,
    access: &KeyAccess<'_>,
) -> Result<Where> {
    let view = store.view(tag)?.ok_or(Error::NoSuchAccount)?;
    let address = store.address_at(tag, view.wots_index, access)?;
    Ok(Where {
        address,
        index: view.wots_index,
    })
}
