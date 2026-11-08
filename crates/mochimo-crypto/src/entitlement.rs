// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! The reward entitlement a validator's cold address has accrued, which caps
//! the amount of a claim.
//!
//! The node rejects a claim above the entitlement only after the cold key
//! has signed it, and the one-time key can then sign nothing else, so the
//! account is stuck until the entitlement grows past the amount. The wallet
//! therefore checks the amount before reserving a key (`Wallet::plan_claim`).
//!
//! # Sources
//!
//! * [`MeshClient`]: `POST /account/entitlement`, the default. The
//!   middleware answers from a cached ledger, so the figure may lag the tip
//!   ([`Origin::Endpoint`] carries the block it was read at). Entitlement only
//!   grows between claims, so a stale figure is never above the ledger's. The
//!   configured node is trusted for this figure, as it is for balances.
//! * [`OperatorSupplied`]: a figure the operator read elsewhere and entered.
//!   It is not checked.
//!
//! The endpoint allows one request per client address per ten seconds and
//! answers HTTP 429 with `Retry-After` otherwise
//! ([`crate::Error::RateLimited`]). Nothing here retries.

use crate::addr::Tag;
use crate::error::Result;
use crate::mesh::{MeshClient, Transport};

/// Where an [`Entitlement`] figure came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// `/account/entitlement`, read at this block.
    Endpoint {
        /// The block index the middleware answered at.
        block: u64,
    },
    /// Entered by the operator; not checked.
    OperatorSupplied,
}

/// An entitlement figure and its source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entitlement {
    /// nanoMochimo.
    pub amount: u64,
    /// Where the figure came from.
    pub origin: Origin,
}

/// A source of entitlement figures.
pub trait EntitlementSource {
    /// The entitlement `tag` holds, as this source knows it.
    fn entitlement(&self, tag: &Tag) -> Result<Entitlement>;
}

impl<T: Transport> EntitlementSource for MeshClient<T> {
    fn entitlement(&self, tag: &Tag) -> Result<Entitlement> {
        let read = self.account_entitlement(tag)?;
        Ok(Entitlement {
            amount: read.entitlement,
            origin: Origin::Endpoint { block: read.tip.index },
        })
    }
}

/// A figure the operator supplied, returned for every tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperatorSupplied {
    /// nanoMochimo.
    pub amount: u64,
}

impl EntitlementSource for OperatorSupplied {
    fn entitlement(&self, _tag: &Tag) -> Result<Entitlement> {
        Ok(Entitlement {
            amount: self.amount,
            origin: Origin::OperatorSupplied,
        })
    }
}
