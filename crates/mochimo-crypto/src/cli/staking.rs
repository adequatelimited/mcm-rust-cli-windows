// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! The v4.1 staking verbs: `stake`, `unstake`, `accept`, `revoke`, the
//! dust-proof forms of `claim`, `set-delegate` and `clear-delegate` used above
//! the trigger height, and the read-only `stake-info`.
//!
//! # Signing order
//!
//! Read the tip to learn the next height, and refuse below the trigger. Read
//! the tag's stake through `/account/balance`, and refuse if the middleware
//! reports none. Apply the node's staking rules and refuse anything it would
//! reject or include without effect. Only then plan, reserve, sign and submit
//! (`Wallet::plan_dust_proof`, `reserve_and_sign`), or with `--resign`
//! reproduce the reserved transaction (`resign_pending`). A `claim`,
//! `set-delegate` or `clear-delegate` reserved below the trigger was signed
//! in the v4.0 exact-balance form; `--resign` reproduces that form when the
//! dust-proof digest is not the reserved one. When the node reports a tip at
//! or below the trigger, `--resign` tries the v4.0 form first and then the
//! dust-proof form. Each attempt signs only the reserved digest.
//!
//! # Heights
//!
//! The node checks a new transaction against its tip and applies it in a
//! later block. A rule the node checks on intake (activation, the minimum
//! stake, a live consent, a claim's fee) is checked at the tip as well; the
//! lock that decides a forfeit is checked at the next height, the earliest
//! one the transaction can be applied at.
//!
//! # What the wallet cannot see
//!
//! The Mesh does not disclose whether the source is a validator address (a
//! slot holder, a pending election, or a bound delegate) or whether it is in
//! the pending reward snapshot. A stake from such a tag binds nothing, and
//! the node refuses one from a bound delegate after the key has signed. The
//! output pages warn about this. Nor does it disclose a consent the tag
//! holds; the node refuses a stake from a tag with a live consent, so
//! `stake` needs `--no-live-consent` unless the reply shows the consent.
//!
//! The lock state and the tip are read from the node. An `unstake` or
//! `accept` from a staked tag without `--forfeit` therefore needs
//! `--lock-ends` with the expiry the operator knows the stake has and knows
//! the chain has passed, and an `accept` from a tag the node reports as not
//! staking needs `--not-staked` or `--forfeit`.

use super::args::{StakingAction, StakingTx};
use super::outcome::{Outcome, StakeInfoPage, StakingContext, StakingRefusal, StakingShipped};
use super::key_access;
use crate::addr::Tag;
use crate::consts::SEED_LEN;
use crate::entitlement::{Entitlement, EntitlementSource, Origin};
use crate::keystore::{KeyAccess, Medium};
use crate::mesh::codec::{StakeFields, StakeSource, StakeTerms};
use crate::mesh::spend::{DustProofOp, PlanBody};
use crate::mesh::{MeshClient, Transport};
use crate::staking::{self, ConsentTerms, Network};
use crate::wallet::Wallet;
use crate::{Error, Secret};

/// The refusal page for `tag`.
fn refused(tag: &Tag, refusal: StakingRefusal) -> Outcome {
    Outcome::StakingRefused { tag: *tag, refusal }
}

/// The tip, the height the node checks a new transaction at.
fn tip_height<T: Transport>(client: &MeshClient<T>) -> core::result::Result<u64, StakingRefusal> {
    match client.network_status() {
        Ok(tip) => Ok(tip.index),
        Err(e) => Err(StakingRefusal::TipUnreadable(e)),
    }
}

/// The height the wallet expects its transaction in: the tip plus one.
fn next_height<T: Transport>(client: &MeshClient<T>) -> core::result::Result<u64, StakingRefusal> {
    match client.network_status() {
        Ok(tip) => Ok(tip.index.saturating_add(1)),
        Err(e) => Err(StakingRefusal::TipUnreadable(e)),
    }
}

/// The stake fields `/account/balance` reports for `tag`, with the
/// spendable balance beside them and the tip the reply was made at. Fields
/// from the middleware's ledger cache can be older than the spendable
/// balance, so they are refused.
fn stake_of<T: Transport>(client: &MeshClient<T>, tag: &Tag) -> core::result::Result<(u64, StakeFields, u64), StakingRefusal> {
    match client.account_stake(tag) {
        Ok(at) => match at.stake {
            Some(s) if s.source == StakeSource::Node => Ok((at.spendable, s, at.tip.index)),
            Some(s) => Err(StakingRefusal::StakeFieldsCached { block: s.block }),
            None => Err(StakingRefusal::StakeUnreported),
        },
        Err(e) => Err(StakingRefusal::StakeUnreadable(e)),
    }
}

/// The terms of a stake, checked against each other: the expiry must be the
/// one the node computes from the commit height and the tier, and the
/// reported lock state must match `height`, the height after the tip the
/// reply was made at. `None` when nothing is staked.
fn terms_of(stake: &StakeFields, height: u64) -> core::result::Result<Option<StakeTerms>, StakingRefusal> {
    if stake.staked == 0 {
        return Ok(None);
    }
    let t = stake.terms.ok_or(StakingRefusal::StakeTermsUnreported)?;
    let consistent = staking::tier_of(t.commit, t.expiry).is_some_and(|k| {
        staking::expiry(t.commit, k) == Some(t.expiry)
            && t.tier.is_none_or(|r| r == k)
            && t.locked == (height < t.expiry)
    });
    if !consistent {
        return Err(StakingRefusal::StakeTermsInconsistent { commit: t.commit, expiry: t.expiry });
    }
    Ok(Some(t))
}

/// The expiry height if the stake is locked at `height`, otherwise `None`.
fn locked_at(terms: Option<StakeTerms>, height: u64) -> Option<u64> {
    terms.filter(|t| height < t.expiry).map(|t| t.expiry)
}

/// For a stake that has ended by the node's report: refused unless the
/// operator passed `--forfeit`, or `--lock-ends` with the reported expiry,
/// stating that the chain has passed it.
fn lock_end_confirmed(terms: Option<StakeTerms>, s: &StakingTx) -> core::result::Result<(), StakingRefusal> {
    match terms {
        Some(t) if !s.forfeit && s.lock_ends != Some(t.expiry) => {
            Err(StakingRefusal::LockEndNotConfirmed { expiry: t.expiry, given: s.lock_ends })
        }
        _ => Ok(()),
    }
}

/// For a stake: refused if the reply shows a live consent, or if it shows
/// none and the operator did not pass `--no-live-consent`. A consent is live
/// below its recording height plus [`staking::CONSENT_LAPSE`].
fn no_live_consent(stake: &StakeFields, height: u64, stated: bool) -> core::result::Result<(), StakingRefusal> {
    match stake.consent {
        Some(c) if c.kind != staking::KIND_REVOKE => {
            let lapses_at = c.height.saturating_add(staking::CONSENT_LAPSE);
            if c.live || height < lapses_at {
                return Err(StakingRefusal::LiveConsent { kind: c.kind, lapses_at });
            }
            Ok(())
        }
        Some(_) => Ok(()),
        None if stated => Ok(()),
        None => Err(StakingRefusal::ConsentUnknown),
    }
}

/// The checks before a dust-proof transaction is signed. Returns the op to
/// sign and the context shown on the page, or the refusal. Public so the
/// rules can be tested against a scripted node without a store.
pub fn checked<T: Transport>(
    client: &MeshClient<T>,
    s: &StakingTx,
) -> core::result::Result<(DustProofOp, StakingContext), StakingRefusal> {
    let (tag, network, fee, forfeit) = (&s.tag, s.network, s.fee_total, s.forfeit);
    let supplied = s.entitlement;
    let tip = tip_height(client)?;
    let mut height = tip.saturating_add(1);
    if !network.active_at(tip) {
        return Err(StakingRefusal::NotActive { height: tip, t41: network.t41 });
    }
    // A revoke never touches a stake, and delegate changes come from cold
    // addresses, which cannot stake, so these do not need the stake fields.
    if matches!(s.action, StakingAction::Revoke | StakingAction::SetDelegate { .. } | StakingAction::ClearDelegate) {
        let spendable = client.resolve_tag(tag).map_err(StakingRefusal::BalanceUnreadable)?.balance;
        covered(fee, spendable)?;
        let op = match &s.action {
            StakingAction::SetDelegate { delegate } => DustProofOp::SetDelegate { delegate: *delegate },
            StakingAction::ClearDelegate => DustProofOp::ClearDelegate,
            _ => DustProofOp::Accept(ConsentTerms::revoke(network.id)),
        };
        let context = StakingContext {
            network,
            height,
            spendable,
            stake: None,
            entitlement: None,
        };
        return Ok((op, context));
    }
    let (spendable, stake, reply_tip) = stake_of(client, tag)?;
    let terms = terms_of(&stake, reply_tip.saturating_add(1))?;
    // A block can land between the two reads. The rules below use the lower
    // of the two tips: the minimum stake only falls, and a consent or a lock
    // is live for longer at a lower height.
    let tip = tip.min(reply_tip);
    height = height.min(reply_tip.saturating_add(1));
    if !network.active_at(tip) {
        return Err(StakingRefusal::NotActive { height: tip, t41: network.t41 });
    }
    let mut context = StakingContext {
        network,
        height,
        spendable,
        stake: Some(stake),
        entitlement: None,
    };
    let locked = locked_at(terms, height);
    let op = match &s.action {
        StakingAction::Stake { amount, tier } => {
            let (at_tip, at_next) = (staking::minstake(tip, network.t41), staking::minstake(height, network.t41));
            let (minimum, at) = if at_tip > at_next { (at_tip, tip) } else { (at_next, height) };
            if *amount < minimum {
                return Err(StakingRefusal::BelowMinimum { amount: *amount, minimum, height: at });
            }
            if stake.staked > 0 {
                return Err(StakingRefusal::AlreadyStaked { staked: stake.staked });
            }
            no_live_consent(&stake, tip, s.no_live_consent)?;
            // A stake the node refuses stays reserved until it lands. With a
            // block to live it can expire before the consent lapses, and the
            // key could then sign nothing else, so a consent the reply does
            // not show rules out a block to live.
            if stake.consent.is_none() && s.blk_to_live != 0 && !s.resign {
                return Err(StakingRefusal::ExpiryWithUnknownConsent { blk_to_live: s.blk_to_live });
            }
            if amount.checked_add(fee).is_none_or(|n| n > spendable) {
                return Err(StakingRefusal::StakeNotCovered { amount: *amount, fee, spendable });
            }
            // `/call tag_resolve` does not resolve a tag with a zero spendable
            // balance, and the wallet plans every spend through it. Keep one
            // fee spendable so `unstake` and `claim` remain possible.
            let left = spendable - amount - fee;
            if left < crate::consts::MFEE {
                return Err(StakingRefusal::StakeLeavesTooLittle { amount: *amount, fee, spendable });
            }
            let e = entitlement_of(client, tag, supplied)?;
            context.entitlement = Some(e);
            if e.amount > 0 {
                return Err(StakingRefusal::EntitlementUnclaimed { entitlement: e.amount });
            }
            DustProofOp::Stake { amount: *amount, tier: *tier, network: network.id }
        }
        StakingAction::Unstake => {
            if stake.staked == 0 {
                return Err(StakingRefusal::NotStaked);
            }
            match locked {
                Some(expiry) if !forfeit => {
                    return Err(StakingRefusal::LockedNeedsForfeit { expiry, height, entitlement: stake.entitlement })
                }
                Some(_) => {}
                None => lock_end_confirmed(terms, s)?,
            }
            covered(fee, spendable.saturating_add(stake.staked))?;
            DustProofOp::Unstake { network: network.id }
        }
        StakingAction::Accept(asked) => {
            let mut consent = *asked;
            consent.network = network.id;
            consent.check(tag).map_err(StakingRefusal::BadTerms)?;
            if matches!(consent.kind, staking::KIND_DELEGATE | staking::KIND_MEMBER_DELEGATE) && !s.unbound_delegate {
                return Err(StakingRefusal::DelegateKeyNeedsFlag { kind: consent.kind });
            }
            if stake.staked > 0 {
                match locked {
                    Some(expiry) if !forfeit => {
                        return Err(StakingRefusal::LockedNeedsForfeit { expiry, height, entitlement: stake.entitlement })
                    }
                    Some(_) => {}
                    None => {
                        lock_end_confirmed(terms, s)?;
                        let left = stake.entitlement.unwrap_or(0);
                        if left > 0 {
                            return Err(StakingRefusal::ExpiredStakeWithEntitlement { entitlement: left });
                        }
                    }
                }
            } else {
                // A locked staker's consent forfeits its entitlement, and
                // only the node says the tag does not stake.
                if !forfeit && !s.not_staked {
                    return Err(StakingRefusal::NotStakedUnconfirmed);
                }
                let e = entitlement_of(client, tag, supplied)?;
                context.entitlement = Some(e);
                if e.amount > 0 {
                    return Err(StakingRefusal::ConsentEntitlementUnclaimed { entitlement: e.amount });
                }
            }
            covered(fee, spendable)?;
            DustProofOp::Accept(consent)
        }
        StakingAction::Revoke | StakingAction::SetDelegate { .. } | StakingAction::ClearDelegate => {
            // Handled above, before the stake was read.
            return Err(StakingRefusal::StakeUnreported);
        }
        StakingAction::Claim { amount } => {
            if let Some(expiry) = locked {
                return Err(StakingRefusal::ClaimWhileLocked { expiry, height });
            }
            let e = if stake.staked > 0 {
                Entitlement {
                    amount: stake.entitlement.unwrap_or(0),
                    origin: Origin::Endpoint { block: stake.block },
                }
            } else {
                entitlement_of(client, tag, supplied)?
            };
            context.entitlement = Some(e);
            if e.amount == 0 {
                return Err(StakingRefusal::NothingToClaim);
            }
            if *amount != staking::CLAIM_ALL && *amount > e.amount {
                return Err(StakingRefusal::BadTerms(Error::ClaimExceedsEntitlement {
                    amount: *amount,
                    entitlement: e.amount,
                }));
            }
            // The node checks the fee at the tip, where a stake that ends at
            // the next height is still locked and releases nothing.
            let released = if locked_at(terms, tip).is_some() { 0 } else { stake.staked };
            covered(fee, spendable.saturating_add(released))?;
            DustProofOp::Claim { amount: *amount }
        }
    };
    Ok((op, context))
}

fn covered(fee: u64, available: u64) -> core::result::Result<(), StakingRefusal> {
    if fee > available {
        return Err(StakingRefusal::FeeNotCovered { fee, available });
    }
    Ok(())
}

/// The entitlement for a tag that does not stake: `/account/entitlement`, or
/// the figure the operator supplied.
fn entitlement_of<T: Transport>(
    client: &MeshClient<T>,
    tag: &Tag,
    supplied: Option<u64>,
) -> core::result::Result<Entitlement, StakingRefusal> {
    let read = match supplied {
        Some(amount) => crate::entitlement::OperatorSupplied { amount }.entitlement(tag),
        None => client.entitlement(tag),
    };
    read.map_err(StakingRefusal::EntitlementUnreadable)
}

/// For a validator verb (`claim`, `set-delegate`, `clear-delegate`), the
/// v4.1 dust-proof staking transaction to sign when the tip is above the
/// trigger, or `None` to keep the v4.0 exact-balance form, which the node
/// also accepts above it. The node checks a new transaction against the tip,
/// so at the trigger itself it would refuse the dust-proof form. An
/// unreadable tip is a refusal, because the two forms have different digests
/// and a one-time key cannot sign both.
pub(super) fn dust_proof_form<T: Transport>(
    client: &MeshClient<T>,
    v: &super::args::ValidatorTx,
) -> core::result::Result<Option<StakingTx>, StakingRefusal> {
    use crate::mesh::spend::ValidatorOp;
    let tip = tip_height(client)?;
    if !v.network.active_at(tip) {
        return Ok(None);
    }
    let action = match &v.op {
        ValidatorOp::Claim { amount } => StakingAction::Claim { amount: *amount },
        ValidatorOp::SetDelegate { delegate } => StakingAction::SetDelegate { delegate: *delegate },
        ValidatorOp::ClearDelegate => StakingAction::ClearDelegate,
    };
    Ok(Some(StakingTx {
        tag: v.tag,
        action,
        fee_total: v.fee_total,
        blk_to_live: v.blk_to_live,
        resign: v.resign,
        network: v.network,
        forfeit: false,
        lock_ends: None,
        no_live_consent: false,
        not_staked: false,
        unbound_delegate: false,
        entitlement: v.entitlement,
    }))
}

/// `--resign` of a validator verb in the dust-proof form, for a reservation
/// made while the node reported a tip above the trigger. The rebuilt plan is
/// signed only if its digest is the reserved one, and no staking check runs
/// first, because nothing new is signed. `None` if the digest differs or the
/// form cannot be built at the current balance; otherwise the outcome.
pub(super) fn resign_dust_proof<M: Medium, T: Transport>(
    w: &mut Wallet<M, T>,
    v: &super::args::ValidatorTx,
    access: &KeyAccess<'_>,
) -> Option<Outcome> {
    use crate::mesh::spend::ValidatorOp;
    let op = match &v.op {
        ValidatorOp::Claim { amount } => DustProofOp::Claim { amount: *amount },
        ValidatorOp::SetDelegate { delegate } => DustProofOp::SetDelegate { delegate: *delegate },
        ValidatorOp::ClearDelegate => DustProofOp::ClearDelegate,
    };
    let (tag, fee, btl) = (&v.tag, v.fee_total, v.blk_to_live);
    let height = match next_height(w.client()) {
        Ok(h) => h,
        Err(r) => return Some(refused(tag, r)),
    };
    let spendable = match w.client().resolve_tag(tag) {
        Ok(e) => e.balance,
        Err(e) => return Some(Outcome::Failed(e)),
    };
    let signed = match w.resign_pending(tag, access, PlanBody::DustProof(op.clone()), fee, btl) {
        Ok(t) => t,
        Err(Error::DigestMismatch | Error::InsufficientBalance { .. }) => return None,
        Err(Error::ReservationLanded { spent_index, settled_index }) => {
            return Some(Outcome::ReservationAlreadyLanded { source: *tag, spent_index, settled_index })
        }
        Err(e) => return Some(Outcome::Failed(e)),
    };
    let submitted = w.submit(&signed);
    Some(Outcome::StakingSent {
        shipped: StakingShipped {
            source: *tag,
            op,
            fee_total: fee,
            wire: signed.wire(),
            submitted,
            resigned: true,
        },
        context: StakingContext {
            network: v.network,
            height,
            spendable,
            stake: None,
            entitlement: None,
        },
    })
}

/// The v4.0 exact-balance validator transaction with the same payload as
/// `op`, or `None` for an op that has no v4.0 form.
fn exact_balance_form(op: &DustProofOp) -> Option<crate::mesh::spend::ValidatorOp> {
    use crate::mesh::spend::ValidatorOp;
    match op {
        DustProofOp::Claim { amount } => Some(ValidatorOp::Claim { amount: *amount }),
        DustProofOp::SetDelegate { delegate } => Some(ValidatorOp::SetDelegate { delegate: *delegate }),
        DustProofOp::ClearDelegate => Some(ValidatorOp::ClearDelegate),
        DustProofOp::Stake { .. } | DustProofOp::Unstake { .. } | DustProofOp::Accept(_) => None,
    }
}

/// A staking verb: check, then plan, reserve, sign and submit, or with
/// `--resign` reproduce the reserved transaction and submit it.
/// `expect_balance`, when given, is the spendable balance the plan must have
/// been built against.
pub(super) fn cmd_staking<M: Medium, T: Transport>(
    w: &mut Wallet<M, T>,
    s: &StakingTx,
    master: Option<&Secret<SEED_LEN>>,
    expect_balance: Option<u64>,
) -> Outcome {
    if let Err(e) = super::destination(&s.tag) {
        return Outcome::CannotRender { tag: s.tag, cause: e };
    }
    let access = match key_access(w.store(), &s.tag, master) {
        Ok(a) => a,
        Err(e) => return Outcome::Failed(e),
    };
    let (op, context) = match checked(w.client(), s) {
        Ok(c) => c,
        Err(r) => return refused(&s.tag, r),
    };
    ship(w, s, access, op, context, expect_balance)
}

/// Plan, reserve, sign and submit `op`; or reproduce the reserved one.
fn ship<M: Medium, T: Transport>(
    w: &mut Wallet<M, T>,
    s: &StakingTx,
    access: KeyAccess<'_>,
    op: DustProofOp,
    context: StakingContext,
    expect_balance: Option<u64>,
) -> Outcome {
    let (tag, fee, btl) = (&s.tag, s.fee_total, s.blk_to_live);
    let signed = if s.resign {
        match w.resign_pending(tag, &access, PlanBody::DustProof(op.clone()), fee, btl) {
            Ok(t) => t,
            // A validator transaction reserved below the trigger was signed in
            // the v4.0 exact-balance form, which the node still accepts.
            // `resign_validator` signs that form only if its digest is the
            // reserved one.
            Err(Error::DigestMismatch) => {
                return match exact_balance_form(&op) {
                    Some(v) => match super::resign_validator(w, tag, &access, v, fee, btl) {
                        o if super::not_this_form(&o) => Outcome::NotTheReservedSpend,
                        o => o,
                    },
                    None => Outcome::NotTheReservedSpend,
                }
            }
            Err(Error::ReservationLanded { spent_index, settled_index }) => {
                return Outcome::ReservationAlreadyLanded { source: *tag, spent_index, settled_index }
            }
            Err(e) => return Outcome::Failed(e),
        }
    } else {
        let plan = match w.plan_dust_proof(tag, &access, op.clone(), fee, btl) {
            Ok(p) => p,
            Err(e) => return Outcome::Failed(e),
        };
        if let Some(expected) = expect_balance {
            if let Err(e) = plan.check_expected_balance(expected) {
                return Outcome::Failed(e);
            }
        }
        match w.reserve_and_sign(&plan, access) {
            Ok(t) => t,
            Err(e) => return Outcome::Failed(e),
        }
    };
    let submitted = w.submit(&signed);
    Outcome::StakingSent {
        shipped: StakingShipped {
            source: *tag,
            op,
            fee_total: fee,
            wire: signed.wire(),
            submitted,
            resigned: s.resign,
        },
        context,
    }
}

/// `stake-info [<tag>]`, read-only: the tip, the named tag's stake and
/// entitlement, and `/stats/staking`. Each read's result or failure is
/// reported separately; one failure does not refuse the page.
pub fn cmd_stake_info<T: Transport>(client: &MeshClient<T>, tag: Option<&Tag>, network: Network) -> Outcome {
    let tip = client.network_status();
    let account = tag.map(|t| (*t, client.account_stake(t)));
    let entitlement = match &account {
        Some((t, Ok(at))) if at.stake.is_none_or(|s| s.staked == 0) => Some(client.entitlement(t)),
        _ => None,
    };
    let stats = client.staking_stats();
    Outcome::StakeInfo(Box::new(StakeInfoPage {
        network,
        tip,
        account,
        entitlement,
        stats,
    }))
}
