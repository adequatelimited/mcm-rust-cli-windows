// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! Building the transaction a wallet signs, and attaching the signature the
//! keystore released. The transaction is built locally from parts this crate
//! holds, never from bytes a server returned.
//!
//! # Why local
//!
//! A wallet that asks the Mesh middleware to construct the unsigned
//! transaction and signs whatever comes back lets the middleware choose what
//! is signed. Here [`SpendPlan::new`] lays out every byte of the signed
//! prefix from the keystore's addresses, the caller's destinations and fee,
//! and one observation of the chain; [`SignedTransaction::attach`] attaches
//! the keystore's signature and re-validates the whole image as the node
//! will. The bytes sent are `wire()`, unchanged.
//!
//! # The server-supplied balance
//!
//! `change_total` is `balance - send - fee`, and the balance comes from the
//! configured node through `/call tag_resolve`. The node's `tx_val` requires
//! `send + change + fee` to equal the ledger balance exactly (`EMCM_TXTOTAL`).
//! A false or stale balance therefore creates an unusable signed spend.
//! Because its key must never sign a different digest, this can permanently
//! lock the balance at the source address even though change names our key.
//!
//! `Wallet::reserve_and_sign` rechecks the balance and address immediately
//! before reservation to catch changes since planning. Repeating a request
//! to the same node does not authenticate it, and a payment can still arrive
//! after that check. Use a trusted node and avoid concurrent incoming
//! payments while a spend is outstanding; never recover by reusing a key.
//! [`SpendPlan::check_expected_balance`] refuses a plan built against any
//! balance other than one the caller read from an independent source; the
//! command line exposes it as `--expect-balance`.
//!
//! # What is refused before anything is reserved
//!
//! Each refusal mirrors a `tx_val`/`mdst_val` check and runs before a key is
//! reserved. `tx_val` needs an open ledger, so most of these are read from
//! the node's source rather than confirmed against a node verdict; the WOTS+
//! checks ([`verify_wots`]) and the destination order have recorded reference
//! verdicts in the fixture corpus.
//!
//! The destination reference grammar is enforced by [`reference_is_valid`],
//! a state-for-state transcription of the node's `mdst_val__reference`
//! (refused as `EMCM_XTXREF`). The serializer emits the bytes given; the rule
//! is applied before them.
//!
//! The plan checks only the protocol fee floor; the node's configured fee
//! (`Myfee`) is not knowable offline. The wallet checks a non-zero
//! block-to-live against the observed tip before reserving, but the plan
//! itself has no tip. Neither check guarantees acceptance: the tip or
//! ledger balance can change before validation, and a signed transaction
//! that becomes unusable cannot safely be replaced under the reserved key.
//!
//! # Validator transactions
//!
//! [`SpendPlan::validator`] lays out the three transactions a validator's
//! cold key signs on the proof-of-stake chain (set-delegate, clear-delegate
//! and claim, [`ValidatorOp`]) through the same reservation, signature and
//! attachment as a transfer; only the payload differs. Their rules: no
//! destinations and a `send_total` of zero, so the change is exactly the
//! balance less the fee; one `MFEE` for the whole transaction; a
//! set-delegate names a non-zero tag that is not the source's; a claim is not
//! zero. What only the node can decide is listed at [`SpendPlan::validator`].
//!
//! # v4.1 dust-proof transactions
//!
//! [`SpendPlan::dust_proof`] lays out the transactions v4.1 adds (stake,
//! unstake, consent and its revoke, [`DustProofOp`]) and the change-zero form
//! v4.1 accepts for a claim and a delegate change. Every one signs
//! `send_total = change_total = 0`: the node checks what the balance must
//! cover and credits the change itself, so a payment landing on the source
//! after signing cannot invalidate it. Rules that depend on the stake, the
//! entitlement and the height are checked by `cli::staking` against what the
//! Mesh reports.
//!
//! # The flow is composed by the caller
//!
//! Nothing here calls `sign_spend`; the keystore is the only signer. The
//! sequence, as exercised in `tests/spend.rs`:
//!
//! ```text
//! a    = keystore.spend_addresses(&tag, &access)?
//! e    = client.resolve_tag(&tag)?                 e.address must be a.source
//! plan = SpendPlan::new(&a, &e, dsts, fee, btl)?   every refusal below
//! r    = keystore.persist_advance(&tag, &plan.digest(), plan.figures())?
//!        r.index() == plan.position().advanced()   the caller's own check
//! keystore.check_spend(&plan.digest(), &r, &access)?   optional: the same checks on a borrowed
//!                                                      receipt; `Wallet::reserve_and_sign` skips it
//! sig  = keystore.sign_spend(&plan.digest(), r, access)?
//! tx   = SignedTransaction::attach(&plan, &sig)?   recovery, then sealed
//! keep tx.wire() outside the format                the retry artifact
//! id   = client.submit(&tx)?                       a socket write, not a verdict
//! ```

use crate::account::WotsIndex;
use crate::addr::{self, Address};
use crate::consts::{ADDR_REF_LEN, HASHLEN, MFEE};
use crate::error::{Error, Result};
use crate::keystore::{Figures, SpendAddresses, SpendSignature};
use crate::tx::wire::{Body, Destination, Transaction, WotsVal};
use crate::wots::{self, Adrs};

use super::{LedgerEntry, TxId};

/// The node's validator for a destination's 16-byte reference field
/// (`MDST::ref`): a state-for-state transcription of the reference's
/// `mdst_val__reference` (commit `bbbaceabe5c21b5d8a094cf34c050d28e4ae93f4`),
/// which refuses with `EMCM_XTXREF`.
///
/// The states are the C's `START`, `DIGIT_DASH`, `DIGIT`, `UPPER_DASH`,
/// `UPPER` and `ZERO`. `START` falls through into `DIGIT_DASH`'s test, so
/// both accept an uppercase letter. Classification is ASCII-only
/// (`'0'..='9'`, `'A'..='Z'`); a high-bit byte matches neither. All sixteen
/// bytes are scanned, and the machine must end in `ZERO`, `DIGIT` or `UPPER`.
///
/// Accepted: all-NUL; otherwise groups that are each all uppercase or all
/// digits, neighbouring groups of different kinds, separated by single
/// dashes, no leading or trailing dash, and every byte after the first NUL
/// zero. Sixteen non-NUL bytes ending in a group are valid.
#[must_use]
pub fn reference_is_valid(reference: &[u8; ADDR_REF_LEN]) -> bool {
    #[derive(Clone, Copy)]
    enum State {
        Start,
        DigitDash,
        Digit,
        UpperDash,
        Upper,
        Zero,
    }
    let mut state = State::Start;
    for &c in reference {
        state = match state {
            State::Start if c == 0 => State::Zero,
            State::Start if c.is_ascii_digit() => State::Digit,
            State::Start | State::DigitDash if c.is_ascii_uppercase() => State::Upper,
            State::UpperDash if c.is_ascii_digit() => State::Digit,
            State::Digit if c.is_ascii_digit() => State::Digit,
            State::Digit if c == b'-' => State::DigitDash,
            State::Digit if c == 0 => State::Zero,
            State::Upper if c.is_ascii_uppercase() => State::Upper,
            State::Upper if c == b'-' => State::UpperDash,
            State::Upper if c == 0 => State::Zero,
            State::Zero if c == 0 => State::Zero,
            _ => return false,
        };
    }
    matches!(state, State::Zero | State::Digit | State::Upper)
}

/// One of the three transactions a validator's cold key signs, as the
/// caller asks for it: the payload, without the header a plan supplies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidatorOp {
    /// Bind `delegate` to the source's validator slot.
    SetDelegate {
        /// The delegate's 20-byte tag.
        delegate: crate::addr::Tag,
    },
    /// Clear the source's delegate binding.
    ClearDelegate,
    /// Release `amount` nanoMochimo of entitlement into spendable balance.
    Claim {
        /// The quantity to release.
        amount: u64,
    },
}

impl ValidatorOp {
    /// The wire payload this operation is.
    #[must_use]
    pub fn body(&self) -> Body {
        match self {
            ValidatorOp::SetDelegate { delegate } => Body::SetDelegate { delegate: *delegate },
            ValidatorOp::ClearDelegate => Body::ClearDelegate,
            ValidatorOp::Claim { amount } => Body::Claim { amount: *amount },
        }
    }
}

/// One of the v4.1 dust-proof transactions, as the caller asks for it: the
/// payload, without the header a plan supplies. Every one signs
/// `send_total = change_total = 0`; the node checks what the balance must
/// cover and credits the change itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DustProofOp {
    /// `TXDAT_STAKE`: stake `amount` at `tier`, for the chain `network` names.
    Stake {
        amount: u64,
        tier: u8,
        network: u16,
    },
    /// `TXDAT_UNSTAKE`: end the stake.
    Unstake {
        network: u16,
    },
    /// `TXDAT_ACCEPT`: consent to a designation, or with kind 0 revoke.
    Accept(crate::staking::ConsentTerms),
    /// `TXDAT_CLAIM` with change zero; `u64::MAX` claims everything.
    Claim {
        amount: u64,
    },
    /// `TXDAT_SET_DELEGATE` with change zero.
    SetDelegate {
        delegate: crate::addr::Tag,
    },
    /// `TXDAT_CLEAR_DELEGATE` with change zero.
    ClearDelegate,
}

impl DustProofOp {
    /// The wire payload this operation is.
    #[must_use]
    pub fn body(&self) -> Body {
        match self {
            DustProofOp::Stake { amount, tier, network } => Body::Stake {
                amount: *amount,
                tier: *tier,
                network: *network,
            },
            DustProofOp::Unstake { network } => Body::Unstake { network: *network },
            DustProofOp::Accept(terms) => Body::Accept(*terms),
            DustProofOp::Claim { amount } => Body::Claim { amount: *amount },
            DustProofOp::SetDelegate { delegate } => Body::SetDelegate { delegate: *delegate },
            DustProofOp::ClearDelegate => Body::ClearDelegate,
        }
    }
}

/// What a plan carries: a transfer's destinations, a validator operation in
/// its v4.0 exact-balance form, or a v4.1 dust-proof operation.
/// `Wallet::resign_pending` rebuilds a reserved plan from this, so every kind
/// is reproduced by the same composer and checked by the same digest
/// comparison.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlanBody {
    /// A transfer: [`SpendPlan::new`].
    Transfer(Vec<Destination>),
    /// A validator transaction: [`SpendPlan::validator`].
    Validator(ValidatorOp),
    /// A v4.1 dust-proof transaction: [`SpendPlan::dust_proof`].
    DustProof(DustProofOp),
}

impl From<Vec<Destination>> for PlanBody {
    fn from(dsts: Vec<Destination>) -> PlanBody {
        PlanBody::Transfer(dsts)
    }
}

impl From<ValidatorOp> for PlanBody {
    fn from(op: ValidatorOp) -> PlanBody {
        PlanBody::Validator(op)
    }
}

impl From<DustProofOp> for PlanBody {
    fn from(op: DustProofOp) -> PlanBody {
        PlanBody::DustProof(op)
    }
}

/// A spend laid out and checked, before any key is reserved.
///
/// Holds the header values and the payload, not a [`Transaction`], so it
/// carries no signature. The unsigned image is rebuilt from these fields when
/// needed, and the cached digest is `TX_HASH_MESSAGE` over that image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendPlan {
    position: WotsIndex,
    src_addr: Address,
    chg_addr: Address,
    send_total: u64,
    change_total: u64,
    fee_total: u64,
    blk_to_live: u64,
    /// `entry.balance` as observed when the plan was built; see
    /// [`SpendPlan::balance`].
    balance: u64,
    /// The payload: a transfer's destinations in wire order, or a validator
    /// operation's.
    body: Body,
    digest: [u8; HASHLEN],
}

impl SpendPlan {
    /// Lays out and checks a spend. The refusals, in order:
    ///
    /// 1. `entry.address != addresses.source` —
    ///    [`Error::ChainAddressMismatch`]: the chain does not hold this tag at
    ///    the key this store signs with next.
    /// 2. a destination count outside `1..=256` — `Error::Range`, from
    ///    [`Transaction::new`](crate::tx::wire::Transaction::new).
    /// 3. a zero amount — [`Error::ZeroAmount`].
    /// 4. a destination carrying the source's tag —
    ///    [`Error::DestinationIsSource`].
    /// 5. the amount tally overflowing — [`Error::Overflow`].
    /// 6. a reference the node's rule refuses — [`Error::InvalidReference`]
    ///    ([`reference_is_valid`]).
    /// 7. `fee_total < MFEE × count` — [`Error::FeeBelowMinimum`]
    ///    (`tx_val`'s own `fee >= MFEE` is implied
    ///    for one destination or more).
    /// 8. `send + fee > balance` — [`Error::InsufficientBalance`]; the change
    ///    is the remainder, so `send + change + fee == balance` holds by
    ///    construction against the observation.
    ///
    /// Destinations are sorted by their 44-byte image, as the node requires
    /// (`EMCM_TXMDSTSORT`); duplicates are kept.
    ///
    /// What only the node can decide, and refuses after the key has signed:
    /// that the source is not bound as a validator's delegate. The node
    /// accepts nothing from a bound delegate's tag but a delegate re-key and
    /// an attestation (`EMCM_BOUND_DELEGATE_CANNOT_SEND`), and the Mesh does
    /// not disclose the binding, so a transfer from such a tag leaves its key
    /// reserved for a transaction that cannot land. The same holds for
    /// [`SpendPlan::validator`] and [`SpendPlan::dust_proof`].
    pub fn new(
        addresses: &SpendAddresses,
        entry: &LedgerEntry,
        mut dsts: Vec<Destination>,
        fee_total: u64,
        blk_to_live: u64,
    ) -> Result<SpendPlan> {
        if entry.address != addresses.source {
            return Err(Error::ChainAddressMismatch {
                position: addresses.position.get(),
            });
        }
        dsts.sort_by_key(Destination::mdst_image);
        // Enforces the destination-count bound.
        let mut tx = Transaction::new(dsts)?;

        let src_tag = addr::tag_of(&addresses.source);
        let mut send_total: u64 = 0;
        for (index, d) in tx.dsts().iter().enumerate() {
            if d.amount == 0 {
                return Err(Error::ZeroAmount { index });
            }
            if d.tag == src_tag {
                return Err(Error::DestinationIsSource { index });
            }
            send_total = send_total
                .checked_add(d.amount)
                .ok_or(Error::Overflow { what: "send total" })?;
            if !reference_is_valid(&d.reference) {
                return Err(Error::InvalidReference { index });
            }
        }
        let count = u64::from(tx.dst_count());
        let min_fee = MFEE.checked_mul(count).ok_or(Error::Overflow { what: "fee floor" })?;
        if fee_total < min_fee {
            return Err(Error::FeeBelowMinimum {
                fee: fee_total,
                min: min_fee,
            });
        }
        let needed = send_total
            .checked_add(fee_total)
            .ok_or(Error::Overflow { what: "send plus fee" })?;
        let change_total = entry
            .balance
            .checked_sub(needed)
            .ok_or(Error::InsufficientBalance {
                balance: entry.balance,
                needed,
            })?;

        tx.src_addr = addresses.source;
        tx.chg_addr = addresses.change;
        tx.send_total = send_total;
        tx.change_total = change_total;
        tx.fee_total = fee_total;
        tx.blk_to_live = blk_to_live;
        let digest = tx.message_digest();

        Ok(SpendPlan {
            position: addresses.position,
            src_addr: tx.src_addr,
            chg_addr: tx.chg_addr,
            send_total,
            change_total,
            fee_total,
            blk_to_live,
            balance: entry.balance,
            body: tx.body().clone(),
            digest,
        })
    }

    /// [`SpendPlan::new`], [`SpendPlan::validator`] or
    /// [`SpendPlan::dust_proof`], as `body` says.
    pub fn build(
        addresses: &SpendAddresses,
        entry: &LedgerEntry,
        body: PlanBody,
        fee_total: u64,
        blk_to_live: u64,
    ) -> Result<SpendPlan> {
        match body {
            PlanBody::Transfer(dsts) => SpendPlan::new(addresses, entry, dsts, fee_total, blk_to_live),
            PlanBody::Validator(op) => SpendPlan::validator(addresses, entry, op, fee_total, blk_to_live),
            PlanBody::DustProof(op) => SpendPlan::dust_proof(addresses, entry, op, fee_total, blk_to_live),
        }
    }

    /// Lays out and checks one of a validator's three transactions. The
    /// refusals, in order:
    ///
    /// 1. `entry.address != addresses.source` —
    ///    [`Error::ChainAddressMismatch`], as for a transfer.
    /// 2. a set-delegate naming the all-zero tag —
    ///    [`Error::DelegateIsZero`]; naming the source's own tag —
    ///    [`Error::DelegateIsSource`].
    /// 3. a claim of zero — [`Error::ClaimZero`].
    /// 4. `fee_total < MFEE` — [`Error::FeeBelowMinimum`]: `tx_val` asks one
    ///    fee of the transaction, and these carry no destinations to count.
    /// 5. `fee > balance` — [`Error::InsufficientBalance`]. The fee comes from
    ///    the spendable balance, never from entitlement, so a cold address
    ///    must hold at least the fee before it can claim.
    ///
    /// `send_total` is zero and `change_total` is `balance - fee`, so
    /// `send + change + fee` equals the observed balance exactly, as `tx_val`
    /// requires.
    ///
    /// What only the node can decide, and refuses after the key has signed:
    /// that the source holds a validator slot; for a set-delegate,
    /// that the delegate tag is on the ledger with at least
    /// [`crate::consts::pos::DELEGATE_MIN_BALANCE`], holds no validator slot
    /// of its own and is bound to no other validator; for a claim, that the
    /// amount does not exceed the source's entitlement, a column the Mesh API
    /// does not serve. `Wallet::plan_claim` checks the last against an
    /// entitlement source before this is reached.
    pub fn validator(
        addresses: &SpendAddresses,
        entry: &LedgerEntry,
        op: ValidatorOp,
        fee_total: u64,
        blk_to_live: u64,
    ) -> Result<SpendPlan> {
        if entry.address != addresses.source {
            return Err(Error::ChainAddressMismatch {
                position: addresses.position.get(),
            });
        }
        let src_tag = addr::tag_of(&addresses.source);
        match &op {
            ValidatorOp::SetDelegate { delegate } => {
                if delegate.iter().all(|b| *b == 0) {
                    return Err(Error::DelegateIsZero);
                }
                if delegate.as_slice() == src_tag {
                    return Err(Error::DelegateIsSource);
                }
            }
            ValidatorOp::ClearDelegate => {}
            ValidatorOp::Claim { amount } => {
                if *amount == 0 {
                    return Err(Error::ClaimZero);
                }
            }
        }
        if fee_total < MFEE {
            return Err(Error::FeeBelowMinimum {
                fee: fee_total,
                min: MFEE,
            });
        }
        let change_total = entry
            .balance
            .checked_sub(fee_total)
            .ok_or(Error::InsufficientBalance {
                balance: entry.balance,
                needed: fee_total,
            })?;

        let mut tx = Transaction::with_body(op.body())?;
        tx.src_addr = addresses.source;
        tx.chg_addr = addresses.change;
        tx.send_total = 0;
        tx.change_total = change_total;
        tx.fee_total = fee_total;
        tx.blk_to_live = blk_to_live;
        let digest = tx.message_digest();

        Ok(SpendPlan {
            position: addresses.position,
            src_addr: tx.src_addr,
            chg_addr: tx.chg_addr,
            send_total: 0,
            change_total,
            fee_total,
            blk_to_live,
            balance: entry.balance,
            body: tx.body().clone(),
            digest,
        })
    }

    /// Lays out and checks one of the v4.1 dust-proof transactions. The
    /// refusals, in order:
    ///
    /// 1. `entry.address != addresses.source` --
    ///    [`Error::ChainAddressMismatch`], as for a transfer.
    /// 2. the payload's own fields: a stake of zero or above tier 5
    ///    ([`Error::StakeFields`]); a claim of zero ([`Error::ClaimZero`]); a
    ///    set-delegate naming the zero tag or the source
    ///    ([`Error::DelegateIsZero`], [`Error::DelegateIsSource`]); consent
    ///    terms its kind does not carry, or a peer that is the source
    ///    ([`Error::ConsentTerms`]).
    /// 3. `fee_total < MFEE` -- [`Error::FeeBelowMinimum`].
    /// 4. what the spendable balance must cover: `amount + fee` for a stake,
    ///    the fee for a consent, a revoke and a delegate change --
    ///    [`Error::InsufficientBalance`]. An unstake and a claim may pay the
    ///    fee from the principal they release, which the plan cannot see, so
    ///    the caller checks those against the stake it read.
    ///
    /// `send_total` and `change_total` are zero. The minimum stake at the
    /// including height, the stake and consent state, and whether the source
    /// is a validator address are checked by the caller against what the Mesh
    /// reports, and finally by the node.
    pub fn dust_proof(
        addresses: &SpendAddresses,
        entry: &LedgerEntry,
        op: DustProofOp,
        fee_total: u64,
        blk_to_live: u64,
    ) -> Result<SpendPlan> {
        if entry.address != addresses.source {
            return Err(Error::ChainAddressMismatch {
                position: addresses.position.get(),
            });
        }
        let src_tag = addr::tag_of(&addresses.source);
        let mut covers: u64 = 0;
        match &op {
            DustProofOp::Stake { amount, tier, .. } => {
                if *amount == 0 || *tier >= crate::staking::TIERS {
                    return Err(Error::StakeFields { amount: *amount, tier: *tier });
                }
                covers = *amount;
            }
            DustProofOp::Unstake { .. } => {}
            DustProofOp::Claim { amount } => {
                if *amount == 0 {
                    return Err(Error::ClaimZero);
                }
            }
            DustProofOp::SetDelegate { delegate } => {
                if delegate.iter().all(|b| *b == 0) {
                    return Err(Error::DelegateIsZero);
                }
                if delegate.as_slice() == src_tag {
                    return Err(Error::DelegateIsSource);
                }
            }
            DustProofOp::ClearDelegate => {}
            DustProofOp::Accept(terms) => {
                let mut own = [0u8; crate::consts::ADDR_TAG_LEN];
                own.copy_from_slice(src_tag);
                terms.check(&own)?;
            }
        }
        if fee_total < MFEE {
            return Err(Error::FeeBelowMinimum {
                fee: fee_total,
                min: MFEE,
            });
        }
        if !matches!(op, DustProofOp::Unstake { .. } | DustProofOp::Claim { .. }) {
            let needed = covers
                .checked_add(fee_total)
                .ok_or(Error::Overflow { what: "stake plus fee" })?;
            if needed > entry.balance {
                return Err(Error::InsufficientBalance {
                    balance: entry.balance,
                    needed,
                });
            }
        }
        let mut tx = Transaction::with_body(op.body())?;
        tx.src_addr = addresses.source;
        tx.chg_addr = addresses.change;
        tx.send_total = 0;
        tx.change_total = 0;
        tx.fee_total = fee_total;
        tx.blk_to_live = blk_to_live;
        let digest = tx.message_digest();
        Ok(SpendPlan {
            position: addresses.position,
            src_addr: tx.src_addr,
            chg_addr: tx.chg_addr,
            send_total: 0,
            change_total: 0,
            fee_total,
            blk_to_live,
            balance: entry.balance,
            body: tx.body().clone(),
            digest,
        })
    }

    /// `TX_HASH_MESSAGE` over the unsigned image: what `persist_advance`
    /// reserves the key for and what `sign_spend` signs.
    pub fn digest(&self) -> [u8; HASHLEN] {
        self.digest
    }

    /// The account tag this spend is from: the tag half of `src_addr`, taken
    /// from the keystore's own `SpendAddresses`. `Wallet::reserve_and_sign`
    /// reserves against this, so a plan cannot be reserved against another
    /// account.
    #[must_use]
    pub fn tag(&self) -> crate::addr::Tag {
        let mut tag = [0u8; crate::consts::ADDR_TAG_LEN];
        tag.copy_from_slice(addr::tag_of(&self.src_addr));
        tag
    }

    /// The position the plan was built for: the key that must sign it.
    pub fn position(&self) -> WotsIndex {
        self.position
    }

    pub fn source(&self) -> &Address {
        &self.src_addr
    }

    pub fn change(&self) -> &Address {
        &self.chg_addr
    }

    pub fn send_total(&self) -> u64 {
        self.send_total
    }

    pub fn change_total(&self) -> u64 {
        self.change_total
    }

    pub fn fee_total(&self) -> u64 {
        self.fee_total
    }

    pub fn blk_to_live(&self) -> u64 {
        self.blk_to_live
    }

    /// The ledger balance the plan was built against, which `tx_val` requires
    /// `send + change + fee` to equal exactly. Stored as observed rather than
    /// summed from the totals. The wallet compares a fresh observation to
    /// this before reservation and never adjusts the plan to match.
    pub fn balance(&self) -> u64 {
        self.balance
    }

    /// Refuses with [`Error::BalanceNotExpected`] unless the plan was built
    /// against `expected`, a balance the caller read from a source other
    /// than the node that served the plan. `Wallet::reserve_and_sign`
    /// reserves only against a fresh observation equal to
    /// [`SpendPlan::balance`], so a plan that passes is reserved against
    /// `expected` too.
    pub fn check_expected_balance(&self, expected: u64) -> Result<()> {
        if self.balance != expected {
            return Err(Error::BalanceNotExpected {
                expected,
                reported: self.balance,
            });
        }
        Ok(())
    }

    /// The two figures the keystore records for this plan's reservation:
    /// [`SpendPlan::balance`] and [`SpendPlan::blk_to_live`].
    pub fn figures(&self) -> Figures {
        Figures {
            reserved_balance: self.balance(),
            blk_to_live: self.blk_to_live(),
        }
    }

    /// The destinations, in wire order; empty for any non-transfer payload.
    pub fn dsts(&self) -> &[Destination] {
        match &self.body {
            Body::Transfer(dsts) => dsts,
            _ => &[],
        }
    }

    /// The payload.
    pub fn body(&self) -> &Body {
        &self.body
    }

    /// The unsigned image these fields describe: zero validation data, no
    /// trailer. Private, so the only route from a plan to a signature-bearing
    /// value is [`SignedTransaction::attach`].
    fn unsigned(&self) -> Result<Transaction> {
        let mut tx = Transaction::with_body(self.body.clone())?;
        tx.src_addr = self.src_addr;
        tx.chg_addr = self.chg_addr;
        tx.send_total = self.send_total;
        tx.change_total = self.change_total;
        tx.fee_total = self.fee_total;
        tx.blk_to_live = self.blk_to_live;
        Ok(tx)
    }
}

/// A transaction with its signature attached, re-validated and sealed.
///
/// Its only constructor, [`SignedTransaction::attach`], takes public data
/// only and reaches no signer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedTransaction {
    tx: Transaction,
}

impl SignedTransaction {
    /// Attaches `sig` to the image `plan` describes, refusing unless it
    /// validates as the node will validate it:
    ///
    /// * `sig.spent_index` must be `plan.position()` —
    ///   [`Error::PositionMismatch`];
    /// * `pk_from_sig` from the words the key started from must recover
    ///   `sig.public_key` — [`Error::SignatureDoesNotRecover`] naming the
    ///   public key;
    /// * the assembled image must pass [`verify_wots`] — the same recovery
    ///   from the wire's own `adrs`, plus `tx_val__wots`'s two comparisons.
    ///
    /// The `adrs` on the wire is the state `pk_from_sig` leaves behind, not
    /// the words the key started from: `tx_val__wots` compares the supplied
    /// `adrs` with the post-recovery one, whose last twelve bytes are the
    /// triple every WOTS+ chain walk ends on.
    ///
    /// The trailer is then sealed with nonce zero and `id = TX_HASH_ID`, as
    /// the node writes it after validation.
    pub fn attach(plan: &SpendPlan, sig: &SpendSignature) -> Result<SignedTransaction> {
        if sig.spent_index != plan.position {
            return Err(Error::PositionMismatch {
                planned: plan.position.get(),
                signed: sig.spent_index.get(),
            });
        }
        let mut tx = plan.unsigned()?;
        let digest = tx.message_digest();
        let mut adrs: Adrs = sig.adrs;
        let recovered = wots::pk_from_sig(&sig.signature, &digest, &sig.pub_seed, &mut adrs);
        if *recovered != *sig.public_key {
            return Err(Error::SignatureDoesNotRecover { what: "public key" });
        }
        tx.wots = WotsVal {
            signature: *sig.signature,
            pub_seed: sig.pub_seed,
            adrs: adrs.le_image(),
        };
        verify_wots(&tx)?;
        tx.seal();
        Ok(SignedTransaction { tx })
    }

    /// The whole wire image, trailer included: what `/construction/submit`
    /// forwards, and the retry artifact a caller keeps.
    pub fn wire(&self) -> Vec<u8> {
        self.tx.to_wire()
    }

    /// The transaction id the node will store: `TX_HASH_ID` with the nonce
    /// zero, which is what `/construction/submit` echoes and `/mempool`
    /// lists.
    pub fn id(&self) -> TxId {
        TxId(self.tx.id_digest())
    }

    /// The signed length, `dsa_off`, and the full length, for a caller
    /// reporting what it is about to send.
    pub fn lengths(&self) -> (usize, usize) {
        (self.tx.dsa_off(), self.tx.wire_len())
    }
}

/// `tx_val__wots` over an assembled image: recover the public key from the
/// wire's own `adrs` over `TX_HASH_MESSAGE`; the post-recovery `adrs` must
/// equal the wire's, and the recovered key's address hash must equal the
/// source address's hash half.
///
/// # Errors
///
/// [`Error::SignatureDoesNotRecover`] naming the failed comparison:
/// `"address scheme"` or `"source address hash"`.
pub fn verify_wots(tx: &Transaction) -> Result<()> {
    let digest = tx.message_digest();
    let supplied = Adrs::from_le_image(&tx.wots.adrs);
    let mut working = supplied;
    let recovered = wots::pk_from_sig(&tx.wots.signature, &digest, &tx.wots.pub_seed, &mut working);
    if working != supplied {
        return Err(Error::SignatureDoesNotRecover {
            what: "address scheme",
        });
    }
    let address = addr::from_wots(&recovered);
    if addr::hash_of(&address) != addr::hash_of(&tx.src_addr) {
        return Err(Error::SignatureDoesNotRecover {
            what: "source address hash",
        });
    }
    Ok(())
}
