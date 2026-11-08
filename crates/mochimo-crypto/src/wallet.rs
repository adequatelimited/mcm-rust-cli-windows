// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! The wallet: a keystore and a chain client, reconciled against each other
//! before either can be used to spend (invariant I4).
//!
//! [`Wallet::open`] is the only constructor and it reconciles every account,
//! so a `Wallet` holds a partition: the accounts the chain confirmed and the
//! accounts it could not explain. Every spend path is a method on it, and each
//! refuses an account from the second set. A store in which nothing
//! reconciled is refused outright.
//!
//! The property is per account, because key reuse is a property of one key
//! stream. An account reconciles when the node reports exactly the address
//! this store derives at its stored position. That is not a proof of the
//! ledger: a node can repeat a public address and invent a balance. The
//! durable local index prevents key reuse within this store; it cannot
//! authenticate chain state or account for another copy of the seed.
//!
//! # Scope of the gate
//!
//! The gate is at the wallet layer and has the same bound as
//! [`crate::keystore::Keystore::sign_spend`]. In-crate code can still call
//! `persist_advance` and `sign_spend` on a raw [`Keystore`] directly, as the
//! keystore's own tests do. Users of this type cannot spend from an
//! unreconciled account; a caller that wants that path must obtain a
//! `Keystore` explicitly.
//!
//! Reconciliation runs at construction rather than at first spend, so no
//! divergent state is ever the basis for a displayed balance, an address
//! handed out, or a decision to send.
//!
//! # What the constructor refuses
//!
//! An unreachable chain, a divergent account, a tag the ledger does not hold,
//! and a derived account with no master seed. [`StartupRefusal`] reports every
//! failing account, not only the first.
//!
//! A freshly added, never-funded account therefore blocks startup until it is
//! funded or removed. The Mesh answers *account not found* for a never-funded
//! tag, an emptied tag and a failed lookup alike, so that answer cannot
//! separate *never funded* from *emptied*, *lookup failed*, *wrong chain* or
//! *wrong seed*. The wallet fails closed, and the refusal names every reading.

use core::fmt;

use crate::account::{AdvanceReceipt, WotsIndex};
use crate::addr::Tag;
use crate::consts::SEED_LEN;
use crate::error::{Error, Result};
use crate::keystore::{KeyAccess, Keystore, Medium, SpendAddresses};
use crate::mesh::spend::{DustProofOp, PlanBody, SignedTransaction, SpendPlan, ValidatorOp};
use crate::mesh::{MeshClient, Transport, TxId};
use crate::recon::{self, AccountStatus, Cancel, Divergence, Progress, Reservation, ScanScope, Unfinished};

/// Re-exported from `recon`, where it is defined because the CLI's
/// `reconcile` runs before a `Wallet` exists.
pub use crate::recon::OperatorAcknowledgement;
use crate::secret::Secret;
use crate::tx::wire::Destination;

/// Why the wallet would not start: every account that failed, in tag order.
///
/// `Display` renders each one's full report. Not an [`Error`] variant,
/// because it carries a multi-line report per account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StartupRefusal {
    /// Every account that could not be reconciled. Non-empty by construction:
    /// [`Wallet::open`] returns `Ok` when this would be empty.
    pub diverged: Vec<Divergence>,
    /// How many accounts the store held.
    pub accounts: usize,
}

impl fmt::Display for StartupRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "WALLET WILL NOT START: {} of {} account(s) could not be reconciled against the \
             chain.\n\nThe wallet is failing closed, and it is deliberate. Divergence \
             between a local key index and the chain has three causes -- a crash between signing \
             and persisting, a restored seed with incomplete history, or another install of \
             this seed spending -- and the divergence alone does not say which. So nothing is \
             moved here: `reconcile` moves an account to the index the chain confirms.\n",
            self.diverged.len(),
            self.accounts
        )?;
        for d in &self.diverged {
            writeln!(f, "{d}\n")?;
        }
        write!(
            f,
            "Do not delete local state or reinstall to get past this. Each of those is a path \
             back to the key reuse this refusal exists to prevent."
        )
    }
}

/// What [`Wallet::open_or_return`] gives back when it refuses: the refusal,
/// and the store and the client it was handed, unchanged.
///
/// Returning the store lets a caller retry the open (for example after a
/// transient lookup failure) without unlocking the store again. The store is
/// still unreconciled; opening it again runs the same reconciliation.
pub struct Refused<M: Medium, T: Transport> {
    /// Why the wallet would not start, exactly as [`Wallet::open`] reports it.
    pub refusal: StartupRefusal,
    /// The store, still open and still locked.
    pub store: Keystore<M>,
    /// The chain client, unchanged.
    pub client: MeshClient<T>,
}

impl<M: Medium, T: Transport> fmt::Debug for Refused<M, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Refused")
            .field("refusal", &self.refusal)
            .finish_non_exhaustive()
    }
}

/// What [`Wallet::open_or_return_with`] gives back when it does not open:
/// why (refused or cancelled), and the store and the client it was handed,
/// unchanged.
///
/// Like [`Refused`], but carries [`Unfinished`] so a cancel is distinguished
/// from a refusal. The store is unreconciled, still open and still locked.
pub struct Unopened<M: Medium, T: Transport> {
    /// `Cancelled`, or the refusal [`Wallet::open`] would report.
    pub why: Unfinished<StartupRefusal>,
    /// The store, still open and still locked.
    pub store: Keystore<M>,
    /// The chain client, unchanged.
    pub client: MeshClient<T>,
}

impl<M: Medium, T: Transport> fmt::Debug for Unopened<M, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Unopened")
            .field("why", &self.why)
            .finish_non_exhaustive()
    }
}

/// Why an open did not produce a wallet, with the store and the client it
/// was handed.
type HandedBack<E, M, T> = (E, Keystore<M>, MeshClient<T>);

/// What settling found. Not `Copy`: `StillOutstanding` carries the
/// reservation's diagnosis, which may hold the error a tip read returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Settlement {
    /// The chain holds the change key's address; the reservation moved to the
    /// retained settled block and the account can spend again.
    Settled { spent_index: WotsIndex, index: WotsIndex },
    /// The chain still holds the key that signed; the reservation stands.
    /// `reservation` is reconciliation's classification of it (live, dead,
    /// or not classifiable), for reporting.
    StillOutstanding {
        spent_index: WotsIndex,
        reservation: Reservation,
    },
    /// Nothing was reserved.
    NothingPending { index: WotsIndex },
}

/// A keystore and a chain client, with every account reconciled or recorded as
/// diverged (see the module documentation).
///
/// A reconciled account is one the node reported at exactly the address this
/// store derives at the stored position; a diverged account is one whose
/// state this wallet cannot explain. Only reconciled accounts can act; every
/// method that would act on a diverged one refuses.
#[must_use]
pub struct Wallet<M: Medium, T: Transport> {
    store: Keystore<M>,
    client: MeshClient<T>,
    accounts: Vec<(Tag, AccountStatus)>,
    /// Every account reconciliation could not explain, in tag order. Never
    /// every account, because [`Wallet::open`] refuses a store in which
    /// nothing reconciled.
    diverged: Vec<Divergence>,
}

impl<M: Medium, T: Transport> Wallet<M, T> {
    /// Open a wallet over a store and a client, reconciling every account
    /// first. The only constructor.
    ///
    /// `master` is borrowed for this call and not retained: derived accounts
    /// reconcile through [`KeyAccess::Master`] and imported ones through
    /// [`KeyAccess::StoredRoot`]. A derived account with no master is a
    /// divergence, not a skip.
    ///
    /// # Errors
    ///
    /// [`StartupRefusal`] when no account reconciled, or the store's tags
    /// cannot be read.
    #[allow(clippy::result_large_err)]
    pub fn open(
        store: Keystore<M>,
        client: MeshClient<T>,
        master: Option<&Secret<SEED_LEN>>,
    ) -> core::result::Result<Wallet<M, T>, StartupRefusal> {
        // `Cancel::NEVER` never stops, so the cancel handler is never called.
        Self::open_asking(store, client, master, &Cancel::NEVER, None, || Ok(())).map_err(|(refusal, _, _)| refusal)
    }

    /// [`Wallet::open`], handing the store and the client back when it
    /// refuses ([`Refused`]).
    #[allow(clippy::result_large_err)]
    pub fn open_or_return(
        store: Keystore<M>,
        client: MeshClient<T>,
        master: Option<&Secret<SEED_LEN>>,
    ) -> core::result::Result<Wallet<M, T>, Refused<M, T>> {
        Self::open_asking(store, client, master, &Cancel::NEVER, None, || Ok(()))
            .map_err(|(refusal, store, client)| Refused { refusal, store, client })
    }

    /// [`Wallet::open`], stoppable from outside: `cancel` is asked before
    /// each account and once per position of each diagnostic walk.
    ///
    /// A cancel returns [`Unfinished::Cancelled`], never a refusal, because a
    /// diagnostic walk cut short would produce an incomplete report. Opening
    /// writes nothing. The store and the client are dropped on failure;
    /// [`Wallet::open_or_return_with`] hands them back.
    #[allow(clippy::result_large_err)]
    pub fn open_with(
        store: Keystore<M>,
        client: MeshClient<T>,
        master: Option<&Secret<SEED_LEN>>,
        cancel: &Cancel<'_>,
    ) -> core::result::Result<Wallet<M, T>, Unfinished<StartupRefusal>> {
        Self::open_asking(store, client, master, cancel, None, || Err(Unfinished::Cancelled)).map_err(|(why, _, _)| why)
    }

    /// [`Wallet::open_with`], handing the store and the client back when it
    /// is refused or cancelled ([`Unopened`]), still open and locked, so it
    /// can be opened again without unlocking it again.
    #[allow(clippy::result_large_err)]
    pub fn open_or_return_with(
        store: Keystore<M>,
        client: MeshClient<T>,
        master: Option<&Secret<SEED_LEN>>,
        cancel: &Cancel<'_>,
    ) -> core::result::Result<Wallet<M, T>, Unopened<M, T>> {
        Self::open_asking(store, client, master, cancel, None, || Err(Unfinished::Cancelled))
            .map_err(|(why, store, client)| Unopened { why, store, client })
    }

    /// [`Wallet::open_with`], telling `progress` how far it has got: before
    /// each account, and every [`recon::PROGRESS_EVERY`] positions of each
    /// diagnostic walk ([`Progress`]).
    ///
    /// `progress` is called synchronously on this thread, between steps. Its
    /// figures are counts so far, not an estimate of time remaining.
    #[allow(clippy::result_large_err)]
    pub fn open_with_progress(
        store: Keystore<M>,
        client: MeshClient<T>,
        master: Option<&Secret<SEED_LEN>>,
        cancel: &Cancel<'_>,
        progress: &mut dyn FnMut(Progress),
    ) -> core::result::Result<Wallet<M, T>, Unfinished<StartupRefusal>> {
        Self::open_asking(store, client, master, cancel, Some(progress), || Err(Unfinished::Cancelled))
            .map_err(|(why, _, _)| why)
    }

    /// [`Wallet::open_or_return_with`], telling `progress` how far it has
    /// got, as [`Wallet::open_with_progress`] does.
    #[allow(clippy::result_large_err)]
    pub fn open_or_return_with_progress(
        store: Keystore<M>,
        client: MeshClient<T>,
        master: Option<&Secret<SEED_LEN>>,
        cancel: &Cancel<'_>,
        progress: &mut dyn FnMut(Progress),
    ) -> core::result::Result<Wallet<M, T>, Unopened<M, T>> {
        Self::open_asking(store, client, master, cancel, Some(progress), || Err(Unfinished::Cancelled))
            .map_err(|(why, store, client)| Unopened { why, store, client })
    }

    /// The reconciliation every open runs. `cancelled` supplies the result
    /// for a cancel and is called only after `cancel` has said stop. Any
    /// failure returns the store and the client with it.
    #[allow(clippy::result_large_err)]
    fn open_asking<E: From<StartupRefusal>>(
        store: Keystore<M>,
        client: MeshClient<T>,
        master: Option<&Secret<SEED_LEN>>,
        cancel: &Cancel<'_>,
        mut progress: Option<&mut dyn FnMut(Progress)>,
        cancelled: impl Fn() -> core::result::Result<(), E>,
    ) -> core::result::Result<Wallet<M, T>, HandedBack<E, M, T>> {
        let tags = match store.tags() {
            Ok(t) => t,
            Err(cause) => {
                let refusal = StartupRefusal {
                    diverged: vec![Divergence::CannotReconcile {
                        tag: [0u8; 20],
                        cause,
                    }],
                    accounts: 0,
                };
                return Err((refusal.into(), store, client));
            }
        };
        let accounts = tags.len();
        let mut ok: Vec<(Tag, AccountStatus)> = Vec::new();
        let mut diverged: Vec<Divergence> = Vec::new();
        for (n, tag) in tags.into_iter().enumerate() {
            if cancel.stop() {
                if let Err(why) = cancelled() {
                    return Err((why, store, client));
                }
            }
            let at = Progress {
                account: u32::try_from(n).unwrap_or(u32::MAX),
                accounts: u32::try_from(accounts).unwrap_or(u32::MAX),
                position: 0,
                // Computed only when progress is reported, because it reads
                // the store.
                ceiling: match progress {
                    Some(_) => ScanScope::DIAGNOSTIC.reach(store.view(&tag).ok().flatten().map(|v| v.wots_index)),
                    None => 0,
                },
            };
            if let Some(report) = progress.as_deref_mut() {
                report(at);
            }
            match Self::access_for(&store, &tag, master) {
                Err(d) => diverged.push(d),
                Ok(access) => {
                    let reconciled = recon::watched(cancel, progress.as_deref_mut(), at, |cancel| {
                        recon::reconcile_account_with(&store, &client, &tag, &access, &ScanScope::DIAGNOSTIC, cancel)
                    });
                    match reconciled {
                        Ok(status) => ok.push((tag, status)),
                        Err(d) => {
                            if d.stopped_by_cancel() {
                                if let Err(why) = cancelled() {
                                    return Err((why, store, client));
                                }
                            }
                            diverged.push(d);
                        }
                    }
                }
            }
        }
        // Refuse only when no account is operable. Reconciled accounts stay
        // usable alongside diverged ones, since key reuse is per account. An
        // empty store opens.
        if ok.is_empty() && !diverged.is_empty() {
            return Err((StartupRefusal { diverged, accounts }.into(), store, client));
        }
        Ok(Wallet {
            store,
            client,
            accounts: ok,
            diverged,
        })
    }

    /// Every account reconciliation could not explain, in tag order.
    ///
    /// Callers should report these on every open, not only when the account
    /// is addressed.
    #[must_use]
    pub fn diverged(&self) -> &[Divergence] {
        &self.diverged
    }

    /// This account's divergence, if it has one.
    #[must_use]
    pub fn divergence_for(&self, tag: &Tag) -> Option<&Divergence> {
        self.diverged.iter().find(|d| d.tag() == *tag)
    }

    /// Refuse when `tag` is an account this wallet could not explain.
    ///
    /// Every operation that acts on one account passes through this. It reads
    /// the partition made at open rather than asking the chain again, so an
    /// account that diverged at open stays diverged for this wallet's life.
    fn require_reconciled(&self, tag: &Tag) -> Result<()> {
        match self.divergence_for(tag) {
            None => Ok(()),
            Some(d) => Err(Error::ReconciliationRefused {
                what: divergence_kind(d),
            }),
        }
    }

    /// Which access an account's kind needs, as decided by
    /// `recon::access_for`. A derived account with no master is a divergence,
    /// not a skipped account.
    #[allow(clippy::result_large_err)]
    fn access_for<'a>(
        store: &Keystore<M>,
        tag: &Tag,
        master: Option<&'a Secret<SEED_LEN>>,
    ) -> core::result::Result<KeyAccess<'a>, Divergence> {
        recon::access_for(store, tag, master)
    }

    /// Every account as reconciliation found it at open.
    #[must_use]
    pub fn accounts(&self) -> &[(Tag, AccountStatus)] {
        &self.accounts
    }

    /// Read-only view of the store. There is no `&mut` counterpart, because
    /// it would allow `persist_advance` outside the reconciliation gate.
    pub fn store(&self) -> &Keystore<M> {
        &self.store
    }

    /// The chain client.
    #[must_use]
    pub fn client(&self) -> &MeshClient<T> {
        &self.client
    }

    /// Reconcile one account again now, with the default diagnostic scope,
    /// and report the result without refusing. For long-running callers that
    /// need to detect a divergence that appears after open.
    #[allow(clippy::result_large_err)]
    pub fn status(
        &self,
        tag: &Tag,
        access: &KeyAccess<'_>,
    ) -> core::result::Result<AccountStatus, Divergence> {
        self.status_with(tag, access, &ScanScope::DIAGNOSTIC, &Cancel::NEVER)
    }

    /// [`Wallet::status`] with a caller-set diagnostic scope, for example a
    /// raised ceiling to search beyond the default window.
    #[allow(clippy::result_large_err)]
    pub fn status_with(
        &self,
        tag: &Tag,
        access: &KeyAccess<'_>,
        scope: &ScanScope,
        cancel: &Cancel<'_>,
    ) -> core::result::Result<AccountStatus, Divergence> {
        recon::reconcile_account_with(&self.store, &self.client, tag, access, scope, cancel)
    }

    /// The addresses a spend from `tag` is built for.
    ///
    /// # Errors
    ///
    /// Refuses an account this wallet could not reconcile, because its stored
    /// position was not confirmed by the chain.
    pub fn spend_addresses(&self, tag: &Tag, access: &KeyAccess<'_>) -> Result<SpendAddresses> {
        self.require_reconciled(tag)?;
        self.store.spend_addresses(tag, access)
    }

    /// Lay out a spend: resolve the tag, then build and check the plan.
    /// `SpendPlan::new` checks the chain address again
    /// (`ChainAddressMismatch`), because the chain can move after open.
    pub fn plan(
        &self,
        tag: &Tag,
        access: &KeyAccess<'_>,
        dsts: Vec<Destination>,
        fee_total: u64,
        blk_to_live: u64,
    ) -> Result<SpendPlan> {
        self.require_reconciled(tag)?;
        let addresses = self.store.spend_addresses(tag, access)?;
        let entry = self.client.resolve_tag(tag)?;
        SpendPlan::new(&addresses, &entry, dsts, fee_total, blk_to_live)
    }

    /// Lay out a validator transaction (set-delegate, clear-delegate or
    /// claim) as [`Wallet::plan`] lays out a transfer
    /// ([`SpendPlan::validator`]). It reserves and signs through
    /// [`Wallet::reserve_and_sign`] like any other plan.
    ///
    /// A claim built here is checked only against its own fields, because the
    /// Mesh API does not serve the entitlement. [`Wallet::plan_claim`] checks
    /// it against an entitlement source first.
    pub fn plan_validator(
        &self,
        tag: &Tag,
        access: &KeyAccess<'_>,
        op: ValidatorOp,
        fee_total: u64,
        blk_to_live: u64,
    ) -> Result<SpendPlan> {
        self.require_reconciled(tag)?;
        let addresses = self.store.spend_addresses(tag, access)?;
        let entry = self.client.resolve_tag(tag)?;
        SpendPlan::validator(&addresses, &entry, op, fee_total, blk_to_live)
    }

    /// Lay out a v4.1 dust-proof transaction (stake, unstake, consent or its
    /// revoke, or a claim or delegate change in its change-zero form) as
    /// [`Wallet::plan`] lays out a transfer ([`SpendPlan::dust_proof`]). It
    /// reserves and signs through [`Wallet::reserve_and_sign`] like any
    /// other plan.
    ///
    /// The plan checks the payload and what the spendable balance must cover.
    /// Rules that depend on the stake, the entitlement and the height (minimum
    /// stake, no top-ups, the lock, a claim that would bind nothing) are the
    /// caller's to check against what the Mesh reports.
    pub fn plan_dust_proof(
        &self,
        tag: &Tag,
        access: &KeyAccess<'_>,
        op: DustProofOp,
        fee_total: u64,
        blk_to_live: u64,
    ) -> Result<SpendPlan> {
        self.require_reconciled(tag)?;
        let addresses = self.store.spend_addresses(tag, access)?;
        let entry = self.client.resolve_tag(tag)?;
        SpendPlan::dust_proof(&addresses, &entry, op, fee_total, blk_to_live)
    }

    /// Reserve the key the plan names, sign, and assemble the wire image.
    ///
    /// Before any write, recheck its position and addresses against the
    /// store, a non-zero expiry against the current tip, and its source and
    /// balance against a fresh ledger read. A refusal leaves the key unused.
    /// These observations trust the configured node and cannot prevent a
    /// balance change or expiry after signing; either can permanently lock
    /// funds because the reserved key must never sign a different digest.
    ///
    /// The returned bytes are not persisted; the caller keeps them until the
    /// reservation resolves. The store's crash consistency rests on a single
    /// snapshot write, so a second on-disk artifact is avoided. If the bytes
    /// are lost while the reservation is open, [`Wallet::resign_pending`]
    /// reproduces them byte for byte. That is the only recovery, because the
    /// index never rolls back to the reserved key.
    pub fn reserve_and_sign(
        &mut self,
        plan: &SpendPlan,
        access: KeyAccess<'_>,
    ) -> Result<SignedTransaction> {
        let tag = plan.tag();
        // Covers plans not built through `plan`.
        self.require_reconciled(&tag)?;
        // A plan may be stale (kept across a settle) or built from another
        // store's addresses. Check key access and both addresses before
        // persisting anything irreversible.
        let addresses = self.store.spend_addresses(&tag, &access)?;
        if addresses.position != plan.position() {
            return Err(Error::StaleSpendPlan {
                planned: plan.position().get(),
                stored: addresses.position.get(),
            });
        }
        if addresses.source != *plan.source() || addresses.change != *plan.change() {
            return Err(Error::SpendPlanAddressMismatch);
        }
        if plan.blk_to_live() != 0 {
            let tip = self.client.network_status()?.index;
            // The next block must still be able to include the spend, and a
            // node accepts at most 256 blocks ahead of the tip.
            if !matches!(plan.blk_to_live().checked_sub(tip), Some(1..=256)) {
                return Err(Error::InvalidExpiry { expiry: plan.blk_to_live(), tip });
            }
        }
        // Read the ledger immediately before reserving, to catch changes since
        // planning. This does not authenticate the node's answer or prevent a
        // later incoming credit.
        let entry = self.client.resolve_tag(&tag)?;
        if entry.address != addresses.source {
            return Err(Error::ChainAddressMismatch { position: addresses.position.get() });
        }
        if entry.balance != plan.balance() {
            return Err(Error::BalanceChanged { planned: plan.balance(), current: entry.balance });
        }
        // The reservation records the planned balance and block-to-live, so
        // a later open can compare them with the ledger entry and the tip.
        let receipt = self.store.persist_advance(&tag, &plan.digest(), plan.figures())?;
        let signature = self.store.sign_spend(&plan.digest(), receipt, access)?;
        SignedTransaction::attach(plan, &signature)
    }

    /// Submit the signed bytes. `Ok` means the middleware wrote them to a
    /// node's socket and echoed their id; it is not confirmation of
    /// acceptance. Use [`Wallet::settle_if_landed`] to check that.
    pub fn submit(&self, signed: &SignedTransaction) -> Result<TxId> {
        self.client.submit(signed)
    }

    /// Settle a reservation when the chain holds the tag at the change key's
    /// address. One observation, no confirmation depth.
    ///
    /// Settling early is safe: if a reorg later reverts the spend, the store
    /// has skipped one key position but no key has signed twice, and the next
    /// open reports an index mismatch. Settling late would freeze the account,
    /// because `persist_advance` refuses while a reservation is unresolved.
    pub fn settle_if_landed(&mut self, tag: &Tag, access: &KeyAccess<'_>) -> Result<Settlement> {
        // Not gated on the partition: this reconciles the account afresh and
        // refuses on what it finds. An account that was absent at open and
        // has since been paid can settle without reopening the wallet.
        match recon::reconcile_account(&self.store, &self.client, tag, access) {
            Ok(AccountStatus::SpendLanded {
                spent_index,
                settled_index,
                ..
            }) => {
                self.store.persist_settled(tag)?;
                Ok(Settlement::Settled {
                    spent_index,
                    index: settled_index,
                })
            }
            Ok(AccountStatus::SpendOutstanding {
                spent_index,
                reservation,
                ..
            }) => Ok(Settlement::StillOutstanding {
                spent_index,
                reservation,
            }),
            Ok(AccountStatus::InSync { index, .. }) => Ok(Settlement::NothingPending { index }),
            Err(d) => Err(Error::ReconciliationRefused {
                what: divergence_kind(&d),
            }),
        }
    }

    /// Lay out a claim of `amount` after comparing it with the entitlement
    /// `source` reports for `tag`. Returns the plan and the entitlement it
    /// was compared with.
    ///
    /// The check runs before anything is reserved, because a node would
    /// refuse an excess claim only after the key has signed. The source is
    /// queried once, without retry.
    ///
    /// # Errors
    ///
    /// [`Error::ClaimExceedsEntitlement`] when `amount` is above the
    /// entitlement, any error from `source`, and the errors of
    /// [`Wallet::plan_validator`].
    pub fn plan_claim(
        &self,
        tag: &Tag,
        access: &KeyAccess<'_>,
        amount: u64,
        fee_total: u64,
        blk_to_live: u64,
        source: &dyn crate::entitlement::EntitlementSource,
    ) -> Result<(SpendPlan, crate::entitlement::Entitlement)> {
        self.require_reconciled(tag)?;
        let entitlement = source.entitlement(tag)?;
        if amount > entitlement.amount {
            return Err(Error::ClaimExceedsEntitlement {
                amount,
                entitlement: entitlement.amount,
            });
        }
        let plan = self.plan_validator(tag, access, ValidatorOp::Claim { amount }, fee_total, blk_to_live)?;
        Ok((plan, entitlement))
    }

    /// Reproduce the signed bytes of an outstanding reservation when the
    /// caller has lost them.
    ///
    /// The caller supplies the spend's parameters: the destinations or the
    /// validator operation ([`PlanBody`]; a `Vec<Destination>` converts), the
    /// fee and the block-to-live. Everything else is rebuilt from the store
    /// and the chain, and the rebuilt plan's digest must equal the reserved
    /// one or nothing signs. Because WOTS+ signing is deterministic, the
    /// output is byte-identical to the lost transaction.
    ///
    /// This is the only way to move funds at a reserved key's address: the
    /// index never rolls back, since that would allow a second, different
    /// digest under one key.
    ///
    /// # Errors
    ///
    /// [`Error::NothingPending`] when no reservation is open,
    /// [`Error::DigestMismatch`] when the rebuilt plan is not the reserved
    /// one, and [`Error::ReservationLanded`] when the chain has already moved
    /// to the reservation's change key (settle it with
    /// [`Wallet::settle_if_landed`] instead).
    pub fn resign_pending(
        &mut self,
        tag: &Tag,
        access: &KeyAccess<'_>,
        body: impl Into<PlanBody>,
        fee_total: u64,
        blk_to_live: u64,
    ) -> Result<SignedTransaction> {
        self.require_reconciled(tag)?;
        let view = self.store.view(tag)?.ok_or(Error::NoSuchAccount)?;
        let pending = view.pending.ok_or(Error::NothingPending)?;
        // The addresses the reserved spend was built for. `address_at` does
        // not refuse an outstanding reservation.
        let source = self.store.address_at(tag, pending.spent_index, access)?;
        let change = self.store.address_at(tag, view.wots_index, access)?;
        let addresses = SpendAddresses::of_derived_addresses(*tag, pending.spent_index, source, change);
        let entry = self.client.resolve_tag(tag)?;
        let plan = match SpendPlan::build(&addresses, &entry, body.into(), fee_total, blk_to_live) {
            Ok(plan) => plan,
            // Here the planner's source is the reserved key. If the
            // reservation has landed, the chain is at the change key and the
            // planner refuses with `ChainAddressMismatch`. Ask the reconciler
            // whether the spend landed, so a landed reservation is reported
            // as such rather than as a divergence.
            Err(Error::ChainAddressMismatch { position }) => {
                // Deciding "landed" needs only the address comparison, so walk
                // no positions; the divergence report is discarded here.
                let comparison_only = ScanScope {
                    ceiling: 0,
                    window: None,
                };
                let status = recon::reconcile_account_with(
                    &self.store,
                    &self.client,
                    tag,
                    access,
                    &comparison_only,
                    // Nothing to cancel: ceiling 0 walks no positions.
                    &Cancel::NEVER,
                );
                return Err(match status {
                    Ok(AccountStatus::SpendLanded {
                        spent_index,
                        settled_index,
                        ..
                    }) => Error::ReservationLanded {
                        spent_index: spent_index.get(),
                        settled_index: settled_index.get(),
                    },
                    // A chain at neither of the reservation's keys is a
                    // divergence; keep the planner's error.
                    _ => Error::ChainAddressMismatch { position },
                });
            }
            Err(e) => return Err(e),
        };
        // The rebuilt plan must be the reserved one; otherwise the reserved
        // key would sign a second, different digest.
        if plan.digest() != pending.digest {
            return Err(Error::DigestMismatch);
        }
        let signature = self.store.resign_reserved(tag, access)?;
        SignedTransaction::attach(&plan, &signature)
    }

    /// Advance past a divergence the operator read and acknowledged.
    ///
    /// The only route from this type to `persist_advance_to`. Delegates to
    /// `recon::advance_after_operator_review` with the default diagnostic
    /// scope. The acknowledgement names a tag and a target, and both must
    /// match the store's current divergence, so an acknowledgement of a
    /// stale report or of another account is refused.
    /// [`OperatorAcknowledgement::of`] takes a [`Divergence`], so an advance
    /// always follows a report.
    pub fn advance_after_operator_review(
        &mut self,
        tag: &Tag,
        access: &KeyAccess<'_>,
        ack: OperatorAcknowledgement,
    ) -> Result<AdvanceReceipt> {
        self.advance_after_operator_review_with(tag, access, ack, &ScanScope::DIAGNOSTIC, &Cancel::NEVER)
    }

    /// [`Wallet::advance_after_operator_review`] under a caller-set scope,
    /// which must be the scope the acknowledged report was made with.
    pub fn advance_after_operator_review_with(
        &mut self,
        tag: &Tag,
        access: &KeyAccess<'_>,
        ack: OperatorAcknowledgement,
        scope: &ScanScope,
        cancel: &Cancel<'_>,
    ) -> Result<AdvanceReceipt> {
        // Not gated on the partition: this exists to act on a diverged
        // account, and `recon` re-derives and re-compares before it writes.
        // The partition is not updated; the account stays diverged until the
        // wallet is reopened.
        recon::advance_after_operator_review(
            &mut self.store,
            &self.client,
            tag,
            access,
            ack,
            scope,
            cancel,
        )
    }

    /// Split the wallet into its store and client. The returned keystore is
    /// no longer covered by the reconciliation gate.
    pub fn into_parts(self) -> (Keystore<M>, MeshClient<T>) {
        (self.store, self.client)
    }
}

/// A short static label for a divergence, carried by [`Error`] in place of
/// the full report or any server-authored text.
fn divergence_kind(d: &Divergence) -> &'static str {
    match d {
        Divergence::IndexMismatch { .. } => "index mismatch",
        Divergence::ReservationUnexplained { .. } => "reservation unexplained",
        Divergence::TagUnresolved { .. } => "tag unresolved by the node",
        Divergence::ChainUnreachable { .. } => "chain unreachable",
        Divergence::NoMasterForDerivedAccount { .. } => "no master for a derived account",
        Divergence::CannotReconcile { .. } => "reconciliation could not run",
    }
}

impl<M: Medium, T: Transport> fmt::Debug for Wallet<M, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Wallet")
            .field("accounts", &self.accounts.len())
            .finish_non_exhaustive()
    }
}
