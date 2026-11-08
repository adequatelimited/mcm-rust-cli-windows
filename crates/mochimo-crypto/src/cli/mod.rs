// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! `tawara`, the command layer.
//!
//! The binary is `src/bin/tawara.rs`; every command is implemented here,
//! generic over [`Medium`] and [`Transport`] so tests can run each command
//! against a scripted chain.
//!
//! # Wallet gate
//!
//! No command holds a `Wallet` and a mutable `Keystore` at once. The commands
//! that hold a mutable store ([`create`], [`restore`] and [`reconcile`]) never
//! name a signer or a `Wallet`; every other command takes a `Wallet`, whose
//! store is reachable only by shared reference. `status` and `reconcile` run
//! before a `Wallet` exists because `Wallet::open` refuses a store with a
//! divergence.
//!
//! Commands return a rendered [`Report`] rather than a signature-bearing
//! type.
//!
//! # What the output must state
//!
//! * A submission is a socket write, not acceptance: `/construction/submit`
//!   returns before the node validates and echoes a locally computed id.
//! * A transaction that passes every offline check can still be rejected by
//!   the node for a ledger, balance or block-to-live reason.
//! * The retry artifact `send` prints is the only copy of the signed bytes.

pub mod address;
pub mod args;
pub mod create;
pub mod discover;
pub mod outcome;
pub mod reconcile;
pub mod render;
pub mod restore;
pub mod staking;

use crate::addr::Tag;
use crate::consts::{ADDR_LEN, ADDR_REF_LEN, ADDR_TAG_LEN, HASHLEN, SEED_LEN};
use crate::keystore::{KeyAccess, Keystore, Medium};
use crate::mesh::spend::SpendPlan;
use crate::mesh::codec;
use crate::mesh::{MeshClient, Transport, TxId};
use crate::account::WotsIndex;
use crate::recon::{AccountStatus, ChainPosition, Divergence, Expiry, Reservation};
use crate::tx::wire::Destination;
use crate::wallet::Wallet;
use crate::{Error, Result, Secret};

use args::{Command, Spend};
use outcome::{AccountLine, Decided, MempoolRow, Outcome};
use reconcile::Direction;

/// The process exit code. A refusal is never `0`.
///
/// A transport failure has no code of its own: during open it is
/// [`Code::StartupRefused`], during a command [`Code::Refused`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
    /// The command did what it says.
    Ok = 0,
    /// argv did not parse.
    Usage = 1,
    /// The wallet refused to open: reconciliation found a divergence.
    StartupRefused = 2,
    /// The wallet opened and the command was refused.
    Refused = 3,
}

/// Rendered output and the code to exit with.
pub struct Report {
    pub text: String,
    pub code: Code,
}

impl Report {
    fn ok(text: String) -> Report {
        Report {
            text,
            code: Code::Ok,
        }
    }
    fn refused(text: String) -> Report {
        Report {
            text,
            code: Code::Refused,
        }
    }
}

fn hex_bytes(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// A tag in its destination form (Base58 with CRC16), the one function every
/// command uses to show a tag to be paid.
///
/// A destination is printed only where it answers the question asked. Where
/// the program echoes a tag the operator supplied and does not recognise, it
/// prints hex instead, so an unknown tag never looks payable.
///
/// The error is propagated rather than replaced with hex. It is unreachable
/// in practice: [`crate::base58::encode`] refuses only an empty input and this
/// payload is twenty-two bytes.
fn destination(tag: &Tag) -> crate::Result<String> {
    crate::addr::tag_to_base58(tag)
}

/// A refusal naming, in hex, a tag whose destination form could not be
/// rendered.
fn cannot_render(tag: &Tag, e: &Error) -> Report {
    Report::refused(format!(
        "cannot render the destination for the tag whose hex is {}: {e}",
        hex_bytes(tag)
    ))
}

/// The key access an account's kind requires: the master for a derived
/// account, the stored root for an imported one (`recon::access_for`).
///
/// Built at each call site because `KeyAccess` is neither `Copy` nor `Clone`
/// and `reserve_and_sign` takes it by value.
///
/// # Errors
///
/// `NoSuchAccount` for a tag the store does not hold, `KeyAccessMismatch`
/// for a derived account in a store with no master, and
/// `ReconciliationRefused` for any other divergence.
pub fn key_access<'a, M: Medium>(
    store: &Keystore<M>,
    tag: &Tag,
    master: Option<&'a Secret<SEED_LEN>>,
) -> crate::Result<KeyAccess<'a>> {
    match crate::recon::access_for(store, tag, master) {
        Ok(access) => Ok(access),
        Err(Divergence::NoMasterForDerivedAccount { .. }) => Err(Error::KeyAccessMismatch {
            kind: crate::account::AccountKind::Derived,
        }),
        Err(Divergence::CannotReconcile { cause, .. }) => Err(cause),
        Err(_) => Err(Error::ReconciliationRefused {
            what: "the store's view of this account could not choose its key access",
        }),
    }
}

/// Run one command and render its outcome. The store is consumed.
pub fn run<M: Medium, T: Transport>(
    store: Keystore<M>,
    client: MeshClient<T>,
    command: &Command,
) -> Report {
    render::render(&decide(store, client, command))
}

/// An outcome produced without a `Wallet`, so with no standing divergences.
fn before_the_gate(outcome: Outcome) -> Decided {
    Decided {
        standing: Vec::new(),
        outcome,
    }
}

/// Run `command` and return its typed outcome, unrendered.
///
/// This is [`run`] without the call to `render`, so decisions can be tested
/// separately from their wording.
pub fn decide<M: Medium, T: Transport>(
    store: Keystore<M>,
    client: MeshClient<T>,
    command: &Command,
) -> Decided {
    // The master seed comes from the store. It is duplicated because the store
    // is moved into a `Wallet` below; `Secret` zeroizes both copies on drop.
    let master = match store.master() {
        Ok(m) => m.map(Secret::duplicate),
        Err(e) => {
            return before_the_gate(Outcome::StoreUnreadable(e))
        }
    };
    let master = master.as_ref();
    // Commands that run without a `Wallet`: `Wallet::open` refuses a tag the
    // ledger has never held (which `address` must serve) and a store with a
    // divergence (which `status` and `reconcile` act on). `create` never
    // reaches here.
    match command {
        Command::Restore { account, scan_to } => {
            return before_the_gate(cmd_restore(store, &client, master, *account, *scan_to))
        }
        Command::Address { tag, account } => {
            return before_the_gate(cmd_address(&store, tag.as_ref(), *account, master))
        }
        // `discover` asks about tags the store does not hold and must run on
        // a store `Wallet::open` would refuse.
        Command::Discover { to } => {
            return before_the_gate(cmd_discover(&store, &client, master, *to))
        }
        // Needs no store. The binary calls `run_submit` before opening one;
        // a store passed here is dropped unread.
        Command::Submit { artifact } => return before_the_gate(cmd_submit(&client, artifact)),
        // The explorer verbs read only the node. The binary calls
        // `run_explorer` before the password prompt.
        Command::LookupTransaction { hash } => {
            return before_the_gate(cmd_transaction(&client, hash))
        }
        Command::RecentTransactions { tag, count, from } => {
            return before_the_gate(cmd_recent_transactions_from(&client, tag, *count, *from))
        }
        Command::Block { at } => return before_the_gate(cmd_block(&client, at)),
        Command::Blocks { count } => return before_the_gate(cmd_blocks(&client, *count)),
        Command::Mempool { count } => return before_the_gate(cmd_mempool(&client, *count)),
        Command::Status { tag, scan_to } => {
            return before_the_gate(cmd_status(&store, &client, tag, master, *scan_to))
        }
        Command::Reconcile { tag, advance_to } => {
            return before_the_gate(cmd_reconcile(store, &client, tag, master, *advance_to, Direction::Advance))
        }
        Command::Rollback { tag, rollback_to } => {
            return before_the_gate(cmd_reconcile(store, &client, tag, master, *rollback_to, Direction::Rollback))
        }
        // The binary reads the import secret and calls `run_import`.
        Command::Import { .. } => return before_the_gate(Outcome::ImportNeedsTheTerminal),
        Command::Entitlement { tag, supplied } => {
            return before_the_gate(cmd_entitlement(&client, tag, *supplied))
        }
        Command::StakeInfo { tag, network } => {
            return before_the_gate(staking::cmd_stake_info(&client, tag.as_ref(), *network))
        }
        _ => {}
    }

    let mut w = match Wallet::open(store, client, master) {
        Ok(w) => w,
        Err(refusal) => {
            return before_the_gate(Outcome::StartupRefused(Box::new(refusal)))
        }
    };

    // The account this command acts on, if it names one. `balance` names
    // none; diverged accounts are reported in the standing notice instead.
    let addressed = match command {
        Command::Settle { tag }
        | Command::Resign(Spend { tag, .. })
        | Command::Send(Spend { tag, .. })
        | Command::Validator(args::ValidatorTx { tag, .. })
        | Command::Staking(args::StakingTx { tag, .. }) => Some(*tag),
        _ => None,
    };
    // A named account that diverged is refused with its own report and no
    // standing notice, which would repeat it.
    if let Some(tag) = addressed {
        if let Some(d) = w.divergence_for(&tag) {
            return before_the_gate(Outcome::Diverged(Box::new(d.clone())));
        }
    }

    // Owned, so the borrow ends before the commands that need `&mut w`.
    let standing = w.diverged().to_vec();
    let outcome = match command {
        Command::Restore { .. }
        | Command::Address { .. }
        | Command::Discover { .. }
        | Command::Create { .. }
        | Command::Status { .. }
        | Command::Reconcile { .. }
        | Command::Rollback { .. }
        | Command::Submit { .. }
        | Command::LookupTransaction { .. }
        | Command::RecentTransactions { .. }
        | Command::Block { .. }
        | Command::Blocks { .. }
        | Command::Mempool { .. }
        | Command::Import { .. }
        | Command::Entitlement { .. }
        | Command::StakeInfo { .. } => Outcome::HandledBeforeTheWallet,
        Command::Balance => cmd_balance(&w),
        Command::Validator(v) => cmd_validator(&mut w, v, master),
        Command::Staking(s) => staking::cmd_staking(&mut w, s, master, None),
        Command::Settle { tag } => cmd_settle(&mut w, tag, master),
        Command::Send(s) => cmd_send(&mut w, s, master),
        Command::Resign(s) => cmd_resign(&mut w, s, master),
    };
    Decided { standing, outcome }
}

/// The diverged accounts, rendered on every page a started wallet produces,
/// so a store that is not whole says so whatever the command was.
///
/// Empty when nothing diverged.
fn standing_divergence_notice(diverged: &[Divergence]) -> String {
    if diverged.is_empty() {
        return String::new();
    }
    let mut out = format!(
        "THIS STORE IS NOT WHOLE: {} account(s) could not be reconciled against the chain. The \
         accounts below are refused; every other account in this store is not.\n\n",
        diverged.len()
    );
    for d in diverged {
        out.push_str(&format!("{d}\n\n"));
    }
    out.push_str(&next_steps(diverged));
    out.push_str("\n\n---\n\n");
    out
}

/// The page an operation on a diverged account is refused with: the full
/// report, and nothing about other accounts, whose health says nothing about
/// whether a second signer used this one.
fn refuse_diverged_account(d: &Divergence) -> Report {
    Report::refused(format!(
        "REFUSED: this account is not reconciled with the chain, so no operation on it is \
         permitted. Other accounts in this store are unaffected and are not refused.\n\n{d}{}",
        next_steps(core::slice::from_ref(d))
    ))
}

/// The commands that resolve each divergence, for the arms a command exists
/// for: `Ahead` names `reconcile --advance-to` with the index, `Unlocated`
/// names `status --scan-to` and then `reconcile`. Tags are printed in `0x`
/// form so they can be pasted.
fn next_steps(diverged: &[Divergence]) -> String {
    let mut out = String::new();
    for d in diverged {
        let Divergence::IndexMismatch { tag, found, .. } = d else { continue };
        let t = format!("0x{}", hex_bytes(tag));
        match found {
            ChainPosition::Ahead { index, .. } => out.push_str(&format!(
                "\n\nIn this program, for account {t}: after reading the report above, \
                 `reconcile {t} --advance-to {}` takes the acknowledged path. It derives \
                 index {} again, compares it to the chain, and advances only on a match.",
                index.get(),
                index.get()
            )),
            ChainPosition::Unlocated { .. } => out.push_str(&format!(
                "\n\nIn this program, for account {t}: `status {t} --scan-to <M>` walks \
                 indices 0 through M and reports the index it finds, writing nothing; then \
                 `reconcile {t} --advance-to <N>` with the index it named takes the \
                 acknowledged path, deriving N again and advancing only on a match."
            )),
            ChainPosition::Behind { .. } => {}
        }
    }
    out
}

fn cmd_restore<M: Medium, T: Transport>(
    mut store: Keystore<M>,
    client: &MeshClient<T>,
    master: Option<&Secret<SEED_LEN>>,
    account: u32,
    scan_to: Option<u32>,
) -> Outcome {
    let Some(m) = master else {
        return Outcome::RestoreNeedsMaster;
    };
    match restore::restore_account(&mut store, client, m, account, scan_to) {
        Ok(r) => Outcome::Restored {
            account,
            found: r.found,
            held_at: r.held_at,
            upgraded: store.upgraded_from(),
        },
        Err(failure) => Outcome::RestoreRefused { account, failure },
    }
}

/// `import --sdk --account N`, with the SDK master seed the binary read from
/// the terminal. Runs without a `Wallet`; the added account is reconciled by
/// the next command's `Wallet::open`.
pub fn run_import<M: Medium, T: Transport>(
    mut store: Keystore<M>,
    client: MeshClient<T>,
    sdk_master: &Secret<SEED_LEN>,
    account: u32,
    scan_to: Option<u32>,
) -> Report {
    let outcome = match restore::import_sdk_account(&mut store, &client, sdk_master, account, scan_to) {
        Ok(r) => Outcome::Imported {
            account,
            found: r.found,
            held_at: r.held_at,
        },
        Err(failure) => Outcome::ImportRefused { account, failure },
    };
    render::render(&before_the_gate(outcome))
}

/// `import --extension-export <path> --tag <tag>`, with the export file's
/// text and the password the binary read from the terminal. Runs without a
/// `Wallet`.
pub fn run_import_extension<M: Medium, T: Transport>(
    mut store: Keystore<M>,
    client: MeshClient<T>,
    export_text: &str,
    password: &[u8],
    tag: &Tag,
    scan_to: Option<u32>,
) -> Report {
    let outcome = match restore::import_extension_account(&mut store, &client, export_text, password, tag, scan_to) {
        Ok(r) => Outcome::ExtensionImported {
            account_index: r.account_index,
            recorded: r.recorded,
            found: r.restored.found,
            held_at: r.restored.held_at,
        },
        Err(failure) => Outcome::ExtensionImportRefused { tag: *tag, failure },
    };
    render::render(&before_the_gate(outcome))
}

/// `entitlement <tag> [--supplied N]`: the entitlement the source reports,
/// and the node's ledger entry for the tag, whose balance a claim's fee is
/// taken from. One request to each; nothing retries.
fn cmd_entitlement<T: Transport>(client: &MeshClient<T>, tag: &Tag, supplied: Option<u64>) -> Outcome {
    use crate::entitlement::{EntitlementSource, OperatorSupplied};
    let reading = match supplied {
        Some(amount) => OperatorSupplied { amount }.entitlement(tag),
        None => client.entitlement(tag),
    };
    let ledger = client.resolve_tag(tag);
    Outcome::EntitlementRead {
        tag: *tag,
        reading,
        ledger,
    }
}

/// `set-delegate`, `clear-delegate`, `claim`: plan a validator transaction,
/// reserve the cold key's current position, sign and submit it; or with
/// `--resign`, reproduce the reserved one and submit it.
fn cmd_validator<M: Medium, T: Transport>(
    w: &mut Wallet<M, T>,
    v: &args::ValidatorTx,
    master: Option<&Secret<SEED_LEN>>,
) -> Outcome {
    if let Err(e) = destination(&v.tag) {
        return Outcome::CannotRender { tag: v.tag, cause: e };
    }
    if v.resign && v.expect_balance.is_some() {
        return Outcome::Failed(Error::ExpectedBalanceOnResign);
    }
    // Above the v4.1 trigger the three are signed in the dust-proof form,
    // and a claim is checked against the tag's stake: `cli::staking`.
    match staking::dust_proof_form(w.client(), v) {
        Ok(Some(s)) => return staking::cmd_staking(w, &s, master, v.expect_balance),
        Ok(None) => {}
        Err(refusal) => return Outcome::StakingRefused { tag: v.tag, refusal },
    }
    let access = match key_access(w.store(), &v.tag, master) {
        Ok(a) => a,
        Err(e) => return Outcome::Failed(e),
    };
    if v.resign {
        let outcome = resign_validator(w, &v.tag, &access, v.op.clone(), v.fee_total, v.blk_to_live);
        // A reservation made while the node reported a tip above the trigger
        // was signed in the dust-proof form. That form is signed only if its
        // digest is the reserved one.
        if not_this_form(&outcome) {
            if let Some(resigned) = staking::resign_dust_proof(w, v, &access) {
                return resigned;
            }
        }
        return outcome;
    }
    let planned = match &v.op {
        crate::mesh::spend::ValidatorOp::Claim { amount } => {
            let supplied = v.entitlement.map(|amount| crate::entitlement::OperatorSupplied { amount });
            let source: &dyn crate::entitlement::EntitlementSource = match &supplied {
                Some(s) => s,
                None => w.client(),
            };
            w.plan_claim(&v.tag, &access, *amount, v.fee_total, v.blk_to_live, source)
                .map(|(plan, e)| (plan, Some(e)))
        }
        op => w
            .plan_validator(&v.tag, &access, op.clone(), v.fee_total, v.blk_to_live)
            .map(|plan| (plan, None)),
    };
    let (plan, entitlement) = match planned {
        Ok(p) => p,
        Err(e) => return Outcome::Failed(e),
    };
    if let Some(expected) = v.expect_balance {
        if let Err(e) = plan.check_expected_balance(expected) {
            return Outcome::Failed(e);
        }
    }
    let signed = match w.reserve_and_sign(&plan, access) {
        Ok(t) => t,
        Err(e) => return Outcome::Failed(e),
    };
    let submitted = w.submit(&signed);
    Outcome::ValidatorSent {
        shipped: outcome::ValidatorShipped {
            source: v.tag,
            op: v.op.clone(),
            fee_total: plan.fee_total(),
            change_total: plan.change_total(),
            blk_to_live: plan.blk_to_live(),
            wire: signed.wire(),
            submitted,
        },
        entitlement,
    }
}

/// Whether a validator `--resign` outcome says the reservation was not made
/// in the form tried: the rebuilt digest differs, or that form cannot be
/// built at the current balance.
fn not_this_form(outcome: &Outcome) -> bool {
    matches!(
        outcome,
        Outcome::NotTheReservedSpend | Outcome::Failed(Error::InsufficientBalance { .. })
    )
}

/// `--resign` of a validator transaction in its v4.0 exact-balance form:
/// rebuild the plan, sign only if its digest is the reserved one, and submit.
pub(super) fn resign_validator<M: Medium, T: Transport>(
    w: &mut Wallet<M, T>,
    tag: &Tag,
    access: &KeyAccess<'_>,
    op: crate::mesh::spend::ValidatorOp,
    fee_total: u64,
    blk_to_live: u64,
) -> Outcome {
    match w.resign_pending(tag, access, op.clone(), fee_total, blk_to_live) {
        Ok(signed) => {
            let tx = match crate::tx::wire::Transaction::from_wire(&signed.wire()) {
                Ok(t) => t,
                Err(e) => return Outcome::Failed(e),
            };
            let submitted = w.submit(&signed);
            Outcome::ValidatorResigned {
                shipped: outcome::ValidatorShipped {
                    source: *tag,
                    op,
                    fee_total: tx.fee_total,
                    change_total: tx.change_total,
                    blk_to_live: tx.blk_to_live,
                    wire: signed.wire(),
                    submitted,
                },
            }
        }
        Err(Error::DigestMismatch) => Outcome::NotTheReservedSpend,
        Err(Error::ReservationLanded {
            spent_index,
            settled_index,
        }) => Outcome::ReservationAlreadyLanded {
            source: *tag,
            spent_index,
            settled_index,
        },
        Err(e) => Outcome::Failed(e),
    }
}

/// One account's state, in the words `balance` and `status` both use.
fn state_of(status: &AccountStatus) -> String {
    match status {
        AccountStatus::InSync { .. } => "in sync".to_string(),
        // A dead reservation replaces the outstanding-spend line. The figures
        // are rendered separately by `reservation_lines`.
        AccountStatus::SpendOutstanding {
            spent_index,
            reservation,
            ..
        } => match reservation {
            Reservation::Recorded(d) if d.is_dead() => format!(
                "RESERVED SPEND at index {} is DEAD -- the signed artifact can no longer be accepted",
                spent_index.get()
            ),
            _ => format!(
                "SPEND OUTSTANDING at index {} -- not yet seen on the chain",
                spent_index.get()
            ),
        },
        AccountStatus::SpendLanded { spent_index, .. } => format!(
            "spend from index {} has landed -- run `settle`",
            spent_index.get()
        ),
    }
}

/// The reserved spend's balance and block-to-live lines, shared by `status`,
/// `balance` and `settle` (`indent` differs per page).
///
/// A recorded reservation always gets both lines, each with its own verdict.
/// A format-version-3 reservation has no recorded figures and gets one line
/// saying so, with no verdict. A dead reservation gets a closing line stating
/// that no second signature from that key will be produced.
///
/// The verdicts follow the node's rules: `tx_val` requires
/// `send + change + fee` to equal the balance exactly, so a moved balance
/// invalidates the artifact for good; a non-zero block-to-live expires once
/// the tip reaches it; zero never expires.
fn reservation_lines(spent_index: WotsIndex, reservation: &Reservation, indent: &str) -> String {
    let mut out = String::new();
    match reservation {
        Reservation::Unrecorded => out.push_str(&format!(
            "{indent}reserved figures  not recorded: this reservation was written under format \
             version 3, which carried neither the balance nor the block-to-live. Whether the \
             artifact can still be accepted cannot be told from this store; the next write \
             re-seals the store as version 4 with the figures declared absent.\n"
        )),
        Reservation::Recorded(d) => {
            let b = d.figures.reserved_balance;
            if d.balance_moved {
                out.push_str(&format!(
                    "{indent}reserved balance  {b} nanoMCM when the spend was built; the ledger holds {} \
                     now. A deposit landed on this tag, and the node demands the signed totals \
                     equal the balance EXACTLY, so the artifact can no longer \
                     be accepted.\n",
                    d.balance_now
                ));
            } else {
                out.push_str(&format!(
                    "{indent}reserved balance  {b} nanoMCM when the spend was built (the ledger holds the \
                     same now)\n"
                ));
            }
            let btl = d.figures.blk_to_live;
            let expiry = match &d.expiry {
                Expiry::NoExpiry => format!("{btl} (never expires)"),
                Expiry::Below { tip } => format!(
                    "{btl} (the node accepts it only while the tip is at or below {btl}, and refuses \
                     it if {btl} is below the tip when it arrives; the tip is {tip})"
                ),
                Expiry::Reached { tip } => format!(
                    "{btl} -- the tip is {tip}: the block-to-live has passed and the artifact can no \
                     longer be accepted"
                ),
                Expiry::Unreadable { cause } => format!(
                    "{btl} (the node accepts it only while the tip is at or below {btl}, and refuses \
                     it if {btl} is below the tip when it arrives); the tip could not be read \
                     ({cause}), so whether it has passed is UNCHECKED here -- not assumed live"
                ),
            };
            out.push_str(&format!("{indent}block-to-live     {expiry}\n"));
            if d.is_dead() {
                // No command re-signs from a reserved key: a second signature
                // would be one-time key reuse.
                out.push_str(&format!(
                    "{indent}A dead reservation has no route out: the whole balance at the reserved \
                     key is reachable only by a signature from that key, and the only signature \
                     this wallet will ever produce from that key is the one already produced. No \
                     command offers a second one, on purpose: a second, different signature under \
                     the key at index {} is the key reuse this wallet's refusals exist to prevent, \
                     and its price would be the whole balance at that key.\n",
                    spent_index.get()
                ));
            }
        }
    }
    out
}

fn cmd_balance<M: Medium, T: Transport>(w: &Wallet<M, T>) -> Outcome {
    Outcome::Balance {
        accounts: w
            .accounts()
            .iter()
            .map(|(tag, status)| AccountLine {
                tag: *tag,
                status: status.clone(),
            })
            .collect(),
    }
}

/// Where to receive. Uses no wallet and no chain; see `cli::address`.
///
/// The page's first line is the destination alone, in Base58, so it can be
/// copied or read by a script. Base58 carries a CRC16 that
/// [`crate::addr::tag_from_base58`] checks; hex carries none.
///
/// The 40-byte ledger address is also printed, labelled. At 80 characters it
/// cannot be mistaken for a destination, and `send` refuses it.
fn cmd_address<M: Medium>(
    store: &Keystore<M>,
    tag: Option<&Tag>,
    account: Option<u32>,
    master: Option<&Secret<SEED_LEN>>,
) -> Outcome {
    if let Some(n) = account {
        return cmd_address_of_unstored_account(store, n, master);
    }
    let Some(tag) = tag else {
        return cmd_accounts(store);
    };
    match key_access(store, tag, master).and_then(|access| address::address_of(store, tag, &access)) {
        Ok(w) => Outcome::Address {
            tag: *tag,
            address: w.address,
            index: w.index,
        },
        Err(Error::NoSuchAccount) => Outcome::NoAccountToAddress { tag: *tag },
        Err(e) => Outcome::Failed(e),
    }
}

/// `address --account N`: the destination of an account this store does not
/// hold, derived from its master and not stored.
///
/// `restore --account N` adds an account only once the chain resolves its
/// tag, so this is how a new account gets a destination to be funded at.
/// Once paid, `restore --account N` adds it with the same tag.
///
/// The store is borrowed immutably and no node is asked.
///
/// Refused for a store with no master, and for an account the store already
/// holds (its position may be past 0; `address <destination>` serves it).
fn cmd_address_of_unstored_account<M: Medium>(
    store: &Keystore<M>,
    account: u32,
    master: Option<&Secret<SEED_LEN>>,
) -> Outcome {
    let Some(master) = master else {
        return Outcome::NoMasterSeed;
    };
    let tag = crate::derive::derive_account_tag(master, account);
    match store.view(&tag) {
        Ok(Some(view)) => {
            return Outcome::AccountAlreadyStored {
                account,
                tag,
                index: view.wots_index,
            }
        }
        Ok(None) => {}
        Err(e) => return Outcome::Failed(e),
    }
    Outcome::UnstoredAddress {
        account,
        tag,
        address: crate::recon::derived_address_at(master, account, WotsIndex::ZERO),
    }
}

/// `discover [--to N]`: what the node says about accounts `0..=N` derived
/// from the master this store holds.
///
/// The page never says an account does not exist: it states the extent
/// searched, lists the indices the node resolved and those the store holds,
/// and names the rest as not resolved (see `cli::discover`).
///
/// The store is borrowed immutably; nothing is reserved, signed or written.
fn cmd_discover<M: Medium, T: Transport>(
    store: &Keystore<M>,
    client: &MeshClient<T>,
    master: Option<&Secret<SEED_LEN>>,
    to: u32,
) -> Outcome {
    let Some(master) = master else {
        return Outcome::DiscoverNeedsMaster;
    };
    match discover::sweep(store, client, master, to) {
        Ok(sweep) => Outcome::Discovered { sweep },
        Err(discover::SweepFailure::ChainUnreachable {
            account,
            searched,
            cause,
        }) => Outcome::SweepStopped {
            account,
            searched,
            to,
            cause,
        },
    }
}

/// A list of indices, sixteen to an indented line.
fn wrapped_indices(indices: &[u32]) -> String {
    let mut out = String::new();
    for (i, n) in indices.iter().enumerate() {
        if i % 16 == 0 {
            out.push_str("\n   ");
        }
        out.push_str(&format!(" {n}"));
    }
    out
}

/// `address` with no tag: what this store holds, from the records alone.
///
/// Needs no seed and no node.
fn cmd_accounts<M: Medium>(store: &Keystore<M>) -> Outcome {
    match address::accounts_in(store) {
        Ok(held) => Outcome::Accounts { held },
        Err(e) => Outcome::Failed(e),
    }
}

/// `status`: one account, reconciled now, without a `Wallet`.
///
/// Exit 0 whenever the comparison produced an answer, including a
/// divergence. Exit 3 when it could not run: the chain unreachable, no master
/// for a derived account, or a tag the store does not hold.
fn cmd_status<M: Medium, T: Transport>(
    store: &Keystore<M>,
    client: &MeshClient<T>,
    tag: &Tag,
    master: Option<&Secret<SEED_LEN>>,
    scan_to: Option<u32>,
) -> Outcome {
    status_outcome(tag, reconcile::account_status(store, client, tag, master, scan_to))
}

/// The `status` outcome for a [`reconcile::account_status`] result, public
/// so a caller that runs the comparison itself gets the same decision.
///
/// In sync or in a spend state is [`Outcome::Status`]; a divergence that is
/// an answer about the account -- an index mismatch, a reservation the chain
/// explains at neither key, a tag the node did not resolve -- is
/// [`Outcome::StatusDiverged`]; a tag the store does not hold is
/// [`Outcome::NoSuchAccount`]; and a comparison that could not run is
/// [`Outcome::StatusRefused`].
pub fn status_outcome(tag: &Tag, compared: core::result::Result<AccountStatus, Divergence>) -> Outcome {
    match compared {
        Ok(status) => Outcome::Status { tag: *tag, status },
        Err(Divergence::CannotReconcile {
            cause: Error::NoSuchAccount,
            ..
        }) => Outcome::NoSuchAccount { tag: *tag },
        // Rendered as the same report a refusal prints, with exit 0.
        Err(d @ (Divergence::IndexMismatch { .. }
        | Divergence::ReservationUnexplained { .. }
        | Divergence::TagUnresolved { .. })) => Outcome::StatusDiverged {
            tag: *tag,
            divergence: Box::new(d),
        },
        Err(d) => Outcome::StatusRefused {
            divergence: Box::new(d),
        },
    }
}

/// The refusal for a tag this store does not hold, shared by `status` and
/// `reconcile`. The tag is shown in hex so it cannot be taken for a
/// destination.
fn no_such_account(tag: &Tag) -> String {
    format!(
        "no account for the tag {} in this store -- that is the tag you named, in hex so it \
         cannot be mistaken for somewhere to send funds. `address` with no argument lists what \
         is here.",
        hex_bytes(tag)
    )
}

/// `settle`. The page carries the reservation's diagnosis while it stands (a
/// dead one omits the `resign` suggestion) and notes when this was the first
/// write over a version-3 store.
fn cmd_settle<M: Medium, T: Transport>(
    w: &mut Wallet<M, T>,
    tag: &Tag,
    master: Option<&Secret<SEED_LEN>>,
) -> Outcome {
    let settlement = match key_access(w.store(), tag, master) {
        Ok(access) => w.settle_if_landed(tag, &access),
        Err(e) => Err(e),
    };
    let upgraded = w.store().upgraded_from();
    match settlement {
        Ok(settlement) => Outcome::Settled {
            settlement,
            upgraded,
        },
        Err(e) => Outcome::Failed(e),
    }
}

/// The destinations as the wire wants them, with `all` already resolved.
///
/// `amount` is `None` only for `all` at a single destination, which takes
/// `resolved` (the balance less the fee). The order is the operator's; the
/// planner sorts afterwards.
fn spend_destinations(s: &Spend, resolved: u64) -> Vec<Destination> {
    s.dsts
        .iter()
        .map(|d| Destination {
            tag: d.to,
            reference: d.reference,
            amount: d.amount.unwrap_or(resolved),
        })
        .collect()
}

/// The warning printed whenever a spend's change is zero.
///
/// A zero change empties the account, and the Mesh reports a zero-balance tag
/// as *account not found*, so reconciliation refuses every operation on the
/// account until it is paid again. Other accounts are unaffected. `submit`
/// still reaches the node meanwhile, as it opens no store.
fn emptying_text(settle_arg: &str) -> String {
    format!(
        "{}  Keep the artifact below. `submit` writes it to the socket without opening the \
         store, and is the route to a node while the account reads as not found.\n",
        emptying_paragraph(settle_arg)
    )
}

/// The part of [`emptying_text`] that applies before anything is signed.
fn emptying_paragraph(settle_arg: &str) -> String {
    format!(
        "\nTHIS EMPTIES THE ACCOUNT. The change is zero, so nothing returns to your next key \
         under {settle_arg}.\n  The Mesh reports a tag it holds at zero balance as \"account not \
         found\", which it does not distinguish from never funded or from a failed lookup, so \
         once this lands every operation ON THIS ACCOUNT refuses until it is paid again. Other \
         accounts in this store keep working, and paying this one from another account in the \
         store is the way back. If this is the only account here, the payment has to come from \
         somewhere else.\n"
    )
}

/// Lay the spend out, resolving `all` against the same ledger observation the
/// plan is built on.
///
/// For `all` this inlines `Wallet::plan` so that a single `resolve_tag`
/// supplies both the amount and the plan; two reads could see different
/// balances and leave a non-zero change. Without `all` it calls `plan`.
pub fn plan_spend<M: Medium, T: Transport>(
    w: &Wallet<M, T>,
    s: &Spend,
    access: &KeyAccess<'_>,
) -> Result<SpendPlan> {
    if !s.spends_everything() {
        return w.plan(&s.tag, access, spend_destinations(s, 0), s.fee_total, s.blk_to_live);
    }
    let addresses = w.spend_addresses(&s.tag, access)?;
    let entry = w.client().resolve_tag(&s.tag)?;
    let amount = spend_all_amount(entry.balance, s.fee_total)?;
    SpendPlan::new(
        &addresses,
        &entry,
        spend_destinations(s, amount),
        s.fee_total,
        s.blk_to_live,
    )
}

/// `balance − fee`.
///
/// # Errors
///
/// `InsufficientBalance` when the balance is at or below the fee, since the
/// node refuses a zero destination amount.
pub fn spend_all_amount(balance: u64, fee_total: u64) -> Result<u64> {
    match balance.checked_sub(fee_total) {
        Some(0) | None => Err(Error::InsufficientBalance {
            balance,
            needed: fee_total.saturating_add(1),
        }),
        Some(amount) => Ok(amount),
    }
}

/// The destinations `resign` rebuilds the reserved plan from.
///
/// `all` resolves against the current balance. If the balance has moved since
/// the reservation, the digest differs and `resign` refuses.
fn resign_destinations<M: Medium, T: Transport>(
    w: &Wallet<M, T>,
    s: &Spend,
    access: &KeyAccess<'_>,
) -> Result<Vec<Destination>> {
    if !s.spends_everything() {
        return Ok(spend_destinations(s, 0));
    }
    let _ = access;
    let entry = w.client().resolve_tag(&s.tag)?;
    let amount = spend_all_amount(entry.balance, s.fee_total)?;
    Ok(spend_destinations(s, amount))
}

/// The lines of the page that list what is being sent, one per destination.
///
/// Each destination is shown in the checksummed form with its amount and any
/// reference, in the order given.
fn destination_lines(dsts: &[Destination]) -> core::result::Result<String, (Tag, Error)> {
    let mut out = String::new();
    for (i, d) in dsts.iter().enumerate() {
        let shown = destination(&d.tag).map_err(|e| (d.tag, e))?;
        out.push_str(&format!("  {:>3}. {} nanoMCM\n       to  {shown}\n", i + 1, d.amount));
        let r = reference_line("       ref ", &d.reference);
        if !r.is_empty() {
            out.push_str(&r);
        }
    }
    Ok(out)
}

/// The reference line for a destination: the field's text up to its first
/// NUL, or empty for the zero field.
fn reference_line(label: &str, field: &[u8; ADDR_REF_LEN]) -> String {
    if *field == [0u8; ADDR_REF_LEN] {
        return String::new();
    }
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    format!("{label}{}\n", String::from_utf8_lossy(&field[..end]))
}

/// The block-to-live, rendered beside the artifact.
///
/// It is inside the signed digest (the last field of `TXHDR`), so `resign`
/// needs it. Zero never expires; a non-zero value expires once the tip
/// reaches it, and a node refuses on arrival a value more than 256 blocks past
/// its tip. The store also records it, and `status` and `balance` show it.
fn block_to_live_line(blk_to_live: u64) -> String {
    if blk_to_live == 0 {
        "0 (never expires: a node that holds the transaction keeps it until it lands)"
            .to_string()
    } else {
        // States both sides of the node's rule. The tip is not read here.
        format!(
            "{blk_to_live} (the node accepts it only while the tip is at or below {blk_to_live}, \
             and refuses it on arrival if {blk_to_live} is below the tip or more than 256 blocks \
             past it)"
        )
    }
}

/// The residue block `send` prints beside the artifact.
fn artifact_notices(wire_hex: &str) -> String {
    format!(
        "RETRY ARTIFACT -- save this before going further:\n\n{wire_hex}\n\nThese are the signed \
         bytes. If submission fails and you lose them, `resign` is the only recovery, and it \
         needs the SAME destination, amount, fee, block-to-live and reference (`--ref`, if one \
         was given) -- anything else is refused as a different transaction. The block-to-live is printed above; record it with the \
         bytes, because nothing else keeps it.\n\nThis transaction passed every check that can \
         be run offline. The node applies the ledger, the balance tally and the block-to-live \
         range after we are gone, and a rejection there is silent to this program.\n"
    )
}

/// What `send` prints after a refused socket write.
const SEND_REFUSAL: &str =
    "The reservation is open and the artifact above is the only copy. Save it.";

/// What `resign` prints after a refused socket write. A submission can fail
/// after the bytes reached the node, so the page points to `settle`.
fn resign_refusal(settle_arg: &str) -> String {
    format!(
        "The store was not changed and the reservation is still open. Whether these bytes \
         reached the node is not known here -- a submission can fail after the body is on the \
         socket. `settle {settle_arg}` once the chain has moved says whether they landed; \
         `resign` with the same values reproduces them and tries the socket again."
    )
}

/// The text after a successful socket write, shared by `send`, `resign` and
/// `submit`.
fn submitted_block(id: &TxId, settle_arg: &str) -> String {
    format!(
        "\nsubmitted: the node accepted the SOCKET WRITE. THIS IS NOT ACCEPTANCE OF THE \
         TRANSACTION.\n  id {}  (computed locally, echoed back -- not the node's \
         verdict)\n\nThe node validates after we are gone. Run `settle {}` once the \
         chain has moved to learn what actually happened.",
        hex_bytes(&id.0),
        settle_arg
    )
}

/// `submit <artifact-hex>`: the artifact `send` printed, written to the
/// socket as it is.
///
/// Opens no store and asks no password, so it works for an emptied account
/// the Mesh reports as not found, where `resign` cannot run. It reserves,
/// signs and writes nothing.
///
/// # Refusals
///
/// The hex must decode, parse as a `tx::wire::Transaction`, and re-serialize
/// to exactly the given bytes (a partial trailer, which `from_wire`
/// zero-extends, is refused). Only the layout is checked; signature, balance
/// and block-to-live are left to the node. Every refusal happens before any
/// socket is opened.
///
/// The page uses [`submitted_block`] and names `settle` with the source tag
/// from the artifact's header.
fn cmd_submit<T: Transport>(client: &MeshClient<T>, artifact_hex: &str) -> Outcome {
    let bytes = match crate::mesh::hex::decode(artifact_hex.trim(), "artifact") {
        Ok(b) => b,
        Err(cause) => return Outcome::ArtifactNotHex { cause },
    };
    let tx = match crate::tx::wire::Transaction::from_wire(&bytes) {
        Ok(tx) => tx,
        Err(cause) => return Outcome::ArtifactNotATransaction { cause },
    };
    // The bytes must round-trip exactly.
    if tx.to_wire() != bytes {
        return Outcome::ArtifactNotWhole {
            given: bytes.len(),
            described: tx.wire_len(),
        };
    }
    let mut source = [0u8; crate::consts::ADDR_TAG_LEN];
    source.copy_from_slice(&tx.src_addr[..crate::consts::ADDR_TAG_LEN]);
    // Checked before writing: an unrenderable source is refused unsent.
    if let Err(cause) = destination(&source) {
        return Outcome::CannotRender { tag: source, cause };
    }
    let submitted = client.submit_wire(&bytes, TxId(tx.id_digest()));
    Outcome::Submitted {
        source,
        bytes,
        submitted,
    }
}

/// `submit` for the binary, which calls it before any store is opened.
pub fn run_submit<T: Transport>(client: &MeshClient<T>, artifact_hex: &str) -> Report {
    render::render(&before_the_gate(cmd_submit(client, artifact_hex)))
}

/// The read-only verbs for the binary, which calls this before the password
/// prompt and before any store is opened.
///
/// `--dir` is not read, created or locked. Any other command is reported as
/// [`Outcome::NotAReadOnlyVerb`].
pub fn run_explorer<T: Transport>(client: &MeshClient<T>, command: &Command) -> Report {
    let outcome = match command {
        Command::LookupTransaction { hash } => cmd_transaction(client, hash),
        Command::RecentTransactions { tag, count, from } => {
            cmd_recent_transactions_from(client, tag, *count, *from)
        }
        Command::Block { at } => cmd_block(client, at),
        Command::Blocks { count } => cmd_blocks(client, *count),
        Command::Mempool { count } => cmd_mempool(client, *count),
        Command::Entitlement { tag, supplied } => cmd_entitlement(client, tag, *supplied),
        Command::StakeInfo { tag, network } => staking::cmd_stake_info(client, tag.as_ref(), *network),
        other => Outcome::NotAReadOnlyVerb {
            command: Box::new(other.clone()),
        },
    };
    render::render(&before_the_gate(outcome))
}

fn cmd_send<M: Medium, T: Transport>(
    w: &mut Wallet<M, T>,
    s: &Spend,
    master: Option<&Secret<SEED_LEN>>,
) -> Outcome {
    let plan = match key_access(w.store(), &s.tag, master).and_then(|access| plan_spend(w, s, &access)) {
        Ok(p) => p,
        Err(e) => return Outcome::Failed(e),
    };
    if let Some(expected) = s.expect_balance {
        if let Err(e) = plan.check_expected_balance(expected) {
            return Outcome::Failed(e);
        }
    }
    // Check that every tag renders before a key is reserved, so a spend is
    // never made whose page cannot be printed. The results are discarded.
    if let Err(e) = destination(&s.tag) {
        return Outcome::CannotRender { tag: s.tag, cause: e };
    }
    if let Err((tag, cause)) = destination_lines(plan.dsts()) {
        return Outcome::CannotRender { tag, cause };
    }
    let signed = match key_access(w.store(), &s.tag, master) {
        Ok(access) => match w.reserve_and_sign(&plan, access) {
            Ok(t) => t,
            Err(e) => return Outcome::Failed(e),
        },
        Err(e) => return Outcome::Failed(e),
    };
    let submitted = w.submit(&signed);
    Outcome::Sent {
        shipped: outcome::Shipped {
            source: s.tag,
            destinations: plan.dsts().to_vec(),
            blk_to_live: plan.blk_to_live(),
            wire: signed.wire().to_vec(),
            submitted,
        },
        send_total: plan.send_total(),
        fee_total: plan.fee_total(),
        change_total: plan.change_total(),
        upgraded: w.store().upgraded_from(),
    }
}

/// `resign`: reproduce the reserved artifact and submit it.
///
/// `resign_pending` returns bytes only when the rebuilt digest matches the
/// store's reservation, so this never submits anything the wallet did not
/// already sign. It does not check whether the reservation has expired; an
/// expired one is reproduced and submitted like any other. A moved balance
/// changes the digest and is refused as `DigestMismatch`.
///
/// A plan that is not the reserved one signs and submits nothing. A
/// reservation the chain has already moved past is reported with a pointer
/// to `settle`.
fn cmd_resign<M: Medium, T: Transport>(
    w: &mut Wallet<M, T>,
    s: &Spend,
    master: Option<&Secret<SEED_LEN>>,
) -> Outcome {
    if s.expect_balance.is_some() {
        return Outcome::Failed(Error::ExpectedBalanceOnResign);
    }
    let access = match key_access(w.store(), &s.tag, master) {
        Ok(access) => access,
        Err(e) => return Outcome::Failed(e),
    };
    let dsts = match resign_destinations(w, s, &access) {
        Ok(d) => d,
        Err(e) => return Outcome::Failed(e),
    };
    // Listed in wire order, the sort `SpendPlan::new` applies.
    let mut listed_dsts = dsts.clone();
    listed_dsts.sort_by_key(Destination::mdst_image);
    let resigned = w.resign_pending(&s.tag, &access, dsts, s.fee_total, s.blk_to_live);
    resign_outcome(w, &s.tag, listed_dsts, s.blk_to_live, resigned)
}

/// The `resign` outcome for a [`Wallet::resign_pending`] result, public so a
/// caller that re-signs through the wallet itself gets the same decision.
///
/// `listed_dsts` are in wire order. A reproduction is submitted through `w`,
/// unless the source tag will not render, in which case it is returned
/// unsent as [`Outcome::ReproducedButUnrenderable`]. A digest mismatch is
/// [`Outcome::NotTheReservedSpend`], a reservation the chain has moved past
/// is [`Outcome::ReservationAlreadyLanded`], and anything else is
/// [`Outcome::Failed`].
pub fn resign_outcome<M: Medium, T: Transport>(
    w: &Wallet<M, T>,
    source: &Tag,
    listed_dsts: Vec<Destination>,
    blk_to_live: u64,
    resigned: Result<crate::mesh::spend::SignedTransaction>,
) -> Outcome {
    match resigned {
        Ok(signed) => {
            let wire = signed.wire().to_vec();
            // Whether the source renders decides whether to submit. The
            // reproduced bytes are returned either way.
            if let Err(cause) = destination(source) {
                return Outcome::ReproducedButUnrenderable {
                    source: *source,
                    destinations: listed_dsts,
                    blk_to_live,
                    wire,
                    cause,
                };
            }
            let submitted = w.submit(&signed);
            Outcome::Resigned {
                shipped: outcome::Shipped {
                    source: *source,
                    destinations: listed_dsts,
                    blk_to_live,
                    wire,
                    submitted,
                },
            }
        }
        Err(Error::DigestMismatch) => Outcome::NotTheReservedSpend,
        Err(Error::ReservationLanded {
            spent_index,
            settled_index,
        }) => Outcome::ReservationAlreadyLanded {
            source: *source,
            spent_index,
            settled_index,
        },
        Err(e) => Outcome::Failed(e),
    }
}

/// `reconcile`: the acknowledged advance or rollback, run without a `Wallet`.
///
/// The whole store's report is printed on every path. Exit 0 on the move, 3
/// on every refusal.
fn cmd_reconcile<M: Medium, T: Transport>(
    mut store: Keystore<M>,
    client: &MeshClient<T>,
    tag: &Tag,
    master: Option<&Secret<SEED_LEN>>,
    to: u32,
    direction: Direction,
) -> Outcome {
    let reviewed = match direction {
        Direction::Advance => reconcile::advance_acknowledged(&mut store, client, tag, master, to),
        Direction::Rollback => reconcile::rollback_acknowledged(&mut store, client, tag, master, to),
    };
    match reviewed {
        Ok(reviewed) => Outcome::Reconciled {
            tag: *tag,
            to,
            reviewed,
            upgraded: store.upgraded_from(),
        },
        Err(e) => Outcome::Failed(e),
    }
}

// ---------------------------------------------------------------------------
// Explorer verbs: read only the node
// ---------------------------------------------------------------------------

/// An amount in nanoMCM and in MCM (1 MCM = 1,000,000,000 nanoMCM), signed
/// because a source operation is a debit.
fn nano_and_mcm(v: i128) -> String {
    // Named `minus`, not `sign`: the signer-reachability scan matches names.
    let a = v.unsigned_abs();
    let whole = a / 1_000_000_000;
    let frac = a % 1_000_000_000;
    let minus = if v < 0 { "-" } else { "" };
    format!("{minus}{a} nanoMCM ({minus}{whole}.{frac:09} MCM)")
}

/// A Mesh timestamp (milliseconds since the epoch), rendered raw and as
/// whole seconds; the crate has no calendar.
fn stamp(ms: i64) -> String {
    format!("{ms} ms since the epoch ({} s)", ms / 1_000)
}

/// Escapes node-supplied text so it stays on one line and cannot control the
/// terminal.
///
/// Escaped: control characters, bidirectional formatting characters,
/// zero-width characters, and the backslash (so every escape shown was
/// written here).
fn terminal_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        let bidi = matches!(ch, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}');
        let zero_width = matches!(ch, '\u{00ad}' | '\u{180e}' | '\u{200b}'..='\u{200d}' | '\u{2060}'..='\u{2064}' | '\u{feff}');
        if ch.is_control() || bidi || zero_width || ch == '\\' {
            out.extend(ch.escape_default());
        } else {
            out.push(ch);
        }
    }
    out
}

/// An operation's address, rendered for a person where it can be.
///
/// A 20-byte tag is shown in Base58 beside its hex. A 40-byte ledger address
/// is shown as hex, labelled as not a destination.
fn explorer_address(text: &str) -> String {
    let body = text.strip_prefix("0x").unwrap_or(text);
    if body.len() == ADDR_TAG_LEN * 2 {
        let mut tag = [0u8; ADDR_TAG_LEN];
        for (i, b) in tag.iter_mut().enumerate() {
            match body.get(i * 2..i * 2 + 2).and_then(|p| u8::from_str_radix(p, 16).ok()) {
                Some(v) => *b = v,
                None => return terminal_text(text),
            }
        }
        return match destination(&tag) {
            Ok(d) => format!("{d}  ({})", terminal_text(text)),
            Err(_) => terminal_text(text),
        };
    }
    if body.len() == ADDR_LEN * 2 {
        return format!("{}  (a 40-byte ledger address: tag then the key's hash -- not a destination)", terminal_text(text));
    }
    terminal_text(text)
}

/// The sentence every page that reads `/search/transactions` carries.
const SEARCH_CONVENTION: &str = "read from /search/transactions, the Mesh's indexer. That endpoint \
     replays rows written when the block was first seen: the source is debited its GROSS amount \
     and the change comes back as its own destination. /block re-parses the wire and shows the \
     NET debit with no change operation. Both are correct and this page does not reconcile them.";

/// The sentence every page that reads `/block` carries.
const BLOCK_CONVENTION: &str = "read from /block, which re-parses the wire: a source is debited \
     its NET amount and the change does not appear as an operation. The indexer's \
     /search/transactions shows the same transaction gross, with the change as a destination.";

fn operation_lines(ops: &[codec::Operation], indent: &str) -> String {
    let mut out = String::new();
    for op in ops {
        out.push_str(&format!("{indent}{:>2}. {:<21} {}\n", op.index, terminal_text(&op.kind), nano_and_mcm(op.amount)));
        out.push_str(&format!("{indent}    {}\n", explorer_address(&op.address)));
        if !op.memo.is_empty() {
            out.push_str(&format!("{indent}    memo {}\n", terminal_text(&op.memo)));
        }
    }
    out
}

fn metadata_lines(meta: &[(String, String)], indent: &str) -> String {
    let mut out = String::new();
    for (k, v) in meta {
        out.push_str(&format!("{indent}{} = {}\n", terminal_text(k), terminal_text(v)));
    }
    out
}

/// `transaction <hash>`: one transaction from the indexer.
pub fn cmd_transaction<T: Transport>(client: &MeshClient<T>, hash: &[u8; HASHLEN]) -> Outcome {
    match client.search_by_hash(hash) {
        Err(cause) => Outcome::SearchFailed { cause },
        Ok(page) if page.transactions.is_empty() => Outcome::TransactionNotFound { hash: *hash },
        Ok(page) => Outcome::LookedUpTransaction {
            page: Box::new(page),
        },
    }
}

/// `recent-transactions <tag> [--count N]`: what touched a tag, newest first.
pub fn cmd_recent_transactions<T: Transport>(
    client: &MeshClient<T>,
    tag: &Tag,
    count: u64,
) -> Outcome {
    match client.search_by_account(tag, count) {
        Ok(page) => Outcome::RecentTransactions {
            tag: *tag,
            from: 0,
            page: Box::new(page),
        },
        Err(cause) => Outcome::SearchFailed { cause },
    }
}

/// `recent-transactions <tag> [--count N] [--from M]`: what touched a tag,
/// newest first, the `from` newest skipped. With `from` 0 it sends the same
/// request as [`cmd_recent_transactions`].
pub fn cmd_recent_transactions_from<T: Transport>(
    client: &MeshClient<T>,
    tag: &Tag,
    count: u64,
    from: u64,
) -> Outcome {
    if from == 0 {
        return cmd_recent_transactions(client, tag, count);
    }
    match client.search_by_account_from(tag, count, from) {
        Ok(page) => Outcome::RecentTransactions {
            tag: *tag,
            from,
            page: Box::new(page),
        },
        Err(cause) => Outcome::SearchFailed { cause },
    }
}

/// `block <number|hash>`: one block, with its reward and what it moved.
pub fn cmd_block<T: Transport>(client: &MeshClient<T>, at: &args::BlockAt) -> Outcome {
    let got = match at {
        args::BlockAt::Index(i) => client.block_by_index(*i),
        args::BlockAt::Hash(h) => client.block_by_hash(h),
    };
    match got {
        Ok(block) => Outcome::Block {
            block: Box::new(block),
        },
        Err(cause) => Outcome::BlockNotServed {
            by_hash: matches!(at, args::BlockAt::Hash(_)),
            cause,
        },
    }
}

/// `blocks [--count N]`: the tip and the N newest, one row each.
pub fn cmd_blocks<T: Transport>(client: &MeshClient<T>, count: u64) -> Outcome {
    let tip = match client.network_status() {
        Ok(t) => t,
        Err(cause) => return Outcome::ExplorerFailed { cause },
    };
    let mut rows = Vec::new();
    for i in 0..count {
        let Some(index) = tip.index.checked_sub(i) else { break };
        // The endpoint serves index 0 as the tip, so the walk stops above it.
        if index == 0 {
            break;
        }
        match client.block_by_index(index) {
            Ok(b) => rows.push(b),
            // A partial list is discarded so it is not read as complete.
            Err(cause) => return Outcome::BlocksStopped { index, cause },
        }
    }
    Outcome::Blocks { count, tip, rows }
}

/// `mempool [--count N]`: the node's queue, its ids and the first `count`
/// of them read whole.
///
/// A transaction that left the queue after the list was read (code 3,
/// *Transaction not found*) gets a row saying so. Any other failure discards
/// the rows read so far, as `blocks` does.
pub fn cmd_mempool<T: Transport>(client: &MeshClient<T>, count: u64) -> Outcome {
    let ids = match client.mempool() {
        Ok(ids) => ids,
        Err(cause) => return Outcome::ExplorerFailed { cause },
    };
    let mut rows = Vec::new();
    for id in ids.iter().take(usize::try_from(count).unwrap_or(usize::MAX)) {
        let transaction = match client.mempool_transaction(id) {
            Ok(t) => Some(Box::new(t)),
            Err(Error::Mesh { code: 3, .. }) => None,
            Err(cause) => return Outcome::MempoolStopped { id: *id, cause },
        };
        rows.push(MempoolRow { id: *id, transaction });
    }
    Outcome::Mempool { count, total: ids.len(), rows }
}

/// The text for a failed explorer read. The Mesh reports its own failures
/// as HTTP 200 with a code (`Error::Mesh`); any other status is
/// `Error::HttpStatus`.
fn explorer_refusal(e: &Error) -> String {
    refusal_with(e, None)
}

/// The text for a failed `/search/transactions` read, with what the answer
/// implies about the node's indexer.
///
/// `mochimo-mesh` serves the route only when its indexer is enabled, so a
/// node without one answers 404. With an indexer, code 2 (internal error)
/// means its database is not connected or the search failed.
fn search_refusal(e: &Error) -> String {
    let note = match e {
        Error::HttpStatus { status: 404 } => Some(
            "The Mesh serves /search/transactions only when its indexer was enabled as it \
             started, and a deployment runs no indexer unless it was configured to: this node \
             does not index. Another may.",
        ),
        Error::Mesh { code: 2, .. } => Some(
            "The Mesh answers its internal error on /search/transactions while its indexer's \
             database is not connected and when a search fails: this node runs an indexer, and \
             it did not answer. It may answer if asked again, and another node may.",
        ),
        _ => None,
    };
    refusal_with(e, note)
}

fn refusal_with(e: &Error, note: Option<&str>) -> String {
    let mut text = format!("{e}");
    if let Some(note) = note {
        text.push_str("\n  ");
        text.push_str(note);
    }
    text.push_str("\n  Nothing was read but the node: no store was opened and no password asked.");
    text
}
