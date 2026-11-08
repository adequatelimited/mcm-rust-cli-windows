// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! The text printed for each decided command.
//!
//! [`render`] depends only on an [`Outcome`]: no store, client or seed. What
//! a command decides is kept separate from how it is worded.
//!
//! Renderers must not look up facts the outcome does not carry; any extra
//! field belongs in the variant. For example, [`Upgraded`] carries the
//! store's format-version change from where the store was open.

use super::outcome::{
    AccountLine, Decided, Outcome, Shipped, StakeInfoPage, StakingContext, StakingRefusal, StakingShipped, Upgraded,
    ValidatorShipped,
};
use super::{
    cannot_render, destination, hex_bytes, no_such_account, reservation_lines, state_of, Code,
    Report,
};
use crate::recon::AccountStatus;

/// The note shown when the command upgraded the store's format version.
fn upgrade(upgraded: Upgraded) -> String {
    match upgraded {
        Some(from) => format!(
            "\n\nThis store was written in format version {} by this command (it was version {from} \
             until now). An older build of this wallet will no longer open \
             it; this build and later ones do. Nothing was retyped and nothing needs to be.",
            crate::keystore::format::VERSION
        ),
        None => String::new(),
    }
}

fn balance(accounts: &[AccountLine]) -> Report {
    if accounts.is_empty() {
        return Report::ok("no accounts in this store.".into());
    }
    let mut out = String::new();
    for AccountLine { tag, status } in accounts {
        let state = state_of(status);
        let dest = match destination(tag) {
            Ok(d) => d,
            Err(e) => return cannot_render(tag, &e),
        };
        out.push_str(&format!(
            "{dest:<width$}  {:>20} nanoMCM spendable  index {}  {}\n",
            status.balance(),
            status.index().get(),
            state,
            width = crate::addr::TAG_BASE58_MAX_CHARS
        ));
        if let AccountStatus::SpendOutstanding {
            spent_index,
            reservation,
            ..
        } = status
        {
            out.push_str(&reservation_lines(*spent_index, reservation, "    "));
        }
    }
    out.push_str(
        "\nEach figure is the SPENDABLE balance, the only one a send is laid out against. Staked \
         coins and reward entitlement are held beside it and are not in it; `stake-info <tag>` \
         shows them.\n",
    );
    Report::ok(out)
}

fn accounts(held: &[super::address::Held]) -> Report {
    if held.is_empty() {
        return Report::ok(
            "no accounts in this store. `create` makes one; `restore --account N` adds one the \
             chain already knows."
                .into(),
        );
    }
    let mut out = format!("{} account(s) in this store:\n", held.len());
    for h in held {
        let dest = match destination(&h.tag) {
            Ok(d) => d,
            Err(e) => return cannot_render(&h.tag, &e),
        };
        out.push_str(&format!(
            "  {dest:<width$}  index {}  {}\n",
            h.index.get(),
            match h.kind {
                crate::account::AccountKind::Derived => "derived",
                crate::account::AccountKind::Imported => "imported",
                crate::account::AccountKind::Sdk => "sdk",
            },
            width = crate::addr::TAG_BASE58_MAX_CHARS
        ));
    }
    out.push_str(
        "\nEach line begins with a DESTINATION -- give one to whoever is paying you. Read from \
         the store's own records: no node was asked and no seed was needed, so this works \
         before the account has any funds and without the phrase. `address <destination>` adds \
         the 40-byte ledger address, and that one does need the seed.",
    );
    Report::ok(out)
}

/// Turn a decided command into the page it prints and the code it exits with.
///
/// Any standing-divergence notice from [`Decided`] is printed before the
/// command's own text.
pub fn render(decided: &Decided) -> Report {
    let report = outcome(&decided.outcome);
    let notice = super::standing_divergence_notice(&decided.standing);
    Report {
        text: format!("{notice}{}", report.text),
        code: report.code,
    }
}

fn outcome(outcome: &Outcome) -> Report {
    match outcome {
        Outcome::Balance { accounts: a } => balance(a),
        Outcome::Accounts { held } => accounts(held),

        Outcome::Address {
            tag,
            address,
            index,
        } => match destination(tag) {
            Err(e) => cannot_render(tag, &e),
            Ok(dest) => Report::ok(format!(
                "{dest}\n  address  {}\n  index    {}\n\nThe first line is this account's \
                 DESTINATION -- Base58 over the tag and its CRC16, the form every Mochimo wallet \
                 takes. Give that to whoever is paying you. It is computed from this store alone: \
                 no node was asked, and it is the destination whether or not the chain has ever \
                 heard of this tag.\n\nThe indented `address` is the 40-byte entry the \
                 LEDGER WILL HOLD for this account at this index. Before the first credit the \
                 ledger holds nothing at all, and the entry the first credit creates comes from \
                 the tag alone -- it matches this line only because a derived account at index 0 \
                 has its tag in both halves. It is not a destination: no wallet takes it, and \
                 neither does this one.",
                hex_bytes(address),
                index.get()
            )),
        },

        Outcome::Restored {
            account,
            found,
            held_at,
            upgraded,
        } => {
            let restored_tag = match destination(&found.tag) {
                Ok(d) => d,
                Err(e) => return cannot_render(&found.tag, &e),
            };
            let what = match held_at {
                None => "added to the store at that index, in one write".to_string(),
                Some(stored) if *stored == found.index => format!(
                    "already in the store, at that same index {}; nothing was written",
                    stored.get()
                ),
                Some(stored) => format!(
                    "ALREADY IN THE STORE, at index {} -- and NOT moved. Restore builds an \
                     account the store lacks; moving one it holds is reconciliation, which \
                     shows you the whole store's report first. Run `status 0x{}` to see it and \
                     `reconcile 0x{} --advance-to {}` to act on it.",
                    stored.get(),
                    hex_bytes(&found.tag),
                    hex_bytes(&found.tag),
                    found.index.get()
                ),
            };
            Report::ok(format!(
                "restored account {account}\n  destination  {}\n  index    {} (from the chain, \
                 never assumed)\n  address  {}\n  balance  {} nanoMCM\n  {what}\n\nthe index came from \
                 scanning derived addresses against the one the chain holds for this tag. \
                 Position 0 is a match like any other, never a default.{}",
                restored_tag,
                found.index.get(),
                hex_bytes(&found.address),
                found.balance,
                upgrade(*upgraded)
            ))
        }

        Outcome::RestoreNeedsMaster => Report::refused(
            "restore derives an account from the master seed, and none was supplied.".into(),
        ),

        Outcome::RestoreRefused { account, failure } => match failure {
            crate::recon::RestoreFailure::NoIndexReproducesTheAddress { scanned, .. } => {
                Report::refused(format!(
                    "{failure}\n\nIn this program: `restore --account {account} --scan-to <M>` walks \
                     indices 0 through M instead of 0 through {}. Each index costs one key \
                     derivation.",
                    scanned.saturating_sub(1)
                ))
            }
            other => Report {
                text: format!("{other}"),
                code: Code::Refused,
            },
        },

        Outcome::Settled {
            settlement,
            upgraded,
        } => settled(settlement, *upgraded),

        Outcome::NoSuchAccount { tag } => Report::refused(no_such_account(tag)),

        // Shown in hex rather than as a Base58 destination, so an unknown tag
        // is not mistaken for somewhere to send funds.
        Outcome::NoAccountToAddress { tag } => Report::refused(format!(
            "no account for the tag {} in this store -- that is the tag you named, in hex so it \
             cannot be mistaken for somewhere to send funds.\n  `create` makes an account; \
             `restore --account N` adds one the chain already knows; `address` with no argument \
             lists what is here.",
            hex_bytes(tag)
        )),

        Outcome::NoMasterSeed => Report::refused(
            "this store holds no master seed (its accounts are imported), so no account can be \
             derived from it; `address <destination>` prints a stored account's address. Nothing \
             was written."
                .into(),
        ),

        Outcome::AccountAlreadyStored {
            account,
            tag,
            index,
        } => match destination(tag) {
            Err(e) => cannot_render(tag, &e),
            Ok(dest) => Report::refused(format!(
                "account {account} is already in this store (its destination is {dest}, at index \
                 {}); run `address {dest}` for the address it will next present -- position 0's \
                 address is one the chain may no longer hold. Nothing was written.",
                index.get()
            )),
        },
        Outcome::CannotRender { tag, cause } => cannot_render(tag, cause),
        Outcome::Failed(e) => Report::refused(format!("{e}")),
        Outcome::Diverged(d) => super::refuse_diverged_account(d),

        Outcome::Sent {
            shipped,
            send_total,
            fee_total,
            change_total,
            upgraded,
        } => sent(shipped, *send_total, *fee_total, *change_total, *upgraded),

        Outcome::Planned {
            source,
            destinations,
            send_total,
            fee_total,
            change_total,
            blk_to_live,
        } => planned(source, destinations, *send_total, *fee_total, *change_total, *blk_to_live),

        Outcome::Resigned { shipped } => resigned(shipped),

        Outcome::ReproducedButUnrenderable {
            source,
            destinations,
            blk_to_live,
            wire,
            cause,
        } => Report::refused(format!(
            "{}\ncannot render the destination for the tag whose hex is {}: {cause}",
            reproduction(destinations, *blk_to_live, wire),
            hex_bytes(source)
        )),

        Outcome::NotTheReservedSpend => Report::refused(
            "this is not the spend that was reserved.\n  `resign` rebuilds the reserved plan and \
             compares it to what the store recorded; the destination, amount, fee, \
             block-to-live or reference differs.\n  ACTION: re-run with the exact values the \
             original `send` used, `--ref` included if one was given. Nothing was signed."
                .into(),
        ),

        Outcome::ReservationAlreadyLanded {
            source,
            spent_index,
            settled_index,
        } => {
            let settle_arg =
                destination(source).unwrap_or_else(|_| format!("0x{}", hex_bytes(source)));
            Report::refused(format!(
                "the chain has moved past the key this reservation holds, so there is nothing \
                 left to reproduce.\n  The chain holds this tag at the key at position \
                 {settled_index}, which is the change key of the reservation at position \
                 {spent_index} -- the state reconciliation calls a landed spend, and the one \
                 `settle` resolves.\n  ACTION: `settle {settle_arg}`, which re-reads the chain, \
                 clears the reservation and keeps the settled block, so a reorg that reverts it \
                 is reported with the digest it settled. Nothing was reserved, nothing was \
                 signed, and nothing reached the socket here.\n  What was observed is the chain \
                 standing at the change key, not which transaction put it there: a change \
                 address follows the POSITION and not the transaction, so any spend from the \
                 reserved key leaves the tag exactly here. `transaction <hash>` on the id the \
                 original `send` printed is what names it."
            ))
        }

        Outcome::Submitted {
            source,
            bytes,
            submitted,
        } => submitted_page(source, bytes, submitted),

        Outcome::ArtifactNotHex { cause } => {
            Report::refused(format!("the artifact is not hex: {cause}\n{SUBMIT_NOTHING}"))
        }
        Outcome::ArtifactNotATransaction { cause } => Report::refused(format!(
            "the artifact does not parse as a transaction: {cause}\n{SUBMIT_NOTHING}"
        )),
        Outcome::ArtifactNotWhole { given, described } => Report::refused(format!(
            "the artifact is not a whole transaction image: {given} bytes were given and the \
             transaction they describe is {described} bytes, so the bytes on the socket would not be the \
             bytes you hold. A truncated or padded artifact is refused rather than repaired.\n\
             {SUBMIT_NOTHING}"
        )),

        Outcome::Status { tag, status } => status_page(tag, status),
        Outcome::StatusDiverged { tag, divergence } => match destination(tag) {
            Err(e) => cannot_render(tag, &e),
            Ok(dest) => Report::ok(format!(
                "{dest}\n  state    DIVERGED -- every operation on this account is refused \
                 until it is reconciled. Other accounts in this store are not. Nothing was changed.\n\n{divergence}{}",
                super::next_steps(core::slice::from_ref(&**divergence))
            )),
        },
        Outcome::StatusRefused { divergence } => Report::refused(format!("{divergence}")),

        Outcome::Reconciled {
            tag,
            to,
            reviewed,
            upgraded,
        } => reconciled(tag, *to, reviewed, *upgraded),

        Outcome::Discovered { sweep } => discovered(sweep),
        Outcome::DiscoverNeedsMaster => Report::refused(
            "this store holds no master seed (its accounts are imported), so no account index \
             can be derived from it and there is nothing to sweep; `address` with no argument \
             lists what this store holds. Nothing was written."
                .into(),
        ),
        Outcome::SweepStopped {
            account,
            searched,
            to,
            cause,
        } => Report::refused(format!(
            "the sweep stopped at account index {account}: {cause}\n  {searched} of {} index(es) \
             were searched. The node was not asked about index {account} or anything above it, \
             so this page reports NO extent and says nothing at all about those indices -- a \
             partial sweep printed as a whole one would be asserting absence by omission.\n  \
             Nothing was written. Fix the node and run it again.",
            u64::from(*to) + 1
        )),

        Outcome::LookedUpTransaction { page } => transaction(page),
        Outcome::TransactionNotFound { hash } => Report::refused(format!(
            "no transaction with hash {} is in this node's index.\n  The indexer holds what it saw \
             when each block arrived; a transaction still in the mempool is not there, and a \
             deployment that runs no indexer answers nothing at all.\n  Nothing was read but the \
             node.",
            hex_bytes(hash)
        )),
        Outcome::RecentTransactions { tag, from, page } => recent_transactions(tag, *from, page),
        Outcome::Block { block } => block_page(block),
        Outcome::BlockNotServed { by_hash, cause } => {
            let mut text = super::explorer_refusal(cause);
            if *by_hash {
                text.push_str(
                    "\n  A block is served by hash only from the deployment's own archive folder, \
                     so a not-found here is about that archive rather than about the chain. The \
                     index always works.",
                );
            }
            Report::refused(text)
        }
        Outcome::Blocks { count, tip, rows } => blocks(*count, tip, rows),
        Outcome::BlocksStopped { index, cause } => Report::refused(format!(
            "{}\n  The tip was read; block {index} was not.",
            super::explorer_refusal(cause)
        )),
        Outcome::Mempool { count, total, rows } => mempool(*count, *total, rows),
        Outcome::MempoolStopped { id, cause } => Report::refused(format!(
            "{}\n  The queue's ids were read; transaction {} was not.",
            super::explorer_refusal(cause),
            hex_bytes(id)
        )),
        Outcome::ExplorerFailed { cause } => Report::refused(super::explorer_refusal(cause)),
        Outcome::SearchFailed { cause } => Report::refused(super::search_refusal(cause)),

        Outcome::StoreUnreadable(e) => Report {
            text: format!("{e}"),
            code: Code::StartupRefused,
        },
        Outcome::StartupRefused(refusal) => Report {
            text: format!("{refusal}{}", super::next_steps(&refusal.diverged)),
            code: Code::StartupRefused,
        },
        Outcome::ValidatorSent { shipped, entitlement } => validator_sent(shipped, entitlement.as_ref()),
        Outcome::ValidatorResigned { shipped } => validator_resigned(shipped),
        Outcome::ImportNeedsTheTerminal => Report::refused(
            "import reads the SDK master seed from the terminal, and this caller gave none. \
             Nothing was written."
                .into(),
        ),
        Outcome::Imported { account, found, held_at } => imported(*account, found, held_at.as_ref()),
        Outcome::ImportRefused { account, failure } => Report::refused(format!(
            "import of SDK account {account}: {failure}\n  Nothing was written to the store."
        )),
        Outcome::EntitlementRead { tag, reading, ledger } => entitlement_page(tag, reading, ledger),
        Outcome::ExtensionImported {
            account_index,
            recorded,
            found,
            held_at,
        } => extension_imported(*account_index, *recorded, found, held_at.as_ref()),
        Outcome::ExtensionImportRefused { tag, failure } => Report::refused(format!(
            "import of the export's account for 0x{}: {failure}\n  Nothing was written to the store, \
             and nothing the export decrypted to was written anywhere.",
            hex_bytes(tag)
        )),
        Outcome::StakingSent { shipped, context } => staking_sent(shipped, context),
        Outcome::StakingRefused { tag, refusal } => staking_refused(tag, refusal),
        Outcome::StakeInfo(page) => stake_info(page),
        Outcome::HandledBeforeTheWallet => {
            Report::refused("this command is handled before the wallet opens".into())
        }
        Outcome::NotAReadOnlyVerb { command } => Report::refused(format!(
            "internal: {command:?} is not one of the read-only verbs and cannot be run without a store"
        )),

        Outcome::UnstoredAddress {
            account,
            tag,
            address,
        } => unstored_address(*account, tag, address),
    }
}

fn settled(settlement: &crate::wallet::Settlement, upgraded: Upgraded) -> Report {
    use crate::recon::Reservation;
    use crate::wallet::Settlement;
    let upgrade = upgrade(upgraded);
    match settlement {
        Settlement::Settled {
            spent_index,
            index,
        } => Report::ok(format!(
            "settled: the chain holds this tag at the change key.\n  spent index {}  ->  next \
             index {}\nthe reservation is cleared and the account can spend again. The settled \
             block is kept in the record until the next spend or advance, so a reorg that \
             reverts it is reported with the digest it settled.{upgrade}",
            spent_index.get(),
            index.get()
        )),
        Settlement::StillOutstanding {
            spent_index,
            reservation,
        } => {
            let lines = reservation_lines(*spent_index, reservation, "  ");
            let dead = matches!(reservation, Reservation::Recorded(d) if d.is_dead());
            Report::ok(if dead {
                format!(
                    "NOT settled: the chain still holds this tag at the key that signed (index {}), \
                     and the reserved artifact can no longer be accepted -- the spend will never \
                     land. The store was not advanced.\n{lines}",
                    spent_index.get()
                )
            } else {
                format!(
                    "NOT settled: the chain still holds this tag at the key that signed (index {}).\nThe \
                     spend has not landed. It may never -- submission is a socket write, not a verdict. \
                     If the retry artifact is lost, `resign` rebuilds it.\n{lines}",
                    spent_index.get()
                )
            })
        }
        Settlement::NothingPending { index } => Report::ok(format!(
            "nothing is reserved for this tag; it is at index {}.",
            index.get()
        )),
    }
}

fn unstored_address(account: u32, tag: &crate::addr::Tag, address: &crate::addr::Address) -> Report {
    let dest = match destination(tag) {
        Ok(d) => d,
        Err(e) => return cannot_render(tag, &e),
    };
    Report::ok(format!(
        "{dest}\n  address  {}\n  index    0\n\nNOT STORED. Account {account} was derived from this \
         store's master seed and written nowhere: nothing was written, nothing reserved, no node \
         asked. The first line is its DESTINATION -- Base58 over the tag and its CRC16, the form \
         every Mochimo wallet takes -- and the indented `address` is the 40-byte entry the ledger \
         will hold at index 0 once it is paid. Give the destination to whoever is paying you; once \
         it has been paid, run `restore --account {account}`, which asks the chain where the \
         account sits and adds it to this store at that position (0 for a first credit), under \
         this same tag. Until then the store does not hold it and `balance` will not show it.",
        hex_bytes(address)
    ))
}

/// Appends the submission result to a page and returns the exit code.
fn shipped_tail(page: &mut String, s: &Shipped, settle_arg: &str, on_refusal: &str) -> Code {
    match &s.submitted {
        Ok(id) => {
            page.push_str(&super::submitted_block(id, settle_arg));
            Code::Ok
        }
        Err(e) => {
            page.push_str(&format!("\nsubmission FAILED: {e}\n{on_refusal}"));
            Code::Refused
        }
    }
}

fn sent(
    s: &Shipped,
    send_total: u64,
    fee_total: u64,
    change_total: u64,
    upgraded: Upgraded,
) -> Report {
    let settle_arg = match destination(&s.source) {
        Ok(d) => d,
        Err(e) => return cannot_render(&s.source, &e),
    };
    let listed = match super::destination_lines(&s.destinations) {
        Ok(l) => l,
        Err((tag, e)) => return cannot_render(&tag, &e),
    };
    let emptying = if change_total == 0 {
        super::emptying_text(&settle_arg)
    } else {
        String::new()
    };
    let wire_hex = hex_bytes(&s.wire);
    let mut page = format!(
        "sending {send_total} nanoMCM to {} destination(s)\n{}{}\n{}{}",
        s.destinations.len(),
        laid_out(&listed, &settle_arg, s.destinations.len(), fee_total, change_total, s.blk_to_live),
        emptying,
        super::artifact_notices(&wire_hex),
        upgrade(upgraded)
    );
    let code = shipped_tail(&mut page, s, &settle_arg, super::SEND_REFUSAL);
    Report { text: page, code }
}

/// The spend summary shown by both `send` and the unsigned plan page, so the
/// two always list a spend the same way.
fn laid_out(listed: &str, settle_arg: &str, count: usize, fee_total: u64, change_total: u64, blk_to_live: u64) -> String {
    format!(
        "{listed}  from   {settle_arg}\n  fee    {fee_total} total (the node's floor is {} per \
         destination, {} here)\n  change {change_total} to your own next key under this tag\n  btl    \
         {}\n\nCheck every destination against its payee before going further. Each is shown in \
         the checksummed form whichever form you typed, so it can be compared character for \
         character with what their wallet shows. They are listed in the order that goes on the \
         wire, which the layout sorts and which need not be the order you typed.\n",
        crate::consts::MFEE,
        crate::consts::MFEE.saturating_mul(u64::try_from(count).unwrap_or(u64::MAX)),
        super::block_to_live_line(blk_to_live),
    )
}

/// A spend laid out but not signed: the [`laid_out`] summary, the emptying
/// paragraph when the change is zero, and a statement that nothing has been
/// signed or sent.
fn planned(
    source: &crate::addr::Tag,
    destinations: &[crate::tx::wire::Destination],
    send_total: u64,
    fee_total: u64,
    change_total: u64,
    blk_to_live: u64,
) -> Report {
    let settle_arg = match destination(source) {
        Ok(d) => d,
        Err(e) => return cannot_render(source, &e),
    };
    let listed = match super::destination_lines(destinations) {
        Ok(l) => l,
        Err((tag, e)) => return cannot_render(&tag, &e),
    };
    let emptying = if change_total == 0 {
        format!(
            "{}  Once it is signed, keep the artifact: `submit` writes it to the socket without \
             opening the store, and is the route to a node while the account reads as not found.\n",
            super::emptying_paragraph(&settle_arg)
        )
    } else {
        String::new()
    };
    Report::ok(format!(
        "NOT SIGNED: a spend of {send_total} nanoMCM to {} destination(s), laid out for you to \
         check. Nothing has been signed yet.\n{}{emptying}\nNo key has been reserved or used, \
         nothing has been signed, and nothing has been sent to a node. Signing reserves this \
         spend's key first, and from then on these figures -- each destination, amount and \
         reference, the fee and the block-to-live -- are the only spend that key will sign: \
         signing it again later needs exactly them.",
        destinations.len(),
        laid_out(&listed, &settle_arg, destinations.len(), fee_total, change_total, blk_to_live),
    ))
}

/// The page `resign` prints for a reproduced transaction, whether or not the
/// submission succeeds.
fn reproduction(destinations: &[crate::tx::wire::Destination], blk_to_live: u64, wire: &[u8]) -> String {
    let listed = match super::destination_lines(destinations) {
        Ok(l) => l,
        // Unreachable from `decide`, which renders the same list first;
        // handled rather than panicking.
        Err((tag, e)) => format!("  <cannot render {}: {e}>\n", hex_bytes(&tag)),
    };
    format!(
        "reproduced {} destination(s)\n{listed}block-to-live {}\n{}\nThese are the SAME \
         bytes the original signing produced -- the reserved key signed the reserved \
         digest again, which WOTS+ determinism makes byte-identical. No second signature \
         was created.\n",
        destinations.len(),
        super::block_to_live_line(blk_to_live),
        super::artifact_notices(&hex_bytes(wire))
    )
}

fn resigned(s: &Shipped) -> Report {
    let mut page = reproduction(&s.destinations, s.blk_to_live, &s.wire);
    let settle_arg = match destination(&s.source) {
        Ok(d) => d,
        // Unreachable from `decide`, which refuses first; handled rather
        // than panicking.
        Err(e) => {
            return Report::refused(format!(
                "{page}\ncannot render the destination for the tag whose hex is {}: {e}",
                hex_bytes(&s.source)
            ))
        }
    };
    let on_refusal = super::resign_refusal(&settle_arg);
    let code = shipped_tail(&mut page, s, &settle_arg, &on_refusal);
    Report { text: page, code }
}

/// What a validator transaction does, in one line.
fn validator_what(op: &crate::mesh::spend::ValidatorOp) -> core::result::Result<String, (crate::addr::Tag, crate::Error)> {
    use crate::mesh::spend::ValidatorOp;
    Ok(match op {
        ValidatorOp::SetDelegate { delegate } => {
            let d = destination(delegate).map_err(|e| (*delegate, e))?;
            format!(
                "set-delegate: bind {d} as this validator's delegate\n  the node also requires \
                 that tag to hold at least {} nanoMCM, no validator slot of its own, and no binding \
                 to another validator -- none of which this wallet can see, and each of which the \
                 node checks only after the cold key has signed",
                crate::consts::pos::DELEGATE_MIN_BALANCE
            )
        }
        ValidatorOp::ClearDelegate => "clear-delegate: clear this validator's delegate binding".to_string(),
        ValidatorOp::Claim { amount } => format!(
            "claim: release {amount} nanoMCM of reward entitlement into the spendable balance"
        ),
    })
}

/// Warnings on every validator page: ways the transaction can become
/// unusable after the key has signed.
const VALIDATOR_WARNINGS: &str = "\
The fee comes from the SPENDABLE balance, never from entitlement. The node demands that \
send + change + fee equal that balance EXACTLY, and this transaction was laid out against \
one observation of it. Any payment that lands on this tag before the transaction is \
included -- and anyone can send dust to a public tag -- makes the totals disagree, the node \
refuses it, and the one-time key that signed it can sign nothing else: the account is then \
frozen at that key. Keep the tag unfunded by anyone else while this is outstanding.";

fn validator_head(s: &ValidatorShipped, settle_arg: &str, what: &str) -> String {
    format!(
        "{what}\n  from   {settle_arg} (the validator's cold tag)\n  fee    {} total, from the \
         spendable balance (the node's floor is {} for the whole transaction)\n  change {} to \
         your own next key under this tag\n  btl    {}\n\n{VALIDATOR_WARNINGS}\n",
        s.fee_total,
        crate::consts::MFEE,
        s.change_total,
        super::block_to_live_line(s.blk_to_live),
    )
}

fn entitlement_line(e: &crate::entitlement::Entitlement) -> String {
    match e.origin {
        crate::entitlement::Origin::Endpoint { block } => format!(
            "  entitlement {} nanoMCM, from /account/entitlement at block {block}. The node \
             answers from a cached ledger, so the figure can be a block or more old; between \
             claims it only grows, so a claim within it stays within the ledger's",
            e.amount
        ),
        crate::entitlement::Origin::OperatorSupplied => format!(
            "  entitlement {} nanoMCM, AS SUPPLIED by --entitlement and checked against nothing. \
             If it is above the ledger's, the node refuses the claim after the key has signed",
            e.amount
        ),
    }
}

fn validator_sent(s: &ValidatorShipped, entitlement: Option<&crate::entitlement::Entitlement>) -> Report {
    let settle_arg = match destination(&s.source) {
        Ok(d) => d,
        Err(e) => return cannot_render(&s.source, &e),
    };
    let what = match validator_what(&s.op) {
        Ok(w) => w,
        Err((tag, e)) => return cannot_render(&tag, &e),
    };
    let mut page = validator_head(s, &settle_arg, &what);
    if let Some(e) = entitlement {
        page.push_str(&format!("{}\n", entitlement_line(e)));
    }
    page.push('\n');
    page.push_str(&super::artifact_notices(&hex_bytes(&s.wire)));
    page.push_str(
        "For a validator transaction `--resign` is the recovery: the same verb with the same \
         parameters and `--resign` reproduces these bytes and writes them again.\n",
    );
    let code = validator_tail(&mut page, s, &settle_arg, super::SEND_REFUSAL);
    Report { text: page, code }
}

fn validator_resigned(s: &ValidatorShipped) -> Report {
    let settle_arg = match destination(&s.source) {
        Ok(d) => d,
        Err(e) => return cannot_render(&s.source, &e),
    };
    let what = match validator_what(&s.op) {
        Ok(w) => w,
        Err((tag, e)) => return cannot_render(&tag, &e),
    };
    let mut page = format!(
        "reproduced the reserved transaction, byte for byte -- the same signature, not a second \
         one under this key\n\n{}\nRETRY ARTIFACT:\n\n{}\n",
        validator_head(s, &settle_arg, &what),
        hex_bytes(&s.wire)
    );
    let on_refusal = super::resign_refusal(&settle_arg);
    let code = validator_tail(&mut page, s, &settle_arg, &on_refusal);
    Report { text: page, code }
}

fn validator_tail(page: &mut String, s: &ValidatorShipped, settle_arg: &str, on_refusal: &str) -> Code {
    match &s.submitted {
        Ok(id) => {
            page.push_str(&super::submitted_block(id, settle_arg));
            page.push_str(
                "\nThe Mesh does not list validator transactions in /block, so the chain moving \
                 this tag to its change key is the only sign that it landed, and `settle` reads \
                 exactly that.",
            );
            Code::Ok
        }
        Err(e) => {
            page.push_str(&format!("\nsubmission FAILED: {e}\n{on_refusal}"));
            Code::Refused
        }
    }
}

fn imported(
    account: u32,
    found: &crate::recon::RestoredAccount,
    held_at: Option<&crate::account::WotsIndex>,
) -> Report {
    let dest = match destination(&found.tag) {
        Ok(d) => d,
        Err(e) => return cannot_render(&found.tag, &e),
    };
    let what = match held_at {
        None => "added to the store at that index, in one write, as an SDK account".to_string(),
        Some(stored) if *stored == found.index => {
            format!("already in the store, at that same index {}; nothing was written", stored.get())
        }
        Some(stored) => format!(
            "ALREADY IN THE STORE, at index {} -- and NOT moved. Run `status 0x{}` to see the \
             whole report.",
            stored.get(),
            hex_bytes(&found.tag)
        ),
    };
    Report::ok(format!(
        "imported SDK account {account}\n  destination  {dest}\n  index    {} (from the chain, \
         never assumed; index 0 is the implicit key, tag and hash equal)\n  address  {}\n  balance  \
         {} nanoMCM\n  {what}\n\nThe store keeps the SDK account seed, not the master seed you \
         typed: the master is in no file this program writes.",
        found.index.get(),
        hex_bytes(&found.address),
        found.balance
    ))
}

fn extension_imported(
    account_index: u32,
    recorded: crate::account::WotsIndex,
    found: &crate::recon::RestoredAccount,
    held_at: Option<&crate::account::WotsIndex>,
) -> Report {
    let dest = match destination(&found.tag) {
        Ok(d) => d,
        Err(e) => return cannot_render(&found.tag, &e),
    };
    let what = match held_at {
        None => "added to the store at that index, in one write, as an imported account".to_string(),
        Some(stored) if *stored == found.index => {
            format!("already in the store, at that same index {}; nothing was written", stored.get())
        }
        Some(stored) => format!(
            "ALREADY IN THE STORE, at index {} -- and NOT moved. Run `status 0x{}` to see the whole report.",
            stored.get(),
            hex_bytes(&found.tag)
        ),
    };
    let disagreed = if recorded == found.index {
        String::new()
    } else {
        format!(
            "\n  the export recorded index {} for this account and the chain holds it at {}; the \
             chain's is the one stored",
            recorded.get(),
            found.index.get()
        )
    };
    Report::ok(format!(
        "imported the export's account {account_index}\n  destination  {dest}\n  index    {} (from the \
         chain, never assumed; index 0 is the implicit key, tag and hash equal){disagreed}\n  address  \
         {}\n  balance  {} nanoMCM\n  {what}\n\nChecked before anything was written: the record names \
         this tag, its account seed regenerates its first address and that address hashes to the \
         tag, and the export's master seed at index {account_index} derives the same seed and tag. \
         The store keeps the account seed and the first key's public parts, encrypted; the master \
         seed and the decrypted export were held in memory only.",
        found.index.get(),
        hex_bytes(&found.address),
        found.balance
    ))
}

fn entitlement_page(
    tag: &crate::addr::Tag,
    reading: &core::result::Result<crate::entitlement::Entitlement, crate::Error>,
    ledger: &core::result::Result<crate::mesh::LedgerEntry, crate::Error>,
) -> Report {
    let dest = destination(tag).unwrap_or_else(|_| format!("0x{}", hex_bytes(tag)));
    let mut page = format!("entitlement of {dest}\n");
    let mut ok = true;
    match reading {
        Ok(e) => {
            page.push_str(&entitlement_line(e));
            page.push('\n');
        }
        Err(e) => {
            ok = false;
            page.push_str(&format!("  entitlement could not be read: {e}\n"));
        }
    }
    match ledger {
        Ok(entry) => {
            page.push_str(&format!(
                "  balance     {} nanoMCM spendable, at address {}\n",
                entry.balance,
                hex_bytes(&entry.address)
            ));
            let fee = crate::consts::MFEE;
            if entry.balance < fee {
                page.push_str(&format!(
                    "  a claim's fee of {fee} cannot be paid from that balance: fund this tag with at \
                     least {fee} nanoMCM first\n"
                ));
            } else {
                page.push_str(&format!("  a claim's fee of {fee} can be paid from that balance\n"));
            }
        }
        Err(e) => page.push_str(&format!(
            "  balance     not read: {e}. The node answers account-not-found for a tag at zero \
             balance, so a cold tag holding only entitlement reads this way, and a claim's fee \
             cannot be paid until the tag is funded\n"
        )),
    }
    page.push_str("\nRead only: nothing was signed, reserved or written.");
    if ok {
        Report::ok(page)
    } else {
        Report::refused(page)
    }
}

// ---- v4.1 staking pages ----

/// nanoMCM as `N nanoMCM (M.MMMMMMMMM MCM)`.
fn nano_mcm(v: u64) -> String {
    let unit = crate::staking::NANO_PER_MCM;
    format!("{v} nanoMCM ({}.{:09} MCM)", v / unit, v % unit)
}

/// Heights as an estimate of time at one block a minute.
fn about(heights: u64) -> String {
    let (days, hours) = crate::staking::days_and_hours(heights);
    format!("about {days} days {hours} hours at one block a minute")
}

fn network_name(n: &crate::staking::Network) -> String {
    match n.id {
        crate::staking::NETWORK_MAINNET => format!("mainnet (network id 0x{:04x}, v4.1 above height {})", n.id, n.t41),
        crate::staking::NETWORK_TESTNET => format!("testnet (network id {}, v4.1 above height {})", n.id, n.t41),
        id => format!("network id {id}, v4.1 above height {}", n.t41),
    }
}

fn kind_name(kind: u8) -> &'static str {
    match kind {
        crate::staking::KIND_REVOKE => "revoke",
        crate::staking::KIND_DELEGATE => "delegate (kind 1)",
        crate::staking::KIND_MEMBER_DELEGATE => "member delegate (kind 2)",
        crate::staking::KIND_MEMBER_COLD => "member cold key (kind 3)",
        crate::staking::KIND_NEW_HOLDER => "new slot holder (kind 4)",
        _ => "unknown kind",
    }
}

/// The lines describing what a staking transaction does.
fn staking_what(s: &StakingShipped, c: &StakingContext) -> String {
    use crate::mesh::spend::DustProofOp;
    let stake_line = |f: &crate::mesh::codec::StakeFields| -> String {
        match f.terms {
            Some(t) => format!(
                "  stake     {} staked, committed at height {}, lock ends at height {}{}",
                nano_mcm(f.staked),
                t.commit,
                t.expiry,
                if c.height < t.expiry {
                    format!(" -- LOCKED for {} more heights, {}", t.expiry - c.height, about(t.expiry - c.height))
                } else {
                    " -- expired".to_string()
                }
            ),
            None => format!("  stake     {} staked", nano_mcm(f.staked)),
        }
    };
    match &s.op {
        DustProofOp::Stake { amount, tier, .. } => {
            let lock = crate::staking::BASE_LOCK << tier;
            let expiry = crate::staking::expiry(c.height, *tier);
            let mut out = format!(
                "stake: lock {} at tier {tier}, coefficient {}x\n  minimum   {} at height {} \
                 (the minimum only falls, so a later block cannot raise it)\n",
                nano_mcm(*amount),
                crate::staking::coefficient(*tier),
                nano_mcm(crate::staking::minstake(c.height, c.network.t41)),
                c.height,
            );
            match expiry {
                Some(e) => out.push_str(&format!(
                    "  lock      if included at height {}, the stake is locked until height {e}, the first \
                     neogenesis at or above {} + {lock}: {}. A later block moves both ends later\n",
                    c.height,
                    c.height,
                    about(e.saturating_sub(c.height))
                )),
                None => out.push_str("  lock      no expiry could be computed for this tier\n"),
            }
            out.push_str(
                "  rewards   half of each real block's emission is split among stakers by weight, \
                 (staked + entitlement) x coefficient; the reward compounds inside the lock. \
                 Unstaking before the lock ends FORFEITS the whole entitlement to the other stakers\n",
            );
            out
        }
        DustProofOp::Unstake { .. } => {
            let mut out = "unstake: return the whole staked principal to the spendable balance\n".to_string();
            if let Some(f) = &c.stake {
                out.push_str(&stake_line(f));
                out.push('\n');
                match (f.terms, f.entitlement) {
                    (Some(t), e) if c.height < t.expiry => out.push_str(&format!(
                        "  FORFEIT   the lock has not ended, so the entitlement this stake has earned -- {} -- is \
                         FORFEITED to the other stakers, as you confirmed with --forfeit\n",
                        e.map_or("not reported".to_string(), nano_mcm)
                    )),
                    (_, e) => out.push_str(&format!(
                        "  reward    the lock has ended, so the entitlement -- {} -- is NOT forfeited. It stays on \
                         this tag, earning nothing more, until you claim it: `claim <tag> all`\n",
                        e.map_or("not reported".to_string(), nano_mcm)
                    )),
                }
            }
            out
        }
        DustProofOp::Claim { amount } => {
            let what = if *amount == crate::staking::CLAIM_ALL {
                "everything (UINT64_MAX: whatever the entitlement is when the block is built)".to_string()
            } else {
                nano_mcm(*amount)
            };
            let mut out = format!("claim: release {what} of reward entitlement into the spendable balance\n");
            if let Some(e) = &c.entitlement {
                out.push_str(&format!("  entitlement {}\n", nano_mcm(e.amount)));
            }
            if let Some(f) = c.stake.as_ref().filter(|f| f.staked > 0) {
                out.push_str(&stake_line(f));
                out.push_str(
                    "\n  ALSO UNSTAKES: the lock has ended, so this claim returns the staked principal to the \
                     spendable balance as well, and the stake ends\n",
                );
            }
            out
        }
        DustProofOp::SetDelegate { delegate } => format!(
            "set-delegate (v4.1 dust-proof form): bind {} as this validator's delegate. Above the trigger it \
             binds only if that tag holds a live kind-1 consent naming this cold tag (`accept --kind 1`)\n",
            destination(delegate).unwrap_or_else(|_| format!("0x{}", hex_bytes(delegate)))
        ),
        DustProofOp::ClearDelegate => {
            "clear-delegate (v4.1 dust-proof form): clear this validator's delegate binding\n".to_string()
        }
        DustProofOp::Accept(t) if t.kind == crate::staking::KIND_REVOKE => {
            "revoke: clear this tag's consent. A revoke never touches a stake\n".to_string()
        }
        DustProofOp::Accept(t) => {
            let mut out = format!(
                "accept: consent, as {}, to a designation naming peer {}\n",
                kind_name(t.kind),
                destination(&t.peer).unwrap_or_else(|_| format!("0x{}", hex_bytes(&t.peer)))
            );
            if t.action != 0 {
                out.push_str(&format!(
                    "  action    {}\n",
                    if t.action == crate::staking::ACTION_ELECT { "elect" } else { "recover" }
                ));
            }
            if t.slot != 0 {
                out.push_str(&format!("  slot      {}\n", t.slot));
            }
            if t.port != 0 {
                let [a, b, cc, d] = t.ip;
                out.push_str(&format!("  ip:port   {a}.{b}.{cc}.{d}:{}\n", t.port));
            }
            if t.flags != 0 {
                out.push_str(&format!("  flags     0x{:02x}\n", t.flags));
            }
            out.push_str(&format!(
                "  digest    {} -- the designation binds only if its own terms reproduce this, within 65,536 \
                 heights of inclusion\n",
                hex_bytes(&t.digest(&s.source))
            ));
            if let Some(f) = c.stake.as_ref().filter(|f| f.staked > 0) {
                out.push_str(&stake_line(f));
                out.push_str("\n  ENDS THE STAKE: a consent ends this tag's stake in the same transaction\n");
            }
            out
        }
    }
}

const DUST_PROOF_NOTE: &str = "\
Dust-proof form: the transaction signs send = change = 0 and the node credits the change itself, \
so a payment that lands on this tag before inclusion cannot invalidate it. The wallet cannot see \
whether this tag is a validator address or sits in the pending reward snapshot -- the Mesh \
does not disclose them -- and a staking transaction from such a tag is included for its fee \
and binds nothing. A tag bound as a validator's delegate must not sign \
anything with this wallet: the node refuses it after the key has signed.";

fn staking_sent(s: &StakingShipped, c: &StakingContext) -> Report {
    let settle_arg = match destination(&s.source) {
        Ok(d) => d,
        Err(e) => return cannot_render(&s.source, &e),
    };
    let mut page = String::new();
    if s.resigned {
        page.push_str(
            "reproduced the reserved transaction, byte for byte -- the same signature, not a second one \
             under this key\n\n",
        );
    }
    page.push_str(&staking_what(s, c));
    page.push_str(&format!(
        "  from      {settle_arg}\n  fee       {} total, from the spendable balance of {}\n  network   {}\n\n{DUST_PROOF_NOTE}\n\n",
        s.fee_total,
        nano_mcm(c.spendable),
        network_name(&c.network),
    ));
    page.push_str(&super::artifact_notices(&hex_bytes(&s.wire)));
    page.push_str(
        "For a staking transaction `--resign` is the recovery: the same verb with the same parameters \
         and `--resign` reproduces these bytes and writes them again.\n",
    );
    let code = match &s.submitted {
        Ok(id) => {
            page.push_str(&super::submitted_block(id, &settle_arg));
            page.push_str(
                "\nThe chain moving this tag to its change key is the sign that it landed, and `settle` reads \
                 exactly that. `stake-info <tag>` shows the stake once it has.",
            );
            Code::Ok
        }
        Err(e) => {
            let on_refusal = if s.resigned { super::resign_refusal(&settle_arg) } else { super::SEND_REFUSAL.to_string() };
            page.push_str(&format!("\nsubmission FAILED: {e}\n{on_refusal}"));
            Code::Refused
        }
    };
    Report { text: page, code }
}

fn staking_refused(tag: &crate::addr::Tag, r: &StakingRefusal) -> Report {
    let who = destination(tag).unwrap_or_else(|_| format!("0x{}", hex_bytes(tag)));
    let why = match r {
        StakingRefusal::NotActive { height, t41 } => format!(
            "the tip, height {height}, does not run the v4.1 rules: they apply above height {t41}, and the \
             node checks a new transaction against the tip. Wait until the tip is above it"
        ),
        StakingRefusal::TipUnreadable(e) => format!("the chain tip could not be read ({e}), so the height is unknown"),
        StakingRefusal::StakeUnreadable(e) => format!(
            "/account/balance could not be read ({e}). Every staking rule depends on this tag's stake, so \
             nothing is signed without it. The Mesh answers account-not-found for a tag with nothing \
             spendable and nothing staked"
        ),
        StakingRefusal::BalanceUnreadable(e) => format!("the spendable balance could not be read ({e})"),
        StakingRefusal::StakeUnreported => "the node's /account/balance reports no stake fields for this tag: \
             the middleware predates v4.1, or its stake source is unavailable. Every staking rule depends on \
             them, so nothing is signed"
            .to_string(),
        StakingRefusal::StakeFieldsCached { block } => format!(
            "the stake fields come from the Mesh's ledger cache, read at height {block}, not from the node, \
             so they can be older than the spendable balance beside them. A transaction signed on them can \
             be refused after the key has signed, so nothing is signed. Try again when the Mesh reads the \
             node again"
        ),
        StakingRefusal::StakeTermsUnreported => "this tag stakes, but the node reports no commit and expiry \
             heights for the stake, so the lock cannot be checked and nothing is signed"
            .to_string(),
        StakingRefusal::StakeTermsInconsistent { commit, expiry } => format!(
            "the node's stake report does not agree with itself: commit height {commit}, expiry {expiry}, the \
             tier and the lock state do not match each other or the tip. Nothing is signed on it. Try again, \
             or ask another node"
        ),
        StakingRefusal::LockEndNotConfirmed { expiry, given } => format!(
            "the node reports that the lock ended at height {expiry}. If it has not, this transaction FORFEITS \
             the entitlement the stake has earned, and the wallet can only see the lock through the node. {}. \
             Pass --lock-ends with the expiry height you know the stake has, once a source other than \
             this node shows the chain past it, or --forfeit to accept the forfeit",
            match given {
                Some(g) => format!("--lock-ends {g} does not match it"),
                None => "--lock-ends was not given".to_string(),
            }
        ),
        StakingRefusal::LiveConsent { kind, lapses_at } => format!(
            "this tag holds a consent of kind {kind} that lapses at height {lapses_at}. The node refuses a \
             stake from a tag with a live consent, and the key would stay reserved for it. Revoke it first \
             (`revoke <tag>`), or wait until it lapses"
        ),
        StakingRefusal::ConsentUnknown => "the Mesh does not show whether this tag holds a consent. The node \
             refuses a stake from a tag whose consent (`accept`) was recorded less than 65,536 blocks ago and \
             not cleared by a revoke or a designation, and the key would stay reserved for it. Pass \
             --no-live-consent if this tag holds no such consent"
            .to_string(),
        StakingRefusal::ExpiryWithUnknownConsent { blk_to_live } => format!(
            "--btl {blk_to_live} is refused while the Mesh does not show whether this tag holds a consent. If \
             it does, the node refuses the stake and the key stays reserved for it; without a block to live \
             the same transaction lands once the consent lapses, but with one it can expire first, and the \
             key can then sign nothing else. Stake without --btl"
        ),
        StakingRefusal::NotStakedUnconfirmed => "the node reports that this tag does not stake, and the wallet \
             can only see the stake through the node. A consent from a tag whose stake is still locked \
             FORFEITS the entitlement the stake has earned. Pass --not-staked if this tag does not stake, or \
             --forfeit to accept the forfeit"
            .to_string(),
        StakingRefusal::ConsentEntitlementUnclaimed { entitlement } => format!(
            "this tag holds {} of unclaimed entitlement, and a consent from it is included for its fee and \
             binds nothing. Claim it first: `claim <tag> all`",
            nano_mcm(*entitlement)
        ),
        StakingRefusal::EntitlementUnreadable(e) => format!(
            "the entitlement could not be read ({e}). A stake or a consent from a tag with unclaimed entitlement is \
             included for its fee and binds nothing, so the wallet does not sign without knowing it; \
             --entitlement N supplies a figure you read elsewhere"
        ),
        StakingRefusal::BelowMinimum { amount, minimum, height } => format!(
            "{} is below the minimum stake at height {height}, {}",
            nano_mcm(*amount),
            nano_mcm(*minimum)
        ),
        StakingRefusal::StakeNotCovered { amount, fee, spendable } => format!(
            "the stake of {} plus the fee of {fee} is more than the spendable balance, {}",
            nano_mcm(*amount),
            nano_mcm(*spendable)
        ),
        StakingRefusal::StakeLeavesTooLittle { amount, fee, spendable } => format!(
            "staking {} with a fee of {fee} would leave less than {} of the spendable {} -- keep at least \
             one fee spendable. The Mesh's tag resolution answers nothing for a tag with nothing spendable, \
             and this wallet reconciles and signs through it, so a stake of everything could not be unstaked \
             or claimed from here",
            nano_mcm(*amount),
            crate::consts::MFEE,
            nano_mcm(*spendable)
        ),
        StakingRefusal::AlreadyStaked { staked } => format!(
            "this tag already stakes {}. There are no top-ups: a new stake needs the old one ended first \
             (`unstake`), which forfeits its entitlement if it is still locked",
            nano_mcm(*staked)
        ),
        StakingRefusal::EntitlementUnclaimed { entitlement } => format!(
            "this tag holds {} of unclaimed entitlement, and a stake from it is included for its fee and \
             binds nothing. Claim it first: `claim <tag> all`",
            nano_mcm(*entitlement)
        ),
        StakingRefusal::NotStaked => "this tag stakes nothing".to_string(),
        StakingRefusal::LockedNeedsForfeit { expiry, height, entitlement } => format!(
            "the stake is LOCKED until height {expiry} ({} heights from {height}, {}). Ending it now FORFEITS \
             the entitlement it has earned -- {} -- to the other stakers. Pass --forfeit to do that anyway, \
             or wait until the lock ends, when the entitlement stays yours to claim",
            expiry - height,
            about(expiry - height),
            entitlement.map_or("not reported by the node".to_string(), nano_mcm)
        ),
        StakingRefusal::ClaimWhileLocked { expiry, height } => format!(
            "the stake is locked until height {expiry} ({} heights from {height}, {}). A claim while locked \
             releases nothing: its fee is charged and its key rotates for no effect. After the lock ends a \
             claim releases the entitlement and unstakes in one transaction",
            expiry - height,
            about(expiry - height)
        ),
        StakingRefusal::NothingToClaim => "there is no entitlement to claim: the claim would be included for its \
             fee and release nothing"
            .to_string(),
        StakingRefusal::ExpiredStakeWithEntitlement { entitlement } => format!(
            "this tag's lock has ended with {} of entitlement still unclaimed; a consent from it binds \
             nothing. Claim first (`claim <tag> all`), which also unstakes",
            nano_mcm(*entitlement)
        ),
        StakingRefusal::FeeNotCovered { fee, available } => format!(
            "the fee of {fee} is more than the {} it can be paid from",
            nano_mcm(*available)
        ),
        StakingRefusal::DelegateKeyNeedsFlag { kind } => format!(
            "a consent of kind {kind} is signed by a validator DELEGATE key. Every signature made with a \
             delegate key must be recorded first in that delegate signer's durable store, \
             which this wallet cannot do; a key the signer later uses at the same position would then have \
             signed twice. Pass --unbound-delegate only if no delegate signer has ever used this key and no \
             validator slot binds it"
        ),
        StakingRefusal::BadTerms(e) => format!("{e}"),
    };
    Report::refused(format!("{who}: {why}.\n\nNothing was reserved or signed, and the key is unused."))
}

fn stake_info(p: &StakeInfoPage) -> Report {
    let mut page = format!("staking on {}\n", network_name(&p.network));
    let height = match &p.tip {
        Ok(t) => {
            page.push_str(&format!("  tip       height {}\n", t.index));
            Some(t.index.saturating_add(1))
        }
        Err(e) => {
            page.push_str(&format!("  tip       not read: {e}\n"));
            None
        }
    };
    let mut ok = p.tip.is_ok();
    if let Some((tag, read)) = &p.account {
        let who = destination(tag).unwrap_or_else(|_| format!("0x{}", hex_bytes(tag)));
        page.push_str(&format!("\naccount {who}\n"));
        match read {
            Ok(at) => {
                page.push_str(&format!(
                    "  spendable {}  -- what a send spends; staked coins and entitlement are not in it\n",
                    nano_mcm(at.spendable)
                ));
                match &at.stake {
                    None => page.push_str(
                        "  staked    not reported: the middleware returned no stake fields\n",
                    ),
                    Some(f) => {
                        page.push_str(&format!("  staked    {}\n", nano_mcm(f.staked)));
                        if let Some(e) = f.entitlement {
                            page.push_str(&format!("  entitled  {}  -- the stake's compounding reward\n", nano_mcm(e)));
                        }
                        if let Some(total) = f.total {
                            page.push_str(&format!("  total     {}\n", nano_mcm(total)));
                        }
                        if let Some(t) = f.terms {
                            match t.tier {
                                Some(k) => page.push_str(&format!(
                                    "  tier      {k}, coefficient {}x\n",
                                    t.coefficient.unwrap_or(crate::staking::coefficient(k))
                                )),
                                None => page.push_str("  tier      none matches the commit and expiry heights\n"),
                            }
                            page.push_str(&format!("  committed height {}\n  expiry    height {}", t.commit, t.expiry));
                            match height {
                                Some(h) if h < t.expiry => page.push_str(&format!(
                                    " -- LOCKED, {} heights to go, {}. Unstaking now forfeits the entitlement\n",
                                    t.expiry - h,
                                    about(t.expiry - h)
                                )),
                                Some(_) => page.push_str(
                                    " -- the lock has ENDED. The entitlement is yours: `claim <tag> all` releases \
                                     it and unstakes in one transaction\n",
                                ),
                                None => page.push_str(&format!(" -- locked by the node's own reckoning: {}\n", t.locked)),
                            }
                            if let Some(w) = t.weight {
                                page.push_str(&format!("  weight    {w}\n"));
                            }
                        }
                        page.push_str(&format!(
                            "  read at   height {} ({})\n",
                            f.block,
                            match f.source {
                                crate::mesh::codec::StakeSource::Node => "one node read: spendable and staked agree",
                                crate::mesh::codec::StakeSource::LedgerCache => {
                                    "the middleware's ledger cache, which can be a cache interval old"
                                }
                                crate::mesh::codec::StakeSource::Unavailable => "no stake source",
                            }
                        ));
                    }
                }
            }
            Err(e) => {
                ok = false;
                page.push_str(&format!(
                    "  not read: {e}. The Mesh answers account-not-found for a tag with nothing spendable and \
                     nothing staked\n"
                ));
            }
        }
        match &p.entitlement {
            Some(Ok(e)) => page.push_str(&format!("  entitled  {}  (/account/entitlement)\n", nano_mcm(e.amount))),
            Some(Err(e)) => page.push_str(&format!("  entitled  not read: {e}\n")),
            None => {}
        }
    }
    page.push_str("\nnetwork\n");
    if let Some(h) = height {
        page.push_str(&format!(
            "  minimum   {} for a stake in the next block, height {h}\n",
            nano_mcm(crate::staking::minstake(h, p.network.t41))
        ));
        match crate::staking::minstake_next_step(h, p.network.t41) {
            Some(at) => page.push_str(&format!(
                "  schedule  it falls by 10 MCM every 65,536 heights to a floor of 10 MCM; next to {} at height \
                 {at}, {}\n",
                nano_mcm(crate::staking::minstake(at, p.network.t41)),
                about(at.saturating_sub(h))
            )),
            None => page.push_str("  schedule  at its floor of 10 MCM\n"),
        }
    }
    page.push_str("  tiers     k = 0..5 locks 65,536 x 2^k heights to the next neogenesis, coefficient k + 1\n");
    match &p.stats {
        Ok(s) => {
            page.push_str(&format!(
                "  v4.1      {} at the middleware's tip, height {}{}\n",
                if s.active { "active" } else { "NOT active" },
                s.tip.index,
                s.trigger.map_or(String::new(), |t| format!("; trigger {t}"))
            ));
            page.push_str(&format!("  min_stake {} (the middleware's figure)\n", nano_mcm(s.min_stake)));
            match &s.ledger {
                Some(l) => page.push_str(&format!(
                    "  staked    {} by {} staker(s), weight {}, at height {}\n",
                    nano_mcm(l.staked),
                    l.stakers,
                    l.weight,
                    l.block
                )),
                None => page.push_str("  staked    the middleware has no ledger cache to total\n"),
            }
            match &s.stake_set {
                Some(ss) => page.push_str(&format!(
                    "  pool      {} to {} staker(s) in block {} (forfeits {}, dust {}, weight {})\n",
                    nano_mcm(ss.pool),
                    ss.count,
                    ss.block.index,
                    nano_mcm(ss.forfeit),
                    nano_mcm(ss.dust),
                    ss.weight
                )),
                None => page.push_str("  pool      no STAKE_SET seen yet\n"),
            }
        }
        Err(crate::Error::HttpStatus { status }) => page.push_str(&format!(
            "  /stats/staking refused with HTTP {status}: the public endpoint's firewall blocks it. The \
             totals and the last pool are not shown; everything above is unaffected\n"
        )),
        Err(e) => page.push_str(&format!("  /stats/staking not read: {e}\n")),
    }
    page.push_str("\nRead only: nothing was signed, reserved or written.");
    if ok {
        Report::ok(page)
    } else {
        Report::refused(page)
    }
}

const SUBMIT_NOTHING: &str =
    "Nothing was written to the socket, nothing to disk, and no store was opened.";

fn submitted_page(
    source: &crate::addr::Tag,
    bytes: &[u8],
    submitted: &core::result::Result<crate::mesh::TxId, crate::Error>,
) -> Report {
    let settle_arg = match destination(source) {
        Ok(d) => d,
        Err(e) => return cannot_render(source, &e),
    };
    let mut page = format!(
        "submitting {} bytes ({} hex characters) from {settle_arg}\n\nNo store was opened and no \
         password asked: the artifact is the input, and this command's one job is to reach the \
         socket. It reserves nothing, signs nothing and writes nothing to disk. The bytes were \
         checked for layout only -- this program has no transaction validator -- so a signature \
         that does not recover, a passed block-to-live or a balance the ledger no longer holds is \
         refused by the node, silently.\n",
        bytes.len(),
        bytes.len() * 2
    );
    match submitted {
        Ok(id) => {
            page.push_str(&super::submitted_block(id, &settle_arg));
            Report::ok(page)
        }
        Err(e) => {
            page.push_str(&format!(
                "\nsubmission FAILED: {e}\nThe artifact is unchanged and still yours. Whether the \
                 bytes reached a node before the failure is not knowable here; `settle {settle_arg}` \
                 answers it once the chain has moved, and this command can be run again."
            ));
            Report::refused(page)
        }
    }
}

fn status_page(tag: &crate::addr::Tag, s: &AccountStatus) -> Report {
    let dest = match destination(tag) {
        Ok(d) => d,
        Err(e) => return cannot_render(tag, &e),
    };
    // Lines after the state line: the ledger address when in sync, or the
    // reservation details when a spend is outstanding.
    let tail = match s {
        AccountStatus::InSync { address, .. } => format!("\n  address  {}", hex_bytes(address)),
        AccountStatus::SpendOutstanding {
            spent_index,
            reservation,
            ..
        } => {
            let lines = reservation_lines(*spent_index, reservation, "  ");
            format!("\n{}", lines.trim_end_matches('\n'))
        }
        AccountStatus::SpendLanded { .. } => String::new(),
    };
    Report::ok(format!(
        "{dest}\n  balance  {} nanoMCM\n  index    {}\n  state    {}{tail}",
        s.balance(),
        s.index().get(),
        state_of(s),
    ))
}

fn reconciled(
    tag: &crate::addr::Tag,
    to: u32,
    reviewed: &super::reconcile::Reviewed,
    upgraded: Upgraded,
) -> Report {
    use super::reconcile::Outcome as Reconcile;
    let report = if reviewed.reports.is_empty() {
        String::new()
    } else {
        let mut r = format!(
            "THE STORE BEFORE THIS DECISION: {} of {} account(s) diverged.\n\n",
            reviewed.reports.len(),
            reviewed.accounts
        );
        for d in &reviewed.reports {
            r.push_str(&format!("{d}\n\n"));
        }
        r
    };
    let others = reviewed.reports.iter().filter(|d| d.tag() != *tag).count();
    let still = if others > 0 {
        format!(
            "\n{others} other account(s) in the report above are still diverged; every \
             operation on each of them is refused until it is reconciled, and `balance` \
             reports them on every run."
        )
    } else {
        String::new()
    };
    match &reviewed.outcome {
        Reconcile::NotHeld => Report::refused(no_such_account(tag)),
        Reconcile::NothingToReconcile(_) => Report::refused(format!(
            "{report}account 0x{}: not diverged; there is nothing to reconcile.{still}",
            hex_bytes(tag)
        )),
        Reconcile::NoAdvance { target: None } => Report::refused(format!(
            "{report}This divergence has no advance to acknowledge. Advancing is only correct \
             when the chain is AHEAD of the local index, at an index the walk confirmed; the \
             report above says what the walk found, and for this account it walked indices 0 \
             through {to} as well as the window. Nothing was written.{still}"
        )),
        Reconcile::NoAdvance { target: Some(t) } => Report::refused(format!(
            "{report}--advance-to {to} does not match the index this divergence reports \
             ({t}). Type the number in the report above. Nothing was written.{still}"
        )),
        Reconcile::NoRollback { target: None } => Report::refused(format!(
            "{report}This divergence has no rollback to acknowledge. Rolling back is only for an \
             account the chain shows BEHIND the local index, at an index the walk confirmed; the \
             report above says what the walk found, and for this account it walked indices 0 \
             through {to} as well as the window. Nothing was written.{still}"
        )),
        Reconcile::NoRollback { target: Some(t) } => Report::refused(format!(
            "{report}--rollback-to {to} does not match the index this divergence reports \
             ({t}). Nothing was written.{still}"
        )),
        Reconcile::RolledBack { index } => Report::ok(format!(
            "{report}rolled account 0x{} back to index {index}. Index {index} was derived and its \
             address compared to the one the chain holds before anything was written. The key at \
             index {index} has signed before, and the next spend from this account signs with it \
             again.{still}{}",
            hex_bytes(tag),
            upgrade(upgraded)
        )),
        Reconcile::Advanced { index } => Report::ok(format!(
            "{report}advanced account 0x{} to index {index} after operator review. Index {index} \
             was derived and its address compared to the one the chain holds before anything was \
             written; the report above is what was acknowledged. The key at every skipped \
             position is now unreachable by this wallet, which is the point: they may already \
             have signed.{still}{}",
            hex_bytes(tag),
            upgrade(upgraded)
        )),
    }
}

fn discovered(sweep: &super::discover::Sweep) -> Report {
    let to = sweep.to;
    let mut rows = String::new();
    let mut unresolved: Vec<u32> = Vec::new();
    for s in &sweep.sightings {
        // Every resolved index and every held index gets its own row. A held
        // account the node does not resolve (the emptied-account window) is
        // still shown.
        if s.entry.is_none() && s.held.is_none() {
            unresolved.push(s.account);
            continue;
        }
        let dest = match destination(&s.tag) {
            Ok(d) => d,
            Err(e) => return cannot_render(&s.tag, &e),
        };
        let balance = match &s.entry {
            Some(e) => super::nano_and_mcm(i128::from(e.balance)),
            None => "not resolved by the node".to_string(),
        };
        let held = match s.held {
            None => String::new(),
            Some((kind, index)) => format!(
                "  IN THIS STORE ({}, at key index {})",
                match kind {
                    crate::account::AccountKind::Derived => "derived",
                    crate::account::AccountKind::Imported => "imported",
                    crate::account::AccountKind::Sdk => "sdk",
                },
                index.get()
            ),
        };
        rows.push_str(&format!(
            "  {:>5}  {dest:<width$}  {balance}{held}\n",
            s.account,
            width = crate::addr::TAG_BASE58_MAX_CHARS
        ));
    }

    let mut out = format!(
        "searched account indices 0..={to} from this store's master seed -- {} index(es), one \
         node call each. The node resolved {} of them.\n\n{rows}",
        u64::from(to) + 1,
        sweep.resolved()
    );
    if !unresolved.is_empty() {
        out.push_str(&format!(
            "  the node did not resolve {} index(es):{}\n",
            unresolved.len(),
            super::wrapped_indices(&unresolved)
        ));
    }
    out.push_str(&format!(
        "\n`did not resolve` is what was OBSERVED, and this page does NOT say those accounts do \
         not exist -- it cannot. The node answers `account not found` for a tag the ledger has no \
         entry for, for a tag it holds at ZERO balance, and for a lookup that failed, and it does \
         not tell the three apart; never funded, a node serving another chain, and a seed that is \
         not the one that made the account all produce the first of them. What is reported per \
         index is the node's answer and nothing beyond it.\n\n\
         The extent is 0..={to} because that is what was asked for: `discover --to N` searches \
         0..=N for any N from 1 to {}, and the number searched is on the first line so it can be \
         raised when it is too small. An index the node resolved is added to this store by \
         `restore --account N`. An index you expected to see and do not is a reason to check the \
         node and the seed, not a verdict.\n\n\
         Nothing was written: no account was added, nothing reserved, nothing signed, and the \
         store is unchanged.",
        super::args::DISCOVER_MAX_TO
    ));
    Report::ok(out)
}

fn transaction(page: &crate::mesh::codec::SearchPage) -> Report {
    let Some(tx) = page.transactions.first() else {
        // Unreachable from `decide`, which maps an empty page to
        // `TransactionNotFound`; handled rather than panicking.
        return Report::refused("no transaction in this page.".into());
    };
    let mut out = format!("transaction {}\n", hex_bytes(&tx.hash));
    if let Some(b) = tx.block {
        out.push_str(&format!("  in block {} ({})\n", b.index, hex_bytes(&b.hash)));
    }
    if let Some(ms) = tx.timestamp_ms {
        out.push_str(&format!("  at       {}\n", super::stamp(ms)));
    }
    out.push_str(&format!("  {} operation(s)\n", tx.operations.len()));
    out.push_str(&super::operation_lines(&tx.operations, "    "));
    if !tx.metadata.is_empty() {
        out.push_str("  metadata, in the endpoint's own spelling:\n");
        out.push_str(&super::metadata_lines(&tx.metadata, "    "));
    }
    out.push_str(&format!("\n{}\n", super::SEARCH_CONVENTION));
    Report::ok(out)
}

fn recent_transactions(
    tag: &crate::addr::Tag,
    from: u64,
    page: &crate::mesh::codec::SearchPage,
) -> Report {
    use crate::mesh::codec;
    let shown = match destination(tag) {
        Ok(d) => d,
        Err(e) => return cannot_render(tag, &e),
    };
    let rows = page.transactions.len() as u64;
    let mut out = if from == 0 {
        format!(
            "recent transactions for {shown}\n  {} of {} row(s), newest first\n",
            rows, page.total_count
        )
    } else if rows == 0 {
        format!(
            "recent transactions for {shown}\n  0 of {} row(s) after the {from} newest\n",
            page.total_count
        )
    } else {
        format!(
            "recent transactions for {shown}\n  rows {} to {} of {}, newest first: the {from} newest \
             are skipped\n",
            from.saturating_add(1),
            from.saturating_add(rows),
            page.total_count
        )
    };
    if page.transactions.is_empty() && from == 0 {
        out.push_str(
            "  (none: this node's index holds no transaction for this tag. A tag never paid has \
             none.)\n",
        );
    } else if page.transactions.is_empty() {
        out.push_str(&format!(
            "  (none after the {from} newest: this node's index holds {} for this tag.)\n",
            page.total_count
        ));
    }
    for tx in &page.transactions {
        let touched: i128 = tx
            .operations
            .iter()
            .filter(|o| o.address.strip_prefix("0x").unwrap_or(&o.address) == hex_bytes(tag))
            .map(|o| o.amount)
            .sum();
        let out_ops = tx.operations.iter().any(|o| {
            o.kind == codec::OP_SOURCE && o.address.strip_prefix("0x").unwrap_or(&o.address) == hex_bytes(tag)
        });
        let in_ops = tx.operations.iter().any(|o| {
            o.kind == codec::OP_DESTINATION && o.address.strip_prefix("0x").unwrap_or(&o.address) == hex_bytes(tag)
        });
        let direction = match (out_ops, in_ops) {
            (true, true) => "both",
            (true, false) => "out",
            (false, true) => "in",
            (false, false) => "--",
        };
        let memo = tx
            .operations
            .iter()
            .find(|o| !o.memo.is_empty())
            .map(|o| super::terminal_text(&o.memo))
            .unwrap_or_default();
        out.push_str(&format!(
            "  block {:>9}  {}  {:<4}  {}\n",
            tx.block.map_or(0, |b| b.index),
            hex_bytes(&tx.hash),
            direction,
            super::nano_and_mcm(touched)
        ));
        if !memo.is_empty() {
            out.push_str(&format!("                    memo {memo}\n"));
        }
    }
    if let Some(n) = page.next_offset {
        out.push_str(&format!(
            "  more rows exist; the endpoint's next offset is {n}, and `--from {n}` reads them\n"
        ));
    }
    out.push_str(&format!("\n{}\n", super::SEARCH_CONVENTION));
    Report::ok(out)
}

fn block_page(block: &crate::mesh::codec::MeshBlock) -> Report {
    use crate::mesh::codec;
    // The reward transaction is the one carrying a REWARD operation.
    let (rewards, spends): (Vec<_>, Vec<_>) = block
        .transactions
        .iter()
        .partition(|t| t.operations.iter().any(|o| o.kind == codec::OP_REWARD));
    let moved: i128 = spends
        .iter()
        .flat_map(|t| t.operations.iter())
        .filter(|o| o.kind == codec::OP_DESTINATION)
        .map(|o| o.amount)
        .sum();
    let fees: i128 = block
        .transactions
        .iter()
        .flat_map(|t| t.operations.iter())
        .filter(|o| o.kind == codec::OP_FEE)
        .map(|o| o.amount)
        .sum();

    let mut out = format!(
        "block {}\n  hash     {}\n  parent   {} ({})\n  at       {}\n",
        block.block.index,
        hex_bytes(&block.block.hash),
        block.parent.index,
        hex_bytes(&block.parent.hash),
        super::stamp(block.timestamp_ms)
    );
    out.push_str(&block_figures(block));
    match rewards.first().and_then(|t| t.operations.iter().find(|o| o.kind == codec::OP_REWARD)) {
        Some(r) => {
            out.push_str(&format!("  reward   {}\n    to     {}\n", super::nano_and_mcm(r.amount), super::explorer_address(&r.address)));
        }
        None => out.push_str("  reward   none in this block\n"),
    }
    out.push_str(&format!(
        "  spends   {}\n  moved    {}  (every destination of every non-reward transaction; the \
         reward is newly minted, not moved, and is not counted)\n  fees     {}\n",
        spends.len(),
        super::nano_and_mcm(moved),
        super::nano_and_mcm(fees)
    ));
    for t in &spends {
        let dests = t.operations.iter().filter(|o| o.kind == codec::OP_DESTINATION).count();
        let total: i128 = t
            .operations
            .iter()
            .filter(|o| o.kind == codec::OP_DESTINATION)
            .map(|o| o.amount)
            .sum();
        out.push_str(&format!(
            "    {}  {} destination(s)  {}\n",
            hex_bytes(&t.hash),
            dests,
            super::nano_and_mcm(total)
        ));
    }
    out.push_str(&format!("\n{}\n", super::BLOCK_CONVENTION));
    Report::ok(out)
}

/// The note printed on every mempool page.
const MEMPOOL_CONVENTION: &str = "read from /mempool and /mempool/transaction, which render a waiting \
     transaction as /block renders one: the source debited its NET amount and the change not an \
     operation. The queue is the node's own; another node's may differ.";

fn mempool(count: u64, total: usize, rows: &[super::outcome::MempoolRow]) -> Report {
    use crate::mesh::codec;
    let mut out = format!(
        "the mempool: {total} transaction(s) waiting to be mined; the first {} read\n",
        rows.len()
    );
    if total == 0 {
        out.push_str("  (none: this node's queue is empty.)\n");
    }
    for row in rows {
        match &row.transaction {
            Some(t) => {
                let sent: i128 = t
                    .operations
                    .iter()
                    .filter(|o| o.kind == codec::OP_DESTINATION)
                    .map(|o| o.amount)
                    .sum();
                let destinations = t.operations.iter().filter(|o| o.kind == codec::OP_DESTINATION).count();
                out.push_str(&format!(
                    "  {}  {} destination(s)  {}\n",
                    hex_bytes(&row.id),
                    destinations,
                    super::nano_and_mcm(sent)
                ));
                out.push_str(&super::operation_lines(&t.operations, "    "));
            }
            None => out.push_str(&format!(
                "  {}  left the queue before it was read: mined since the list was read, or dropped\n",
                hex_bytes(&row.id)
            )),
        }
    }
    if total > rows.len() {
        out.push_str(&format!(
            "  {} more waiting, not read: this page reads the first {count}, and --count reads up to \
             {}\n",
            total - rows.len(),
            super::args::MAX_COUNT
        ));
    }
    out.push_str(&format!("\n{MEMPOOL_CONVENTION}\n"));
    Report::ok(out)
}

fn blocks(count: u64, tip: &crate::mesh::ChainTip, rows: &[crate::mesh::codec::MeshBlock]) -> Report {
    let mut out = format!("the {count} newest block(s); the tip is {}\n", tip.index);
    for b in rows {
        out.push_str(&format!(
            "  {:>9}  {}  {}  {} transaction(s)  {}\n",
            b.block.index,
            hex_bytes(&b.block.hash),
            super::stamp(b.timestamp_ms),
            b.transactions.len(),
            kind_word(b.kind())
        ));
    }
    Report::ok(out)
}

/// A block's kind as printed, or "kind not sent" if the node did not say.
fn kind_word(kind: Option<crate::mesh::codec::BlockKind>) -> &'static str {
    use crate::mesh::codec::BlockKind;
    match kind {
        Some(BlockKind::Normal) => "normal",
        Some(BlockKind::Pseudo) => "pseudo",
        Some(BlockKind::Neogenesis) => "neogenesis",
        None => "kind not sent",
    }
}

/// The `block` page's metadata lines: kind, difficulty, nonce, Merkle root,
/// size, transaction count, minimum fee and, for a normal block, the haiku
/// joined onto one line. Without metadata, a single line says so.
fn block_figures(block: &crate::mesh::codec::MeshBlock) -> String {
    use crate::mesh::codec::BlockKind;
    let kind = block.kind();
    let Some(m) = &block.metadata else {
        return format!(
            "  type     {}; this node sent no block metadata\n",
            kind_word(kind)
        );
    };
    let what = match kind {
        Some(BlockKind::Pseudo) => "pseudo: no transactions, and no proof of work is checked for it",
        Some(BlockKind::Neogenesis) => "neogenesis: it carries the ledger, at every 256th block",
        _ => "normal",
    };
    let mut out = format!(
        "  type     {what}\n  work     difficulty {}, nonce {}\n  root     {}\n  size     {} bytes, {} transaction(s) besides the reward, minimum fee {}\n",
        m.difficulty,
        hex_bytes(&m.nonce),
        hex_bytes(&m.root),
        m.block_size,
        m.tx_count,
        super::nano_and_mcm(i128::from(m.fee))
    );
    if kind == Some(BlockKind::Normal) {
        let lines: Vec<String> = m
            .haiku
            .split('\n')
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(super::terminal_text)
            .collect();
        if !lines.is_empty() {
            out.push_str(&format!("  haiku    {}\n", lines.join(" / ")));
        }
    }
    out
}
