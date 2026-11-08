// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

#![cfg(all(feature = "native", not(miri)))]
//! CLI tests: every command driven against the scriptable chain, every
//! refusal rendered and read back, and every exit code asserted.
//!
//! Requires `native` (keystore and derivation) and is skipped under Miri
//! (WOTS+ cost and filesystem access). These paths are safe Rust over
//! primitives and the `codec` that other suites run under Miri.
//!
//! # Assertions read the output
//!
//! The CLI's product is its text, so the three notices -- a submission is not
//! a verdict, `tx_val` never ran, the artifact can be lost -- are asserted
//! against captured output rather than against the source that produces it.

#[path = "support/keystore_harness.rs"]
mod keystore_harness;
#[path = "support/chain.rs"]
mod chain;
#[path = "support/extension_export.rs"]
mod extension_export;

use chain::{addr_at, hexs, master, Chain, ChainState, TAG};
use keystore_harness::{reopen, ScratchDir};
use mochimo_crypto::account::Account;
use mochimo_crypto::cli::args::{self, Command, Spend, SpendTo};
use mochimo_crypto::cli::{self, Code};
use mochimo_crypto::consts::{ADDR_REF_LEN, ADDR_TAG_LEN, MFEE};
use mochimo_crypto::keystore::{Figures, KeyAccess, Keystore};
use mochimo_crypto::mesh::MeshClient;
use mochimo_crypto::tx::wire::Destination;
use mochimo_crypto::wallet::Wallet;

const TO: [u8; ADDR_TAG_LEN] = [0x6b; ADDR_TAG_LEN];

/// A store holding `F-address-widths`' derived account 0, at position 0.
fn store(name: &str) -> (ScratchDir, Keystore) {
    let dir = ScratchDir::new(name);
    let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    // The store holds its own master seed, which `cli::run` reads. Without
    // it `Wallet::open` refuses the derived account with
    // `NoMasterForDerivedAccount`.
    let _durable = ks.adopt_master(&master()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(Account::derive(&master(), 0))
        .unwrap_or_else(|e| panic!("{e}"));
    (dir, ks)
}

fn spend() -> Spend {
    Spend {
        tag: TAG,
        dsts: vec![SpendTo { to: TO, reference: [0; ADDR_REF_LEN], amount: Some(1_000) }],
        fee_total: MFEE,
        blk_to_live: 0,
        expect_balance: None,
    }
}

/// [`spend`] carrying a destination reference, laid out as `--ref <text>`
/// lays it out: the ASCII bytes, NUL-padded to the field.
fn spend_with_reference(text: &str) -> Spend {
    assert!(text.is_ascii() && text.len() <= ADDR_REF_LEN, "{text:?} is not a reference this helper lays out");
    let mut s = spend();
    s.dsts[0].reference[..text.len()].copy_from_slice(text.as_bytes());
    s
}

/// The bytes of a hex string, for reading a wire image back.
fn bytes_of(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap_or_else(|e| panic!("{e}")))
        .collect()
}

/// Run one command over a fresh store and a scripted chain.
fn run_on(name: &str, chain: Chain, cmd: &Command) -> cli::Report {
    let (_dir, ks) = store(name);
    cli::run(ks, MeshClient::new(chain), cmd)
}

/// [`run_on`], keeping the directory so the store can be reopened and read
/// afterwards.
fn run_on_keeping(name: &str, chain: Chain, cmd: &Command) -> (ScratchDir, cli::Report) {
    let (dir, ks) = store(name);
    let r = cli::run(ks, MeshClient::new(chain), cmd);
    (dir, r)
}

/// The stored index of `TAG`, read back from disk.
fn stored_index(dir: &ScratchDir) -> u32 {
    let ks = reopen("stored index", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    ks.view(&TAG)
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("the store no longer holds the account"))
        .wots_index
        .get()
}

/// Sign the same spend through the wallet API on a throwaway store, to learn
/// the transaction id the CLI's run will produce.
///
/// The id comes from `SignedTransaction::id()`. `MeshClient::submit`
/// compares its own id against the echo, so a divergence fails the CLI's
/// `send`.
fn id_for_the_spend(name: &str) -> [u8; 32] {
    id_for(name, &spend())
}

/// [`id_for_the_spend`] over any `Spend`. The block-to-live is part of the
/// digest, so a chain scripted to accept a spend needs that spend's own id.
fn id_for(name: &str, s: &Spend) -> [u8; 32] {
    let (_dir, ks) = store(name);
    let m = master();
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    if s.blk_to_live != 0 {
        chain.set_tip(s.blk_to_live - 1);
    }
    let mut w = Wallet::open(ks, MeshClient::new(chain), Some(&m)).unwrap_or_else(|e| panic!("{e}"));
    let plan = w
        .plan(
            &TAG,
            &KeyAccess::Master(&m),
            // Every destination: the id covers all of them. `None` is the
            // `all` keyword, resolved against this chain's 5,000,000.
            s.dsts
                .iter()
                .map(|d| Destination {
                    tag: d.to,
                    reference: d.reference,
                    amount: d.amount.unwrap_or(5_000_000 - s.fee_total),
                })
                .collect(),
            s.fee_total,
            s.blk_to_live,
        )
        .unwrap_or_else(|e| panic!("{e}"));
    let signed = w
        .reserve_and_sign(&plan, KeyAccess::Master(&m))
        .unwrap_or_else(|e| panic!("{e}"));
    signed.id().0
}

/// A tag in the machine form the parser requires: `0x` and forty hex
/// characters. Bare hex is refused so that no forty-character substring of
/// the program's output can be taken as a destination.
fn prefixed(tag: &[u8]) -> String {
    format!("0x{}", hexs(tag))
}

/// The two password reads `create` makes (`read_new_password` reads twice
/// and requires them to agree), followed by `rest`.
fn password_then(rest: Vec<String>) -> Vec<String> {
    let pw = keystore_harness::TEST_PASSWORD_STR.to_string();
    let mut v = vec![pw.clone(), pw];
    v.extend(rest);
    v
}

/// `create`'s three entropy draws, fixed. The salt and nonce seed come from
/// the harness, so a store built here is byte-identical to one built by
/// `keystore_harness::create` with the same contents.
fn test_create_entropy() -> create_cmd::CreateEntropy {
    create_cmd::CreateEntropy {
        phrase: ENTROPY,
        salt: keystore_harness::TEST_SALT,
        nonce_seed: keystore_harness::TEST_NONCE_SEED,
    }
}

fn assert_says(report: &cli::Report, needle: &str, what: &str) {
    assert!(
        report.text.contains(needle),
        "{what}: the rendered output does not contain {needle:?}.\n--- output ---\n{}",
        report.text
    );
}

// ---------------------------------------------------------------------------
// The open path: every command reconciles first, or the wallet does not exist
// ---------------------------------------------------------------------------

/// Chain state: in sync at position 0. The wallet opens and `balance` reports.
#[test]
fn balance_reports_every_account_after_reconciliation() {
    let r = run_on(
        "cli-balance",
        Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]),
        &Command::Balance,
    );
    assert_eq!(r.code, Code::Ok, "an in-sync store did not open: {}", r.text);
    // A destination, not a hex tag: the line an operator copies.
    let dest = mochimo_crypto::addr::tag_to_base58(&TAG).unwrap_or_else(|e| panic!("{e}"));
    assert_says(&r, &dest, "balance");
    // This page prints one spelling only. Startup refusals still render tags
    // in hex (`recon::hex20`), pinned by
    // `a_divergence_refuses_startup_with_code_2_and_names_what_diverged`.
    assert!(
        !r.text.contains(&hexs(&TAG)),
        "balance prints the hex tag beside the destination; two spellings of one identifier on \
         one line is the transcription hazard the destination form removed:\n{}",
        r.text
    );
    assert_says(&r, "5000000", "balance");
    assert_says(&r, "in sync", "balance");
}

/// Chain state: the chain is at position 2 and the store at 0 — local behind.
/// Exit code 2, with the I4 divergence report.
#[test]
fn a_divergence_refuses_startup_with_code_2_and_names_what_diverged() {
    let r = run_on(
        "cli-diverged",
        Chain::new(&[(TAG, ChainState::At(addr_at(2), 5_000_000))]),
        &Command::Balance,
    );
    assert_eq!(
        r.code,
        Code::StartupRefused,
        "a divergence did not refuse startup: {}",
        r.text
    );
    assert_ne!(r.code, Code::Ok, "a refusal exited 0");
    // I4's message-quality clause: what diverged, both indices, the gap, the action.
    assert_says(&r, "ACTION", "the startup refusal");
    assert_says(&r, &hexs(&TAG), "the startup refusal");
}

/// Chain state: unreachable. Restore fails closed rather than assuming zero,
/// and a wallet cannot open either.
#[test]
fn an_unreachable_chain_refuses_rather_than_assuming() {
    let r = run_on(
        "cli-unreachable",
        Chain::new(&[(TAG, ChainState::Unreachable)]),
        &Command::Balance,
    );
    assert_eq!(r.code, Code::StartupRefused, "output: {}", r.text);
}

// ---------------------------------------------------------------------------
// Reading commands
// ---------------------------------------------------------------------------

/// `address` answers with a transport that refuses every request, on a store
/// whose tag the chain has never held: the state before the first payment.
#[test]
fn address_answers_before_the_tag_is_funded_and_asks_no_node() {
    let (_dir, ks) = store("cli-address-unfunded");
    // Absent from the ledger, and the fake counts every request it is given.
    let chain = Chain::new(&[(TAG, ChainState::Unreachable)]);
    let r = cli::run(ks, MeshClient::new(chain), &Command::Address { tag: Some(TAG), account: None },
    );
    assert_eq!(
        r.code,
        Code::Ok,
        "address refused on an unfunded tag -- the deadlock is back: {}",
        r.text
    );
    assert_says(&r, &hexs(&addr_at(0)), "address");
    // The first line is the bare destination; the ledger address follows,
    // indented.
    let dest = mochimo_crypto::addr::tag_to_base58(&TAG).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        r.text.lines().next(),
        Some(dest.as_str()),
        "the first line is not the bare destination:\n{}",
        r.text
    );
    assert_says(&r, "DESTINATION", "address");
    assert_says(&r, "It is not a destination: no wallet takes it, and neither does this one", "address");
}

/// A transport that counts, through a handle the test keeps after the client
/// is moved into `cli::run`.
///
/// `cli::run` consumes the client, so the count lives behind an `Rc` the
/// test keeps.
struct Counting {
    inner: Chain,
    calls: std::rc::Rc<std::cell::Cell<usize>>,
}

impl mochimo_crypto::mesh::Transport for Counting {
    fn post(&self, path: &str, body: &[u8]) -> mochimo_crypto::Result<Vec<u8>> {
        self.calls.set(self.calls.get() + 1);
        self.inner.post(path, body)
    }
}

/// `address` makes no request: the counter is zero after both forms of the
/// command, and a control shows the counter works.
#[test]
fn address_makes_no_request_at_all() {
    let mut shapes = 0usize;
    for tag in [Some(TAG), None] {
        let (_dir, ks) = store("cli-address-nonet");
        let calls = std::rc::Rc::new(std::cell::Cell::new(0usize));
        let client = MeshClient::new(Counting {
            inner: Chain::new(&[]),
            calls: std::rc::Rc::clone(&calls),
        });
        let r = cli::run(ks, client, &Command::Address { tag, account: None });
        assert_eq!(r.code, Code::Ok, "{}", r.text);
        assert_eq!(calls.get(), 0, "address (tag {:?}) sent {} request(s) to the node", tag.map(|_| "given"), calls.get());
        shapes += 1;
    }
    assert_eq!(shapes, 2);
    // Control: a command that does make requests is counted.
    let (_dir, ks) = store("cli-address-nonet-control");
    let calls = std::rc::Rc::new(std::cell::Cell::new(0usize));
    let client = MeshClient::new(Counting {
        inner: Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]),
        calls: std::rc::Rc::clone(&calls),
    });
    let r = cli::run(ks, client, &Command::Balance);
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    assert!(calls.get() > 0, "balance made no request, so the counter is not counting");
    println!("address requests: 0 across 2 shape(s); balance made {} as the control", calls.get());
}

/// `address --account N` end to end. On a store holding account 0,
/// `address --account 1` prints a destination and says the account is not
/// stored, writing nothing and making no request. The chain is then funded at
/// that destination's position-0 address, `restore --account 1` adds the
/// account at position 0, and the stored tag is the one the printed
/// destination decodes to.
#[test]
fn address_account_derives_a_destination_without_storing_and_restore_then_adds_it() {
    let (dir, ks) = store("cli-address-account");
    let before = dir.snapshot_bytes();
    let calls = std::rc::Rc::new(std::cell::Cell::new(0usize));
    let client = MeshClient::new(Counting {
        inner: Chain::new(&[]),
        calls: std::rc::Rc::clone(&calls),
    });
    let r = cli::run(ks, client, &Command::Address { tag: None, account: Some(1) });
    assert_eq!(r.code, Code::Ok, "address --account 1 was refused:\n{}", r.text);
    assert_eq!(calls.get(), 0, "address --account made {} request(s)", calls.get());
    assert_eq!(dir.snapshot_bytes(), before, "address --account WROTE to the store");
    assert_says(&r, "NOT STORED", "address --account");
    assert_says(&r, "nothing was written, nothing reserved, no node asked", "address --account");
    assert_says(&r, "restore --account 1", "address --account");
    assert_says(&r, "\n  index    0\n", "address --account");
    let dest = r.text.lines().next().unwrap_or_default().to_owned();
    let printed_tag = mochimo_crypto::addr::tag_from_base58(&dest).unwrap_or_else(|e| panic!("line one is not a destination: {e}"));
    assert_eq!(printed_tag, chain::tag1(), "the printed destination is not account 1's tag");
    let printed_address = r
        .text
        .lines()
        .find_map(|l| l.strip_prefix("  address  "))
        .unwrap_or_else(|| panic!("no address line:\n{}", r.text))
        .to_owned();
    let expected = mochimo_crypto::recon::derived_address_at(&master(), 1, mochimo_crypto::account::WotsIndex::ZERO);
    assert_eq!(printed_address, hexs(&expected), "the printed address is not account 1's position-0 address");

    // Fund that destination, then restore: the same tag is added at
    // position 0.
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    let funded_tag = chain
        .credit_destination(&dest, expected, 7_000)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(funded_tag, printed_tag);
    let ks = reopen("address account restore", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let r2 = cli::run(ks, MeshClient::new(chain), &Command::Restore { account: 1, scan_to: None });
    assert_eq!(r2.code, Code::Ok, "restore --account 1 after funding was refused:\n{}", r2.text);
    assert_says(&r2, "index    0", "restore");
    assert_says(&r2, "added to the store", "restore");
    assert_says(&r2, &dest, "restore");
    let after = reopen("address account after", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let held = after.view(&printed_tag).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("the restored account is not in the store"));
    assert_eq!(held.wots_index.get(), 0);
    assert_eq!(held.tag, printed_tag, "the restored tag differs from the printed one");
    // And now `address <tag>` answers for it, with the same address.
    let r3 = cli::run(after, MeshClient::new(Chain::new(&[])), &Command::Address { tag: Some(printed_tag), account: None });
    assert_eq!(r3.code, Code::Ok, "{}", r3.text);
    assert_says(&r3, &format!("  address  {}", hexs(&expected)), "address <tag> after the restore");
    println!(
        "  address --account 1: destination {dest}, tag 0x{}; funded at position 0; restore --account 1 added it at index 0 under the same tag; snapshot bytes identical across the derive",
        hexs(&printed_tag)
    );
}

/// The two refusals of `address --account N`: a store holding no master
/// derives nothing (imported accounts only), and an account the store
/// already holds is answered by `address <destination>`, not by position
/// 0's address, which the chain may no longer hold. Both write nothing.
#[test]
fn address_account_refuses_a_masterless_store_and_an_account_already_held() {
    let dir = ScratchDir::new("cli-address-account-nomaster");
    let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(keystore_harness::imported_account()).unwrap_or_else(|e| panic!("{e}"));
    let before = dir.snapshot_bytes();
    let r = cli::run(ks, MeshClient::new(Chain::new(&[])), &Command::Address { tag: None, account: Some(1) });
    assert_eq!(r.code, Code::Refused, "a masterless store derived an account:\n{}", r.text);
    assert_says(&r, "no master seed", "address --account on an imported-only store");
    assert_says(&r, "Nothing was written", "address --account refusal");
    assert_eq!(dir.snapshot_bytes(), before, "the refusal wrote");

    let (dir2, ks2) = store("cli-address-account-held");
    let before2 = dir2.snapshot_bytes();
    let dest = mochimo_crypto::addr::tag_to_base58(&TAG).unwrap_or_else(|e| panic!("{e}"));
    let r2 = cli::run(ks2, MeshClient::new(Chain::new(&[])), &Command::Address { tag: None, account: Some(0) });
    assert_eq!(r2.code, Code::Refused, "an account the store holds was answered at position 0:\n{}", r2.text);
    assert_says(&r2, "already in this store", "address --account on a held account");
    assert_says(&r2, &format!("run `address {dest}`"), "address --account on a held account");
    assert_eq!(dir2.snapshot_bytes(), before2, "the refusal wrote");
    println!("  address --account refusals: no master (imported-only) and an account already held, both without a write");
}

// ---------------------------------------------------------------------------
// discover: a read-only sweep that never asserts absence
// ---------------------------------------------------------------------------

/// `discover` reports the node's answer per index and the extent searched,
/// and writes nothing.
///
/// The store holds account 0; the chain resolves accounts 0 and 2 and
/// answers code 4 for the rest. The page carries the extent, a row per
/// resolved index, the held marker on account 0 and the unresolved indices,
/// and never claims an account does not exist.
#[test]
fn discover_reports_every_index_the_node_answered_for_and_writes_nothing() {
    let (dir, ks) = store("cli-discover");
    let before = dir.snapshot_bytes();
    let m = master();
    let tag2 = mochimo_crypto::derive::derive_account_tag(&m, 2);
    let addr2 = mochimo_crypto::recon::derived_address_at(&m, 2, mochimo_crypto::account::WotsIndex::ZERO);
    let chain = Chain::new(&[
        (TAG, ChainState::At(addr_at(0), 5_000_000)),
        (tag2, ChainState::At(addr2, 7_000)),
    ]);
    let r = cli::run(ks, MeshClient::new(chain), &Command::Discover { to: 4 });
    assert_eq!(r.code, Code::Ok, "discover was refused:\n{}", r.text);
    assert_eq!(dir.snapshot_bytes(), before, "discover WROTE to the store");

    // The extent asked for, not the count found.
    assert_says(&r, "searched account indices 0..=4", "discover");
    assert_says(&r, "5 index(es), one node call each", "discover");
    assert_says(&r, "The node resolved 2 of them.", "discover");

    // The two resolved rows, by destination, with the balance from the same
    // `tag_resolve` answer.
    let dest0 = mochimo_crypto::addr::tag_to_base58(&TAG).unwrap_or_else(|e| panic!("{e}"));
    let dest2 = mochimo_crypto::addr::tag_to_base58(&tag2).unwrap_or_else(|e| panic!("{e}"));
    assert_says(&r, &dest0, "discover");
    assert_says(&r, &dest2, "discover");
    assert_says(&r, "5000000 nanoMCM (0.005000000 MCM)", "discover");
    assert_says(&r, "7000 nanoMCM (0.000007000 MCM)", "discover");

    // The held account is marked, not hidden.
    assert_says(&r, "IN THIS STORE (derived, at key index 0)", "discover");
    assert!(
        !r.text.lines().any(|l| l.contains(&dest2) && l.contains("IN THIS STORE")),
        "an account the store does not hold was marked as held:\n{}",
        r.text
    );

    // The three indices the node did not resolve.
    assert_says(&r, "the node did not resolve 3 index(es):", "discover");
    for i in [1u32, 3, 4] {
        assert!(
            r.text.split("did not resolve 3 index(es):").nth(1).is_some_and(|t| t.split_whitespace().any(|w| w == i.to_string())),
            "index {i} is missing from the unresolved list:\n{}",
            r.text
        );
    }

    // Nothing on the page says an account is absent, and the page says why.
    for forbidden in [
        "does not exist",
        "no such account",
        "you have 2 accounts",
        "has no accounts",
        "never funded at",
    ] {
        assert!(
            !r.text.to_ascii_lowercase().contains(&forbidden.to_ascii_lowercase()),
            "the page asserts absence with {forbidden:?}:\n{}",
            r.text
        );
    }
    assert_says(&r, "does NOT say those accounts do not exist -- it cannot", "discover");
    assert_says(&r, "Nothing was written", "discover");
    assert_says(&r, "restore --account N", "discover");
    println!("  discover: extent 0..=4 printed, 2 resolved, 1 marked held, 3 named unresolved, snapshot bytes identical");
}

/// A sweep that resolves nothing still succeeds: exit 0, the extent printed,
/// no claim of absence. An unreachable node is exit 3, with no extent
/// reported for indices never asked about.
#[test]
fn discover_finding_nothing_is_exit_zero_and_an_unreachable_node_is_not() {
    let (_d, ks) = store("cli-discover-empty");
    let r = cli::run(
        ks,
        MeshClient::new(Chain::new(&[(TAG, ChainState::Absent)])),
        &Command::Discover { to: 3 },
    );
    assert_eq!(r.code, Code::Ok, "a clean sweep that found nothing was not exit 0:\n{}", r.text);
    assert_says(&r, "searched account indices 0..=3", "discover, nothing found");
    assert_says(&r, "The node resolved 0 of them.", "discover, nothing found");
    // Three, not four: account 0 is held but unresolved (an emptied
    // account), so it keeps its own row marked held and unresolved.
    assert_says(&r, "the node did not resolve 3 index(es):", "discover, nothing found");
    assert!(
        r.text.lines().any(|l| l.contains("IN THIS STORE") && l.contains("not resolved by the node")),
        "a held account the node did not resolve lost its row:\n{}",
        r.text
    );
    assert!(!r.text.to_ascii_lowercase().contains("does not exist"), "{}", r.text);

    let (dir2, ks2) = store("cli-discover-down");
    let before = dir2.snapshot_bytes();
    let r2 = cli::run(
        ks2,
        MeshClient::new(Chain::new(&[(TAG, ChainState::Unreachable)])),
        &Command::Discover { to: 3 },
    );
    assert_eq!(r2.code, Code::Refused, "an unreachable node was reported as a finding:\n{}", r2.text);
    assert_says(&r2, "the sweep stopped at account index 0", "discover, unreachable");
    assert_says(&r2, "0 of 4 index(es) were searched", "discover, unreachable");
    assert_says(&r2, "asserting absence by omission", "discover, unreachable");
    assert_eq!(dir2.snapshot_bytes(), before, "the refusal wrote");
    println!("  discover: a clean sweep finding nothing is exit 0; an unreachable node is exit 3 and reports no extent");
}

/// A store holding no master derives no account index, and says so in the
/// words `address --account N` uses for the same fact. It asks the node
/// nothing at all.
#[test]
fn discover_refuses_a_store_with_no_master_and_asks_the_node_nothing() {
    let dir = ScratchDir::new("cli-discover-nomaster");
    let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(keystore_harness::imported_account()).unwrap_or_else(|e| panic!("{e}"));
    let before = dir.snapshot_bytes();
    let calls = std::rc::Rc::new(std::cell::Cell::new(0usize));
    let client = MeshClient::new(Counting {
        inner: Chain::new(&[]),
        calls: std::rc::Rc::clone(&calls),
    });
    let r = cli::run(ks, client, &Command::Discover { to: 8 });
    assert_eq!(r.code, Code::Refused, "a masterless store swept:\n{}", r.text);
    assert_says(&r, "no master seed", "discover on an imported-only store");
    assert_says(&r, "Nothing was written", "discover refusal");
    assert_eq!(calls.get(), 0, "the refusal made {} node call(s)", calls.get());
    assert_eq!(dir.snapshot_bytes(), before, "the refusal wrote");
    println!("  discover: a masterless store is refused before any call, 0 request(s) made");
}

/// A tag the store does not hold is refused, not answered.
#[test]
fn address_refuses_a_tag_the_store_does_not_hold() {
    let r = run_on(
        "cli-address-unknown",
        Chain::new(&[(TAG, ChainState::At(addr_at(0), 7))]),
        &Command::Address { tag: Some(TO), account: None },
    );
    assert_eq!(r.code, Code::Refused, "output: {}", r.text);
    assert_says(&r, "no account", "address");
}

/// `status` reconciles now and reports without refusing.
#[test]
fn status_reports_without_refusing() {
    let r = run_on(
        "cli-status",
        Chain::new(&[(TAG, ChainState::At(addr_at(0), 42))]),
        &Command::Status { tag: TAG, scan_to: None },
    );
    assert_eq!(r.code, Code::Ok, "output: {}", r.text);
    // Rendered text, not the derived `Debug` byte array.
    let dest = mochimo_crypto::addr::tag_to_base58(&TAG).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(r.text.lines().next(), Some(dest.as_str()), "status: {}", r.text);
    assert_says(&r, "in sync", "status");
    assert_says(&r, &hexs(&addr_at(0)), "status");
    assert!(
        !r.text.contains("InSync {"),
        "status still prints the derived Debug:\n{}",
        r.text
    );
}

// ---------------------------------------------------------------------------
// send: the artifact and the notices printed beside it
// ---------------------------------------------------------------------------

/// The whole spend path, and the three notices as rendered.
#[test]
fn send_prints_the_artifact_and_says_a_submission_is_not_a_verdict() {
    let id = id_for_the_spend("cli-send-id");
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.accepts_submit(id);
    let r = run_on("cli-send", chain, &Command::Send(spend()));
    assert_eq!(r.code, Code::Ok, "the spend did not go through: {}", r.text);

    // Notice 1: the retry artifact, labelled before it is printed.
    assert_says(&r, "RETRY ARTIFACT", "send");
    assert_says(&r, "`resign` is the only recovery", "send");
    assert_says(&r, "SAME destination, amount, fee, block-to-live and reference", "send");

    // Notice 2: `tx_val` has not run offline.
    assert_says(&r, "passed every check that can be run offline", "send");
    assert_says(&r, "a rejection there is silent to this program", "send");

    // Notice 3: submission is only a socket write.
    assert_says(&r, "THIS IS NOT ACCEPTANCE OF THE TRANSACTION", "send");
    assert_says(&r, "computed locally", "send");
    assert_says(&r, "not the node's", "send");
}

/// `send --expect-balance`: a node reporting any other balance is refused
/// before a key is reserved and nothing reaches the socket; a node reporting
/// the expected balance signs and submits as without the flag.
#[test]
fn send_with_an_expected_balance_refuses_any_other_before_reserving() {
    let mut s = spend();
    s.expect_balance = Some(5_000_000);
    for reported in [4_999_999, 5_000_001] {
        let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), reported))]);
        let log = chain.submit_log();
        let (dir, r) = run_on_keeping(&format!("cli-send-expect-{reported}"), chain, &Command::Send(s.clone()));
        assert_eq!(r.code, Code::Refused, "{}", r.text);
        assert_says(&r, &format!("the node reports a balance of {reported} nanoMCM, not the expected 5000000"), "send --expect-balance");
        assert!(log.borrow().is_empty(), "a refused spend reached the socket");
        assert_eq!(stored_index(&dir), 0, "a refused spend reserved a key");
    }
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.accepts_submit(id_for_the_spend("cli-send-expect-id"));
    let r = run_on("cli-send-expect", chain, &Command::Send(s));
    assert_eq!(r.code, Code::Ok, "{}", r.text);
}

/// `--expect-balance` parses for `send` and the validator verbs, and is
/// refused for `resign` and with `--resign`, which reproduce a reservation.
#[test]
fn expect_balance_is_taken_by_send_and_the_validator_verbs_only() {
    let tag = prefixed(&TAG);
    let to = prefixed(&TO);
    let n = ["--dir", "d", "--node", "https://n"];
    let run = |rest: &[&str]| -> Result<Command, args::Usage> {
        let mut v: Vec<&str> = n.to_vec();
        v.extend_from_slice(rest);
        parsed(&v)
    };
    match run(&["send", &tag, &to, "1000", "--expect-balance", "5000000"]) {
        Ok(Command::Send(s)) => assert_eq!(s.expect_balance, Some(5_000_000)),
        other => panic!("send --expect-balance parsed as {other:?}"),
    }
    match run(&["claim", &tag, "5", "--expect-balance", "700"]) {
        Ok(Command::Validator(v)) => assert_eq!(v.expect_balance, Some(700)),
        other => panic!("claim --expect-balance parsed as {other:?}"),
    }
    for (rest, why) in [
        (vec!["resign", tag.as_str(), to.as_str(), "1000", "--expect-balance", "5"], "--expect-balance"),
        (vec!["claim", tag.as_str(), "5", "--expect-balance", "700", "--resign"], "reproduces the reserved one"),
    ] {
        match run(&rest) {
            Err(u) => assert!(u.0.contains(why), "{rest:?}: {}", u.0),
            Ok(c) => panic!("{rest:?} parsed as {c:?}"),
        }
    }
}

/// A validator transaction with `--expect-balance`, in both forms: below the
/// trigger (exact balance) and above it (dust-proof), a node reporting
/// another spendable balance is refused before the cold key is reserved.
#[test]
fn validator_verbs_with_an_expected_balance_refuse_any_other_before_reserving() {
    use chain::{Entitled, Staked};
    use mochimo_crypto::mesh::spend::ValidatorOp;
    let mut cmd = validator(ValidatorOp::Claim { amount: 1_000 }, false, None);
    if let Command::Validator(v) = &mut cmd {
        v.expect_balance = Some(4_000_000);
    }
    for tip in [V40_TIP, V41_TIP] {
        let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
        chain.set_tip(tip);
        chain.stakes(TAG, Staked::Nothing { block: tip });
        chain.entitles(Entitled::Amount(21_582, tip));
        let log = chain.submit_log();
        let (dir, r) = run_on_keeping(&format!("cli-claim-expect-{tip}"), chain, &cmd);
        assert_eq!(r.code, Code::Refused, "{}", r.text);
        assert_says(&r, "the node reports a balance of 5000000 nanoMCM, not the expected 4000000", "claim --expect-balance");
        assert!(log.borrow().is_empty(), "a refused claim reached the socket");
        assert_eq!(stored_index(&dir), 0, "a refused claim reserved a key");
    }
}

/// A failed submission leaves the reservation open and says the artifact is
/// the only copy — exit code 3, because the command did not happen.
#[test]
fn a_failed_submission_is_refused_and_says_the_artifact_is_the_only_copy() {
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.refuses_submit();
    let r = run_on("cli-send-fail", chain, &Command::Send(spend()));
    assert_eq!(r.code, Code::Refused, "output: {}", r.text);
    assert_says(&r, "RETRY ARTIFACT", "a failed submit");
    assert_says(&r, "the only copy", "a failed submit");
}

/// More than the balance is refused before anything is reserved.
#[test]
fn send_refuses_more_than_the_balance_with_code_3() {
    let mut s = spend();
    s.dsts[0].amount = Some(9_000_000);
    let r = run_on(
        "cli-send-broke",
        Chain::new(&[(TAG, ChainState::At(addr_at(0), 1_000))]),
        &Command::Send(s),
    );
    assert_eq!(r.code, Code::Refused, "output: {}", r.text);
    assert_ne!(r.code, Code::Ok, "a refusal exited 0");
}

// ---------------------------------------------------------------------------
// settle and resign: the reservation's two resolutions
// ---------------------------------------------------------------------------

/// Chain state: the tag has moved to the change key. Settling clears the
/// reservation.
#[test]
fn settle_clears_the_reservation_when_the_chain_shows_the_change_key() {
    let id = id_for_the_spend("cli-settle-id");
    let (_dir, ks) = store("cli-settle");
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.accepts_submit(id);
    let sent = cli::run(ks, MeshClient::new(chain), &Command::Send(spend()),
    );
    assert_eq!(sent.code, Code::Ok, "{}", sent.text);

    // The store is at position 1 now; move the chain to the change key.
    let (_dir2, ks2) = store("cli-settle-2");
    let mut ks2 = ks2;
    let receipt = ks2
        .persist_advance(&TAG, &[0u8; 32], Figures { reserved_balance: 5_000_000, blk_to_live: 0 })
        .unwrap_or_else(|e| panic!("{e}"));
    drop(receipt);
    let r = cli::run(
        ks2,
        MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(1), 4_000_000))])),
        &Command::Settle { tag: TAG },
    );
    assert_eq!(r.code, Code::Ok, "output: {}", r.text);
    assert_says(&r, "settled", "settle");
}

/// Chain state: the tag is still at the key that signed. Settling does not
/// settle, and says why in the operator's terms.
#[test]
fn settle_says_not_settled_while_the_chain_still_holds_the_spent_key() {
    let (_dir, ks) = store("cli-settle-out");
    let mut ks = ks;
    let receipt = ks
        .persist_advance(&TAG, &[0u8; 32], Figures { reserved_balance: 5_000_000, blk_to_live: 0 })
        .unwrap_or_else(|e| panic!("{e}"));
    drop(receipt);
    let r = cli::run(
        ks,
        MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))])),
        &Command::Settle { tag: TAG },
    );
    assert_eq!(r.code, Code::Ok, "output: {}", r.text);
    assert_says(&r, "NOT settled", "settle");
    assert_says(&r, "socket write, not a verdict", "settle");
    assert_says(&r, "`resign` rebuilds it", "settle");
}

/// `resign` on a plan that is not the reserved one is refused by name, and the
/// message says what to do — nothing was signed.
#[test]
fn resign_refuses_a_different_spend_and_says_nothing_was_signed() {
    let (_dir, ks) = store("cli-resign-wrong");
    let mut ks = ks;
    let receipt = ks
        .persist_advance(&TAG, &[0u8; 32], Figures { reserved_balance: 5_000_000, blk_to_live: 0 })
        .unwrap_or_else(|e| panic!("{e}"));
    drop(receipt);
    let mut s = spend();
    s.dsts[0].amount = Some(999); // not what was reserved
    // `resign` submits what it reproduces, so a plan that is not the reserved
    // one must put nothing on the socket. The log is checked before the page
    // text so that a missing digest comparison fails on this assertion.
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    let log = chain.submit_log();
    let r = cli::run(ks, MeshClient::new(chain), &Command::Resign(s));
    assert_eq!(r.code, Code::Refused, "output: {}", r.text);
    assert_eq!(
        log.borrow().len(),
        0,
        "a resign of a plan that is not the reserved one put {} body(ies) on the socket:\n{}",
        log.borrow().len(),
        r.text
    );
    assert_says(&r, "not the spend that was reserved", "resign");
    assert_says(&r, "Nothing was signed", "resign");
}

/// `resign` after the reserved spend has already landed names `settle`, and
/// is not reported as an I4 divergence.
///
/// The chain is scripted at the change key, the state after a `send` that
/// succeeded. The page must not show the divergence text, and must not claim
/// which transaction moved the chain: the change address follows the
/// position, not the transaction.
#[test]
fn resign_after_the_spend_landed_names_settle_and_not_a_divergence() {
    let (dir, _artifact) = send_that_never_left("cli-resign-landed");
    // The chain is at the change key: a landed spend, which `settle` resolves.
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(1), 4_998_500))]);
    let log = chain.submit_log();
    let ks = reopen("resign landed", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let r = cli::run(ks, MeshClient::new(chain), &Command::Resign(spend()));
    assert_eq!(r.code, Code::Refused, "output: {}", r.text);
    assert_eq!(
        log.borrow().len(),
        0,
        "a resign over a landed spend put {} body(ies) on the socket:\n{}",
        log.borrow().len(),
        r.text
    );

    // In order: the observation, the classification, the verb, the limit.
    assert_says(&r, "the chain has moved past the key this reservation holds", "resign over a landed spend");
    assert_says(&r, "the state reconciliation calls a landed spend", "resign over a landed spend");
    assert_says(&r, "at the key at position 1", "resign over a landed spend");
    assert_says(&r, "the reservation at position 0", "resign over a landed spend");
    let src = mochimo_crypto::addr::tag_to_base58(&TAG).unwrap_or_else(|e| panic!("{e}"));
    assert_says(&r, &format!("`settle {src}`"), "resign over a landed spend");

    // It reports the observation, not a settlement.
    assert_says(&r, "not which transaction put it there", "resign over a landed spend");

    // None of the divergence page's claims, which do not hold here.
    for wrong in ["three causes", "do not advance the index by hand", "reconcile"] {
        assert!(
            !r.text.contains(wrong),
            "the landed page still carries the divergence page's {wrong:?}:\n{}",
            r.text
        );
    }

    // The store is untouched: index 1, reservation open for `settle` to clear.
    assert_eq!(stored_index(&dir), 1, "a refused resign moved the stored index");
    let ks = reopen("resign landed after", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    assert!(
        ks.view(&TAG).unwrap_or_else(|e| panic!("{e}")).is_some_and(|v| v.pending.is_some()),
        "a refused resign resolved the reservation"
    );
}

/// `send` over the same chain state refuses as a divergence and never shows
/// the landed-spend page.
///
/// With no reservation open, a chain one key ahead was moved by another
/// signer (I4), and the wallet refuses at startup. Fails if the landed-spend
/// refusal moves into `SpendPlan::new`. The planner side is in
/// `tests/spend.rs`.
#[test]
fn send_over_a_chain_one_key_on_is_still_a_divergence_and_never_the_landed_page() {
    let r = run_on(
        "cli-send-one-on",
        Chain::new(&[(TAG, ChainState::At(addr_at(1), 4_998_500))]),
        &Command::Send(spend()),
    );
    assert_eq!(r.code, Code::StartupRefused, "output: {}", r.text);
    assert_says(&r, "WALLET WILL NOT START", "send over a chain one key on");
    assert_says(&r, "another install of this seed spending", "send over a chain one key on");
    for wrong in ["already landed", "nothing left to reproduce", "`settle"] {
        assert!(
            !r.text.contains(wrong),
            "`send` was given `resign`'s landed page ({wrong:?}), which no `send` state can be:\n{}",
            r.text
        );
    }
}

/// A `send` whose socket write failed, in process: the reservation is open
/// and the page carries the artifact. The child-process form is
/// `p10_send_that_never_left`.
fn send_that_never_left(name: &str) -> (ScratchDir, String) {
    send_that_never_left_with(name, &spend())
}

/// [`send_that_never_left`] over any `Spend`, for the reference tests.
fn send_that_never_left_with(name: &str, s: &Spend) -> (ScratchDir, String) {
    let (dir, ks) = store(name);
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.refuses_submit();
    let r = cli::run(ks, MeshClient::new(chain), &Command::Send(s.clone()));
    assert_eq!(r.code, Code::Refused, "premise: a send through a refusing socket did not exit 3:\n{}", r.text);
    let artifact = r
        .text
        .lines()
        .find(|l| l.len() >= 200 && l.bytes().all(|b| b.is_ascii_hexdigit()))
        .unwrap_or_else(|| panic!("premise: send's page carries no artifact line:\n{}", r.text))
        .to_owned();
    (dir, artifact)
}

/// `submit` sends the given artifact unchanged and writes nothing.
///
/// Refusals first, each exit 3 with an empty submit log: not hex, hex that is
/// no transaction, and the artifact one byte short (a length `from_wire`
/// accepts and zero-extends, caught by the byte-identity check). Then the
/// artifact `send` printed: exit 0, the log holds it byte for byte as
/// `signed_transaction`, the page carries the `submitted:` block naming
/// `settle` with the source, and the store is as `send` left it (index 1,
/// reservation open).
#[test]
fn submit_ships_a_saved_artifact_as_it_is_and_refuses_what_is_not_one_before_the_socket() {
    let (dir, artifact) = send_that_never_left("cli-submit");
    let id = id_for_the_spend("cli-submit-id");
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.accepts_submit(id);
    let log = chain.submit_log();
    let client = MeshClient::new(chain);
    let truncated = artifact[..artifact.len() - 2].to_owned();
    let cases: [(&str, &str); 3] = [
        ("zz", "is not hex"),
        ("00ff", "does not parse as a transaction"),
        (truncated.as_str(), "is not a whole transaction image"),
    ];
    for (input, why) in cases {
        let shown = &input[..input.len().min(16)];
        let r = cli::run_submit(&client, input);
        assert_eq!(r.code, Code::Refused, "`submit {shown}...` did not exit 3:\n{}", r.text);
        assert!(r.text.contains(why), "the refusal for `{shown}...` does not say the artifact {why}:\n{}", r.text);
        assert!(
            r.text.contains("Nothing was written to the socket"),
            "the refusal for `{shown}...` does not say nothing was written:\n{}",
            r.text
        );
        assert!(
            log.borrow().is_empty(),
            "a refused artifact reached the socket: {} body(ies) after `{shown}...`",
            log.borrow().len()
        );
    }

    let settle_arg = mochimo_crypto::addr::tag_to_base58(&TAG).unwrap_or_else(|e| panic!("{e}"));
    let ks = reopen("submit", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let r = cli::run(ks, client, &Command::Submit { artifact: artifact.clone() });
    assert_eq!(r.code, Code::Ok, "submit of the artifact send printed did not exit 0:\n{}", r.text);
    assert_says(&r, "submitted: the node accepted the SOCKET WRITE", "submit");
    assert_says(&r, "THIS IS NOT ACCEPTANCE OF THE TRANSACTION", "submit");
    assert_says(&r, &format!("Run `settle {settle_arg}`"), "submit");
    assert_says(&r, "No store was opened and no password asked", "submit");
    let bodies = log.borrow().clone();
    assert_eq!(bodies.len(), 1, "the chain saw {} submit body(ies), not one", bodies.len());
    assert_eq!(
        p10_signed_transaction_of(&hexs(&bodies[0])).as_deref(),
        Some(artifact.as_str()),
        "the submit body does not carry the artifact byte for byte"
    );
    assert_eq!(stored_state(&dir), (1, true), "submit changed the store; it writes nothing");
    println!("  submit: three refusals with the socket untouched, then one body carrying the artifact");
}

/// `submit` sends a validator artifact as it sends a transfer. A signed claim
/// parses, re-serializes byte for byte and reaches the socket as one body's
/// `signed_transaction`, with the page naming `settle` for the claiming tag.
/// The same artifact with an unsupported type byte is refused before the
/// socket, naming the type.
#[test]
fn submit_ships_a_validator_artifact_and_refuses_a_type_it_does_not_build() {
    let (_dir, ks) = store("cli-submit-claim");
    let m = master();
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    let mut w = Wallet::open(ks, MeshClient::new(chain), Some(&m)).unwrap_or_else(|e| panic!("{e}"));
    let plan = w
        .plan_validator(&TAG, &KeyAccess::Master(&m), mochimo_crypto::mesh::spend::ValidatorOp::Claim { amount: 5 }, MFEE, 0)
        .unwrap_or_else(|e| panic!("{e}"));
    let signed = w.reserve_and_sign(&plan, KeyAccess::Master(&m)).unwrap_or_else(|e| panic!("{e}"));
    let artifact = hexs(&signed.wire());

    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.accepts_submit(signed.id().0);
    let log = chain.submit_log();
    let client = MeshClient::new(chain);

    let mut retyped = bytes_of(&artifact);
    retyped[0] = 0x04;
    let r = cli::run_submit(&client, &hexs(&retyped));
    assert_eq!(r.code, Code::Refused, "a type-0x04 artifact did not exit 3:
{}", r.text);
    assert!(r.text.contains("0x04"), "the refusal does not name the type:
{}", r.text);
    assert!(log.borrow().is_empty(), "a refused artifact reached the socket");

    let r = cli::run_submit(&client, &artifact);
    assert_eq!(r.code, Code::Ok, "submit of a claim did not exit 0:
{}", r.text);
    let settle_arg = mochimo_crypto::addr::tag_to_base58(&TAG).unwrap_or_else(|e| panic!("{e}"));
    assert!(r.text.contains(&format!("Run `settle {settle_arg}`")), "{}", r.text);
    let bodies = log.borrow().clone();
    assert_eq!(bodies.len(), 1);
    assert_eq!(p10_signed_transaction_of(&hexs(&bodies[0])).as_deref(), Some(artifact.as_str()));
    println!("  submit: a 2372-byte claim shipped as it is; a type-0x04 image refused before the socket");
}

/// `send` without `--ref` writes a zero destination reference at bytes
/// 20..36 of the one destination, which begins at image offset 116.
#[test]
fn send_writes_a_zero_destination_reference_at_the_documented_offset() {
    let (_dir, artifact) = send_that_never_left("cli-zero-ref");
    let mut bytes = Vec::with_capacity(artifact.len() / 2);
    for i in (0..artifact.len()).step_by(2) {
        bytes.push(u8::from_str_radix(&artifact[i..i + 2], 16).unwrap_or_else(|e| panic!("{e}")));
    }
    let tx = mochimo_crypto::tx::wire::Transaction::from_wire(&bytes).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(tx.dsts().len(), 1);
    assert_eq!(tx.dsts()[0].reference, [0u8; 16], "send wrote a non-zero destination reference");
    assert_eq!(&bytes[116 + 20..116 + 36], &[0u8; 16], "the reference bytes at image offset 136..152 are not zero");
    assert_eq!(&bytes[116..116 + 20], &TO[..], "the destination tag is not at image offset 116");
    println!("  zero reference: send's one destination carries sixteen zero reference bytes at image offset 136..152");
}

/// `send --ref AB-00-EF` writes the reference, NUL-padded, at bytes 20..36 of
/// the one destination at image offset 116.
#[test]
fn send_with_a_reference_lays_it_out_at_the_documented_offset() {
    let s = spend_with_reference("AB-00-EF");
    let (_dir, artifact) = send_that_never_left_with("cli-ref-offset", &s);
    let bytes = bytes_of(&artifact);
    let tx = mochimo_crypto::tx::wire::Transaction::from_wire(&bytes).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(tx.dsts().len(), 1);
    assert_eq!(tx.dsts()[0].reference, *b"AB-00-EF\0\0\0\0\0\0\0\0", "the destination does not carry the reference NUL-padded");
    assert_eq!(&bytes[116 + 20..116 + 36], b"AB-00-EF\0\0\0\0\0\0\0\0", "the reference is not at image offset 136..152");
    assert_eq!(&bytes[116..116 + 20], &TO[..], "the destination tag is not at image offset 116");
    println!("  reference offset: send --ref AB-00-EF carries the field at image offset 136..152, NUL-padded, the tag at 116");
}

/// A reference the node's rule refuses is a usage error at parse time,
/// naming the flag, the value and the rule, before any prompt, store or
/// socket. `--ref` given twice is the repeated-flag refusal. The rule's
/// accepted examples parse to the NUL-padded field.
#[test]
fn a_refused_reference_is_a_usage_error_with_the_rules_words() {
    let tag = format!("0x{}", hexs(&TAG));
    let to = format!("0x{}", hexs(&TO));
    let with = |extra: &[&str]| {
        let mut a = vec!["--dir", "/d", "--node", "n", "send", &tag, &to, "1000"];
        a.extend_from_slice(extra);
        args::parse(&argv(&a))
    };
    let mut refused = 0usize;
    for value in ["AB-CD-EF", "123-456-789", "ABC-", "-123", "ab-00-ef", "AB 00", "AB--00", "AB-12-CD-34-EF-56"] {
        match with(&["--ref", value]) {
            Err(u) => {
                assert!(u.0.starts_with("--ref: `") && u.0.contains(value), "--ref {value}: the refusal does not name the flag and the value: {}", u.0);
                assert!(u.0.contains(args::REFERENCE_RULE), "--ref {value}: the refusal does not carry the rule's words: {}", u.0);
                assert!(u.0.contains("AB-00-EF") && u.0.contains("single dashes"), "--ref {value}: the rule's words are not the rule: {}", u.0);
                refused += 1;
            }
            Ok(other) => panic!("--ref {value} was accepted: {other:?}"),
        }
    }
    match with(&["--ref", "AB", "--ref", "CD"]) {
        Err(u) => assert_eq!(u.0, "--ref given twice"),
        Ok(other) => panic!("--ref twice was accepted: {other:?}"),
    }
    let mut accepted = 0usize;
    for (value, field) in [("AB-00-EF", *b"AB-00-EF\0\0\0\0\0\0\0\0"), ("123-CDE-789", *b"123-CDE-789\0\0\0\0\0"), ("ABC", *b"ABC\0\0\0\0\0\0\0\0\0\0\0\0\0"), ("123", *b"123\0\0\0\0\0\0\0\0\0\0\0\0\0")] {
        match with(&["--ref", value]) {
            Ok(args::ParsedArgv::Run(inv)) => match inv.command {
                Command::Send(s) => assert_eq!(s.dsts[0].reference, field, "--ref {value} did not lay out NUL-padded"),
                other => panic!("--ref {value} parsed to {other:?}"),
            },
            other => panic!("--ref {value} was refused or read as help: {other:?}"),
        }
        accepted += 1;
    }
    println!("  reference refusals: {refused} values refused at parse time with the rule's words, `--ref` twice refused by name, {accepted} of the node's own examples laid out NUL-padded");
}

/// `resign --ref` reproduces the artifact `send --ref` printed, byte for
/// byte. `resign` without the reference is refused by the digest check as a
/// different transaction, naming the reference among the figures to retype,
/// with nothing on the socket and the store untouched.
#[test]
fn resign_with_the_reference_reproduces_the_artifact_and_without_it_is_refused() {
    let s = spend_with_reference("AB-00-EF");
    let (dir, artifact) = send_that_never_left_with("cli-ref-resign", &s);
    let id = id_for("cli-ref-resign-id", &s);

    // With the reference: reproduced and shipped.
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.accepts_submit(id);
    let log = chain.submit_log();
    let ks = reopen("resign with ref", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let r = cli::run(ks, MeshClient::new(chain), &Command::Resign(s.clone()));
    assert_eq!(r.code, Code::Ok, "resign with the reference did not exit 0:\n{}", r.text);
    assert_says(&r, "       ref AB-00-EF", "resign's page");
    assert_says(&r, &artifact, "resign's page");
    let shipped: Vec<String> = log.borrow().iter().map(|b| hexs(b)).collect();
    assert_eq!(shipped.len(), 1, "resign with the reference put {} body(ies) on the socket", shipped.len());
    assert_eq!(p10_signed_transaction_of(&shipped[0]).as_deref(), Some(artifact.as_str()), "the body is not the artifact send --ref printed");
    assert_eq!(&bytes_of(&artifact)[136..152], b"AB-00-EF\0\0\0\0\0\0\0\0", "the reproduced artifact does not carry the reference");

    // Without it: a different transaction, refused before the socket.
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.accepts_submit(id);
    let log = chain.submit_log();
    let ks = reopen("resign without ref", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let r = cli::run(ks, MeshClient::new(chain), &Command::Resign(spend()));
    assert_eq!(r.code, Code::Refused, "resign without the reference did not exit 3:\n{}", r.text);
    assert_says(&r, "not the spend that was reserved", "resign without the reference");
    assert_says(&r, "block-to-live or reference differs", "resign without the reference");
    assert_says(&r, "`--ref` included if one was given", "resign without the reference");
    assert_says(&r, "Nothing was signed", "resign without the reference");
    assert!(log.borrow().is_empty(), "resign without the reference put {} body(ies) on the socket", log.borrow().len());
    assert_eq!(stored_state(&dir), (1, true), "the store moved");
    println!("  resign with the reference: one body, the artifact byte for byte, `reference AB-00-EF` on the page; without it: refused as a different transaction naming the reference, nothing on the socket");
}

/// The index and whether a reservation is open, read back from disk.
fn stored_state(dir: &ScratchDir) -> (u32, bool) {
    let ks = reopen("stored state", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let v = ks
        .view(&TAG)
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("the store no longer holds the account"));
    (v.wots_index.get(), v.pending.is_some())
}

/// `resign` submits what it reproduces and reports the write as `send` does.
///
/// Checked against the artifact `send` printed: the submit log holds exactly
/// one body whose `signed_transaction` is that artifact; the page carries it,
/// the same-bytes sentence and `send`'s three success lines (the write is not
/// a verdict, the id was computed locally, `settle <src>` with the source
/// destination); `HELP` says the verb submits; and the store is unchanged
/// (index 1, reservation open), since `Keystore::resign_reserved` takes
/// `&self`.
#[test]
fn resign_submits_what_it_reproduces_and_says_a_submission_is_not_a_verdict() {
    let (dir, artifact) = send_that_never_left("cli-resign-ships");
    let id = id_for_the_spend("cli-resign-ships-id");
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.accepts_submit(id);
    let log = chain.submit_log();
    let ks = reopen("resign ships", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let r = cli::run(ks, MeshClient::new(chain), &Command::Resign(spend()));
    assert_eq!(r.code, Code::Ok, "output: {}", r.text);

    // The socket.
    let bodies: Vec<String> = log.borrow().iter().map(|b| hexs(b)).collect();
    assert_eq!(bodies.len(), 1, "the chain saw {} submit body(ies); resign writes the socket once", bodies.len());
    assert_eq!(
        p10_signed_transaction_of(&bodies[0]).as_deref(),
        Some(artifact.as_str()),
        "the body on the socket does not carry the artifact send printed"
    );

    // The page.
    assert_says(&r, &artifact, "resign");
    assert_says(&r, "SAME bytes the original signing produced", "resign");
    assert_says(&r, "submitted: the node accepted the SOCKET WRITE", "resign");
    assert_says(&r, "THIS IS NOT ACCEPTANCE OF THE TRANSACTION", "resign");
    assert_says(&r, "computed locally", "resign");
    let src = mochimo_crypto::addr::tag_to_base58(&TAG).unwrap_or_else(|e| panic!("{e}"));
    assert_says(&r, &format!("Run `settle {src}`"), "resign");
    assert_says(&r, &format!("id {}", hexs(&id)), "resign");

    // The help describes the verb's behaviour.
    assert!(
        args::HELP.contains("rebuild a lost retry artifact and submit it"),
        "HELP's resign entry does not say the verb submits:\n{}",
        args::HELP
    );

    // The store.
    assert_eq!(stored_state(&dir), (1, true), "resign moved the store; settle is what clears the reservation");

    // Print the submitted body so the test log shows it. It matches the
    // child-process chain's body: same seed, same spend, deterministic
    // signature.
    println!(
        "  submit body on the socket ({} bytes): {}",
        log.borrow()[0].len(),
        String::from_utf8_lossy(&log.borrow()[0])
    );
}

/// A refused socket write under `resign` is exit 3, the artifact is on the
/// page with `resign`'s own sentence (the bytes are not the only copy, since
/// the command reproduces them), and the store is untouched.
///
/// The write is part of the command, so a failed write is exit 3 as for
/// `send`. The refused write still appears in the chain's log.
///
/// That exit-3 reports go to stderr is checked by
/// `pty::resign_on_a_real_pty_completes_the_recovery_send_could_not`.
#[test]
fn resign_through_a_refusing_socket_is_refused_and_keeps_the_reservation() {
    let (dir, artifact) = send_that_never_left("cli-resign-refused");
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.refuses_submit();
    let log = chain.submit_log();
    let ks = reopen("resign refused", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let r = cli::run(ks, MeshClient::new(chain), &Command::Resign(spend()));
    assert_eq!(r.code, Code::Refused, "output: {}", r.text);
    assert_says(&r, &artifact, "a refused resign");
    assert_says(&r, "submission FAILED", "a refused resign");
    assert_says(&r, "not known here", "a refused resign");
    assert_says(&r, "tries the socket again", "a refused resign");
    assert!(
        !r.text.contains("the only copy"),
        "resign's refusal borrowed send's sentence; after resign the artifact is not the only copy:\n{}",
        r.text
    );
    assert!(!r.text.contains("submitted:"), "a refused write said submitted:\n{}", r.text);
    let bodies: Vec<String> = log.borrow().iter().map(|b| hexs(b)).collect();
    assert_eq!(bodies.len(), 1, "the refused write is still a write the chain saw; it saw {}", bodies.len());
    assert_eq!(
        p10_signed_transaction_of(&bodies[0]).as_deref(),
        Some(artifact.as_str()),
        "the refused body does not carry the artifact"
    );
    assert_eq!(stored_state(&dir), (1, true), "a refused resign moved the store");
}

// ---------------------------------------------------------------------------
// reconcile: the acknowledgement gate, from the operator's side
// ---------------------------------------------------------------------------

/// The number the operator types must be the number the report named,
/// checked through the rendered refusal and the untouched store.
///
/// `Code::StartupRefused` alone would not distinguish a right number from a
/// wrong one.
#[test]
fn reconcile_refuses_an_advance_to_that_does_not_match_the_report() {
    let (dir, r) = run_on_keeping(
        "cli-reconcile-wrong",
        Chain::new(&[(TAG, ChainState::At(addr_at(2), 9))]),
        &Command::Reconcile {
            tag: TAG,
            advance_to: 7,
        },
    );
    assert_eq!(r.code, Code::Refused, "output: {}", r.text);
    assert_says(&r, "--advance-to 7 does not match the index this divergence reports (2)", "reconcile");
    assert_says(&r, "Nothing was written", "reconcile");
    assert_eq!(stored_index(&dir), 0, "a refused reconcile moved the index");

    // A divergence advancing cannot fix: local ahead of the chain.
    let (dir2, ks) = store("cli-reconcile-behind");
    let mut ks = ks;
    let _ = ks.persist_advance_to(&TAG, mochimo_crypto::account::WotsIndex::ZERO.advanced().unwrap_or_else(|e| panic!("{e}")))
        .unwrap_or_else(|e| panic!("{e}"));
    drop(ks);
    let ks = reopen("behind", dir2.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let r2 = cli::run(
        ks,
        MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(0), 9))])),
        &Command::Reconcile { tag: TAG, advance_to: 0 },
    );
    assert_eq!(r2.code, Code::Refused, "output: {}", r2.text);
    assert_says(&r2, "no advance to acknowledge", "reconcile behind");
    assert_says(&r2, "1 BEHIND local", "reconcile behind");
    assert_eq!(stored_index(&dir2), 1, "a behind divergence moved the index");
}

/// The acknowledged path: the number the report named advances the store,
/// the report is printed before the write, and the store then reconciles.
#[test]
fn reconcile_with_the_number_the_report_named_advances_the_store() {
    let (dir, r) = run_on_keeping(
        "cli-reconcile-right",
        Chain::new(&[(TAG, ChainState::At(addr_at(2), 9))]),
        &Command::Reconcile {
            tag: TAG,
            advance_to: 2,
        },
    );
    assert_eq!(r.code, Code::Ok, "THE ACKNOWLEDGED PATH IS NOT REACHABLE: {}", r.text);
    assert_says(&r, "THE STORE BEFORE THIS DECISION: 1 of 1 account(s) diverged", "reconcile");
    assert_says(&r, "key at index 2 -- 2 ahead of local", "reconcile");
    assert_says(&r, "SECOND WALLET", "reconcile");
    assert_says(&r, &format!("advanced account 0x{} to index 2", hexs(&TAG)), "reconcile");
    assert_eq!(stored_index(&dir), 2, "the advance did not reach disk");

    // And the store now opens: `balance` is in sync at index 2.
    let ks = reopen("after reconcile", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let b = cli::run(ks, MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(2), 9))])), &Command::Balance);
    assert_eq!(b.code, Code::Ok, "balance after the advance: {}", b.text);
    assert_says(&b, "index 2", "balance");
    assert_says(&b, "in sync", "balance");
}

/// An index the operator names is derived and compared, never trusted. With
/// the chain at 100, past the window and the ceiling: 99 is refused with
/// nothing written, 5000 is refused naming the index found, 100 advances.
#[test]
fn reconcile_refuses_an_index_the_chain_does_not_confirm_and_writes_nothing() {
    let far = || Chain::new(&[(TAG, ChainState::At(addr_at(100), 9))]);
    let (d1, r1) = run_on_keeping("cli-reconcile-99", far(), &Command::Reconcile { tag: TAG, advance_to: 99 });
    assert_eq!(r1.code, Code::Refused, "99 was accepted: {}", r1.text);
    assert_says(&r1, "no advance to acknowledge", "reconcile 99");
    assert_says(&r1, "indices 0 through 99", "reconcile 99");
    assert_eq!(stored_index(&d1), 0, "naming 99 moved the index");

    let (d2, r2) = run_on_keeping("cli-reconcile-5000", far(), &Command::Reconcile { tag: TAG, advance_to: 5000 });
    assert_eq!(r2.code, Code::Refused, "5000 was accepted: {}", r2.text);
    assert_says(&r2, "--advance-to 5000 does not match the index this divergence reports (100)", "reconcile 5000");
    assert_eq!(stored_index(&d2), 0, "naming 5000 moved the index");

    let (d3, r3) = run_on_keeping("cli-reconcile-100", far(), &Command::Reconcile { tag: TAG, advance_to: 100 });
    assert_eq!(r3.code, Code::Ok, "the confirmed index was refused: {}", r3.text);
    assert_says(&r3, "key at index 100 -- 100 ahead of local", "reconcile 100");
    assert_eq!(stored_index(&d3), 100, "the confirmed advance did not reach disk");
}

/// The whole store is read and reported before the write, and a spend this
/// wallet did not make on another account does not hold back the named
/// account's advance: another install on the same seed is expected.
#[test]
fn reconcile_advances_while_another_account_shows_a_spend_this_wallet_did_not_make() {
    let m = master();
    let other = mochimo_crypto::derive::derive_account_tag(&m, 1);
    let other_at = |i: u32| mochimo_crypto::recon::derived_address_at(&m, 1, chain::pos(i));
    let two_accounts = |name: &str| -> (ScratchDir, Keystore) {
        let (dir, mut ks) = store(name);
        ks.add(Account::derive(&m, 1)).unwrap_or_else(|e| panic!("{e}"));
        // Account 1 reserves a spend at index 0, with figures matching the
        // balance of 1 the control scripts, so the reservation reads live.
        let _ = ks
            .persist_advance(&other, &[0xD1; 32], Figures { reserved_balance: 1, blk_to_live: 0 })
            .unwrap_or_else(|e| panic!("{e}"));
        drop(ks);
        let ks = reopen(name, dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
        (dir, ks)
    };

    // Account 1's chain address is at neither its spent key (0) nor its
    // change key (1): something else spent from this seed.
    let (dir, ks) = two_accounts("cli-second-wallet");
    let r = cli::run(
        ks,
        MeshClient::new(Chain::new(&[
            (TAG, ChainState::At(addr_at(2), 9)),
            (other, ChainState::At(other_at(5), 1)),
        ])),
        &Command::Reconcile { tag: TAG, advance_to: 2 },
    );
    assert_eq!(r.code, Code::Ok, "another account's divergence held back the advance: {}", r.text);
    assert_says(&r, "2 of 2 account(s) diverged", "reconcile");
    assert_says(&r, &hexs(&other), "reconcile");
    assert_says(&r, &format!("advanced account 0x{} to index 2", hexs(&TAG)), "reconcile");
    assert_says(&r, "1 other account(s) in the report above are still diverged", "reconcile");
    assert_eq!(stored_index(&dir), 2, "the advance did not reach disk");

    // Control: account 1's reservation still outstanding (chain at its spent
    // key) is a known state, and the advance proceeds.
    let (dir2, ks2) = two_accounts("cli-second-wallet-control");
    let r2 = cli::run(
        ks2,
        MeshClient::new(Chain::new(&[
            (TAG, ChainState::At(addr_at(2), 9)),
            (other, ChainState::At(other_at(0), 1)),
        ])),
        &Command::Reconcile { tag: TAG, advance_to: 2 },
    );
    assert_eq!(r2.code, Code::Ok, "{}", r2.text);
    assert_eq!(stored_index(&dir2), 2);
}

/// `reconcile --rollback-to` moves an account the chain shows behind the
/// store back to exactly that index, and refuses every other number and the
/// chain ahead, with nothing written.
#[test]
fn reconcile_rolls_back_only_to_the_index_the_chain_shows_behind() {
    let behind = |name: &str, local: u32| -> (ScratchDir, Keystore) {
        let (dir, mut ks) = store(name);
        let _ = ks.persist_advance_to(&TAG, chain::pos(local)).unwrap_or_else(|e| panic!("{e}"));
        drop(ks);
        let ks = reopen(name, dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
        (dir, ks)
    };
    let at = |i: u32| MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(i), 9))]));

    let (d1, ks) = behind("cli-rollback-wrong", 3);
    let r1 = cli::run(ks, at(1), &Command::Rollback { tag: TAG, rollback_to: 2 });
    assert_eq!(r1.code, Code::Refused, "output: {}", r1.text);
    assert_says(&r1, "--rollback-to 2 does not match the index this divergence reports (1)", "rollback 2");
    assert_says(&r1, "Nothing was written", "rollback 2");
    assert_eq!(stored_index(&d1), 3, "a refused rollback moved the index");

    let (d2, r2) = run_on_keeping(
        "cli-rollback-ahead",
        Chain::new(&[(TAG, ChainState::At(addr_at(2), 9))]),
        &Command::Rollback { tag: TAG, rollback_to: 2 },
    );
    assert_eq!(r2.code, Code::Refused, "output: {}", r2.text);
    assert_says(&r2, "no rollback to acknowledge", "rollback ahead");
    assert_eq!(stored_index(&d2), 0, "a rollback moved an account the chain shows ahead");

    let (d3, ks) = behind("cli-rollback-right", 3);
    let r3 = cli::run(ks, at(1), &Command::Rollback { tag: TAG, rollback_to: 1 });
    assert_eq!(r3.code, Code::Ok, "the confirmed rollback was refused: {}", r3.text);
    assert_says(&r3, "2 BEHIND local", "rollback");
    assert_says(&r3, &format!("rolled account 0x{} back to index 1", hexs(&TAG)), "rollback");
    assert_says(&r3, "has signed before", "rollback");
    assert_eq!(stored_index(&d3), 1, "the rollback did not reach disk");

    let ks = reopen("after rollback", d3.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let b = cli::run(ks, at(1), &Command::Balance);
    assert_eq!(b.code, Code::Ok, "balance after the rollback: {}", b.text);
    assert_says(&b, "in sync", "balance");
}

// ---------------------------------------------------------------------------
// status: before the gate
// ---------------------------------------------------------------------------

/// `status` reports a divergence rather than stopping on it -- exit 0, the
/// report and the in-program next step, nothing written -- and with
/// `--scan-to` it finds a far-along index the default walk does not reach.
#[test]
fn status_reports_a_divergence_without_opening_a_wallet() {
    let (dir, r) = run_on_keeping(
        "cli-status-diverged",
        Chain::new(&[(TAG, ChainState::At(addr_at(2), 9))]),
        &Command::Status { tag: TAG, scan_to: None },
    );
    assert_eq!(r.code, Code::Ok, "status on a divergence did not report: {}", r.text);
    assert_says(&r, "DIVERGED", "status");
    assert_says(&r, "key at index 2 -- 2 ahead of local", "status");
    assert_says(&r, &format!("reconcile 0x{} --advance-to 2", hexs(&TAG)), "status");
    assert!(!r.text.contains("WALLET WILL NOT START"), "status rendered the startup refusal:\n{}", r.text);
    assert_eq!(stored_index(&dir), 0, "status wrote to the store");

    // Out of reach of the walk: the extent walked and the remedy are named.
    // `--scan-to 19` sets the ceiling to 20; the default ceiling of 10,000
    // would find index 30 (case below), and exhausting it takes minutes.
    let r2 = run_on(
        "cli-status-far",
        Chain::new(&[(TAG, ChainState::At(addr_at(30), 9))]),
        &Command::Status { tag: TAG, scan_to: Some(19) },
    );
    assert_eq!(r2.code, Code::Ok, "{}", r2.text);
    assert_says(&r2, "NO key index this scan walked", "status far");
    assert_says(&r2, "indices 0 through 19", "status far");
    assert_says(&r2, &format!("status 0x{} --scan-to <M>", hexs(&TAG)), "status far");
    assert!(!r2.text.contains("does not own this tag, or"), "the closed disjunction:\n{}", r2.text);

    // Without `--scan-to`, the default ceiling of 10,000 reaches index 30.
    let r2d = run_on(
        "cli-status-far-default",
        Chain::new(&[(TAG, ChainState::At(addr_at(30), 9))]),
        &Command::Status { tag: TAG, scan_to: None },
    );
    assert_eq!(r2d.code, Code::Ok, "{}", r2d.text);
    assert_says(&r2d, "key at index 30 -- 30 ahead of local", "status at the default ceiling");
    assert!(!r2d.text.contains("NO key index this scan walked"), "the default ceiling did not reach index 30:\n{}", r2d.text);
    let r3 = run_on(
        "cli-status-far-raised",
        Chain::new(&[(TAG, ChainState::At(addr_at(30), 9))]),
        &Command::Status { tag: TAG, scan_to: Some(40) },
    );
    assert_eq!(r3.code, Code::Ok, "{}", r3.text);
    assert_says(&r3, "key at index 30 -- 30 ahead of local", "status --scan-to");
    assert_says(&r3, &format!("reconcile 0x{} --advance-to 30", hexs(&TAG)), "status --scan-to");
}

/// Key access is chosen per account: a derived account in a store with no
/// master is reported by name, not as "could not compare".
#[test]
fn status_names_the_missing_master_for_a_derived_account() {
    let dir = ScratchDir::new("cli-status-nomaster");
    let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(Account::derive(&master(), 0)).unwrap_or_else(|e| panic!("{e}"));
    let r = cli::run(
        ks,
        MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(0), 9))])),
        &Command::Status { tag: TAG, scan_to: None },
    );
    assert_eq!(r.code, Code::Refused, "{}", r.text);
    assert_says(&r, "no master seed was supplied", "status without a master");
    assert!(!r.text.contains("could not compare"), "the generic failure, not the named one:\n{}", r.text);
}

/// A tag the store does not hold is refused by name, for `status` and
/// `reconcile` alike.
#[test]
fn status_and_reconcile_refuse_a_tag_the_store_does_not_hold_by_name() {
    let other = mochimo_crypto::derive::derive_account_tag(&master(), 1);
    let chain = || Chain::new(&[(TAG, ChainState::At(addr_at(0), 9))]);
    let r = run_on("cli-status-notheld", chain(), &Command::Status { tag: other, scan_to: None });
    assert_eq!(r.code, Code::Refused, "{}", r.text);
    assert_says(&r, "no account for the tag", "status");
    assert!(!r.text.contains("could not ask the question"), "{}", r.text);
    let r2 = run_on("cli-reconcile-notheld", chain(), &Command::Reconcile { tag: other, advance_to: 1 });
    assert_eq!(r2.code, Code::Refused, "{}", r2.text);
    assert_says(&r2, "no account for the tag", "reconcile");
}

/// The startup refusal names the next step per account where one exists:
/// the `reconcile` line for `Ahead`, the search and then the line for an
/// unlocated address, nothing otherwise.
#[test]
fn the_startup_refusal_names_the_next_step_only_where_one_exists() {
    let r = run_on("cli-next-ahead", Chain::new(&[(TAG, ChainState::At(addr_at(3), 9))]), &Command::Balance);
    assert_eq!(r.code, Code::StartupRefused);
    assert_says(&r, &format!("reconcile 0x{} --advance-to 3", hexs(&TAG)), "refusal, ahead");
    // Far ahead but within the default walk: the startup page names the
    // advance for index 30. The unlocated case would walk all 10,000
    // positions here, so its line is asserted on the `status` page
    // (`status_reports_a_divergence_without_opening_a_wallet`), which uses
    // the same `next_steps`.
    let r2 = run_on("cli-next-far", Chain::new(&[(TAG, ChainState::At(addr_at(30), 9))]), &Command::Balance);
    assert_eq!(r2.code, Code::StartupRefused);
    assert_says(&r2, &format!("reconcile 0x{} --advance-to 30", hexs(&TAG)), "refusal, far ahead");
    let r3 = run_on("cli-next-absent", Chain::new(&[(TAG, ChainState::Absent)]), &Command::Balance);
    assert_eq!(r3.code, Code::StartupRefused);
    assert!(!r3.text.contains("In this program"), "a next step was printed for an arm that has none:\n{}", r3.text);
}

// ---------------------------------------------------------------------------
// restore: the one command that holds a mutable store
// ---------------------------------------------------------------------------

/// The index comes from the chain. Position 0 is a match like any other.
#[test]
fn restore_takes_the_index_from_the_chain_and_says_so() {
    let dir = ScratchDir::new("cli-restore");
    let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    // `restore` derives from the master stored in the store; without one it
    // refuses with the no-master message.
    let _durable = ks.adopt_master(&master()).unwrap_or_else(|e| panic!("{e}"));
    let r = cli::run(
        ks,
        MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(3), 11))])),
        &Command::Restore { account: 0, scan_to: None },
    );
    assert_eq!(r.code, Code::Ok, "output: {}", r.text);
    assert_says(&r, "index    3", "restore");
    assert_says(&r, "(from the chain, never assumed)", "restore");
    assert_says(&r, "a match like any other, never a default", "restore");
    assert_says(&r, "added to the store", "restore");
}

/// `restore` never moves an account the store already holds, even when the
/// chain is ahead: that would be a silent advance, which I4 forbids.
#[test]
fn restore_does_not_touch_an_account_the_store_already_holds() {
    let (dir, r) = run_on_keeping(
        "cli-restore-held",
        Chain::new(&[(TAG, ChainState::At(addr_at(3), 11))]),
        &Command::Restore { account: 0, scan_to: None },
    );
    assert_eq!(r.code, Code::Ok, "output: {}", r.text);
    assert_says(&r, "index    3", "restore");
    assert_says(&r, "ALREADY IN THE STORE, at index 0 -- and NOT moved", "restore");
    assert_says(&r, &format!("reconcile 0x{} --advance-to 3", hexs(&TAG)), "restore");
    assert_eq!(stored_index(&dir), 0, "restore advanced an account the store already held");
}

/// A raised ceiling restores a far-along account in one write.
#[test]
fn restore_with_a_raised_ceiling_finds_a_far_along_account() {
    let fresh = |name: &str| -> (ScratchDir, Keystore) {
        let dir = ScratchDir::new(name);
        let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
        let _durable = ks.adopt_master(&master()).unwrap_or_else(|e| panic!("{e}"));
        (dir, ks)
    };
    // A ceiling the account is past: refused, counting what it walked.
    // `--scan-to 19` is a ceiling of 20.
    let (_d1, ks1) = fresh("cli-restore-far-bounded");
    let r1 = cli::run(
        ks1,
        MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(30), 11))])),
        &Command::Restore { account: 0, scan_to: Some(19) },
    );
    assert_eq!(r1.code, Code::Refused, "output: {}", r1.text);
    assert_says(&r1, "none of key indices 0 through 19", "restore far");
    assert_says(&r1, "restore --account 0 --scan-to <M>", "restore far");

    // Without `--scan-to`, the default ceiling of 10,000 finds index 30 and
    // stores the account there.
    let (d1d, ks1d) = fresh("cli-restore-far-default");
    let r1d = cli::run(
        ks1d,
        MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(30), 11))])),
        &Command::Restore { account: 0, scan_to: None },
    );
    assert_eq!(r1d.code, Code::Ok, "the default ceiling did not restore an account at index 30: {}", r1d.text);
    assert_says(&r1d, "index    30", "restore at the default ceiling");
    assert_eq!(stored_index(&d1d), 30, "the restored account is not at the found index");

    let (d2, ks2) = fresh("cli-restore-far-raised");
    let r2 = cli::run(
        ks2,
        MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(30), 11))])),
        &Command::Restore { account: 0, scan_to: Some(40) },
    );
    assert_eq!(r2.code, Code::Ok, "output: {}", r2.text);
    assert_says(&r2, "index    30", "restore --scan-to");
    assert_says(&r2, "added to the store at that index, in one write", "restore --scan-to");
    assert_eq!(stored_index(&d2), 30, "the restored account is not at the found index");
}

/// A tag the ledger does not hold has no index to derive. Fail, never zero.
#[test]
fn restore_refuses_a_tag_the_chain_does_not_hold() {
    let dir = ScratchDir::new("cli-restore-absent");
    let ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    let r = cli::run(
        ks,
        MeshClient::new(Chain::new(&[(TAG, ChainState::Absent)])),
        &Command::Restore { account: 0, scan_to: None },
    );
    assert_eq!(r.code, Code::Refused, "output: {}", r.text);
    assert_ne!(r.code, Code::Ok, "a refusal exited 0");
}

/// An unreachable chain during restore fails closed (I5).
#[test]
fn restore_fails_closed_when_the_chain_is_unreachable() {
    let dir = ScratchDir::new("cli-restore-down");
    let ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    let r = cli::run(
        ks,
        MeshClient::new(Chain::new(&[(TAG, ChainState::Unreachable)])),
        &Command::Restore { account: 0, scan_to: None },
    );
    assert_eq!(r.code, Code::Refused, "output: {}", r.text);
}

/// Restore needs the master, and says so when it is absent.
#[test]
fn restore_without_a_master_is_refused() {
    let dir = ScratchDir::new("cli-restore-nomaster");
    let ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    let r = cli::run(
        ks,
        MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(0), 1))])),
        &Command::Restore { account: 0, scan_to: None },
    );
    assert_eq!(r.code, Code::Refused, "output: {}", r.text);
    assert_says(&r, "master seed", "restore");
}

// ---------------------------------------------------------------------------
// The parser
// ---------------------------------------------------------------------------

fn argv(s: &[&str]) -> Vec<String> {
    s.iter().map(|x| (*x).to_string()).collect()
}

#[test]
fn the_parser_accepts_the_recorded_flow() {
    let inv = match args::parse(&argv(&[
        "--dir", "/tmp/d", "--node", "https://n", "send", &prefixed(&TAG), &prefixed(&TO), "1000",
    ]))
    .unwrap_or_else(|e| panic!("{e}"))
    {
        args::ParsedArgv::Run(i) => i,
        args::ParsedArgv::Help => panic!("a send invocation parsed as help"),
    };
    assert_eq!(inv.dir, "/tmp/d");
    assert_eq!(inv.node.as_deref(), Some("https://n"));
    assert_eq!(
        inv.command,
        Command::Send(Spend {
            tag: TAG,
            dsts: vec![SpendTo { to: TO, reference: [0; ADDR_REF_LEN], amount: Some(1000) }],
            fee_total: MFEE,
            blk_to_live: 0,
            expect_balance: None,
        })
    );
}

#[test]
fn the_parser_refuses_what_it_cannot_read() {
    let cases: [(&[&str], &str); 9] = [
        (&["--dir", "/d", "--node", "n"], "no command"),
        (&["--node", "n", "balance"], "--dir is required"),
        (&["--dir", "/d", "balance"], "--node is required"),
        (&["--dir", "/d", "--node", "n", "fly"], "unknown command"),
        // Without the `0x` prefix an argument is parsed as a destination.
        (&["--dir", "/d", "--node", "n", "address", "zz"], "is not a destination"),
        (&["--dir", "/d", "--node", "n", "address", "0x00"], "hex characters"),
        (
            &["--dir", "/d", "--node", "n", "address", "0xzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"],
            "not hexadecimal",
        ),
        // Bare forty-hex is refused with the fix named: half of a printed
        // ledger address is also forty hex characters.
        (
            &["--dir", "/d", "--node", "n", "address", "05ff0f69d4c1cd682ed3341c0b7773054b58800f"],
            "is a bare hex tag. Write it as `0x",
        ),
        (&["--dir", "/d", "--node", "n", "restore"], "--account"),
    ];
    for (a, needle) in cases {
        match args::parse(&argv(a)) {
            Ok(v) => panic!("{a:?} parsed to {v:?}; it should not have"),
            Err(u) => assert!(
                format!("{u}").contains(needle),
                "{a:?} was refused, but not for {needle:?}: {u}"
            ),
        }
    }
}

/// `--scan-to` on `status` and `restore`, `--advance-to` on `reconcile`: read
/// as key indices, the last index refused, and a flag where the tag should
/// be diagnosed as the missing tag.
#[test]
fn the_parser_reads_scan_to_and_refuses_the_last_index() {
    let tag = prefixed(&TAG);
    let run = |a: &[&str]| -> Command {
        match args::parse(&argv(a)).unwrap_or_else(|e| panic!("{a:?}: {e}")) {
            args::ParsedArgv::Run(i) => i.command,
            args::ParsedArgv::Help => panic!("{a:?} parsed as help"),
        }
    };
    assert_eq!(
        run(&["--dir", "/d", "--node", "n", "status", &tag, "--scan-to", "5"]),
        Command::Status { tag: TAG, scan_to: Some(5) }
    );
    assert_eq!(
        run(&["--dir", "/d", "--node", "n", "status", &tag]),
        Command::Status { tag: TAG, scan_to: None }
    );
    assert_eq!(
        run(&["--dir", "/d", "--node", "n", "restore", "--account", "0", "--scan-to", "7"]),
        Command::Restore { account: 0, scan_to: Some(7) }
    );
    assert_eq!(
        run(&["--dir", "/d", "--node", "n", "reconcile", &tag, "--advance-to", "4294967294"]),
        Command::Reconcile { tag: TAG, advance_to: u32::MAX - 1 }
    );
    let refused: [(&[&str], &str); 5] = [
        (&["--dir", "/d", "--node", "n", "reconcile", &tag, "--advance-to", "4294967295"], "out of range"),
        (&["--dir", "/d", "--node", "n", "status", &tag, "--scan-to", "4294967295"], "out of range"),
        (&["--dir", "/d", "--node", "n", "status", "--scan-to", "5"], "status needs <tag>"),
        (&["--dir", "/d", "--node", "n", "reconcile", "--advance-to", "5"], "reconcile needs <tag>"),
        (&["--dir", "/d", "--node", "n", "reconcile", &tag, "--scan-to", "5"], "unexpected argument"),
    ];
    for (a, needle) in refused {
        match args::parse(&argv(a)) {
            Ok(v) => panic!("{a:?} parsed to {v:?}; it should not have"),
            Err(u) => assert!(u.0.contains(needle), "{a:?} was refused, but not for {needle:?}: {}", u.0),
        }
    }
}

/// A typo'd flag is a usage error, not a silently ignored argument.
#[test]
fn the_parser_refuses_an_unknown_flag_rather_than_ignoring_it() {
    let r = args::parse(&argv(&[
        "--dir", "/d", "--node", "n", "send", &prefixed(&TAG), &prefixed(&TO), "1", "--fee-total", "9",
    ]));
    match r {
        Ok(v) => panic!("a typo'd flag was accepted: {v:?}"),
        Err(u) => assert!(
            format!("{u}").contains("unexpected argument"),
            "wrong refusal: {u}"
        ),
    }
}

/// Help is an outcome, not an error. All three spellings work without
/// `--dir` or `--node`. Help is recognised before the verb or as the verb;
/// after the verb it is a stray token, refused by name.
#[test]
fn help_is_reachable_without_making_a_mistake() {
    for spelling in [vec!["-h"], vec!["--help"], vec!["help"]] {
        match args::parse(&argv(&spelling)) {
            Ok(args::ParsedArgv::Help) => {}
            Ok(args::ParsedArgv::Run(i)) => panic!("{spelling:?} parsed as a command: {i:?}"),
            Err(u) => panic!("{spelling:?} was a usage error, not help: {u}"),
        }
    }
    // Before the verb of a full invocation.
    match args::parse(&argv(&["--dir", "/d", "--node", "n", "--help", "balance"])) {
        Ok(args::ParsedArgv::Help) => {}
        other => panic!("--help before a verb did not ask for help: {other:?}"),
    }
    // After the verb it is a stray token, refused by name.
    match args::parse(&argv(&["--dir", "/d", "--node", "n", "balance", "--help"])) {
        Err(u) => assert!(u.0.contains("unexpected argument `--help`"), "wrong refusal: {}", u.0),
        other => panic!("--help after the verb was not refused: {other:?}"),
    }
    assert!(
        args::HELP.contains("create") && args::HELP.contains("address"),
        "the help text does not mention the two commands that work before funding"
    );
    println!("CLI help: 4 spelling(s) reachable without a usage error");
}

/// The number of variants of the `enum` whose header is `header` in `src`:
/// lines at exactly four spaces of indent beginning with an uppercase letter
/// inside its brace-matched block. Fields sit at eight, doc comments start
/// with `/`, and the closing brace is not a letter, so nothing else counts.
fn enum_variants(src: &str, header: &str) -> usize {
    let start = src.find(header).unwrap_or_else(|| panic!("{header:?} not found in the source"));
    let rest = &src[start..];
    let open = rest.find('{').unwrap_or(0);
    let mut depth = 0usize;
    let mut end = rest.len();
    for (i, c) in rest[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = open + i;
                    break;
                }
            }
            _ => {}
        }
    }
    rest[open..end]
        .lines()
        .filter(|l| l.starts_with("    ") && !l.starts_with("     "))
        .filter(|l| l[4..].starts_with(|c: char| c.is_ascii_uppercase()))
        .count()
}

/// `--node` is required exactly where a node is used, and the help says so.
///
/// `create` and `address` need no node. The rule is `Command::needs_node`,
/// whose `match` has no wildcard, so a new verb must decide.
///
/// Every verb is listed with its minimal argv; the list is checked against
/// the `Command` variants and the `HELP` verbs so an omission fails. Without
/// `--node` the verbs that need one refuse and the others parse to
/// `node: None`; with it every verb parses and keeps it. The usage text is
/// then checked against the same rule.
#[test]
fn only_create_and_address_parse_without_a_node() {
    let tag = prefixed(&TAG);
    let to = prefixed(&TO);
    let hash = "0x18593f2f13964e5e2a07f147a7d706292f5638b3894daff55eecf3b1b812ccaf";
    let cold_claim = ["claim", tag.as_str(), "5"];
    let verbs: [(&str, Vec<&str>, bool); 26] = [
        ("create", vec!["create"], false),
        ("address", vec!["address"], false),
        ("balance", vec!["balance"], true),
        ("send", vec!["send", &tag, &to, "1"], true),
        ("settle", vec!["settle", &tag], true),
        ("resign", vec!["resign", &tag, &to, "1"], true),
        ("reconcile", vec!["reconcile", &tag, "--advance-to", "1"], true),
        ("restore", vec!["restore", "--account", "0"], true),
        ("status", vec!["status", &tag], true),
        ("submit", vec!["submit", "00"], true),
        // The five read-only verbs: they need a node but open no store
        // (`opens_no_store`).
        ("transaction", vec!["transaction", hash], true),
        ("recent-transactions", vec!["recent-transactions", &tag], true),
        ("block", vec!["block", "1078535"], true),
        ("blocks", vec!["blocks"], true),
        ("mempool", vec!["mempool"], true),
        // `discover` opens the store (for the master) and asks the node once
        // per index.
        ("discover", vec!["discover"], true),
        // The validator cold-key verbs. `import` reads its seed from the
        // terminal after the store opens; `entitlement` opens no store.
        ("import", vec!["import", "--sdk", "--account", "0"], true),
        ("set-delegate", vec!["set-delegate", &tag, &to], true),
        ("clear-delegate", vec!["clear-delegate", &tag], true),
        ("claim", cold_claim.to_vec(), true),
        ("entitlement", vec!["entitlement", &tag], true),
        // The v4.1 staking verbs. `stake-info` opens no store.
        ("stake", vec!["stake", &tag, "500000000000", "--tier", "0"], true),
        ("unstake", vec!["unstake", &tag], true),
        ("accept", vec!["accept", &tag, "--kind", "1", "--peer", &to], true),
        ("revoke", vec!["revoke", &tag], true),
        ("stake-info", vec!["stake-info", &tag], true),
    ];
    // `Command::Validator` covers three verbs (`set-delegate`,
    // `clear-delegate`, `claim`) and `Command::Staking` four (`stake`,
    // `unstake`, `accept`, `revoke`), and the one verb `reconcile` has two
    // variants (`Reconcile` and `Rollback`), so there are four fewer
    // variants than verbs.
    const VERBS_PER_VALIDATOR_VARIANT: usize = 3;
    const VERBS_PER_STAKING_VARIANT: usize = 4;
    const VARIANTS_OF_RECONCILE: usize = 2;
    // Check the table against the source: `Command`'s variants in `args.rs`
    // and the verbs in `HELP`. A new verb without a row fails here.
    let variants = enum_variants(include_str!("../src/cli/args.rs"), "pub enum Command {");
    assert_eq!(
        variants + VERBS_PER_VALIDATOR_VARIANT - 1 + VERBS_PER_STAKING_VARIANT - 1 - (VARIANTS_OF_RECONCILE - 1),
        verbs.len(),
        "`Command` has {variants} variant(s) and this table lists {}; add the verb here",
        verbs.len()
    );
    // Distinct verbs, not usage lines: `send` and `resign` each have two
    // forms (positional pairs and `--destinations <path>`).
    let help_verbs: std::collections::BTreeSet<&str> = args::HELP
        .lines()
        .filter(|l| l.starts_with("  ") && l.chars().nth(2).is_some_and(|c| c.is_ascii_lowercase()))
        .filter_map(|l| l.split_whitespace().next())
        .collect();
    assert_eq!(
        help_verbs.len(),
        verbs.len(),
        "HELP names {} verb(s) {help_verbs:?} and this table {}",
        help_verbs.len(),
        verbs.len()
    );
    let mut walked = 0usize;
    let mut without = 0usize;
    for (verb, rest, needs) in &verbs {
        walked += 1;
        let mut a = vec!["--dir", "/d"];
        a.extend(rest.iter().copied());
        match args::parse(&argv(&a)) {
            Err(u) => {
                assert!(
                    *needs,
                    "`{verb}` without --node was refused, but it needs no node: {u}"
                );
                // `u.0`, the bare message: the rendered `Usage` appends
                // `HELP`, which names every verb and would match any error.
                assert!(
                    u.0.contains(&format!("--node is required for `{verb}`")),
                    "`{verb}` without --node was refused for the wrong reason, or the refusal \
                     does not name the verb: {}",
                    u.0
                );
            }
            Ok(args::ParsedArgv::Run(inv)) => {
                assert!(
                    !*needs,
                    "`{verb}` parsed WITHOUT --node, and it reconciles against a node first: \
                     the binary would dial nothing and the command would refuse later, or \
                     worse, not refuse"
                );
                assert_eq!(inv.node, None);
                assert!(!inv.command.needs_node(), "`{verb}` parsed without a node but says it needs one");
                without += 1;
            }
            Ok(args::ParsedArgv::Help) => panic!("`{verb}` parsed as help"),
        }
        // A loopback node, which the plaintext-HTTP check allows.
        let mut b = vec!["--dir", "/d", "--node", "http://127.0.0.1:8080"];
        b.extend(rest.iter().copied());
        match args::parse(&argv(&b)) {
            Ok(args::ParsedArgv::Run(inv)) => {
                assert_eq!(inv.node.as_deref(), Some("http://127.0.0.1:8080"), "`{verb}` dropped a supplied --node");
                assert_eq!(inv.command.needs_node(), *needs, "`{verb}`'s needs_node disagrees with this table");
                // Verbs the binary runs without the password prompt.
                let opens_none = [
                    "submit",
                    "transaction",
                    "recent-transactions",
                    "block",
                    "blocks",
                    "mempool",
                    "entitlement",
                    "stake-info",
                ];
                assert_eq!(
                    inv.command.opens_no_store(),
                    opens_none.contains(verb),
                    "`{verb}`'s opens_no_store disagrees with the eight verbs whose whole input is the node"
                );
            }
            other => panic!("`{verb}` with --node did not parse to a command: {other:?}"),
        }
    }
    assert_eq!(walked, verbs.len(), "the walk did not cover every verb");
    assert_eq!(without, 2, "exactly create and address run without a node");

    // The help text must match the parser: the usage line marks the flag
    // optional and the closing sentence names the two commands that do not
    // require it.
    let usage = args::HELP.lines().next().unwrap_or_default();
    assert!(
        usage.contains("[--node <URL>]"),
        "the usage line does not mark --node optional: {usage:?}"
    );
    assert!(
        args::HELP.contains("create and address need no `--node`"),
        "the help's closing sentence no longer says which two commands run without a node"
    );
    println!("CLI node requirement: {walked} verb(s) walked, {without} run without a node");
}

/// Exit codes are distinct and a refusal is never 0.
#[test]
fn every_exit_code_is_distinct_and_no_refusal_is_zero() {
    let codes = [
        Code::Ok,
        Code::Usage,
        Code::StartupRefused,
        Code::Refused,
    ];
    let nums: Vec<i32> = codes.iter().map(|c| *c as i32).collect();
    assert_eq!(nums, vec![0, 1, 2, 3], "the exit codes moved");
    for c in &codes[1..] {
        assert_ne!(*c as i32, 0, "a refusal code is 0");
    }
    println!(
        "CLI exit codes: {} distinct, {} of them refusals, none zero",
        nums.len(),
        nums.len() - 1
    );
}

// ---------------------------------------------------------------------------
// create: the store, and the phrase
// ---------------------------------------------------------------------------

use mochimo_crypto::cli::create::{self as create_cmd, ENTROPY_LEN};

const ENTROPY: [u8; ENTROPY_LEN] = [0x5a; ENTROPY_LEN];

/// The phrase `ENTROPY` encodes, generated the way `orchestrate` generates it.
///
/// `create` takes a phrase that the caller generates and confirms before the
/// write, so the library-level tests generate it here.
fn test_phrase() -> String {
    mochimo_crypto::mnemonic::phrase_from_entropy(&ENTROPY)
        .unwrap_or_else(|e| panic!("{e}"))
        .expose()
        .to_string()
}

/// `create` over the test constants, on `dir`.
fn create_here(dir: &std::path::Path, words: &str) -> mochimo_crypto::Result<create_cmd::Created> {
    create_cmd::create(
        dir,
        words,
        keystore_harness::TEST_PASSWORD_STR,
        keystore_harness::TEST_SALT,
        keystore_harness::TEST_NONCE_SEED,
    )
}

// ---------------------------------------------------------------------------
// The password floor: counted in characters, checked at the library entry
// point and at the prompt
// ---------------------------------------------------------------------------

/// An `MIN_PASSWORD_LEN - 1`-character password whose UTF-8 is at least
/// `MIN_PASSWORD_LEN` bytes, which distinguishes a character count from a
/// byte count.
fn one_short_but_wide() -> String {
    let p = format!("{}é", "a".repeat(create_cmd::MIN_PASSWORD_LEN - 2));
    assert_eq!(p.chars().count(), create_cmd::MIN_PASSWORD_LEN - 1, "premise: one character short");
    assert!(p.len() >= create_cmd::MIN_PASSWORD_LEN, "premise: not short in bytes");
    p
}

/// The floor counts characters, not bytes, and the message says so.
///
/// The ASCII boundary from both sides; then inputs where the units differ:
/// one character short but twelve bytes wide, three emoji, four CJK
/// characters (each refused with the character count shown), and twelve
/// accented characters (accepted).
///
/// The value twelve is asserted separately; the boundary cases are built
/// from the constant.
#[test]
fn the_password_floor_counts_characters_not_bytes() {
    use create_cmd::{password_refusal, MIN_PASSWORD_LEN};
    assert_eq!(
        MIN_PASSWORD_LEN,
        12,
        "the password floor moved. Twelve is the encryption decision's floor (a floor under the search \
         space, no character-class rule); change it at cli::create::MIN_PASSWORD_LEN first, then here"
    );
    let at_floor = "a".repeat(MIN_PASSWORD_LEN);
    let one_short = "a".repeat(MIN_PASSWORD_LEN - 1);
    assert!(
        password_refusal(&at_floor).is_none(),
        "{MIN_PASSWORD_LEN} ASCII characters were refused; the floor is not inclusive"
    );
    let why = password_refusal(&one_short)
        .unwrap_or_else(|| panic!("{} ASCII characters were accepted", MIN_PASSWORD_LEN - 1));
    for needle in [
        format!("{} character", MIN_PASSWORD_LEN - 1),
        format!("fewer than {MIN_PASSWORD_LEN}"),
        "Nothing was created".to_string(),
    ] {
        assert!(why.contains(&needle), "the refusal does not say {needle:?} (the count, its unit as character, the floor): {why}");
    }

    // The discriminators: short in characters, not short in bytes.
    let wide = one_short_but_wide();
    let why = password_refusal(&wide).unwrap_or_else(|| {
        panic!(
            "{} characters were accepted because their UTF-8 is {} bytes: the floor counts bytes \
             while the message says character(s), and eleven characters with one accented \
             letter pass a twelve-character floor",
            wide.chars().count(),
            wide.len()
        )
    });
    assert!(
        why.contains(&format!("{} character", MIN_PASSWORD_LEN - 1)),
        "the count rendered is not the character count ({}): the message says character and \
         measures something else: {why}",
        MIN_PASSWORD_LEN - 1
    );
    for (label, pw) in [("three emoji", "🔑🔑🔑"), ("four CJK characters", "鍵鍵鍵鍵")] {
        assert!(pw.len() >= MIN_PASSWORD_LEN, "premise: {label} is not short in bytes");
        let why = password_refusal(pw).unwrap_or_else(|| {
            panic!("{label} ({} bytes, {} characters) were accepted", pw.len(), pw.chars().count())
        });
        assert!(
            why.contains(&format!("{} character", pw.chars().count())),
            "{label}: the character count is not what the refusal renders: {why}"
        );
    }
    // Twelve accented characters are twelve characters.
    let wide_enough = "é".repeat(MIN_PASSWORD_LEN);
    assert!(
        password_refusal(&wide_enough).is_none(),
        "{MIN_PASSWORD_LEN} accented characters were refused; the floor counts something other \
         than characters"
    );
    println!(
        "  password floor: {MIN_PASSWORD_LEN} characters inclusive; {} chars/{} bytes, three \
         emoji and four CJK refused with the character count rendered; {} accented chars accepted",
        wide.chars().count(),
        wide.len(),
        MIN_PASSWORD_LEN
    );
}

/// The library entry point `create_cmd::create` checks the floor before
/// anything is written.
///
/// Asserts the error variant with its count and floor, and that the
/// directory does not exist. The control seals at exactly the floor in
/// accented characters, so a byte-counting floor would fail both arms.
#[test]
fn create_refuses_a_short_password_and_writes_nothing() {
    use create_cmd::MIN_PASSWORD_LEN;
    let dir = ScratchDir::new("cli-create-short-pw");
    let target = dir.path().to_path_buf();
    let wide = one_short_but_wide();
    let err = create_cmd::create(
        &target,
        &test_phrase(),
        &wide,
        keystore_harness::TEST_SALT,
        keystore_harness::TEST_NONCE_SEED,
    )
    .err();
    assert!(
        matches!(
            err,
            Some(mochimo_crypto::Error::PasswordTooShort { chars, min })
                if chars == MIN_PASSWORD_LEN - 1 && min == MIN_PASSWORD_LEN
        ),
        "the library entry point sealed a store under {} characters ({} bytes), or refused it \
         under another name than PasswordTooShort {{ chars: {}, min: {MIN_PASSWORD_LEN} }}: \
         {err:?}. Only the prompt asked the floor once",
        wide.chars().count(),
        wide.len(),
        MIN_PASSWORD_LEN - 1
    );
    assert!(
        !target.exists(),
        "a store was written before the floor was asked -- {} exists after the refusal. The \
         floor must be asked before Keystore::create makes the directory",
        target.display()
    );
    let rendered = format!("{}", err.unwrap_or_else(|| panic!("checked above")));
    for needle in [
        format!("{} character", MIN_PASSWORD_LEN - 1),
        format!("fewer than {MIN_PASSWORD_LEN}"),
        "MIN_PASSWORD_LEN".to_string(),
    ] {
        assert!(rendered.contains(&needle), "the rendered error does not say {needle:?}: {rendered}");
    }

    // Control: exactly the floor, in multi-byte characters, seals a store.
    let dir2 = ScratchDir::new("cli-create-floor-pw");
    let at_floor = "é".repeat(MIN_PASSWORD_LEN);
    create_cmd::create(
        dir2.path(),
        &test_phrase(),
        &at_floor,
        keystore_harness::TEST_SALT,
        keystore_harness::TEST_NONCE_SEED,
    )
    .unwrap_or_else(|e| panic!("{MIN_PASSWORD_LEN} accented characters were refused by the library entry point: {e}"));
    assert!(dir2.path().join("accounts.mks").exists(), "the control wrote no store");
    println!(
        "  create: {} chars/{} bytes refused as PasswordTooShort with nothing written; {} accented \
         chars sealed a store",
        wide.chars().count(),
        wide.len(),
        MIN_PASSWORD_LEN
    );
}

/// The prompt refuses a short password before a phrase exists: `orchestrate`
/// with a password below the floor refuses, writes no store, and names the
/// floor.
///
/// Also: nothing was shown, no entropy was drawn, and the password was read
/// exactly once. Uses the multi-byte password so a byte-counting prompt
/// fails.
#[test]
fn orchestrate_refuses_a_short_password_before_a_phrase_exists() {
    use create_cmd::MIN_PASSWORD_LEN;
    let dir = ScratchDir::new("cli-create-short-orch");
    let target = dir.path().to_path_buf();
    let shown: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let log = Rc::clone(&shown);
    let reads = Rc::new(RefCell::new(Vec::new()));
    let rl = Rc::clone(&reads);
    let entropy_taken = Rc::new(RefCell::new(false));
    let taken = Rc::clone(&entropy_taken);
    let wide = one_short_but_wide();
    let r = create_cmd::orchestrate(
        &target,
        false,
        || {
            *taken.borrow_mut() = true;
            Ok(zeroize::Zeroizing::new(test_create_entropy()))
        },
        || Ok(Recorder::watching(log, vec![wide.clone(), wide.clone(), "never asked".into()], rl)),
    );
    assert_eq!(r.code, Code::Refused, "output: {}", r.text);
    assert_says(&r, &format!("{} character", MIN_PASSWORD_LEN - 1), "the short-password refusal");
    assert_says(&r, &format!("fewer than {MIN_PASSWORD_LEN}"), "the short-password refusal");
    assert_says(&r, "Nothing was created", "the short-password refusal");
    assert!(
        !target.exists(),
        "a store was written under a password below the floor: {} exists",
        target.display()
    );
    assert!(
        shown.borrow().is_empty(),
        "a phrase was shown before the password was refused: {:?}. The early copy exists so \
         the operator is told before a phrase exists for a store that never will",
        shown.borrow()
    );
    assert!(!*entropy_taken.borrow(), "entropy was drawn before the password was refused");
    assert_eq!(
        reads.borrow().len(),
        1,
        "the password was read {} time(s); a password below the floor is read once and refused, \
         not confirmed: {:?}",
        reads.borrow().len(),
        reads.borrow()
    );
    println!(
        "  orchestrate: {} chars/{} bytes refused at the first read; nothing shown, no entropy \
         drawn, nothing written",
        wide.chars().count(),
        wide.len()
    );
}

/// `create` makes the store from a phrase and derives account 0 of it.
/// Deterministic because the entropy behind the phrase is a parameter. The
/// write takes the phrase as input and returns nothing secret.
#[test]
fn create_makes_a_store_holding_account_0_of_the_phrase() {
    let dir = ScratchDir::new("cli-create");
    let phrase = test_phrase();
    assert_eq!(
        phrase.split_whitespace().count(),
        24,
        "32 bytes of entropy is BIP39's 24-word case"
    );
    let c = create_here(dir.path(), &phrase).unwrap_or_else(|e| panic!("{e}"));
    // The account is really in the store, and it is account 0 of that phrase.
    let ks = reopen("cli flow 1", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let view = ks
        .view(&c.tag)
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("account 0 is not in the store"));
    assert_eq!(view.wots_index.get(), 0, "a fresh account is at position 0");
    let m = mochimo_crypto::mnemonic::master_seed_from_phrase(&phrase, "")
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        c.tag,
        mochimo_crypto::derive::derive_account_tag(&m, 0),
        "the tag is not account 0 of the phrase that was shown"
    );
}

/// One phrase, two stores, one account 0: a phrase whose store was refused
/// or never written recovers the same wallet with `create --from-phrase`.
#[test]
fn the_same_phrase_makes_the_same_account_0_in_any_store() {
    let dir = ScratchDir::new("cli-create-supplied");
    let seed = ScratchDir::new("cli-create-supplied-src");
    let phrase = test_phrase();
    let src = create_here(seed.path(), &phrase).unwrap_or_else(|e| panic!("{e}"));
    let c = create_here(dir.path(), &phrase).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(c.tag, src.tag, "the same phrase produced a different account 0");
}

/// An existing store is refused, and `Keystore::create` is what refuses it.
#[test]
fn create_refuses_an_existing_store() {
    let dir = ScratchDir::new("cli-create-twice");
    let phrase = test_phrase();
    create_here(dir.path(), &phrase).unwrap_or_else(|e| panic!("{e}"));
    // The refusal must come from `Keystore::create`'s snapshot check, not
    // from `add` refusing a duplicate tag. Both are `Error::Exists` and
    // differ only in `what`, so `what` is checked.
    match create_here(dir.path(), &phrase) {
        Ok(_) => panic!("a second create over the same directory succeeded"),
        Err(mochimo_crypto::Error::Exists { what: "snapshot" }) => {}
        Err(e) => panic!(
            "the second create was refused, but not by Keystore::create's snapshot check: \
             {e:?}. A refusal from `add` means the store was opened rather than refused."
        ),
    }
}

/// The confirmation checks the words it says it checks, and nothing more.
#[test]
fn the_confirmation_wants_those_three_words_and_no_others() {
    let _dir = ScratchDir::new("cli-create-confirm");
    let phrase = mochimo_crypto::mnemonic::phrase_from_entropy(&ENTROPY)
        .unwrap_or_else(|e| panic!("{e}"));
    let words: Vec<&str> = phrase.expose().split_whitespace().collect();
    let p = create_cmd::CONFIRM_POSITIONS;
    let right = format!("{} {} {}", words[p[0] - 1], words[p[1] - 1], words[p[2] - 1]);
    assert!(create_cmd::confirmation_matches(phrase.expose(), &right));
    assert!(
        create_cmd::confirmation_matches(phrase.expose(), &right.to_uppercase()),
        "case should not matter for a transcribed word"
    );
    assert!(!create_cmd::confirmation_matches(phrase.expose(), "abandon abandon abandon"));
    assert!(
        !create_cmd::confirmation_matches(phrase.expose(), &format!("{right} extra")),
        "a fourth word should not pass"
    );
    assert!(!create_cmd::confirmation_matches(phrase.expose(), ""));
    println!(
        "create confirmation: {} position(s) checked, {} rejection case(s)",
        p.len(),
        4
    );
}

// ---------------------------------------------------------------------------
// The full flow from an empty directory
// ---------------------------------------------------------------------------

/// create -> address -> the chain funds that address -> balance -> send ->
/// settle, in one test, with every step going through the CLI.
#[test]
fn the_whole_flow_from_an_empty_directory_to_a_settled_spend() {
    let dir = ScratchDir::new("cli-flow");

    // 1. create -- no chain involved at all. The phrase is generated here,
    //    as `orchestrate` generates it, and handed to the write.
    let phrase = test_phrase();
    let c = create_here(dir.path(), &phrase).unwrap_or_else(|e| panic!("{e}"));
    let m = mochimo_crypto::mnemonic::master_seed_from_phrase(&phrase, "")
        .unwrap_or_else(|e| panic!("{e}"));
    let tag = c.tag;

    // 2. address -- before the tag exists on any chain.
    let ks = reopen("cli flow 2", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let unfunded = Chain::new(&[(tag, ChainState::Absent)]);
    let r = cli::run(ks, MeshClient::new(unfunded), &Command::Address { tag: Some(tag), account: None });
    assert_eq!(r.code, Code::Ok, "address failed on an unfunded tag: {}", r.text);
    let addr0 = mochimo_crypto::recon::derived_address_at(
        &m,
        0,
        mochimo_crypto::account::WotsIndex::ZERO,
    );
    assert_says(&r, &hexs(&addr0), "the address to fund");

    // The destination as an operator copies it: the first line of output.
    let printed = r.text.lines().next().unwrap_or("").to_string();

    // 3. the chain funds that printed string, through an entry point that
    //    takes only the destination form.
    let funded = || {
        let c = Chain::new(&[]);
        let credited = c
            .credit_destination(&printed, addr0, 5_000_000)
            .unwrap_or_else(|e| panic!("{e}"));
        // The decoded string is the stored tag. An encoding wrong in both
        // directions would still pass; the group C KAT covers that.
        assert_eq!(
            credited, tag,
            "the destination the CLI printed (`{printed}`) decodes to a different tag than the \
             store holds; funds sent to it would be irrecoverable"
        );
        c
    };

    // 4. balance -- the first command that opens a Wallet.
    let ks = reopen("cli flow 3", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let r = cli::run(ks, MeshClient::new(funded()), &Command::Balance);
    assert_eq!(r.code, Code::Ok, "balance refused after funding: {}", r.text);
    assert_says(&r, "5000000", "balance");

    // 5. send. The id comes from a dry run that advances this store, so the
    // CLI's send runs on a second store made from the same entropy.
    let spend = Spend { tag, dsts: vec![SpendTo { to: TO, reference: [0; ADDR_REF_LEN], amount: Some(1_000) }], fee_total: MFEE, blk_to_live: 0, expect_balance: None };
    let id = {
        let ks2 = reopen("cli flow 5", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
        let mut w = Wallet::open(ks2, MeshClient::new(funded()), Some(&m))
            .unwrap_or_else(|e| panic!("{e}"));
        let plan = w
            .plan(
                &tag,
                &KeyAccess::Master(&m),
                vec![Destination { tag: TO, reference: [0; 16], amount: 1_000 }],
                MFEE,
                0,
            )
            .unwrap_or_else(|e| panic!("{e}"));
        w.reserve_and_sign(&plan, KeyAccess::Master(&m))
            .unwrap_or_else(|e| panic!("{e}"))
            .id()
            .0
    };
    // That dry run advanced its own copy of the store; take a fresh one.
    let dir2 = ScratchDir::new("cli-flow-send");
    let c2 = create_here(dir2.path(), &phrase).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(c2.tag, tag, "the same entropy made a different account");
    let ks = reopen("cli flow 6", dir2.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let chain = funded();
    chain.accepts_submit(id);
    let r = cli::run(ks, MeshClient::new(chain), &Command::Send(spend));
    assert_eq!(r.code, Code::Ok, "send failed: {}", r.text);
    assert_says(&r, "THIS IS NOT ACCEPTANCE OF THE TRANSACTION", "send");
    // The destination is shown in checksummed form, whichever form was typed.
    let to_dest = mochimo_crypto::addr::tag_to_base58(&TO).unwrap_or_else(|e| panic!("{e}"));
    assert_says(&r, &to_dest, "send's destination read-back");

    // The `settle` argument is taken from the rendered text, as an operator
    // would copy it, and parsed with `args::parse`: the renderer and the
    // parser must agree.
    let settle_arg = r
        .text
        .split("Run `settle ")
        .nth(1)
        .and_then(|t| t.split('`').next())
        .unwrap_or_else(|| panic!("send did not print a `settle` hint:\n{}", r.text))
        .trim()
        .to_string();
    match args::parse(&argv(&["--dir", "/d", "--node", "n", "settle", &settle_arg])) {
        Ok(args::ParsedArgv::Run(i)) => assert_eq!(
            i.command,
            Command::Settle { tag },
            "the `settle` argument this program printed parses to a different tag than the \
             store holds: {settle_arg}"
        ),
        other => panic!("the printed `settle {settle_arg}` did not parse: {other:?}"),
    }

    // 6. settle -- the chain has moved to the change key.
    let addr1 = mochimo_crypto::recon::derived_address_at(
        &m,
        0,
        mochimo_crypto::account::WotsIndex::ZERO.advanced().unwrap_or_else(|e| panic!("{e}")),
    );
    let ks = reopen("cli flow 7", dir2.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let r = cli::run(
        ks,
        MeshClient::new(Chain::new(&[(tag, ChainState::At(addr1, 4_000_000))])),
        &Command::Settle { tag },
    );
    assert_eq!(r.code, Code::Ok, "settle failed: {}", r.text);
    assert_says(&r, "settled", "settle");

    // 7. send again: the retained settled block must not freeze the account.
    //    Through a refusing socket: exit 3 with the artifact on the page, and
    //    the store at index 2 with a reservation open. A freeze
    //    (`PendingUnresolved` before reserving) fails all three.
    let ks = reopen("cli flow 8", dir2.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let chain = Chain::new(&[(tag, ChainState::At(addr1, 4_000_000))]);
    chain.refuses_submit();
    let r = cli::run(
        ks,
        MeshClient::new(chain),
        &Command::Send(Spend { tag, dsts: vec![SpendTo { to: TO, reference: [0; ADDR_REF_LEN], amount: Some(1_000) }], fee_total: MFEE, blk_to_live: 0, expect_balance: None }),
    );
    assert_eq!(r.code, Code::Refused, "step 7: a send through a refusing socket exits 3:\n{}", r.text);
    assert_says(&r, "RETRY ARTIFACT", "step 7: the second spend was planned, reserved and signed");
    let ks = reopen("cli flow 9", dir2.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let v = ks
        .view(&tag)
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("step 7: the store no longer holds the account"));
    assert_eq!(
        (v.wots_index.get(), v.pending.is_some(), v.settled.is_some()),
        (2, true, false),
        "step 7: the second send did not advance the store past the retained settled block and \
         release it -- the freeze the retained block must not cause"
    );
    drop(ks);

    println!(
        "CLI flow: 7 step(s) from an empty directory to a settled spend and a second spend, 0 \
         reaching around the CLI"
    );
}

// ---------------------------------------------------------------------------
// The absent terminal
// ---------------------------------------------------------------------------

use std::cell::RefCell;
use std::rc::Rc;

/// A terminal that records what it was shown and answers from a script.
///
/// The `shown` log is shared with the test through an `Rc`.
struct Recorder {
    shown: Rc<RefCell<Vec<String>>>,
    answers: Vec<String>,
    /// Which read each prompt went through, in order: `"secret"` for the
    /// echo-off read and `"visible"` for the echoing one. Both return answers
    /// from the same script, so only this log shows which read ran.
    reads: Rc<RefCell<Vec<(&'static str, String)>>>,
}

impl Recorder {
    fn new(shown: Rc<RefCell<Vec<String>>>, answers: Vec<String>) -> Recorder {
        Recorder {
            shown,
            answers,
            reads: Rc::new(RefCell::new(Vec::new())),
        }
    }
    fn watching(
        shown: Rc<RefCell<Vec<String>>>,
        answers: Vec<String>,
        reads: Rc<RefCell<Vec<(&'static str, String)>>>,
    ) -> Recorder {
        Recorder {
            shown,
            answers,
            reads,
        }
    }
}

impl create_cmd::Terminal for Recorder {
    fn show(&mut self, text: &str) -> Result<(), String> {
        self.shown.borrow_mut().push(text.to_string());
        Ok(())
    }
    fn read_secret_line(&mut self, prompt: &str) -> Result<zeroize::Zeroizing<String>, String> {
        self.reads.borrow_mut().push(("secret", prompt.to_string()));
        if self.answers.is_empty() {
            return Err("test: the script ran out of answers".into());
        }
        Ok(zeroize::Zeroizing::new(self.answers.remove(0)))
    }
    /// The confirmation's read, which the trait takes by value.
    ///
    /// Answers from the same script and records which read ran. That nothing
    /// can be read afterwards is enforced by the signature (see
    /// `ui/fail/terminal_cannot_read_a_secret_after_the_visible_read.rs`).
    fn read_visible_line(mut self, prompt: &str) -> Result<zeroize::Zeroizing<String>, String> {
        self.reads.borrow_mut().push(("visible", prompt.to_string()));
        if self.answers.is_empty() {
            return Err("test: the script ran out of answers".into());
        }
        Ok(zeroize::Zeroizing::new(self.answers.remove(0)))
    }
}

/// With no controlling terminal, `create` writes nothing and shows no phrase.
/// The exit code alone would not show whether a store was written or a
/// phrase printed before the failure.
#[test]
fn create_without_a_terminal_writes_nothing_and_shows_no_phrase() {
    let dir = ScratchDir::new("cli-create-no-tty");
    let target = dir.path().to_path_buf();
    assert!(!target.exists(), "the target must not exist beforehand");

    let shown: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let entropy_taken = Rc::new(RefCell::new(false));
    let taken = Rc::clone(&entropy_taken);

    let r = create_cmd::orchestrate(
        &target,
        false,
        || {
            *taken.borrow_mut() = true;
            Ok(zeroize::Zeroizing::new(test_create_entropy()))
        },
        || {
            Err::<Recorder, String>(
                "cannot open /dev/tty: Device not configured (os error 6)".into(),
            )
        },
    );

    assert_eq!(r.code, Code::Refused, "output: {}", r.text);
    // The store must not exist.
    assert!(
        !target.exists(),
        "THE STORE WAS WRITTEN BEFORE THE TERMINAL WAS ACQUIRED -- {} exists after a refusal \
         that had nowhere to confirm a phrase. This is the store-before-terminal defect.",
        target.display()
    );
    // Nothing was displayed.
    assert!(
        shown.borrow().is_empty(),
        "something was shown despite there being no terminal: {:?}",
        shown.borrow()
    );
    // No entropy was drawn: terminal acquisition comes first.
    assert!(
        !*entropy_taken.borrow(),
        "entropy was drawn before the terminal was acquired"
    );
    assert!(
        r.text.contains("/dev/tty"),
        "the refusal does not name the cause: {}",
        r.text
    );
    // Every `create` refusal ends with this sentence, appended centrally.
    assert_says(&r, "Nothing was created", "the no-terminal refusal");
    // `shown` sees only output through the `Terminal` trait. Direct prints
    // in `cli/create.rs` are forbidden by
    // `invariants.rs::the_cli_cannot_reach_around_the_wallet`.
    println!(
        "create without a terminal: store absent, {} thing(s) shown, entropy drawn: {}",
        shown.borrow().len(),
        *entropy_taken.borrow()
    );
}

/// `create --from-phrase` states which derivation scheme it restores before
/// it reads anything.
///
/// Mochimo wallets differ in how a phrase becomes a seed; a phrase from
/// another scheme derives a valid but empty store with no error. The script
/// has no answers, so the first read fails and anything shown was shown
/// before the password and the words.
#[test]
fn create_from_phrase_warns_about_the_derivation_scheme_before_any_read() {
    let dir = ScratchDir::new("cli-create-scheme-warning");
    let shown: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let log = Rc::clone(&shown);

    let r = create_cmd::orchestrate(
        dir.path(),
        true,
        || Ok(zeroize::Zeroizing::new(test_create_entropy())),
        || Ok(Recorder::new(log, Vec::new())),
    );
    assert_eq!(r.code, Code::Refused, "the empty script should have refused: {}", r.text);

    let first = shown
        .borrow()
        .first()
        .cloned()
        .unwrap_or_else(|| panic!("nothing was shown before the first read; the warning cannot be read after the phrase is typed"));

    for needle in [
        "one derivation scheme",
        "browser extension",
        "no error",
        "empty",
    ] {
        assert!(
            first.contains(needle),
            "the scheme warning does not carry {needle:?}:\n{first}"
        );
    }
    // It must not say the phrase will be rejected: nothing rejects it.
    for stale in ["unsupported", "invalid phrase", "will fail"] {
        assert!(!first.contains(stale), "the warning promises an error the operator will not see: {first}");
    }
    assert!(
        !dir.path().join("accounts.mks").exists(),
        "a store was written by a run whose reads all failed"
    );
    println!("  create --from-phrase: the scheme warning is shown before the first read");
}

/// Control: with a terminal, the same call writes the store and shows the
/// phrase.
#[test]
fn create_with_a_terminal_writes_the_store_and_shows_the_phrase_once() {
    let dir = ScratchDir::new("cli-create-tty");
    let target = dir.path().to_path_buf();
    let shown: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let log = Rc::clone(&shown);

    // The confirmation is answered from the phrase the run itself produces:
    // derive it the same way `create` does, from the same entropy.
    let expected = mochimo_crypto::mnemonic::phrase_from_entropy(&ENTROPY)
        .unwrap_or_else(|e| panic!("{e}"));
    let words: Vec<&str> = expected.expose().split_whitespace().collect();
    let p = create_cmd::CONFIRM_POSITIONS;
    let answer = format!("{} {} {}", words[p[0] - 1], words[p[1] - 1], words[p[2] - 1]);

    let r = create_cmd::orchestrate(
        &target,
        false,
        || Ok(zeroize::Zeroizing::new(test_create_entropy())),
        || {
            Ok(Recorder::new(log, password_then(vec![answer])))
        },
    );
    assert_eq!(r.code, Code::Ok, "output: {}", r.text);
    assert!(target.join("accounts.mks").exists(), "no store was written");
    assert_eq!(shown.borrow().len(), 1, "the phrase should be shown exactly once");
    assert!(
        shown.borrow()[0].contains("WRITE THIS DOWN"),
        "what was shown is not the phrase notice: {:?}",
        shown.borrow()[0]
    );
    assert_says(&r, "confirmed", "create");
    // `create` prints a destination and not the hex tag. The tag is
    // recomputed from the entropy, independently of the report.
    let tag = mochimo_crypto::mnemonic::master_seed_from_phrase(expected.expose(), "")
        .map(|m| mochimo_crypto::derive::derive_account_tag(&m, 0))
        .unwrap_or_else(|e| panic!("{e}"));
    let dest = mochimo_crypto::addr::tag_to_base58(&tag).unwrap_or_else(|e| panic!("{e}"));
    assert_says(&r, &dest, "create");
    assert!(
        !r.text.contains(&hexs(&tag)),
        "create prints the hex tag beside the destination -- two spellings of one identifier \
         is what the shipped wallet refused:\n{}",
        r.text
    );
}

/// A wrong confirmation refuses and leaves nothing on disk.
///
/// A store left behind would hold a phrase nobody confirmed. An operator who
/// did record the phrase rebuilds the same store with `create --from-phrase`
/// (see `the_same_phrase_makes_the_same_account_0_in_any_store`). Asserts the
/// exit code and that the directory is absent.
#[test]
fn a_wrong_confirmation_refuses_and_leaves_nothing_on_disk() {
    let dir = ScratchDir::new("cli-create-badconfirm");
    let target = dir.path().to_path_buf();
    let shown: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let log = Rc::clone(&shown);
    let r = create_cmd::orchestrate(
        &target,
        false,
        || Ok(zeroize::Zeroizing::new(test_create_entropy())),
        || {
            Ok(Recorder::new(log, password_then(vec!["abandon abandon abandon".into()])))
        },
    );
    assert_eq!(r.code, Code::Refused, "output: {}", r.text);
    assert!(
        !target.exists(),
        "THE STORE WAS WRITTEN BEFORE THE CONFIRMATION -- {} exists after a refused \
         confirmation. The exit code says refused and the filesystem says created, which is \
         the pair the confirm-before-write order removed.",
        target.display()
    );
    assert_eq!(shown.borrow().len(), 1, "the phrase is shown before the confirmation");
    assert_says(&r, "Nothing was created", "a wrong confirmation");
    assert_says(&r, "create --from-phrase", "a wrong confirmation's route back");
    assert!(
        !r.text.contains("WAS created"),
        "the refusal claims a store exists:\n{}",
        r.text
    );
}

/// A display that fails refuses before anything is written.
///
/// `show` returns a `Result`, so a failed display (for example a read-only
/// descriptor) is refused before the confirmation, with nothing on disk.
#[test]
fn a_display_that_fails_refuses_with_nothing_written() {
    struct Mute {
        inner: Recorder,
    }
    impl create_cmd::Terminal for Mute {
        fn show(&mut self, _text: &str) -> Result<(), String> {
            Err("cannot write to /dev/tty: Bad file descriptor (os error 9)".into())
        }
        fn read_secret_line(&mut self, prompt: &str) -> Result<zeroize::Zeroizing<String>, String> {
            self.inner.read_secret_line(prompt)
        }
        fn read_visible_line(self, prompt: &str) -> Result<zeroize::Zeroizing<String>, String> {
            self.inner.read_visible_line(prompt)
        }
    }
    let dir = ScratchDir::new("cli-create-mute");
    let target = dir.path().to_path_buf();
    let shown: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let log = Rc::clone(&shown);
    let confirmed = Rc::new(RefCell::new(Vec::new()));
    let reads = Rc::clone(&confirmed);
    let r = create_cmd::orchestrate(
        &target,
        false,
        || Ok(zeroize::Zeroizing::new(test_create_entropy())),
        || {
            Ok(Mute {
                inner: Recorder::watching(log, password_then(vec!["never asked".into()]), reads),
            })
        },
    );
    assert_eq!(r.code, Code::Refused, "output: {}", r.text);
    assert!(
        !target.exists(),
        "a store was written although the phrase could not be shown: {}",
        target.display()
    );
    assert_says(&r, "Bad file descriptor", "a failed display");
    assert_says(&r, "Nothing was created", "a failed display");
    assert!(
        !confirmed.borrow().iter().any(|(kind, _)| *kind == "visible"),
        "the confirmation was asked after the display failed: {:?}",
        confirmed.borrow()
    );
}

/// A phrase the parser refuses leaves nothing on disk.
///
/// The phrase is parsed before `Keystore::create` makes the directory, so a
/// mistyped phrase leaves no empty store or lock file behind. Asserts the
/// result and that the directory is absent.
#[test]
fn a_refused_phrase_leaves_nothing_on_disk() {
    // Twenty-four valid words with a wrong checksum (the valid vector ends
    // in "art").
    let bad = ["abandon"; 24].join(" ");

    // The library entry point.
    let dir = ScratchDir::new("cli-create-badphrase");
    let err = match create_here(dir.path(), &bad) {
        Ok(_) => panic!("a bad checksum must refuse"),
        Err(e) => e,
    };
    assert!(
        matches!(err, mochimo_crypto::Error::Mnemonic { what: "checksum mismatch" }),
        "refused for the wrong reason: {err:?}"
    );
    assert!(
        !dir.path().exists(),
        "A STORE EXISTS after a refused phrase: {} holds {:?}. The keystore was sealed before \
         the words were parsed, so a typo in twenty-four words leaves an empty store that \
         refuses the retry as `already exists`.",
        dir.path().display(),
        dir.listing()
    );

    // The orchestrated `--from-phrase` path, with the text the operator reads.
    let dir2 = ScratchDir::new("cli-create-badphrase-orchestrated");
    let shown: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let log = Rc::clone(&shown);
    let r = create_cmd::orchestrate(
        dir2.path(),
        true,
        || Ok(zeroize::Zeroizing::new(test_create_entropy())),
        || Ok(Recorder::new(log, password_then(vec![bad.clone()]))),
    );
    assert_eq!(r.code, Code::Refused, "output: {}", r.text);
    assert!(
        !dir2.path().exists(),
        "A STORE EXISTS after a refused phrase through --from-phrase: {} holds {:?}",
        dir2.path().display(),
        dir2.listing()
    );
    assert_says(&r, "checksum mismatch", "a refused phrase");
    assert_says(&r, "Nothing was created", "a refused phrase");
    // Only the derivation-scheme warning is shown, before any read. The
    // phrase is never displayed back.
    let shown = shown.borrow();
    assert_eq!(shown.len(), 1, "more than the scheme warning was shown: {shown:?}");
    assert!(shown[0].starts_with("BEFORE YOU TYPE:"), "what was shown is not the scheme warning: {shown:?}");
    assert!(
        !shown[0].contains(bad.split_whitespace().next().unwrap_or("?")),
        "the supplied phrase reached the screen: {shown:?}"
    );
}

// ---------------------------------------------------------------------------
// The destination identifier
// ---------------------------------------------------------------------------
//
// Destinations are the Base58 tag form (22 to 31 characters) that other
// Mochimo wallets use. The codec is `addr::{tag_to_base58, tag_from_base58}`.
//
// * The round trip in the flow test (through `credit_destination`) catches an
//   error in one direction only.
// * The KAT below catches an error shared by encoder and decoder. Group C's
//   strings come from the reference; `C9`'s is also checked against the
//   TypeScript implementation.

/// Group C, embedded at compile time.
const GROUP_C: &str = include_str!("../../../fixtures/group_c_addr.json");

/// Group CX: values returned by executing the TypeScript functions
/// `TagUtils.addrTagToBase58`, `bs58.decode`, `validateBase58Tag` and
/// `base58ToAddrTag`. Unlike group C's transcribed
/// `crosscheck_typescript_expected`, these come from an independent
/// implementation.
const GROUP_CX: &str = include_str!("../../../fixtures/group_c_crosscheck.json");

fn group_c() -> serde_json::Value {
    serde_json::from_str(GROUP_C).unwrap_or_else(|e| panic!("group_c_addr.json parses: {e}"))
}

fn group_cx() -> serde_json::Value {
    serde_json::from_str(GROUP_CX)
        .unwrap_or_else(|e| panic!("group_c_crosscheck.json parses: {e}"))
}

fn unhex_tag(s: &str) -> [u8; ADDR_TAG_LEN] {
    let mut out = [0u8; ADDR_TAG_LEN];
    let b = s.as_bytes();
    assert_eq!(b.len(), ADDR_TAG_LEN * 2, "not a 20-byte hex tag: {s}");
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .unwrap_or_else(|e| panic!("bad hex in {s}: {e}"));
    }
    out
}

/// KAT: every group C Base58 encoding of a 22-byte tag payload, plus the
/// thousand-entry corpus, through `addr::tag_to_base58` and back through
/// `addr::tag_from_base58`. Expected values are the reference's
/// `crc16 + put16 + base58_encode` output.
#[test]
fn the_destination_matches_every_group_c_vector() {
    let root = group_c();
    let mut vectors = 0usize;
    let mut crosschecked = 0usize;
    for v in root["vectors"]
        .as_array()
        .unwrap_or_else(|| panic!("group C has a vectors array"))
    {
        let (Some(tag_hex), Some(expected)) = (
            v.get("tag").and_then(|t| t.as_str()),
            v.get("base58_of_tag22").and_then(|t| t.as_str()),
        ) else {
            continue;
        };
        let id = v["id"].as_str().unwrap_or("?");
        let tag = unhex_tag(tag_hex);
        let got = mochimo_crypto::addr::tag_to_base58(&tag)
            .unwrap_or_else(|e| panic!("{id}: tag_to_base58: {e}"));
        assert_eq!(
            got, expected,
            "{id}: the destination this crate renders is not the one the reference emitted for \
             tag {tag_hex}"
        );
        let back = mochimo_crypto::addr::tag_from_base58(expected)
            .unwrap_or_else(|e| panic!("{id}: the reference's own string was refused: {e}"));
        assert_eq!(back, tag, "{id}: the reference's string decodes to a different tag");
        vectors += 1;
    }
    // The corpus: 1000 tags, each the first 20 bytes of a reference sha256,
    // with the reference's own crc16 and base58 beside them.
    let entries = root["crc16_base58_corpus"]["entries"]
        .as_array()
        .unwrap_or_else(|| panic!("group C carries crc16_base58_corpus.entries"));
    let mut walked = 0usize;
    for e in entries {
        let tag = unhex_tag(e["tag"].as_str().unwrap_or_else(|| panic!("corpus entry has a tag")));
        let expected = e["base58"].as_str().unwrap_or_else(|| panic!("corpus entry has base58"));
        let got = mochimo_crypto::addr::tag_to_base58(&tag)
            .unwrap_or_else(|e| panic!("corpus tag_to_base58: {e}"));
        assert_eq!(got, expected, "corpus entry {}: destination", e["i"]);
        assert_eq!(
            mochimo_crypto::addr::tag_from_base58(expected).unwrap_or_else(|e| panic!("{e}")),
            tag,
            "corpus entry {}: round trip", e["i"]
        );
        walked += 1;
    }
    // Minimum counts: group C has four `base58_of_tag22` vectors (C7, C8, C9,
    // C10) and the corpus declares its own count.
    assert_eq!(
        vectors, 4,
        "expected the four group C vectors carrying base58_of_tag22 (C7, C8, C9, C10); walked \
         {vectors}. A walk that shrank is a walk that stopped checking."
    );
    // Independent check: `crosscheck_typescript_executed` in group CX is
    // what `TagUtils.addrTagToBase58` returned when run.
    for v in group_cx()["vectors"].as_array().unwrap_or(&Vec::new()) {
        let (Some(hex), Some(executed)) = (
            v.get("input_hex").and_then(|t| t.as_str()),
            v.get("crosscheck_typescript_executed").and_then(|t| t.as_str()),
        ) else {
            continue;
        };
        if hex.len() != ADDR_TAG_LEN * 2 || !v["source"].as_str().unwrap_or("").contains("addrTagToBase58") {
            continue;
        }
        let id = v["id"].as_str().unwrap_or("?");
        let got = mochimo_crypto::addr::tag_to_base58(&unhex_tag(hex))
            .unwrap_or_else(|e| panic!("{id}: {e}"));
        assert_eq!(
            got, executed,
            "{id}: this crate disagrees with what TagUtils.addrTagToBase58 RETURNED for {hex}"
        );
        crosschecked += 1;
    }
    assert!(
        crosschecked >= 4,
        "only {crosschecked} executed-TypeScript encodings were replayed; expected CX-C7, \
         CX-C8, CX-C9 and CX-C10. Without them every value here traces to the same C and the \
         agreement is a self-comparison."
    );
    let declared = root["crc16_base58_corpus"]["count"].as_u64().unwrap_or(0) as usize;
    assert_eq!(
        walked, declared,
        "the corpus declares {declared} entries and the walk saw {walked}"
    );
    assert!(walked >= 1000, "the corpus shrank to {walked}");
    println!(
        "  destination KAT: {vectors} group C vector(s), {crosschecked} replayed against \
         EXECUTED TypeScript return values, {walked} corpus entries"
    );
}

/// Where this crate deliberately diverges from the TypeScript implementation,
/// checked against group CX.
///
/// In `tag-utils.ts`, `validateBase58Tag` checks the CRC16 while
/// `base58ToAddrTag` checks only the 22-byte length and returns the tag
/// unvalidated. `addr::tag_from_base58` does both and refuses on a checksum
/// mismatch. Group CX records both TypeScript results per string.
#[test]
fn the_decoder_agrees_with_the_shipped_typescript_except_where_it_deliberately_does_not() {
    let mut agreed = 0usize;
    let mut diverged = 0usize;
    for v in group_cx()["vectors"].as_array().unwrap_or(&Vec::new()) {
        let (Some(input), Some(valid)) = (
            v.get("input_base58").and_then(|t| t.as_str()),
            v.get("validate_base58_tag").and_then(serde_json::Value::as_bool),
        ) else {
            continue;
        };
        let id = v["id"].as_str().unwrap_or("?");
        let ours = mochimo_crypto::addr::tag_from_base58(input);
        if valid {
            // Where the TypeScript validates, accept and return the
            // same twenty bytes it returned.
            let want = v["base58_to_addr_tag"]
                .as_str()
                .unwrap_or_else(|| panic!("{id}: validate_base58_tag is true with no tag beside it"));
            let got = ours.unwrap_or_else(|e| {
                panic!("{id}: the TypeScript validated `{input}` and this crate refused it: {e}")
            });
            assert_eq!(
                hexs(&got), want,
                "{id}: both accept `{input}` and they return different tags"
            );
            agreed += 1;
        } else {
            // Where it does not validate, refuse, even where
            // `base58ToAddrTag` still returns a tag (CX-C12).
            assert!(
                ours.is_err(),
                "{id}: `{input}` fails validateBase58Tag and this crate accepted it. The CRC16 \
                 is the only thing between a mistyped destination and a payment nobody can \
                 recover; fusing validate with decode is the whole point."
            );
            if v.get("base58_to_addr_tag").and_then(|t| t.as_str()).is_some() {
                diverged += 1;
            }
        }
    }
    assert!(
        agreed >= 3,
        "only {agreed} vector(s) had both implementations accepting; the agreement half of this \
         walk is nearly empty and the divergence half then proves only that we refuse things"
    );
    assert!(
        diverged >= 1,
        "no vector recorded the TypeScript RETURNING a tag for a string it did not validate. \
         CX-C12 is that vector, and without it this test does not measure the divergence it is \
         named for -- it just agrees with the reference."
    );
    println!(
        "  decoder vs shipped TypeScript: {agreed} agreement(s), {diverged} recorded divergence(s) \
         (validateBase58Tag false, base58ToAddrTag returns a tag, we refuse)"
    );
}

/// The two accepted forms cannot collide.
///
/// A bare hex tag is forty characters; `addr::TAG_BASE58_MAX_CHARS` is
/// thirty-one. Also checked: no forty-character Base58 string decodes to
/// twenty-two bytes.
#[test]
fn the_two_destination_forms_cannot_collide() {
    use mochimo_crypto::addr::{TAG_BASE58_MAX_CHARS, TAG_BASE58_MIN_CHARS};

    // 1. The fixtures bound the window at both ends: C7's all-zero tag is the
    //    shortest 22-byte encoding (one '1' per leading zero byte) and C8's
    //    all-ff tag the longest.
    let root = group_c();
    let mut shortest = usize::MAX;
    let mut longest = 0usize;
    let mut seen = 0usize;
    for v in root["vectors"].as_array().unwrap_or(&Vec::new()) {
        if let Some(s) = v.get("base58_of_tag22").and_then(|t| t.as_str()) {
            shortest = shortest.min(s.chars().count());
            longest = longest.max(s.chars().count());
            seen += 1;
        }
    }
    for e in root["crc16_base58_corpus"]["entries"]
        .as_array()
        .unwrap_or(&Vec::new())
    {
        if let Some(s) = e["base58"].as_str() {
            shortest = shortest.min(s.chars().count());
            longest = longest.max(s.chars().count());
            seen += 1;
        }
    }
    assert!(seen >= 1004, "the length walk saw only {seen} recorded encodings");
    assert_eq!(
        (shortest, longest),
        (TAG_BASE58_MIN_CHARS, TAG_BASE58_MAX_CHARS),
        "the declared window is [{TAG_BASE58_MIN_CHARS}, {TAG_BASE58_MAX_CHARS}] but the \
         reference's own strings run [{shortest}, {longest}]"
    );
    // Checked at compile time: widening the window to a hex tag's length
    // fails the build.
    const {
        assert!(
            TAG_BASE58_MAX_CHARS < ADDR_TAG_LEN * 2,
            "a destination can be as long as a hex tag, so the two accepted forms overlap and \
             the parser's length dispatch is ambiguous"
        );
    }

    // 2. No forty-character Base58 string is a tag, for every count of
    //    leading zeros.
    //
    //    With `z` leading `'1'`s the decoded length is `z` plus the byte
    //    length of the value in the remaining `40 - z` digits, which is
    //    smallest for `'2'` followed by `'1'`s. If that minimum exceeds
    //    twenty-two for every `z`, so does every forty-character string.
    let mut probed = 0usize;
    let mut smallest = usize::MAX;
    for zeros in 0..=40usize {
        let s: String = if zeros == 40 {
            "1".repeat(40)
        } else {
            "1".repeat(zeros) + "2" + &"1".repeat(39 - zeros)
        };
        assert_eq!(s.chars().count(), 40);
        let decoded = mochimo_crypto::base58::decode(&s)
            .unwrap_or_else(|e| panic!("40-char probe with {zeros} leading '1's: {e}"));
        assert_ne!(
            decoded.len(),
            ADDR_TAG_LEN + 2,
            "a 40-character Base58 string ({s}) decoded to a {}-byte payload -- the two \
             accepted forms CAN collide and the parser's dispatch is unsound",
            ADDR_TAG_LEN + 2
        );
        assert!(
            mochimo_crypto::addr::tag_from_base58(&s).is_err(),
            "a 40-character string was accepted as a destination: {s}"
        );
        smallest = smallest.min(decoded.len());
        probed += 1;
        // A sample with the tail maximised instead.
        let big: String = "1".repeat(zeros) + &"z".repeat(40 - zeros);
        let d2 = mochimo_crypto::base58::decode(&big).unwrap_or_else(|e| panic!("{e}"));
        assert_ne!(d2.len(), ADDR_TAG_LEN + 2, "40-char probe (max tail): {big}");
    }
    assert_eq!(probed, 41, "the 40-character probe walked {probed} of 41 cases");
    assert!(
        smallest > ADDR_TAG_LEN + 2,
        "the SHORTEST payload any forty-character Base58 string can decode to is {smallest} \
         bytes, which is not more than the {} a destination carries. The two accepted forms \
         can overlap.",
        ADDR_TAG_LEN + 2
    );

    // 3. Over the corpus: every tag's hex form is refused as a destination,
    //    and its destination form is refused as hex.
    let mut both = 0usize;
    for e in root["crc16_base58_corpus"]["entries"]
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .take(64)
    {
        let hex = e["tag"].as_str().unwrap_or_default();
        let b58 = e["base58"].as_str().unwrap_or_default();
        assert!(
            mochimo_crypto::addr::tag_from_base58(hex).is_err(),
            "the hex form of a tag was accepted as a destination: {hex}"
        );
        assert!(b58.chars().count() != ADDR_TAG_LEN * 2, "a destination is hex-tag length: {b58}");
        both += 1;
    }
    assert_eq!(both, 64);
    println!(
        "  form disjointness: {seen} recorded encodings in [{shortest},{longest}], {probed} \
         forty-character minima (shortest {smallest} bytes, a destination is {}), {both} \
         corpus pairs", ADDR_TAG_LEN + 2
    );
}

/// The checksum catches a typo the Base58 codec accepts.
///
/// `C12` is `C9`'s string with its last character altered. The reference's
/// `base58_decode` returns `rc == 0` and twenty-two bytes; the fixture
/// records `checksum_would_reject: true`.
#[test]
fn a_mistyped_destination_is_refused_by_its_checksum() {
    let root = group_c();
    let c12 = root["vectors"]
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .find(|v| v["id"] == "C12")
        .cloned()
        .unwrap_or_else(|| panic!("group C carries C12, the altered-character negative"));
    let altered = c12["in"].as_str().unwrap_or_else(|| panic!("C12 has `in`"));
    assert_eq!(
        c12["rc"].as_i64(),
        Some(0),
        "C12 no longer records the codec ACCEPTING the altered string; without that this test \
         asserts nothing about the checksum"
    );
    assert_eq!(c12["checksum_would_reject"].as_bool(), Some(true));

    // The codec accepts it, exactly as the fixture says.
    let raw = mochimo_crypto::base58::decode(altered)
        .unwrap_or_else(|e| panic!("C12's string was refused by the codec: {e}"));
    assert_eq!(raw.len(), ADDR_TAG_LEN + 2, "C12 decodes to a 22-byte payload");

    // And the checksum does not.
    let refusal = match mochimo_crypto::addr::tag_from_base58(altered) {
        Ok(t) => panic!(
            "an altered destination was ACCEPTED, as tag {}. Funds sent to it are \
             irrecoverable.",
            hexs(&t)
        ),
        Err(e) => format!("{e}"),
    };
    // The refusal's rendered wording.
    assert!(
        refusal.contains("checksum does not match"),
        "the refusal does not say what is wrong: {refusal}"
    );
    assert!(
        refusal.contains("One character is wrong"),
        "the refusal does not tell the operator what to do: {refusal}"
    );
    println!("  checksum refusal: {refusal}");
}

/// `send <to>` takes a Base58 destination from another wallet, a `0x` hex
/// tag, or a mix of the two.
#[test]
fn send_accepts_a_destination_and_a_hex_tag_and_agrees_with_itself() {
    let dest = mochimo_crypto::addr::tag_to_base58(&TO).unwrap_or_else(|e| panic!("{e}"));
    let src = mochimo_crypto::addr::tag_to_base58(&TAG).unwrap_or_else(|e| panic!("{e}"));

    let parse = |tag: &str, to: &str| -> Command {
        match args::parse(&argv(&[
            "--dir", "/d", "--node", "n", "send", tag, to, "1000",
        ]))
        .unwrap_or_else(|e| panic!("`send {tag} {to} 1000` was refused: {e}"))
        {
            args::ParsedArgv::Run(i) => i.command,
            args::ParsedArgv::Help => panic!("a send parsed as help"),
        }
    };

    let want = Command::Send(Spend {
        tag: TAG,
        dsts: vec![SpendTo { to: TO, reference: [0; ADDR_REF_LEN], amount: Some(1000) }],
        fee_total: MFEE,
        blk_to_live: 0,
        expect_balance: None,
    });
    // Base58 on both sides.
    assert_eq!(parse(&src, &dest), want, "a Base58 send did not parse to the same spend");
    // `0x` hex on both sides: the form the Mesh endpoints and fixtures use.
    assert_eq!(parse(&prefixed(&TAG), &prefixed(&TO)), want, "a 0x-hex send stopped parsing");
    // Mixed forms.
    assert_eq!(parse(&prefixed(&TAG), &dest), want);
    assert_eq!(parse(&src, &prefixed(&TO)), want);
    // Surrounding whitespace is trimmed, as other Mochimo clients do.
    assert_eq!(parse(&format!("  {src}\n"), &format!("\t{dest} ")), want, "whitespace");
    // A `0x` prefix always means hex, so a short one is refused as bad hex.
    match args::parse(&argv(&["--dir", "/d", "--node", "n", "status", "0x1234"])) {
        Ok(v) => panic!("`0x1234` parsed: {v:?}"),
        Err(u) => assert!(
            format!("{u}").contains("hex characters"),
            "a 0x-prefixed argument was diagnosed as a destination: {u}"
        ),
    }
    // The Base58 alphabet has no `0`, so no destination begins `0x`.
    assert!(
        !src.starts_with('0') && !dest.starts_with('0'),
        "a destination began with `0`, which the Base58 alphabet excludes"
    );
}

/// The all-zero tag is refused by name.
///
/// `crc16` of twenty zero bytes is zero (`C7`), so its checksum matches and
/// `addr::tag_from_base58` decodes it. Nothing downstream refuses it either
/// (`mdst_val` has no zero-tag rule), so a payment to it would settle and
/// could never be spent. It is the value an uninitialised field produces.
#[test]
fn the_all_zero_destination_is_refused_although_its_checksum_verifies() {
    let zero: [u8; ADDR_TAG_LEN] = [0u8; ADDR_TAG_LEN];
    let encoded = mochimo_crypto::addr::tag_to_base58(&zero).unwrap_or_else(|e| panic!("{e}"));
    // `C7`'s recorded string.
    assert_eq!(encoded, "1".repeat(ADDR_TAG_LEN + 2), "C7's encoding moved");
    // The codec accepts it, checksum included.
    assert_eq!(
        mochimo_crypto::addr::tag_from_base58(&encoded).unwrap_or_else(|e| panic!("{e}")),
        zero,
        "the codec must agree with the reference here; the refusal is a policy one layer up"
    );
    // The CLI does not, in either form, and says why.
    for form in [encoded.clone(), format!("0x{}", hexs(&zero))] {
        let u = match args::parse(&argv(&["--dir", "/d", "--node", "n", "settle", &form])) {
            Ok(v) => panic!("the all-zero tag `{form}` parsed to {v:?}"),
            Err(u) => format!("{u}"),
        };
        assert!(
            u.contains("all-zero tag"),
            "`{form}`: refused, but not as the zero tag:\n{u}"
        );
        assert!(
            u.contains("cannot refuse this one"),
            "`{form}`: the refusal does not say why the checksum is no help here:\n{u}"
        );
    }
    // Control: one bit away is accepted.
    let mut nearly = zero;
    nearly[ADDR_TAG_LEN - 1] = 1;
    let near = mochimo_crypto::addr::tag_to_base58(&nearly).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(near, "1111111111111111111Nzs", "C10's encoding moved");
    assert!(
        args::parse(&argv(&["--dir", "/d", "--node", "n", "settle", &near])).is_ok(),
        "a tag one bit from zero was refused too, so the zero-tag rows establish nothing"
    );
}

/// The parser's destination refusals, read from real parses.
#[test]
fn the_parser_refuses_a_destination_it_cannot_take() {
    let good = mochimo_crypto::addr::tag_to_base58(&TO).unwrap_or_else(|e| panic!("{e}"));
    // C12: valid Base58, decodes to 22 bytes, checksum wrong.
    let altered = group_c()["vectors"]
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .find(|v| v["id"] == "C12")
        .and_then(|v| v["in"].as_str())
        .map(str::to_string)
        .unwrap_or_else(|| panic!("group C carries C12"));
    // C13's 21-byte payload: valid Base58, decodes to the wrong length.
    let short_payload = group_c()["vectors"]
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .find(|v| v["id"] == "C13")
        .and_then(|v| v["base58_21"].as_str())
        .map(str::to_string)
        .unwrap_or_else(|| panic!("group C carries C13"));

    let cases: [(String, &str, &str); 5] = [
        (altered, "checksum does not match", "one character altered"),
        (short_payload, "byte(s); a destination is 22", "a 21-byte payload"),
        ("0OIl0OIl0OIl0OIl0OIl0OIl".to_string(), "not Base58", "outside the alphabet"),
        (String::new(), "character(s); a destination is", "the empty string"),
        ("1".repeat(80), "character(s); a destination is", "eighty characters"),
    ];
    let mut rendered = 0usize;
    for (input, needle, what) in cases {
        let r = args::parse(&argv(&["--dir", "/d", "--node", "n", "settle", &input]));
        let u = match r {
            Ok(v) => panic!("{what} (`{input}`) parsed to {v:?}"),
            Err(u) => format!("{u}"),
        };
        assert!(
            u.contains(needle),
            "{what}: refused, but not for {needle:?}.\n--- rendered ---\n{u}"
        );
        assert!(
            u.contains("is not a destination"),
            "{what}: the refusal does not say what kind of thing was expected:\n{u}"
        );
        rendered += 1;
    }
    // Control: a valid destination is accepted.
    assert!(
        args::parse(&argv(&["--dir", "/d", "--node", "n", "settle", &good])).is_ok(),
        "a well-formed destination was refused, so the five refusals above establish nothing"
    );
    assert_eq!(rendered, 5);
}

/// `Chain::credit_destination` accepts only the destination form, so the
/// flow test cannot be funded by a string other wallets would refuse. Its
/// refusals are asserted here, including the hex tag and ledger address.
#[test]
fn the_fake_refuses_every_form_but_the_reference_one() {
    let good = mochimo_crypto::addr::tag_to_base58(&TAG).unwrap_or_else(|e| panic!("{e}"));
    let altered = group_c()["vectors"]
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .find(|v| v["id"] == "C12")
        .and_then(|v| v["in"].as_str())
        .map(str::to_string)
        .unwrap_or_else(|| panic!("group C carries C12"));

    let short_payload = group_c()["vectors"]
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .find(|v| v["id"] == "C13")
        .and_then(|v| v["base58_21"].as_str())
        .map(str::to_string)
        .unwrap_or_else(|| panic!("group C carries C13"));

    // Each row has its own expected message, so the refusal reason is checked.
    let refused: [(String, &str, &str); 6] = [
        // The bare tag.
        (hexs(&TAG), "the 40-hex tag", "character(s); a destination is"),
        // The ledger address.
        (hexs(&addr_at(0)), "the 80-hex ledger address", "character(s); a destination is"),
        (altered, "a destination with one character altered", "checksum does not match"),
        (short_payload, "Base58 over a 21-byte payload", "byte(s); a destination is 22"),
        (String::new(), "the empty string", "character(s); a destination is"),
        ("0OIl0OIl0OIl0OIl0OIl0OIl".to_string(), "characters outside the alphabet", "not Base58"),
    ];
    let mut seen = 0usize;
    let mut arms: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for (input, what, needle) in refused {
        let c = Chain::new(&[]);
        match c.credit_destination(&input, addr_at(0), 5_000_000) {
            Ok(t) => panic!(
                "the chain accepted {what} (`{input}`) as a destination, crediting tag {}. \
                 With this door open the flow test cannot catch a CLI that prints an \
                 identifier no other client takes.",
                hexs(&t)
            ),
            Err(e) => {
                assert!(
                    e.contains("refuses it"),
                    "{what}: the refusal does not say what happened:\n{e}"
                );
                assert!(
                    e.contains(needle),
                    "{what}: refused, but not for {needle:?} -- so this row is \
                     indistinguishable from the others:\n{e}"
                );
                arms.insert(needle);
                seen += 1;
            }
        }
    }
    assert_eq!(seen, 6);
    assert_eq!(
        arms.len(),
        4,
        "the six rows reached {} distinct refusal(s); rows that all land on one arm test one \
         arm six times",
        arms.len()
    );
    // Control: the destination form is accepted and credits its tag.
    let c = Chain::new(&[]);
    assert_eq!(
        c.credit_destination(&good, addr_at(0), 7).unwrap_or_else(|e| panic!("{e}")),
        TAG,
        "the reference form was refused, or credited the wrong tag"
    );
}

/// `address` with no argument lists the store without a node or a master
/// seed.
#[test]
fn address_with_no_argument_lists_the_store_with_no_node_and_no_seed() {
    let (_dir, ks) = store("cli-address-list");
    // Every request refused, and no master supplied at all.
    let chain = Chain::new(&[(TAG, ChainState::Unreachable)]);
    let r = cli::run(ks, MeshClient::new(chain), &Command::Address { tag: None, account: None });
    assert_eq!(
        r.code,
        Code::Ok,
        "listing the store needed something it should not: {}",
        r.text
    );
    let dest = mochimo_crypto::addr::tag_to_base58(&TAG).unwrap_or_else(|e| panic!("{e}"));
    assert_says(&r, &dest, "the listing");
    assert_says(&r, "index 0", "the listing");
    assert_says(&r, "derived", "the listing");
    // The first line is a header. `address <tag>` puts a bare destination on
    // line one; a script that lost its tag argument must not receive the
    // first account's destination instead.
    let first = r.text.lines().next().unwrap_or("");
    assert!(
        first.starts_with("1 account(s)"),
        "the listing's first line is not a header: {first:?}"
    );
    assert!(
        mochimo_crypto::addr::tag_from_base58(first.split_whitespace().next().unwrap_or(""))
            .is_err(),
        "the listing's first line parses as a destination, so a script that lost its tag \
         argument would read one instead of failing: {first:?}"
    );
    // The first field of an account line is accepted as a destination.
    let line = r
        .text
        .lines()
        .find(|l| l.trim_start().starts_with(&dest))
        .unwrap_or_else(|| panic!("no account line:\n{}", r.text));
    let c = Chain::new(&[]);
    assert_eq!(
        c.credit_destination(line.split_whitespace().next().unwrap_or(""), addr_at(0), 1)
            .unwrap_or_else(|e| panic!("{e}")),
        TAG
    );
}

/// An empty store lists as empty rather than refusing.
#[test]
fn address_with_no_argument_on_an_empty_store_says_so() {
    let dir = ScratchDir::new("cli-address-list-empty");
    let ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    let r = cli::run(
        ks,
        MeshClient::new(Chain::new(&[])),
        &Command::Address { tag: None, account: None },
    );
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    assert_says(&r, "no accounts in this store", "the empty listing");
}

/// `address` takes one tag; two arguments are a usage error.
#[test]
fn address_takes_one_tag_or_none_and_never_two() {
    let a = hexs(&TAG);
    match args::parse(&argv(&["--dir", "/d", "--node", "n", "address", &a, &a])) {
        Ok(v) => panic!("`address <tag> <tag>` parsed to {v:?}"),
        Err(u) => assert!(
            format!("{u}").contains("takes one tag, or none at all"),
            "wrong refusal: {u}"
        ),
    }
    match args::parse(&argv(&["--dir", "/d", "--node", "n", "address"])) {
        Ok(args::ParsedArgv::Run(i)) => {
            assert_eq!(i.command, Command::Address { tag: None, account: None })
        }
        other => panic!("bare `address` did not parse to a listing: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// `create`'s confirmation
// ---------------------------------------------------------------------------

/// The phrase and the answer the run's own entropy produces, so the
/// confirmation can be answered right or wrong on purpose.
fn expected_confirmation() -> String {
    let phrase = mochimo_crypto::mnemonic::phrase_from_entropy(&ENTROPY)
        .unwrap_or_else(|e| panic!("{e}"));
    let words: Vec<String> = phrase
        .expose()
        .split_whitespace()
        .map(str::to_string)
        .collect();
    let p = create_cmd::CONFIRM_POSITIONS;
    format!(
        "{} {} {}",
        words[p[0] - 1],
        words[p[1] - 1],
        words[p[2] - 1]
    )
}

/// A wrong confirmation exits 3, writes nothing, and names
/// `create --from-phrase` as the way back, with the instruction to record the
/// phrase before funding.
///
/// The confirmation is a single attempt: one that can be retried until it
/// matches would prove nothing, since the phrase is on the same screen.
#[test]
fn a_wrong_confirmation_names_the_route_back_and_no_destination() {
    let dir = ScratchDir::new("cli-create-badconfirm-dest");
    let target = dir.path().to_path_buf();
    let shown: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let log = Rc::clone(&shown);
    let r = create_cmd::orchestrate(
        &target,
        false,
        || Ok(zeroize::Zeroizing::new(test_create_entropy())),
        || Ok(Recorder::new(log, password_then(vec!["abandon abandon abandon".into()]))),
    );
    assert_eq!(r.code, Code::Refused, "a wrong confirmation did not exit 3: {}", r.text);
    assert!(!target.exists(), "a refused confirmation left {} on disk", target.display());

    // The destination the phrase would have produced must not be shown: the
    // backup was not confirmed.
    let expected = mochimo_crypto::mnemonic::phrase_from_entropy(&ENTROPY)
        .map(|p| {
            mochimo_crypto::mnemonic::master_seed_from_phrase(p.expose(), "")
                .map(|m| mochimo_crypto::derive::derive_account_tag(&m, 0))
        })
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|e| panic!("{e}"));
    let dest = mochimo_crypto::addr::tag_to_base58(&expected).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        !r.text.contains(&dest) && !r.text.contains("destination"),
        "the refusal offers a destination for a store that does not exist:\n{}",
        r.text
    );
    assert_says(&r, "Nothing was created", "the exit-3 refusal");
    assert_says(&r, "create --from-phrase", "the exit-3 refusal's route back");
    assert_says(&r, "write the phrase down", "the exit-3 refusal");
}

/// The three-word confirmation is read with echo; a supplied phrase is not.
///
/// Echo protects nothing for the confirmation, since the phrase is already
/// on screen. Both reads return answers from the same script, so the test
/// checks which read ran.
///
/// That no echo-off read can follow the echoing one is a compile-time
/// property, covered by
/// `ui/fail/terminal_cannot_read_a_secret_after_the_visible_read.rs`.
#[test]
fn the_confirmation_is_read_visibly_and_a_supplied_phrase_is_not() {
    // Generated phrase: the only visible read is the confirmation.
    let dir = ScratchDir::new("cli-create-visible");
    let shown: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let reads: Rc<RefCell<Vec<(&'static str, String)>>> = Rc::new(RefCell::new(Vec::new()));
    let (log, rl) = (Rc::clone(&shown), Rc::clone(&reads));
    let r = create_cmd::orchestrate(
        dir.path(),
        false,
        || Ok(zeroize::Zeroizing::new(test_create_entropy())),
        || Ok(Recorder::watching(log, password_then(vec![expected_confirmation()]), rl)),
    );
    assert_eq!(r.code, Code::Ok, "output: {}", r.text);
    let got = reads.borrow().clone();

    // The full read sequence, in order:
    //
    //   1-2. the new password, twice, echo off (it is on no screen);
    //     3. the three-word confirmation, visible, and last. The visible read
    //        takes `self`, so nothing can read after it; this assertion
    //        catches the password reads moving after it.
    assert_eq!(
        got.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
        vec!["secret", "secret", "visible"],
        "create's terminal reads are not two echo-off password reads followed by the visible \
         confirmation: {got:?}"
    );
    assert!(
        got[0].1.contains("password") && got[1].1.contains("again"),
        "the first two reads are not the password and its confirmation: {got:?}"
    );
    assert!(
        got[2].1.contains("type words"),
        "the visible read is not the confirmation prompt: {:?}",
        got[2].1
    );

    // Supplied phrase: read with echo off, since it is not on screen.
    let dir2 = ScratchDir::new("cli-create-visible-supplied");
    let shown2: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let reads2: Rc<RefCell<Vec<(&'static str, String)>>> = Rc::new(RefCell::new(Vec::new()));
    let (log2, rl2) = (Rc::clone(&shown2), Rc::clone(&reads2));
    let phrase = mochimo_crypto::mnemonic::phrase_from_entropy(&ENTROPY)
        .unwrap_or_else(|e| panic!("{e}"));
    let r2 = create_cmd::orchestrate(
        dir2.path(),
        true,
        || Ok(zeroize::Zeroizing::new(test_create_entropy())),
        || Ok(Recorder::watching(log2, password_then(vec![phrase.expose().to_string()]), rl2)),
    );
    assert_eq!(r2.code, Code::Ok, "output: {}", r2.text);
    let got2 = reads2.borrow().clone();
    // Three reads, all echo-off: the password twice, then the phrase. Nothing
    // is displayed, so there is no visible read.
    assert_eq!(
        got2.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
        vec!["secret", "secret", "secret"],
        "--from-phrase read something visibly; a phrase the operator types is not on any screen \
         and the mnemonic prompt's argument applies to it in full: {got2:?}"
    );
    assert!(
        got2[2].1.contains("recovery phrase"),
        "the third read is not the phrase prompt: {got2:?}"
    );
    // Only the scheme warning, before the first read; the typed phrase is
    // never echoed.
    assert_eq!(
        shown2.borrow().len(),
        1,
        "the --from-phrase path showed something besides the scheme warning: {:?}",
        shown2.borrow()
    );
}

/// The listing needs no node and no master seed.
///
/// It answers from stored records, deriving nothing and asking no node. It
/// needs the password only because the store is encrypted. Driven with a
/// transport that refuses every request.
#[test]
fn the_listing_needs_no_node_and_no_seed() {
    let (_dir, ks) = store("cli-listing-no-node");
    // Every request refused.
    let chain = Chain::new(&[(TAG, ChainState::Unreachable)]);
    let r = cli::run(ks, MeshClient::new(chain), &Command::Address { tag: None, account: None });
    assert_eq!(
        r.code,
        Code::Ok,
        "listing the store reached for something it should not: {}",
        r.text
    );
    let dest = mochimo_crypto::addr::tag_to_base58(&TAG).unwrap_or_else(|e| panic!("{e}"));
    assert_says(&r, &dest, "the listing");

    // A store with no master (`store()` adopts one). The premise is asserted
    // first.
    let dir2 = ScratchDir::new("cli-listing-no-master");
    let mut bare = Keystore::create(dir2.path(), &keystore_harness::init())
        .unwrap_or_else(|e| panic!("{e}"));
    bare.add(Account::derive(&master(), 0)).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        bare.master().unwrap_or_else(|e| panic!("{e}")).is_none(),
        "this test's premise is that the store holds no master; if it does, the assertion below \
         no longer distinguishes a listing that derives from one that does not"
    );
    let r2 = cli::run(bare, MeshClient::new(Chain::new(&[])), &Command::Address { tag: None, account: None });
    assert_eq!(
        r2.code,
        Code::Ok,
        "the listing refused a store with no master, so it derives after all: {}",
        r2.text
    );
    assert_says(&r2, &dest, "the seedless listing");
}

// ---------------------------------------------------------------------------
// The shipped binary, on a real pseudo-terminal
// ---------------------------------------------------------------------------
//
// The tests above drive `cli::Report` through a test double. These build the
// shipped binary (`cargo build -p mochimo-crypto --features mesh-https --bin
// tawara`, as a subprocess) and run it under `script(1)`, which gives it a
// pseudo-terminal as its controlling terminal. BSD (`script -q /dev/null cmd
// args`) and util-linux (`-c`) forms are both supported.
//
// The binary's stdout and stderr are redirected to files inside the pty, so
// the transcript is what the terminal shows and the files are what a shell
// redirect would capture.
//
// The harness builds its subject rather than skipping when it is absent. It
// is excluded under Miri, which cannot spawn processes.
//
// Covered: the password prompt with echo off, the phrase shown, the
// confirmation with echo on, a store the typed password opens, and the
// phrase reproducing the store's destination both in-process and through
// `create --from-phrase`. Not covered: terminal scrollback, a `SIGKILL`
// inside the echo-off window.
#[cfg(not(miri))]
mod pty {
    use std::io::{Read, Write};
    use std::path::{Path, PathBuf};
    use std::process::{Child, ChildStdin, Command, Stdio};
    use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
    use std::sync::{Arc, Mutex, OnceLock};
    use std::time::{Duration, Instant};

    use super::create_cmd;
    use super::keystore_harness::ScratchDir;
    use super::{addr_at, hexs, master, TAG};
    use mochimo_crypto::keystore::{Keystore, Unlock, NONCE_SEED_LEN};

    /// How long one step may take before the session is killed and the test
    /// fails with the transcript. The slowest step is Argon2id at
    /// `Kdf::RECOMMENDED` in the debug profile.
    const STEP: Duration = Duration::from_secs(300);

    /// A test password above the twelve-character floor.
    const PASSWORD: &str = "harness-password-not-for-real-use";

    /// A node the binary never dials: `create` needs the flag and not the
    /// socket.
    const NODE: &str = "http://127.0.0.1:1";

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("crate lives at <repo>/crates/mochimo-crypto")
            .to_path_buf()
    }

    /// The shipped binary, built once per test process.
    ///
    /// # Panics
    ///
    /// If the binary cannot be built; the harness never skips.
    fn wallet_binary() -> &'static Path {
        static EXE: OnceLock<PathBuf> = OnceLock::new();
        EXE.get_or_init(|| {
            let cargo = std::env::var("CARGO").unwrap_or_else(|_| {
                panic!(
                    "CARGO is unset. Cargo sets it for every test process it runs, so this \
                     test is not being run by cargo and cannot build the binary it tests. Run \
                     the suite with `cargo test`, not by invoking the test binary."
                )
            });
            // Match the profile of the outer test run.
            let me = std::env::current_exe().expect("current_exe");
            let release = me.components().any(|c| c.as_os_str() == "release");
            let mut cmd = Command::new(&cargo);
            cmd.current_dir(repo_root()).args([
                "build",
                "-p",
                "mochimo-crypto",
                "--features",
                "mesh-https",
                "--bin",
                "tawara",
                "--message-format=json",
            ]);
            if release {
                cmd.arg("--release");
            }
            // Remove the variables cargo sets for this test process. `ring`'s
            // build script declares `rerun-if-env-changed=CARGO_MANIFEST_DIR`,
            // so an inherited value would make the nested build's fingerprint
            // differ from a shell build's and force a rebuild each time.
            // `CARGO` and the toolchain selection are kept.
            for (k, _) in std::env::vars_os() {
                let k = k.to_string_lossy();
                let injected = matches!(
                    k.as_ref(),
                    "CARGO_MANIFEST_DIR"
                        | "CARGO_MANIFEST_PATH"
                        | "CARGO_CRATE_NAME"
                        | "CARGO_PRIMARY_PACKAGE"
                        | "CARGO_TARGET_TMPDIR"
                        | "OUT_DIR"
                ) || k.starts_with("CARGO_PKG_")
                    || k.starts_with("CARGO_BIN_EXE_");
                if injected {
                    cmd.env_remove(k.as_ref());
                }
            }
            let out = cmd
                .output()
                .unwrap_or_else(|e| panic!("could not run `{cargo} build --bin tawara`: {e}"));
            assert!(
                out.status.success(),
                "`cargo build --features mesh-https --bin tawara` failed ({}), so the pty \
                 harness has no subject. This is a build failure of the shipped binary, not a \
                 finding about its terminal handling.\n{}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            );
            let mut exe: Option<PathBuf> = None;
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };
                if v["reason"] != "compiler-artifact" || v["target"]["name"] != "tawara" {
                    continue;
                }
                let is_bin = v["target"]["kind"]
                    .as_array()
                    .is_some_and(|k| k.iter().any(|x| x == "bin"));
                if !is_bin {
                    continue;
                }
                if let Some(p) = v["executable"].as_str() {
                    exe = Some(PathBuf::from(p));
                }
            }
            let exe = exe.unwrap_or_else(|| {
                panic!(
                    "cargo built without reporting an executable for the `tawara` bin \
                     target. The harness reads the path from cargo's own JSON rather than \
                     guessing `target/debug/tawara`, so a renamed target or a moved target \
                     directory fails here rather than running a stale binary."
                )
            });
            assert!(exe.is_file(), "cargo named {} and it is not a file", exe.display());
            // No path in this line: the test census parses integers from
            // test output.
            println!(
                "pty harness: built the shipped binary in the {} profile",
                if release { "release" } else { "debug" }
            );
            exe
        })
    }

    /// One shell-quoted word, for the util-linux form that goes through `sh -c`.
    fn quote(s: &str) -> String {
        format!("'{}'", s.replace('\'', "'\\''"))
    }

    /// `script(1)` around `wrapper exe args...`, in the host's dialect.
    ///
    /// BSD (macOS) `script` takes the command as trailing arguments and execs
    /// it directly; util-linux takes one string after `-c` and passes it to a
    /// shell, with `-e` to return the child's status (BSD always does). Any
    /// other host fails here rather than passing with no terminal.
    fn script_command(wrapper: &Path, exe: &Path, args: &[&str]) -> Command {
        let mut cmd = Command::new("script");
        if cfg!(target_os = "macos") {
            cmd.args(["-q", "/dev/null"]).arg(wrapper).arg(exe).args(args);
        } else if cfg!(target_os = "linux") {
            let mut words = vec![quote(&wrapper.to_string_lossy()), quote(&exe.to_string_lossy())];
            words.extend(args.iter().map(|a| quote(a)));
            cmd.args(["-q", "-e", "-c", &words.join(" "), "/dev/null"]);
        } else {
            panic!(
                "the pty harness knows BSD and util-linux `script(1)` and this host is \
                 neither ({}). It does not skip: without a pseudo-terminal nothing here is \
                 measured.",
                std::env::consts::OS
            );
        }
        cmd
    }

    /// What one driven run of the binary left behind.
    pub struct Outcome {
        /// The process's exit code, or `None` if a signal took it.
        pub code: Option<i32>,
        /// Everything the pty carried, `\r` stripped: the operator's screen.
        pub screen: String,
        /// The binary's stdout, as a shell redirect would have captured it.
        pub stdout: String,
        /// The binary's stderr, likewise.
        pub stderr: String,
        /// Prompts this session waited for and answered.
        pub prompts: usize,
    }

    /// A binary running under a pty, with its stdin held by the test.
    ///
    /// Answers are sent only after their prompt appears: the pty echoes input
    /// as it arrives, so a password typed before `stty -echo` would be echoed.
    pub struct Session {
        child: Child,
        stdin: Option<ChildStdin>,
        rx: Receiver<Vec<u8>>,
        script_stderr: Arc<Mutex<Vec<u8>>>,
        transcript: Vec<u8>,
        cursor: usize,
        stdout_file: PathBuf,
        stderr_file: PathBuf,
        prompts: usize,
        started: Instant,
    }

    impl Session {
        /// Spawn `tawara args...` under a pty, with its own stdout and
        /// stderr redirected to files inside `io`.
        pub fn spawn(io: &Path, args: &[&str]) -> Session {
            std::fs::create_dir_all(io).unwrap_or_else(|e| panic!("cannot create {}: {e}", io.display()));
            let wrapper = io.join("run.sh");
            let stdout_file = io.join("stdout");
            let stderr_file = io.join("stderr");
            // Redirect inside the pty, so only what the binary writes to
            // /dev/tty reaches the transcript.
            std::fs::write(
                &wrapper,
                "#!/bin/sh\nexec \"$@\" > \"$MCM_PTY_STDOUT\" 2> \"$MCM_PTY_STDERR\"\n",
            )
            .unwrap_or_else(|e| panic!("cannot write {}: {e}", wrapper.display()));
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700))
                    .unwrap_or_else(|e| panic!("chmod {}: {e}", wrapper.display()));
            }
            let mut cmd = script_command(&wrapper, wallet_binary(), args);
            cmd.env("MCM_PTY_STDOUT", &stdout_file)
                .env("MCM_PTY_STDERR", &stderr_file)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let mut child = cmd.spawn().unwrap_or_else(|e| {
                panic!(
                    "cannot spawn `script`: {e}. The pty harness needs script(1) on PATH and \
                     does not skip without it."
                )
            });
            let stdin = child.stdin.take().expect("piped stdin");
            let mut stdout = child.stdout.take().expect("piped stdout");
            let mut stderr = child.stderr.take().expect("piped stderr");
            let (tx, rx) = mpsc::channel::<Vec<u8>>();
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    match stdout.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if tx.send(buf[..n].to_vec()).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
            let script_stderr = Arc::new(Mutex::new(Vec::new()));
            let sink = Arc::clone(&script_stderr);
            std::thread::spawn(move || {
                let mut all = Vec::new();
                let _ = stderr.read_to_end(&mut all);
                sink.lock().unwrap_or_else(|p| p.into_inner()).extend(all);
            });
            Session {
                child,
                stdin: Some(stdin),
                rx,
                script_stderr,
                transcript: Vec::new(),
                cursor: 0,
                stdout_file,
                stderr_file,
                prompts: 0,
                started: Instant::now(),
            }
        }

        fn screen(&self) -> String {
            String::from_utf8_lossy(&self.transcript).replace('\r', "")
        }

        fn diagnostics(&mut self) -> String {
            let status = match self.child.try_wait() {
                Ok(Some(s)) => format!("{s}"),
                Ok(None) => "still running (killed by the harness)".to_string(),
                Err(e) => format!("unknown ({e})"),
            };
            let file = |p: &Path| std::fs::read_to_string(p).unwrap_or_default();
            format!(
                "--- status: {status}\n--- the operator's screen ---\n{}\n--- the binary's stdout \
                 ---\n{}\n--- the binary's stderr ---\n{}\n--- script's own stderr ---\n{}",
                self.screen(),
                file(&self.stdout_file),
                file(&self.stderr_file),
                String::from_utf8_lossy(&self.script_stderr.lock().unwrap_or_else(|p| p.into_inner()))
            )
        }

        fn find_from_cursor(&self, needle: &[u8]) -> Option<usize> {
            let hay = &self.transcript[self.cursor..];
            hay.windows(needle.len()).position(|w| w == needle).map(|i| self.cursor + i)
        }

        /// Wait until `needle` appears on the screen after everything already
        /// consumed, and return the text that came before it. Kills the
        /// session and fails the test on timeout or on the pty closing first.
        pub fn expect(&mut self, needle: &str) -> String {
            let deadline = Instant::now() + STEP;
            loop {
                if let Some(at) = self.find_from_cursor(needle.as_bytes()) {
                    let before = String::from_utf8_lossy(&self.transcript[self.cursor..at])
                        .replace('\r', "");
                    self.cursor = at + needle.len();
                    return before;
                }
                let left = deadline.saturating_duration_since(Instant::now());
                match self.rx.recv_timeout(left.max(Duration::from_millis(1))) {
                    Ok(chunk) => self.transcript.extend(chunk),
                    Err(RecvTimeoutError::Disconnected) => {
                        let d = self.diagnostics();
                        panic!(
                            "THE OPERATOR WAS NEVER SHOWN {needle:?}: the pty closed without it. \
                             This is the shape of the read-only-descriptor defect -- the binary reached the end \
                             of a path whose prompt never appeared.\n{d}"
                        );
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        let _ = self.child.kill();
                        let d = self.diagnostics();
                        panic!(
                            "THE OPERATOR WAS NEVER SHOWN {needle:?}: nothing more appeared on the \
                             pty in {:?} (session age {:?}). A binary waiting on an answer to a \
                             question it never asked looks exactly like this.\n{d}",
                            STEP,
                            self.started.elapsed()
                        );
                    }
                }
            }
        }

        /// `expect`, counted: the needle is a prompt the harness will answer.
        pub fn expect_prompt(&mut self, needle: &str) -> String {
            let s = self.expect(needle);
            self.prompts += 1;
            s
        }

        /// End of input at the prompt: one `0x04` byte (VEOF), no newline.
        /// The pty is in canonical mode, so a VEOF at the start of a line makes
        /// the binary's `read` return zero bytes, which `read_scrubbed_line`
        /// reports as end of input.
        pub fn send_eof(&mut self) {
            let stdin = self.stdin.as_mut().expect("stdin is held until finish");
            stdin
                .write_all(b"\x04")
                .and_then(|()| stdin.flush())
                .unwrap_or_else(|e| panic!("cannot send end-of-file into the pty: {e}"));
        }

        /// Type a line, Enter included.
        pub fn send(&mut self, line: &str) {
            let stdin = self.stdin.as_mut().expect("stdin is held until finish");
            stdin
                .write_all(line.as_bytes())
                .and_then(|()| stdin.write_all(b"\n"))
                .and_then(|()| stdin.flush())
                .unwrap_or_else(|e| panic!("cannot type into the pty: {e}"));
        }

        /// Wait for the binary to exit on its own, then collect everything.
        pub fn finish(mut self) -> Outcome {
            let deadline = Instant::now() + STEP;
            let status = loop {
                match self.child.try_wait() {
                    Ok(Some(s)) => break s,
                    Ok(None) if Instant::now() < deadline => {
                        // Keep draining so a chatty child cannot fill the pipe.
                        while let Ok(chunk) = self.rx.try_recv() {
                            self.transcript.extend(chunk);
                        }
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Ok(None) => {
                        let _ = self.child.kill();
                        let d = self.diagnostics();
                        panic!(
                            "the binary did not exit within {STEP:?} of its last answer. A \
                             process still waiting for input after the confirmation is a \
                             process that asked a question the harness did not see.\n{d}"
                        );
                    }
                    Err(e) => panic!("waiting for script: {e}"),
                }
            };
            // The child is gone; closing stdin now lets `script` finish and
            // its reader thread hit EOF.
            drop(self.stdin.take());
            while let Ok(chunk) = self.rx.recv_timeout(Duration::from_secs(5)) {
                self.transcript.extend(chunk);
            }
            let file = |p: &Path| std::fs::read_to_string(p).unwrap_or_default();
            Outcome {
                code: status.code(),
                screen: self.screen(),
                stdout: file(&self.stdout_file),
                stderr: file(&self.stderr_file),
                prompts: self.prompts,
            }
        }
    }

    impl Drop for Session {
        fn drop(&mut self) {
            // A test that panicked mid-session must not leave `script` and the
            // binary parked on a pty waiting for an answer that will not come.
            if let Ok(None) = self.child.try_wait() {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }
    }

    /// The twenty-four words: the first line after `WRITE THIS DOWN` with
    /// exactly that many lowercase words on it.
    fn phrase_after_notice(s: &mut Session) -> Vec<String> {
        s.expect("WRITE THIS DOWN");
        // The phrase is the next line with 24 tokens; wait for the sentence
        // that follows it so the whole line is guaranteed to have arrived.
        let block = s.expect("It is the ONLY backup of this wallet.");
        let words: Vec<String> = block
            .lines()
            .map(str::split_whitespace)
            .map(|ws| ws.map(str::to_owned).collect::<Vec<_>>())
            .find(|ws| ws.len() == 24)
            .unwrap_or_else(|| panic!("no 24-word line between the notice and its explanation:\n{block}"));
        for w in &words {
            assert!(
                !w.is_empty() && w.bytes().all(|b| b.is_ascii_lowercase()),
                "a shown word is not a lowercase word: {w:?}"
            );
        }
        words
    }

    /// The positions the question asks for, read off the screen and checked
    /// against the constant the binary was built with.
    fn positions_asked(s: &mut Session) -> [usize; 3] {
        s.expect("type words ");
        let text = s.expect_prompt(", separated by spaces: ");
        let nums: Vec<usize> = text
            .split(|c: char| !c.is_ascii_digit())
            .filter(|t| !t.is_empty())
            .map(|t| t.parse().unwrap_or_else(|e| panic!("{t:?} in {text:?}: {e}")))
            .collect();
        let got: [usize; 3] = nums
            .as_slice()
            .try_into()
            .unwrap_or_else(|_| panic!("the question names {} position(s), not 3: {text:?}", nums.len()));
        assert_eq!(
            got,
            create_cmd::CONFIRM_POSITIONS,
            "the question on the screen asks for different positions than the code confirms"
        );
        got
    }

    /// Account 0's destination for a phrase, computed in this process,
    /// independently of the binary's output.
    fn destination_of(phrase: &str) -> String {
        let m = mochimo_crypto::mnemonic::master_seed_from_phrase(phrase, "")
            .unwrap_or_else(|e| panic!("{e}"));
        let tag = mochimo_crypto::derive::derive_account_tag(&m, 0);
        mochimo_crypto::addr::tag_to_base58(&tag).unwrap_or_else(|e| panic!("{e}"))
    }

    /// The shipped binary, on a terminal, shows a phrase, and that phrase
    /// recovers the store it writes. If `/dev/tty` were opened read-only the
    /// first `expect` would time out.
    #[test]
    fn create_on_a_real_pty_shows_a_phrase_that_recovers_the_store() {
        let io = ScratchDir::new("pty-create-io");
        let store = ScratchDir::new("pty-create");
        let dir = store.path().to_string_lossy().into_owned();

        let mut s = Session::spawn(io.path(), &["--dir", &dir, "--node", NODE, "create"]);
        s.expect_prompt("choose a password for this wallet");
        s.send(PASSWORD);
        s.expect_prompt("type it again: ");
        s.send(PASSWORD);
        let words = phrase_after_notice(&mut s);
        let p = positions_asked(&mut s);
        let answer = format!("{} {} {}", words[p[0] - 1], words[p[1] - 1], words[p[2] - 1]);
        s.send(&answer);
        let o = s.finish();
        let phrase = words.join(" ");

        assert_eq!(o.code, Some(0), "create did not exit 0.\n--- screen ---\n{}\n--- stdout ---\n{}\n--- stderr ---\n{}", o.screen, o.stdout, o.stderr);

        // The screen: the phrase once, the password never, the answer echoed.
        assert_eq!(o.screen.matches(&phrase).count(), 1, "the phrase is not on the screen exactly once:\n{}", o.screen);
        assert!(!o.screen.contains(PASSWORD), "THE PASSWORD WAS ECHOED to the terminal:\n{}", o.screen);
        assert_eq!(
            o.screen.matches(&answer).count(),
            1,
            "the confirmation answer was not echoed exactly once -- either echo was not restored \
             before the question or the echo landed twice:\n{}",
            o.screen
        );

        // The streams: the report on stdout, the phrase on neither.
        assert!(!o.stdout.contains(&phrase) && !o.stderr.contains(&phrase), "THE PHRASE LEFT THE TERMINAL through a process-wide stream -- `create > file` would have written the words to disk.\n--- stdout ---\n{}\n--- stderr ---\n{}", o.stdout, o.stderr);
        assert!(!o.screen.contains("destination"), "the report went to the terminal rather than to stdout:\n{}", o.screen);
        assert!(o.stderr.is_empty(), "stderr is not empty on the exit-0 path:\n{}", o.stderr);
        let expected = destination_of(&phrase);
        assert!(o.stdout.contains("created "), "no `created` line on stdout:\n{}", o.stdout);
        assert!(o.stdout.contains(&format!("destination  {expected}")), "stdout does not carry the destination this process derived from the shown phrase.\n--- stdout ---\n{}\n--- expected ---\n{expected}", o.stdout);
        assert!(o.stdout.contains("confirmed    3 words read back"), "stdout does not say the confirmation happened:\n{}", o.stdout);

        // The store: on disk, opened by the password that was typed, holding
        // account 0 of the phrase that was shown.
        let ks = Keystore::open(
            store.path(),
            &Unlock { password: PASSWORD.as_bytes(), nonce_seed: [7u8; NONCE_SEED_LEN] },
        )
        .unwrap_or_else(|e| panic!("the store the binary wrote does not open with the password that was typed: {e}"));
        let tags = ks.tags().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(tags.len(), 1, "the store should hold exactly account 0");
        assert_eq!(
            mochimo_crypto::addr::tag_to_base58(&tags[0]).unwrap_or_else(|e| panic!("{e}")),
            expected,
            "the store holds a different account than the phrase on the screen derives"
        );
        drop(ks);

        // The phrase recovers the store: `create --from-phrase` on a second
        // pty, into a fresh directory, gives the same destination.
        let io2 = ScratchDir::new("pty-restore-io");
        let store2 = ScratchDir::new("pty-restore");
        let dir2 = store2.path().to_string_lossy().into_owned();
        let mut s2 = Session::spawn(io2.path(), &["--dir", &dir2, "--node", NODE, "create", "--from-phrase"]);
        s2.expect_prompt("choose a password for this wallet");
        s2.send(PASSWORD);
        s2.expect_prompt("type it again: ");
        s2.send(PASSWORD);
        s2.expect_prompt("existing recovery phrase (12 or 24 words): ");
        s2.send(&phrase);
        let o2 = s2.finish();
        assert_eq!(o2.code, Some(0), "create --from-phrase did not exit 0.\n--- screen ---\n{}\n--- stderr ---\n{}", o2.screen, o2.stderr);
        assert!(!o2.screen.contains(&phrase), "THE TYPED PHRASE WAS ECHOED on the --from-phrase path:\n{}", o2.screen);
        assert!(o2.stdout.contains(&format!("destination  {expected}")), "the phrase the first run showed did not reproduce its destination through --from-phrase.\n--- stdout ---\n{}\n--- expected ---\n{expected}", o2.stdout);

        println!(
            "tty create: {} prompt(s) answered on a pseudo-terminal by the shipped binary",
            o.prompts + o2.prompts
        );
    }

    /// A wrong answer on a real terminal exits 3 with nothing on disk.
    ///
    /// The in-process test above covers the library; this covers the binary.
    #[test]
    fn a_wrong_confirmation_on_a_real_pty_leaves_nothing_on_disk() {
        let io = ScratchDir::new("pty-badconfirm-io");
        let store = ScratchDir::new("pty-badconfirm");
        let dir = store.path().to_string_lossy().into_owned();

        let mut s = Session::spawn(io.path(), &["--dir", &dir, "--node", NODE, "create"]);
        s.expect_prompt("choose a password for this wallet");
        s.send(PASSWORD);
        s.expect_prompt("type it again: ");
        s.send(PASSWORD);
        let words = phrase_after_notice(&mut s);
        let _ = positions_asked(&mut s);
        s.send("abandon abandon abandon");
        let o = s.finish();

        assert_eq!(o.code, Some(3), "a wrong confirmation did not exit 3.\n--- screen ---\n{}\n--- stderr ---\n{}", o.screen, o.stderr);
        assert!(
            !store.path().exists(),
            "THE STORE WAS WRITTEN BEFORE THE CONFIRMATION: {} exists after exit 3. The exit \
             code says refused and the filesystem says created.",
            store.path().display()
        );
        assert!(o.stderr.contains("those are not words 1, 12 and 24"), "the refusal is not on stderr:\n{}", o.stderr);
        assert!(o.stderr.contains("Nothing was created"), "the refusal does not say nothing was created:\n{}", o.stderr);
        assert!(o.stdout.is_empty(), "stdout is not empty on the exit-3 path:\n{}", o.stdout);
        assert_eq!(o.screen.matches(&words.join(" ")).count(), 1, "the phrase is not on the screen exactly once:\n{}", o.screen);
        println!(
            "tty refusal: {} prompt(s) answered on a pseudo-terminal by the shipped binary",
            o.prompts
        );
    }

    /// Drive `create`'s prompts on an open session and return the words it
    /// showed. Shared by the tests that need a store made through the binary.
    fn drive_create(s: &mut Session) -> Vec<String> {
        s.expect_prompt("choose a password for this wallet");
        s.send(PASSWORD);
        s.expect_prompt("type it again: ");
        s.send(PASSWORD);
        let words = phrase_after_notice(s);
        let p = positions_asked(s);
        let answer = format!("{} {} {}", words[p[0] - 1], words[p[1] - 1], words[p[2] - 1]);
        s.send(&answer);
        words
    }

    /// The two commands that need no node run without `--node`, and the
    /// shared password prompt reaches the terminal, not stderr.
    ///
    /// Fails if: `--node` is required for either command; the prompt goes to
    /// stderr (redirected to a file inside the pty); `/dev/tty` is opened
    /// read-only; or anything is written to stderr on the exit-0 path.
    #[test]
    fn address_on_a_real_pty_needs_no_node_and_its_prompt_survives_a_redirected_stderr() {
        let io = ScratchDir::new("pty-nonode-create-io");
        let store = ScratchDir::new("pty-nonode");
        let dir = store.path().to_string_lossy().into_owned();

        // `create`, with no `--node` on argv at all.
        let mut s = Session::spawn(io.path(), &["--dir", &dir, "create"]);
        let words = drive_create(&mut s);
        let o = s.finish();
        assert_eq!(o.code, Some(0), "create without --node did not exit 0.\n--- screen ---\n{}\n--- stderr ---\n{}", o.screen, o.stderr);
        let expected = destination_of(&words.join(" "));
        assert!(o.stdout.contains(&format!("destination  {expected}")), "create's stdout lacks the destination:\n{}", o.stdout);
        assert!(!o.stderr.contains("--node"), "create without --node complained about the node:\n{}", o.stderr);
        // `created_text` is checked here; the parser test checks `HELP`.
        assert!(
            o.stdout.contains("both need no `--node`"),
            "create's report no longer says the two commands need no --node:\n{}",
            o.stdout
        );

        // `address`, with no `--node`, its stderr going to a file. The prompt
        // must be on the screen; the password must not be.
        let io2 = ScratchDir::new("pty-nonode-address-io");
        let mut s2 = Session::spawn(io2.path(), &["--dir", &dir, "address"]);
        s2.expect_prompt("password: ");
        s2.send(PASSWORD);
        let o2 = s2.finish();
        assert_eq!(o2.code, Some(0), "address without --node did not exit 0.\n--- screen ---\n{}\n--- stderr ---\n{}", o2.screen, o2.stderr);
        assert_eq!(
            o2.screen.matches("password: ").count(),
            1,
            "the password prompt is not on the operator's screen exactly once:\n{}",
            o2.screen
        );
        assert!(
            !o2.stderr.contains("password"),
            "THE PASSWORD PROMPT WENT TO STDERR: `address 2>file` would ask for a password on no \
             screen. The prompt must go to the terminal the binary acquired, as `create`'s \
             does.\n--- stderr file ---\n{}",
            o2.stderr
        );
        assert!(!o2.screen.contains(PASSWORD), "THE PASSWORD WAS ECHOED to the terminal:\n{}", o2.screen);
        assert!(o2.stderr.is_empty(), "stderr is not empty on address's exit-0 path:\n{}", o2.stderr);
        assert!(o2.stdout.contains("1 account(s) in this store:"), "address did not list the store:\n{}", o2.stdout);
        assert!(o2.stdout.contains(&expected), "the listing lacks the destination create printed:\n--- stdout ---\n{}\n--- expected ---\n{expected}", o2.stdout);
        assert!(!o2.screen.contains(&expected), "the listing went to the terminal rather than to stdout:\n{}", o2.screen);

        println!(
            "tty password: {} prompt(s) answered on a pseudo-terminal by the shipped binary with no node",
            o.prompts + o2.prompts
        );
    }

    /// A command that reconciles refuses at argv without `--node`, before any
    /// prompt: exit 1 with the usage on stderr, nothing on the screen, no
    /// password asked, no directory made. `balance` stands for the rest; the
    /// parser test covers every verb.
    #[test]
    fn balance_without_a_node_is_a_usage_error_before_any_prompt() {
        let io = ScratchDir::new("pty-nonode-balance-io");
        let store = ScratchDir::new("pty-nonode-balance");
        let dir = store.path().to_string_lossy().into_owned();
        let s = Session::spawn(io.path(), &["--dir", &dir, "balance"]);
        let o = s.finish();
        assert_eq!(o.code, Some(1), "balance without --node did not exit 1.\n--- screen ---\n{}\n--- stderr ---\n{}", o.screen, o.stderr);
        // The exact phrase, because the usage text that follows it names
        // every verb and "balance" alone would match any usage error.
        assert!(
            o.stderr.contains("usage: --node is required for `balance`"),
            "the refusal is not the usage error naming the verb:\n{}",
            o.stderr
        );
        assert!(o.screen.trim().is_empty(), "something reached the terminal before the usage refusal:\n{}", o.screen);
        // Match the prompt itself: the usage text contains "prompts for its
        // password".
        assert!(
            !o.screen.contains("password: ") && !o.stderr.contains("password: "),
            "a password was asked for before argv was refused.\n--- screen ---\n{}\n--- stderr ---\n{}",
            o.screen,
            o.stderr
        );
        assert!(o.stdout.is_empty(), "stdout is not empty on the exit-1 path:\n{}", o.stdout);
        assert!(!store.path().exists(), "the usage refusal made the directory {}", store.path().display());
        println!("tty usage: exit 1 with no prompt for balance without a node");
    }


    /// A help spelling after the verb is a usage error through the binary:
    /// `send <tag> -h 5` exits 1 with the usage naming `-h`, nothing on the
    /// screen, no prompt, no directory made.
    #[test]
    fn a_help_spelling_in_an_argument_position_is_a_usage_error_not_help() {
        let io = ScratchDir::new("pty-help-position-io");
        let store = ScratchDir::new("pty-help-position");
        let dir = store.path().to_string_lossy().into_owned();
        let tag = format!("0x{}", hexs(&TAG));
        let s = Session::spawn(io.path(), &["--dir", &dir, "--node", NODE, "send", &tag, "-h", "5"]);
        let o = s.finish();
        assert_eq!(o.code, Some(1), "`send <tag> -h 5` did not exit 1.\n--- screen ---\n{}\n--- stderr ---\n{}\n--- stdout ---\n{}", o.screen, o.stderr, o.stdout);
        assert!(
            o.stderr.contains("usage: unexpected argument `-h` after `send`"),
            "the refusal is not the usage error naming the token:\n{}",
            o.stderr
        );
        assert!(o.stdout.is_empty(), "stdout is not empty on the exit-1 path (the help was printed?):\n{}", o.stdout);
        assert!(o.screen.trim().is_empty(), "something reached the terminal before the usage refusal:\n{}", o.screen);
        assert!(!store.path().exists(), "the usage refusal made the directory {}", store.path().display());
        println!("tty help position: exit 1 naming `-h` for send <tag> -h 5, no prompt, no help printed");
    }

    /// A repeated flag is a usage error through the binary: `send ... --fee
    /// 500 --fee 600` exits 1 naming `--fee`, before any prompt.
    #[test]
    fn a_repeated_flag_is_a_usage_error_before_any_prompt() {
        let io = ScratchDir::new("pty-repeated-flag-io");
        let store = ScratchDir::new("pty-repeated-flag");
        let dir = store.path().to_string_lossy().into_owned();
        let tag = format!("0x{}", hexs(&TAG));
        let to = format!("0x{}", hexs(&super::TO));
        let s = Session::spawn(io.path(), &["--dir", &dir, "--node", NODE, "send", &tag, &to, "1", "--fee", "500", "--fee", "600"]);
        let o = s.finish();
        assert_eq!(o.code, Some(1), "a repeated --fee did not exit 1.\n--- screen ---\n{}\n--- stderr ---\n{}", o.screen, o.stderr);
        assert!(o.stderr.contains("usage: --fee given twice"), "the refusal does not name the repeated flag:\n{}", o.stderr);
        assert!(!o.screen.contains("password: ") && !o.stderr.contains("password: "), "a password was asked before argv was refused");
        assert!(!store.path().exists(), "the usage refusal made the directory {}", store.path().display());
        println!("tty repeated flag: exit 1 naming --fee, no prompt");
    }

    /// Ctrl-D at the password prompt is reported as end of input, not as a
    /// wrong password, before the store is read: exit 2, the snapshot
    /// untouched and the lock released. At `create`'s first prompt it is exit
    /// 3 with "Nothing was created" and no directory made.
    #[test]
    fn end_of_input_at_a_prompt_is_refused_before_anything_is_compared() {
        use mochimo_crypto::account::Account;
        let store = ScratchDir::new("pty-eof");
        let dir = store.path().to_string_lossy().into_owned();
        {
            let mut ks = Keystore::create(store.path(), &super::keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
            let _ = ks.adopt_master(&master()).unwrap_or_else(|e| panic!("{e}"));
            ks.add(Account::derive(&master(), 0)).unwrap_or_else(|e| panic!("{e}"));
        }
        let before = store.snapshot_bytes();
        let io = ScratchDir::new("pty-eof-io");
        let mut s = Session::spawn(io.path(), &["--dir", &dir, "--node", NODE, "balance"]);
        s.expect_prompt("password: ");
        s.send_eof();
        let o = s.finish();
        assert_eq!(o.code, Some(2), "end of input at the password prompt did not exit 2.\n--- screen ---\n{}\n--- stderr ---\n{}", o.screen, o.stderr);
        assert!(o.stderr.contains("end of input at the prompt"), "the refusal is not the end-of-input text:\n{}", o.stderr);
        assert!(
            !o.stderr.contains("did not decrypt") && !o.stderr.contains("password is wrong"),
            "END OF INPUT WAS REPORTED AS A WRONG PASSWORD: the binary read Ctrl-D as an empty line and compared it:\n{}",
            o.stderr
        );
        assert!(o.stdout.is_empty(), "stdout is not empty on the exit-2 path:\n{}", o.stdout);
        assert_eq!(store.snapshot_bytes(), before, "the store was touched by a refused prompt");
        let ks = Keystore::open(store.path(), &super::keystore_harness::unlock()).unwrap_or_else(|e| panic!("the lock was not released after the refusal: {e}"));
        drop(ks);

        let fresh = ScratchDir::new("pty-eof-create");
        let fresh_dir = fresh.path().to_string_lossy().into_owned();
        let io2 = ScratchDir::new("pty-eof-create-io");
        let mut s2 = Session::spawn(io2.path(), &["--dir", &fresh_dir, "create"]);
        s2.expect_prompt("choose a password for this wallet");
        s2.send_eof();
        let o2 = s2.finish();
        assert_eq!(o2.code, Some(3), "end of input at create's first prompt did not exit 3.\n--- screen ---\n{}\n--- stderr ---\n{}", o2.screen, o2.stderr);
        assert!(o2.stderr.contains("end of input at the prompt"), "create's refusal is not the end-of-input text:\n{}", o2.stderr);
        // Both the sentence and the absent directory.
        assert!(o2.stderr.contains("Nothing was created"), "create's end-of-input refusal does not say nothing was created:\n{}", o2.stderr);
        assert!(!fresh.path().exists(), "end of input at create's prompt made the directory {}", fresh.path().display());
        println!("tty end of input: one 0x04 byte at the password prompt -> exit 2 in the prompt's own words, store untouched; at create's prompt -> exit 3 saying nothing was created, and nothing was");
    }

    /// `address --account 1` through the shipped binary: no `--node`, the
    /// password answered, exit 0 with a destination on line one and NOT
    /// STORED on the page, nothing on stderr, and the snapshot bytes
    /// identical before and after.
    #[test]
    fn address_account_on_a_real_pty_needs_no_node_and_writes_nothing() {
        use mochimo_crypto::account::Account;
        let store = ScratchDir::new("pty-address-account");
        let dir = store.path().to_string_lossy().into_owned();
        {
            let mut ks = Keystore::create(store.path(), &super::keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
            let _ = ks.adopt_master(&master()).unwrap_or_else(|e| panic!("{e}"));
            ks.add(Account::derive(&master(), 0)).unwrap_or_else(|e| panic!("{e}"));
        }
        let before = store.snapshot_bytes();
        let io = ScratchDir::new("pty-address-account-io");
        let mut s = Session::spawn(io.path(), &["--dir", &dir, "address", "--account", "1"]);
        s.expect_prompt("password: ");
        s.send(PASSWORD);
        let o = s.finish();
        assert_eq!(o.code, Some(0), "address --account 1 did not exit 0.\n--- screen ---\n{}\n--- stderr ---\n{}", o.screen, o.stderr);
        assert!(o.stderr.is_empty(), "stderr is not empty on the exit-0 path:\n{}", o.stderr);
        let expected = mochimo_crypto::addr::tag_to_base58(&super::chain::tag1()).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(o.stdout.lines().next().unwrap_or_default(), expected, "line one is not account 1's destination:\n{}", o.stdout);
        assert!(o.stdout.contains("NOT STORED"), "the page does not say the account is not stored:\n{}", o.stdout);
        assert_eq!(store.snapshot_bytes(), before, "address --account WROTE to the store through the binary");
        println!("tty address --account: {} prompt(s), no node, exit 0, snapshot bytes identical", o.prompts);
    }

    /// A failed open leaves `keystore.lock` behind, and the leftover is
    /// inert: `create` refuses on the snapshot while it exists, and proceeds
    /// past the lock once it does not.
    ///
    /// Scenario: a copied store with no lock and version word 2. Fails if the
    /// failed open no longer leaves the lock, if `create` overwrites a
    /// snapshot it cannot read, or if `create` refuses a directory holding
    /// only an unheld lock.
    #[test]
    fn a_failed_open_leaves_an_inert_lock_and_create_proceeds_once_the_snapshot_is_gone() {
        let store = ScratchDir::new("pty-leftover-lock");
        let dir = store.path().to_string_lossy().into_owned();
        let has = |name: &str| store.listing().iter().any(|n| n == name);

        // A real store, then a copy with version word 2 and no lock. The
        // current word is 4 and 3 is still readable; 2 is refused.
        let ks = Keystore::create(store.path(), &super::keystore_harness::init())
            .unwrap_or_else(|e| panic!("{e}"));
        drop(ks);
        let mut image = store.snapshot_bytes();
        assert_eq!(
            u16::from_le_bytes([image[8], image[9]]),
            4,
            "premise: a fresh store's version word is 4; the flip below assumes the layout"
        );
        image[8..10].copy_from_slice(&2u16.to_le_bytes());
        store.write_snapshot(&image);
        std::fs::remove_file(store.path().join("keystore.lock")).unwrap_or_else(|e| panic!("{e}"));
        assert!(!has("keystore.lock"), "premise: the copy has no lock");

        // 1. `balance` prompts, opens, is refused on the version word -- and
        //    the lock is back.
        let io = ScratchDir::new("pty-leftover-balance-io");
        let mut s = Session::spawn(io.path(), &["--dir", &dir, "--node", NODE, "balance"]);
        s.expect_prompt("password: ");
        s.send(PASSWORD);
        let o = s.finish();
        assert_eq!(o.code, Some(2), "balance on a version-2 file did not exit 2.\n--- screen ---\n{}\n--- stderr ---\n{}", o.screen, o.stderr);
        assert!(o.stderr.contains("format version 2"), "the refusal does not name the version:\n{}", o.stderr);
        assert!(o.stdout.is_empty(), "stdout is not empty on the exit-2 path:\n{}", o.stdout);
        assert!(
            has("keystore.lock"),
            "the failed open did NOT leave keystore.lock: `open_with` no longer takes the lock \
             before the read, and the keystore module doc's \"The lock\" recording the side \
             effect is now false. Listing: {:?}",
            store.listing()
        );

        // 2. `create` over the unreadable snapshot: refused on the snapshot,
        //    before any prompt, with the bytes untouched.
        let io2 = ScratchDir::new("pty-leftover-create-refused-io");
        let s2 = Session::spawn(io2.path(), &["--dir", &dir, "create"]);
        let o2 = s2.finish();
        assert_eq!(o2.code, Some(3), "create over an existing snapshot did not exit 3.\n--- screen ---\n{}\n--- stderr ---\n{}", o2.screen, o2.stderr);
        assert!(o2.stderr.contains("a keystore already exists") && o2.stderr.contains("snapshot is present"), "the refusal does not name the snapshot:\n{}", o2.stderr);
        assert!(
            o2.stderr.contains("use a different --dir") && o2.stderr.contains("restore --account N"),
            "the refusal names no next step:\n{}",
            o2.stderr
        );
        assert!(!o2.stderr.contains("lock file"), "the refusal named the lock file rather than the snapshot:\n{}", o2.stderr);
        assert!(o2.screen.trim().is_empty(), "create over an existing store showed the operator something:\n{}", o2.screen);
        assert_eq!(store.snapshot_bytes(), image, "THE UNREADABLE SNAPSHOT WAS REWRITTEN by a refused create");

        // 3. The operator removes the snapshot; the lock stays; and
        //    `create` walks through it.
        std::fs::remove_file(store.path().join("accounts.mks")).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(store.listing(), vec!["keystore.lock".to_string()], "premise: only the lock remains");
        let io3 = ScratchDir::new("pty-leftover-create-io");
        let mut s3 = Session::spawn(io3.path(), &["--dir", &dir, "create"]);
        let words = drive_create(&mut s3);
        let o3 = s3.finish();
        assert_eq!(
            o3.code,
            Some(0),
            "create REFUSED a directory holding only an unheld keystore.lock -- the stale-lock \
             semantics the lock design chose flock to avoid.\n--- screen ---\n{}\n--- stderr ---\n{}",
            o3.screen,
            o3.stderr
        );
        let expected = destination_of(&words.join(" "));
        assert!(o3.stdout.contains(&format!("destination  {expected}")), "create's stdout lacks the destination:\n{}", o3.stdout);
        let ks = Keystore::open(
            store.path(),
            &Unlock { password: PASSWORD.as_bytes(), nonce_seed: [7u8; NONCE_SEED_LEN] },
        )
        .unwrap_or_else(|e| panic!("the store created through the leftover lock does not open: {e}"));
        assert_eq!(ks.tags().unwrap_or_else(|e| panic!("{e}")).len(), 1);
        drop(ks);

        println!(
            "tty leftover lock: {} prompt(s) answered on a pseudo-terminal across the refused open, the refused create and the create that proceeded",
            o.prompts + o2.prompts + o3.prompts
        );
    }


    /// A `--node` this program cannot use is refused before any prompt, for
    /// every command alike -- including the two that never dial.
    ///
    /// The transport is built first for every verb and opens no socket, so a
    /// bad URL is refused without a password prompt, Argon2id or the
    /// keystore lock.
    #[test]
    fn a_malformed_node_is_refused_before_any_prompt_whatever_the_command() {
        let store = ScratchDir::new("pty-badnode");
        let dir = store.path().to_string_lossy().into_owned();
        let mut refused = 0usize;
        for verb in ["create", "address", "balance"] {
            let io = ScratchDir::new("pty-badnode-io");
            let s = Session::spawn(io.path(), &["--dir", &dir, "--node", "localhost:8080", verb]);
            let o = s.finish();
            assert_eq!(o.code, Some(2), "`{verb} --node localhost:8080` did not exit 2.\n--- screen ---\n{}\n--- stderr ---\n{}", o.screen, o.stderr);
            assert!(o.stderr.contains("cannot use node localhost:8080"), "`{verb}`'s refusal does not name the node:\n{}", o.stderr);
            assert!(o.screen.trim().is_empty(), "`{verb}` showed the operator something before refusing the node:\n{}", o.screen);
            assert!(!o.screen.contains("password: ") && !o.stderr.contains("password: "), "`{verb}` asked for a password before refusing the node");
            assert!(o.stdout.is_empty(), "`{verb}` wrote to stdout on the exit-2 path:\n{}", o.stdout);
            assert!(!store.path().exists(), "`{verb}` made the directory {} before refusing the node", store.path().display());
            refused += 1;
        }
        println!("tty malformed node: {refused} command(s) refused before any prompt");
    }
    // ---------------------------------------------------------------------
    // The acknowledged path, through the shipped binary
    // ---------------------------------------------------------------------

    /// What the loopback answers `/construction/submit` with.
    #[derive(Clone, Copy)]
    enum Submit {
        /// The ledger entry, as for every other path, which `parse_submit`
        /// refuses.
        AsLedger,
        /// HTTP 503: the reservation is written and the write fails.
        Refuse,
        /// Echo this id as bare hex, the live endpoint's shape.
        Accept([u8; 32]),
    }

    /// The 20 bytes of the `"tag": "0x<40 hex>"` field of a `/call` body, if
    /// present. `None` for bodies that name no tag (`/block`,
    /// `/network/status`, a submit).
    fn asked_tag(body: &[u8]) -> Option<[u8; 20]> {
        let text = String::from_utf8_lossy(body);
        let at = text.find("\"tag\"")?;
        let rest = &text[at..];
        let start = rest.find("0x")? + 2;
        let hex: String = rest[start..].chars().take(40).collect();
        if hex.len() != 40 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let mut out = [0u8; 20];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(out)
    }

    /// A loopback Mesh endpoint that answers every `/call` with one ledger
    /// entry, switchable between requests, and counts the requests it
    /// answered.
    ///
    /// The binary uses the real `UreqTransport` over a real socket, as in
    /// `tests/mesh_http.rs`. The same balance and hash half are returned for
    /// every tag, with the asked-for tag spliced into the tag half so the
    /// codec's prefix check passes for any tag (needed by `discover`).
    struct Ledger {
        url: String,
        entry: Arc<Mutex<(mochimo_crypto::addr::Address, u64)>>,
        answered: Arc<Mutex<usize>>,
        stop: Arc<std::sync::atomic::AtomicBool>,
        submit: Arc<Mutex<Submit>>,
        /// Every `/construction/submit` body, whatever was answered.
        submits: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl Ledger {
        fn serve(address: mochimo_crypto::addr::Address, balance: u64) -> Ledger {
            use std::io::{Read as _, Write as _};
            use std::net::TcpListener;
            let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("bind: {e}"));
            listener.set_nonblocking(true).unwrap_or_else(|e| panic!("nonblocking: {e}"));
            let port = listener.local_addr().unwrap_or_else(|e| panic!("local_addr: {e}")).port();
            let entry = Arc::new(Mutex::new((address, balance)));
            let answered = Arc::new(Mutex::new(0usize));
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let submit = Arc::new(Mutex::new(Submit::AsLedger));
            let submits: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
            let (e2, a2, s2) = (Arc::clone(&entry), Arc::clone(&answered), Arc::clone(&stop));
            let (m2, b2) = (Arc::clone(&submit), Arc::clone(&submits));
            std::thread::spawn(move || {
                while !s2.load(std::sync::atomic::Ordering::Relaxed) {
                    let (mut stream, _) = match listener.accept() {
                        Ok(c) => c,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(10));
                            continue;
                        }
                        Err(e) => panic!("accept: {e}"),
                    };
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                    // Read one request: headers, then Content-Length bytes.
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 1024];
                    let header_end = loop {
                        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break Some(i + 4);
                        }
                        match stream.read(&mut chunk) {
                            Ok(0) | Err(_) => break None,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    };
                    let Some(header_end) = header_end else { continue };
                    let head = String::from_utf8_lossy(&buf[..header_end]).to_ascii_lowercase();
                    let len: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse().ok())
                        .unwrap_or(0);
                    while buf.len() < header_end + len {
                        match stream.read(&mut chunk) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let (mut address, balance) = *e2.lock().unwrap_or_else(|p| p.into_inner());
                    // The tag the body asked about, spliced over the answer's
                    // tag half so the codec's own check passes for any tag.
                    if let Some(asked) = asked_tag(&buf[header_end.min(buf.len())..]) {
                        address[..20].copy_from_slice(&asked);
                    }
                    // The request path, from the lower-cased head; Mesh paths
                    // are lower case.
                    let path = head.lines().next().and_then(|l| l.split_whitespace().nth(1)).unwrap_or("").to_owned();
                    let mode = *m2.lock().unwrap_or_else(|p| p.into_inner());
                    if path == "/construction/submit" {
                        let end = (header_end + len).min(buf.len());
                        b2.lock().unwrap_or_else(|p| p.into_inner()).push(buf[header_end..end].to_vec());
                    }
                    let (status, body) = match (path.as_str(), mode) {
                        ("/construction/submit", Submit::Refuse) => (
                            "503 Service Unavailable",
                            r#"{"error":"test: the lever refuses the write after the reservation is written"}"#.to_string(),
                        ),
                        ("/construction/submit", Submit::Accept(id)) => (
                            "200 OK",
                            format!(r#"{{"transaction_identifier":{{"hash":"{}"}}}}"#, hexs(&id)),
                        ),
                        // One row for the explorer verbs, in
                        // `/search/transactions` shape (source debited gross,
                        // change as its own destination, metadata as JSON
                        // numbers). Captured bodies are replayed in
                        // `tests/mesh.rs`.
                        ("/search/transactions", _) => (
                            "200 OK",
                            format!(
                                r#"{{"transactions":[{{"block_identifier":{{"index":1078535,"hash":"0x{h}"}},"transaction_identifier":{{"hash":"0x{t}"}},"timestamp":1788500208000,"operations":[{{"operation_identifier":{{"index":0}},"type":"SOURCE_TRANSFER","status":"SUCCESS","account":{{"address":"0x{tag}"}},"amount":{{"value":"-50000000","currency":{{"symbol":"MCM","decimals":9}}}}}},{{"operation_identifier":{{"index":1}},"type":"DESTINATION_TRANSFER","status":"SUCCESS","account":{{"address":"0xdbc01bb8a41f3dc24b0083bb6b9efe910e2477cb"}},"amount":{{"value":"10000000","currency":{{"symbol":"MCM","decimals":9}}}},"metadata":{{"memo":"PTY-1"}}}}],"metadata":{{"block_to_live":0,"change_total":39999500,"fee_total":500,"send_total":10000000}}}}],"total_count":1}}"#,
                                h = "36".repeat(32),
                                t = "18".repeat(32),
                                tag = hexs(&TAG),
                            ),
                        ),
                        _ => (
                            "200 OK",
                            format!(
                                r#"{{"result":{{"address":"0x{}","amount":{balance}}},"idempotent":true}}"#,
                                hexs(&address)
                            ),
                        ),
                    };
                    let reply = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(reply.as_bytes());
                    let _ = stream.flush();
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    *a2.lock().unwrap_or_else(|p| p.into_inner()) += 1;
                }
            });
            Ledger { url: format!("http://127.0.0.1:{port}"), entry, answered, stop, submit, submits }
        }

        fn set(&self, address: mochimo_crypto::addr::Address, balance: u64) {
            *self.entry.lock().unwrap_or_else(|p| p.into_inner()) = (address, balance);
        }

        fn answered(&self) -> usize {
            *self.answered.lock().unwrap_or_else(|p| p.into_inner())
        }

        /// Answer every `/construction/submit` with HTTP 503.
        fn refuse_submits(&self) {
            *self.submit.lock().unwrap_or_else(|p| p.into_inner()) = Submit::Refuse;
        }

        /// Echo `id` from `/construction/submit`. The caller supplies it from
        /// `SignedTransaction::id()` on a dry run.
        fn accept_submits(&self, id: [u8; 32]) {
            *self.submit.lock().unwrap_or_else(|p| p.into_inner()) = Submit::Accept(id);
        }

        /// Every submit body the loopback received, in order.
        fn submits(&self) -> Vec<Vec<u8>> {
            self.submits.lock().unwrap_or_else(|p| p.into_inner()).clone()
        }
    }

    impl Drop for Ledger {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// One command against the ledger, its password answered, its outcome.
    fn run_reconciling(io: &Path, dir: &str, url: &str, args: &[&str]) -> Outcome {
        let mut argv = vec!["--dir", dir, "--node", url];
        argv.extend_from_slice(args);
        let mut s = Session::spawn(io, &argv);
        s.expect_prompt("password: ");
        s.send(PASSWORD);
        s.finish()
    }

    /// The `resign` recovery completes through the shipped binary.
    ///
    /// `send` through a loopback that answers `/construction/submit` with
    /// HTTP 503: the reservation is written and the write fails, exit 3,
    /// stdout empty, the whole page including the artifact on stderr. Then
    /// `resign` with the same values while the loopback echoes the id: exit 0,
    /// stderr empty, the artifact and `submitted:` on stdout. The loopback
    /// holds two bodies, both the artifact byte for byte. The store is left
    /// at index 1 with the reservation open for `settle`.
    ///
    /// This harness sees the output streams, which `main` selects by exit
    /// code. A refused `resign` is covered in process.
    #[test]
    fn resign_on_a_real_pty_completes_the_recovery_send_could_not() {
        use mochimo_crypto::account::Account;
        let store = ScratchDir::new("pty-resign");
        let dir = store.path().to_string_lossy().into_owned();
        {
            let mut ks = Keystore::create(store.path(), &super::keystore_harness::init())
                .unwrap_or_else(|e| panic!("{e}"));
            let _ = ks.adopt_master(&master()).unwrap_or_else(|e| panic!("{e}"));
            ks.add(Account::derive(&master(), 0)).unwrap_or_else(|e| panic!("{e}"));
        }
        let tag_arg = format!("0x{}", hexs(&TAG));
        let to_arg = format!("0x{}", hexs(&super::TO));
        let ledger = Ledger::serve(addr_at(0), 5_000_000);
        ledger.refuse_submits();

        // 1. `send`: the socket refuses after the reservation is written.
        let io1 = ScratchDir::new("pty-resign-io1");
        let o1 = run_reconciling(io1.path(), &dir, &ledger.url, &["send", &tag_arg, &to_arg, "1000"]);
        assert_eq!(
            o1.code,
            Some(3),
            "send through a refusing socket did not exit 3.\n--- screen ---\n{}\n--- stderr ---\n{}\n--- stdout ---\n{}",
            o1.screen, o1.stderr, o1.stdout
        );
        assert!(o1.stdout.is_empty(), "send's exit-3 page reached stdout:\n{}", o1.stdout);
        let artifact = o1
            .stderr
            .lines()
            .find(|l| l.len() >= 200 && l.bytes().all(|b| b.is_ascii_hexdigit()))
            .unwrap_or_else(|| panic!("send's stderr carries no artifact line:\n{}", o1.stderr))
            .to_owned();
        assert!(o1.stderr.contains("submission FAILED"), "send's refusal is not on stderr:\n{}", o1.stderr);
        assert!(o1.stderr.contains("the only copy"), "send's refusal does not say the page is the only copy:\n{}", o1.stderr);

        // 2. `resign`: the same values, the socket now accepts.
        ledger.accept_submits(super::id_for_the_spend("pty-resign-id"));
        let io2 = ScratchDir::new("pty-resign-io2");
        let o2 = run_reconciling(io2.path(), &dir, &ledger.url, &["resign", &tag_arg, &to_arg, "1000"]);
        assert_eq!(
            o2.code,
            Some(0),
            "THE RECOVERY DID NOT COMPLETE THROUGH THE BINARY: resign with the exact values, against \
             a socket that accepts, did not exit 0. resign is meant to submit what it reproduces, so the \
             operator never needs a hand-built POST.\n--- screen ---\n{}\n--- stderr ---\n{}\n--- stdout ---\n{}",
            o2.screen, o2.stderr, o2.stdout
        );
        assert!(o2.stderr.is_empty(), "resign wrote to stderr on the exit-0 path:\n{}", o2.stderr);
        assert!(o2.stdout.contains(&artifact), "resign's stdout does not carry the artifact send printed:\n{}", o2.stdout);
        assert!(
            o2.stdout.contains("submitted: the node accepted the SOCKET WRITE"),
            "resign's stdout does not say the bytes were written, as send's does:\n{}",
            o2.stdout
        );
        assert!(o2.stdout.contains("Run `settle"), "resign's stdout does not name settle as the next step:\n{}", o2.stdout);

        // 3. The socket: two bodies, both the artifact.
        let bodies = ledger.submits();
        assert_eq!(bodies.len(), 2, "the loopback saw {} submit body(ies); send's refused write and resign's are two", bodies.len());
        for (i, b) in bodies.iter().enumerate() {
            assert_eq!(
                super::p10_signed_transaction_of(&hexs(b)).as_deref(),
                Some(artifact.as_str()),
                "submit body {i} does not carry the artifact byte for byte"
            );
        }

        // 4. The store, read in this process: index 1, reservation open.
        let ks = Keystore::open(store.path(), &super::keystore_harness::unlock()).unwrap_or_else(|e| panic!("{e}"));
        let v = ks.view(&TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("gone"));
        assert_eq!(
            (v.wots_index.get(), v.pending.is_some()),
            (1, true),
            "the store after the recovery is not index 1 with the reservation open; settle is what clears it"
        );
        drop(ks);
        assert!(ledger.answered() >= 4, "the loopback answered {} request(s); two commands each resolve and submit", ledger.answered());
        let digest = |b: &[u8]| hexs(&mochimo_crypto::backend::selected::sha256(b));
        println!(
            "tty resign: send refused at the socket (exit 3, the artifact on stderr), resign shipped the same bytes (exit 0, on stdout); {} prompt(s); bodies {} and {} bytes, sha256 {} and {}; artifact sha256 {}",
            o1.prompts + o2.prompts,
            bodies[0].len(),
            bodies[1].len(),
            digest(&bodies[0]),
            digest(&bodies[1]),
            digest(artifact.as_bytes())
        );
    }

    /// `send --ref AB-00-EF` through the shipped binary against the
    /// loopback: exit 0, the page carrying `ref  AB-00-EF` beside the other
    /// figures, and the one submit body on the socket carrying the artifact
    /// the page printed, with the reference at bytes 20..36 of its
    /// destination, NUL-padded.
    #[test]
    fn send_with_a_reference_on_a_real_pty_ships_it() {
        use mochimo_crypto::account::Account;
        let store = ScratchDir::new("pty-ref");
        let dir = store.path().to_string_lossy().into_owned();
        {
            let mut ks = Keystore::create(store.path(), &super::keystore_harness::init())
                .unwrap_or_else(|e| panic!("{e}"));
            let _ = ks.adopt_master(&master()).unwrap_or_else(|e| panic!("{e}"));
            ks.add(Account::derive(&master(), 0)).unwrap_or_else(|e| panic!("{e}"));
        }
        let tag_arg = format!("0x{}", hexs(&TAG));
        let to_arg = format!("0x{}", hexs(&super::TO));
        let s = super::spend_with_reference("AB-00-EF");
        let ledger = Ledger::serve(addr_at(0), 5_000_000);
        ledger.accept_submits(super::id_for("pty-ref-id", &s));
        let io = ScratchDir::new("pty-ref-io");
        let o = run_reconciling(io.path(), &dir, &ledger.url, &["send", &tag_arg, &to_arg, "1000", "--ref", "AB-00-EF"]);
        assert_eq!(
            o.code,
            Some(0),
            "send --ref through the binary did not exit 0.\n--- screen ---\n{}\n--- stderr ---\n{}\n--- stdout ---\n{}",
            o.screen, o.stderr, o.stdout
        );
        assert!(o.stderr.is_empty(), "send --ref wrote to stderr on the exit-0 path:\n{}", o.stderr);
        assert!(o.stdout.contains("       ref AB-00-EF"), "the page does not carry the reference line:\n{}", o.stdout);
        assert!(o.stdout.contains("submitted: the node accepted the SOCKET WRITE"), "the page does not say the bytes were written:\n{}", o.stdout);
        let artifact = o
            .stdout
            .lines()
            .find(|l| l.len() >= 200 && l.bytes().all(|b| b.is_ascii_hexdigit()))
            .unwrap_or_else(|| panic!("the page carries no artifact line:\n{}", o.stdout))
            .to_owned();
        let bodies = ledger.submits();
        assert_eq!(bodies.len(), 1, "the loopback saw {} submit body(ies); one send is one", bodies.len());
        let shipped = super::p10_signed_transaction_of(&hexs(&bodies[0])).unwrap_or_else(|| panic!("the body carries no signed_transaction"));
        assert_eq!(shipped, artifact, "the body is not the artifact the page printed");
        let bytes = super::bytes_of(&shipped);
        assert_eq!(&bytes[136..152], b"AB-00-EF\0\0\0\0\0\0\0\0", "the shipped destination reference is not AB-00-EF NUL-padded at image offset 136..152");
        assert_eq!(&bytes[116..136], &super::TO[..], "the shipped destination tag is not at image offset 116");
        println!(
            "tty send --ref: exit 0, {} prompt(s), one body of {} bytes whose destination reference is AB-00-EF NUL-padded at image offset 136..152",
            o.prompts,
            bodies[0].len()
        );
    }

    /// `discover` through the shipped binary: exit 0, the extent on the page,
    /// the held account marked, and the store untouched.
    ///
    /// The loopback resolves every index. This test covers the real
    /// transport, a single prompt, and no writes to a real directory.
    #[test]
    fn discover_on_a_real_pty_sweeps_and_writes_nothing() {
        use mochimo_crypto::account::Account;
        let store = ScratchDir::new("pty-discover");
        let dir = store.path().to_string_lossy().into_owned();
        {
            let mut ks = Keystore::create(store.path(), &super::keystore_harness::init())
                .unwrap_or_else(|e| panic!("{e}"));
            let _ = ks.adopt_master(&master()).unwrap_or_else(|e| panic!("{e}"));
            ks.add(Account::derive(&master(), 0)).unwrap_or_else(|e| panic!("{e}"));
        }
        let before = store.snapshot_bytes();
        let ledger = Ledger::serve(addr_at(0), 4_200);
        let io = ScratchDir::new("pty-discover-io");
        let o = run_reconciling(io.path(), &dir, &ledger.url, &["discover", "--to", "2"]);
        assert_eq!(
            o.code,
            Some(0),
            "discover through the binary did not exit 0.\n--- screen ---\n{}\n--- stderr ---\n{}\n--- stdout ---\n{}",
            o.screen, o.stderr, o.stdout
        );
        assert!(o.stderr.is_empty(), "stderr is not empty on the exit-0 path:\n{}", o.stderr);
        assert!(o.stdout.contains("searched account indices 0..=2"), "the extent is not on the page:\n{}", o.stdout);
        assert!(o.stdout.contains("3 index(es), one node call each"), "{}", o.stdout);
        assert!(
            o.stdout.contains("IN THIS STORE (derived, at key index 0)"),
            "the held account is not marked:\n{}",
            o.stdout
        );
        assert!(
            !o.stdout.to_ascii_lowercase().contains("does not exist"),
            "the page asserts absence:\n{}",
            o.stdout
        );
        assert_eq!(store.snapshot_bytes(), before, "discover WROTE to the store through the binary");
        assert!(ledger.answered() >= 3, "the loopback answered {} request(s); three indices are three calls", ledger.answered());
        println!(
            "tty discover: {} prompt(s), exit 0, {} loopback answer(s) for 3 indices, snapshot bytes identical",
            o.prompts,
            ledger.answered()
        );
    }

    /// A three-destination `send` through the shipped binary: the positional
    /// pairs reach the wire as three destinations, the fee is the floor for
    /// three, and the image has the matching length.
    /// `options[2]` is the destination count minus one, so three reads as 2.
    #[test]
    fn send_to_three_destinations_on_a_real_pty_ships_all_three() {
        use mochimo_crypto::account::Account;
        let store = ScratchDir::new("pty-multi");
        let dir = store.path().to_string_lossy().into_owned();
        {
            let mut ks = Keystore::create(store.path(), &super::keystore_harness::init())
                .unwrap_or_else(|e| panic!("{e}"));
            let _ = ks.adopt_master(&master()).unwrap_or_else(|e| panic!("{e}"));
            ks.add(Account::derive(&master(), 0)).unwrap_or_else(|e| panic!("{e}"));
        }
        let tags = [[0x6bu8; 20], [0x7cu8; 20], [0x9cu8; 20]];
        let args: Vec<String> = tags.iter().map(|t| format!("0x{}", hexs(t))).collect();
        let tag_arg = format!("0x{}", hexs(&TAG));
        let mut s = super::spend();
        s.dsts = tags
            .iter()
            .zip([1_000u64, 2_000, 3_000])
            .map(|(t, a)| super::SpendTo { to: *t, reference: [0; 16], amount: Some(a) })
            .collect();
        s.fee_total = super::MFEE * 3;
        let ledger = Ledger::serve(addr_at(0), 5_000_000);
        ledger.accept_submits(super::id_for("pty-multi-id", &s));
        let io = ScratchDir::new("pty-multi-io");
        let o = run_reconciling(
            io.path(),
            &dir,
            &ledger.url,
            &["send", &tag_arg, &args[0], "1000", &args[1], "2000", &args[2], "3000"],
        );
        assert_eq!(
            o.code,
            Some(0),
            "a three-destination send through the binary did not exit 0.\n--- screen ---\n{}\n--- stderr ---\n{}\n--- stdout ---\n{}",
            o.screen, o.stderr, o.stdout
        );
        assert!(o.stdout.contains("sending 6000 nanoMCM to 3 destination(s)"), "{}", o.stdout);
        assert!(
            o.stdout.contains("fee    1500 total (the node's floor is 500 per destination, 1500 here)"),
            "the page does not state the floor for three:\n{}",
            o.stdout
        );
        let bodies = ledger.submits();
        assert_eq!(bodies.len(), 1, "the loopback saw {} submit body(ies)", bodies.len());
        let shipped = super::p10_signed_transaction_of(&hexs(&bodies[0]))
            .unwrap_or_else(|| panic!("the body carries no signed_transaction"));
        let bytes = super::bytes_of(&shipped);
        assert_eq!(bytes.get(2), Some(&2u8), "options[2] is not `three destinations minus one`");
        assert_eq!(bytes.len(), 2364 + 44 * 3, "the image is not the length three destinations give");
        println!(
            "tty send x3: exit 0, one body of {} bytes, options[2] = 2, fee 1500 = 500 x 3",
            bodies[0].len()
        );
    }

    /// `submit` sends a saved artifact through the shipped binary and opens no
    /// store.
    ///
    /// The artifact comes from an in-process `send` whose write was refused.
    /// This process holds that store's lock for the whole run while the
    /// binary runs with `--dir` naming it. Expected: no password prompt, exit
    /// 0, `submitted:` on stdout, nothing on stderr, exactly one
    /// `/construction/submit` request carrying the artifact byte for byte,
    /// and the store unchanged (index 1, reservation open).
    #[test]
    fn submit_on_a_real_pty_ships_a_saved_artifact_and_opens_no_store() {
        let (store, artifact) = super::send_that_never_left("pty-submit");
        // Take the hold through the harness's `reopen`, not `Keystore::open`.
        // Tests run on parallel threads that spawn children, and a child
        // briefly inherits this process's descriptors (and so the `flock` of
        // the just-dropped handle) until its `exec`. `reopen` retries
        // `Locked`, bounded, and reports when it had to; see its doc.
        let held = super::reopen("pty submit hold", store.path())
            .result
            .unwrap_or_else(|e| panic!("cannot hold the store's lock: {e}"));
        let ledger = Ledger::serve(addr_at(0), 5_000_000);
        ledger.accept_submits(super::id_for_the_spend("pty-submit-id"));
        let dir = store.path().to_string_lossy().into_owned();
        let io = ScratchDir::new("pty-submit-io");
        let s = Session::spawn(io.path(), &["--dir", &dir, "--node", &ledger.url, "submit", &artifact]);
        let o = s.finish();
        assert_eq!(
            o.code,
            Some(0),
            "submit through the binary did not exit 0.\n--- screen ---\n{}\n--- stderr ---\n{}\n--- stdout ---\n{}",
            o.screen, o.stderr, o.stdout
        );
        assert!(
            !o.screen.contains("password: ") && !o.stderr.contains("password: "),
            "submit asked for a password; it opens no store.\n--- screen ---\n{}\n--- stderr ---\n{}",
            o.screen, o.stderr
        );
        assert!(o.stderr.is_empty(), "submit wrote to stderr on the exit-0 path:\n{}", o.stderr);
        assert!(
            o.stdout.contains("submitted: the node accepted the SOCKET WRITE"),
            "submit's stdout does not say the bytes were written, as send's does:\n{}",
            o.stdout
        );
        assert!(o.stdout.contains("Run `settle"), "submit's stdout does not name settle as the next step:\n{}", o.stdout);
        assert!(o.stdout.contains("No store was opened"), "submit's page does not say no store was opened:\n{}", o.stdout);
        let bodies = ledger.submits();
        assert_eq!(bodies.len(), 1, "the loopback saw {} submit body(ies); the artifact needs one", bodies.len());
        assert_eq!(
            super::p10_signed_transaction_of(&hexs(&bodies[0])).as_deref(),
            Some(artifact.as_str()),
            "the submit body does not carry the artifact byte for byte"
        );
        assert_eq!(ledger.answered(), 1, "submit made {} request(s); it resolves nothing and submits once", ledger.answered());
        drop(held);
        // Released and re-taken at once, through `reopen` as above.
        let ks = super::reopen("pty submit after", store.path()).result.unwrap_or_else(|e| panic!("{e}"));
        let v = ks.view(&TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("gone"));
        assert_eq!(
            (v.wots_index.get(), v.pending.is_some()),
            (1, true),
            "the store after submit is not what send left; submit writes nothing"
        );
        drop(ks);
        let digest = |b: &[u8]| hexs(&mochimo_crypto::backend::selected::sha256(b));
        println!(
            "tty submit: the artifact of a refused send shipped by the binary with the store locked and no prompt (exit 0, on stdout); {} prompt(s); body {} bytes, sha256 {}; artifact sha256 {}",
            o.prompts,
            bodies[0].len(),
            digest(&bodies[0]),
            digest(artifact.as_bytes())
        );
    }

    /// `submit` refuses what is not an artifact before any socket is opened,
    /// and needs no store directory.
    ///
    /// Three inputs against an accepting loopback: text that is not hex, hex
    /// that is no transaction, and a real artifact one byte short (a length
    /// `from_wire` accepts and zero-extends). Each exits 3 with the refusal
    /// on stderr saying nothing was written; the loopback receives nothing;
    /// no password is asked; and the nonexistent `--dir` is still absent.
    #[test]
    fn submit_on_a_real_pty_refuses_what_is_not_an_artifact_before_the_socket() {
        let (_store, artifact) = super::send_that_never_left("pty-submit-refuse");
        let ledger = Ledger::serve(addr_at(0), 5_000_000);
        ledger.accept_submits(super::id_for_the_spend("pty-submit-refuse-id"));
        let absent = ScratchDir::new("pty-submit-absent");
        let dir = absent.path().to_string_lossy().into_owned();
        let truncated = artifact[..artifact.len() - 2].to_owned();
        let cases: [(&str, &str); 3] = [
            ("zz", "is not hex"),
            ("00ff", "does not parse as a transaction"),
            (truncated.as_str(), "is not a whole transaction image"),
        ];
        let mut refused = 0usize;
        for (input, why) in cases {
            let shown = &input[..input.len().min(16)];
            let io = ScratchDir::new("pty-submit-refuse-io");
            let s = Session::spawn(io.path(), &["--dir", &dir, "--node", &ledger.url, "submit", input]);
            let o = s.finish();
            assert_eq!(
                o.code,
                Some(3),
                "`submit {shown}...` did not exit 3.\n--- screen ---\n{}\n--- stderr ---\n{}\n--- stdout ---\n{}",
                o.screen, o.stderr, o.stdout
            );
            assert!(o.stderr.contains(why), "the refusal for `{shown}...` does not say the artifact {why}:\n{}", o.stderr);
            assert!(
                o.stderr.contains("Nothing was written to the socket"),
                "the refusal for `{shown}...` does not say nothing was written:\n{}",
                o.stderr
            );
            assert!(o.stdout.is_empty(), "stdout is not empty on the exit-3 path:\n{}", o.stdout);
            assert!(
                !o.screen.contains("password: ") && !o.stderr.contains("password: "),
                "`submit {shown}...` asked for a password"
            );
            assert!(!absent.path().exists(), "`submit {shown}...` made the store directory {}", absent.path().display());
            refused += 1;
        }
        assert_eq!(ledger.submits().len(), 0, "a refused artifact reached the socket: {} body(ies)", ledger.submits().len());
        assert_eq!(ledger.answered(), 0, "the loopback answered {} request(s); a refused artifact opens no socket", ledger.answered());
        println!("tty submit refusals: {refused} inputs refused before the socket, no prompt, no directory made");
    }

    /// `recent-transactions` through the shipped binary opens no store and
    /// asks no password. `--dir` names a nonexistent directory that is still
    /// absent afterwards.
    #[test]
    fn recent_transactions_on_a_real_pty_opens_no_store_and_asks_no_password() {
        let ledger = Ledger::serve(addr_at(0), 5_000_000);
        let absent = ScratchDir::new("pty-recent-absent");
        let dir = absent.path().join("no-wallet-here").to_string_lossy().into_owned();
        let tag_arg = format!("0x{}", hexs(&TAG));
        let io = ScratchDir::new("pty-recent-io");
        let s = Session::spawn(io.path(), &["--dir", &dir, "--node", &ledger.url, "recent-transactions", &tag_arg]);
        let o = s.finish();
        assert_eq!(
            o.code,
            Some(0),
            "recent-transactions through the binary did not exit 0.\n--- screen ---\n{}\n--- stderr ---\n{}\n--- stdout ---\n{}",
            o.screen, o.stderr, o.stdout
        );
        assert!(
            !o.screen.contains("password: ") && !o.stderr.contains("password: "),
            "recent-transactions asked for a password; it opens no store.\n--- screen ---\n{}",
            o.screen
        );
        assert!(o.stderr.is_empty(), "recent-transactions wrote to stderr on the exit-0 path:\n{}", o.stderr);
        assert!(
            !std::path::Path::new(&dir).exists(),
            "recent-transactions made the store directory {dir}"
        );
        assert!(o.stdout.contains("1 of 1 row(s), newest first"), "{}", o.stdout);
        assert!(o.stdout.contains("block   1078535"), "{}", o.stdout);
        assert!(o.stdout.contains("memo PTY-1"), "the memo is not on the page:\n{}", o.stdout);
        assert!(o.stdout.contains("/search/transactions"), "the page does not name the endpoint:\n{}", o.stdout);
        assert_eq!(ledger.answered(), 1, "recent-transactions made {} request(s); it asks one", ledger.answered());
        println!(
            "tty recent-transactions: exit 0, {} prompt(s), the store directory never made, one request to the node",
            o.prompts
        );
    }

    /// The acknowledged path works in the shipped binary and verifies the
    /// index it is given. `reconcile` runs before `Wallet::open`, which would
    /// refuse on the divergence being reconciled.
    #[test]
    fn reconcile_on_a_real_pty_takes_the_acknowledged_path_the_report_names() {
        use mochimo_crypto::account::Account;
        let store = ScratchDir::new("pty-reconcile");
        let dir = store.path().to_string_lossy().into_owned();
        {
            let mut ks = Keystore::create(store.path(), &super::keystore_harness::init())
                .unwrap_or_else(|e| panic!("{e}"));
            let _ = ks.adopt_master(&master()).unwrap_or_else(|e| panic!("{e}"));
            ks.add(Account::derive(&master(), 0)).unwrap_or_else(|e| panic!("{e}"));
        }
        let tag_arg = format!("0x{}", hexs(&TAG));
        let mut prompts = 0usize;

        // The chain sits at index 2; the store at 0. Local behind, gap 2.
        let ledger = Ledger::serve(addr_at(2), 9);

        // 1. `balance` refuses with I4's report and names the path.
        let io1 = ScratchDir::new("pty-reconcile-io1");
        let o1 = run_reconciling(io1.path(), &dir, &ledger.url, &["balance"]);
        prompts += o1.prompts;
        assert_eq!(o1.code, Some(2), "balance on a diverged store did not exit 2.\n--- screen ---\n{}\n--- stderr ---\n{}", o1.screen, o1.stderr);
        assert!(o1.stderr.contains("key at index 2 -- 2 ahead of local"), "the report does not name the chain's index and the gap:\n{}", o1.stderr);
        assert!(o1.stderr.contains(&format!("reconcile {tag_arg} --advance-to 2")), "the report does not print the command that takes the acknowledged path:\n{}", o1.stderr);

        // 2. A wrong number is refused by the acknowledgement check: exit 3,
        //    the mismatch named, nothing written.
        let io2 = ScratchDir::new("pty-reconcile-io2");
        let o2 = run_reconciling(io2.path(), &dir, &ledger.url, &["reconcile", &tag_arg, "--advance-to", "7"]);
        prompts += o2.prompts;
        assert_eq!(o2.code, Some(3), "reconcile with the wrong index did not exit 3.\n--- screen ---\n{}\n--- stderr ---\n{}\n--- stdout ---\n{}", o2.screen, o2.stderr, o2.stdout);
        assert!(o2.stderr.contains("--advance-to 7 does not match the index this divergence reports (2)"), "the mismatch is not named:\n{}", o2.stderr);

        // 3. The number the report named advances the store: exit 0.
        let io3 = ScratchDir::new("pty-reconcile-io3");
        let o3 = run_reconciling(io3.path(), &dir, &ledger.url, &["reconcile", &tag_arg, "--advance-to", "2"]);
        prompts += o3.prompts;
        assert_eq!(
            o3.code,
            Some(0),
            "THE ACKNOWLEDGED PATH IS NOT REACHABLE: reconcile with the exact index the report \
             named did not exit 0, which leaves a divergence with no way out of it.\n--- screen ---\n{}\n--- stderr ---\n{}\n--- stdout ---\n{}",
            o3.screen, o3.stderr, o3.stdout
        );
        assert!(o3.stdout.contains("to index 2 after operator review"), "reconcile's stdout does not say what it did:\n{}", o3.stdout);
        assert!(o3.stdout.contains("THE STORE BEFORE THIS DECISION"), "the report was not printed before the write:\n{}", o3.stdout);

        // 4. `balance` now opens: in sync at index 2.
        let io4 = ScratchDir::new("pty-reconcile-io4");
        let o4 = run_reconciling(io4.path(), &dir, &ledger.url, &["balance"]);
        prompts += o4.prompts;
        assert_eq!(o4.code, Some(0), "balance after the advance did not open.\n--- stderr ---\n{}", o4.stderr);
        assert!(o4.stdout.contains("index 2") && o4.stdout.contains("in sync"), "balance does not show index 2 in sync:\n{}", o4.stdout);

        // 5. The chain moves to index 30, past the window. `status --scan-to
        //    19` (a ceiling of 20) reports it out of reach: exit 0, the report
        //    on stdout, and the next step named without choosing among the
        //    causes. The default ceiling of 10,000 would find it (step 5b).
        ledger.set(addr_at(30), 11);
        let io5 = ScratchDir::new("pty-reconcile-io5");
        let o5 = run_reconciling(io5.path(), &dir, &ledger.url, &["status", &tag_arg, "--scan-to", "19"]);
        prompts += o5.prompts;
        assert_eq!(o5.code, Some(0), "status on a far-along divergence did not exit 0.\n--- stderr ---\n{}\n--- stdout ---\n{}", o5.stderr, o5.stdout);
        assert!(o5.stdout.contains("NO key index this scan walked"), "status does not report the unlocated address on stdout:\n{}", o5.stdout);
        assert!(o5.stdout.contains("indices 0 through 19"), "status does not say what it walked:\n{}", o5.stdout);
        assert!(!o5.stdout.contains("does not own this tag, or"), "status still asserts the closed disjunction:\n{}", o5.stdout);
        assert!(o5.stderr.is_empty(), "status wrote to stderr on the exit-0 path:\n{}", o5.stderr);

        // 5b. With no flag, the default ceiling reaches index 30 and names it.
        let io5b = ScratchDir::new("pty-reconcile-io5b");
        let o5b = run_reconciling(io5b.path(), &dir, &ledger.url, &["status", &tag_arg]);
        prompts += o5b.prompts;
        assert_eq!(o5b.code, Some(0), "status at the default ceiling did not exit 0.\n--- stderr ---\n{}\n--- stdout ---\n{}", o5b.stderr, o5b.stdout);
        assert!(o5b.stdout.contains("key at index 30 -- 28 ahead of local"), "the DEFAULT ceiling did not reach index 30:\n{}", o5b.stdout);

        // 6. `status --scan-to 40` finds the exact index by searching further.
        let io6 = ScratchDir::new("pty-reconcile-io6");
        let o6 = run_reconciling(io6.path(), &dir, &ledger.url, &["status", &tag_arg, "--scan-to", "40"]);
        prompts += o6.prompts;
        assert_eq!(o6.code, Some(0), "status --scan-to on a divergence did not exit 0.\n--- stderr ---\n{}\n--- stdout ---\n{}", o6.stderr, o6.stdout);
        assert!(o6.stdout.contains("key at index 30 -- 28 ahead of local"), "the raised ceiling did not find index 30:\n{}", o6.stdout);
        assert!(o6.stdout.contains(&format!("reconcile {tag_arg} --advance-to 30")), "status does not print the command that follows:\n{}", o6.stdout);

        // 7. A named far-along index is verified: 29 is refused with nothing
        //    written, 30 advances.
        let io7 = ScratchDir::new("pty-reconcile-io7");
        let o7 = run_reconciling(io7.path(), &dir, &ledger.url, &["reconcile", &tag_arg, "--advance-to", "29"]);
        prompts += o7.prompts;
        assert_eq!(o7.code, Some(3), "a wrong far-along index was not refused.\n--- stderr ---\n{}\n--- stdout ---\n{}", o7.stderr, o7.stdout);
        assert!(o7.stderr.contains("indices 0 through 29"), "the refusal does not say the named index was walked:\n{}", o7.stderr);
        assert!(o7.stderr.contains("no advance to acknowledge"), "the refusal does not say why:\n{}", o7.stderr);
        let io8 = ScratchDir::new("pty-reconcile-io8");
        let o8 = run_reconciling(io8.path(), &dir, &ledger.url, &["reconcile", &tag_arg, "--advance-to", "30"]);
        prompts += o8.prompts;
        assert_eq!(o8.code, Some(0), "a verified far-along index did not advance.\n--- stderr ---\n{}\n--- stdout ---\n{}", o8.stderr, o8.stdout);
        assert!(o8.stdout.contains("to index 30 after operator review"), "reconcile's stdout does not name the index:\n{}", o8.stdout);
        let io9 = ScratchDir::new("pty-reconcile-io9");
        let o9 = run_reconciling(io9.path(), &dir, &ledger.url, &["balance"]);
        prompts += o9.prompts;
        assert_eq!(o9.code, Some(0), "balance after the far-along advance did not open.\n--- stderr ---\n{}", o9.stderr);
        assert!(o9.stdout.contains("index 30") && o9.stdout.contains("in sync"), "balance does not show index 30 in sync:\n{}", o9.stdout);

        // The store on disk agrees, read in this process.
        let ks = Keystore::open(store.path(), &super::keystore_harness::unlock()).unwrap_or_else(|e| panic!("{e}"));
        let v = ks.view(&TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("gone"));
        assert_eq!(v.wots_index.get(), 30, "the store is not at the index the binary said it advanced to");
        drop(ks);

        assert!(ledger.answered() >= 9, "the ledger answered {} request(s); fewer than the nine commands means a command never dialed", ledger.answered());
        println!(
            "tty reconcile: {prompts} prompt(s) answered on a pseudo-terminal across the refusal, the acknowledged advance, the far-along search and the verified advance"
        );
    }

}

// ===========================================================================
// Recovery after a lost page. Each test drives the command layer over a
// store the operator returns to in a fresh process.
// ===========================================================================

/// The operator's next session, as a separate process.
///
/// The tests below model an operator who ran `send`, lost the page, and
/// returns with the store, the password and the phrase. A fresh process
/// ensures only the file on disk and the chain carry state, not process
/// memory. The parent re-executes this test binary
/// (`std::env::current_exe`) with this test selected (`--exact`); the child
/// runs one command over the same directory against a chain scripted from
/// the environment, printing its output between markers the parent parses.
///
/// In the parent run, with no environment set, this test does nothing.
///
/// The environment, all set by [`p10_child_session_run`]:
/// `P10_CHILD_STORE` (the directory), `P10_CHILD_CMD` (`status`, `balance`,
/// `settle`, `resign:<btl>`, or `argv:` followed by argv words joined by
/// `\x1f`), `P10_CHILD_BALANCE` and `P10_CHILD_ADDR_INDEX` (the ledger's
/// entry for `TAG`: `addr_at(index)` with that balance), `P10_CHILD_TIP`
/// (what `/network/status` answers), and `P10_CHILD_ACCEPT_ID` (a hex id
/// `/construction/submit` echoes; if absent, the socket refuses).
#[test]
fn p10_child_session() {
    let Ok(dir) = std::env::var("P10_CHILD_STORE") else {
        println!("  child session: not invoked as a child; nothing to do here");
        return;
    };
    let need = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("child: {k} is unset"));
    let cmd = need("P10_CHILD_CMD");
    let balance: u64 = need("P10_CHILD_BALANCE").parse().expect("child: P10_CHILD_BALANCE");
    let addr_index: u32 = std::env::var("P10_CHILD_ADDR_INDEX").ok().map_or(0, |s| s.parse().expect("child: P10_CHILD_ADDR_INDEX"));
    let tip: u64 = need("P10_CHILD_TIP").parse().expect("child: P10_CHILD_TIP");

    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(addr_index), balance))]);
    chain.set_tip(tip);
    match std::env::var("P10_CHILD_ACCEPT_ID") {
        Ok(h) => {
            let mut id = [0u8; 32];
            for (i, b) in id.iter_mut().enumerate() {
                *b = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).expect("child: P10_CHILD_ACCEPT_ID hex");
            }
            chain.accepts_submit(id);
        }
        Err(_) => chain.refuses_submit(),
    }
    let log = chain.submit_log();
    let path = std::path::Path::new(&dir);
    let ks = reopen("child", path).result.unwrap_or_else(|e| panic!("child: cannot open the store: {e}"));
    let client = MeshClient::new(chain);

    let report = match cmd.as_str() {
        "status" => cli::run(ks, client, &Command::Status { tag: TAG, scan_to: None }),
        "balance" => cli::run(ks, client, &Command::Balance),
        "settle" => cli::run(ks, client, &Command::Settle { tag: TAG }),
        s if s.starts_with("resign:") => {
            let mut sp = spend();
            sp.blk_to_live = s["resign:".len()..].parse().expect("child: resign:<btl>");
            cli::run(ks, client, &Command::Resign(sp))
        }
        s if s.starts_with("argv:") => {
            let mut argv: Vec<String> = vec!["--dir".into(), dir.clone(), "--node".into(), "http://127.0.0.1:1".into()];
            argv.extend(s["argv:".len()..].split('\x1f').map(str::to_owned));
            match args::parse(&argv) {
                Ok(args::ParsedArgv::Run(inv)) => cli::run(ks, client, &inv.command),
                Ok(args::ParsedArgv::Help) => cli::Report { text: "help".into(), code: Code::Ok },
                Err(u) => {
                    // Nothing consumed the store on this path; release the
                    // lock before the read-back below reopens it.
                    drop(ks);
                    drop(client);
                    println!("<<<CHILD USAGE>>>{}", u.0);
                    cli::Report { text: format!("{u}"), code: Code::Usage }
                }
            }
        }
        other => panic!("child: unknown P10_CHILD_CMD {other:?}"),
    };
    println!("<<<CHILD CODE>>>{}", report.code as i32);
    println!("<<<CHILD REPORT>>>\n{}\n<<<CHILD END>>>", report.text);
    for body in log.borrow().iter() {
        println!("<<<CHILD SUBMIT>>>{}", hexs(body));
    }
    // The store after the command, read back from disk: the index and
    // whether a reservation is still open.
    let after = reopen("child after", path).result.unwrap_or_else(|e| panic!("child: cannot reopen the store: {e}"));
    let view = after
        .view(&TAG)
        .unwrap_or_else(|e| panic!("child: {e}"))
        .unwrap_or_else(|| panic!("child: the store no longer holds TAG"));
    println!("<<<CHILD INDEX>>>{}", view.wots_index.get());
    println!("<<<CHILD PENDING>>>{}", u8::from(view.pending.is_some()));
}

/// What a child session printed, parsed back.
struct P10Child {
    code: i32,
    text: String,
    /// Every `/construction/submit` body the chain saw, hex-encoded.
    submits: Vec<String>,
    /// The usage error, when argv did not parse.
    usage: Option<String>,
    index: u32,
    pending: bool,
}

/// Run one command in a child session over `dir`; see [`p10_child_session`].
///
/// # Panics
///
/// If the child prints no report.
fn p10_child_session_run(dir: &std::path::Path, cmd: &str, balance: u64, addr_index: u32, tip: u64, accept: Option<[u8; 32]>) -> P10Child {
    let me = std::env::current_exe().expect("current_exe");
    let mut c = std::process::Command::new(me);
    c.args(["--exact", "p10_child_session", "--nocapture", "--test-threads", "1"])
        .env("P10_CHILD_STORE", dir)
        .env("P10_CHILD_CMD", cmd)
        .env("P10_CHILD_BALANCE", balance.to_string())
        .env("P10_CHILD_ADDR_INDEX", addr_index.to_string())
        .env("P10_CHILD_TIP", tip.to_string());
    match accept {
        Some(id) => {
            c.env("P10_CHILD_ACCEPT_ID", hexs(&id));
        }
        None => {
            c.env_remove("P10_CHILD_ACCEPT_ID");
        }
    }
    let out = c.output().unwrap_or_else(|e| panic!("cannot spawn the child session: {e}"));
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "the child session for `{cmd}` failed ({}):\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        out.status
    );
    // Anywhere in a line, not only at its start: under `--nocapture` libtest
    // prints `test p10_child_session ... ` on the same line.
    let after = |marker: &str| -> Option<String> {
        stdout
            .lines()
            .find_map(|l| l.find(marker).map(|i| l[i + marker.len()..].to_owned()))
    };
    let code: i32 = after("<<<CHILD CODE>>>")
        .unwrap_or_else(|| panic!("the child session for `{cmd}` printed no report:\n{stdout}\n--- stderr ---\n{stderr}"))
        .parse()
        .expect("child code");
    let start = stdout.find("<<<CHILD REPORT>>>\n").expect("report start") + "<<<CHILD REPORT>>>\n".len();
    let end = stdout[start..].find("\n<<<CHILD END>>>").expect("report end") + start;
    let text = stdout[start..end].to_owned();
    let submits: Vec<String> = stdout.lines().filter_map(|l| l.strip_prefix("<<<CHILD SUBMIT>>>").map(str::to_owned)).collect();
    let usage = after("<<<CHILD USAGE>>>");
    let index: u32 = after("<<<CHILD INDEX>>>").expect("child index").parse().expect("child index");
    let pending = after("<<<CHILD PENDING>>>").expect("child pending") == "1";
    P10Child { code, text, submits, usage, index, pending }
}

/// A `send` whose submission the socket refused: the reservation is open and
/// the artifact was printed once, on the page the operator then loses.
struct P10Sent {
    dir: ScratchDir,
    artifact_hex: String,
}

fn p10_send_that_never_left(name: &str, blk_to_live: u64, tip: u64) -> P10Sent {
    let (dir, ks) = store(name);
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.set_tip(tip);
    chain.refuses_submit();
    let mut s = spend();
    s.blk_to_live = blk_to_live;
    let r = cli::run(ks, MeshClient::new(chain), &Command::Send(s));
    assert_eq!(r.code, Code::Refused, "premise: a send through a refusing socket did not exit 3:\n{}", r.text);
    let artifact_hex = r
        .text
        .lines()
        .find(|l| l.len() >= 200 && l.bytes().all(|b| b.is_ascii_hexdigit()))
        .unwrap_or_else(|| panic!("premise: send's page carries no artifact line:\n{}", r.text))
        .to_owned();
    let ks = reopen("sent", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let v = ks.view(&TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("no TAG"));
    assert!(v.pending.is_some() && v.wots_index.get() == 1, "premise: the refused send left no reservation at index 0");
    drop(ks);
    P10Sent { dir, artifact_hex }
}

/// The `signed_transaction` field of a submit body the chain recorded.
fn p10_signed_transaction_of(body_hex: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(body_hex.len() / 2);
    for i in (0..body_hex.len()).step_by(2) {
        bytes.push(u8::from_str_radix(body_hex.get(i..i + 2)?, 16).ok()?);
    }
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    v.get("signed_transaction")?.as_str().map(str::to_owned)
}

/// The shipped binary submits a reproduced artifact.
///
/// A `send` through a refusing socket leaves a reservation and a lost page.
/// In a fresh process `resign` runs with the same values against a chain that
/// now accepts. The check is on what reached the socket: one recorded
/// `/construction/submit` body must carry the reproduced artifact as its
/// `signed_transaction`. Two routes are accepted: (i) `resign` submits what
/// it reproduces, or (ii) a `submit` verb taking `<hex>` or `<tag> <hex>`.
///
/// # Controls
///
/// `resign` must exit 0 and its page must carry the artifact byte for byte;
/// exit 0 alone also requires the scripted socket to accept. The accepting
/// id comes from `SignedTransaction::id()` on a dry run.
#[test]
fn the_binary_submits_a_reproduced_artifact() {
    const TIP: u64 = 1_080_711;
    let sent = p10_send_that_never_left("lost-page", 0, TIP);
    let id = id_for_the_spend("lost-page-id");
    let shipped = |run: &P10Child| {
        run.submits
            .iter()
            .any(|body| p10_signed_transaction_of(body).as_deref() == Some(sent.artifact_hex.as_str()))
    };

    // Route (i): the recovery verb itself.
    let resigned = p10_child_session_run(sent.dir.path(), "resign:0", 5_000_000, 0, TIP, Some(id));
    assert_eq!(resigned.code, 0, "control: resign did not reproduce the artifact:\n{}", resigned.text);
    assert!(
        resigned.text.contains(&sent.artifact_hex),
        "control: resign's page does not carry the lost artifact byte for byte:\n{}",
        resigned.text
    );
    let route_i = shipped(&resigned);

    // Route (ii): a verb that takes the artifact.
    let tag = prefixed(&TAG);
    let mut route_ii: Option<String> = None;
    let mut refusals: Vec<String> = Vec::new();
    for argv in [vec!["submit", sent.artifact_hex.as_str()], vec!["submit", tag.as_str(), sent.artifact_hex.as_str()]] {
        let run = p10_child_session_run(sent.dir.path(), &format!("argv:{}", argv.join("\x1f")), 5_000_000, 0, TIP, Some(id));
        if shipped(&run) {
            route_ii = Some(format!("submit {}", if argv.len() == 2 { "<hex>" } else { "<tag> <hex>" }));
            break;
        }
        refusals.push(run.usage.unwrap_or_else(|| run.text.lines().next().unwrap_or("").to_owned()));
    }

    if route_i || route_ii.is_some() {
        println!(
            "  reproduced artifact submitted by the binary: route (i) resign ships it = {route_i}; route (ii) verb = {}",
            route_ii.as_deref().unwrap_or("none")
        );
        return;
    }
    panic!(
        "THE SHIPPED BINARY CANNOT SUBMIT A REPRODUCED ARTIFACT. `resign` reproduced the lost \
         artifact byte for byte in a fresh process against a chain that would have accepted it, and \
         the chain saw {} submit body(ies) -- none carrying it. Without that, finishing the recovery \
         needs a hand-built POST.\n\
         \n\
         The condition: \"the shipped binary can submit a reproduced artifact, so the \
         recovery `resign` exists for can be completed without a hand-built POST.\"\n\
         \n\
         What satisfies it: (i) `resign` ships what it reproduces, or (ii) a `submit` verb \
         taking the artifact as `submit <hex>` or `submit <tag> <hex>`, which the chain then sees on \
         the socket. The probes here got: {refusals:?}. A verb of another shape needs this probe \
         changed deliberately; it is not edited to fit.",
        resigned.submits.len()
    );
}

/// `send` and `resign` print the block-to-live they signed over, in decimal
/// with its meaning, and the notice says to record it.
///
/// `resign` needs the value. Since format version 4 it is also stored and
/// rendered by `status` and `balance` (see
/// `the_block_to_live_is_recovered_from_the_store_without_knowing_the_value`).
/// The `resign` chain scripts a tip below the value, because a stored
/// non-zero block-to-live is compared to the tip at open.
#[test]
fn send_and_resign_print_the_block_to_live_they_signed_over() {
    // Zero (the default, never expires), through an accepting socket.
    let id = id_for_the_spend("cli-btl-zero-id");
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.accepts_submit(id);
    let r = run_on("cli-btl-zero", chain, &Command::Send(spend()));
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    assert_says(&r, "  btl    0 (never expires", "send with the default block-to-live");
    assert_says(&r, "record it with the bytes", "send's notice");

    // Non-zero, through a refusing socket, then reproduced.
    let (dir, ks) = store("cli-btl-4242");
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.set_tip(4_000);
    chain.refuses_submit();
    let mut s = spend();
    s.blk_to_live = 4_242;
    let r = cli::run(ks, MeshClient::new(chain), &Command::Send(s.clone()));
    assert_eq!(r.code, Code::Refused, "{}", r.text);
    assert_says(&r, "  btl    4242 (the node accepts it only while the tip is at or below 4242", "send with --btl 4242");
    assert_says(&r, "refuses it on arrival if 4242 is below the tip", "send's page, the lower bound of the window");
    let ks = reopen("cli btl resign", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    // `resign` submits what it reproduces, so the chain accepts this spend's
    // id (the block-to-live is in the digest). The page is asserted before
    // the exit code so a socket failure is reported as such.
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.set_tip(4_000);
    chain.accepts_submit(id_for("cli-btl-4242-id", &s));
    let r = cli::run(ks, MeshClient::new(chain), &Command::Resign(s));
    assert_says(&r, "block-to-live 4242 (the node accepts it only while the tip is at or below 4242", "resign's page");
    assert_eq!(
        r.code,
        Code::Ok,
        "resign exits 0 only when the socket accepted the write; this chain was scripted to:\n{}",
        r.text
    );
    println!("  block-to-live rendered: send (0 and 4242) and resign (4242)");
}

/// The state `balance` and `status` render for a live reservation
/// (`cli::state_of`'s `SpendOutstanding` arm).
const P10_LIVE_LINE: &str = "SPEND OUTSTANDING at index 0 -- not yet seen on the chain";
/// The words a dead reservation's page must carry.
const P10_DEAD_PHRASE: &str = "can no longer be accepted";
/// The dead-reservation sentence: the specification's wording, and that no
/// command offers a second signature.
const P10_NO_ROUTE_OUT: &str = "A dead reservation has no route out: the whole balance at the reserved key is reachable only by a signature from that key, and the only signature this wallet will ever produce from that key is the one already produced. No command offers a second one, on purpose";

/// A dead reservation is reported as dead, from the store and the chain
/// alone.
///
/// A deposit that lands while a reservation is open credits the tag in
/// place, and `tx_val` requires `send + change + fee == balance` exactly, so
/// the signed bytes can never be accepted. A non-zero block-to-live that the
/// tip has reached has the same effect.
///
/// Four stores, each with a refused send, read back in fresh processes by
/// `status`, `balance` and `settle` (commands that take no spend
/// parameters):
///
/// | | reserved | chain afterwards | expected |
/// | --- | --- | --- | --- |
/// | A | btl 0 | balance 5,000,000 -> 6,000,000 | dead: the balance moved |
/// | B | btl 4,242 | tip 4,242 | dead: the block-to-live passed |
/// | C | btl 0 | unchanged, tip 100 | live (control) |
/// | D | btl 4,242 | unchanged, tip 4,241 | live (control) |
///
/// B is on the boundary: block N is the last that can carry btl N
/// (`cmp64(txe->tx_btl, bnum) < 0` refuses against the block's own number,
/// and `txclean` drops against `Cblocknum + 1`), so a reservation is dead
/// once the tip reaches its value. D keeps every non-zero block-to-live from
/// being called dead. These boundaries are this crate's reading of the
/// reference; there is no offline `EMCM_TXBTL` vector.
///
/// A dead page must drop the live state text, carry [`P10_DEAD_PHRASE`], and
/// show the figure only the store knows: the reserved balance in A, the
/// block-to-live in B. `settle` must not prescribe `resign` for dead bytes
/// and must not advance the store. `Pending` stores both figures since
/// format version 4.
///
/// Not driven: `reconcile` (a dead reservation is not a divergence), and
/// `resign` in scenario B, which reproduces and submits the expired bytes
/// because the block-to-live is not part of the plan inputs.
#[test]
fn a_dead_reservation_is_reported_as_dead_from_the_store_and_the_chain_alone() {
    struct Scenario {
        name: &'static str,
        btl: u64,
        tip_at_send: u64,
        balance_after: u64,
        tip_after: u64,
        dead: bool,
        figure: &'static str,
    }
    let scenarios = [
        Scenario { name: "A", btl: 0, tip_at_send: 100, balance_after: 6_000_000, tip_after: 100, dead: true, figure: "5000000" },
        Scenario { name: "B", btl: 4_242, tip_at_send: 4_000, balance_after: 5_000_000, tip_after: 4_242, dead: true, figure: "4242" },
        Scenario { name: "C", btl: 0, tip_at_send: 100, balance_after: 5_000_000, tip_after: 100, dead: false, figure: "" },
        Scenario { name: "D", btl: 4_242, tip_at_send: 4_000, balance_after: 5_000_000, tip_after: 4_241, dead: false, figure: "" },
    ];
    let mut failures: Vec<String> = Vec::new();
    let mut live_state_text: Option<String> = None;
    for sc in &scenarios {
        let sent = p10_send_that_never_left(&format!("dead-reservation-{}", sc.name), sc.btl, sc.tip_at_send);
        let run = |cmd: &str| p10_child_session_run(sent.dir.path(), cmd, sc.balance_after, 0, sc.tip_after, None);
        let status = run("status");
        let balance = run("balance");
        let settle = run("settle");
        // The state text as `status` renders it, recovered from the page.
        let state_text = status
            .text
            .lines()
            .find_map(|l| l.strip_prefix("  state    "))
            .map(str::to_owned)
            .unwrap_or_default();
        if !sc.dead {
            // Controls: a control that is not a live reservation means the
            // scenario setup is broken.
            for (what, page) in [("status", &status.text), ("balance", &balance.text)] {
                assert!(
                    page.contains(P10_LIVE_LINE),
                    "control {}: `{what}` does not render the live reservation {P10_LIVE_LINE:?}; the scenario is not the state this check is about:\n{page}",
                    sc.name
                );
            }
            assert!(settle.text.contains("NOT settled"), "control {}: settle did not say NOT settled:\n{}", sc.name, settle.text);
            assert!(settle.index == 1 && settle.pending, "control {}: settle moved the store", sc.name);
            assert_eq!(state_text, P10_LIVE_LINE, "control {}: the typed needle and the rendered state disagree", sc.name);
            live_state_text = Some(state_text);
            continue;
        }
        let live = live_state_text.clone().unwrap_or_else(|| P10_LIVE_LINE.to_owned());
        for (what, page) in [("status", &status.text), ("balance", &balance.text), ("settle", &settle.text)] {
            if page.contains(&live) {
                failures.push(format!("{} `{what}`: still renders the live state {live:?}", sc.name));
            }
            if !page.contains(P10_DEAD_PHRASE) {
                failures.push(format!("{} `{what}`: does not say {P10_DEAD_PHRASE:?}", sc.name));
            }
            // No route out is offered, and the page says so in the
            // specification's words.
            if !page.contains(P10_NO_ROUTE_OUT) {
                failures.push(format!("{} `{what}`: does not say {P10_NO_ROUTE_OUT:?}", sc.name));
            }
        }
        for (what, page) in [("status", &status.text), ("balance", &balance.text)] {
            if !page.split(|c: char| !c.is_ascii_digit()).any(|t| t == sc.figure) {
                failures.push(format!("{} `{what}`: does not carry the reserved figure {} the store had to hold", sc.name, sc.figure));
            }
        }
        if settle.text.contains("`resign` rebuilds it") {
            failures.push(format!("{} `settle`: prescribes `resign` for bytes that can never be accepted", sc.name));
        }
        if !(settle.index == 1 && settle.pending) {
            failures.push(format!("{} `settle`: advanced the store past a reservation the chain never confirmed", sc.name));
        }
    }
    assert!(live_state_text.is_some(), "no control ran");
    if failures.is_empty() {
        println!("  dead reservations diagnosed: 2 dead scenario(s) told, 2 live controls untouched");
        return;
    }
    panic!(
        "A DEAD RESERVATION IS REPORTED AS A LIVE ONE. In {} scenario/page pair(s) the binary told an \
         operator whose signed artifact can never be accepted again that the spend was `not yet seen \
         on the chain`, and `settle` went on prescribing `resign` for bytes the ledger will refuse:\n\
         \x20 - {}\n\
         \n\
         The condition: \"an operator whose reserved artifact can no longer be accepted \
         -- the balance moved, or the block-to-live passed -- is told so by the binary, from the store \
         and the chain alone, without retyping the original arguments.\"\n\
         \n\
         What that needs: `Pending` carrying the reserved balance and the block-to-live beside the \
         index and the digest (format.rs::Pending carries them since format version 4), so that \
         reconciliation can compare them to the ledger entry and the tip; a state that renders \
         {P10_DEAD_PHRASE:?} with the reserved figure (that wording is this \
         check's interface); and a `settle` that stops naming `resign`. Format version 4's figures \
         provide this; storing the signed bytes instead was rejected for their width. \
         There is no route out of the dead state, on purpose, and the page says so beside the price.",
        failures.len(),
        failures.join("\n  - ")
    );
}

/// The block-to-live is recovered from the store without knowing the value.
///
/// `blk_to_live` is the last field of `TXHDR` and is inside the digest, so
/// `resign` needs it. Since format version 4, `status` and `balance` render
/// it from the record on its own line.
///
/// Two stores with different values, each with a refused send and a lost
/// page. In fresh processes the operator runs `status`, `balance` and
/// `resign` without the block-to-live. Every decimal token on those pages is
/// then tried as `--btl` to `resign`, and one must reproduce the lost
/// artifact byte for byte, for both stores, so a constant cannot pass.
///
/// # Controls
///
/// The reserved value is in the artifact's little-endian bytes at byte
/// `[108..116)` (hex `[216..232)`); `resign` with the value reproduces the
/// artifact; and a `status` page before the send carries neither value. The
/// chain scripts a tip below each value and accepts the submission `resign`
/// makes.
#[test]
fn the_block_to_live_is_recovered_from_the_store_without_knowing_the_value() {
    let mut verdicts: Vec<(u64, bool, usize)> = Vec::new();
    for (name, b) in [("btl-recovery-a", 1_080_961u64), ("btl-recovery-b", 2_161_922u64)] {
        let tip = b - 250;
        // The coincidence guard, on a store with nothing reserved.
        let (fresh, ks) = store(&format!("{name}-fresh"));
        drop(ks);
        let before = p10_child_session_run(fresh.path(), "status", 5_000_000, 0, tip, None);
        assert!(
            !before.text.split(|c: char| !c.is_ascii_digit()).any(|t| t == b.to_string()),
            "premise: the value {b} appears on a page with nothing reserved:\n{}",
            before.text
        );

        let sent = p10_send_that_never_left(name, b, tip);
        // `TXHDR` is options[4] | src_addr[40] | chg_addr[40] | send_total[8]
        // | change_total[8] | fee_total[8] | blk_to_live[8] (types.h), so the
        // block-to-live is byte [108..116) of the artifact, hex [216..232).
        let le: String = b.to_le_bytes().iter().map(|x| format!("{x:02x}")).collect();
        assert_eq!(
            &sent.artifact_hex[216..232],
            le,
            "the premise no longer holds: the block-to-live is not at hex [216..232) of the artifact"
        );
        // `resign` submits what it reproduces, so every child run gets the
        // accepting id for this store's spend (the block-to-live is in the
        // digest). A right value reproduces and submits, exit 0; a wrong one
        // is `DigestMismatch` before any write. `status` and `balance` never
        // submit.
        let mut with_b = spend();
        with_b.blk_to_live = b;
        let id = id_for(&format!("{name}-id"), &with_b);
        let run = |cmd: &str| p10_child_session_run(sent.dir.path(), cmd, 5_000_000, 0, tip, Some(id));
        let known = run(&format!("resign:{b}"));
        // The artifact first, so reproduction and socket failures are
        // reported separately.
        assert!(
            known.text.contains(&sent.artifact_hex),
            "control: resign WITH the value did not reproduce the artifact:\n{}",
            known.text
        );
        assert_eq!(
            known.code,
            0,
            "control: resign WITH the value reproduced it but the write was not accepted:\n{}",
            known.text
        );

        // The operator who lost the page: three commands that need no value.
        let pages = [run("status"), run("balance"), run("resign:0")];
        let mut tokens: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
        for p in &pages {
            for t in p.text.split(|c: char| !c.is_ascii_digit()) {
                if let Ok(n) = t.parse::<u64>() {
                    tokens.insert(n);
                }
            }
        }
        assert!(tokens.len() <= 64, "the harvest is too wide to try ({} tokens); the pages changed shape", tokens.len());
        let recovered = tokens
            .iter()
            .any(|t| {
                let attempt = run(&format!("resign:{t}"));
                attempt.code == 0 && attempt.text.contains(&sent.artifact_hex)
            });
        verdicts.push((b, recovered, tokens.len()));
    }
    if verdicts.iter().all(|(_, ok, _)| *ok) {
        println!("  block-to-live recovered without the value: {} store(s), from the pages alone", verdicts.len());
        return;
    }
    panic!(
        "THE BLOCK-TO-LIVE CANNOT BE RECOVERED FROM THE STORE. An operator holding the store, the \
         password and the phrase, and not the value, ran `status`, `balance` and `resign` without \
         it and tried every number those pages showed as `--btl`; the lost artifact was reproduced \
         in {} of {} store(s) ({}).\n\
         \n\
         The condition: \"an operator holding the store, the password and the phrase \
         can recover a reservation made with a non-zero block-to-live without knowing the value.\"\n\
         \n\
         Either route clears it: the store carries the reserved block-to-live and `status`/`balance` \
         render it beside the SPEND OUTSTANDING line (with its expiry against the tip, which no marker \
         asserts), or `resign`'s refusal names the value it derived and compared (the acknowledged path's shape; \
         naming only the FIELD leaves the value unknown). Both need `Pending` to carry \
         more than the index and the digest; abandonment is not a route, and printing the \
         value on `send`'s page does not reach an operator who lost the page. Format version \
         4's figures are what discharged this; 5c's signed bytes were rejected \
         on width.",
        verdicts.iter().filter(|(_, ok, _)| *ok).count(),
        verdicts.len(),
        verdicts
            .iter()
            .map(|(b, ok, n)| format!("btl {b}: {} after {n} token(s)", if *ok { "recovered" } else { "NOT recovered" }))
            .collect::<Vec<_>>()
            .join("; ")
    );
}

/// `status` and `balance` render the reserved figures on their own lines
/// under the unchanged state line: the reserved balance and the
/// block-to-live with the tip it was compared to, in the same words on both
/// pages. A page with nothing reserved carries none of them.
#[test]
fn status_and_balance_render_the_reserved_figures_on_their_own_lines_beside_the_pinned_state_line() {
    let sent = p10_send_that_never_left("p13-figures", 4_242, 4_000);
    let status = p10_child_session_run(sent.dir.path(), "status", 5_000_000, 0, 4_000, None);
    let state = status
        .text
        .lines()
        .find_map(|l| l.strip_prefix("  state    "))
        .unwrap_or_default();
    assert_eq!(state, P10_LIVE_LINE, "the state line is not byte for byte the live line:\n{}", status.text);
    for needle in [
        "\n  reserved balance  5000000 nanoMCM when the spend was built",
        "\n  block-to-live     4242 (the node accepts it only while the tip is at or below 4242, and refuses it if 4242 is below the tip when it arrives; the tip is 4000",
    ] {
        assert!(status.text.contains(needle), "`status` does not carry {needle:?} on its own line:\n{}", status.text);
    }
    let balance = p10_child_session_run(sent.dir.path(), "balance", 5_000_000, 0, 4_000, None);
    assert!(balance.text.contains(P10_LIVE_LINE), "`balance` lost the live line:\n{}", balance.text);
    for needle in [
        "\n    reserved balance  5000000 nanoMCM when the spend was built",
        "\n    block-to-live     4242 (the node accepts it only while the tip is at or below 4242, and refuses it if 4242 is below the tip when it arrives; the tip is 4000",
    ] {
        assert!(balance.text.contains(needle), "`balance` does not carry {needle:?} under the account's row:\n{}", balance.text);
    }
    // Nothing reserved, nothing rendered.
    let (fresh, ks) = store("p13-figures-fresh");
    drop(ks);
    let before = p10_child_session_run(fresh.path(), "status", 5_000_000, 0, 4_000, None);
    assert!(!before.text.contains("reserved balance"), "a page with nothing reserved renders a reserved balance:\n{}", before.text);
    assert!(!before.text.contains("block-to-live"), "a page with nothing reserved renders a block-to-live:\n{}", before.text);
    println!("  reserved figures: rendered on their own lines by status and balance, the state line pinned");
}

/// A migrated store says its figures were not recorded, and its first write
/// re-seals it as version 4.
///
/// From a captured version-3 reservation: `status` and `balance` say the
/// figures were not recorded under format version 3, print no upgrade line,
/// and leave the file unchanged. The `settle` that lands it is the first
/// write; its page says the store is now format version 4 and older builds
/// cannot open it, and the version word is 4. A following `status` has no
/// upgrade line. Each command runs in a fresh process.
#[test]
fn a_migrated_store_says_its_figures_were_not_recorded_and_is_resealed_by_its_first_write() {
    const IMAGE: &[u8] = include_bytes!("../testdata/keystore_v3_reserved_snapshot.bin");
    const UPGRADE: &str = "written in format version 4";
    let dir = ScratchDir::new("p13-migrated");
    drop(keystore_harness::create(dir.path()).unwrap_or_else(|e| panic!("{e}")));
    dir.write_snapshot(IMAGE);

    let status = p10_child_session_run(dir.path(), "status", 5_000_000, 0, 100, None);
    assert_eq!(status.code, 0, "{}", status.text);
    let state = status.text.lines().find_map(|l| l.strip_prefix("  state    ")).unwrap_or_default();
    assert_eq!(state, P10_LIVE_LINE, "a migrated reservation is neither live nor dead and keeps the live line:\n{}", status.text);
    assert!(status.text.contains("not recorded") && status.text.contains("format version 3"), "`status` does not say the figures were not recorded under version 3:\n{}", status.text);
    assert!(!status.text.contains(UPGRADE), "`status` printed the upgrade line without writing:\n{}", status.text);
    assert_eq!(dir.snapshot_bytes(), IMAGE, "`status` rewrote a version-3 store");

    let balance = p10_child_session_run(dir.path(), "balance", 5_000_000, 0, 100, None);
    assert_eq!(balance.code, 0, "{}", balance.text);
    assert!(balance.text.contains("not recorded"), "`balance` does not say the figures were not recorded:\n{}", balance.text);
    assert!(!balance.text.contains(UPGRADE), "`balance` printed the upgrade line without writing:\n{}", balance.text);
    assert_eq!(dir.snapshot_bytes(), IMAGE, "`balance` rewrote a version-3 store");

    // The first write: the chain at the change key, and settle lands it.
    let settle = p10_child_session_run(dir.path(), "settle", 4_000_000, 1, 100, None);
    assert_eq!(settle.code, 0, "{}", settle.text);
    assert!(settle.text.contains("settled"), "{}", settle.text);
    assert!(settle.text.contains(UPGRADE) && settle.text.contains("older build"), "the command that made the first write did not announce the crossing:\n{}", settle.text);
    assert!(settle.index == 1 && !settle.pending, "settle left the store in the wrong state");
    let after = dir.snapshot_bytes();
    assert_eq!(u16::from_le_bytes([after[8], after[9]]), 4, "the first write did not re-seal the store as version 4");
    assert_eq!(after.len(), 51 + 45 + 195 + 16, "one version-4 record");

    let again = p10_child_session_run(dir.path(), "status", 4_000_000, 1, 100, None);
    assert_eq!(again.code, 0, "{}", again.text);
    assert!(again.text.contains("in sync"), "{}", again.text);
    assert!(!again.text.contains(UPGRADE), "a store opened at version 4 printed the upgrade line:\n{}", again.text);
    println!("  migrated store: status and balance say not recorded and write nothing; settle makes the first write, announces version 4; the next status is quiet");
}

// ---------------------------------------------------------------------------
// The five read-only verbs
// ---------------------------------------------------------------------------

/// A transport scripted for the explorer endpoints alone.
///
/// Replies follow the shapes group N recorded, reduced to the fields the
/// pages print; the captured bodies are replayed in `tests/mesh.rs`. A search
/// by account and a block by hash have no group N vector and follow the Go
/// source at the commit the corpus names.
struct Explorer {
    tip: u64,
    /// Every path posted to, in order.
    paths: RefCell<Vec<String>>,
    /// Every body posted, in order.
    bodies: RefCell<Vec<Vec<u8>>>,
    /// When set, how `/search/transactions` refuses: not served (404, no
    /// indexer), or the middleware's error object with a code.
    search_refused: Option<SearchRefused>,
    /// When set, `/search/transactions` answers an empty page.
    empty: bool,
    /// The ids `/mempool` lists, in order; when empty it answers `null`, as
    /// the middleware encodes a nil list.
    queue: Vec<[u8; 32]>,
    /// Ids `/mempool/transaction` answers code 3 for: the queue no longer
    /// holds them.
    gone: Vec<[u8; 32]>,
    /// Ids `/mempool/transaction` answers code 2 for, and, when it holds the
    /// all-zero id, what `/mempool` itself answers.
    broken: Vec<[u8; 32]>,
}

impl Explorer {
    fn new(tip: u64) -> Explorer {
        Explorer {
            tip,
            paths: RefCell::new(Vec::new()),
            bodies: RefCell::new(Vec::new()),
            search_refused: None,
            empty: false,
            queue: Vec::new(),
            gone: Vec::new(),
            broken: Vec::new(),
        }
    }
    fn with_queue(mut self, queue: &[[u8; 32]], gone: &[[u8; 32]], broken: &[[u8; 32]]) -> Explorer {
        self.queue = queue.to_vec();
        self.gone = gone.to_vec();
        self.broken = broken.to_vec();
        self
    }
    /// One waiting transaction as `/mempool/transaction` renders it: the
    /// `/block` shape with status `PENDING` and the reference padded to
    /// sixteen bytes.
    fn pending_body(id: &[u8; 32]) -> String {
        format!(
            r#"{{"transaction":{{"transaction_identifier":{{"hash":"0x{t}"}},"operations":[{{"operation_identifier":{{"index":0}},"type":"DESTINATION_TRANSFER","status":"PENDING","account":{{"address":"0xdbc01bb8a41f3dc24b0083bb6b9efe910e2477cb"}},"amount":{{"value":"10000000","currency":{{"symbol":"MCM","decimals":9}}}},"metadata":{{"memo":"INVOICE-7"}}}},{{"operation_identifier":{{"index":1}},"type":"SOURCE_TRANSFER","status":"PENDING","account":{{"address":"0x371c388eba10f265c648008e1ad2c94e680c0f4a"}},"amount":{{"value":"-10000500","currency":{{"symbol":"MCM","decimals":9}}}}}},{{"operation_identifier":{{"index":2}},"type":"FEE","status":"PENDING","account":{{"address":"0x0000000000000000000000000000000000000000"}},"amount":{{"value":"500","currency":{{"symbol":"MCM","decimals":9}}}}}}],"metadata":{{"block_to_live":"0"}}}}}}"#,
            t = hexs(id),
        )
    }
    fn without_indexer(mut self) -> Explorer {
        self.search_refused = Some(SearchRefused::NotServed);
        self
    }
    fn refusing_search(mut self, code: u64) -> Explorer {
        self.search_refused = Some(SearchRefused::Code(code));
        self
    }
    fn with_no_rows(mut self) -> Explorer {
        self.empty = true;
        self
    }
    /// One transaction as `/search/transactions` renders it: the source
    /// debited gross, the change as its own destination, metadata as JSON
    /// numbers.
    fn search_row(index: u64, tag_hex: &str) -> String {
        format!(
            r#"{{"block_identifier":{{"index":{index},"hash":"0x{h}"}},"transaction_identifier":{{"hash":"0x{t}"}},"timestamp":1788500208000,"operations":[{{"operation_identifier":{{"index":0}},"type":"SOURCE_TRANSFER","status":"SUCCESS","account":{{"address":"0x{tag_hex}"}},"amount":{{"value":"-50000000","currency":{{"symbol":"MCM","decimals":9}}}}}},{{"operation_identifier":{{"index":1}},"type":"DESTINATION_TRANSFER","status":"SUCCESS","account":{{"address":"0xdbc01bb8a41f3dc24b0083bb6b9efe910e2477cb"}},"amount":{{"value":"10000000","currency":{{"symbol":"MCM","decimals":9}}}},"metadata":{{"memo":"INVOICE-7"}}}},{{"operation_identifier":{{"index":2}},"type":"DESTINATION_TRANSFER","status":"SUCCESS","account":{{"address":"0x{tag_hex}"}},"amount":{{"value":"39999500","currency":{{"symbol":"MCM","decimals":9}}}}}},{{"operation_identifier":{{"index":3}},"type":"FEE","status":"SUCCESS","account":{{"address":"0x7b33270a98d2e6b188aedcdf10b7867b16cd9b0b"}},"amount":{{"value":"500","currency":{{"symbol":"MCM","decimals":9}}}}}}],"metadata":{{"block_to_live":0,"change_total":39999500,"fee_total":500,"send_total":10000000}}}}"#,
            h = "36".repeat(32),
            t = "18".repeat(32),
        )
    }
    /// One block as `/block` renders it: a reward transaction, then one spend
    /// whose source is debited net with no change operation, metadata as
    /// decimal strings.
    fn block_body(index: u64) -> String {
        format!(
            r#"{{"block":{{"block_identifier":{{"index":{index},"hash":"0x{h}"}},"parent_block_identifier":{{"index":{p},"hash":"0x{ph}"}},"timestamp":1788500198000,"transactions":[{{"transaction_identifier":{{"hash":"0x{r}"}},"operations":[{{"operation_identifier":{{"index":0}},"type":"REWARD","status":"SUCCESS","account":{{"address":"0x9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c"}},"amount":{{"value":"12065840589","currency":{{"symbol":"MCM","decimals":9}}}}}}]}},{{"transaction_identifier":{{"hash":"0x{t}"}},"operations":[{{"operation_identifier":{{"index":0}},"type":"DESTINATION_TRANSFER","status":"SUCCESS","account":{{"address":"0xdbc01bb8a41f3dc24b0083bb6b9efe910e2477cb"}},"amount":{{"value":"10000000","currency":{{"symbol":"MCM","decimals":9}}}},"metadata":{{"memo":""}}}},{{"operation_identifier":{{"index":1}},"type":"SOURCE_TRANSFER","status":"SUCCESS","account":{{"address":"0x371c388eba10f265c648008e1ad2c94e680c0f4a"}},"amount":{{"value":"-10000500","currency":{{"symbol":"MCM","decimals":9}}}},"metadata":{{"change_amount":"39999500","source_amount":"50000000"}}}},{{"operation_identifier":{{"index":2}},"type":"FEE","status":"SUCCESS","account":{{"address":"0x7b33270a98d2e6b188aedcdf10b7867b16cd9b0b"}},"amount":{{"value":"500","currency":{{"symbol":"MCM","decimals":9}}}}}}],"metadata":{{"block_to_live":"0"}}}}]}}}}"#,
            h = "36".repeat(32),
            p = index - 1,
            ph = "72".repeat(32),
            r = "ab".repeat(32),
            t = "18".repeat(32),
        )
    }
}

/// How [`Explorer`] refuses `/search/transactions`.
#[derive(Clone, Copy)]
enum SearchRefused {
    /// Not served: the deployment runs no indexer.
    NotServed,
    /// Served, answering the middleware's error object with this code.
    Code(u64),
}

impl mochimo_crypto::mesh::Transport for Explorer {
    fn post(&self, path: &str, body: &[u8]) -> mochimo_crypto::Result<Vec<u8>> {
        self.paths.borrow_mut().push(path.to_owned());
        self.bodies.borrow_mut().push(body.to_vec());
        match path {
            "/network/status" => Ok(format!(
                r#"{{"current_block_identifier":{{"index":{},"hash":"0x{}"}}}}"#,
                self.tip,
                "ab".repeat(32)
            )
            .into_bytes()),
            "/block" => {
                let v: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
                let index = v["block_identifier"]["index"].as_u64().unwrap_or(self.tip);
                Ok(Explorer::block_body(index).into_bytes())
            }
            "/search/transactions" => {
                match self.search_refused {
                    // The route exists only with the indexer enabled: the
                    // router's 404, reported as a non-200 status.
                    Some(SearchRefused::NotServed) => {
                        return Err(mochimo_crypto::Error::HttpStatus { status: 404 });
                    }
                    // `giveError`: HTTP 200 with an object from the table in
                    // `handlers.go`.
                    Some(SearchRefused::Code(code)) => {
                        let (message, retriable) = match code {
                            1 => ("Invalid request", false),
                            _ => ("Internal general error", true),
                        };
                        return Ok(format!(r#"{{"code":{code},"message":"{message}","retriable":{retriable}}}"#).into_bytes());
                    }
                    None => {}
                }
                if self.empty {
                    return Ok(br#"{"transactions":[],"total_count":0}"#.to_vec());
                }
                let v: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
                let tag_hex = v["account_identifier"]["address"]
                    .as_str()
                    .map(|s| s.trim_start_matches("0x").to_owned())
                    .unwrap_or_else(|| "37".repeat(20));
                Ok(format!(
                    r#"{{"transactions":[{}],"total_count":1}}"#,
                    Explorer::search_row(1_078_535, &tag_hex)
                )
                .into_bytes())
            }
            "/mempool" => {
                if self.broken.contains(&[0; 32]) {
                    return Ok(br#"{"code":2,"message":"Internal general error","retriable":true}"#.to_vec());
                }
                if self.queue.is_empty() {
                    return Ok(br#"{"transaction_identifiers":null}"#.to_vec());
                }
                let ids: Vec<String> = self.queue.iter().map(|id| format!(r#"{{"hash":"0x{}"}}"#, hexs(id))).collect();
                Ok(format!(r#"{{"transaction_identifiers":[{}]}}"#, ids.join(",")).into_bytes())
            }
            "/mempool/transaction" => {
                let v: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
                let asked = v["transaction_identifier"]["hash"].as_str().unwrap_or("").to_owned();
                let id = self
                    .queue
                    .iter()
                    .find(|id| format!("0x{}", hexs(*id)) == asked)
                    .unwrap_or_else(|| panic!("asked for {asked}, which /mempool did not list"));
                if self.gone.contains(id) {
                    return Ok(br#"{"code":3,"message":"Transaction not found","retriable":true}"#.to_vec());
                }
                if self.broken.contains(id) {
                    return Ok(br#"{"code":2,"message":"Internal general error","retriable":true}"#.to_vec());
                }
                Ok(Explorer::pending_body(id).into_bytes())
            }
            other => panic!("the explorer double was asked for {other}"),
        }
    }
}


/// An explorer reply carried through the transport, codec and CLI renderer.
fn render_explorer_reply(path: &'static str, body: &serde_json::Value, cmd: &Command) -> cli::Report {
    struct Reply {
        path: &'static str,
        body: Vec<u8>,
    }
    impl mochimo_crypto::mesh::Transport for Reply {
        fn post(&self, path: &str, _body: &[u8]) -> mochimo_crypto::Result<Vec<u8>> {
            assert_eq!(path, self.path);
            Ok(self.body.clone())
        }
    }
    let body = serde_json::to_vec(body).unwrap_or_else(|e| panic!("{e}"));
    cli::run_explorer(&MeshClient::new(Reply { path, body }), cmd)
}

/// Control characters are checked in memory; no reply is sent to a terminal.
#[test]
fn transaction_escapes_every_external_text_field() {
    use serde_json::{json, Value};
    let row = Explorer::search_row(1_078_535, &hexs(&TAG));
    let mut row: Value = serde_json::from_str(&row).unwrap_or_else(|e| panic!("{e}"));
    let mut controls = String::new();
    for code in (0..=0x1f).chain(0x7f..=0x9f).chain([
        0x061c, 0x200e, 0x200f, 0x2028, 0x2029, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
        0x2066, 0x2067, 0x2068, 0x2069,
        // Zero-width: soft hyphen, Mongolian vowel separator, ZWSP, ZWNJ, ZWJ,
        // word joiner and the invisible operators, and the byte-order mark.
        0x00ad, 0x180e, 0x200b, 0x200c, 0x200d, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xfeff,
    ]) {
        controls.push(char::from_u32(code).unwrap_or_else(|| panic!("invalid test character")));
    }
    row["operations"][0]["type"] = json!("TYPE\u{1b}");
    row["operations"][0]["account"]["address"] = json!("fallback\raddress");
    row["operations"][0]["metadata"] = json!({"memo": format!("café 東京{controls}")});
    // Both fixed-width branches must also treat malformed addresses as text.
    row["operations"][1]["account"]["address"] = json!(format!("{}\u{9b}", "a".repeat(38)));
    row["operations"][2]["account"]["address"] = json!(format!("{}\u{9b}", "b".repeat(78)));
    // A literal backslash is escaped too, so text a node sends cannot pass
    // for an escape this renderer wrote.
    row["metadata"] = json!({"key\u{202e}": "value\u{2066}end\u{2069}\u{7}", "lookalike": r"C:\u{1b}"});
    let body = json!({"transactions": [row], "total_count": 1});
    let cmd = Command::LookupTransaction { hash: [0x18; 32] };
    let report = render_explorer_reply("/search/transactions", &body, &cmd);
    assert_eq!(report.code, Code::Ok);
    for ch in controls.chars().filter(|c| *c != '\n') {
        assert!(!report.text.contains(ch), "raw control {ch:?} in output");
    }
    for visible in [
        r"TYPE\u{1b}",
        r"fallback\raddress",
        r"memo café 東京\u{0}",
        r"\t\n\u{b}",
        r"key\u{202e} = value\u{2066}end\u{2069}\u{7}",
        r"lookalike = C:\\u{1b}",
        r"\u{ad}\u{180e}\u{200b}\u{200c}\u{200d}\u{2060}\u{2061}\u{2062}\u{2063}\u{2064}\u{feff}",
    ] {
        assert!(report.text.contains(visible), "missing escaped field {visible:?}");
    }
    assert!(report.text.contains(&format!("{}\\u{{9b}}", "a".repeat(38))));
    assert!(report.text.contains(&format!("{}\\u{{9b}}", "b".repeat(78))));
    let mut clean = body.clone();
    clean["transactions"][0]["operations"][0]["metadata"]["memo"] = json!("café 東京");
    let clean_report = render_explorer_reply("/search/transactions", &clean, &cmd);
    assert_eq!(report.text.lines().count(), clean_report.text.lines().count(), "the memo added a display line");
}

#[test]
fn recent_transactions_escapes_memos_and_preserves_unicode() {
    use serde_json::{json, Value};
    let row = Explorer::search_row(1_078_535, &hexs(&TAG));
    let mut row: Value = serde_json::from_str(&row).unwrap_or_else(|e| panic!("{e}"));
    row["operations"][1]["metadata"]["memo"] = json!("café 東京\nnext\t\u{1b}\u{9b}\u{202e}");
    let body = json!({"transactions": [row], "total_count": 1});
    let report = render_explorer_reply(
        "/search/transactions", &body, &Command::RecentTransactions { tag: TAG, count: 5, from: 0 },
    );
    assert_eq!(report.code, Code::Ok);
    assert!(report.text.contains("                    memo café 東京\\nnext\\t\\u{1b}\\u{9b}\\u{202e}\n"));
    assert!(!report.text.chars().any(|c| c.is_control() && c != '\n'));
    assert!(!report.text.contains('\u{202e}'));
}

#[test]
fn block_escapes_the_reward_address() {
    use serde_json::{json, Value};
    let mut body: Value = serde_json::from_str(&Explorer::block_body(1_078_535))
        .unwrap_or_else(|e| panic!("{e}"));
    body["block"]["transactions"][0]["operations"][0]["account"]["address"] = json!("reward\naddress\u{1b}\u{2067}");
    let report = render_explorer_reply(
        "/block", &body, &Command::Block { at: args::BlockAt::Index(1_078_535) },
    );
    assert_eq!(report.code, Code::Ok);
    assert!(report.text.contains("    to     reward\\naddress\\u{1b}\\u{2067}\n"));
    assert!(!report.text.chars().any(|c| c.is_control() && c != '\n'));
    assert!(!report.text.contains('\u{2067}'));
}

/// `transaction <hash>`: the indexer's rendering of one transaction, with
/// the page naming the endpoint it read.
#[test]
fn transaction_prints_the_indexers_rendering_and_names_the_endpoint() {
    let hash = [0x18u8; 32];
    let e = Explorer::new(1_078_600);
    let r = cli::run_explorer(&MeshClient::new(e), &Command::LookupTransaction { hash });
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    assert!(r.text.contains("transaction 1818"), "{}", r.text);
    assert!(r.text.contains("in block 1078535"), "{}", r.text);
    assert!(r.text.contains("4 operation(s)"), "{}", r.text);
    assert!(r.text.contains("SOURCE_TRANSFER"), "{}", r.text);
    assert!(r.text.contains("-50000000 nanoMCM (-0.050000000 MCM)"), "the gross debit is not rendered:\n{}", r.text);
    assert!(r.text.contains("memo INVOICE-7"), "{}", r.text);
    assert!(r.text.contains("block_to_live = 0"), "{}", r.text);
    assert!(r.text.contains("send_total = 10000000"), "{}", r.text);
    assert!(r.text.contains("/search/transactions"), "the page does not name the endpoint:\n{}", r.text);
    assert!(r.text.contains("GROSS"), "the page does not state the convention:\n{}", r.text);
    println!("  transaction: 4 operations, the gross debit, the memo, the metadata, the endpoint named");
}

/// `recent-transactions <tag>`: one row per transaction, newest first, with
/// the direction relative to the tag.
#[test]
fn recent_transactions_prints_a_row_per_transaction_with_its_direction() {
    let e = Explorer::new(1_078_600);
    let r = cli::run_explorer(&MeshClient::new(e), &Command::RecentTransactions { tag: TAG, count: 5, from: 0 });
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    assert!(r.text.contains("1 of 1 row(s), newest first"), "{}", r.text);
    assert!(r.text.contains("block   1078535"), "{}", r.text);
    // The scripted row debits the tag 50,000,000 and returns 39,999,500 to
    // it, so the tag is on both sides and the net it felt is -10,000,500.
    assert!(r.text.contains("both"), "the direction is not both:\n{}", r.text);
    assert!(r.text.contains("-10000500 nanoMCM"), "the amount that touched the tag is wrong:\n{}", r.text);
    println!("  recent-transactions: one row, direction `both`, the tag's own net -10,000,500");
}

/// `recent-transactions --from M`: the first page is requested with no
/// offset in the body; a later one carries the offset the Mesh handler
/// reads, and the page says which rows it shows and how to continue.
#[test]
fn recent_transactions_from_sends_the_offset_and_says_which_rows_it_shows() {
    let tag_hex = hexs(&TAG);
    let network = r#""network_identifier":{"blockchain":"mochimo","network":"mainnet"}"#;
    let client = MeshClient::new(Explorer::new(1_078_600));
    let r = cli::run_explorer(&client, &Command::RecentTransactions { tag: TAG, count: 5, from: 0 });
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    let r = cli::run_explorer(&client, &Command::RecentTransactions { tag: TAG, count: 100, from: 200 });
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    let bodies: Vec<String> = client
        .transport()
        .bodies
        .borrow()
        .iter()
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .collect();
    assert_eq!(
        bodies,
        [
            format!(r#"{{"account_identifier":{{"address":"0x{tag_hex}"}},"limit":5,{network}}}"#),
            format!(r#"{{"account_identifier":{{"address":"0x{tag_hex}"}},"limit":100,{network},"offset":200}}"#),
        ],
        "the first page's body changed, or a later one does not carry its offset"
    );
    // The builder includes the offset, 0 included; the verb omits it for the
    // first page.
    assert_eq!(
        mochimo_crypto::mesh::codec::request_search_by_account_from(&TAG, 5, 0),
        format!(r#"{{"account_identifier":{{"address":"0x{tag_hex}"}},"limit":5,{network},"offset":0}}"#).into_bytes(),
        "the builder does not send an offset of 0"
    );

    // A middle page: which rows, the total, and the flag to continue.
    use serde_json::{json, Value};
    let row: Value = serde_json::from_str(&Explorer::search_row(1_078_535, &tag_hex)).unwrap_or_else(|e| panic!("{e}"));
    let cmd = Command::RecentTransactions { tag: TAG, count: 1, from: 100 };
    let body = json!({"transactions": [row], "total_count": 250, "next_offset": 101});
    let page = render_explorer_reply("/search/transactions", &body, &cmd);
    assert_eq!(page.code, Code::Ok, "{}", page.text);
    assert!(page.text.contains("  rows 101 to 101 of 250, newest first: the 100 newest are skipped\n"), "{}", page.text);
    assert!(page.text.contains("the endpoint's next offset is 101, and `--from 101` reads them"), "{}", page.text);
    assert!(!page.text.contains("(none"), "{}", page.text);

    // Past the last row: an empty page, not a refusal.
    let cmd = Command::RecentTransactions { tag: TAG, count: 5, from: 300 };
    let page = render_explorer_reply("/search/transactions", &json!({"transactions": [], "total_count": 250}), &cmd);
    assert_eq!(page.code, Code::Ok, "{}", page.text);
    assert!(page.text.contains("  0 of 250 row(s) after the 300 newest\n"), "{}", page.text);
    assert!(page.text.contains("(none after the 300 newest: this node's index holds 250 for this tag.)"), "{}", page.text);
    assert!(!page.text.contains("never paid"), "an offset past the end is not a tag with no history:\n{}", page.text);
    println!("  recent-transactions --from: page 1's body unchanged, the offset sent after it, rows 101 to 101 of 250 named, --from 101 offered");
}

/// A tag the index has never seen prints an empty table and exits 0. No
/// indexer (search not served) and an unresponsive indexer (code 2) are
/// refusals that say which, for both `transaction` and
/// `recent-transactions`; code 1 (an undecodable request) names neither.
#[test]
fn recent_transactions_is_empty_on_no_history_and_refuses_with_no_indexer() {
    let r = cli::run_explorer(
        &MeshClient::new(Explorer::new(10).with_no_rows()),
        &Command::RecentTransactions { tag: TAG, count: 5, from: 0 },
    );
    assert_eq!(r.code, Code::Ok, "an empty history is not a refusal:\n{}", r.text);
    assert!(r.text.contains("0 of 0 row(s)"), "{}", r.text);
    assert!(r.text.contains("(none:"), "{}", r.text);

    let r = cli::run_explorer(
        &MeshClient::new(Explorer::new(10).without_indexer()),
        &Command::RecentTransactions { tag: TAG, count: 5, from: 0 },
    );
    assert_eq!(r.code, Code::Refused, "a missing indexer is not an ok page:\n{}", r.text);
    assert!(r.text.contains("HTTP 404"), "{}", r.text);
    assert!(r.text.contains("this node does not index"), "the refusal does not name the indexer:\n{}", r.text);
    assert!(!r.text.contains("did not answer"), "{}", r.text);
    assert!(r.text.contains("no store was opened"), "{}", r.text);

    let r = cli::run_explorer(
        &MeshClient::new(Explorer::new(10).refusing_search(2)),
        &Command::RecentTransactions { tag: TAG, count: 5, from: 0 },
    );
    assert_eq!(r.code, Code::Refused, "{}", r.text);
    assert!(r.text.contains("mesh error code 2 (retriable)"), "{}", r.text);
    assert!(r.text.contains("this node runs an indexer, and it did not answer"), "{}", r.text);
    assert!(!r.text.contains("does not index"), "an indexer that did not answer was read as none:\n{}", r.text);

    let r = cli::run_explorer(
        &MeshClient::new(Explorer::new(10).refusing_search(1)),
        &Command::RecentTransactions { tag: TAG, count: 5, from: 0 },
    );
    assert_eq!(r.code, Code::Refused, "{}", r.text);
    assert!(r.text.contains("mesh error code 1"), "{}", r.text);
    assert!(!r.text.contains("indexer"), "an invalid request was read as about the indexer:\n{}", r.text);

    let hash = [0x18u8; 32];
    let r = cli::run_explorer(&MeshClient::new(Explorer::new(10).without_indexer()), &Command::LookupTransaction { hash });
    assert_eq!(r.code, Code::Refused, "{}", r.text);
    assert!(r.text.contains("this node does not index"), "{}", r.text);
    let r = cli::run_explorer(&MeshClient::new(Explorer::new(10).refusing_search(2)), &Command::LookupTransaction { hash });
    assert!(r.text.contains("it did not answer"), "{}", r.text);
    println!(
        "  recent-transactions, transaction: an empty index is exit 0 with an empty table; the 404 of no indexer and the code 2 of one that did not answer are exit 3 naming which; code 1 names neither"
    );
}

/// `mempool`: the queue size, the first `--count` transactions read in full,
/// a transaction that left the queue between the list and the read reported
/// as such, and the endpoint's convention named.
#[test]
fn mempool_lists_the_queue_and_reads_the_first_of_it_whole() {
    let (a, b, c) = ([0xa1u8; 32], [0xb2u8; 32], [0xc3u8; 32]);
    let client = MeshClient::new(Explorer::new(10).with_queue(&[a, b, c], &[b], &[]));
    let r = cli::run_explorer(&client, &Command::Mempool { count: 2 });
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    assert!(r.text.starts_with("the mempool: 3 transaction(s) waiting to be mined; the first 2 read\n"), "{}", r.text);
    assert!(r.text.contains(&format!("  {}  1 destination(s)  10000000 nanoMCM (0.010000000 MCM)\n", hexs(&a))), "{}", r.text);
    assert!(r.text.contains("memo INVOICE-7"), "the destination's reference is not on the page:\n{}", r.text);
    assert!(r.text.contains("-10000500 nanoMCM"), "the source is not debited net:\n{}", r.text);
    assert!(
        r.text.contains(&format!("  {}  left the queue before it was read: mined since the list was read, or dropped\n", hexs(&b))),
        "{}",
        r.text
    );
    assert!(!r.text.contains(&hexs(&c)), "a third transaction was read:\n{}", r.text);
    assert!(r.text.contains("  1 more waiting, not read: this page reads the first 2, and --count reads up to 100\n"), "{}", r.text);
    assert!(r.text.contains("/mempool and /mempool/transaction"), "the page does not name the endpoints:\n{}", r.text);
    let paths = client.transport().paths.borrow().clone();
    assert_eq!(paths, ["/mempool", "/mempool/transaction", "/mempool/transaction"]);
    let bodies: Vec<String> = client.transport().bodies.borrow().iter().map(|b| String::from_utf8_lossy(b).into_owned()).collect();
    let network = r#""network_identifier":{"blockchain":"mochimo","network":"mainnet"}"#;
    assert_eq!(
        bodies,
        [
            format!("{{{network}}}"),
            format!(r#"{{{network},"transaction_identifier":{{"hash":"0x{}"}}}}"#, hexs(&a)),
            format!(r#"{{{network},"transaction_identifier":{{"hash":"0x{}"}}}}"#, hexs(&b)),
        ],
        "the requests are not the bodies the handlers read"
    );
    println!("  mempool: 3 waiting, 2 read, one gone since the list, the rest counted, 3 requests with their bodies");
}

/// An empty queue (the middleware's `null`) is a page saying so and exit 0.
/// A queue that cannot be read, or a transaction that fails for another
/// reason than having left it, is a refusal that says which.
#[test]
fn mempool_says_an_empty_queue_and_refuses_what_it_could_not_read() {
    let client = MeshClient::new(Explorer::new(10));
    let r = cli::run_explorer(&client, &Command::Mempool { count: 5 });
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    assert!(r.text.contains("the mempool: 0 transaction(s) waiting to be mined; the first 0 read\n"), "{}", r.text);
    assert!(r.text.contains("(none: this node's queue is empty.)"), "{}", r.text);
    assert_eq!(client.transport().paths.borrow().len(), 1, "an empty queue asked for a transaction");

    let r = cli::run_explorer(&MeshClient::new(Explorer::new(10).with_queue(&[], &[], &[[0; 32]])), &Command::Mempool { count: 5 });
    assert_eq!(r.code, Code::Refused, "{}", r.text);
    assert!(r.text.contains("no store was opened"), "{}", r.text);
    assert!(!r.text.contains("indexer"), "the queue's code 2 was read as about the indexer:\n{}", r.text);

    let (a, b) = ([0xa1u8; 32], [0xb2u8; 32]);
    let r = cli::run_explorer(&MeshClient::new(Explorer::new(10).with_queue(&[a, b], &[], &[b])), &Command::Mempool { count: 5 });
    assert_eq!(r.code, Code::Refused, "a page missing a transaction it could not read is not an ok page:\n{}", r.text);
    assert!(r.text.contains(&format!("The queue's ids were read; transaction {} was not.", hexs(&b))), "{}", r.text);
    assert!(!r.text.contains("destination(s)"), "the rows read before the failure were printed:\n{}", r.text);
    println!("  mempool: an empty queue is exit 0 and says so; a queue not read, and a transaction not read, are exit 3 naming which");
}

/// `block <number>`: the reward is reported separately and excluded from
/// what moved.
#[test]
fn block_reports_its_reward_apart_from_what_it_moved() {
    let e = Explorer::new(1_078_600);
    let r = cli::run_explorer(&MeshClient::new(e), &Command::Block { at: args::BlockAt::Index(1_078_535) });
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    assert!(r.text.contains("block 1078535"), "{}", r.text);
    assert!(r.text.contains("parent   1078534"), "{}", r.text);
    assert!(r.text.contains("reward   12065840589 nanoMCM"), "{}", r.text);
    assert!(r.text.contains("spends   1"), "{}", r.text);
    // The reward is 12,065,840,589 and the one spend delivers 10,000,000.
    // `moved` is the second, never the sum.
    assert!(r.text.contains("moved    10000000 nanoMCM"), "the reward leaked into what moved:\n{}", r.text);
    assert!(r.text.contains("fees     500 nanoMCM"), "{}", r.text);
    assert!(r.text.contains("/block, which re-parses the wire"), "{}", r.text);
    println!("  block: reward 12,065,840,589 on its own line, moved 10,000,000, fees 500");
}

/// `blocks`: the tip, then one row per block below it.
#[test]
fn blocks_walks_down_from_the_tip_one_row_each() {
    let e = Explorer::new(1_078_600);
    let r = cli::run_explorer(&MeshClient::new(e), &Command::Blocks { count: 3 });
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    assert!(r.text.contains("the tip is 1078600"), "{}", r.text);
    for i in ["1078600", "1078599", "1078598"] {
        assert!(r.text.contains(i), "block {i} is not on the page:\n{}", r.text);
    }
    assert!(!r.text.contains("1078597"), "a fourth block was fetched:\n{}", r.text);
    // Two: the reward transaction and the one spend. `/block` lists the
    // reward among its transactions, so `block <n>` counts spends separately.
    assert!(r.text.contains("2 transaction(s)"), "the row does not carry a transaction count:\n{}", r.text);
    println!("  blocks: the tip and the two below it, one row each, one /block call per row");
}

/// `block` and `blocks` name a block's kind and print its figures: a normal
/// block's difficulty, root, size, count, minimum fee and haiku; a
/// pseudo-block's without the haiku; a neogenesis block named from its
/// number even without metadata; and missing metadata reported as such.
#[test]
fn block_and_blocks_name_the_kind_and_print_the_blocks_own_figures() {
    use serde_json::{json, Value};
    let with = |index: u64, metadata: Option<Value>| -> Value {
        let mut body: Value = serde_json::from_str(&Explorer::block_body(index)).unwrap_or_else(|e| panic!("{e}"));
        if let Some(m) = metadata {
            body["block"]["metadata"] = m;
        }
        body
    };
    let figures = |tx_count: u64| {
        json!({
            "block_size": 9824, "difficulty": 37, "fee": 500,
            "haiku": "at night \nsoft snakes \nreturning ",
            "nonce": format!("0x{}", "0c".repeat(32)), "root": format!("0x{}", "fa".repeat(32)),
            "stime": 1_788_500_198_000_i64, "tx_count": tx_count,
        })
    };
    let page = |index: u64, metadata: Option<Value>| {
        let r = render_explorer_reply("/block", &with(index, metadata), &Command::Block { at: args::BlockAt::Index(index) });
        assert_eq!(r.code, Code::Ok, "{}", r.text);
        r.text
    };

    let normal = page(1_078_535, Some(figures(4)));
    for line in [
        "  type     normal\n",
        &format!("  work     difficulty 37, nonce {}\n", "0c".repeat(32)),
        &format!("  root     {}\n", "fa".repeat(32)),
        "  size     9824 bytes, 4 transaction(s) besides the reward, minimum fee 500 nanoMCM (0.000000500 MCM)\n",
        "  haiku    at night / soft snakes / returning\n",
    ] {
        assert!(normal.contains(line), "missing {line:?}:\n{normal}");
    }
    assert!(normal.contains("reward   12065840589 nanoMCM"), "the page's other lines moved:\n{normal}");

    let pseudo = page(1_078_535, Some(figures(0)));
    assert!(pseudo.contains("  type     pseudo: no transactions, and no proof of work is checked for it\n"), "{pseudo}");
    assert!(!pseudo.contains("haiku"), "a pseudo-block's nonce is not a haiku:\n{pseudo}");

    let neogenesis = page(1_078_528, None);
    assert!(neogenesis.contains("  type     neogenesis; this node sent no block metadata\n"), "{neogenesis}");
    let bare = page(1_078_535, None);
    assert!(bare.contains("  type     kind not sent; this node sent no block metadata\n"), "{bare}");
    assert!(!bare.contains("  work "), "{bare}");

    // A haiku the node sent with control characters stays on its own line.
    let mut odd = figures(4);
    odd["haiku"] = json!("one\u{1b}[2J \n\u{202e}two");
    let escaped = page(1_078_535, Some(odd));
    assert!(escaped.contains("  haiku    one\\u{1b}[2J / \\u{202e}two\n"), "{escaped}");

    // `blocks`: each row ends with its kind; the double sends no metadata,
    // so only the neogenesis number is named.
    let r = cli::run_explorer(&MeshClient::new(Explorer::new(1_078_529)), &Command::Blocks { count: 3 });
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    let rows: Vec<&str> = r.text.lines().skip(1).collect();
    assert_eq!(rows.len(), 3, "{}", r.text);
    assert!(rows[0].trim_start().starts_with("1078529") && rows[0].ends_with("  kind not sent"), "{}", r.text);
    assert!(rows[1].trim_start().starts_with("1078528") && rows[1].ends_with("  neogenesis"), "{}", r.text);
    assert!(rows[2].ends_with("  kind not sent"), "{}", r.text);
    println!("  block: normal with its figures and haiku, pseudo without, neogenesis by number, none said; blocks rows end with the kind");
}

// ---------------------------------------------------------------------------
// The partition: a diverged account is refused, its siblings are not
// ---------------------------------------------------------------------------

/// Account 1, funded and in sync, beside account 0 swept to zero.
///
/// The emptied account reads as `Absent`: the Mesh answers code 4 for a tag
/// at zero balance, because its quorum discards zero-amount answers. The
/// ledger entry still exists and reappears once the tag is paid.
fn emptied_and_funded(name: &str) -> (ScratchDir, Keystore, mochimo_crypto::addr::Tag, Chain) {
    let m = master();
    let sibling = mochimo_crypto::derive::derive_account_tag(&m, 1);
    let (dir, mut ks) = store(name);
    ks.add(Account::derive(&m, 1)).unwrap_or_else(|e| panic!("{e}"));
    // Account 0 swept itself to zero: the key at 0 signed and the store
    // advanced to the change key at 1, with the reservation still open.
    let _ = ks
        .persist_advance(&TAG, &[0xD1; 32], Figures { reserved_balance: 5_000_000, blk_to_live: 0 })
        .unwrap_or_else(|e| panic!("{e}"));
    drop(ks);
    let ks = reopen(name, dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let sibling_at = mochimo_crypto::recon::derived_address_at(&m, 1, chain::pos(0));
    let chain = Chain::new(&[
        (TAG, ChainState::Absent),
        (sibling, ChainState::At(sibling_at, 9_000_000)),
    ]);
    (dir, ks, sibling, chain)
}

/// The id a spend from `tag` will carry, from a dry run on a throwaway store
/// built from the same entropy (the dry run advances its own copy).
fn submit_id_for(name: &str, tag: mochimo_crypto::addr::Tag, dsts: Vec<Destination>) -> [u8; 32] {
    let m = master();
    let (_dir, ks, _sibling, chain) = emptied_and_funded(name);
    let mut w = Wallet::open(ks, MeshClient::new(chain), Some(&m)).unwrap_or_else(|e| panic!("{e}"));
    let plan = w
        .plan(&tag, &KeyAccess::Master(&m), dsts, MFEE, 0)
        .unwrap_or_else(|e| panic!("{e}"));
    w.reserve_and_sign(&plan, KeyAccess::Master(&m))
        .unwrap_or_else(|e| panic!("{e}"))
        .id()
        .0
}

/// A sibling that reconciles can spend while another account is diverged.
///
/// The accounts' key streams are independent. A confirmed index on the
/// sibling means the node returned exactly the address derived at the stored
/// position, so its next key is unused.
#[test]
fn a_reconciling_account_spends_while_a_sibling_is_diverged() {
    let m = master();
    let sibling = mochimo_crypto::derive::derive_account_tag(&m, 1);
    let id = submit_id_for(
        "cli-partition-send-dry",
        sibling,
        vec![Destination { tag: TO, reference: [0; 16], amount: 1_000 }],
    );
    let (_dir, ks, _s, chain) = emptied_and_funded("cli-partition-send");
    chain.accepts_submit(id);
    let s = Spend {
        tag: sibling,
        dsts: vec![SpendTo { to: TO, reference: [0; ADDR_REF_LEN], amount: Some(1_000) }],
        fee_total: MFEE,
        blk_to_live: 0,
        expect_balance: None,
    };
    let r = cli::run(ks, MeshClient::new(chain), &Command::Send(s));
    assert_eq!(
        r.code,
        Code::Ok,
        "a funded account could not spend while a sibling was diverged:\n{}",
        r.text
    );
    assert_says(&r, "sending 1000 nanoMCM", "send from the reconciling account");
    // The page still carries the diverged account's report.
    assert_says(&r, "THIS STORE IS NOT WHOLE", "send from the reconciling account");
}

/// The diverged account's own `send` refuses, by name, with its report,
/// carrying the same three readings of code 4 as the startup refusal.
#[test]
fn the_diverged_accounts_own_send_refuses_by_name_with_its_report() {
    let (_dir, ks, _sibling, chain) = emptied_and_funded("cli-partition-refuse");
    let r = cli::run(ks, MeshClient::new(chain), &Command::Send(spend()));
    assert_ne!(r.code, Code::Ok, "a diverged account spent:\n{}", r.text);
    assert_says(&r, &format!("account {}", hexs(&TAG)), "the refusal names the account");
    assert_says(&r, "did not resolve this tag", "the refusal carries the report");
    assert_says(&r, "ZERO balance", "the report keeps the three readings");
    assert_says(&r, "lookup itself failed", "the report keeps the three readings");
    // The account is refused, not the store: the wallet opened because the
    // sibling reconciled.
    assert!(
        !r.text.contains("WALLET WILL NOT START"),
        "a per-account refusal rendered the whole-store page:\n{}",
        r.text
    );
    assert_eq!(
        r.code,
        Code::Refused,
        "the command was refused by a wallet that started, which is exit 3 and not startup:\n{}",
        r.text
    );
}

/// Every command that opens the wallet renders every diverged report.
/// `balance` shows reconciled and diverged accounts together.
#[test]
fn every_command_that_opens_the_wallet_renders_the_diverged_report() {
    for (what, command) in [
        ("balance", Command::Balance),
        ("settle", Command::Settle { tag: mochimo_crypto::derive::derive_account_tag(&master(), 1) }),
    ] {
        let (_dir, ks, _sibling, chain) = emptied_and_funded(&format!("cli-partition-notice-{what}"));
        let r = cli::run(ks, MeshClient::new(chain), &command);
        assert_says(&r, &format!("account {}", hexs(&TAG)), what);
        assert_says(&r, "did not resolve this tag", what);
    }
    // `balance` shows the sibling's funds and the diverged report.
    let (_dir, ks, _sibling, chain) = emptied_and_funded("cli-partition-balance");
    let r = cli::run(ks, MeshClient::new(chain), &Command::Balance);
    assert_eq!(r.code, Code::Ok, "balance refused a store with one good account:\n{}", r.text);
    assert_says(&r, "9000000", "balance lists the reconciled account's funds");
    assert_says(&r, "did not resolve this tag", "balance lists the diverged account");
}

/// A store where no account reconciles refuses outright (`StartupRefusal`).
#[test]
fn a_store_where_no_account_reconciles_still_refuses_outright() {
    let (_dir, ks) = store("cli-partition-none");
    let r = cli::run(
        ks,
        MeshClient::new(Chain::new(&[(TAG, ChainState::Absent)])),
        &Command::Balance,
    );
    assert_eq!(r.code, Code::StartupRefused, "a store with no operable account opened:\n{}", r.text);
    assert_says(&r, "WALLET WILL NOT START", "the whole-store refusal");
}

/// Paying the emptied account from its sibling restores it, and it settles.
///
/// The ledger keeps the zero-balance entry, so a paid tag reappears at the
/// address the store expects (the change key of the spend that emptied it)
/// and `settle` resolves the reservation. The scripted node does not mine,
/// so the post-payment ledger state is scripted.
#[test]
fn paying_the_emptied_account_from_its_sibling_lets_it_settle() {
    let m = master();
    let (dir, ks, sibling, chain) = emptied_and_funded("cli-partition-recover");

    // 1. The emptied account cannot settle while the chain will not show it.
    let r = cli::run(ks, MeshClient::new(chain), &Command::Settle { tag: TAG });
    assert_ne!(r.code, Code::Ok, "an invisible account settled:\n{}", r.text);
    assert_says(&r, "did not resolve this tag", "settle on the diverged account");

    // 2. The sibling pays it, which requires the wallet to open.
    let ks = reopen("cli-partition-recover-2", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let sibling_at = mochimo_crypto::recon::derived_address_at(&m, 1, chain::pos(0));
    let id = submit_id_for(
        "cli-partition-recover-dry",
        sibling,
        vec![Destination { tag: TAG, reference: [0; 16], amount: 2_000_000 }],
    );
    let pay = Spend {
        tag: sibling,
        dsts: vec![SpendTo { to: TAG, reference: [0; ADDR_REF_LEN], amount: Some(2_000_000) }],
        fee_total: MFEE,
        blk_to_live: 0,
        expect_balance: None,
    };
    let paying = Chain::new(&[
        (TAG, ChainState::Absent),
        (sibling, ChainState::At(sibling_at, 9_000_000)),
    ]);
    paying.accepts_submit(id);
    let r = cli::run(ks, MeshClient::new(paying), &Command::Send(pay));
    assert_eq!(r.code, Code::Ok, "the sibling could not pay the emptied account:\n{}", r.text);

    // 3. The entry reappears at the change key of the spend that emptied it,
    //    the position the store already holds.
    let ks = reopen("cli-partition-recover-3", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let r = cli::run(
        ks,
        MeshClient::new(Chain::new(&[
            (TAG, ChainState::At(addr_at(1), 2_000_000)),
            (sibling, ChainState::At(sibling_at, 6_999_000)),
        ])),
        &Command::Settle { tag: TAG },
    );
    assert_eq!(r.code, Code::Ok, "the re-funded account did not settle:\n{}", r.text);
    assert_says(&r, "settled", "settle after the account was paid");
}

// ---------------------------------------------------------------------------
// The long operations, cancelled
// ---------------------------------------------------------------------------

/// A cancel that counts how often it is asked and says stop at the `at`-th
/// asking (from zero). `new` keeps saying stop afterwards; `once` says it at
/// that asking only and `false` after, as `Cancel::when` allows (a flag
/// cleared on read). `u32::MAX` never stops, to count a full run's askings.
struct StopAt {
    at: u32,
    once: bool,
    asked: std::cell::Cell<u32>,
}

impl StopAt {
    fn new(at: u32) -> StopAt {
        StopAt { at, once: false, asked: std::cell::Cell::new(0) }
    }

    fn once(at: u32) -> StopAt {
        StopAt { at, once: true, asked: std::cell::Cell::new(0) }
    }

    fn ask(&self) -> bool {
        let n = self.asked.get();
        self.asked.set(n + 1);
        if self.once {
            n == self.at
        } else {
            n >= self.at
        }
    }
}

/// A restore cancelled at any point writes nothing and returns `Cancelled`.
///
/// The store holds account 0 and the chain holds account 1 at position 2,
/// so an uncancelled restore of account 1 checks for cancellation five
/// times: before the node, at positions 0, 1 and 2, and before the commit.
/// That run is the control and adds the account at index 2. A cancel is then
/// landed at each of the five points, on a fresh store each time, both as a
/// persistent and as a one-shot cancel; each leaves the snapshot unchanged
/// and the account absent.
#[test]
fn a_restore_cancelled_at_any_point_writes_nothing() {
    use mochimo_crypto::cli::restore;
    use mochimo_crypto::recon::{Cancel, Unfinished};
    let m = master();
    let tag1 = mochimo_crypto::derive::derive_account_tag(&m, 1);
    let at2 = mochimo_crypto::recon::derived_address_at(&m, 1, chain::pos(2));
    let chain = || Chain::new(&[(tag1, ChainState::At(at2, 3_000))]);

    let (_dir, mut ks) = store("cli-restore-cancel-measure");
    let measure = StopAt::new(u32::MAX);
    let ask = || measure.ask();
    let client = MeshClient::new(chain());
    let restored = restore::restore_account_with(&mut ks, &client, &m, 1, Some(4), &Cancel::when(&ask))
        .unwrap_or_else(|e| panic!("an uncancelled restore failed: {e:?}"));
    assert_eq!(restored.found.index.get(), 2);
    assert_eq!(restored.held_at, None, "the control did not add the account");
    let askings = measure.asked.get();
    assert_eq!(askings, 5, "a restore found at position 2 asked its cancel {askings} time(s), not 5");

    for (at, stop) in (0..askings).flat_map(|at| [(at, StopAt::new(at)), (at, StopAt::once(at))]) {
        let (dir, mut ks) = store("cli-restore-cancel");
        let before = dir.snapshot_bytes();
        let ask = || stop.ask();
        let client = MeshClient::new(chain());
        let result = restore::restore_account_with(&mut ks, &client, &m, 1, Some(4), &Cancel::when(&ask));
        assert!(
            matches!(result, Err(Unfinished::Cancelled)),
            "a cancel at asking {at} came back as {:?}",
            result.as_ref().map(|r| r.found.index.get())
        );
        assert_eq!(dir.snapshot_bytes(), before, "a cancel at asking {at} changed the snapshot");
        assert!(
            ks.view(&tag1).unwrap_or_else(|e| panic!("{e}")).is_none(),
            "a cancel at asking {at} left the account in the store"
        );
        let expected = usize::from(at > 0);
        assert_eq!(client.transport().calls(), expected, "a cancel at asking {at} asked the node the wrong number of times");
    }
}

/// A sweep cancelled before any index's node call stops there and returns
/// `Cancelled`, not a partial sweep reported as complete.
///
/// The control, with a cancel that never fires, equals `sweep`'s result and
/// checks once per index, so the counts below are request counts.
#[test]
fn a_sweep_cancelled_before_any_index_asks_no_further_and_writes_nothing() {
    use mochimo_crypto::cli::discover;
    use mochimo_crypto::recon::{Cancel, Unfinished};
    let m = master();
    let chain = || Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    let (dir, ks) = store("cli-sweep-cancel");
    let before = dir.snapshot_bytes();

    let plain = discover::sweep(&ks, &MeshClient::new(chain()), &m, 3).unwrap_or_else(|e| panic!("{e:?}"));
    let never = StopAt::new(u32::MAX);
    let ask = || never.ask();
    let client = MeshClient::new(chain());
    let same = discover::sweep_with(&ks, &client, &m, 3, &Cancel::when(&ask)).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(same, plain, "a cancel that never fires changed the sweep");
    assert_eq!(client.transport().calls(), 4);
    assert_eq!(never.asked.get(), 4, "the cancel was not asked once per index");

    for (at, stop) in (0..4u32).flat_map(|at| [(at, StopAt::new(at)), (at, StopAt::once(at))]) {
        let ask = || stop.ask();
        let client = MeshClient::new(chain());
        let result = discover::sweep_with(&ks, &client, &m, 3, &Cancel::when(&ask));
        assert!(matches!(result, Err(Unfinished::Cancelled)), "a cancel before index {at} came back as {result:?}");
        assert_eq!(client.transport().calls(), at as usize, "a cancel before index {at} asked about it anyway");
    }
    assert_eq!(dir.snapshot_bytes(), before, "a sweep changed the snapshot");
}

/// A reconcile cancelled at any point writes nothing and returns
/// `Cancelled`, never `AcknowledgementDoesNotMatch`.
///
/// The store is at 0, the chain at 3, and the operator names 3. An
/// uncancelled run checks eleven times: before the account, at the four
/// positions of the walk, before the write's re-check, at the four positions
/// of the re-check's walk, and between the re-check's match and the write.
/// The control advances to 3. A cancel during the re-check's walk makes the
/// re-check fail to match; that is still reported as `Cancelled`, including
/// for a one-shot cancel. Every landing leaves the snapshot unchanged and
/// the stored index at 0.
#[test]
fn a_reconcile_cancelled_at_any_point_writes_nothing() {
    use mochimo_crypto::cli::reconcile;
    use mochimo_crypto::recon::{Cancel, Unfinished};
    let m = master();
    let chain = || Chain::new(&[(TAG, ChainState::At(addr_at(3), 1_000))]);

    let (dir, mut ks) = store("cli-reconcile-cancel-measure");
    let measure = StopAt::new(u32::MAX);
    let ask = || measure.ask();
    let reviewed = reconcile::advance_acknowledged_with(&mut ks, &MeshClient::new(chain()), &TAG, Some(&m), 3, &Cancel::when(&ask))
        .unwrap_or_else(|e| panic!("an uncancelled reconcile failed: {e:?}"));
    assert_eq!(reviewed.outcome, reconcile::Outcome::Advanced { index: 3 }, "the control did not advance");
    drop(ks);
    assert_eq!(stored_index(&dir), 3);
    let askings = measure.asked.get();
    assert_eq!(askings, 11, "the reconcile asked its cancel {askings} time(s), not 11");

    for (at, stop) in (0..askings).flat_map(|at| [(at, StopAt::new(at)), (at, StopAt::once(at))]) {
        let (dir, mut ks) = store("cli-reconcile-cancel");
        let before = dir.snapshot_bytes();
        let ask = || stop.ask();
        let client = MeshClient::new(chain());
        let result = reconcile::advance_acknowledged_with(&mut ks, &client, &TAG, Some(&m), 3, &Cancel::when(&ask));
        assert!(
            matches!(result, Err(Unfinished::Cancelled)),
            "a cancel at asking {at} came back as {:?}",
            result.as_ref().map(|r| &r.outcome)
        );
        if at == 0 {
            assert_eq!(client.transport().calls(), 0, "a cancel raised first asked the node");
        }
        drop(ks);
        assert_eq!(dir.snapshot_bytes(), before, "a cancel at asking {at} changed the snapshot");
        assert_eq!(stored_index(&dir), 0, "a cancel at asking {at} moved the index");
    }
}

// ---------------------------------------------------------------------------
// The long operations, watched
// ---------------------------------------------------------------------------

/// A restore reports once before it asks the node, then every
/// `PROGRESS_EVERY` positions of its scan.
///
/// The chain holds account 1 at position `PROGRESS_EVERY - 1`, so the scan
/// covers exactly `PROGRESS_EVERY` positions and reports once more, against
/// the ceiling `--scan-to` sets. The first report precedes any request; the
/// account is added where a plain restore would add it.
#[test]
fn a_restore_reports_before_the_node_and_every_progress_interval_of_its_scan() {
    use mochimo_crypto::cli::restore;
    use mochimo_crypto::recon::{Cancel, Progress, PROGRESS_EVERY};
    let m = master();
    let tag1 = mochimo_crypto::derive::derive_account_tag(&m, 1);
    let last = PROGRESS_EVERY - 1;
    let at = mochimo_crypto::recon::derived_address_at(&m, 1, chain::pos(last));
    let (_dir, mut ks) = store("cli-restore-progress");
    let client = MeshClient::new(Chain::new(&[(tag1, ChainState::At(at, 3_000))]));
    let mut seen: Vec<(Progress, usize)> = Vec::new();
    let scan_to = PROGRESS_EVERY + 100;
    let restored = restore::restore_account_with_progress(&mut ks, &client, &m, 1, Some(scan_to), &Cancel::NEVER, &mut |p| {
        seen.push((p, client.transport().calls()));
    })
    .unwrap_or_else(|e| panic!("an uncancelled restore failed: {e:?}"));
    assert_eq!(restored.found.index.get(), last);
    let ceiling = scan_to + 1;
    assert_eq!(
        seen,
        vec![
            (Progress { account: 0, accounts: 1, position: 0, ceiling }, 0),
            (Progress { account: 0, accounts: 1, position: PROGRESS_EVERY, ceiling }, 1),
        ],
        "the restore's reports were not one before the node and one per interval of its scan"
    );
}

/// A sweep reports each index before asking the node about it; position and
/// ceiling are zero, and the reports are the indices searched, in order.
#[test]
fn a_sweep_reports_each_index_before_it_asks_the_node_about_it() {
    use mochimo_crypto::cli::discover;
    use mochimo_crypto::recon::{Cancel, Progress};
    let m = master();
    let (_dir, ks) = store("cli-sweep-progress");
    let client = MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]));
    let mut seen: Vec<(Progress, usize)> = Vec::new();
    let swept = discover::sweep_with_progress(&ks, &client, &m, 3, &Cancel::NEVER, &mut |p| {
        seen.push((p, client.transport().calls()));
    })
    .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(swept.to, 3);
    let expected: Vec<(Progress, usize)> = (0..4u32)
        .map(|account| (Progress { account, accounts: 4, position: 0, ceiling: 0 }, account as usize))
        .collect();
    assert_eq!(seen, expected, "the sweep did not report each index once, before its node call");
}

/// A reconcile reports each account before reconciling it, and the named
/// one again before the write's re-check.
///
/// The store is at 0, the chain at 3, and the operator names 3: the walk
/// reaches 3 in four positions, short of an interval, so only the two starts
/// are reported. Their ceiling is the divergence window around the stored
/// position, which contains the raised ceiling.
#[test]
fn a_reconcile_reports_each_account_and_the_named_one_again_before_the_write() {
    use mochimo_crypto::cli::reconcile;
    use mochimo_crypto::recon::{Cancel, Progress, ScanScope, DIVERGENCE_WINDOW};
    let m = master();
    let (dir, mut ks) = store("cli-reconcile-progress");
    let client = MeshClient::new(Chain::new(&[(TAG, ChainState::At(addr_at(3), 1_000))]));
    let mut seen: Vec<(Progress, usize)> = Vec::new();
    let reviewed = reconcile::advance_acknowledged_with_progress(&mut ks, &client, &TAG, Some(&m), 3, &Cancel::NEVER, &mut |p| {
        seen.push((p, client.transport().calls()));
    })
    .unwrap_or_else(|e| panic!("an uncancelled reconcile failed: {e:?}"));
    assert_eq!(reviewed.outcome, reconcile::Outcome::Advanced { index: 3 });
    drop(ks);
    assert_eq!(stored_index(&dir), 3);
    // Window positions 0 through 20 hold the raised ceiling's 0 through 3.
    let ceiling = DIVERGENCE_WINDOW + 1;
    assert_eq!(ScanScope::DIAGNOSTIC.window, Some(DIVERGENCE_WINDOW));
    assert_eq!(
        seen,
        vec![
            (Progress { account: 0, accounts: 1, position: 0, ceiling }, 0),
            (Progress { account: 0, accounts: 1, position: 0, ceiling }, 1),
        ],
        "the reconcile did not report its account, and again before the re-check"
    );
}

// ---------------------------------------------------------------------------
// The command line's decisions, called from outside it
// ---------------------------------------------------------------------------

/// `status_outcome` matches the decision `status` makes: for each of its four
/// outcomes (in sync, a divergence with the chain at 3 and the store at 0, a
/// tag the store does not hold, an unreachable chain), the outcome built
/// from `reconcile::account_status` equals what `decide` returns.
#[test]
fn status_outcome_is_the_decision_status_makes_for_every_class_of_answer() {
    use mochimo_crypto::cli::outcome::Outcome;
    let m = master();
    let alien = [0x42; ADDR_TAG_LEN];
    let cases: [(&str, ChainState, [u8; ADDR_TAG_LEN]); 4] = [
        ("in sync", ChainState::At(addr_at(0), 5_000_000), TAG),
        ("diverged", ChainState::At(addr_at(3), 5_000_000), TAG),
        ("not held", ChainState::At(addr_at(0), 5_000_000), alien),
        ("unreachable", ChainState::Unreachable, TAG),
    ];
    let mut kinds = Vec::new();
    for (what, state, asked) in cases {
        let (_d1, ks) = store("cli-status-outcome-decide");
        let decided = cli::decide(ks, MeshClient::new(Chain::new(&[(TAG, state)])), &Command::Status { tag: asked, scan_to: None });
        let (_d2, ks) = store("cli-status-outcome-direct");
        let compared = cli::reconcile::account_status(&ks, &MeshClient::new(Chain::new(&[(TAG, state)])), &asked, Some(&m), None);
        let direct = cli::status_outcome(&asked, compared);
        assert_eq!(direct, decided.outcome, "{what}: status_outcome decided differently from status");
        kinds.push(match direct {
            Outcome::Status { .. } => "Status",
            Outcome::StatusDiverged { .. } => "StatusDiverged",
            Outcome::NoSuchAccount { .. } => "NoSuchAccount",
            Outcome::StatusRefused { .. } => "StatusRefused",
            _ => "another",
        });
    }
    assert_eq!(kinds, ["Status", "StatusDiverged", "NoSuchAccount", "StatusRefused"], "the cases did not reach every class");
}

/// `resign_outcome` matches the decision `resign` makes: with a reservation
/// open, the outcome built from `Wallet::resign_pending` equals what `decide`
/// returns, for a spend that is not the reserved one, a reservation the chain
/// has moved past, and a reproduction written to the socket. `resign` writes
/// nothing to the store, so both paths use the same reservation.
#[test]
fn resign_outcome_is_the_decision_resign_makes() {
    use mochimo_crypto::cli::outcome::Outcome;
    let m = master();
    let (dir, _artifact) = send_that_never_left("cli-resign-outcome");
    let id = id_for_the_spend("cli-resign-outcome-id");
    let mut wrong = spend();
    wrong.dsts[0].amount = Some(999);
    let cases: [(&str, Spend, ChainState); 3] = [
        ("not the reserved spend", wrong, ChainState::At(addr_at(0), 5_000_000)),
        ("already landed", spend(), ChainState::At(addr_at(1), 4_998_500)),
        ("reproduced", spend(), ChainState::At(addr_at(0), 5_000_000)),
    ];
    let mut kinds = Vec::new();
    for (what, s, state) in cases {
        let chain = || {
            let c = Chain::new(&[(TAG, state)]);
            c.accepts_submit(id);
            c
        };
        let ks = reopen("resign outcome decide", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
        let decided = cli::decide(ks, MeshClient::new(chain()), &Command::Resign(s.clone()));

        let ks = reopen("resign outcome direct", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
        let mut w = Wallet::open(ks, MeshClient::new(chain()), Some(&m)).unwrap_or_else(|e| panic!("{what}: {e}"));
        let access = cli::key_access(w.store(), &s.tag, Some(&m)).unwrap_or_else(|e| panic!("{e}"));
        let dsts: Vec<Destination> = s
            .dsts
            .iter()
            .map(|d| Destination { tag: d.to, reference: d.reference, amount: d.amount.unwrap_or(0) })
            .collect();
        let mut listed = dsts.clone();
        listed.sort_by_key(Destination::mdst_image);
        let resigned = w.resign_pending(&s.tag, &access, dsts, s.fee_total, s.blk_to_live);
        let direct = cli::resign_outcome(&w, &s.tag, listed, s.blk_to_live, resigned);
        assert_eq!(direct, decided.outcome, "{what}: resign_outcome decided differently from resign");
        kinds.push(match direct {
            Outcome::NotTheReservedSpend => "NotTheReservedSpend",
            Outcome::ReservationAlreadyLanded { .. } => "ReservationAlreadyLanded",
            Outcome::Resigned { .. } => "Resigned",
            _ => "another",
        });
    }
    assert_eq!(kinds, ["NotTheReservedSpend", "ReservationAlreadyLanded", "Resigned"], "the cases did not reach every class");
}

/// The public decision functions answer as the command line does: the key
/// access an account kind needs and its refusals, the amount `all` sends,
/// the scope `--scan-to` requests, the sentence every pre-write `create`
/// refusal ends with, and which node URLs need `--allow-plaintext-node`.
#[test]
fn the_decisions_made_public_answer_as_the_command_line_does() {
    use mochimo_crypto::recon::ScanScope;
    use mochimo_crypto::Error;
    let m = master();
    let (_dir, ks) = store("cli-public-decisions");
    assert!(matches!(cli::key_access(&ks, &TAG, Some(&m)), Ok(KeyAccess::Master(_))));
    assert!(matches!(cli::key_access(&ks, &TAG, None), Err(Error::KeyAccessMismatch { .. })));
    assert!(matches!(cli::key_access(&ks, &[0x42; ADDR_TAG_LEN], Some(&m)), Err(Error::NoSuchAccount)));

    assert_eq!(cli::spend_all_amount(5_000_000, MFEE), Ok(5_000_000 - MFEE));
    assert!(matches!(cli::spend_all_amount(MFEE, MFEE), Err(Error::InsufficientBalance { .. })));

    assert_eq!(cli::reconcile::scope_to(None), ScanScope::DIAGNOSTIC);
    assert_eq!(cli::reconcile::scope_to(Some(500)), ScanScope::DIAGNOSTIC.with_ceiling(501));

    assert_eq!(cli::create::nothing_was_created("the terminal closed"), "the terminal closed. Nothing was created.");
    assert_eq!(cli::create::nothing_was_created("the terminal closed."), "the terminal closed. Nothing was created.");

    for (url, gated) in [
        ("http://127.0.0.1:8080", false),
        ("http://localhost/", false),
        ("http://[::1]:8080", false),
        ("http://node.example:8080", true),
        ("https://node.example", false),
    ] {
        assert_eq!(args::plaintext_off_loopback(url), gated, "{url}");
    }
}

// ---------------------------------------------------------------------------
// The validator cold-key verbs
// ---------------------------------------------------------------------------

fn parsed(words: &[&str]) -> Result<Command, args::Usage> {
    match args::parse(&argv(words))? {
        args::ParsedArgv::Run(inv) => Ok(inv.command),
        args::ParsedArgv::Help => Err(args::Usage("help".into())),
    }
}

/// The four verbs' argv, accepted and refused. `--fee` defaults to `MFEE`
/// for the whole transaction, `--resign` is a bare flag, `--entitlement` is
/// a claim's alone, `import` requires `--sdk` and `--account`, a zero claim
/// is refused before any prompt, and every one of them needs `--node`.
#[test]
fn the_validator_verbs_parse_and_refuse_as_the_help_says() {
    use mochimo_crypto::mesh::spend::ValidatorOp;
    let cold = prefixed(&TAG);
    let delegate = prefixed(&TO);
    let base = ["--dir", "d", "--node", "https://n"];
    let with = |rest: &[&str]| -> Vec<String> {
        let mut v: Vec<String> = base.iter().map(|s| (*s).to_owned()).collect();
        v.extend(rest.iter().map(|s| (*s).to_owned()));
        v
    };
    let run = |rest: &[&str]| -> Result<Command, args::Usage> {
        match args::parse(&with(rest))? {
            args::ParsedArgv::Run(inv) => Ok(inv.command),
            args::ParsedArgv::Help => Err(args::Usage("help".into())),
        }
    };
    assert_eq!(
        run(&["set-delegate", &cold, &delegate]),
        Ok(Command::Validator(args::ValidatorTx {
            tag: TAG,
            op: ValidatorOp::SetDelegate { delegate: TO },
            fee_total: MFEE,
            blk_to_live: 0,
            resign: false,
            entitlement: None,
            network: mochimo_crypto::staking::Network::MAINNET,
            expect_balance: None,
        }))
    );
    assert_eq!(
        run(&["clear-delegate", &cold, "--fee", "600", "--resign"]),
        Ok(Command::Validator(args::ValidatorTx {
            tag: TAG,
            op: ValidatorOp::ClearDelegate,
            fee_total: 600,
            blk_to_live: 0,
            resign: true,
            entitlement: None,
            network: mochimo_crypto::staking::Network::MAINNET,
            expect_balance: None,
        }))
    );
    assert_eq!(
        run(&["claim", &cold, "1000", "--entitlement", "5000", "--btl", "9"]),
        Ok(Command::Validator(args::ValidatorTx {
            tag: TAG,
            op: ValidatorOp::Claim { amount: 1000 },
            fee_total: MFEE,
            blk_to_live: 9,
            resign: false,
            entitlement: Some(5000),
            network: mochimo_crypto::staking::Network::MAINNET,
            expect_balance: None,
        }))
    );
    assert_eq!(run(&["entitlement", &cold]), Ok(Command::Entitlement { tag: TAG, supplied: None }));
    assert_eq!(
        run(&["entitlement", &cold, "--supplied", "7"]),
        Ok(Command::Entitlement { tag: TAG, supplied: Some(7) })
    );
    assert_eq!(
        run(&["import", "--sdk", "--account", "3", "--scan-to", "20"]),
        Ok(Command::Import(args::ImportFrom::Sdk { account: 3, scan_to: Some(20) }))
    );
    for (rest, why) in [
        (vec!["claim", cold.as_str(), "0"], "EMCM_CLAIM_ZERO"),
        (vec!["claim", cold.as_str()], "claim needs <cold-tag> <amount>"),
        (vec!["set-delegate", cold.as_str()], "set-delegate needs <cold-tag> <delegate-tag>"),
        (vec!["clear-delegate", cold.as_str(), "--entitlement", "1"], "unexpected argument `--entitlement`"),
        (vec!["import", "--account", "3"], "import needs exactly one source"),
        (vec!["import", "--sdk"], "import needs --account <N>"),
    ] {
        match run(&rest) {
            Err(u) => assert!(u.0.contains(why), "{rest:?}: {}", u.0),
            Ok(c) => panic!("{rest:?} parsed as {c:?}"),
        }
    }
    assert!(parsed(&["--dir", "d", "claim", &cold, "5"]).is_err_and(|u| u.0.contains("--node is required")));
    assert!(Command::Entitlement { tag: TAG, supplied: None }.opens_no_store());
    println!("  validator verbs: 6 argv forms parsed, 7 refused");
}

/// The id a validator transaction from `TAG` at position 0 will have, from a
/// dry run on a throwaway store over the same chain, as [`id_for`] does for
/// a transfer.
fn validator_id(name: &str, op: mochimo_crypto::mesh::spend::ValidatorOp, balance: u64) -> [u8; 32] {
    let (_dir, ks) = store(name);
    let m = master();
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), balance))]);
    let mut w = Wallet::open(ks, MeshClient::new(chain), Some(&m)).unwrap_or_else(|e| panic!("{e}"));
    let plan = w
        .plan_validator(&TAG, &KeyAccess::Master(&m), op, MFEE, 0)
        .unwrap_or_else(|e| panic!("{e}"));
    w.reserve_and_sign(&plan, KeyAccess::Master(&m)).unwrap_or_else(|e| panic!("{e}")).id().0
}

/// A tip below the mainnet v4.1 trigger, where the three validator verbs
/// keep v4.0's exact-balance form; above it they are the dust-proof
/// transactions `cli::staking` checks and signs.
const V40_TIP: u64 = 1_124_000;

fn validator(op: mochimo_crypto::mesh::spend::ValidatorOp, resign: bool, entitlement: Option<u64>) -> Command {
    Command::Validator(args::ValidatorTx {
        tag: TAG,
        op,
        fee_total: MFEE,
        blk_to_live: 0,
        resign,
        entitlement,
        network: mochimo_crypto::staking::Network::MAINNET,
        expect_balance: None,
    })
}

/// `claim` end to end through the command layer. The entitlement comes from
/// the scripted `/account/entitlement`; the page names the claim, the figure
/// and the block it was read at, the fee taken from the spendable balance and
/// the dust-griefing warning, and carries the artifact the socket receives.
/// `--resign` with the same parameters reproduces the same bytes; a
/// different amount is refused with nothing on the socket.
#[test]
fn claim_reads_the_endpoint_signs_and_resigns_through_the_command_layer() {
    use chain::Entitled;
    use mochimo_crypto::mesh::spend::ValidatorOp;
    let claim = ValidatorOp::Claim { amount: 1_000 };
    let id = validator_id("cli-claim-id", claim.clone(), 5_000_000);
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.set_tip(V40_TIP);
    chain.entitles(Entitled::Amount(21_582, 1_124_001));
    chain.accepts_submit(id);
    let log = chain.submit_log();
    let (dir, r) = run_on_keeping("cli-claim", chain, &validator(claim.clone(), false, None));
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    for needle in [
        "claim: release 1000 nanoMCM of reward entitlement",
        "entitlement 21582 nanoMCM, from /account/entitlement at block 1124001",
        "from the spendable balance",
        "anyone can send dust to a public tag",
        "RETRY ARTIFACT",
        "submitted: the node accepted the SOCKET WRITE",
    ] {
        assert_says(&r, needle, "claim");
    }
    let bodies = log.borrow().clone();
    assert_eq!(bodies.len(), 1);
    let artifact = p10_signed_transaction_of(&hexs(&bodies[0])).unwrap_or_else(|| panic!("no artifact"));
    assert!(r.text.contains(&artifact), "the page does not carry the artifact the socket got");
    assert_eq!(stored_index(&dir), 1, "the claim did not reserve its key");

    // `--resign`, the same parameters: the same bytes.
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.set_tip(V40_TIP);
    chain.accepts_submit(id);
    let log2 = chain.submit_log();
    let ks = reopen("cli-claim", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let r2 = cli::run(ks, MeshClient::new(chain), &validator(claim, true, None));
    assert_eq!(r2.code, Code::Ok, "{}", r2.text);
    assert_says(&r2, "reproduced the reserved transaction, byte for byte", "claim --resign");
    assert_eq!(p10_signed_transaction_of(&hexs(&log2.borrow()[0])).as_deref(), Some(artifact.as_str()));

    // A different amount is not the reserved transaction.
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.set_tip(V40_TIP);
    let log3 = chain.submit_log();
    let ks = reopen("cli-claim", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let r3 = cli::run(ks, MeshClient::new(chain), &validator(ValidatorOp::Claim { amount: 999 }, true, None));
    assert_eq!(r3.code, Code::Refused, "{}", r3.text);
    assert_says(&r3, "this is not the spend that was reserved", "claim --resign, another amount");
    assert!(log3.borrow().is_empty(), "a different claim reached the socket");
    println!("  claim: endpoint figure on the page, artifact shipped, resign byte-identical, another amount refused");
}

/// A claim reserved below the v4.1 trigger is signed in the v4.0
/// exact-balance form. `--resign` after the tip has passed the trigger
/// reproduces those bytes, not the dust-proof form, and a different amount
/// is still refused with nothing on the socket.
#[test]
fn claim_reserved_below_the_trigger_resigns_in_its_own_form_above_it() {
    use chain::{Entitled, Staked};
    use mochimo_crypto::mesh::spend::ValidatorOp;
    let claim = ValidatorOp::Claim { amount: 1_000 };
    let id = validator_id("cli-claim-t41-id", claim.clone(), 5_000_000);
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.set_tip(V40_TIP);
    chain.entitles(Entitled::Amount(21_582, 1_124_001));
    chain.refuses_submit();
    let log = chain.submit_log();
    let (dir, r) = run_on_keeping("cli-claim-t41", chain, &validator(claim.clone(), false, None));
    assert_eq!(r.code, Code::Refused, "{}", r.text);
    assert_eq!(stored_index(&dir), 1, "the claim did not reserve its key");
    let artifact = p10_signed_transaction_of(&hexs(&log.borrow()[0])).unwrap_or_else(|| panic!("no artifact"));

    let chain = v41_chain(5_000_000, Staked::Nothing { block: V41_TIP });
    chain.entitles(Entitled::Amount(21_582, V41_TIP));
    chain.accepts_submit(id);
    let log2 = chain.submit_log();
    let ks = reopen("cli-claim-t41", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let r2 = cli::run(ks, MeshClient::new(chain), &validator(claim, true, None));
    assert_eq!(r2.code, Code::Ok, "{}", r2.text);
    assert_says(&r2, "reproduced the reserved transaction, byte for byte", "claim --resign above the trigger");
    assert_eq!(p10_signed_transaction_of(&hexs(&log2.borrow()[0])).as_deref(), Some(artifact.as_str()));

    let chain = v41_chain(5_000_000, Staked::Nothing { block: V41_TIP });
    chain.entitles(Entitled::Amount(21_582, V41_TIP));
    let log3 = chain.submit_log();
    let ks = reopen("cli-claim-t41", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let r3 = cli::run(ks, MeshClient::new(chain), &validator(ValidatorOp::Claim { amount: 999 }, true, None));
    assert_eq!(r3.code, Code::Refused, "{}", r3.text);
    assert_says(&r3, "this is not the spend that was reserved", "claim --resign above the trigger, another amount");
    assert!(log3.borrow().is_empty(), "a different claim reached the socket");
}

/// A claim reserved above the v4.1 trigger is signed in the dust-proof form.
/// `--resign` while the node reports a tip below the trigger reproduces
/// those bytes, and a different amount is still refused with nothing on the
/// socket.
#[test]
fn claim_reserved_above_the_trigger_resigns_in_its_own_form_below_it() {
    use chain::{Entitled, Staked};
    use mochimo_crypto::mesh::spend::{DustProofOp, ValidatorOp};
    let claim = ValidatorOp::Claim { amount: 1_000 };
    let id = dust_proof_id("cli-claim-v41-id", DustProofOp::Claim { amount: 1_000 }, 5_000_000);
    let chain = v41_chain(5_000_000, Staked::Nothing { block: V41_TIP });
    chain.entitles(Entitled::Amount(21_582, V41_TIP));
    chain.refuses_submit();
    let log = chain.submit_log();
    let (dir, r) = run_on_keeping("cli-claim-v41", chain, &validator(claim.clone(), false, None));
    assert_eq!(r.code, Code::Refused, "{}", r.text);
    assert_eq!(stored_index(&dir), 1, "the claim did not reserve its key");
    let artifact = p10_signed_transaction_of(&hexs(&log.borrow()[0])).unwrap_or_else(|| panic!("no artifact"));

    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.set_tip(V40_TIP);
    chain.accepts_submit(id);
    let log2 = chain.submit_log();
    let ks = reopen("cli-claim-v41", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let r2 = cli::run(ks, MeshClient::new(chain), &validator(claim, true, None));
    assert_eq!(r2.code, Code::Ok, "{}", r2.text);
    assert_says(&r2, "reproduced the reserved transaction, byte for byte", "claim --resign below the trigger");
    assert_eq!(p10_signed_transaction_of(&hexs(&log2.borrow()[0])).as_deref(), Some(artifact.as_str()));

    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.set_tip(V40_TIP);
    let log3 = chain.submit_log();
    let ks = reopen("cli-claim-v41", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let r3 = cli::run(ks, MeshClient::new(chain), &validator(ValidatorOp::Claim { amount: 999 }, true, None));
    assert_eq!(r3.code, Code::Refused, "{}", r3.text);
    assert_says(&r3, "this is not the spend that was reserved", "claim --resign below the trigger, another amount");
    assert!(log3.borrow().is_empty(), "a different claim reached the socket");
}

/// A dust-proof claim may take its fee from the principal it releases, so
/// it can be reserved with a spendable balance below the fee, where the
/// v4.0 form cannot be built. `--resign` with another amount says it is not
/// the reserved spend rather than that the balance is short, and `--resign`
/// with the same amount below the trigger reproduces the bytes.
#[test]
fn a_claim_with_its_fee_from_the_principal_resigns_and_refuses_as_not_reserved() {
    use chain::{Entitled, Staked};
    use mochimo_crypto::mesh::spend::{DustProofOp, ValidatorOp};
    let t41 = mochimo_crypto::staking::MAINNET_T41;
    let ended = Staked::Stake { staked: 500 * MCM, commit: t41 - 65_600, expiry: t41, entitlement: 42_000, block: V41_TIP };
    let spendable = MFEE - 200;
    let claim = ValidatorOp::Claim { amount: 1_000 };
    let id = dust_proof_id("cli-claim-principal-id", DustProofOp::Claim { amount: 1_000 }, spendable);
    let chain = v41_chain(spendable, ended);
    chain.refuses_submit();
    let log = chain.submit_log();
    let (dir, r) = run_on_keeping("cli-claim-principal", chain, &validator(claim.clone(), false, None));
    assert_eq!(r.code, Code::Refused, "{}", r.text);
    assert_eq!(stored_index(&dir), 1, "the claim did not reserve its key");
    let artifact = p10_signed_transaction_of(&hexs(&log.borrow()[0])).unwrap_or_else(|| panic!("no artifact"));

    let chain = v41_chain(spendable, ended);
    chain.entitles(Entitled::Amount(42_000, V41_TIP));
    let log2 = chain.submit_log();
    let ks = reopen("cli-claim-principal", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let r2 = cli::run(ks, MeshClient::new(chain), &validator(ValidatorOp::Claim { amount: 999 }, true, None));
    assert_eq!(r2.code, Code::Refused, "{}", r2.text);
    assert_says(&r2, "this is not the spend that was reserved", "claim --resign, another amount");
    assert!(log2.borrow().is_empty(), "a different claim reached the socket");

    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), spendable))]);
    chain.set_tip(V40_TIP);
    chain.accepts_submit(id);
    let log3 = chain.submit_log();
    let ks = reopen("cli-claim-principal", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let r3 = cli::run(ks, MeshClient::new(chain), &validator(claim, true, None));
    assert_eq!(r3.code, Code::Ok, "{}", r3.text);
    assert_says(&r3, "reproduced the reserved transaction, byte for byte", "claim --resign below the trigger");
    assert_eq!(p10_signed_transaction_of(&hexs(&log3.borrow()[0])).as_deref(), Some(artifact.as_str()));
}

/// A resign built without the parser, with an expected balance, is refused
/// before anything is signed: for `resign` and for a validator verb's
/// `--resign`, each over a reservation it would otherwise reproduce.
#[test]
fn a_resign_with_an_expected_balance_is_refused_at_the_library_boundary() {
    use mochimo_crypto::mesh::spend::ValidatorOp;
    let (dir, _artifact) = send_that_never_left("cli-resign-expect");
    let mut s = spend();
    s.expect_balance = Some(5_000_000);
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    let log = chain.submit_log();
    let ks = reopen("cli-resign-expect", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let r = cli::run(ks, MeshClient::new(chain), &Command::Resign(s));
    assert_eq!(r.code, Code::Refused, "{}", r.text);
    assert_says(&r, "an expected balance applies to a new signature", "resign with an expected balance");
    assert!(log.borrow().is_empty(), "a refused resign reached the socket");

    let claim = ValidatorOp::Claim { amount: 1_000 };
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.set_tip(V40_TIP);
    chain.entitles(chain::Entitled::Amount(21_582, V40_TIP));
    chain.refuses_submit();
    let (dir, r) = run_on_keeping("cli-claim-resign-expect", chain, &validator(claim.clone(), false, None));
    assert_eq!(r.code, Code::Refused, "{}", r.text);
    assert_eq!(stored_index(&dir), 1, "the claim did not reserve its key");
    let mut cmd = validator(claim, true, None);
    if let Command::Validator(v) = &mut cmd {
        v.expect_balance = Some(5_000_000);
    }
    for tip in [V40_TIP, V41_TIP] {
        let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
        chain.set_tip(tip);
        let log = chain.submit_log();
        let ks = reopen("cli-claim-resign-expect", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
        let r = cli::run(ks, MeshClient::new(chain), &cmd);
        assert_eq!(r.code, Code::Refused, "{}", r.text);
        assert_says(&r, "an expected balance applies to a new signature", "claim --resign with an expected balance");
        assert!(log.borrow().is_empty(), "a refused claim resign reached the socket");
    }
}

/// What `claim` refuses before the key is reserved: an amount above the
/// endpoint's entitlement, an amount above a supplied one, and a
/// rate-limited endpoint, whose page says to wait. Each leaves the stored
/// position at 0 and the socket untouched.
#[test]
fn claim_refuses_above_the_entitlement_and_under_a_rate_limit_before_reserving() {
    use chain::Entitled;
    use mochimo_crypto::mesh::spend::ValidatorOp;
    let cases: [(Entitled, Option<u64>, u64, &str); 3] = [
        (Entitled::Amount(999, 7), None, 1_000, "above the entitlement of 999 nanoMCM"),
        (Entitled::Amount(10_000, 7), Some(500), 1_000, "above the entitlement of 500 nanoMCM"),
        (Entitled::RateLimited(Some(10)), None, 1_000, "asks for 10 second(s) before the next one"),
    ];
    for (n, (answer, supplied, amount, why)) in cases.into_iter().enumerate() {
        let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
        chain.set_tip(V40_TIP);
        chain.entitles(answer);
        let log = chain.submit_log();
        let (dir, r) = run_on_keeping(&format!("cli-claim-refused-{n}"), chain, &validator(ValidatorOp::Claim { amount }, false, supplied));
        assert_eq!(r.code, Code::Refused, "{}", r.text);
        assert_says(&r, why, "a refused claim");
        assert!(log.borrow().is_empty());
        assert_eq!(stored_index(&dir), 0, "a refused claim reserved a key");
    }
    println!("  claim refusals: over the endpoint's figure, over a supplied one, rate-limited -- none reserved");
}

/// `set-delegate` and `clear-delegate` through the command layer: the
/// delegate's requirements the node checks after signing are on the page;
/// naming the validator's own tag is refused before anything is reserved.
#[test]
fn set_and_clear_delegate_sign_and_name_what_only_the_node_can_check() {
    use mochimo_crypto::mesh::spend::ValidatorOp;
    let set = ValidatorOp::SetDelegate { delegate: TO };
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.set_tip(V40_TIP);
    chain.accepts_submit(validator_id("cli-set-delegate-id", set.clone(), 5_000_000));
    let r = run_on("cli-set-delegate", chain, &validator(set, false, None));
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    assert_says(&r, "set-delegate: bind", "set-delegate");
    assert_says(&r, "at least 1000000000 nanoMCM, no validator slot of its own", "set-delegate");

    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.set_tip(V40_TIP);
    chain.accepts_submit(validator_id("cli-clear-delegate-id", ValidatorOp::ClearDelegate, 5_000_000));
    let r = run_on("cli-clear-delegate", chain, &validator(ValidatorOp::ClearDelegate, false, None));
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    assert_says(&r, "clear-delegate: clear this validator's delegate binding", "clear-delegate");

    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.set_tip(V40_TIP);
    let (dir, r) = run_on_keeping("cli-set-self", chain, &validator(ValidatorOp::SetDelegate { delegate: TAG }, false, None));
    assert_eq!(r.code, Code::Refused, "{}", r.text);
    assert_says(&r, "EMCM_DELEGATE_IS_SELF", "set-delegate to itself");
    assert_eq!(stored_index(&dir), 0);
}

/// `entitlement <tag>`: the endpoint's figure and block, or a supplied one
/// marked unchecked, with the spendable balance and whether it covers a
/// claim's fee; a rate limit is a refusal naming the wait. Read only.
#[test]
fn the_entitlement_verb_reads_the_figure_and_the_balance_its_fee_needs() {
    use chain::Entitled;
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 499))]);
    chain.entitles(Entitled::Amount(21_582_964_000_000, 1_124_001));
    let r = cli::run_explorer(&MeshClient::new(chain), &Command::Entitlement { tag: TAG, supplied: None });
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    assert_says(&r, "entitlement 21582964000000 nanoMCM, from /account/entitlement at block 1124001", "entitlement");
    assert_says(&r, "balance     499 nanoMCM spendable", "entitlement");
    assert_says(&r, "cannot be paid from that balance", "entitlement");

    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000))]);
    let calls = chain.entitlement_calls();
    let r = cli::run_explorer(&MeshClient::new(chain), &Command::Entitlement { tag: TAG, supplied: Some(42) });
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    assert_says(&r, "AS SUPPLIED", "entitlement --supplied");
    assert_eq!(calls.get(), 0, "a supplied figure asked the endpoint");

    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000))]);
    chain.entitles(Entitled::RateLimited(Some(10)));
    let r = cli::run_explorer(&MeshClient::new(chain), &Command::Entitlement { tag: TAG, supplied: None });
    assert_eq!(r.code, Code::Refused, "{}", r.text);
    assert_says(&r, "asks for 10 second(s)", "entitlement, rate-limited");
}

/// `import --sdk` through the command layer, with the SDK master seed
/// handed in as the binary hands it in: the account is stored as an SDK
/// account at the chain's position and the page names the destination.
#[test]
fn import_stores_an_sdk_account_at_the_chains_position() {
    let sdk_master = mochimo_crypto::Secret::new([0x5c; 32]);
    let seed = mochimo_crypto::derive::sdk_account_seed(&sdk_master, 2);
    let tag = mochimo_crypto::derive::sdk_account_tag(&seed);
    let chain = Chain::new(&[(tag, ChainState::At(mochimo_crypto::recon::sdk_address_at(&seed, mochimo_crypto::account::WotsIndex::ZERO), 900))]);
    let (dir, ks) = store("cli-import");
    let r = cli::run_import(ks, MeshClient::new(chain), &sdk_master, 2, None);
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    assert_says(&r, "imported SDK account 2", "import");
    assert_says(&r, "index    0 (from the chain", "import");
    let ks = reopen("cli-import", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let v = ks.view(&tag).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("not stored"));
    assert_eq!(v.kind, mochimo_crypto::account::AccountKind::Sdk);
}

/// `import --extension-export <path> --tag <tag>` through argv and the
/// command layer: the tag in either accepted form, `--account` refused with
/// it, and the page naming what was checked and saying the master seed
/// stayed in memory. A wrong password is refused with nothing written.
#[test]
fn import_from_an_extension_export_parses_runs_and_refuses_a_wrong_password() {
    let ext_master = mochimo_crypto::Secret::new([0x23; 32]);
    let tag = mochimo_crypto::derive::derive_account_tag(&ext_master, 1);
    let b58 = mochimo_crypto::addr::tag_to_base58(&tag).unwrap_or_else(|e| panic!("{e}"));
    for form in [b58.clone(), prefixed(&tag)] {
        assert_eq!(
            parsed(&["--dir", "d", "--node", "https://n", "import", "--extension-export", "e.json", "--tag", &form]),
            Ok(Command::Import(args::ImportFrom::ExtensionExport { path: "e.json".into(), tag, scan_to: None }))
        );
    }
    assert!(parsed(&["--dir", "d", "--node", "https://n", "import", "--extension-export", "e.json", "--tag", &b58, "--account", "1"])
        .is_err_and(|u| u.0.contains("selects the account by --tag")));
    assert!(parsed(&["--dir", "d", "--node", "https://n", "import", "--extension-export", "e.json"])
        .is_err_and(|u| u.0.contains("needs --tag")));
    assert!(parsed(&["--dir", "d", "--node", "https://n", "import", "--sdk", "--extension-export", "e.json", "--tag", &b58])
        .is_err_and(|u| u.0.contains("exactly one source")));

    let text = extension_export::export(&ext_master, extension_export::PASSWORD, &[extension_export::record(&ext_master, 1, -1)]);
    let first = mochimo_crypto::derive::derive_account(&ext_master, 1).first_key().implicit_address();
    let chain = || Chain::new(&[(tag, ChainState::At(first, 900))]);

    let (dir, ks) = store("cli-ext-import-wrong");
    let r = cli::run_import_extension(ks, MeshClient::new(chain()), &text, b"not the password", &tag, None);
    assert_eq!(r.code, Code::Refused, "{}", r.text);
    assert_says(&r, "the password is not the one the export was made with", "a wrong export password");
    assert_says(&r, "nothing the export decrypted to was written anywhere", "a wrong export password");
    let ks = reopen("cli-ext-import-wrong", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    assert!(ks.view(&tag).unwrap_or_else(|e| panic!("{e}")).is_none());

    let (dir, ks) = store("cli-ext-import");
    let r = cli::run_import_extension(ks, MeshClient::new(chain()), &text, extension_export::PASSWORD.as_bytes(), &tag, None);
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    assert_says(&r, "imported the export's account 1", "import --extension-export");
    assert_says(&r, &format!("destination  {b58}"), "import --extension-export");
    assert_says(&r, "index    0 (from the chain", "import --extension-export");
    assert_says(&r, "the master seed and the decrypted export were held in memory only", "import --extension-export");
    let ks = reopen("cli-ext-import", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let v = ks.view(&tag).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("not stored"));
    assert_eq!(v.kind, mochimo_crypto::account::AccountKind::Imported);
}

// ---- the v4.1 staking verbs ----------------------------------------------------

/// A tip above the mainnet v4.1 trigger: the next block is 101 heights in,
/// where the minimum stake is still 500 MCM.
const V41_TIP: u64 = mochimo_crypto::staking::MAINNET_T41 + 100;
const MCM: u64 = 1_000_000_000;

fn staking(action: args::StakingAction, resign: bool, forfeit: bool, unbound: bool) -> Command {
    Command::Staking(args::StakingTx {
        tag: TAG,
        action,
        fee_total: MFEE,
        blk_to_live: 0,
        resign,
        network: mochimo_crypto::staking::Network::MAINNET,
        forfeit,
        lock_ends: None,
        no_live_consent: false,
        not_staked: false,
        unbound_delegate: unbound,
        entitlement: None,
    })
}

/// `cmd` with its staking parameters changed by `f`.
fn with(cmd: Command, f: impl FnOnce(&mut args::StakingTx)) -> Command {
    match cmd {
        Command::Staking(mut s) => {
            f(&mut s);
            Command::Staking(s)
        }
        other => other,
    }
}

/// A `stake` whose operator states the tag holds no live consent.
fn stake_cmd(amount: u64, tier: u8, resign: bool) -> Command {
    with(staking(args::StakingAction::Stake { amount, tier }, resign, false, false), |s| s.no_live_consent = true)
}

/// A chain holding `TAG` at position 0 with `balance` spendable, its tip
/// above the trigger, and `/account/balance` reporting `staked`.
fn v41_chain(balance: u64, staked: chain::Staked) -> Chain {
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), balance))]);
    chain.set_tip(V41_TIP);
    chain.stakes(TAG, staked);
    chain
}

/// The id a dust-proof transaction from `TAG` at position 0 will have, from
/// a dry run on a throwaway store, as `validator_id` does.
fn dust_proof_id(name: &str, op: mochimo_crypto::mesh::spend::DustProofOp, balance: u64) -> [u8; 32] {
    let (_dir, ks) = store(name);
    let m = master();
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), balance))]);
    let mut w = Wallet::open(ks, MeshClient::new(chain), Some(&m)).unwrap_or_else(|e| panic!("{e}"));
    let plan = w
        .plan_dust_proof(&TAG, &KeyAccess::Master(&m), op, MFEE, 0)
        .unwrap_or_else(|e| panic!("{e}"));
    w.reserve_and_sign(&plan, KeyAccess::Master(&m)).unwrap_or_else(|e| panic!("{e}")).id().0
}

/// The staking verbs' argv, accepted and refused, and `claim all`.
#[test]
fn staking_verbs_parse_and_refuse_what_the_node_would() {
    use args::StakingAction;
    use mochimo_crypto::staking::{ConsentTerms, Network, NETWORK_TESTNET};
    let tag = prefixed(&TAG);
    let to = prefixed(&TO);
    let n = ["--dir", "d", "--node", "https://n"];
    let run = |rest: &[&str]| -> Result<Command, args::Usage> {
        let mut v: Vec<&str> = n.to_vec();
        v.extend_from_slice(rest);
        parsed(&v)
    };
    let stake = run(&["stake", &tag, "600000000000", "--tier", "2", "--fee", "700", "--no-live-consent"])
        .unwrap_or_else(|u| panic!("{}", u.0));
    assert_eq!(
        stake,
        Command::Staking(args::StakingTx {
            tag: TAG,
            action: StakingAction::Stake { amount: 600 * MCM, tier: 2 },
            fee_total: 700,
            blk_to_live: 0,
            resign: false,
            network: Network::MAINNET,
            forfeit: false,
            lock_ends: None,
            no_live_consent: true,
            not_staked: false,
            unbound_delegate: false,
            entitlement: None,
        })
    );
    let unstake = run(&["unstake", &tag, "--forfeit", "--network", "testnet", "--t41", "1024"])
        .unwrap_or_else(|u| panic!("{}", u.0));
    assert!(matches!(
        unstake,
        Command::Staking(args::StakingTx { action: StakingAction::Unstake, forfeit: true, network: Network { id: NETWORK_TESTNET, t41: 1024 }, .. })
    ));
    let unstake = run(&["unstake", &tag, "--lock-ends", "1202176"]).unwrap_or_else(|u| panic!("{}", u.0));
    assert!(matches!(
        unstake,
        Command::Staking(args::StakingTx { action: StakingAction::Unstake, forfeit: false, lock_ends: Some(1_202_176), .. })
    ));
    let accept = run(&[
        "accept", &tag, "--kind", "member-delegate", "--peer", &to, "--action", "elect", "--slot", "9", "--ip", "34.1.2.3",
        "--port", "2195", "--flags", "1", "--unbound-delegate", "--lock-ends", "1202176", "--entitlement", "0",
    ])
    .unwrap_or_else(|u| panic!("{}", u.0));
    assert_eq!(
        accept,
        Command::Staking(args::StakingTx {
            tag: TAG,
            action: StakingAction::Accept(ConsentTerms {
                kind: 2,
                peer: TO,
                action: 1,
                slot: 9,
                ip: [34, 1, 2, 3],
                port: 2195,
                flags: 1,
                network: 0xACA1,
            }),
            fee_total: MFEE,
            blk_to_live: 0,
            resign: false,
            network: Network::MAINNET,
            forfeit: false,
            lock_ends: Some(1_202_176),
            no_live_consent: false,
            not_staked: false,
            unbound_delegate: true,
            entitlement: Some(0),
        })
    );
    assert!(matches!(run(&["revoke", &tag]), Ok(Command::Staking(args::StakingTx { action: StakingAction::Revoke, .. }))));
    assert_eq!(run(&["stake-info"]), Ok(Command::StakeInfo { tag: None, network: Network::MAINNET }));
    assert_eq!(run(&["stake-info", &tag]), Ok(Command::StakeInfo { tag: Some(TAG), network: Network::MAINNET }));
    assert!(matches!(
        run(&["claim", &tag, "all"]),
        Ok(Command::Validator(args::ValidatorTx { op: mochimo_crypto::mesh::spend::ValidatorOp::Claim { amount: u64::MAX }, .. }))
    ));
    for (rest, why) in [
        (vec!["stake", tag.as_str(), "600000000000"], "stake needs --tier"),
        (vec!["stake", tag.as_str(), "600000000000", "--tier", "6"], "tiers run 0 to 5"),
        (vec!["stake", tag.as_str(), "0", "--tier", "1"], "an amount of zero"),
        (vec!["stake", tag.as_str(), "--tier", "1"], "stake needs <tag> <amount>"),
        (vec!["unstake", tag.as_str(), "--tier", "1"], "unexpected argument `--tier`"),
        (vec!["accept", tag.as_str(), "--peer", to.as_str()], "accept needs --kind"),
        (vec!["accept", tag.as_str(), "--kind", "5", "--peer", to.as_str()], "--kind 5"),
        (vec!["accept", tag.as_str(), "--kind", "1"], "accept needs --peer"),
        (vec!["accept", tag.as_str(), "--kind", "2", "--peer", to.as_str(), "--ip", "1.2.3"], "a dotted quad"),
        (vec!["revoke", tag.as_str(), "--forfeit"], "unexpected argument `--forfeit`"),
        (vec!["unstake", tag.as_str(), "--no-live-consent"], "unexpected argument `--no-live-consent`"),
        (vec!["stake", tag.as_str(), "600000000000", "--tier", "1", "--lock-ends", "5"], "unexpected argument `--lock-ends`"),
        (vec!["unstake", tag.as_str(), "--lock-ends", "5", "--forfeit"], "--forfeit and --lock-ends cannot be given together"),
        (vec!["unstake", tag.as_str(), "--not-staked"], "unexpected argument `--not-staked`"),
        (
            vec!["accept", tag.as_str(), "--kind", "1", "--peer", to.as_str(), "--forfeit", "--not-staked"],
            "--forfeit and --not-staked cannot be given together",
        ),
        (
            vec!["accept", tag.as_str(), "--kind", "1", "--peer", to.as_str(), "--not-staked", "--lock-ends", "5"],
            "--lock-ends and --not-staked cannot be given together",
        ),
        (vec!["unstake", tag.as_str(), "--network", "testnet"], "needs --t41"),
        (vec!["unstake", tag.as_str(), "--network", "testnet", "--t41", "1000"], "a multiple of 256"),
        (vec!["unstake", tag.as_str(), "--t41", "1024"], "mainnet's trigger is 1136384"),
        (vec!["stake-info", "--network", "devnet"], "mainnet or testnet"),
    ] {
        match run(&rest) {
            Err(u) => assert!(u.0.contains(why), "{rest:?}: {}", u.0),
            Ok(c) => panic!("{rest:?} parsed as {c:?}"),
        }
    }
    assert!(matches!(
        run(&["accept", &tag, "--kind", "1", "--peer", &to, "--not-staked"]),
        Ok(Command::Staking(args::StakingTx { not_staked: true, forfeit: false, lock_ends: None, .. }))
    ));
    assert!(Command::StakeInfo { tag: None, network: Network::MAINNET }.opens_no_store());
    println!("  staking verbs: 10 argv forms parsed, 20 refused");
}

/// `stake` end to end through the command layer. Above the trigger, a
/// tag with no stake and no entitlement stakes 500 MCM at tier 2: the page
/// names the coefficient, the minimum at the next height and the lock end;
/// the socket receives the artifact, which is the dust-proof form (send and
/// change zero) carrying `MSTAKE` with the mainnet network id; `--resign`
/// reproduces the same bytes.
#[test]
fn stake_checks_the_rules_shows_the_lock_signs_and_resigns() {
    use chain::{Entitled, Staked};
    use mochimo_crypto::mesh::spend::DustProofOp;
    let amount = 500 * MCM;
    let balance = 600 * MCM;
    let op = DustProofOp::Stake { amount, tier: 2, network: 0xACA1 };
    let id = dust_proof_id("cli-stake-id", op, balance);
    let chain = v41_chain(balance, Staked::Nothing { block: V41_TIP });
    chain.entitles(Entitled::Amount(0, V41_TIP));
    chain.accepts_submit(id);
    let log = chain.submit_log();
    let (dir, r) = run_on_keeping("cli-stake", chain, &stake_cmd(amount, 2, false));
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    let h = V41_TIP + 1;
    let end = mochimo_crypto::staking::expiry(h, 2).unwrap_or_else(|| panic!("no expiry"));
    for needle in [
        "stake: lock 500000000000 nanoMCM (500.000000000 MCM) at tier 2, coefficient 3x",
        &format!("minimum   500000000000 nanoMCM (500.000000000 MCM) at height {h}"),
        &format!("locked until height {end}"),
        "FORFEITS the whole entitlement",
        "Dust-proof form",
        "network id 0xaca1",
        "RETRY ARTIFACT",
    ] {
        assert_says(&r, needle, "stake");
    }
    let bodies = log.borrow().clone();
    assert_eq!(bodies.len(), 1);
    let artifact = p10_signed_transaction_of(&hexs(&bodies[0])).unwrap_or_else(|| panic!("no artifact"));
    assert!(r.text.contains(&artifact), "the page does not carry the artifact the socket got");
    let wire = bytes_of(&artifact);
    assert_eq!(wire[0], 0x0C, "options[0] is TXDAT_STAKE");
    assert_eq!(&wire[84..100], &[0u8; 16], "send and change are zero: the dust-proof form");
    assert_eq!(&wire[116..124], &amount.to_le_bytes(), "MSTAKE.amount");
    assert_eq!(&wire[124..127], &[2, 0xA1, 0xAC], "MSTAKE.tier and network 0xACA1, little-endian");
    assert_eq!(stored_index(&dir), 1, "the stake did not reserve its key");

    let chain = v41_chain(balance, Staked::Nothing { block: V41_TIP });
    chain.entitles(Entitled::Amount(0, V41_TIP));
    chain.accepts_submit(id);
    let log2 = chain.submit_log();
    let ks = reopen("cli-stake", dir.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let r2 = cli::run(ks, MeshClient::new(chain), &stake_cmd(amount, 2, true));
    assert_eq!(r2.code, Code::Ok, "{}", r2.text);
    assert_says(&r2, "reproduced the reserved transaction, byte for byte", "stake --resign");
    assert_eq!(p10_signed_transaction_of(&hexs(&log2.borrow()[0])).as_deref(), Some(artifact.as_str()));
    println!("  stake: rules checked, lock {h}..{end} shown, dust-proof artifact shipped, resign byte-identical");
}

/// What `stake` refuses before the key is reserved: below the trigger, below
/// the minimum, a stake already held, unclaimed entitlement, an unreadable
/// entitlement, a middleware with no stake fields, a stake the spendable
/// balance cannot cover with its fee, and one that would leave less than a
/// fee spendable. Each leaves the position at 0 and the socket untouched.
#[test]
fn stake_refuses_before_reserving_whatever_would_be_refused_or_bind_nothing() {
    use chain::{Entitled, Staked};
    let t41 = mochimo_crypto::staking::MAINNET_T41;
    // (tip, spendable balance, the stake reported, the entitlement answer,
    // the amount asked for, what the refusal must say)
    type Case = (u64, u64, Staked, Option<Entitled>, u64, &'static str);
    let cases: [Case; 12] = [
        (t41 - 1, 600 * MCM, Staked::Nothing { block: 1 }, Some(Entitled::Amount(0, 1)), 500 * MCM, "does not run the v4.1 rules"),
        // The next block runs the v4.1 rules, but the node checks a new
        // transaction against the tip, which does not.
        (t41, 600 * MCM, Staked::Nothing { block: t41 }, Some(Entitled::Amount(0, 1)), 500 * MCM, "the tip, height 1136384"),
        // The minimum steps down at the next height; the node checks the
        // tip's.
        (
            t41 + 65_535,
            600 * MCM,
            Staked::Nothing { block: t41 + 65_535 },
            Some(Entitled::Amount(0, 1)),
            495 * MCM,
            "below the minimum stake at height 1201919",
        ),
        (V41_TIP, 600 * MCM, Staked::Cached { block: V41_TIP - 15 }, Some(Entitled::Amount(0, 1)), 500 * MCM, "ledger cache"),
        (
            V41_TIP,
            600 * MCM,
            Staked::Consent { kind: 4, height: V41_TIP - 10, block: V41_TIP },
            Some(Entitled::Amount(0, 1)),
            500 * MCM,
            "holds a consent of kind 4 that lapses at height",
        ),
        (V41_TIP, 600 * MCM, Staked::Nothing { block: 1 }, Some(Entitled::Amount(0, 1)), 499 * MCM, "below the minimum stake"),
        (
            V41_TIP,
            600 * MCM,
            Staked::Stake { staked: 10 * MCM, commit: t41 + 1, expiry: t41 + 65_792, entitlement: 0, block: 1 },
            None,
            500 * MCM,
            "There are no top-ups",
        ),
        (V41_TIP, 600 * MCM, Staked::Nothing { block: 1 }, Some(Entitled::Amount(7, 1)), 500 * MCM, "unclaimed entitlement"),
        (V41_TIP, 600 * MCM, Staked::Nothing { block: 1 }, Some(Entitled::RateLimited(Some(10))), 500 * MCM, "--entitlement N supplies"),
        (V41_TIP, 600 * MCM, Staked::Unreported, Some(Entitled::Amount(0, 1)), 500 * MCM, "reports no stake fields"),
        (V41_TIP, 500 * MCM, Staked::Nothing { block: 1 }, Some(Entitled::Amount(0, 1)), 500 * MCM, "plus the fee of 500 is more than"),
        (V41_TIP, 500 * MCM + 600, Staked::Nothing { block: 1 }, Some(Entitled::Amount(0, 1)), 500 * MCM, "keep at least one fee spendable"),
    ];
    for (n, (tip, balance, staked, entitled, amount, why)) in cases.into_iter().enumerate() {
        let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), balance))]);
        chain.set_tip(tip);
        chain.stakes(TAG, staked);
        if let Some(e) = entitled {
            chain.entitles(e);
        }
        let log = chain.submit_log();
        let cmd = stake_cmd(amount, 0, false);
        let (dir, r) = run_on_keeping(&format!("cli-stake-refused-{n}"), chain, &cmd);
        assert_eq!(r.code, Code::Refused, "case {n}: {}", r.text);
        assert_says(&r, why, "a refused stake");
        assert_says(&r, "Nothing was reserved or signed", "a refused stake");
        assert!(log.borrow().is_empty(), "case {n} reached the socket");
        assert_eq!(stored_index(&dir), 0, "case {n} reserved a key");
    }
    println!("  stake refusals: 12 cases, none reserved");
}

/// `unstake` before the lock ends needs `--forfeit`, and the page says what
/// is forfeited; after it ends, the page says the entitlement remains to be
/// claimed. A tag with nothing staked is refused.
#[test]
fn unstake_needs_forfeit_while_locked_and_keeps_the_entitlement_after() {
    use chain::Staked;
    use mochimo_crypto::mesh::spend::DustProofOp;
    let t41 = mochimo_crypto::staking::MAINNET_T41;
    let locked = Staked::Stake { staked: 500 * MCM, commit: t41 + 1, expiry: t41 + 65_792, entitlement: 42_000, block: V41_TIP };
    let ended = Staked::Stake { staked: 500 * MCM, commit: t41 - 65_600, expiry: t41, entitlement: 42_000, block: V41_TIP };
    let op = DustProofOp::Unstake { network: 0xACA1 };

    let chain = v41_chain(MFEE, locked);
    let log = chain.submit_log();
    let (dir, r) = run_on_keeping("cli-unstake-locked", chain, &staking(args::StakingAction::Unstake, false, false, false));
    assert_eq!(r.code, Code::Refused, "{}", r.text);
    assert_says(&r, "the stake is LOCKED until height", "unstake without --forfeit");
    assert_says(&r, "FORFEITS the entitlement it has earned -- 42000 nanoMCM", "unstake without --forfeit");
    assert_says(&r, "Pass --forfeit", "unstake without --forfeit");
    assert!(log.borrow().is_empty());
    assert_eq!(stored_index(&dir), 0);

    let chain = v41_chain(MFEE, locked);
    chain.accepts_submit(dust_proof_id("cli-unstake-forfeit-id", op.clone(), MFEE));
    let r = run_on("cli-unstake-forfeit", chain, &staking(args::StakingAction::Unstake, false, true, false));
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    assert_says(&r, "is FORFEITED to the other stakers, as you confirmed with --forfeit", "unstake --forfeit");

    let chain = v41_chain(MFEE, ended);
    chain.accepts_submit(dust_proof_id("cli-unstake-ended-id", op, MFEE));
    let cmd = with(staking(args::StakingAction::Unstake, false, false, false), |s| s.lock_ends = Some(t41));
    let r = run_on("cli-unstake-ended", chain, &cmd);
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    assert_says(&r, "is NOT forfeited", "unstake after expiry");
    assert_says(&r, "`claim <tag> all`", "unstake after expiry");

    let chain = v41_chain(MFEE, Staked::Nothing { block: V41_TIP });
    let r = run_on("cli-unstake-nothing", chain, &staking(args::StakingAction::Unstake, false, true, false));
    assert_eq!(r.code, Code::Refused, "{}", r.text);
    assert_says(&r, "this tag stakes nothing", "unstake with no stake");
    println!("  unstake: locked refused without --forfeit, forfeit and expiry pages, nothing staked refused");
}

/// `claim` above the trigger is the dust-proof form: refused while the stake
/// is locked; after the lock it is signed with change zero, says it also
/// unstakes, and `all` carries `UINT64_MAX`. Below the trigger it keeps the
/// v4.0 form (tested above). An unreadable tip is refused, because the two
/// forms have different digests.
#[test]
fn claim_above_the_trigger_refuses_while_locked_and_unstakes_after() {
    use chain::Staked;
    use mochimo_crypto::mesh::spend::{DustProofOp, ValidatorOp};
    let t41 = mochimo_crypto::staking::MAINNET_T41;
    let locked = Staked::Stake { staked: 500 * MCM, commit: t41 + 1, expiry: t41 + 65_792, entitlement: 42_000, block: V41_TIP };
    let ended = Staked::Stake { staked: 500 * MCM, commit: t41 - 65_600, expiry: t41, entitlement: 42_000, block: V41_TIP };
    let all = validator(ValidatorOp::Claim { amount: u64::MAX }, false, None);

    let chain = v41_chain(MFEE, locked);
    let log = chain.submit_log();
    let (dir, r) = run_on_keeping("cli-claim-locked", chain, &all);
    assert_eq!(r.code, Code::Refused, "{}", r.text);
    assert_says(&r, "A claim while locked releases nothing", "claim while locked");
    assert!(log.borrow().is_empty());
    assert_eq!(stored_index(&dir), 0);

    let chain = v41_chain(MFEE, ended);
    chain.accepts_submit(dust_proof_id("cli-claim-ended-id", DustProofOp::Claim { amount: u64::MAX }, MFEE));
    let log = chain.submit_log();
    let r = run_on("cli-claim-ended", chain, &all);
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    assert_says(&r, "everything (UINT64_MAX", "claim all");
    assert_says(&r, "ALSO UNSTAKES", "claim after expiry");
    let wire = bytes_of(&p10_signed_transaction_of(&hexs(&log.borrow()[0])).unwrap_or_else(|| panic!("no artifact")));
    assert_eq!(wire[0], 0x06, "options[0] is TXDAT_CLAIM");
    assert_eq!(&wire[84..100], &[0u8; 16], "send and change zero: the only form a claim that unstakes may take (F5)");
    assert_eq!(&wire[116..124], &[0xff; 8], "MCLAIM.amount is UINT64_MAX");

    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), MFEE))]);
    chain.refuses_tip();
    let r = run_on("cli-claim-no-tip", chain, &all);
    assert_eq!(r.code, Code::Refused, "{}", r.text);
    assert_says(&r, "the chain tip could not be read", "claim with no tip");
    println!("  claim above the trigger: locked refused, after expiry dust-proof and unstaking, no tip refused");
}

/// A consent of a delegate kind needs `--unbound-delegate`, because it is
/// signed with a delegate key; with it, the `ACCEPT` is signed and its digest
/// is on the page. A consent naming the consenting tag itself is refused by
/// the terms check.
#[test]
fn accept_of_a_delegate_kind_needs_the_unbound_flag_and_shows_its_digest() {
    use chain::Staked;
    use mochimo_crypto::mesh::spend::DustProofOp;
    use mochimo_crypto::staking::ConsentTerms;
    let terms = ConsentTerms { kind: 1, peer: TO, ..ConsentTerms::revoke(0xACA1) };
    let accept = args::StakingAction::Accept(terms);

    let chain = v41_chain(MFEE, Staked::Nothing { block: V41_TIP });
    let (dir, r) = run_on_keeping("cli-accept-flag", chain, &staking(accept.clone(), false, false, false));
    assert_eq!(r.code, Code::Refused, "{}", r.text);
    assert_says(&r, "signed by a validator DELEGATE key", "accept kind 1 without the flag");
    assert_says(&r, "--unbound-delegate", "accept kind 1 without the flag");
    assert_eq!(stored_index(&dir), 0);

    let chain = v41_chain(MFEE, Staked::Nothing { block: V41_TIP });
    chain.entitles(chain::Entitled::Amount(0, V41_TIP));
    chain.accepts_submit(dust_proof_id("cli-accept-id", DustProofOp::Accept(terms), MFEE));
    let r = run_on("cli-accept", chain, &with(staking(accept, false, false, true), |s| s.not_staked = true));
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    assert_says(&r, "accept: consent, as delegate (kind 1)", "accept");
    assert_says(&r, &format!("digest    {}", hexs(&terms.digest(&TAG))), "accept");

    let own = ConsentTerms { kind: 4, peer: TAG, slot: 9, ip: [34, 1, 2, 3], port: 2196, ..ConsentTerms::revoke(0xACA1) };
    let chain = v41_chain(MFEE, Staked::Nothing { block: V41_TIP });
    let r = run_on("cli-accept-own", chain, &with(staking(args::StakingAction::Accept(own), false, false, false), |s| s.not_staked = true));
    assert_eq!(r.code, Code::Refused, "{}", r.text);
    assert_says(&r, "the peer is the consenting tag itself", "accept naming itself");
    println!("  accept: delegate kind refused without the flag, signed with it, own peer refused");
}

/// `stake` from a tag whose consent state the Mesh does not show needs
/// `--no-live-consent`, because the node refuses a stake from a tag holding
/// a live consent after the key has signed. A disclosed consent that has
/// lapsed needs no flag.
#[test]
fn stake_needs_the_consent_stated_unless_the_reply_shows_it() {
    use chain::{Entitled, Staked};
    use mochimo_crypto::mesh::spend::DustProofOp;
    let amount = 500 * MCM;
    let balance = 600 * MCM;
    let chain = v41_chain(balance, Staked::Nothing { block: V41_TIP });
    chain.entitles(Entitled::Amount(0, V41_TIP));
    let log = chain.submit_log();
    let cmd = staking(args::StakingAction::Stake { amount, tier: 0 }, false, false, false);
    let (dir, r) = run_on_keeping("cli-stake-consent-unknown", chain, &cmd);
    assert_eq!(r.code, Code::Refused, "{}", r.text);
    assert_says(&r, "does not show whether this tag holds a consent", "stake without the consent stated");
    assert_says(&r, "--no-live-consent", "stake without the consent stated");
    assert!(log.borrow().is_empty());
    assert_eq!(stored_index(&dir), 0);

    let op = DustProofOp::Stake { amount, tier: 0, network: 0xACA1 };
    let lapsed = V41_TIP - 70_000;
    let chain = v41_chain(balance, Staked::Consent { kind: 1, height: lapsed, block: V41_TIP });
    chain.entitles(Entitled::Amount(0, V41_TIP));
    chain.accepts_submit(dust_proof_id("cli-stake-consent-lapsed-id", op, balance));
    let r = run_on("cli-stake-consent-lapsed", chain, &cmd);
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    println!("  stake: unknown consent refused without the flag, a lapsed disclosed consent signed");
}

/// The lock is read from the node, so an `unstake` or an `accept` from a
/// staked tag whose lock has ended by that report needs `--lock-ends` with
/// the reported expiry (or `--forfeit`). A report whose expiry does not
/// follow from its commit height and tier, or that has no terms at all, is
/// refused whatever the flags.
#[test]
fn unstake_and_accept_from_a_staked_tag_rest_on_a_confirmed_lock_end() {
    use chain::Staked;
    use mochimo_crypto::staking::ConsentTerms;
    let t41 = mochimo_crypto::staking::MAINNET_T41;
    let ended = Staked::Stake { staked: 500 * MCM, commit: t41 - 65_600, expiry: t41, entitlement: 0, block: V41_TIP };
    let unstake = staking(args::StakingAction::Unstake, false, false, false);
    let terms = ConsentTerms { kind: 4, peer: TO, slot: 9, ip: [34, 1, 2, 3], port: 2196, ..ConsentTerms::revoke(0xACA1) };
    let accept = staking(args::StakingAction::Accept(terms), false, false, false);

    let refusals: [(Staked, Command, &str); 6] = [
        (ended, unstake.clone(), "--lock-ends was not given"),
        (ended, with(unstake.clone(), |s| s.lock_ends = Some(t41 + 256)), "--lock-ends 1136640 does not match it"),
        (ended, accept.clone(), "--lock-ends was not given"),
        // An expiry below the tip that no tier gives for this commit height.
        (
            Staked::Stake { staked: 500 * MCM, commit: t41 + 1, expiry: t41 + 64, entitlement: 42_000, block: V41_TIP },
            with(unstake.clone(), |s| s.lock_ends = Some(t41 + 64)),
            "does not agree with itself",
        ),
        // A tier that matches the span, but not an expiry the node computes.
        (
            Staked::Stake { staked: 500 * MCM, commit: t41 - 65_500, expiry: t41 + 64, entitlement: 42_000, block: V41_TIP },
            with(unstake.clone(), |s| s.lock_ends = Some(t41 + 64)),
            "does not agree with itself",
        ),
        (
            Staked::Untermed { staked: 500 * MCM, entitlement: 42_000, block: V41_TIP },
            with(unstake.clone(), |s| s.forfeit = true),
            "reports no commit and expiry",
        ),
    ];
    for (n, (staked, cmd, why)) in refusals.into_iter().enumerate() {
        let chain = v41_chain(MFEE, staked);
        let log = chain.submit_log();
        let (dir, r) = run_on_keeping(&format!("cli-lock-end-refused-{n}"), chain, &cmd);
        assert_eq!(r.code, Code::Refused, "case {n}: {}", r.text);
        assert_says(&r, why, "an unconfirmed lock end");
        assert_says(&r, "Nothing was reserved or signed", "an unconfirmed lock end");
        assert!(log.borrow().is_empty(), "case {n} reached the socket");
        assert_eq!(stored_index(&dir), 0, "case {n} reserved a key");
    }

    let chain = v41_chain(MFEE, ended);
    chain.accepts_submit(dust_proof_id("cli-accept-ended-id", mochimo_crypto::mesh::spend::DustProofOp::Accept(terms), MFEE));
    let r = run_on("cli-accept-ended", chain, &with(accept, |s| s.lock_ends = Some(t41)));
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    println!("  lock end: 6 refusals, accept with the confirmed expiry signed");
}

/// A consent from a tag that does not stake but holds entitlement is
/// included for its fee and binds nothing, so it is refused.
#[test]
fn accept_from_a_tag_with_entitlement_is_refused() {
    use chain::{Entitled, Staked};
    use mochimo_crypto::staking::ConsentTerms;
    let terms = ConsentTerms { kind: 4, peer: TO, slot: 9, ip: [34, 1, 2, 3], port: 2196, ..ConsentTerms::revoke(0xACA1) };
    let chain = v41_chain(MFEE, Staked::Nothing { block: V41_TIP });
    chain.entitles(Entitled::Amount(42_000, V41_TIP));
    let log = chain.submit_log();
    let cmd = with(staking(args::StakingAction::Accept(terms), false, false, false), |s| s.not_staked = true);
    let (dir, r) = run_on_keeping("cli-accept-entitled", chain, &cmd);
    assert_eq!(r.code, Code::Refused, "{}", r.text);
    assert_says(&r, "and a consent from it is included for its fee and binds nothing", "accept with entitlement");
    assert!(log.borrow().is_empty());
    assert_eq!(stored_index(&dir), 0);
    println!("  accept: a tag with unclaimed entitlement refused");
}

/// At the tip one below a stake's expiry the node still treats the stake as
/// locked, so a claim's fee must come from the spendable balance. At the
/// trigger itself a validator claim keeps the v4.0 form, which the node
/// accepts at the tip and above it.
#[test]
fn checks_use_the_tip_the_node_checks_against() {
    use chain::{Entitled, Staked};
    use mochimo_crypto::mesh::spend::ValidatorOp;
    let t41 = mochimo_crypto::staking::MAINNET_T41;
    let commit = t41 + 1_000;
    let expiry = mochimo_crypto::staking::expiry(commit, 0).unwrap_or_else(|| panic!("no expiry"));
    let ending = Staked::Stake { staked: 500 * MCM, commit, expiry, entitlement: 42_000, block: expiry - 1 };
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), MFEE - 1))]);
    chain.set_tip(expiry - 1);
    chain.stakes(TAG, ending);
    let log = chain.submit_log();
    let (dir, r) = run_on_keeping("cli-claim-at-expiry", chain, &validator(ValidatorOp::Claim { amount: u64::MAX }, false, None));
    assert_eq!(r.code, Code::Refused, "{}", r.text);
    assert_says(&r, "the fee of 500 is more than the 499 nanoMCM", "claim one block before the expiry");
    assert!(log.borrow().is_empty());
    assert_eq!(stored_index(&dir), 0);

    let claim = ValidatorOp::Claim { amount: 1_000 };
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.set_tip(t41);
    chain.entitles(Entitled::Amount(21_582, t41));
    chain.accepts_submit(validator_id("cli-claim-at-trigger-id", claim.clone(), 5_000_000));
    let log = chain.submit_log();
    let r = run_on("cli-claim-at-trigger", chain, &validator(claim, false, None));
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    let wire = bytes_of(&p10_signed_transaction_of(&hexs(&log.borrow()[0])).unwrap_or_else(|| panic!("no artifact")));
    assert_ne!(&wire[92..100], &[0u8; 8], "the v4.0 form carries the change");
    println!("  tip: a claim one block before the expiry pays its fee from the spendable balance; v4.0 form at the trigger");
}

/// A block can land between the tip read and `/account/balance`. The
/// reply's lock state is checked at the height after the reply's own tip,
/// so a true report is not refused; the lock that decides a forfeit is read
/// at the lower of the two tips, so the stake still counts as locked.
#[test]
fn a_block_between_the_two_reads_does_not_refuse_a_true_report() {
    use chain::Staked;
    use mochimo_crypto::mesh::spend::DustProofOp;
    let commit = mochimo_crypto::staking::MAINNET_T41 + 1_000;
    let expiry = mochimo_crypto::staking::expiry(commit, 0).unwrap_or_else(|| panic!("no expiry"));
    let stake = Staked::Stake { staked: 500 * MCM, commit, expiry, entitlement: 42_000, block: expiry - 1 };
    let straddling = || {
        let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), MFEE))]);
        chain.set_tip(expiry - 2);
        chain.balance_at(expiry - 1);
        chain.stakes(TAG, stake);
        chain
    };
    let unstake = staking(args::StakingAction::Unstake, false, false, false);

    let chain = straddling();
    chain.accepts_submit(dust_proof_id("cli-unstake-straddle-id", DustProofOp::Unstake { network: 0xACA1 }, MFEE));
    let r = run_on("cli-unstake-straddle", chain, &with(unstake.clone(), |s| s.forfeit = true));
    assert_eq!(r.code, Code::Ok, "{}", r.text);

    let chain = straddling();
    let log = chain.submit_log();
    let (dir, r) = run_on_keeping("cli-unstake-straddle-ends", chain, &with(unstake, |s| s.lock_ends = Some(expiry)));
    assert_eq!(r.code, Code::Refused, "{}", r.text);
    assert_says(&r, &format!("the stake is LOCKED until height {expiry}"), "unstake across a block");
    assert!(log.borrow().is_empty());
    assert_eq!(stored_index(&dir), 0);
    println!("  two reads across a block: the true report signs with --forfeit, the lock still holds");
}

/// The node's report that a tag does not stake is the wallet's only view of
/// it, and a consent from a locked staker forfeits its entitlement, so an
/// `accept` from such a tag needs `--not-staked` or `--forfeit`.
#[test]
fn accept_from_a_tag_reported_unstaked_needs_it_stated() {
    use chain::{Entitled, Staked};
    use mochimo_crypto::mesh::spend::DustProofOp;
    use mochimo_crypto::staking::ConsentTerms;
    let terms = ConsentTerms { kind: 4, peer: TO, slot: 9, ip: [34, 1, 2, 3], port: 2196, ..ConsentTerms::revoke(0xACA1) };
    let accept = staking(args::StakingAction::Accept(terms), false, false, false);

    let chain = v41_chain(MFEE, Staked::Nothing { block: V41_TIP });
    chain.entitles(Entitled::Amount(0, V41_TIP));
    let log = chain.submit_log();
    let (dir, r) = run_on_keeping("cli-accept-unstated", chain, &accept);
    assert_eq!(r.code, Code::Refused, "{}", r.text);
    assert_says(&r, "the node reports that this tag does not stake", "accept without --not-staked");
    assert_says(&r, "Pass --not-staked", "accept without --not-staked");
    assert!(log.borrow().is_empty());
    assert_eq!(stored_index(&dir), 0);

    let chain = v41_chain(MFEE, Staked::Nothing { block: V41_TIP });
    chain.entitles(Entitled::Amount(0, V41_TIP));
    chain.accepts_submit(dust_proof_id("cli-accept-forfeit-id", DustProofOp::Accept(terms), MFEE));
    let r = run_on("cli-accept-forfeit", chain, &with(accept, |s| s.forfeit = true));
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    println!("  accept from a tag reported unstaked: refused unstated, signed with --forfeit");
}

/// A stake whose consent state rests on `--no-live-consent` is refused with
/// a block to live: if a consent is live the node refuses the stake, and an
/// expired reservation would leave the key nothing it could sign.
#[test]
fn stake_with_an_unshown_consent_refuses_a_block_to_live() {
    use chain::{Entitled, Staked};
    let chain = v41_chain(600 * MCM, Staked::Nothing { block: V41_TIP });
    chain.entitles(Entitled::Amount(0, V41_TIP));
    let log = chain.submit_log();
    let cmd = with(stake_cmd(500 * MCM, 1, false), |s| s.blk_to_live = 50);
    let (dir, r) = run_on_keeping("cli-stake-btl-unknown-consent", chain, &cmd);
    assert_eq!(r.code, Code::Refused, "{}", r.text);
    assert_says(&r, "--btl 50 is refused while the Mesh does not show", "stake --btl with an unshown consent");
    assert!(log.borrow().is_empty());
    assert_eq!(stored_index(&dir), 0);

    let lapsed = V41_TIP - 70_000;
    let chain = v41_chain(600 * MCM, Staked::Consent { kind: 1, height: lapsed, block: V41_TIP });
    chain.entitles(Entitled::Amount(0, V41_TIP));
    let client = MeshClient::new(chain);
    let s = match with(staking(args::StakingAction::Stake { amount: 500 * MCM, tier: 1 }, false, false, false), |s| s.blk_to_live = 50) {
        Command::Staking(s) => s,
        other => panic!("{other:?}"),
    };
    assert!(cli::staking::checked(&client, &s).is_ok(), "a disclosed, lapsed consent allows a block to live");
    println!("  stake --btl: refused on the operator's statement, allowed on a disclosed lapsed consent");
}

/// `stake-info` shows the tag's lock, coefficient and entitlement, and the
/// minimum stake and its schedule; if `/stats/staking` is refused (HTTP 403)
/// that is reported in its place and the rest is still shown.
#[test]
fn stake_info_shows_the_stake_and_survives_a_refused_stats_endpoint() {
    use chain::{Staked, StakingStatsAnswer};
    use mochimo_crypto::staking::Network;
    let t41 = mochimo_crypto::staking::MAINNET_T41;
    let stake = Staked::Stake { staked: 500 * MCM, commit: t41 + 1, expiry: t41 + 65_792, entitlement: 42_000, block: V41_TIP };
    let chain = v41_chain(7 * MCM, stake);
    chain.reports_staking(StakingStatsAnswer::Forbidden);
    let r = cli::run_explorer(&MeshClient::new(chain), &Command::StakeInfo { tag: Some(TAG), network: Network::MAINNET });
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    for needle in [
        "spendable 7000000000 nanoMCM (7.000000000 MCM)",
        "staked    500000000000 nanoMCM (500.000000000 MCM)",
        "entitled  42000 nanoMCM",
        "tier      0, coefficient 1x",
        "-- LOCKED, 65691 heights to go",
        "minimum   500000000000 nanoMCM (500.000000000 MCM) for a stake in the next block",
        &format!("next to 490000000000 nanoMCM (490.000000000 MCM) at height {}", t41 + 65_536),
        "/stats/staking refused with HTTP 403",
        "Read only",
    ] {
        assert_says(&r, needle, "stake-info");
    }

    let chain = Chain::new(&[]);
    chain.set_tip(V41_TIP);
    chain.reports_staking(StakingStatsAnswer::At { tip: V41_TIP });
    let r = cli::run_explorer(&MeshClient::new(chain), &Command::StakeInfo { tag: None, network: Network::MAINNET });
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    assert_says(&r, "staked    1200000000000 nanoMCM (1200.000000000 MCM) by 2 staker(s)", "stake-info network");
    assert_says(&r, "pool      2500000000 nanoMCM (2.500000000 MCM) to 2 staker(s)", "stake-info network");
    println!("  stake-info: account view, schedule, 403 survived; network totals and pool");
}

/// `balance` labels every figure spendable and says where staked coins and
/// entitlement are shown, since neither is included.
#[test]
fn balance_says_its_figures_are_spendable_only() {
    let r = run_on("cli-balance-spendable", Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]), &Command::Balance);
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    assert_says(&r, "5000000 nanoMCM spendable", "balance");
    assert_says(&r, "`stake-info <tag>` shows them", "balance");
}

/// `set-delegate` and `clear-delegate` above the trigger are the dust-proof
/// form (send and change zero) and need no stake fields, since a cold
/// address cannot stake. The page says the binding takes effect only with
/// the delegate's consent.
#[test]
fn delegate_changes_above_the_trigger_are_dust_proof_and_need_no_stake_fields() {
    use mochimo_crypto::mesh::spend::{DustProofOp, ValidatorOp};
    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.set_tip(V41_TIP);
    chain.accepts_submit(dust_proof_id("cli-sdlg-v41-id", DustProofOp::SetDelegate { delegate: TO }, 5_000_000));
    let log = chain.submit_log();
    let r = run_on("cli-sdlg-v41", chain, &validator(ValidatorOp::SetDelegate { delegate: TO }, false, None));
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    assert_says(&r, "set-delegate (v4.1 dust-proof form)", "set-delegate above the trigger");
    assert_says(&r, "live kind-1 consent naming this cold tag", "set-delegate above the trigger");
    let wire = bytes_of(&p10_signed_transaction_of(&hexs(&log.borrow()[0])).unwrap_or_else(|| panic!("no artifact")));
    assert_eq!((wire[0], &wire[84..100]), (0x01, &[0u8; 16][..]), "TXDAT_SET_DELEGATE with send and change zero");

    let chain = Chain::new(&[(TAG, ChainState::At(addr_at(0), 5_000_000))]);
    chain.set_tip(V41_TIP);
    chain.accepts_submit(dust_proof_id("cli-cdlg-v41-id", DustProofOp::ClearDelegate, 5_000_000));
    let r = run_on("cli-cdlg-v41", chain, &validator(ValidatorOp::ClearDelegate, false, None));
    assert_eq!(r.code, Code::Ok, "{}", r.text);
    assert_says(&r, "clear-delegate (v4.1 dust-proof form)", "clear-delegate above the trigger");
}
