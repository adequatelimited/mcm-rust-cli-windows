// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! Command-line argument parsing, without a parser dependency.
//!
//! Exit code 1 means argv did not parse. There is no generated help, no shell
//! completion and no `--flag=value` spelling (only `--flag value`).
//!
//! # Panic-freedom
//!
//! The parser does not index a slice, unwrap or assert. Every read goes
//! through `Iterator::next` or `str::strip_prefix` and every conversion
//! returns `Result`, so no argv can make it panic.

use crate::addr::Tag;
use crate::consts::{ADDR_REF_LEN, ADDR_TAG_LEN, HASHLEN, MFEE};

/// Where the store is, which node to ask, and what to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invocation {
    pub dir: String,
    /// The `--node` URL. [`parse`] refuses a command that
    /// [`Command::needs_node`] without one, so `None` occurs only for
    /// `create` and `address`.
    pub node: Option<String>,
    pub command: Command,
}

/// One command, with its arguments already in the types the wallet takes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// Make a keystore and add account 0. Runs without a `Wallet`: it signs
    /// nothing, so it works before the account is funded.
    Create {
        /// Read an existing recovery phrase instead of generating one, so a
        /// wallet can be restored on a new machine.
        from_phrase: bool,
    },
    /// Every account, as reconciliation found it.
    Balance,
    /// Where to receive. With a tag, the address that tag will next present;
    /// without one, every account in the store (needs neither a node nor the
    /// master seed). With `--account N` (exclusive with a tag), the
    /// position-0 address of account N derived from the store's master and
    /// not stored, so an account can be funded before `restore --account N`
    /// adds it.
    Address { tag: Option<Tag>, account: Option<u32> },
    /// Lay out, reserve, sign, print the artifact, submit.
    Send(Spend),
    /// Settle a reservation if the chain shows the change key.
    Settle { tag: Tag },
    /// Reproduce a lost retry artifact and submit it. Takes the whole spend
    /// again; see [`Spend`].
    Resign(Spend),
    /// Advance past a divergence the operator has read, to an index the
    /// chain confirms: the walk covers `0..=advance_to` and the advance
    /// happens only if the live report names exactly that index.
    Reconcile { tag: Tag, advance_to: u32 },
    /// Roll back past a divergence the operator has read, to an index the
    /// chain confirms behind the local index: the walk covers
    /// `0..=rollback_to` and the rollback happens only if the live report
    /// names exactly that index.
    Rollback { tag: Tag, rollback_to: u32 },
    /// Derive an account, find its index on the chain, add it to the store.
    /// `scan_to` walks indices `0..=scan_to` instead of the default
    /// `0..=9999` (`recon::RECOVERY_CEILING`).
    Restore { account: u32, scan_to: Option<u32> },
    /// Reconcile one account now and report a divergence rather than refuse.
    /// `scan_to` widens the search as it does for `restore`.
    Status { tag: Tag, scan_to: Option<u32> },
    /// Write a saved artifact (the hex `send` printed) to the socket as it
    /// is. Opens no store, asks no password, reserves and signs nothing, so it
    /// works for an emptied account the Mesh no longer resolves. The hex is
    /// decoded by the command, so a bad artifact is a refusal (exit 3) rather
    /// than a usage error.
    Submit { artifact: String },
    /// One transaction, read from the Mesh's indexer by its hash
    /// (`/search/transactions`). Read-only: opens no store, asks no
    /// password, writes nothing.
    ///
    /// Not named `Transaction`: the signature-type scan matches type names
    /// across the crate, and `tx::wire::Transaction` holds a signature.
    LookupTransaction { hash: [u8; HASHLEN] },
    /// The newest transactions that touched a tag, newest first
    /// (`/search/transactions` by account). `count` is the endpoint's
    /// `limit`, and `from` its `offset`: how many of the newest to skip.
    RecentTransactions { tag: Tag, count: u64, from: u64 },
    /// One block, by index or by hash (`/block`).
    Block { at: BlockAt },
    /// The `count` newest blocks: the tip from `/network/status`, then
    /// `/block` for each index below it.
    Blocks { count: u64 },
    /// The transactions the node's queue holds, waiting to be mined: the
    /// ids from `/mempool`, then `/mempool/transaction` for the first
    /// `count` of them.
    Mempool { count: u64 },
    /// What the node says about accounts `0..=to` derived from the store's
    /// master: one `/call` per index, nothing written. Constructs no wallet,
    /// so it runs on a store `Wallet::open` would refuse.
    ///
    /// It never reports an account as absent, only as not resolved by the
    /// node (see `cli::discover`).
    Discover { to: u32 },
    /// Add an account the store does not hold, at the position the chain
    /// holds it at, from key material made elsewhere. Every secret is read
    /// from the terminal by the binary, never from argv.
    Import(ImportFrom),
    /// One of a validator's cold-key transactions (`set-delegate`,
    /// `clear-delegate`, `claim`), laid out, reserved, signed and written, or
    /// with `--resign` the reserved one reproduced and written.
    Validator(ValidatorTx),
    /// The reward entitlement a tag holds, from `/account/entitlement` or as
    /// the operator supplies it, beside the spendable balance the fee comes
    /// from. Read-only: opens no store, asks no password.
    Entitlement { tag: Tag, supplied: Option<u64> },
    /// One of the v4.1 staking transactions (`stake`, `unstake`, `accept`,
    /// `revoke`), checked against the stake the Mesh reports, laid out,
    /// reserved, signed and written; or with `--resign` the reserved one
    /// reproduced and written.
    Staking(StakingTx),
    /// A tag's stake and the network's staking figures. Read-only: opens no
    /// store, asks no password.
    StakeInfo {
        tag: Option<Tag>,
        network: crate::staking::Network,
    },
}

/// Where `import` takes the account from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImportFrom {
    /// `--sdk --account N`: account `N` of a Mochimo SDK master seed, the
    /// scheme the proof-of-stake chain's validator cold keys use. The seed
    /// is asked for on the terminal.
    Sdk { account: u32, scan_to: Option<u32> },
    /// `--extension-export <path> --tag <tag>`: the account the Mochimo
    /// browser extension's export file holds for `tag`, stored as an
    /// imported root. The export password is asked for on the terminal.
    ExtensionExport { path: String, tag: Tag, scan_to: Option<u32> },
}

/// A validator transaction's parameters, as the command line gave them.
///
/// `--resign` takes the same parameters again: the plan is rebuilt and its
/// digest compared with the reserved one, so a different delegate, amount,
/// fee or block-to-live is refused and nothing is signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorTx {
    /// The validator's cold tag: the source.
    pub tag: Tag,
    pub op: crate::mesh::spend::ValidatorOp,
    /// The total fee. Defaults to `MFEE`, the node's floor, taken from the
    /// spendable balance.
    pub fee_total: u64,
    pub blk_to_live: u64,
    /// Reproduce the reserved transaction rather than reserve a new one.
    pub resign: bool,
    /// For a claim: an entitlement the operator supplies, used in place of
    /// `/account/entitlement`.
    pub entitlement: Option<u64>,
    /// Which chain. Above its v4.1 trigger these transactions are signed in
    /// the dust-proof form and a claim is checked against the tag's stake
    /// (`cli::staking`); at or below it, in v4.0's exact-balance form.
    pub network: crate::staking::Network,
    /// `--expect-balance N`: the spendable balance the operator read from a
    /// source other than the configured node. When given, a plan built
    /// against any other balance is refused before a key is reserved.
    pub expect_balance: Option<u64>,
}

/// A staking verb's parameters, as the command line gave them: the v4.1
/// dust-proof transactions.
///
/// `--resign` takes the same parameters again: the plan is rebuilt and its
/// digest compared with the reserved one, so anything else is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StakingTx {
    /// The source: the staker, or the consenting tag.
    pub tag: Tag,
    pub action: StakingAction,
    /// The total fee. Defaults to `MFEE`, from the spendable balance.
    pub fee_total: u64,
    /// The block-to-live; zero, the default, never expires.
    pub blk_to_live: u64,
    /// Reproduce the reserved transaction rather than reserve a new one.
    pub resign: bool,
    /// Which chain: the network id the payload signs and the trigger.
    pub network: crate::staking::Network,
    /// The operator accepts that a locked stake's entitlement is forfeited:
    /// `unstake` before expiry, or a consent from a locked staker.
    pub forfeit: bool,
    /// The expiry height the operator states the stake has and the chain
    /// has passed, for `unstake` and `accept` from a staked tag without
    /// `--forfeit`.
    pub lock_ends: Option<u64>,
    /// The operator states that the tag holds no live consent, for `stake`
    /// when the middleware does not disclose consents.
    pub no_live_consent: bool,
    /// The operator states that the tag does not stake, for `accept` from a
    /// tag the node reports as not staking.
    pub not_staked: bool,
    /// The operator states that the consenting key is a delegate key no
    /// delegate signer has used and no slot binds.
    pub unbound_delegate: bool,
    /// An entitlement the operator supplies in place of
    /// `/account/entitlement`, for `stake` and `claim`.
    pub entitlement: Option<u64>,
}

/// What a staking verb does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StakingAction {
    /// `stake <tag> <amount> --tier K`.
    Stake { amount: u64, tier: u8 },
    /// `unstake <tag>`.
    Unstake,
    /// `accept <tag> --kind K --peer P ...`, the network already the one
    /// [`StakingTx::network`] names.
    Accept(crate::staking::ConsentTerms),
    /// `revoke <tag>`.
    Revoke,
    /// `claim` above the trigger: the dust-proof form.
    Claim { amount: u64 },
    /// `set-delegate` above the trigger: the dust-proof form.
    SetDelegate { delegate: Tag },
    /// `clear-delegate` above the trigger: the dust-proof form.
    ClearDelegate,
}

/// How `block` was asked for.
///
/// Index 0 is never produced: the endpoint's `getBlock` queries by number
/// only when `Index != 0` and otherwise serves the current block, so the
/// parser refuses `block 0`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockAt {
    Index(u64),
    Hash([u8; HASHLEN]),
}

impl Command {
    /// Whether this command asks a node anything. [`parse`] refuses a
    /// missing `--node` exactly when this is true.
    ///
    /// The match has no wildcard arm, so a new verb must decide here. Only
    /// `create` and `address` answer `false`: they open no wallet and send no
    /// request.
    pub fn needs_node(&self) -> bool {
        match self {
            Command::Create { .. } | Command::Address { .. } => false,
            Command::Balance
            | Command::Send(_)
            | Command::Settle { .. }
            | Command::Resign(_)
            | Command::Reconcile { .. }
            | Command::Rollback { .. }
            | Command::Restore { .. }
            | Command::Status { .. }
            | Command::Submit { .. }
            | Command::LookupTransaction { .. }
            | Command::RecentTransactions { .. }
            | Command::Block { .. }
            | Command::Blocks { .. }
            | Command::Mempool { .. }
            | Command::Discover { .. }
            | Command::Import { .. }
            | Command::Validator(_)
            | Command::Entitlement { .. }
            | Command::Staking(_)
            | Command::StakeInfo { .. } => true,
        }
    }

    /// Whether the verb reads a node and nothing else: no store is opened, no
    /// password asked, nothing written. The binary runs these before the
    /// password prompt.
    ///
    /// `--dir` is still required by the parser but is not read, created or
    /// locked.
    #[must_use]
    pub fn opens_no_store(&self) -> bool {
        matches!(
            self,
            Command::Submit { .. }
                | Command::LookupTransaction { .. }
                | Command::RecentTransactions { .. }
                | Command::Block { .. }
                | Command::Blocks { .. }
                | Command::Mempool { .. }
                | Command::Entitlement { .. }
                | Command::StakeInfo { .. }
        )
    }
}

/// A spend's parameters.
///
/// `Resign` carries the same fields as `Send`: `Wallet::resign_pending`
/// rebuilds the reserved plan and compares its digest to the recorded one, so
/// the destinations, amounts, fee and block-to-live must be re-supplied
/// exactly; anything else is `DigestMismatch`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spend {
    pub tag: Tag,
    /// The destinations in the order the operator gave them, one to 256.
    ///
    /// The planner sorts them by their 44-byte wire image, so this is not the
    /// wire order; it is the order the page lists and `resign` expects.
    pub dsts: Vec<SpendTo>,
    /// The total fee, not per destination. Defaults to `MFEE × N`, the
    /// node's floor (`500 × N`).
    pub fee_total: u64,
    pub blk_to_live: u64,
    /// `--expect-balance N`, `send` only: the balance the operator read from
    /// a source other than the configured node. When given, a plan built
    /// against any other balance is refused before a key is reserved.
    pub expect_balance: Option<u64>,
}

/// One destination as the command line gave it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendTo {
    pub to: Tag,
    /// `MDST::ref`, the destination's 16-byte reference field: `--ref
    /// <text>` for a single destination, the third column of a
    /// `--destinations` line, or sixteen zero bytes. Validated at parse time
    /// by the node's rule (`crate::mesh::spend::reference_is_valid`). It is
    /// inside the signed digest, so `resign` needs the same value.
    pub reference: [u8; ADDR_REF_LEN],
    /// `None` when the amount was the keyword `all`: `balance − fee`, read
    /// from the same ledger observation the plan is built against. The parser
    /// admits `None` only when there is a single destination.
    pub amount: Option<u64>,
}

impl Spend {
    /// Whether the one destination's amount was the keyword `all`.
    #[must_use]
    pub fn spends_everything(&self) -> bool {
        self.dsts.len() == 1 && self.dsts.iter().any(|d| d.amount.is_none())
    }
}

/// Why argv did not parse. Rendered to the operator; exit code 1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Usage(pub String);

impl core::fmt::Display for Usage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "usage: {}\n\n{}", self.0, HELP)
    }
}

pub const HELP: &str = "\
tawara --dir <DIR> [--node <URL>] [--allow-plaintext-node] <command>
tawara -h | --help | help

  create [--from-phrase]                   make the store and account 0. Generates a
                                           24-word phrase and shows it ONCE, or reads
                                           one you already have. Needs no chain
  address [<tag> | --account <N>]          where to receive. With no argument, every
                                           account in the store -- no node, and no
                                           phrase. With a tag, that account's address
                                           too. With --account N, the address of an
                                           account this store does NOT hold, derived
                                           from its seed and not stored: fund it, then
                                           `restore --account N` adds it. Works before
                                           the account has any funds
  balance                                  every account, as reconciliation found it
  send <tag> <to> <amount> [<to> <amount> ...] [--fee N] [--btl N] [--ref TEXT]
       [--expect-balance N]
  send <tag> --destinations <path> [--fee N] [--btl N] [--expect-balance N]
                                           lay out, reserve, sign, print the artifact
                                           and submit it. One to 256 destinations, as
                                           positional pairs or a file of them; <amount>
                                           may be `all` for a single destination
  settle <tag>                             settle a reservation the chain shows landed
  resign <tag> <to> <amount> [<to> <amount> ...] [--fee N] [--btl N] [--ref TEXT]
  resign <tag> --destinations <path> [--fee N] [--btl N]
                                           rebuild a lost retry artifact and submit it
                                           -- the SAME spend, exactly, or it is refused
  submit <artifact-hex>                    write a saved artifact -- the hex `send`
                                           printed -- to the socket as it is. Opens no
                                           store and asks no password; the layout is
                                           checked and nothing else is judged
  reconcile <tag> --advance-to <N>         advance past a divergence you have read, to
                                           the index its report names; N is derived
                                           and compared to the chain first, never trusted
  reconcile <tag> --rollback-to <N>        roll back to the index the chain shows BEHIND
                                           this store, after a confirmation on the
                                           terminal. The key at N has signed before and
                                           signs again on the next spend
  discover [--to <N>]                      ask the node about accounts 0..=N derived from
                                           this store's seed and print what it said about
                                           each, N defaulting to 64 and running 1..=1024.
                                           Writes nothing. It reports what the node
                                           ANSWERED and never that an account does not
                                           exist, which it cannot know
  restore --account <N> [--scan-to <M>]    re-derive an account and find its index;
                                           --scan-to walks indices 0..=M (default 0..=9999)
  status <tag> [--scan-to <M>]             reconcile one account now, without refusing
                                           -- reports a divergence rather than stopping
                                           on it; --scan-to searches further along
  transaction <hash>                       one transaction from the node's indexer
  recent-transactions <tag> [--count N] [--from M]
                                           what touched a tag, newest first (N: 5),
                                           skipping the M newest (M: 0)
  block <number | hash>                    one block, its reward and what it moved
  blocks [--count N]                       the newest blocks, one row each (N: 5)
  mempool [--count N]                      the transactions waiting to be mined, the
                                           first N read whole (N: 5)

validator cold keys (the proof-of-stake chain):
  import --sdk --account <N> [--scan-to <M>]
  import --extension-export <path> --tag <tag> [--scan-to <M>]
                                           add account N of a Mochimo SDK master seed --
                                           the scheme the cold keys were made under -- or
                                           the account a browser-extension export holds
                                           for <tag>, at the index the chain holds it at.
                                           The seed or the export password is asked for
                                           on the terminal, never in argv
  set-delegate <cold-tag> <delegate-tag> [--fee N] [--btl N] [--expect-balance N]
               [--resign]
                                           bind a delegate to the validator's slot. The
                                           delegate must hold 1 MCM and no slot of its
                                           own and be bound to no other validator; only
                                           the node can check that, after signing
  clear-delegate <cold-tag> [--fee N] [--btl N] [--expect-balance N] [--resign]
                                           clear the validator's delegate binding
  claim <cold-tag> <amount | all> [--entitlement N] [--fee N] [--btl N]
        [--expect-balance N] [--resign]
                                           release <amount> of reward entitlement into
                                           the spendable balance. Refused above the
                                           entitlement /account/entitlement reports, or
                                           above --entitlement N when given
  entitlement <tag> [--supplied N]         the entitlement a tag holds and the balance
                                           its fee would come from. READ ONLY

for the validator verbs, --fee defaults to 500, the node's floor, and comes from the
SPENDABLE balance, never from entitlement: a cold address must hold at least the fee.
The node demands send + change + fee equal the balance EXACTLY, so any payment that
lands on the cold tag between signing and inclusion -- anyone can send dust to a
public tag -- invalidates the signed transaction, and its one-time key can sign
nothing else. --resign reproduces the reserved one with the same parameters.
/account/entitlement answers one check per address per ten seconds; a second inside
that window is refused with the wait to observe, and nothing retries.

staking (v4.1, above the trigger: mainnet block 1,136,384):
  stake <tag> <amount> --tier <0..5> [--no-live-consent] [--fee N] [--btl N]
        [--entitlement N] [--resign]
                                           lock <amount> of the spendable balance until
                                           the first neogenesis 65,536 x 2^tier heights
                                           on, at coefficient tier + 1. Refused below
                                           the minimum stake, with a stake already
                                           held, or with entitlement not yet claimed.
                                           The node refuses a stake from a tag whose
                                           consent (accept) is under 65,536 blocks old
                                           and not cleared; while the Mesh does not
                                           show consents, --no-live-consent states
                                           there is none, and --btl is refused.
                                           Shows the lock end
  unstake <tag> [--forfeit | --lock-ends H] [--fee N] [--btl N] [--resign]
                                           return the staked principal. Before the lock
                                           ends the entitlement is FORFEITED: refused
                                           without --forfeit. After, it stays to claim,
                                           and --lock-ends H must name the expiry
                                           height you know the stake has, once you
                                           have seen the chain pass it elsewhere
  claim <tag> <amount | all> ...           above the trigger: dust-proof; refused while a stake is
                                           locked; after the lock ends it also unstakes
  accept <tag> --kind <1..4> --peer <tag> [--action elect|recover] [--slot N]
         [--ip A.B.C.D] [--port P] [--flags N] [--unbound-delegate]
         [--forfeit | --lock-ends H | --not-staked] [--entitlement N]
                                           consent to a validator designation naming
                                           the peer. Kinds 1 and 2 are signed by a
                                           delegate key: refused without --unbound-delegate.
                                           Refused while the tag holds entitlement; from
                                           a staked tag as for unstake. A consent from a
                                           locked staker FORFEITS its entitlement, so
                                           from a tag the node reports as not staking
                                           --not-staked states that it does not
  revoke <tag> [--fee N] [--btl N] [--resign]
                                           clear this tag's consent
  stake-info [<tag>]                       the stake, lock, coefficient and entitlement
                                           of a tag, the minimum stake and its schedule,
                                           and the network's totals. READ ONLY

for the staking verbs --network mainnet is the default; --network testnet --t41 <H>
names the proof-of-stake testnet and its trigger. Every staking transaction is
dust-proof: it signs a zero change, so a payment landing on the tag cannot invalidate
it. The fee comes from the spendable balance (an unstake's and a claim's may come
from the principal they release).

--expect-balance N refuses to reserve a key unless the node reports exactly N as the
source's spendable balance. The change is computed from the node's figure, and the
node rejects a transaction whose totals miss the ledger balance only after its
one-time key has signed. Read N from a source other than --node.

amounts are in nanoMochimo.

the last five verbs READ ONLY: they open no store and ask no password, so they work
with no wallet on this machine. --dir is still required, and is not touched. --count
runs 1..=100: the Mesh takes a limit only inside that window and otherwise answers
with its own default of ten rows without saying so, so a count it would ignore is
refused here. --from runs 0..=9223372036854775807, the Mesh's own range for an
offset; a page that has more after it names the --from that reads them. `block 0`
is refused too -- the Mesh serves index 0 as the CURRENT block, not as genesis.

`--ref TEXT` sets the destination's 16-byte reference field, checked against the
node's own rule before anything is asked or signed: groups of uppercase letters
A-Z or digits 0-9, each group one kind, neighbouring groups of different kinds,
single dashes between groups and none at either end, at most sixteen characters
-- `AB-00-EF`, `123-CDE-789`, `ABC`, `123`. Without it the field is zero. `resign`
needs the same `--ref` the `send` used. It names ONE destination's reference, so
it is taken only with a single destination; with several, the file's third column
gives a reference per line.

`discover` is the other half of `address --account N`: that one says where account N
would receive and asks nobody, this one asks the node about a range of accounts at one
call each. An index it reports as not resolved is not an account that does not exist --
the node answers `account not found` for a tag with no ledger entry, for a tag at zero
balance, and for a lookup that failed, and tells none of the three apart. An index it
resolves is added to this store by `restore --account N`; `discover` itself writes
nothing and reserves nothing.

`--destinations <path>` reads one destination per line, `<to> <amount> [<ref>]`,
whitespace separated, `#` starting a comment. Blank lines are skipped. Use it when
the payees do not fit on a command line, or when they need references.

`--fee` is a TOTAL, never per destination. It defaults to 500 x the number of
destinations, which is exactly the floor the node applies; a fee below that floor
is refused before anything is signed.

`all` as the <amount> sends the whole balance less the fee, read from the same
ledger observation the plan is built against, so the change is zero and the
account is emptied. Only for a single destination.

a destination is Base58 over a tag and its CRC16 -- 22 to 31 characters, the form
every Mochimo wallet emits and takes, and the only form that catches a typo.
`0x` followed by 40 hex characters is accepted too: that is the machine form the
Mesh endpoints use and the form this project's fixtures record. The `0x` is
REQUIRED, because hex carries no checksum and a form with no checksum has to be
asked for -- bare 40-hex would also accept the second half of the 80-character
ledger address `address` prints, which is a tag nobody holds.
the store is encrypted: every command prompts for its password on the terminal, and
the master seed is read out of the store rather than typed. the recovery phrase is a
backup, not a login -- only `create --from-phrase` asks for it.
`--scan-to` and `--advance-to` walk key indices from 0 up to the number given, and every
index walked costs one key derivation: name a number near where the account is. Without
`--scan-to`, `restore` and `status` walk 0..=9999, which is what the only other wallet
for this chain walks; a search that finds nothing pays for all ten thousand, about
sixteen seconds, and a search that finds the account stops there and pays nothing.
create and address need no `--node`; every other command asks a node before it runs
and requires one. An `http://` node off the loopback interface needs
`--allow-plaintext-node`: the node's answers drive reconciliation and the amounts a
spend is built from, and on a plaintext link anyone on the path can rewrite them.
`https://`, and `http://` to 127.0.0.0/8, ::1 or localhost, need no flag.";

/// A tag the operator supplied, in either accepted form.
///
/// # The two forms
///
/// * a destination: Base58 over the tag and its CRC16, 22 to 31 characters,
///   the form Mochimo wallets emit and accept.
/// * `0x` followed by 40 hex characters: the machine form the Mesh endpoints
///   use.
///
/// # Bare 40-hex is refused
///
/// `address` prints the 40-byte ledger address as 80 hex characters, and its
/// second half (the hash half) is 40 hex characters that a bare-hex parser
/// would accept as a tag. After one spend that half is a tag nobody controls,
/// and hex carries no checksum, so a payment to it is lost. Nothing this
/// program prints carries the `0x` prefix, so requiring it rules that out.
///
/// # The forms are disjoint
///
/// The Base58 alphabet excludes `0`, so no destination begins `0x`, and a
/// destination is at most [`crate::addr::TAG_BASE58_MAX_CHARS`] = 31
/// characters where a hex tag is 40.
///
/// # Trimmed
///
/// Surrounding whitespace is trimmed, as other Mochimo wallets do, so a
/// pasted destination with a trailing newline is accepted.
fn tag_from_text(s: &str, what: &'static str) -> Result<Tag, Usage> {
    let t = s.trim();
    if t.starts_with("0x") {
        return refuse_the_zero_tag(tag_from_hex(t, what)?, t, what);
    }
    if t.chars().count() == ADDR_TAG_LEN * 2 && t.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Usage(format!(
            "{what}: `{t}` is a bare hex tag. Write it as `0x{t}` if that is what you mean.\n  \
             Hex carries no checksum, so it is accepted only when you say it is hex. The reason \
             is specific: `address` prints a 40-byte ledger address as eighty hex characters, \
             and its second half is also forty hex characters -- a tag nobody holds, which a \
             bare-hex parser would take without complaint."
        )));
    }
    let tag = crate::addr::tag_from_base58(t).map_err(|e| {
        Usage(format!(
            "{what}: `{t}` is not a destination -- {e}.\n  A destination is Base58 over a tag \
             and its CRC16, which is what every Mochimo wallet emits; `0x` and {} hex \
             characters is accepted too.",
            ADDR_TAG_LEN * 2
        ))
    })?;
    refuse_the_zero_tag(tag, t, what)
}

/// Refuses the all-zero tag.
///
/// `crc16` of twenty zero bytes is zero, so the checksum cannot catch this
/// value, and neither the planner nor the node refuses it: a payment to it
/// settles and can never be spent. It is also what an uninitialised or
/// truncated buffer produces.
///
/// This is wallet policy, applied where the operator typed the tag;
/// [`crate::addr::tag_from_base58`] is a codec and decodes the value like any
/// other.
fn refuse_the_zero_tag(tag: Tag, given: &str, what: &'static str) -> Result<Tag, Usage> {
    if tag.iter().any(|&b| b != 0) {
        return Ok(tag);
    }
    Err(Usage(format!(
        "{what}: `{given}` is the all-zero tag, and this wallet will not use it.\n  Its checksum \
         is zero as well -- crc16 of twenty zero bytes is 0 -- so the CRC16 that refuses every \
         other mistyped destination cannot refuse this one. It is what an uninitialised or \
         truncated buffer produces, the chain will credit it, and nothing can ever spend it \
         again."
    )))
}

fn tag_from_hex(s: &str, what: &'static str) -> Result<Tag, Usage> {
    let body = s.strip_prefix("0x").unwrap_or(s);
    let mut out = [0u8; ADDR_TAG_LEN];
    let mut written = 0usize;
    let mut hi: Option<u8> = None;
    for c in body.chars() {
        let d = match c.to_digit(16) {
            Some(d) => d as u8,
            None => return Err(Usage(format!("{what}: `{s}` is not hexadecimal"))),
        };
        match hi {
            None => hi = Some(d),
            Some(h) => {
                match out.get_mut(written) {
                    Some(slot) => *slot = (h << 4) | d,
                    None => {
                        return Err(Usage(format!(
                            "{what}: `{s}` is longer than {ADDR_TAG_LEN} bytes"
                        )))
                    }
                }
                written += 1;
                hi = None;
            }
        }
    }
    if hi.is_some() || written != ADDR_TAG_LEN {
        return Err(Usage(format!(
            "{what}: `{s}` is {} hex characters; a tag is {}",
            body.chars().count(),
            ADDR_TAG_LEN * 2
        )));
    }
    Ok(out)
}

fn u64_arg(s: &str, what: &'static str) -> Result<u64, Usage> {
    s.parse::<u64>()
        .map_err(|_| Usage(format!("{what}: `{s}` is not a whole number")))
}

/// A flag that takes a value, read from the tail of a command's arguments.
fn u64_flag(rest: &[String], name: &str) -> Result<Option<u64>, Usage> {
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        if a == name {
            return match it.next() {
                Some(v) => u64_arg(v, "flag value").map(Some),
                None => Err(Usage(format!("{name} needs a value"))),
            };
        }
    }
    Ok(None)
}

/// A flag whose value is text: the first occurrence
/// ([`reject_unknown_flags`] refuses a second).
fn text_flag<'a>(rest: &'a [String], name: &str) -> Result<Option<&'a str>, Usage> {
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        if a == name {
            return match it.next() {
                Some(v) => Ok(Some(v.as_str())),
                None => Err(Usage(format!("{name} needs a value"))),
            };
        }
    }
    Ok(None)
}

/// The node's rule for a destination reference, as quoted in every `--ref`
/// refusal. The rule itself is `mesh::spend::reference_is_valid`.
pub const REFERENCE_RULE: &str = "a reference is up to sixteen characters: groups of uppercase \
letters A-Z or digits 0-9, each group all one kind, neighbouring groups of different kinds, \
single dashes between groups and none at either end -- `AB-00-EF`, `123-CDE-789`, `ABC` and \
`123` are accepted; `AB-CD-EF`, `123-456-789`, `ABC-` and `-123` are not";

/// `--ref <text>`: the destination's reference field, validated by the
/// node's rule and NUL-padded to sixteen bytes. Sixteen zero bytes without
/// the flag.
fn reference_flag(rest: &[String]) -> Result<[u8; ADDR_REF_LEN], Usage> {
    match text_flag(rest, "--ref")? {
        None => Ok([0u8; ADDR_REF_LEN]),
        Some(text) => reference_field(text, "--ref"),
    }
}

/// One reference's text, NUL-padded to sixteen bytes and checked against the
/// node's rule. `whose` names where it came from (the flag, or a file and
/// line) for the refusal message.
fn reference_field(text: &str, whose: &str) -> Result<[u8; ADDR_REF_LEN], Usage> {
    let mut field = [0u8; ADDR_REF_LEN];
    if !text.is_ascii() {
        return Err(Usage(format!("{whose}: `{text}` is not ASCII; {REFERENCE_RULE}")));
    }
    if text.len() > ADDR_REF_LEN {
        return Err(Usage(format!(
            "{whose}: `{text}` is {} characters and the field holds {ADDR_REF_LEN}; {REFERENCE_RULE}",
            text.len()
        )));
    }
    field[..text.len()].copy_from_slice(text.as_bytes());
    if !crate::mesh::spend::reference_is_valid(&field) {
        return Err(Usage(format!(
            "{whose}: `{text}` does not follow the node's rule for a destination reference; {REFERENCE_RULE}"
        )));
    }
    Ok(field)
}

/// Refuses any token in the tail that is not one of the command's flags, and
/// any flag given twice, so a mistyped or repeated flag is a usage error
/// rather than silently ignored.
///
/// A `valued` flag consumes the token after it; a `bare` flag does not.
fn reject_unknown_flags(rest: &[String], valued: &[&str], bare: &[&str]) -> Result<(), Usage> {
    let mut it = rest.iter();
    let mut seen: Vec<&str> = Vec::new();
    while let Some(a) = it.next() {
        let is_bare = bare.contains(&a.as_str());
        if !is_bare && !valued.contains(&a.as_str()) {
            return Err(Usage(format!("unexpected argument `{a}`")));
        }
        if seen.contains(&a.as_str()) {
            return Err(Usage(format!("{a} given twice")));
        }
        seen.push(a.as_str());
        if is_bare {
            continue;
        }
        if it.next().is_none() {
            return Err(Usage(format!("{a} needs a value")));
        }
    }
    Ok(())
}

/// A flag that is present or absent.
fn bare_flag(rest: &[String], name: &str) -> bool {
    rest.iter().any(|a| a == name)
}

/// `send` and `resign`, in either of two exclusive forms:
///
/// ```text
/// <tag> <to> <amount> [<to> <amount> ...] [--fee N] [--btl N] [--ref TEXT]
/// <tag> --destinations <path>            [--fee N] [--btl N]
/// ```
///
/// Destinations are positional pairs because a repeated flag is a usage
/// error everywhere in this parser.
///
/// `--ref` is accepted only with one destination; with several, the file's
/// third column gives a reference per line. `all` (the whole balance less the
/// fee) is accepted only with one destination.
fn spend_args(rest: &[String], verb: &'static str) -> Result<Spend, Usage> {
    let Some(tag) = rest.first() else {
        return Err(Usage(format!("{verb} needs <tag> <to> <amount>")));
    };
    let tag = tag_from_text(tag, "source tag")?;
    let after = rest.get(1..).unwrap_or(&[]);

    // The two forms are told apart by the first token after the tag, which is
    // either `--destinations` or the first `<to>`.
    let from_file = after.first().is_some_and(|a| a == "--destinations");
    // `resign` reproduces a plan whose balance the reservation recorded, so
    // only `send` takes `--expect-balance`.
    let send = verb == "send";
    let valued = |base: &[&'static str]| -> Vec<&'static str> {
        let mut v = base.to_vec();
        if send {
            v.push("--expect-balance");
        }
        v
    };
    let (dsts, tail) = if from_file {
        reject_unknown_flags(after, &valued(&["--destinations", "--fee", "--btl", "--ref"]), &[])?;
        if text_flag(after, "--ref")?.is_some() {
            return Err(Usage(
                "--ref names one destination's reference and --destinations carries a \
                 reference per line; give it in the file's third column instead"
                    .into(),
            ));
        }
        let path = match text_flag(after, "--destinations")? {
            Some(p) => p,
            None => return Err(Usage("--destinations needs a value".into())),
        };
        let text = std::fs::read_to_string(path)
            .map_err(|e| Usage(format!("--destinations: cannot read `{path}`: {e}")))?;
        (destinations_from_text(&text, path)?, after)
    } else {
        // Positional pairs run until the first flag.
        let pairs_len = after.iter().take_while(|a| !a.starts_with("--")).count();
        let (pairs, tail) = after.split_at(pairs_len);
        if pairs.is_empty() {
            return Err(Usage(format!("{verb} needs <tag> <to> <amount>")));
        }
        if pairs.len() % 2 != 0 {
            return Err(Usage(format!(
                "{verb} takes <to> <amount> pairs and {} token(s) were given after the tag; \
                 the last destination has no amount",
                pairs.len()
            )));
        }
        reject_unknown_flags(tail, &valued(&["--fee", "--btl", "--ref"]), &[])?;
        let single = pairs.len() == 2;
        let reference = reference_flag(tail)?;
        if !single && reference != [0u8; ADDR_REF_LEN] {
            return Err(Usage(format!(
                "--ref names one destination's reference and {} were given; use \
                 `--destinations <path>`, whose third column is a reference per line",
                pairs.len() / 2
            )));
        }
        // Walked by `next`, never indexed, so an odd count is a refusal here
        // too rather than an `unwrap`.
        let mut dsts = Vec::new();
        let mut it = pairs.iter();
        while let Some(to) = it.next() {
            let Some(amount) = it.next() else {
                return Err(Usage(format!("{verb}: `{to}` has no amount")));
            };
            dsts.push(SpendTo {
                to: tag_from_text(to, "destination tag")?,
                reference,
                amount: amount_arg(amount, single)?,
            });
        }
        (dsts, tail)
    };

    check_destinations(&dsts)?;
    let n = u64::try_from(dsts.len()).unwrap_or(u64::MAX);
    Ok(Spend {
        tag,
        fee_total: u64_flag(tail, "--fee")?.unwrap_or(MFEE.saturating_mul(n)),
        blk_to_live: u64_flag(tail, "--btl")?.unwrap_or(0),
        dsts,
        expect_balance: if send { u64_flag(tail, "--expect-balance")? } else { None },
    })
}

/// `<amount>`: a whole number of nanoMochimo, or the keyword `all`.
///
/// `all` is refused unless `single`, with a message that says so.
fn amount_arg(s: &str, single: bool) -> Result<Option<u64>, Usage> {
    if s == "all" {
        return if single {
            Ok(None)
        } else {
            Err(Usage(
                "`all` means the whole balance less the fee and is only available for a \
                 single destination; give each destination its own amount"
                    .into(),
            ))
        };
    }
    u64_arg(s, "amount").map(Some)
}

/// Checks the whole destination list.
///
/// The count bound is the protocol's (`crate::tx::MAX_DESTINATIONS`). The
/// duplicate-tag refusal is wallet policy, not a protocol rule: the node
/// accepts it, but a repeated tag is almost always a mistyped payee. It is
/// kept out of `SpendPlan`, which applies only the node's rules.
fn check_destinations(dsts: &[SpendTo]) -> Result<(), Usage> {
    let max = usize::from(crate::tx::MAX_DESTINATIONS);
    if dsts.is_empty() || dsts.len() > max {
        return Err(Usage(format!(
            "a spend carries 1 to {max} destinations and {} were given",
            dsts.len()
        )));
    }
    for (i, d) in dsts.iter().enumerate() {
        if let Some(j) = dsts.iter().take(i).position(|e| e.to == d.to) {
            return Err(Usage(format!(
                "destinations {} and {} are the same tag. The node would accept it, but one \
                 tag twice in one spend is almost always a mistyped payee and the money does \
                 not come back; send twice if you mean it",
                j + 1,
                i + 1
            )));
        }
    }
    Ok(())
}

/// `--count N`, the row count the explorer verbs take.
///
/// Defaults to 5. The range `1..=100` is the Mesh's: its search endpoint uses
/// a `limit` only when `0 < limit <= 100` and otherwise silently answers with
/// ten rows, so a value outside it is refused here. `blocks` and `mempool`
/// use the same bound, since each row is one request.
fn count_flag(rest: &[String]) -> Result<u64, Usage> {
    reject_unknown_flags(rest, &["--count"], &[])?;
    count_value(rest)
}

/// [`count_flag`]'s reading of `--count`, for a verb that takes other flags
/// beside it and has refused any it does not.
fn count_value(rest: &[String]) -> Result<u64, Usage> {
    let n = u64_flag(rest, "--count")?.unwrap_or(DEFAULT_COUNT);
    if n == 0 || n > MAX_COUNT {
        return Err(Usage(format!(
            "--count: {n} is outside 1..={MAX_COUNT}. The Mesh's search endpoint takes a limit \
             only inside that window and otherwise answers with its own default of ten rows \
             without saying so, so a count it would ignore is refused here instead"
        )));
    }
    Ok(n)
}

/// `--from M`, the rows `recent-transactions` skips: the endpoint's
/// `offset`.
///
/// Defaults to 0, the newest. The Mesh decodes `offset` as an `int64`, so a
/// value above [`MAX_FROM`] is refused here. A value past the tag's last row
/// is accepted and answered with an empty page.
fn from_flag(rest: &[String]) -> Result<u64, Usage> {
    let m = u64_flag(rest, "--from")?.unwrap_or(0);
    if m > MAX_FROM {
        return Err(Usage(format!(
            "--from: {m} is outside 0..={MAX_FROM}. The Mesh reads an offset as a signed 64-bit \
             number and answers a larger one as an invalid request, so it is refused here \
             instead"
        )));
    }
    Ok(m)
}

/// The largest `--from` `recent-transactions` takes: `i64::MAX`, the
/// Mesh's own range for an offset.
pub const MAX_FROM: u64 = i64::MAX as u64;

/// How many rows an explorer verb prints without `--count`.
pub const DEFAULT_COUNT: u64 = 5;
/// The largest `--count` either explorer verb takes; the Mesh's own ceiling.
pub const MAX_COUNT: u64 = 100;

/// How far `discover` sweeps without `--to`: account indices `0..=64`.
///
/// The extent is printed on the page with how to raise it.
pub const DISCOVER_DEFAULT_TO: u32 = 64;

/// The largest `--to` `discover` takes.
///
/// Each index is one request to the node, so this bounds what a mistyped
/// number can cost. It is this program's limit, not the protocol's.
pub const DISCOVER_MAX_TO: u32 = 1_024;

/// `discover`'s `--to`, defaulting to [`DISCOVER_DEFAULT_TO`].
///
/// Zero is refused with its own reason: a sweep of index 0 only finds the
/// account `create` already stored, and zero is what an unexpanded shell
/// variable produces.
fn discover_to_flag(rest: &[String]) -> Result<u32, Usage> {
    reject_unknown_flags(rest, &["--to"], &[])?;
    let n = match u64_flag(rest, "--to")? {
        Some(n) => n,
        None => return Ok(DISCOVER_DEFAULT_TO),
    };
    // Zero and values above the ceiling are refused with different reasons.
    match u32::try_from(n) {
        Ok(to) if (1..=DISCOVER_MAX_TO).contains(&to) => Ok(to),
        Ok(0) => Err(Usage(format!(
            "--to: {n} is outside 1..={DISCOVER_MAX_TO}. A sweep bounded at 0 searches only \
             account index 0, which a store with a master already holds, so it can observe \
             nothing the store does not record while still costing a node call -- `address` \
             with no argument lists what is here, and `balance` reports it. Zero is also what \
             an unexpanded shell variable produces"
        ))),
        _ => Err(Usage(format!(
            "--to: {n} is outside 1..={DISCOVER_MAX_TO}. Every index in the sweep is one call \
             to the node, so the ceiling is this program's own: it keeps a mistyped number from \
             turning into thousands of round trips before the first line of output. Name a \
             bound at or below {DISCOVER_MAX_TO}"
        ))),
    }
}

/// A 32-byte transaction hash, `0x` + 64 hex or the bare 64.
///
/// Bare hex is accepted here, unlike for a destination, because nothing is
/// paid to a transaction hash.
fn hash_arg(arg: Option<&String>, verb: &'static str) -> Result<[u8; HASHLEN], Usage> {
    let Some(text) = arg else {
        return Err(Usage(format!("{verb} needs <hash>")));
    };
    let body = text.strip_prefix("0x").unwrap_or(text);
    if body.len() != HASHLEN * 2 || !body.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err(Usage(format!(
            "{verb}: `{text}` is not a transaction hash; it is {} hex characters and a hash is \
             {} (with or without a leading `0x`)",
            body.len(),
            HASHLEN * 2
        )));
    }
    let mut out = [0u8; HASHLEN];
    for (i, b) in out.iter_mut().enumerate() {
        let pair = body.get(i * 2..i * 2 + 2).ok_or_else(|| Usage(format!("{verb}: `{text}` is not a hash")))?;
        *b = u8::from_str_radix(pair, 16).map_err(|_| Usage(format!("{verb}: `{text}` is not a hash")))?;
    }
    Ok(out)
}

/// `block <number>` or `block <hash>`.
///
/// Index 0 is refused: the endpoint serves index 0 as the current block, not
/// genesis (see [`BlockAt`]).
fn block_at(arg: Option<&String>) -> Result<BlockAt, Usage> {
    let Some(text) = arg else {
        return Err(Usage("block needs <number> or <hash>".into()));
    };
    if text.as_bytes().iter().all(u8::is_ascii_digit) {
        let n = u64_arg(text, "block number")?;
        if n == 0 {
            return Err(Usage(
                "block 0: the Mesh serves index 0 as the CURRENT block, not as genesis -- its \
                 getBlock routes by number only for a non-zero index -- so a page for `block 0` \
                 would be the tip under the wrong name. Use `blocks` for the tip, or name a \
                 block from 1 up"
                    .into(),
            ));
        }
        return Ok(BlockAt::Index(n));
    }
    Ok(BlockAt::Hash(hash_arg(arg, "block")?))
}

/// `--destinations <path>`, parsed from the file's text.
///
/// One destination per non-empty line, `<to> <amount> [<ref>]`, whitespace
/// separated; `#` starts a comment. Every refusal names the line number.
fn destinations_from_text(text: &str, path: &str) -> Result<Vec<SpendTo>, Usage> {
    let mut out = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line = match raw.split_once('#') {
            Some((before, _)) => before,
            None => raw,
        };
        let mut f = line.split_whitespace();
        let Some(to) = f.next() else { continue };
        let at = format!("{path} line {}", n + 1);
        let Some(amount) = f.next() else {
            return Err(Usage(format!("{at}: `{to}` has no amount")));
        };
        let reference = match f.next() {
            Some(r) => reference_field(r, &at)?,
            None => [0u8; ADDR_REF_LEN],
        };
        if let Some(surplus) = f.next() {
            return Err(Usage(format!(
                "{at}: unexpected `{surplus}`; a line is <to> <amount> [<ref>]"
            )));
        }
        out.push(SpendTo {
            to: tag_from_text(to, "destination tag")?,
            reference,
            // `all` is a command-line keyword only.
            amount: Some(u64_arg(amount, "amount")?),
        });
    }
    if out.is_empty() {
        return Err(Usage(format!("{path}: no destinations; every line was blank or a comment")));
    }
    Ok(out)
}

/// A key index named on the command line (`--advance-to`, `--scan-to`).
///
/// `u32::MAX` is refused too: the last position cannot be advanced from, so an
/// account there could never reserve a spend.
fn index_flag(rest: &[String], name: &str) -> Result<Option<u32>, Usage> {
    match u64_flag(rest, name)? {
        None => Ok(None),
        Some(n) => match u32::try_from(n) {
            Ok(i) if i < u32::MAX => Ok(Some(i)),
            _ => Err(Usage(format!(
                "{name}: {n} is out of range; key indices run from 0 to {}",
                u32::MAX - 1
            ))),
        },
    }
}

/// The tag a command takes first, before its flags. A flag in that position
/// is reported as a missing tag.
fn leading_tag(rest: &[String], verb: &'static str) -> Result<Tag, Usage> {
    match rest.first() {
        Some(t) if !t.starts_with("--") => tag_from_text(t, "tag"),
        _ => Err(Usage(format!("{verb} needs <tag>"))),
    }
}

/// `submit`'s one argument, the artifact hex as typed. The command decodes it
/// (a bad artifact is exit 3). A flag in its place is reported as a missing
/// artifact.
fn artifact_arg(rest: &[String], verb: &'static str) -> Result<String, Usage> {
    match rest.first() {
        Some(a) if rest.len() == 1 && !a.starts_with("--") => Ok(a.clone()),
        Some(a) if a.starts_with("--") => Err(Usage(format!("{verb} needs <artifact-hex>"))),
        Some(_) => Err(Usage(format!("{verb} takes one <artifact-hex>"))),
        None => Err(Usage(format!("{verb} needs <artifact-hex>"))),
    }
}

fn tag_arg(rest: &[String], verb: &'static str) -> Result<Tag, Usage> {
    match rest.first() {
        Some(t) if rest.len() == 1 => tag_from_text(t, "tag"),
        Some(_) => Err(Usage(format!("{verb} takes one tag"))),
        None => Err(Usage(format!("{verb} needs <tag>"))),
    }
}

/// `address`'s optional tag. `None` means list the store; more than one
/// argument is a usage error.
fn optional_tag_arg(rest: &[String], verb: &'static str) -> Result<Option<Tag>, Usage> {
    match rest.first() {
        None => Ok(None),
        Some(t) if rest.len() == 1 => tag_from_text(t, "tag").map(Some),
        Some(_) => Err(Usage(format!("{verb} takes one tag, or none at all"))),
    }
}

/// The flags a validator transaction takes after its positional arguments:
/// `--fee`, `--btl`, `--resign`, `--expect-balance` (not with `--resign`),
/// `--network`, `--t41`, and for a claim `--entitlement`.
fn validator_tx(
    tag: Tag,
    op: crate::mesh::spend::ValidatorOp,
    tail: &[String],
    claim: bool,
) -> Result<Command, Usage> {
    let valued: &[&str] = if claim {
        &["--fee", "--btl", "--entitlement", "--network", "--t41", "--expect-balance"]
    } else {
        &["--fee", "--btl", "--network", "--t41", "--expect-balance"]
    };
    reject_unknown_flags(tail, valued, &["--resign"])?;
    let resign = bare_flag(tail, "--resign");
    let expect_balance = u64_flag(tail, "--expect-balance")?;
    if resign && expect_balance.is_some() {
        return Err(Usage(
            "--expect-balance applies to a new signature; --resign reproduces the reserved one, \
             whose balance the reservation recorded"
                .into(),
        ));
    }
    Ok(Command::Validator(ValidatorTx {
        tag,
        op,
        fee_total: u64_flag(tail, "--fee")?.unwrap_or(MFEE),
        blk_to_live: u64_flag(tail, "--btl")?.unwrap_or(0),
        resign,
        entitlement: if claim { u64_flag(tail, "--entitlement")? } else { None },
        network: network_flags(tail)?,
        expect_balance,
    }))
}

/// `--network mainnet` (the default) or `--network testnet --t41 <H>`: the
/// chain a staking transaction is signed for. Mainnet's trigger is fixed;
/// a `--t41` that disagrees with it is refused rather than obeyed, and the
/// testnet's must be given and be a neogenesis height (a multiple of 256).
fn network_flags(tail: &[String]) -> Result<crate::staking::Network, Usage> {
    use crate::staking::{Network, MAINNET_T41, NETWORK_TESTNET};
    let t41 = u64_flag(tail, "--t41")?;
    match text_flag(tail, "--network")? {
        None | Some("mainnet") => match t41 {
            Some(t) if t != MAINNET_T41 => Err(Usage(format!(
                "--t41 {t}: mainnet's trigger is {MAINNET_T41}; --t41 names the testnet's, with --network testnet"
            ))),
            _ => Ok(Network::MAINNET),
        },
        Some("testnet") => match t41 {
            None => Err(Usage("--network testnet needs --t41 <H>, the testnet's trigger height".into())),
            Some(t) if t % 256 != 0 => Err(Usage(format!(
                "--t41 {t}: the trigger is a neogenesis height, a multiple of 256"
            ))),
            Some(t) => Ok(Network { id: NETWORK_TESTNET, t41: t }),
        },
        Some(other) => Err(Usage(format!("--network {other}: mainnet or testnet"))),
    }
}

/// The valued flags every staking verb takes.
const STAKING_VALUED: [&str; 4] = ["--fee", "--btl", "--network", "--t41"];

/// A staking verb's command from its source tag, its action and the flags
/// after its positional arguments.
fn staking_tx(tag: Tag, action: StakingAction, tail: &[String]) -> Result<Command, Usage> {
    let given: Vec<&str> =
        ["--forfeit", "--lock-ends", "--not-staked"].into_iter().filter(|f| tail.iter().any(|a| a == f)).collect();
    if given.len() > 1 {
        return Err(Usage(format!("{} cannot be given together: pass only one", given.join(" and "))));
    }
    Ok(Command::Staking(StakingTx {
        tag,
        action,
        fee_total: u64_flag(tail, "--fee")?.unwrap_or(MFEE),
        blk_to_live: u64_flag(tail, "--btl")?.unwrap_or(0),
        resign: bare_flag(tail, "--resign"),
        network: network_flags(tail)?,
        forfeit: bare_flag(tail, "--forfeit"),
        lock_ends: u64_flag(tail, "--lock-ends")?,
        no_live_consent: bare_flag(tail, "--no-live-consent"),
        not_staked: bare_flag(tail, "--not-staked"),
        unbound_delegate: bare_flag(tail, "--unbound-delegate"),
        entitlement: u64_flag(tail, "--entitlement")?,
    }))
}

/// `accept`'s terms from its flags: `--kind` as 1 to 4 or `delegate`,
/// `member-delegate`, `member-cold`, `new-holder`;
/// `--action elect|recover`; `--ip` a dotted quad. Which terms the kind may
/// carry is `ConsentTerms::check`'s, applied before anything is signed.
fn consent_terms(tail: &[String], network: u16) -> Result<crate::staking::ConsentTerms, Usage> {
    use crate::staking::{ConsentTerms, ACTION_ELECT, ACTION_RECOVER};
    let kind = match text_flag(tail, "--kind")? {
        None => return Err(Usage("accept needs --kind <1..4>; `revoke` clears a consent".into())),
        Some("delegate" | "1") => 1,
        Some("member-delegate" | "2") => 2,
        Some("member-cold" | "3") => 3,
        Some("new-holder" | "4") => 4,
        Some(other) => {
            return Err(Usage(format!(
                "--kind {other}: 1 delegate, 2 member-delegate, 3 member-cold or 4 new-holder"
            )))
        }
    };
    let peer = match text_flag(tail, "--peer")? {
        Some(p) => tag_from_text(p, "--peer")?,
        None => return Err(Usage("accept needs --peer <tag>: the counterpart the consent names".into())),
    };
    let action = match text_flag(tail, "--action")? {
        None => 0,
        Some("elect") => ACTION_ELECT,
        Some("recover") => ACTION_RECOVER,
        Some(other) => return Err(Usage(format!("--action {other}: elect or recover"))),
    };
    let slot = match u64_flag(tail, "--slot")? {
        None => 0,
        Some(n) => u32::try_from(n).map_err(|_| Usage(format!("--slot {n} is out of range")))?,
    };
    let ip = match text_flag(tail, "--ip")? {
        None => [0; 4],
        Some(text) => match text.parse::<core::net::Ipv4Addr>() {
            Ok(a) => a.octets(),
            Err(_) => return Err(Usage(format!("--ip {text}: a dotted quad, A.B.C.D"))),
        },
    };
    let port = match u64_flag(tail, "--port")? {
        None => 0,
        Some(n) => u16::try_from(n).map_err(|_| Usage(format!("--port {n} is out of range")))?,
    };
    let flags = match u64_flag(tail, "--flags")? {
        None => 0,
        Some(n) => u8::try_from(n).map_err(|_| Usage(format!("--flags {n} is out of range")))?,
    };
    Ok(ConsentTerms {
        kind,
        peer,
        action,
        slot,
        ip,
        port,
        flags,
        network,
    })
}

/// What argv asked for.
///
/// Not named `Parsed`: `keystore::format::Parsed` holds key material, and the
/// source scan that checks `Debug` derives matches bare type names.
///
/// Help is an outcome, not an error, so `--help` exits 0.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParsedArgv {
    /// `-h`, `--help`, or the `help` verb. The caller prints [`HELP`] and
    /// exits **0**.
    Help,
    /// A command to run.
    Run(Invocation),
}

/// The three spellings that ask for help: `help` as the verb, or `-h` or
/// `--help` before it. After the verb they are refused as unexpected tokens.
fn asks_for_help(a: &str) -> bool {
    a == "-h" || a == "--help" || a == "help"
}

/// Whether `url` is plaintext HTTP to something other than the loopback
/// interface, which needs `--allow-plaintext-node`.
///
/// # What counts as loopback
///
/// Any address in `127.0.0.0/8`, `::1`, and the name `localhost`.
/// `localhost` depends on the host's name resolution, but redirecting it
/// requires control of the host, which is beyond the network attacker this
/// check addresses.
///
/// A URL that is not `http://` returns `false`; the transport refuses unknown
/// schemes itself.
pub fn plaintext_off_loopback(url: &str) -> bool {
    // Strip one trailing slash, as the transport does.
    let url = url.strip_suffix('/').unwrap_or(url);
    let Some(authority) = url.strip_prefix("http://") else {
        return false;
    };
    let host = if let Some(rest) = authority.strip_prefix('[') {
        // `[::1]:8080`: an IPv6 literal ends at the first `]`.
        match rest.split_once(']') {
            Some((h, _)) => h,
            None => return true,
        }
    } else {
        authority.split(':').next().unwrap_or("")
    };
    if host.eq_ignore_ascii_case("localhost") {
        return false;
    }
    // Any name other than `localhost` is treated as remote, including
    // `127.0.0.1.example.com`.
    match host.parse::<core::net::IpAddr>() {
        Ok(ip) => !ip.is_loopback(),
        Err(_) => true,
    }
}

/// The refusal for a plaintext node off loopback, stating what the link
/// controls so the operator knows what `--allow-plaintext-node` accepts.
fn plaintext_node_refusal(url: &str) -> String {
    format!(
        "--node {url} is plaintext http to a host that is not loopback, and everything this \
         wallet decides comes from that link: the balance a spend is laid out against, the \
         ledger address reconciliation compares its own record to, the chain tip a \
         block-to-live is judged against, and the key position that says whether a key has \
         already signed. Anyone on the path can rewrite all of it, and can read every tag you \
         ask about.\n  A rewritten balance does not move funds -- the node checks send + \
         change + fee against the ledger and rejects a transaction built on a lie -- but a \
         rewritten reconciliation report is what `reconcile --advance-to` acts on.\n  ACTION: \
         use an https node, or pass --allow-plaintext-node to accept this. http to \
         127.0.0.0/8, ::1 or localhost needs no flag."
    )
}

/// Parse `argv` without the program name.
pub fn parse(argv: &[String]) -> Result<ParsedArgv, Usage> {
    let mut dir: Option<String> = None;
    let mut node: Option<String> = None;
    let mut allow_plaintext = false;
    let mut it = argv.iter();
    let verb = loop {
        match it.next() {
            None => return Err(Usage("no command".into())),
            Some(a) if asks_for_help(a) => return Ok(ParsedArgv::Help),
            // A repeated global flag is a usage error naming the flag.
            Some(a) if a == "--dir" => {
                if dir.is_some() {
                    return Err(Usage("--dir given twice".into()));
                }
                match it.next() {
                    Some(v) => dir = Some(v.clone()),
                    None => return Err(Usage("--dir needs a value".into())),
                }
            }
            Some(a) if a == "--node" => {
                if node.is_some() {
                    return Err(Usage("--node given twice".into()));
                }
                match it.next() {
                    Some(v) => node = Some(v.clone()),
                    None => return Err(Usage("--node needs a value".into())),
                }
            }
            Some(a) if a == "--allow-plaintext-node" => {
                if allow_plaintext {
                    return Err(Usage("--allow-plaintext-node given twice".into()));
                }
                allow_plaintext = true;
            }
            Some(a) if a.starts_with("--") => {
                return Err(Usage(format!("unknown global flag `{a}`")))
            }
            Some(a) => break a.clone(),
        }
    };
    let rest: Vec<String> = it.cloned().collect();
    if let Some(h) = rest.iter().find(|a| asks_for_help(a)) {
        return Err(Usage(format!(
            "unexpected argument `{h}` after `{verb}`; help is `help` as the command, or -h or \
             --help before it"
        )));
    }

    let command = match verb.as_str() {
        "balance" => {
            reject_unknown_flags(&rest, &[], &[])?;
            Command::Balance
        }
        "create" => {
            reject_unknown_flags(&rest, &[], &["--from-phrase"])?;
            Command::Create {
                from_phrase: bare_flag(&rest, "--from-phrase"),
            }
        }
        "address" => {
            if bare_flag(&rest, "--account") {
                // Exclusive with a tag: anything beside the flag and its
                // value is an unexpected argument.
                reject_unknown_flags(&rest, &["--account"], &[])?;
                let n = u64_flag(&rest, "--account")?
                    .ok_or_else(|| Usage("--account needs a value".into()))?;
                let account = u32::try_from(n)
                    .map_err(|_| Usage(format!("--account: {n} is out of range")))?;
                Command::Address {
                    tag: None,
                    account: Some(account),
                }
            } else {
                Command::Address {
                    tag: optional_tag_arg(&rest, "address")?,
                    account: None,
                }
            }
        }
        "status" => {
            let tag = leading_tag(&rest, "status")?;
            let tail = rest.get(1..).unwrap_or(&[]);
            reject_unknown_flags(tail, &["--scan-to"], &[])?;
            Command::Status {
                tag,
                scan_to: index_flag(tail, "--scan-to")?,
            }
        }
        "settle" => Command::Settle {
            tag: tag_arg(&rest, "settle")?,
        },
        "send" => Command::Send(spend_args(&rest, "send")?),
        "resign" => Command::Resign(spend_args(&rest, "resign")?),
        "transaction" => Command::LookupTransaction {
            hash: hash_arg(rest.first(), "transaction")?,
        },
        "recent-transactions" => {
            let tag = leading_tag(&rest, "recent-transactions")?;
            let tail = rest.get(1..).unwrap_or(&[]);
            reject_unknown_flags(tail, &["--count", "--from"], &[])?;
            Command::RecentTransactions {
                tag,
                count: count_value(tail)?,
                from: from_flag(tail)?,
            }
        }
        "block" => Command::Block { at: block_at(rest.first())? },
        "blocks" => Command::Blocks {
            count: count_flag(&rest)?,
        },
        "mempool" => Command::Mempool {
            count: count_flag(&rest)?,
        },
        "discover" => Command::Discover {
            to: discover_to_flag(&rest)?,
        },
        "submit" => Command::Submit {
            artifact: artifact_arg(&rest, "submit")?,
        },
        "reconcile" => {
            let tag = leading_tag(&rest, "reconcile")?;
            let tail = rest.get(1..).unwrap_or(&[]);
            reject_unknown_flags(tail, &["--advance-to", "--rollback-to"], &[])?;
            match (index_flag(tail, "--advance-to")?, index_flag(tail, "--rollback-to")?) {
                (Some(advance_to), None) => Command::Reconcile { tag, advance_to },
                (None, Some(rollback_to)) => Command::Rollback { tag, rollback_to },
                (Some(_), Some(_)) => {
                    return Err(Usage("reconcile takes --advance-to or --rollback-to, not both".into()))
                }
                (None, None) => return Err(Usage("reconcile needs --advance-to <N> or --rollback-to <N>".into())),
            }
        }
        "import" => {
            reject_unknown_flags(&rest, &["--account", "--scan-to", "--extension-export", "--tag"], &["--sdk"])?;
            let scan_to = index_flag(&rest, "--scan-to")?;
            match (bare_flag(&rest, "--sdk"), text_flag(&rest, "--extension-export")?) {
                (true, None) => {
                    if text_flag(&rest, "--tag")?.is_some() {
                        return Err(Usage("import --sdk takes --account <N>, not --tag".into()));
                    }
                    let n = u64_flag(&rest, "--account")?
                        .ok_or_else(|| Usage("import needs --account <N>".into()))?;
                    let account = u32::try_from(n)
                        .map_err(|_| Usage(format!("--account: {n} is out of range")))?;
                    Command::Import(ImportFrom::Sdk { account, scan_to })
                }
                (false, Some(path)) => {
                    if u64_flag(&rest, "--account")?.is_some() {
                        return Err(Usage(
                            "import --extension-export selects the account by --tag; the export \
                             records its index itself"
                                .into(),
                        ));
                    }
                    let tag = match text_flag(&rest, "--tag")? {
                        Some(t) => tag_from_text(t, "tag")?,
                        None => return Err(Usage("import --extension-export needs --tag <tag>".into())),
                    };
                    Command::Import(ImportFrom::ExtensionExport { path: path.to_owned(), tag, scan_to })
                }
                _ => {
                    return Err(Usage(
                        "import needs exactly one source: --sdk (a Mochimo SDK master seed, with \
                         --account <N>) or --extension-export <path> (the browser extension's \
                         export file, with --tag <tag>). The source is named so a seed from one \
                         scheme is never taken for another"
                            .into(),
                    ))
                }
            }
        }
        "set-delegate" => {
            let tag = leading_tag(&rest, "set-delegate")?;
            let delegate = match rest.get(1) {
                Some(d) if !d.starts_with("--") => tag_from_text(d, "delegate tag")?,
                _ => return Err(Usage("set-delegate needs <cold-tag> <delegate-tag>".into())),
            };
            let tail = rest.get(2..).unwrap_or(&[]);
            validator_tx(tag, crate::mesh::spend::ValidatorOp::SetDelegate { delegate }, tail, false)?
        }
        "clear-delegate" => {
            let tag = leading_tag(&rest, "clear-delegate")?;
            let tail = rest.get(1..).unwrap_or(&[]);
            validator_tx(tag, crate::mesh::spend::ValidatorOp::ClearDelegate, tail, false)?
        }
        "claim" => {
            let tag = leading_tag(&rest, "claim")?;
            let amount = match rest.get(1) {
                Some(a) if a == "all" => crate::staking::CLAIM_ALL,
                Some(a) if !a.starts_with("--") => u64_arg(a, "claim amount")?,
                _ => return Err(Usage("claim needs <cold-tag> <amount>".into())),
            };
            if amount == 0 {
                return Err(Usage("claim: an amount of zero is refused by the node (EMCM_CLAIM_ZERO)".into()));
            }
            let tail = rest.get(2..).unwrap_or(&[]);
            validator_tx(tag, crate::mesh::spend::ValidatorOp::Claim { amount }, tail, true)?
        }
        "entitlement" => {
            let tag = leading_tag(&rest, "entitlement")?;
            let tail = rest.get(1..).unwrap_or(&[]);
            reject_unknown_flags(tail, &["--supplied"], &[])?;
            Command::Entitlement {
                tag,
                supplied: u64_flag(tail, "--supplied")?,
            }
        }
        "stake" => {
            let tag = leading_tag(&rest, "stake")?;
            let amount = match rest.get(1) {
                Some(a) if !a.starts_with("--") => u64_arg(a, "stake amount")?,
                _ => return Err(Usage("stake needs <tag> <amount> --tier <0..5>".into())),
            };
            if amount == 0 {
                return Err(Usage("stake: an amount of zero is refused by the node".into()));
            }
            let tail = rest.get(2..).unwrap_or(&[]);
            let mut valued = STAKING_VALUED.to_vec();
            valued.extend(["--tier", "--entitlement"]);
            reject_unknown_flags(tail, &valued, &["--resign", "--no-live-consent"])?;
            let tier = match u64_flag(tail, "--tier")? {
                Some(t) => match u8::try_from(t) {
                    Ok(k) if k < crate::staking::TIERS => k,
                    _ => return Err(Usage(format!("--tier {t}: tiers run 0 to 5"))),
                },
                None => {
                    return Err(Usage(
                        "stake needs --tier <0..5>: the lock is 65,536 x 2^tier heights".into(),
                    ))
                }
            };
            staking_tx(tag, StakingAction::Stake { amount, tier }, tail)?
        }
        "unstake" => {
            let tag = leading_tag(&rest, "unstake")?;
            let tail = rest.get(1..).unwrap_or(&[]);
            let mut valued = STAKING_VALUED.to_vec();
            valued.push("--lock-ends");
            reject_unknown_flags(tail, &valued, &["--resign", "--forfeit"])?;
            staking_tx(tag, StakingAction::Unstake, tail)?
        }
        "accept" => {
            let tag = leading_tag(&rest, "accept")?;
            let tail = rest.get(1..).unwrap_or(&[]);
            let mut valued = STAKING_VALUED.to_vec();
            valued.extend(["--kind", "--peer", "--action", "--slot", "--ip", "--port", "--flags"]);
            valued.extend(["--lock-ends", "--entitlement"]);
            reject_unknown_flags(tail, &valued, &["--resign", "--forfeit", "--unbound-delegate", "--not-staked"])?;
            let network = network_flags(tail)?;
            let terms = consent_terms(tail, network.id)?;
            staking_tx(tag, StakingAction::Accept(terms), tail)?
        }
        "revoke" => {
            let tag = leading_tag(&rest, "revoke")?;
            let tail = rest.get(1..).unwrap_or(&[]);
            reject_unknown_flags(tail, &STAKING_VALUED, &["--resign"])?;
            staking_tx(tag, StakingAction::Revoke, tail)?
        }
        "stake-info" => {
            let (tag, tail) = match rest.first() {
                Some(t) if !t.starts_with("--") => (Some(tag_from_text(t, "tag")?), rest.get(1..).unwrap_or(&[])),
                _ => (None, rest.as_slice()),
            };
            reject_unknown_flags(tail, &["--network", "--t41"], &[])?;
            Command::StakeInfo {
                tag,
                network: network_flags(tail)?,
            }
        }
        "restore" => {
            reject_unknown_flags(&rest, &["--account", "--scan-to"], &[])?;
            let n = u64_flag(&rest, "--account")?
                .ok_or_else(|| Usage("restore needs --account <N>".into()))?;
            let account = u32::try_from(n)
                .map_err(|_| Usage(format!("--account: {n} is out of range")))?;
            Command::Restore {
                account,
                scan_to: index_flag(&rest, "--scan-to")?,
            }
        }
        other => return Err(Usage(format!("unknown command `{other}`"))),
    };

    let dir = dir.ok_or_else(|| Usage("--dir is required".into()))?;
    if let Some(url) = &node {
        if plaintext_off_loopback(url) && !allow_plaintext {
            return Err(Usage(plaintext_node_refusal(url)));
        }
    }

    let node = match (command.needs_node(), node) {
        (true, None) => {
            return Err(Usage(format!(
                "--node is required for `{verb}`, which asks a node before it runs; only \
                 `create` and `address` work without one"
            )))
        }
        (_, node) => node,
    };
    Ok(ParsedArgv::Run(Invocation { dir, node, command }))
}

#[cfg(test)]
mod tests {
    //! Parser cases: which argv is refused, and where help is recognised.
    use super::*;

    fn argv(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    fn refusal(a: &[&str]) -> String {
        match parse(&argv(a)) {
            Err(u) => u.0,
            Ok(other) => panic!("{a:?} parsed rather than being refused: {other:?}"),
        }
    }

    /// The `Spend` a `send` argv parses to, or a panic naming what came back.
    fn sent(a: &[&str]) -> Spend {
        match parse(&argv(a)) {
            Ok(ParsedArgv::Run(inv)) => match inv.command {
                Command::Send(s) => s,
                other => panic!("{a:?} parsed as {other:?}, not a send"),
            },
            other => panic!("{a:?} did not parse as a run: {other:?}"),
        }
    }

    /// Help is recognised where a verb or a global flag is: `help` as the
    /// verb, `-h`/`--help` before it, alone or after a global flag.
    #[test]
    fn help_is_recognised_before_the_verb_or_as_the_verb() {
        for a in [
            vec!["-h"],
            vec!["--help"],
            vec!["help"],
            vec!["--dir", "/d", "--help"],
            vec!["--dir", "/d", "-h", "balance"],
            vec!["--dir", "/d", "--node", "n", "help"],
        ] {
            assert!(matches!(parse(&argv(&a)), Ok(ParsedArgv::Help)), "{a:?} did not ask for help");
        }
    }

    /// After the verb a help spelling is a stray token, refused by name,
    /// like every other -- in a flag position, a tag position or an amount
    /// position alike.
    #[test]
    fn help_after_the_verb_is_an_unexpected_argument() {
        let tag = "0x05ff0f69d4c1cd682ed3341c0b7773054b58800f";
        for (a, token) in [
            (vec!["--dir", "/d", "--node", "n", "balance", "--help"], "--help"),
            (vec!["--dir", "/d", "--node", "n", "send", tag, "-h", "5"], "-h"),
            (vec!["--dir", "/d", "--node", "n", "send", tag, tag, "help"], "help"),
            (vec!["--dir", "/d", "address", "-h"], "-h"),
        ] {
            let u = refusal(&a);
            assert!(
                u.contains(&format!("unexpected argument `{token}`")),
                "{a:?}: the refusal does not name the token: {u}"
            );
            assert!(u.contains("help is `help` as the command"), "{a:?}: the refusal does not say where help is: {u}");
        }
    }

    /// Every flag given twice is a usage error naming the flag: the two
    /// global flags, the two spend flags, the two index flags, `restore`'s
    /// account and the one bare flag. Neither the first nor the last wins.
    #[test]
    fn a_repeated_flag_is_a_usage_error_naming_the_flag() {
        let tag = "0x05ff0f69d4c1cd682ed3341c0b7773054b58800f";
        let to = "0x6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b";
        for (a, flag) in [
            (vec!["--dir", "/a", "--dir", "/b", "balance"], "--dir"),
            (vec!["--dir", "/d", "--node", "n", "--node", "m", "balance"], "--node"),
            (vec!["--dir", "/d", "--node", "n", "send", tag, to, "1", "--fee", "500", "--fee", "600"], "--fee"),
            (vec!["--dir", "/d", "--node", "n", "send", tag, to, "1", "--btl", "1", "--btl", "2"], "--btl"),
            (vec!["--dir", "/d", "--node", "n", "resign", tag, to, "1", "--fee", "500", "--fee", "500"], "--fee"),
            (vec!["--dir", "/d", "--node", "n", "send", tag, to, "1", "--ref", "AB", "--ref", "CD"], "--ref"),
            (vec!["--dir", "/d", "--node", "n", "resign", tag, to, "1", "--ref", "AB", "--ref", "AB"], "--ref"),
            (vec!["--dir", "/d", "--node", "n", "status", tag, "--scan-to", "1", "--scan-to", "2"], "--scan-to"),
            (vec!["--dir", "/d", "--node", "n", "reconcile", tag, "--advance-to", "1", "--advance-to", "1"], "--advance-to"),
            (vec!["--dir", "/d", "--node", "n", "reconcile", tag, "--rollback-to", "1", "--rollback-to", "1"], "--rollback-to"),
            (vec!["--dir", "/d", "--node", "n", "restore", "--account", "0", "--account", "1"], "--account"),
            (vec!["--dir", "/d", "--node", "n", "restore", "--account", "0", "--scan-to", "3", "--scan-to", "4"], "--scan-to"),
            (vec!["--dir", "/d", "create", "--from-phrase", "--from-phrase"], "--from-phrase"),
        ] {
            let u = refusal(&a);
            assert_eq!(u, format!("{flag} given twice"), "{a:?}: the refusal does not name the repeated flag");
        }
        // `address --account N` parses to the derive-only shape; with a tag
        // beside it, or nothing after it, it is refused.
        assert_eq!(
            parse(&argv(&["--dir", "/d", "address", "--account", "1"])).ok(),
            Some(ParsedArgv::Run(Invocation {
                dir: "/d".into(),
                node: None,
                command: Command::Address { tag: None, account: Some(1) },
            }))
        );
        assert!(refusal(&["--dir", "/d", "address", tag, "--account", "1"]).contains("unexpected argument"));
        assert_eq!(refusal(&["--dir", "/d", "address", "--account"]), "--account needs a value");
        // The control: each flag once still parses.
        assert!(parse(&argv(&["--dir", "/d", "--node", "n", "send", tag, to, "1", "--fee", "600", "--btl", "2"])).is_ok());
    }

    /// `--ref` is validated by the node's rule at parse time: accepted values
    /// parse to the NUL-padded field, invalid ones are refused naming the
    /// flag, value and rule, over-long and non-ASCII values have their own
    /// reasons, and no flag gives sixteen zero bytes.
    #[test]
    fn a_reference_is_validated_at_parse_time() {
        let tag = "0x05ff0f69d4c1cd682ed3341c0b7773054b58800f";
        let to = "0x6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b";
        let with = |r: &str| argv(&["--dir", "/d", "--node", "n", "send", tag, to, "1", "--ref", r]);
        for (text, field) in [
            ("AB-00-EF", *b"AB-00-EF\0\0\0\0\0\0\0\0"),
            ("123-CDE-789", *b"123-CDE-789\0\0\0\0\0"),
            ("ABC", *b"ABC\0\0\0\0\0\0\0\0\0\0\0\0\0"),
            ("123", *b"123\0\0\0\0\0\0\0\0\0\0\0\0\0"),
            ("AB-12-CD-34-EF-5", *b"AB-12-CD-34-EF-5"),
        ] {
            match parse(&with(text)) {
                Ok(ParsedArgv::Run(inv)) => match inv.command {
                    Command::Send(s) => assert_eq!(s.dsts[0].reference, field, "--ref {text} did not lay out as expected"),
                    other => panic!("--ref {text} parsed to {other:?}"),
                },
                other => panic!("--ref {text} was refused or read as help: {other:?}"),
            }
        }
        for text in ["AB-CD-EF", "123-456-789", "ABC-", "-123", "ab-00-ef", "AB 00", "AB--00"] {
            let u = refusal(&with(text).iter().map(String::as_str).collect::<Vec<_>>());
            assert!(u.starts_with("--ref: ") && u.contains(text), "the refusal of --ref {text} does not name the flag and the value: {u}");
            assert!(u.contains("node's rule") && u.contains(REFERENCE_RULE), "the refusal of --ref {text} does not carry the rule's words: {u}");
        }
        let long = refusal(&with("AB-12-CD-34-EF-56").iter().map(String::as_str).collect::<Vec<_>>());
        assert!(long.contains("17 characters and the field holds 16"), "seventeen characters: {long}");
        let wide = refusal(&with("AB-\u{e9}0").iter().map(String::as_str).collect::<Vec<_>>());
        assert!(wide.contains("is not ASCII"), "a non-ASCII value: {wide}");
        match parse(&argv(&["--dir", "/d", "--node", "n", "send", tag, to, "1"])) {
            Ok(ParsedArgv::Run(inv)) => match inv.command {
                Command::Send(s) => assert_eq!(s.dsts[0].reference, [0u8; ADDR_REF_LEN], "without --ref the field is not zero"),
                other => panic!("parsed to {other:?}"),
            },
            other => panic!("refused or read as help: {other:?}"),
        }
    }

    /// The explorer verbs' `--count`: default, ceiling, and refusals outside
    /// the Mesh's window.
    #[test]
    fn the_count_flag_defaults_to_five_and_refuses_what_the_mesh_would_ignore() {
        let tag = "0x05ff0f69d4c1cd682ed3341c0b7773054b58800f";
        let base = ["--dir", "/d", "--node", "n"];
        let run = |a: &[&str]| parse(&argv(&[&base[..], a].concat()));
        match run(&["blocks"]) {
            Ok(ParsedArgv::Run(i)) => assert_eq!(i.command, Command::Blocks { count: DEFAULT_COUNT }),
            other => panic!("blocks did not default: {other:?}"),
        }
        match run(&["recent-transactions", tag]) {
            Ok(ParsedArgv::Run(i)) => match i.command {
                Command::RecentTransactions { count, .. } => assert_eq!(count, DEFAULT_COUNT),
                other => panic!("not a recent-transactions: {other:?}"),
            },
            other => panic!("recent-transactions did not default: {other:?}"),
        }
        match run(&["blocks", "--count", "100"]) {
            Ok(ParsedArgv::Run(i)) => assert_eq!(i.command, Command::Blocks { count: MAX_COUNT }),
            other => panic!("the ceiling itself was refused: {other:?}"),
        }
        // Outside the window the endpoint would silently answer ten rows.
        for bad in ["0", "101", "250"] {
            let e = refusal(&[&base[..], &["blocks", "--count", bad]].concat());
            assert!(e.contains(&format!("--count: {bad} is outside 1..=100")), "{e}");
            assert!(e.contains("its own default of ten rows"), "{e}");
        }
        println!("  --count: defaults to {DEFAULT_COUNT}, takes {MAX_COUNT}, refuses 0 and 101 with the endpoint's reason");
    }

    /// `recent-transactions`' `--from`: the default, the ceiling, the
    /// refusal above it, and `--count` beside it in either order.
    #[test]
    fn the_from_flag_defaults_to_the_newest_and_refuses_what_the_mesh_cannot_decode() {
        let tag = "0x05ff0f69d4c1cd682ed3341c0b7773054b58800f";
        let base = ["--dir", "/d", "--node", "n"];
        let run = |a: &[&str]| parse(&argv(&[&base[..], a].concat()));
        let read = |a: &[&str]| match run(a) {
            Ok(ParsedArgv::Run(i)) => match i.command {
                Command::RecentTransactions { count, from, .. } => (count, from),
                other => panic!("not a recent-transactions: {other:?}"),
            },
            other => panic!("{a:?} was refused or read as help: {other:?}"),
        };
        assert_eq!(read(&["recent-transactions", tag]), (DEFAULT_COUNT, 0));
        assert_eq!(read(&["recent-transactions", tag, "--from", "100"]), (DEFAULT_COUNT, 100));
        assert_eq!(read(&["recent-transactions", tag, "--from", "200", "--count", "100"]), (100, 200));
        assert_eq!(read(&["recent-transactions", tag, "--count", "100", "--from", "200"]), (100, 200));
        let top = MAX_FROM.to_string();
        assert_eq!(read(&["recent-transactions", tag, "--from", &top]), (DEFAULT_COUNT, MAX_FROM));
        assert_eq!(MAX_FROM, 9_223_372_036_854_775_807);
        // Above `i64::MAX` the endpoint cannot decode the request.
        for bad in ["9223372036854775808", &u64::MAX.to_string()] {
            let e = refusal(&[&base[..], &["recent-transactions", tag, "--from", bad]].concat());
            assert!(e.contains(&format!("--from: {bad} is outside 0..=9223372036854775807")), "{e}");
            assert!(e.contains("invalid request"), "{e}");
        }
        // The count's window still holds beside it, and neither flag twice.
        let e = refusal(&[&base[..], &["recent-transactions", tag, "--from", "1", "--count", "0"]].concat());
        assert!(e.contains("--count: 0 is outside 1..=100"), "{e}");
        let e = refusal(&[&base[..], &["recent-transactions", tag, "--from", "1", "--from", "2"]].concat());
        assert!(e.contains("--from given twice"), "{e}");
        // `blocks` takes no offset.
        let e = refusal(&[&base[..], &["blocks", "--from", "1"]].concat());
        assert!(e.contains("unexpected argument `--from`"), "{e}");
        println!("  --from: defaults to 0, takes {MAX_FROM}, refuses the next with the endpoint's reason");
    }

    /// `discover`'s `--to`: the default, the bounds, and the refusals.
    #[test]
    fn the_discover_to_flag_defaults_to_sixty_four_and_refuses_outside_its_own_window() {
        let base = ["--dir", "/d", "--node", "n"];
        let run = |a: &[&str]| parse(&argv(&[&base[..], a].concat()));
        match run(&["discover"]) {
            Ok(ParsedArgv::Run(i)) => assert_eq!(i.command, Command::Discover { to: DISCOVER_DEFAULT_TO }),
            other => panic!("discover did not default: {other:?}"),
        }
        match run(&["discover", "--to", "1024"]) {
            Ok(ParsedArgv::Run(i)) => assert_eq!(i.command, Command::Discover { to: DISCOVER_MAX_TO }),
            other => panic!("the ceiling itself was refused: {other:?}"),
        }
        match run(&["discover", "--to", "1"]) {
            Ok(ParsedArgv::Run(i)) => assert_eq!(i.command, Command::Discover { to: 1 }),
            other => panic!("the floor itself was refused: {other:?}"),
        }
        // Every refusal names the bounds and echoes the value; the reasons
        // are checked by the two tests below.
        for bad in ["0", "1025", "1000000"] {
            let e = refusal(&[&base[..], &["discover", "--to", bad]].concat());
            assert!(e.contains(&format!("--to: {bad} is outside 1..=1024")), "{e}");
        }
        // And the flag obeys the parser's own rules: given twice, and given
        // without a value.
        assert!(refusal(&[&base[..], &["discover", "--to", "2", "--to", "3"]].concat()).contains("--to given twice"));
        assert!(refusal(&[&base[..], &["discover", "--to"]].concat()).contains("--to needs a value"));
        assert!(refusal(&[&base[..], &["discover", "7"]].concat()).contains("unexpected argument `7`"));
        println!("  --to: defaults to {DISCOVER_DEFAULT_TO}, takes 1 and {DISCOVER_MAX_TO}, refuses 0 and 1025 with this program's own reason");
    }

    /// `reconcile` takes exactly one of `--advance-to` and `--rollback-to`.
    #[test]
    fn reconcile_takes_one_direction() {
        let tag = "0x05ff0f69d4c1cd682ed3341c0b7773054b58800f";
        let base = ["--dir", "/d", "--node", "n", "reconcile", tag];
        match parse(&argv(&[&base[..], &["--rollback-to", "3"]].concat())) {
            Ok(ParsedArgv::Run(i)) => assert!(
                matches!(i.command, Command::Rollback { rollback_to: 3, .. }),
                "{:?}",
                i.command
            ),
            other => panic!("--rollback-to 3 did not parse to a rollback: {other:?}"),
        }
        match parse(&argv(&[&base[..], &["--advance-to", "3"]].concat())) {
            Ok(ParsedArgv::Run(i)) => assert!(
                matches!(i.command, Command::Reconcile { advance_to: 3, .. }),
                "{:?}",
                i.command
            ),
            other => panic!("--advance-to 3 did not parse to an advance: {other:?}"),
        }
        assert_eq!(
            refusal(&[&base[..], &["--advance-to", "3", "--rollback-to", "2"]].concat()),
            "reconcile takes --advance-to or --rollback-to, not both"
        );
        assert_eq!(refusal(&base), "reconcile needs --advance-to <N> or --rollback-to <N>");
    }

    /// `--to 0` is refused with zero's reason and not the ceiling's.
    #[test]
    fn the_to_refusal_for_zero_is_about_zero_and_not_about_the_ceiling() {
        let base = ["--dir", "/d", "--node", "n"];
        let e = refusal(&[&base[..], &["discover", "--to", "0"]].concat());
        assert!(e.contains("--to: 0 is outside 1..=1024"), "the bounds and the value are not both named: {e}");
        assert!(e.contains("searches only account index 0"), "zero's refusal does not give zero's reason: {e}");
        assert!(e.contains("`address` with no argument"), "zero's refusal does not name the verb that answers it: {e}");
        assert!(
            !e.contains("thousands of round trips"),
            "zero's refusal carries the CEILING's reason, which is the defect the split fixed: {e}"
        );
        println!("  --to 0: refused with zero's own reason, and without the ceiling's");
    }

    /// `--to` above the ceiling is refused with the ceiling's reason and not
    /// zero's: one past the ceiling, a typical typo, and a value past `u32`
    /// (which fails `try_from` rather than the range test).
    #[test]
    fn the_to_refusal_above_the_ceiling_is_about_the_ceiling_and_not_about_zero() {
        let base = ["--dir", "/d", "--node", "n"];
        for bad in ["1025", "2000", "4294967296"] {
            let e = refusal(&[&base[..], &["discover", "--to", bad]].concat());
            assert!(e.contains(&format!("--to: {bad} is outside 1..=1024")), "the bounds and the value are not both named: {e}");
            assert!(e.contains("one call to the node"), "the ceiling's refusal does not give the ceiling's reason: {e}");
            assert!(e.contains("Name a bound at or below 1024"), "the ceiling's refusal does not say what to type instead: {e}");
            assert!(
                !e.contains("bounded at 0") && !e.contains("account index 0"),
                "`--to {bad}` is told about account index 0, which is the defect the split fixed: {e}"
            );
        }
        println!("  --to above the ceiling: 1025, 2000 and one past u32 each refused with the ceiling's reason, and without zero's");
    }

    /// `https` and loopback `http` pass; any other `http` node is refused
    /// until `--allow-plaintext-node` is given, and the refusal says what the
    /// link controls.
    #[test]
    fn plaintext_node_off_loopback_needs_the_flag() {
        fn with(n: &str) -> Vec<&str> {
            vec!["--dir", "/d", "--node", n, "balance"]
        }
        fn allowed(n: &str) -> Vec<&str> {
            vec!["--dir", "/d", "--node", n, "--allow-plaintext-node", "balance"]
        }

        // https, and http to every spelling of loopback: no flag, no refusal.
        for ok in [
            "https://api.mochimo.org",
            "http://127.0.0.1:8080",
            "http://127.9.9.9",
            "http://[::1]:8080",
            "http://localhost:8080",
            "http://LocalHost",
            "http://localhost/",
        ] {
            assert!(parse(&argv(&with(ok))).is_ok(), "{ok} was refused without the flag");
        }

        // http anywhere else: refused, and the refusal says what is at stake.
        for bad in ["http://api.mochimo.org", "http://10.0.0.5:8080", "http://127.0.0.1.example.com"] {
            let e = refusal(&with(bad));
            assert!(e.contains("--allow-plaintext-node"), "the refusal does not name the flag: {e}");
            assert!(e.contains("reconciliation"), "the refusal does not say what the link decides: {e}");
            assert!(e.contains("balance"), "the refusal does not say a spend is laid out against it: {e}");
            // And the flag is what clears it.
            assert!(parse(&argv(&allowed(bad))).is_ok(), "{bad} stayed refused with the flag given");
        }
        println!("  --node: https and loopback http pass, other http refused until --allow-plaintext-node");
    }

    /// `block 0` is refused, because the endpoint serves index 0 as the tip.
    #[test]
    fn block_zero_is_refused_because_the_mesh_reads_it_as_the_tip() {
        let base = ["--dir", "/d", "--node", "n"];
        let e = refusal(&[&base[..], &["block", "0"]].concat());
        assert!(e.contains("the CURRENT block, not as genesis"), "{e}");
        match parse(&argv(&[&base[..], &["block", "1"]].concat())) {
            Ok(ParsedArgv::Run(i)) => assert_eq!(i.command, Command::Block { at: BlockAt::Index(1) }),
            other => panic!("block 1 did not parse: {other:?}"),
        }
        // A hash, with and without the prefix, is the other form.
        let h = "18593f2f13964e5e2a07f147a7d706292f5638b3894daff55eecf3b1b812ccaf";
        for spelling in [h.to_owned(), format!("0x{h}")] {
            match parse(&argv(&[&base[..], &["block", &spelling]].concat())) {
                Ok(ParsedArgv::Run(i)) => match i.command {
                    Command::Block { at: BlockAt::Hash(got) } => assert_eq!(got[0], 0x18),
                    other => panic!("{spelling} did not parse as a hash: {other:?}"),
                },
                other => panic!("{spelling} did not parse: {other:?}"),
            }
        }
        let e = refusal(&[&base[..], &["block", "deadbeef"]].concat());
        assert!(e.contains("is not a transaction hash"), "{e}");
        println!("  block: 0 refused as the tip's index, a number and a hash in both spellings parse, a short hash is refused");
    }

    /// `transaction <hash>` takes the hash in both spellings and refuses
    /// anything that is not one.
    #[test]
    fn transaction_takes_a_hash_in_either_spelling() {
        let base = ["--dir", "/d", "--node", "n"];
        let h = "18593f2f13964e5e2a07f147a7d706292f5638b3894daff55eecf3b1b812ccaf";
        for spelling in [h.to_owned(), format!("0x{h}")] {
            match parse(&argv(&[&base[..], &["transaction", &spelling]].concat())) {
                Ok(ParsedArgv::Run(i)) => match i.command {
                    Command::LookupTransaction { hash } => assert_eq!(hash[0], 0x18),
                    other => panic!("not a transaction: {other:?}"),
                },
                other => panic!("{spelling} did not parse: {other:?}"),
            }
        }
        assert!(refusal(&[&base[..], &["transaction"]].concat()).contains("transaction needs <hash>"));
        assert!(refusal(&[&base[..], &["transaction", "zz"]].concat()).contains("is not a transaction hash"));
        println!("  transaction: a hash bare or prefixed, and two refusals");
    }

    /// Positional `<to> <amount>` pairs keep their order, `--fee` defaults to
    /// the floor for the destination count, and an odd token count is
    /// refused as a missing amount.
    #[test]
    fn several_destinations_parse_as_pairs() {
        let src = "0x05ff0f69d4c1cd682ed3341c0b7773054b58800f";
        let a = "0x6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b";
        let b = "0x7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c";
        let c = "0x8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d";
        let s = sent(&["--dir", "/d", "--node", "n", "send", src, a, "1", b, "2", c, "3"]);
        assert_eq!(s.dsts.len(), 3, "three pairs did not give three destinations");
        assert_eq!(
            s.dsts.iter().map(|d| d.amount).collect::<Vec<_>>(),
            vec![Some(1), Some(2), Some(3)],
            "the amounts did not stay with their destinations, in order"
        );
        assert_eq!(s.dsts[0].to[0], 0x6b);
        assert_eq!(s.dsts[1].to[0], 0x7c);
        assert_eq!(s.dsts[2].to[0], 0x8d);
        assert_eq!(s.fee_total, MFEE * 3, "--fee did not default to the floor for three");
        assert!(s.dsts.iter().all(|d| d.reference == [0u8; ADDR_REF_LEN]));

        // One destination is the unchanged case: the default is still 500.
        let one = sent(&["--dir", "/d", "--node", "n", "send", src, a, "1"]);
        assert_eq!(one.fee_total, MFEE);
        assert_eq!(one.dsts.len(), 1);

        let odd = refusal(&["--dir", "/d", "--node", "n", "send", src, a, "1", b]);
        assert!(odd.contains("the last destination has no amount"), "{odd}");
        println!(
            "  pairs: three parse in order with fee floor {}, one still defaults to {MFEE}, an odd \
             token count is refused as the missing amount",
            MFEE * 3
        );
    }

    /// The whole-list rules: the count bound, and the duplicate-tag refusal.
    #[test]
    fn the_destination_list_is_bounded_and_refuses_a_repeated_tag() {
        let src = "0x05ff0f69d4c1cd682ed3341c0b7773054b58800f";
        let a = "0x6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b";
        let dup = refusal(&["--dir", "/d", "--node", "n", "send", src, a, "1", a, "2"]);
        assert!(dup.contains("destinations 1 and 2 are the same tag"), "{dup}");
        assert!(dup.contains("mistyped payee"), "{dup}");

        // 257 distinct destinations, built from the index so no two repeat.
        let mut argvv: Vec<String> =
            ["--dir", "/d", "--node", "n", "send", src].iter().map(|s| (*s).to_string()).collect();
        for i in 0..257u32 {
            argvv.push(format!("0x{:040x}", i + 1));
            argvv.push("1".to_string());
        }
        let refs: Vec<&str> = argvv.iter().map(String::as_str).collect();
        let over = refusal(&refs);
        assert!(over.contains("1 to 256 destinations and 257 were given"), "{over}");
        println!("  list: a repeated tag and a 257th destination are both usage errors");
    }

    /// `--ref` names ONE destination's reference, so it is refused with
    /// several; `all` means the whole balance, so it is refused with several.
    #[test]
    fn ref_and_all_are_single_destination_only() {
        let src = "0x05ff0f69d4c1cd682ed3341c0b7773054b58800f";
        let a = "0x6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b";
        let b = "0x7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c";
        let r = refusal(&["--dir", "/d", "--node", "n", "send", src, a, "1", b, "2", "--ref", "ABC"]);
        assert!(r.contains("--ref names one destination's reference and 2 were given"), "{r}");
        let all = refusal(&["--dir", "/d", "--node", "n", "send", src, a, "all", b, "2"]);
        assert!(all.contains("only available for a single destination"), "{all}");

        let one = sent(&["--dir", "/d", "--node", "n", "send", src, a, "all"]);
        assert_eq!(one.dsts.len(), 1);
        assert_eq!(one.dsts[0].amount, None, "`all` did not park the amount as unknown");
        assert!(one.spends_everything());
        println!("  all/--ref: both refused with several destinations; `all` alone parses as an unknown amount");
    }

    /// The `--destinations` text parser: three columns, the third optional,
    /// comments and blank lines skipped, and every refusal naming its line.
    #[test]
    fn a_destinations_file_parses_three_columns_and_names_its_lines() {
        let text = "\
# payroll, October
0x6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b  1000  AB-00-EF

0x7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c  2000   # no reference on this one
0x8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d  3000  INVOICE-99
";
        let d = destinations_from_text(text, "p").unwrap_or_else(|e| panic!("the file parses: {}", e.0));
        assert_eq!(d.len(), 3, "comments and blank lines were not skipped");
        assert_eq!(d[0].reference, *b"AB-00-EF\0\0\0\0\0\0\0\0", "the third column is the reference");
        assert_eq!(d[1].reference, [0u8; ADDR_REF_LEN], "a line without a third column is not zero");
        assert_eq!(d[2].reference, *b"INVOICE-99\0\0\0\0\0\0");
        assert_eq!(d.iter().map(|x| x.amount).collect::<Vec<_>>(), vec![Some(1000), Some(2000), Some(3000)]);

        for (bad, needle) in [
            ("0x6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b\n", "has no amount"),
            ("0x6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b 1 AB-CD-EF\n", "does not follow the node's rule"),
            ("0x6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b 1 ABC junk\n", "unexpected `junk`"),
            ("# only a comment\n", "no destinations"),
        ] {
            let e = destinations_from_text(bad, "p").expect_err(needle);
            assert!(e.0.contains(needle), "wanted {needle:?} in {:?}", e.0);
        }
        println!("  file: three columns with the reference optional, comments and blanks skipped, four refusals by line");
    }
}
