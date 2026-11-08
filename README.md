# Tawara

A command-line Rust wallet for **Mochimo**.

It manages an encrypted local keystore, derives **WOTS+ one-time** signing keys, builds and submits spends through the public Mesh API, and refuses to act on any account whose local key state and the chain disagree. That refusal is intentional: accounts that reconcile keep working, and only a store in which *nothing* reconciled refuses to start.

This repository is one crate (`mochimo-crypto`) and one binary, Tawara (`tawara`). The wallet is specified in full in [`docs/specification.md`](docs/specification.md), and the fixture corpus under `fixtures/` is the executable form of that specification.

Every action is one command that prompts (when needed), prints a report, and exits.

Tawara is maintained, owned and published by **Adequate Systems HK Limited**.

- Original Author: Kami Sama
- Maintainer, owner and publisher: Adequate Systems HK Limited
- Contact: support@adequatelimited.com

---

## Why this wallet feels different

Mochimo does not reuse signing keys the way typical Bitcoin wallets reuse addresses.

Each spend uses a **WOTS+ one-time key**. Signing twice with the same key leaks private material. So this wallet:

1. **Advances** to the next key index and writes that advance to disk **before** it releases a signature.
2. Marks the spend as **reserved** (pending) until the chain shows it landed.
3. **Settles** the reservation locally once the ledger confirms the change key.

That is the reserve → submit → settle cycle. Between reserve and settle, the old key is spent and the new position is not yet confirmed in your store.

It is also why an account **fails closed** when its stored index and the Mesh disagree (invariant **I4**): that account, not the whole store. The command line does not move the index on its own: `reconcile` moves it, and only to the index the chain confirms. **Do not delete the store or reinstall just to get past a refusal** — that is a path back to key reuse.

---

## Requirements

- **Linux, macOS and Windows** — built and tested on **Linux** and **macOS**. On Windows the library's and the command layer's test suites pass, and the program has been run interactively at a Windows 11 console on x86-64: its prompts, `Ctrl-Z`, passwords with non-ASCII characters set on macOS, and a connection to a node all worked. No automated test runs the program on Windows, and that run was elevated, so the permission checks under an ordinary account are untested. On Windows the keystore's permission checks are access lists rather than mode bits, secrets are read from the console rather than `/dev/tty`, and a store is two files rewritten in place rather than one file replaced by a rename — see *Limits*. The BSDs have the Unix interfaces and are untested.
- Rust **1.89+** (see root `Cargo.toml`)
- A normal controlling terminal — the password and the recovery phrase are read from `/dev/tty` (on Windows, the console the program runs in), never from a pipe or a redirect
- Network access for any command that talks to a Mesh node

On some machines Cargo is not on the default `PATH`:

```sh
export PATH="$HOME/.cargo/bin:$PATH"
```

---

## Build

The shipped binary needs TLS (`mesh-https`):

```sh
cargo build --features mesh-https --bin tawara
```

Or run without installing:

```sh
cargo run --features mesh-https --bin tawara -- --help
```

Everything after the `--` is passed to `tawara` itself.

---

## Invocation shape

```text
tawara --dir <DIR> [--node <URL>] [--allow-plaintext-node] <command> ...
```

| Flag | Required? | Meaning |
| --- | --- | --- |
| `--dir <DIR>` | **Always** | Directory that holds the encrypted keystore. There is no default path. |
| `--node <URL>` | For commands that touch the chain | Mesh HTTP(S) base URL. There is no default URL. |
| `--allow-plaintext-node` | Only for a plaintext node off the loopback interface | Accepts an `http://` node that is not `127.0.0.0/8`, `::1` or `localhost`. Without it such a URL is refused. |

Flags take a separate token (`--dir ./my-store`), not `--dir=./my-store`.

**Network identity:** every Mesh request this wallet sends names `{"blockchain":"mochimo","network":"mainnet"}`. Choosing `--node` selects which server you talk to; it does not switch the wallet to a different named network. A common public Mesh endpoint is `https://api.mochimo.org`.

### One-liner template

Replace `<DIR>` and add `--node` when needed:

```sh
cargo run --features mesh-https --bin tawara -- --dir <DIR> <command>
cargo run --features mesh-https --bin tawara -- --dir <DIR> --node https://api.mochimo.org <command>
```

After `cargo build --features mesh-https --bin tawara` you can call the binary directly:

```sh
./target/debug/tawara --dir <DIR> --node https://api.mochimo.org balance
```

---

## Concepts you need before the first spend

### Amounts (nanoMochimo)

All amounts on the command line are **nanoMochimo** (nanoMCM):

```text
1 MCM = 1_000_000_000 nanoMCM
```

Example: `2500000000` nanoMCM = 2.5 MCM.

### Tags, destinations, and ledger addresses

**Prefer Base58 everywhere you type or share an account identity.** That is what other Mochimo wallets show, and it is the only everyday form with a checksum that catches typos. Use `0x`+hex only when you are deliberately pasting a Mesh-style machine value.

| Term | What it is | What to use |
| --- | --- | --- |
| **Destination / tag (Base58)** | Tag + CRC-16, Base58-encoded | **Suggested default.** 22–31 characters. Use this for `<tag>`, `<to>`, and sharing receive addresses. |
| **Tag (hex)** | Raw 20-byte account id | Optional: `0x` + exactly 40 hex. Mesh/machine form; accepted, but most users never need it. |
| **Ledger address** | 40 bytes = tag ‖ hash of the current key | Printed as 80 hex by `address` for diagnostics — **not** a payment destination. |

The CLI accepts a tag or payee as:

- **Base58** (22–31 chars) — **suggested.** Checksum catches typos.
- **`0x` + exactly 40 hex characters** — accepted for Mesh-style paste. The `0x` prefix is **required**. Bare 40-hex is refused on purpose: `address` also prints an 80-hex ledger address, and the second half looks like a tag but is not one you control.

The all-zero tag is refused in both forms.

### Password vs recovery phrase

- The **password** encrypts the store on disk (Argon2id + ChaCha20-Poly1305). Almost every command prompts for it.
- The **BIP39 recovery phrase** is a **backup**, not a login. Only `create` (generate) and `create --from-phrase` deal with it; after that the master seed lives in the encrypted store. `create` generates **24 words**, but `create --from-phrase` accepts **12, 15, 18, 21 or 24**, so a 12- or 18-word phrase from another wallet is not turned away at the prompt — whether it restores *your* accounts is the separate question under **Seed derivation** below.

Minimum password length is **12 characters** (Unicode scalar values).

### Fee and change

Default fee is **500** nanoMCM per destination, and `--fee` is a **total**: it defaults to `500 × <number of destinations>`, which is exactly the protocol floor `MFEE × N`. A fee below that floor is refused before anything is signed.

A spend satisfies:

```text
send_amount + change + fee = observed_balance
```

Change goes back to **your next one-time key** under the same account tag (not to a separate “change address” you pick).

Before reserving a key, the wallet rechecks the plan's key position, source, change address and balance. If state changed while the spend was being prepared, it refuses without consuming the key; review the new state and retry. These reads trust the configured node. Use a trusted node and independently verify its state before signing. An incoming payment after the final check can still invalidate the signed transaction and permanently lock funds, so avoid incoming payments until the spend lands. Never reset the index or sign a different transaction with the reserved key.

To empty an account in one payment, use the keyword `all` as the amount:

```text
tawara ... send <tag> <to> all
```

`all` is `balance − fee`, read at the moment the spend is laid out, so the change is zero. (Typing the number yourself works too — balance `1000000000` with the default fee `500` is `999999500` — but the full balance as `<amount>` always fails, because nothing is left for the fee.) Read the warning `all` prints: an emptied account reads as **not found** to the Mesh until it is paid again, so `settle`, `send` and `resign` naming it are refused and `balance` lists it as unreconciled, while every other account in the store keeps working. `submit` is the only route to a node for that account meanwhile.

### Block-to-live (`--btl`)

- Default **`0`**: never expires (nodes keep it until it lands, subject to their own rules).
- Non-zero `N`: the spend must land by block `N`. Before reserving, the wallet requires a readable tip, `N` later than that tip, and `N` at most 256 blocks ahead. An invalid window or failed tip read leaves the key unused. Expiry before inclusion can still permanently lock funds; the default `0` avoids this expiry risk.
- `--btl` is **signed into the artifact**. If you need `resign` later, you must pass the **same** `--btl` (and the same destination, amount, fee and `--ref`).

### Expected balance (`--expect-balance`)

- `send`, `set-delegate`, `clear-delegate` and `claim` take `--expect-balance N`. The wallet then refuses to reserve a key unless the node reports exactly `N` as the source's spendable balance. Read `N` from a source other than `--node`.
- Without it, the change is computed from the configured node's figure. A false figure is found only after the key has signed, when the node rejects the totals.
- `resign` and `--resign` do not take it: the reserved transaction already fixes the balance, so do not repeat it there.

### What `settle` is (and is not)

`settle` does **not** tell the network “this address is retired.”

The chain already saw the spend. `settle` only updates **your local store**: clear the pending reservation once the Mesh shows the change key on the ledger, so the account is no longer mid-spend.

---

## Commands

### Summary

| Command | Needs `--node`? | Role |
| --- | --- | --- |
| `create [--from-phrase]` | No | Create store + account 0 |
| `address [<tag> \| --account <N>]` | No | Print receive destination(s); `--account N` derives an account the store does not hold, without storing it |
| `balance` | Yes | Balances after reconciliation |
| `send <tag> <to> <amount> [<to> <amount> …]` or `send <tag> --destinations <path>` | Yes | Reserve, sign, print artifact, submit. 1–256 destinations; `<amount>` may be `all` |
| `settle <tag>` | Yes | Clear reservation after chain confirms |
| `resign <tag> <to> <amount> [<to> <amount> …]` or `resign <tag> --destinations <path>` | Yes | Rebuild **identical** artifact and submit |
| `submit <artifact-hex>` | Yes | Write a saved artifact to the socket as it is; opens no store, asks no password |
| `transaction <hash>` | Yes | One transaction from the node's indexer; opens no store |
| `recent-transactions <tag> [--count N] [--from M]` | Yes | What touched a tag, newest first (N defaults to 5), the M newest skipped (M defaults to 0); opens no store |
| `block <number \| hash>` | Yes | One block: its kind, difficulty and haiku, its reward and what it moved; opens no store |
| `blocks [--count N]` | Yes | The newest blocks, one row each with its kind (N defaults to 5); opens no store |
| `mempool [--count N]` | Yes | The transactions the node's queue holds, the first N read whole (N defaults to 5); opens no store |
| `status <tag> [--scan-to M]` | Yes | Report sync / divergence without failing closed |
| `reconcile <tag> --advance-to N` | Yes | Advance after you understand a divergence |
| `reconcile <tag> --rollback-to N` | Yes | Roll back to the index the chain shows behind this store, after a confirmation |
| `restore --account N [--scan-to M]` | Yes | Re-derive an on-chain account into the store |
| `discover [--to N]` | Yes | Ask the node about accounts `0..=N` from your seed (N defaults to 64, max 1024). **Writes nothing**, and never says an account does not exist — only what the node answered |

### Full one-liners

```sh
cargo run --features mesh-https --bin tawara -- --dir <DIR> create
cargo run --features mesh-https --bin tawara -- --dir <DIR> create --from-phrase
cargo run --features mesh-https --bin tawara -- --dir <DIR> address
cargo run --features mesh-https --bin tawara -- --dir <DIR> address <tag>
cargo run --features mesh-https --bin tawara -- --dir <DIR> address --account N

cargo run --features mesh-https --bin tawara -- --dir <DIR> --node https://api.mochimo.org balance
cargo run --features mesh-https --bin tawara -- --dir <DIR> --node https://api.mochimo.org send <tag> <to> <amount>
cargo run --features mesh-https --bin tawara -- --dir <DIR> --node https://api.mochimo.org send <tag> <to1> <amount1> <to2> <amount2> <to3> <amount3>
cargo run --features mesh-https --bin tawara -- --dir <DIR> --node https://api.mochimo.org send <tag> --destinations payees.txt
cargo run --features mesh-https --bin tawara -- --dir <DIR> --node https://api.mochimo.org send <tag> <to> all
cargo run --features mesh-https --bin tawara -- --dir <DIR> --node https://api.mochimo.org send <tag> <to> <amount> --fee N --btl N --ref TEXT
cargo run --features mesh-https --bin tawara -- --dir <DIR> --node https://api.mochimo.org settle <tag>
cargo run --features mesh-https --bin tawara -- --dir <DIR> --node https://api.mochimo.org resign <tag> <to> <amount>
cargo run --features mesh-https --bin tawara -- --dir <DIR> --node https://api.mochimo.org resign <tag> --destinations payees.txt
cargo run --features mesh-https --bin tawara -- --dir <DIR> --node https://api.mochimo.org resign <tag> <to> <amount> --fee N --btl N --ref TEXT
cargo run --features mesh-https --bin tawara -- --dir <DIR> --node https://api.mochimo.org submit <artifact-hex>
cargo run --features mesh-https --bin tawara -- --dir <DIR> --node https://api.mochimo.org status <tag>
cargo run --features mesh-https --bin tawara -- --dir <DIR> --node https://api.mochimo.org status <tag> --scan-to M
cargo run --features mesh-https --bin tawara -- --dir <DIR> --node https://api.mochimo.org reconcile <tag> --advance-to N
cargo run --features mesh-https --bin tawara -- --dir <DIR> --node https://api.mochimo.org discover
cargo run --features mesh-https --bin tawara -- --dir <DIR> --node https://api.mochimo.org discover --to 256
cargo run --features mesh-https --bin tawara -- --dir <DIR> --node https://api.mochimo.org restore --account N
cargo run --features mesh-https --bin tawara -- --dir <DIR> --node https://api.mochimo.org restore --account N --scan-to M
cargo run --features mesh-https --bin tawara -- --dir <DIR> --node https://api.mochimo.org transaction <hash>
cargo run --features mesh-https --bin tawara -- --dir <DIR> --node https://api.mochimo.org recent-transactions <tag> --count 10
cargo run --features mesh-https --bin tawara -- --dir <DIR> --node https://api.mochimo.org block 1078535
cargo run --features mesh-https --bin tawara -- --dir <DIR> --node https://api.mochimo.org blocks --count 10
```

### Command notes

**`create`**  
Creates `<DIR>` and account 0. Generates a 24-word phrase and shows it **once** on the terminal (write it down before confirming). Confirmation asks for words at positions **1, 12, and 24** (fixed positions). Wrong confirmation leaves **nothing** on disk. `--from-phrase` reads an existing phrase instead of generating one.

**`address`**  
Works before the account is funded. Copy and share the **Base58** destination (not the 80-hex ledger address). `--account N` prints the destination of an account the store does not yet hold, derived from its seed and not stored: fund it, then `restore --account N` adds it.

**`balance`**  
Reports every account that reconciled, and prints the full report of every account that did not. It opens as long as **one** account reconciles; a store whose accounts are all unfunded or all at zero balance has nothing to operate and exits with a startup refusal (see below).

**`send`**  
Takes **1 to 256 destinations**: positional `<to> <amount>` pairs, or `--destinations <path>` — a file whose non-empty lines are `<to> <amount> [<ref>]`, `#` starting a comment. The two forms are exclusive, and two destinations sharing a tag are refused as a typo. `--fee` is a total defaulting to `500 × N`. Prints a large hex **artifact**. Keep it until the spend settles. If the process dies after signing, `submit` pushes that printout as it is, and `resign` with identical arguments rebuilds and submits it. `--ref TEXT` sets the reference of a **single** destination (a memo some payees require) — with several, put a reference in the file's third column instead: up to 16 characters of uppercase letters and digits in groups separated by single dashes, **each group all one kind and neighbouring groups of different kinds** — so `AB-00-EF` and `123-CDE-789` are accepted and `AB-CD-EF` is not — checked against the node's rule before anything is asked or signed.

**`settle`**  
Local bookkeeping after the chain shows the spend. Needs the named account to have reconciled; it is refused by name (exit 3) if it did not.

**`submit`**  
Writes a saved artifact (the hex `send` printed) to the socket exactly as it is. Opens no store and asks no password; only the layout is checked. It is the route to the socket for an account the wallet refuses, as after that account was emptied — and the only route left when the emptied account is the store's only one and the wallet will not start at all.

**`resign`**  
Must match the pending spend **exactly** (every destination, every amount, fee, btl, and any `--ref`). The order does not matter — the layout sorts destinations before signing — but every value must be the one that was reserved. The store keeps only the digest, not the destinations, so `resign` cannot tell you what they were: keep your own record. It reproduces the same signature bytes (WOTS+ is deterministic); it does not create a second different signature under the reserved key.

**`transaction` / `recent-transactions` / `block` / `blocks` / `mempool`**  
Read-only. They **open no store and ask no password**, so they work with no wallet on this machine at all; `--dir` is still required and is not touched. `--count` runs 1–100 and defaults to 5 — outside that window the Mesh quietly answers with its own default of ten rows, so a count it would ignore is refused here instead. `recent-transactions --from M` skips the M newest rows to read further back; a page with more after it names the `--from` that reads them, and since new rows arrive at the newest end, a later page can repeat a row that landed in between but never skips one. `block 0` is refused too: the Mesh serves index 0 as the *current* block, not as genesis. Each page names the endpoint it read, because `/block` and `/search/transactions` render the same transaction differently and neither is wrong (see below).

**`status`**  
First tool when something looks wrong. It **reports** divergence instead of refusing the account.

**`reconcile`**  
Only after you have read a divergence report and understand it. `--advance-to N` is checked against the chain; it is not blindly trusted. `--rollback-to N` moves an account back to the index the chain shows behind this store, after you answer `yes` to its warning: the key at that index has signed before and signs again on the next spend, so wait first if the network may still settle.

**`discover`**  
Derives the tags of accounts `0..=N` from the seed in your store and asks the node about each one, then prints what it said per index **and the range it searched**. It writes nothing: no account is added, nothing is reserved, nothing is signed. Accounts you already hold are shown and marked.

Read the page as observations, not as a census. The Mesh answers *account not found* for a tag with no ledger entry, for a tag at zero balance, and for a lookup that failed, and it does not distinguish them — so an index missing from the results is an index the node did not resolve, which is a reason to check the node and the seed, not proof the account does not exist. Raise `--to` if you think the range was too small. An index that did resolve goes into the store with `restore --account N`.

**`restore`**  
Re-derives account `N` and finds its index on chain. The account must already be visible on the chain. Default scan is indices `0..=9999` — the same bound the Mochimo browser extension walks — and `--scan-to` sets it for one run. Every index walked costs a derivation, but only a scan that finds **nothing** pays for the whole bound: a scan stops the moment it matches, so an account a few spends along is found in a few derivations.

---

## Ordinary operator path

1. **Create** the store; write the 24 words on paper.
2. **`address`** — give the Base58 destination to whoever will pay you.
3. Wait for the deposit to confirm on-chain.
4. **`balance`** — confirm the wallet sees funds.
5. **`send`** — keep the printed artifact until settled.
6. **`settle`** — once the chain shows the spend landed.

Example send (placeholders only):

```sh
cargo run --features mesh-https --bin tawara -- --dir <DIR> --node https://api.mochimo.org send <your-base58-tag> <payee-base58> <amount-in-nanoMCM>
```

---

## When an account is refused (exit code 3), and when the wallet will not start (exit code 2)

Reconciliation is **per account**. An account whose state the wallet cannot explain is refused by name, with its full report, and that report is printed on every page the wallet produces until it is resolved — so a store that is not whole says so on every run. **Other accounts in the store keep working**: they reconciled, which means the node returned exactly the address this store derived at their stored position, and that confirmation is about their own key stream and nothing else.

Two different outcomes, and the exit code tells you which:

- **Exit 3**, a page that begins with **REFUSED** — the wallet started, and the account you named is one it cannot explain. Everything else in the store still works.
- **Exit 2**, a page that begins with **WALLET WILL NOT START** — *no* account reconciled, so there is nothing to operate. A store holding one account is in this state whenever that account is.

### “Account not found” from the Mesh

The Mesh tag-resolve endpoint returns “account not found” in **three** states it does **not** distinguish — and three states are not three things that happened to you: the first of them, no ledger entry for this tag, is equally what you get from a `--node` pointed at a chain this account is not on, or from the wrong recovery phrase, which is why the wallet's own report ends by telling you to check both.

1. The tag has **never been funded** on this chain.
2. The tag is on the ledger at **zero balance** (empty accounts are discarded by Mesh quorum behaviour).
3. A **transient** lookup failure (timeouts, nodes between blocks, etc.).

So after you **sweep an account to zero**, that account is refused even though the send succeeded. Its local index may already have advanced (e.g. to `1` after the first spend). That is expected, and it does not touch your other accounts.

The ledger has not lost the account. It keeps a zero-balance entry and keeps rehashing it, so paying the tag makes it visible again **at exactly the address this wallet expects** — the change key of the spend that emptied it — and `settle` then works normally.

**What to do:**

1. Run `status <tag>` (reports without refusing).
2. If you emptied the account on purpose: send a **small** amount to it. **If you have another account in this store with funds, send it from there** — that account is not refused, and this is the whole reason the refusal is per account. Then `settle` if a reservation is still open.
3. If the emptied account is the **only** account in this store, the wallet will not start at all and the payment has to come from somewhere else — another wallet, an exchange, anyone. Nothing local can fix it: the Mesh will not show a zero-balance entry, and querying the full 40-byte address instead of the tag does not get around it either.
4. If the account was never funded: fund it, or do not expect its commands to work yet. `create` and `address` still work without a node.
5. Retry once if you suspect a transient Mesh failure.
6. **Do not** delete the store to force progress.

### Other divergences

If `status` reports a real index mismatch (not merely unresolved tag), read the report carefully. `reconcile … --advance-to N` is for an account the chain shows ahead, after a spend from another install of the same phrase or an older copy of this store. `reconcile … --rollback-to N` is for an account the chain shows behind, after the chain itself rolled back.

---

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | Usage / argv error (including missing `--node` when required) |
| `2` | Startup refused — nothing ran: bad node URL, no TTY, no entropy source, the store would not open, or **no** account reconciled |
| `3` | The command was refused — every refusal from the twelve verbs that open no wallet at all (`create`, `address`, `discover`, `status`, `reconcile`, `restore`, `submit`, `transaction`, `recent-transactions`, `block`, `blocks`, `mempool`), and every refusal from a command that did open one: an account the wallet could not explain, a digest mismatch on `resign`, a `resign` whose reservation the chain has already moved past, and a socket write that failed |

Success reports go to **stdout**. Non-zero reports go to **stderr**. That matters if `send` signs and then the socket write fails: the artifact may be on stderr with exit `3`.

---

## Limits

Known limits of this binary:

- **No default `--dir` / `--node`** — you must pass them.
- **Accounts past 0 enter the store only once funded** — `create` makes account 0; `address --account N` prints account N's destination without storing it; fund that destination, then `restore --account N` adds the account. An unfunded account cannot be stored, because the Mesh cannot tell never-funded from emptied. `discover` will tell you which indices the node *does* resolve, without storing anything — but it cannot tell you that an index has no account, for the same reason.
- **History comes from the Mesh's indexer, and not every deployment runs one** — `transaction` and `recent-transactions` read `/search/transactions`, which a node serves only if it was configured to index. Where it was not, the node does not serve the endpoint at all and answers HTTP 404; where it was and its indexer's database is not connected, it answers code 2, its internal error. Those two verbs report either rather than an empty list, and say which; `block` and `blocks` do not depend on it. History is also rendered *gross* there — a spend's source shows its whole balance leaving and the change coming back as a separate credit — while `block` shows the same spend *net*. Both are correct; each page says which it is showing.
- **An emptied account needs an incoming payment to come back** — the Mesh will not show a tag it holds at zero balance, so that account is refused until someone pays it. Another account in the same store can, which is why only that account is refused. If it is the **only** account in the store, the wallet does not start and the payment has to come from outside. Nothing local fixes it: querying the full 40-byte address instead of the tag does not get around the quorum's zero-discard.
- **Dead reservation** — if the balance changes after signing, the node supplied a false balance, or `--btl` expires, the signed bytes may never be accepted and funds can be permanently locked. `--expect-balance` refuses a false balance before signing, when you read the figure from another source. Clearing the reservation, restoring an old snapshot, or signing a replacement would risk reusing a one-time key. The wallet retains the reservation and explains its state; it has no safe local repair for this protocol limit.
- **Seed derivation** — several schemes exist across Mochimo clients and they do not agree. This wallet matches the **browser extension** scheme (fixture group F). A phrase from another scheme is not refused: it derives a working store whose accounts are empty, which looks exactly like a wallet nobody has paid. `create --from-phrase` says so before it reads anything, and nothing detects the case afterwards, so an empty balance on a phrase from elsewhere is not evidence the funds are gone.
- **Password prompt** — needs a real terminal; cannot be driven from a plain pipe. On Windows that is a console: Windows Terminal, the classic console window, or an editor's terminal that hosts one. A terminal that is not a console — `mintty` without `winpty` — is not known to work; through `winpty` it has worked.
- **On Windows a store is two files, and it moves one way** — `accounts.mks` and `accounts.mks.1`. Every change is written into the one that does not hold the newest state and flushed to the disk before the wallet treats it as done, so a power cut or a system crash cannot bring back a state older than the last change the wallet reported — on a disk that honours the flush, as on Linux and macOS. Keep both files together and delete neither: the wallet refuses a store missing its second file rather than guess what it held. A store copied from Linux or macOS opens on Windows and is converted by its first change there; a store copied from Windows is refused on Linux and macOS, and nothing here converts one back.
- **On Windows, another program can hold the store open** — an antivirus scanner, a search indexer, or a backup or sync agent. When one holds a store file without letting others write to it, the wallet refuses to open the store and nothing is read or changed; the error says so. Run the command again, and if the refusal persists, exclude the keystore directory from that program. While the wallet has a store open, no other program can change or delete its files.
- **Memory is not locked and core dumps are not suppressed** — the master seed, the decrypted store, the password and the expanded signing keys sit in ordinary pageable memory while in use. Each is overwritten on drop, and that is the whole of it: a page already written to swap, a core dump, a hibernation image or an attached debugger are outside what this program addresses. Swap encryption and a core-dump limit are the platform's tools, set outside this process.
- **Interrupting a long scan skips that overwrite** — `restore` and `status` walk key positions with the master seed in memory, up to 10,000 of them, and the overwrite above happens when the seed is dropped. `Ctrl-C` does not drop anything: this program installs no signal handler, so the default disposition ends the process with the seed still in its pages. The library accepts a cancellation predicate (`recon::Cancel`) that lets a caller stop a walk and return normally, but this binary does not use one. Let a long scan finish where you can.

---

## Developer: build, test, lint

```sh
export PATH="$HOME/.cargo/bin:$PATH"

cargo build --workspace
cargo test --workspace --no-fail-fast
cargo clippy --workspace --all-targets -- -D warnings
cargo build --features mesh-https --bin tawara
```

The full test suite replays thousands of fixture vectors and can take several minutes. The invariants (I1–I8) are defined in [`docs/specification.md`](docs/specification.md).

Features of note:

| Feature | Default | Purpose |
| --- | --- | --- |
| `native` | yes | Primitives, keystore, mesh codec, CLI |
| `mesh-http` | no | HTTP transport without TLS (tests) |
| `mesh-https` | no | TLS for the shipped binary |
| `raw-backend` | no | Test-only primitive surface |

---

## Further reading

- [`docs/specification.md`](docs/specification.md) — wire formats, keystore, reconciliation, Mesh client, CLI semantics
- `tawara --help` — the command list built into the binary

---

## Safety reminders

- The **24-word recovery phrase** is full control of the wallet. Anyone who has it can recreate the accounts and spend the funds. Treat it like cash (or more carefully than cash):
  - It is shown **once** at `create` time — write it down before you confirm, then clear the terminal scrollback if you can.
  - Store it **offline** in a secure place you control (e.g. paper or another offline backup). Do not keep the only copy in a screenshot, email, cloud note, chat, or password manager synced to many devices unless you accept that risk.
  - **Never share it** with anyone — not support, not a website, not another “wallet helper,” not this program again except when you deliberately run `create --from-phrase` to restore.
  - If you lose both the phrase and the encrypted store (or forget the store password and lose the phrase), the funds are unrecoverable.
- Treat the **password** as the unlock for the encrypted store file on disk. It is not a substitute for the phrase.
- Keep **`send` artifacts** until `settle` succeeds.
- When an account is refused, read `status` and the report — **do not** wipe local state to silence I4.
- Prefer **Base58** for tags and payees; use `0x`+hex only for Mesh-style values when you must.

---

## License

Copyright Adequate Systems HK Limited.

This project is licensed under the **Mochimo Cryptocurrency Engine License Agreement, version 1.0**. The full text is in [`LICENSE.md`](LICENSE.md).

    This Source Code Form is subject to the terms of the MOCHIMO
    CRYPTOCURRENCY ENGINE LICENSE AGREEMENT, v. 1.0. If a copy of that
    license agreement was not distributed with this file, You can find a
    link to the license at https://www.mochimo.org/license
