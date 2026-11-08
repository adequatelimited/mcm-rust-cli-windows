# Vendored standards text

Byte-for-byte copies of the two published standards whose test vectors the
keystore's primitives are replayed against. They exist so that the literals
in `crates/mochimo-crypto/src/keystore/format.rs` have a provenance a reader
can check on disk rather than a citation to a document off it.

**Never edit the `.txt` files.** What enforces that is
`format::tests::published_vector_literals_match_the_vendored_rfc_text`: it
hashes each file against a literal recorded when the file was fetched and
reads every replayed literal back out of its section, so an edit here reds
the board instead of moving an expectation. What it cannot see is a
coordinated edit to the file, the hash literal and the vector literal
together (P4's matrix row R3) — the copy at the publisher is what a reader
compares against for that, and the command is below. This README is prose
and is editable; the same test requires the two hashes below to appear in
it, so the copy here cannot drift from the asserted one silently.

| file | source | retrieved | bytes | sha256 | replayed by |
| --- | --- | --- | --- | --- | --- |
| `rfc9106.txt` | `https://www.rfc-editor.org/rfc/rfc9106.txt` | 2026-09-06 | 37228 | `855c06f060379e34285e83a217e9069b5c72e161a1e54df9af5cd88dbb231f31` | `argon2id_v13_matches_the_rfc9106_vector` (§5.3) |
| `rfc8439.txt` | `https://www.rfc-editor.org/rfc/rfc8439.txt` | 2026-09-06 | 88847 | `25bef70fbf7a07ff45c2fe4cb7c6ce954eac687413d8610603268b4e4415324c` | `chacha20poly1305_matches_rfc8439` (§2.8.2) |

To re-establish that a copy is the published file:

```sh
curl -sSL -o /tmp/rfc9106.txt https://www.rfc-editor.org/rfc/rfc9106.txt && shasum -a 256 /tmp/rfc9106.txt docs/standards/rfc9106.txt
```

Both hashes were also corroborated offline when they were recorded: the
`argon2` 0.5.3 crate's own `tests/kat.rs` (pinned by `Cargo.lock`'s
checksum) carries the RFC 9106 §5.3 Argon2id tag byte for byte, transcribed
by a different party from the draft that became the RFC.

`rfc9106.txt` begins with a UTF-8 byte-order mark (`ef bb bf`) and
`rfc8439.txt` with three blank lines; both are kept exactly as served, which
is what the hash pins. The test embeds the files with `include_bytes!`, so no
toolchain text-normalisation stands between the file and the hash
(`include_str!` was measured to preserve the byte-order mark on this
toolchain too — nine bytes in, nine out — but the bytes route needs no such
measurement). `.gitattributes` marks the files `-text` so a checkout with
line-ending conversion would not change the bytes the test hashes; that is a
prophylactic for a checkout this project does not use, and no test here
exercises it.

Each file is reproduced unmodified and carries its own Copyright Notice,
which reads in part: "This document is subject to BCP 78 and the IETF
Trust's Legal Provisions Relating to IETF Documents
(https://trustee.ietf.org/license-info) in effect on the date of publication
of this document." Neither BCP 78 nor those provisions is vendored here, and
this file makes no claim beyond quoting the notice.
