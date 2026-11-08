// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

#![cfg(not(miri))]
//! Invariant checks over this crate's source, fixture corpus, documents and
//! libtest run lists. Several spawn `cargo` or a sibling test binary, so the
//! file is excluded under Miri, which cannot spawn processes.
//!
//! The specification (`docs/specification.md`, "Invariants") describes what
//! these checks hold. Where a check requires another test, it requires that
//! test's execution, through the `census` module, not its name in source.

// `support` is shared by every test binary; this one uses only the fixture
// loader. The allow is scoped to this binary so dead helpers still warn in
// the other test targets.
#[allow(dead_code)]
mod support;
#[path = "support/keystore_harness.rs"]
mod keystore_harness;
#[path = "support/drop_witness.rs"]
mod drop_witness;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use mochimo_crypto::consts::SEED_LEN;
use mochimo_crypto::Secret;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate lives at <repo>/crates/mochimo-crypto")
        .to_path_buf()
}

/// `text` with `//` line comments and `/* */` block comments blanked out.
///
/// Checks that search source for a symbol must not match a comment that
/// mentions it. String, char and raw-string literals are opaque to the
/// comment scanner and are emitted verbatim, because downstream checks search
/// for quoted names. A bare `'` is a lifetime.
///
/// # Panics
///
/// On an unterminated block comment, string or raw string, rather than
/// silently truncating the output.
fn code_only(text: &str) -> String {
    strip_comments(text)
}

fn strip_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let b = text.as_bytes();
    let mut i = 0usize;
    // Emits a quoted run verbatim and returns the index after its delimiter.
    let emit_string = |out: &mut String, open: usize, delim: u8| -> usize {
        let mut j = open + 1;
        let end = loop {
            if j >= b.len() {
                panic!(
                    "code_only: string opened at byte {open} and never closed. \
                     Everything after it would be discarded. This is the \
                     stripper reporting on its input, not a claim about \
                     whatever check called it."
                );
            }
            match b[j] {
                // Skip the escaped byte. Landing mid-UTF-8 is harmless: a
                // continuation byte is never `\` or a delimiter.
                b'\\' => j += 2,
                c if c == delim => break j,
                _ => j += 1,
            }
        };
        out.push_str(&text[open..=end]);
        end + 1
    };
    while i < b.len() {
        if b[i..].starts_with(b"/*") {
            let Some(rel) = text[i + 2..].find("*/") else {
                panic!(
                    "code_only: block comment opened at byte {i} and never closed. \
                     Everything after it would be discarded. This is the stripper \
                     reporting on its input, not a claim about whatever check \
                     called it."
                );
            };
            i += 2 + rel + 2;
        } else if b[i..].starts_with(b"//") {
            match text[i..].find('\n') {
                Some(rel) => i += rel,
                // A line comment running to EOF discards nothing but itself.
                None => break,
            }
        } else if (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_'))
            && matches!(b[i], b'r' | b'b' | b'c')
        {
            // Raw strings have no escapes and a quote-plus-hashes delimiter,
            // so they cannot go through `emit_string`.
            match raw_string_len(b, i) {
                Some(RawString::Terminated(n)) => {
                    out.push_str(&text[i..i + n]);
                    i += n;
                }
                Some(RawString::Unterminated) => panic!(
                    "code_only: raw string opened at byte {i} and never closed. \
                     Everything after it would be discarded. This is the \
                     stripper reporting on its input, not a claim about \
                     whatever check called it."
                ),
                // Not a raw string: an ordinary identifier byte.
                None => {
                    out.push(char::from(b[i]));
                    i += 1;
                }
            }
        } else if b[i] == b'"' {
            i = emit_string(&mut out, i, b'"');
        } else if b[i] == b'\'' {
            match char_literal_len(b, i) {
                Some(n) => {
                    out.push_str(&text[i..i + n]);
                    i += n;
                }
                // Not a char literal, so a lifetime (`&'a`).
                None => {
                    out.push('\'');
                    i += 1;
                }
            }
        } else {
            out.push(text[i..].chars().next().unwrap_or('\0'));
            i += text[i..].chars().next().map_or(1, char::len_utf8);
        }
    }
    out
}

/// The byte length of the Rust char literal starting at `i`, or `None` if
/// what starts there is not one (a lifetime such as `&'a str`).
fn char_literal_len(b: &[u8], i: usize) -> Option<usize> {
    if b.get(i + 1) == Some(&b'\\') {
        // `'\''` closes at i+3, so the search starts there. The window covers
        // the longest escape, `'\u{10FFFF}'`.
        let hi = b.len().min(i + 14);
        return b
            .get(i + 3..hi)
            .and_then(|w| w.iter().position(|&c| c == b'\''))
            .map(|rel| 3 + rel + 1);
    }
    // One char, possibly multi-byte, then a closing quote.
    let mut j = i + 2;
    while j < b.len() && (b[j] & 0xC0) == 0x80 {
        j += 1;
    }
    (b.get(j) == Some(&b'\'')).then_some(j + 1 - i)
}

/// What [`raw_string_len`] found at a position that opens a raw string.
///
/// A malformed literal is reported as `Unterminated` rather than treated as
/// ordinary code.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RawString {
    /// Byte length of the whole literal, prefix and closing hashes included.
    Terminated(usize),
    Unterminated,
}

/// The Rust raw string starting at `i`, if one starts there.
///
/// Accepts an optional `b` or `c` prefix, `r`, any number of `#` (including
/// zero), then `"`. The literal ends at the first `"` followed by exactly that
/// many `#`; there are no escapes inside. The caller checks the left boundary
/// so that `our"` and `for#"` cannot open one.
fn raw_string_len(b: &[u8], i: usize) -> Option<RawString> {
    let mut j = i;
    if matches!(b.get(j), Some(&b'b') | Some(&b'c')) {
        j += 1;
    }
    if b.get(j) != Some(&b'r') {
        return None;
    }
    j += 1;
    let first_hash = j;
    while b.get(j) == Some(&b'#') {
        j += 1;
    }
    let hashes = j - first_hash;
    if b.get(j) != Some(&b'"') {
        return None;
    }
    let mut k = j + 1;
    while k < b.len() {
        if b[k] == b'"' && b[k + 1..].iter().take(hashes).filter(|&&c| c == b'#').count() == hashes {
            return Some(RawString::Terminated(k + 1 + hashes - i));
        }
        k += 1;
    }
    Some(RawString::Unterminated)
}

/// The extent of a Rust raw string at `i`, in any spelling, or `None`.
///
/// A second reader of the same grammar as [`raw_string_len`], written
/// separately so a defect must occur in both to go unnoticed. An unterminated
/// literal runs to EOF. The grammar is pinned by
/// `stripper_reads_every_raw_string_spelling`; this pins the two readers to
/// each other over the corpus in
/// `code_only_understands_every_construct_its_inputs_contain`.
fn raw_extent(b: &[u8], i: usize) -> Option<usize> {
    if i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_') {
        return None;
    }
    let mut p = i;
    if matches!(b.get(p), Some(&b'b') | Some(&b'c')) {
        p += 1;
    }
    if b.get(p) != Some(&b'r') {
        return None;
    }
    p += 1;
    let first = p;
    while b.get(p) == Some(&b'#') {
        p += 1;
    }
    let hashes = p - first;
    if b.get(p) != Some(&b'"') {
        return None;
    }
    let mut k = p + 1;
    'scan: while k < b.len() {
        if b[k] == b'"' {
            for d in 0..hashes {
                if b.get(k + 1 + d) != Some(&b'#') {
                    k += 1;
                    continue 'scan;
                }
            }
            return Some(k + 1 + hashes);
        }
        k += 1;
    }
    Some(b.len())
}

#[test]
fn raw_extent_agrees_with_the_strippers_own_reader() {
    // Both readers, on constructed cases the tree may not contain.
    for src in [
        "r\"a // b\"",
        "r#\"a\" // b\"#",
        "r##\"a\"# /* b\"##",
        "br#\"a\" // b\"#",
        "cr\"a // b\"",
    ] {
        let b = src.as_bytes();
        let mine = raw_extent(b, 0);
        let theirs = raw_string_len(b, 0);
        assert_eq!(
            mine,
            Some(src.len()),
            "raw_extent disagrees with the language on {src:?}"
        );
        assert_eq!(
            theirs,
            Some(RawString::Terminated(src.len())),
            "raw_string_len disagrees with the language on {src:?}"
        );
    }
    // Both must decline the same non-raw-string bytes.
    for src in ["our\"x\"", "b\"x\"", "r#fn", "rest"] {
        let b = src.as_bytes();
        assert_eq!(raw_extent(b, 0), None, "raw_extent took {src:?}");
        assert_eq!(raw_string_len(b, 0), None, "raw_string_len took {src:?}");
    }
}

// -------------------------------------------------------------------------
// Tests of the comment stripper
//
// Constructed inputs rather than corpus scans: the panicking arms cannot be
// reached by any input that compiles.
// -------------------------------------------------------------------------

#[test]
fn stripper_removes_comments_and_keeps_code() {
    assert_eq!(code_only("a /* b */ c"), "a  c");
    assert_eq!(code_only("a // b\nc"), "a \nc");
    // The stripper does not nest block comments: the first closer wins.
    assert_eq!(code_only("a /* b /* c */ d"), "a  d");
}

#[test]
fn stripper_does_not_open_a_comment_inside_a_string() {
    // A glob inside a string must not open a block comment.
    let src = "let g = \"ui/pass/*.rs\"; let x = 1;";
    assert_eq!(code_only(src), src);
    // The literal's contents survive, because downstream checks search for
    // quoted names.
    assert!(code_only(src).contains("\"ui/pass/*.rs\""));
}

#[test]
fn stripper_does_not_close_a_string_on_an_escaped_quote() {
    let src = "let s = \"a \\\" b\"; let x = 1;";
    assert_eq!(code_only(src), src);
}

#[test]
fn stripper_reads_char_literals_and_leaves_lifetimes_alone() {
    // A quote char literal and lifetimes both break a naive quote tracker.
    let quote_char = "let q = '\"'; let s = \"x\"; let y = 1;";
    assert_eq!(code_only(quote_char), quote_char);
    let escaped = "let q = '\\''; let s = \"x\"; let y = 1;";
    assert_eq!(code_only(escaped), escaped);
    let lifetime = "fn f<'a>(s: &'a str) -> &'a str { s }";
    assert_eq!(code_only(lifetime), lifetime);
    // A lifetime must not swallow the code up to the next one.
    let two = "fn f<'a, 'b>(x: &'a u8, y: &'b u8) {}";
    assert_eq!(code_only(two), two);
}

#[test]
fn stripper_distributes_over_concatenation() {
    // The corpus-wide property checked by
    // `code_only_understands_every_construct_its_inputs_contain`, on a
    // constructed pair.
    let a = "let g = \"a/*b\";\n";
    let b = "let h = \"c*/d\";\n";
    assert_eq!(
        code_only(&format!("{a}{b}")),
        format!("{}{}", code_only(a), code_only(b))
    );
}

#[test]
#[should_panic(expected = "block comment opened at byte")]
fn stripper_refuses_to_truncate_on_an_unterminated_comment() {
    code_only("let x = 1; /* and then nothing");
}

#[test]
#[should_panic(expected = "string opened at byte")]
fn stripper_refuses_to_truncate_on_an_unterminated_string() {
    code_only("let x = \"and then nothing");
}

// -------------------------------------------------------------------------
// Raw strings
//
// Inputs are ordinary escaped strings whose contents spell a raw string, so
// this file adds no raw-string literal to the corpus it checks.
// -------------------------------------------------------------------------

#[test]
fn stripper_does_not_open_a_comment_inside_a_raw_string() {
    // A quote-pairing stripper reads `"a"` as the whole string and the `//`
    // after it as a comment that swallows the statement's `;`.
    let line = "let s = r#\"a\" // b\"#;\nlet keep = 1;";
    assert_eq!(code_only(line), line);

    // A phantom opener must not reach a real `*/` further down, and the
    // genuine comment must still be stripped.
    let across = "let s = r##\"a\" /* b\"##;\nlet gone = 1; /* x */\nlet keep = 2;";
    assert_eq!(code_only(across), "let s = r##\"a\" /* b\"##;\nlet gone = 1; \nlet keep = 2;");

    // A closer with no opener inside a raw string.
    let closer = "let s = r#\"a\" */ b\"#;\nlet keep = 1;";
    assert_eq!(code_only(closer), closer);
}

#[test]
fn stripper_does_not_apply_escapes_inside_a_raw_string() {
    // `\` is not an escape in a raw string, so `r"a\"` ends at the quote
    // after the backslash.
    let trailing_backslash = "let s = r\"a\\\";\nlet keep = 1;";
    assert_eq!(code_only(trailing_backslash), trailing_backslash);
}

#[test]
fn stripper_reads_every_raw_string_spelling() {
    // Zero, one and two hashes and the `b`/`c` prefixes. Each contains a
    // comment token so an unrecognised spelling shows up as damage.
    for src in [
        "let s = r\"a // b\";\nlet keep = 1;",
        "let s = r#\"a\" // b\"#;\nlet keep = 1;",
        "let s = r##\"a\"# // b\"##;\nlet keep = 1;",
        "let s = br#\"a\" // b\"#;\nlet keep = 1;",
        "let s = cr\"a // b\";\nlet keep = 1;",
    ] {
        assert_eq!(code_only(src), src, "spelling not recognised: {src:?}");
    }

    // The closing delimiter is a quote followed by EXACTLY the opening hash
    // count. A hash after that belongs to the code, not to the literal.
    let extra_hash = "let s = r#\"a\"#;\nlet keep = 1;";
    assert_eq!(code_only(extra_hash), extra_hash);
}

#[test]
fn stripper_does_not_mistake_ordinary_code_for_a_raw_string() {
    // Each contains `r"`, `b"` or `c"` without opening a raw string; if one
    // did, the trailing comment would survive.

    // `r` continuing an identifier: the left-boundary check stops `our"x"`
    // from opening one.
    assert_eq!(code_only("let v = our\"x\"; // c\nlet k = 1;"), "let v = our\"x\"; \nlet k = 1;");
    // A byte string is escaped, not raw: the `\"` must not close it.
    assert_eq!(code_only("let v = b\"x\\\"y\"; // c\nlet k = 1;"), "let v = b\"x\\\"y\"; \nlet k = 1;");
    // A raw *identifier* has hashes and no quote.
    assert_eq!(code_only("let r#fn = 1; // c\nlet k = 2;"), "let r#fn = 1; \nlet k = 2;");
    // A bare `r`, `b` or `c` that begins an ordinary name.
    assert_eq!(code_only("let rest = 1; // c\nlet k = 2;"), "let rest = 1; \nlet k = 2;");

    // The left-boundary rule, on input that is not valid Rust: no valid input
    // reaches it, so this is its only test. `our` and `#` are ordinary bytes,
    // `"a"` is a string and the `//` opens a line comment to the end.
    assert_eq!(code_only("x our#\"a\" // b\"# y"), "x our#\"a\" ");
}

#[test]
#[should_panic(expected = "raw string opened at byte")]
fn stripper_refuses_to_truncate_on_an_unterminated_raw_string() {
    // Must report the stripper and the offset rather than shorten the corpus.
    code_only("let x = r#\"and then nothing");
}

/// Every `.rs` under `crates/*/src/`, as `(path relative to the repo root,
/// raw text)`, sorted by path.
///
/// Walks every crate, so a new crate is covered without being listed. The
/// raw view is for `no_native_endian_conversions_anywhere_in_the_crate`, which
/// lexes and drops comments itself; searching checks use [`crate_sources`].
fn crate_source_files() -> Vec<(String, String)> {
    let root = repo_root();
    let crates = root.join("crates");
    let mut out: Vec<(String, String)> = Vec::new();

    let members = std::fs::read_dir(&crates)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", crates.display()));
    for member in members.flatten() {
        let src = member.path().join("src");
        if !src.is_dir() {
            continue;
        }
        let mut stack = vec![src];
        while let Some(d) = stack.pop() {
            let entries = std::fs::read_dir(&d)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", d.display()));
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    let text = std::fs::read_to_string(&p)
                        .unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()));
                    let name = p
                        .strip_prefix(&root)
                        .unwrap_or(&p)
                        .to_string_lossy()
                        .into_owned();
                    out.push((name, text));
                }
            }
        }
    }
    out.sort();
    out
}

/// [`crate_source_files`] with comments stripped, for checks that search it.
fn crate_sources() -> Vec<(String, String)> {
    crate_source_files()
        .into_iter()
        .map(|(name, text)| {
            let code = code_only(&text);
            (name, code)
        })
        .collect()
}

/// Every `.rs` under this crate's `tests/`, comment-stripped and concatenated
/// in sorted path order, for checks whose subject is the suite itself.
///
/// Stripping means a commented-out test cannot satisfy a search. It is built
/// from `test_source_files()`, which stays raw because
/// `code_only_understands_every_construct_its_inputs_contain` measures
/// `code_only` with it; the `doc_openers >= 200` floor there fails if that
/// walk is ever stripped.
fn test_sources() -> String {
    let mut out = String::new();
    for (_, text) in test_source_files() {
        out.push_str(&code_only(&text));
        out.push('\n');
    }
    // The needle is a literal in this file and matches its own source line.
    // That is intended: the subject is whether the walk picked up
    // `invariants.rs`, so do not construct it from fragments. It keeps the two
    // callers, `group_e_constants_stay_anchored` and
    // `crosscheck_fields_stay_asserted`, from passing over an empty corpus.
    assert!(
        out.contains("fn no_native_endian_conversions_anywhere_in_the_crate"),
        "test_sources() did not pick up invariants.rs; the walk is broken and \
         every check built on it would pass vacuously"
    );
    out
}

// ===========================================================================
// The execution census
// ===========================================================================

/// Asks libtest whether a named test ran and passed.
///
/// Names come from each binary's `--list` and verdicts from libtest's summary
/// line, so a test generated by a macro or inside a `cfg`-gated module is
/// counted as the runner sees it.
/// `execution_census_population_is_libtests_run_list` holds the population to
/// the run list.
///
/// The current test binaries are found by running
/// `cargo test --workspace --no-run --message-format=json` from inside the
/// test; cargo holds no build lock while it runs test binaries. An in-process
/// registry cannot see other test binaries, a written manifest can go stale,
/// and globbing `target/debug/deps/` can pick a binary from another
/// configuration.
///
/// An empty `#[test] fn foo() {}` runs and passes, so every executed target
/// must also print a line reporting what it measured. With `--show-output`, a
/// passing test that printed something gets a `---- <name> stdout ----` block.
///
/// # Limits
///
/// * A passing test with a matching name that prints a plausible evidence line
///   is not detected.
/// * `Tier::Listed` cannot see `#[ignore]`, because `--list` prints an ignored
///   test like any other. `Tier::Executed` counts `passed`, so an ignored test
///   fails it; suite-wide, `no_test_in_the_suite_is_ignored` covers the case.
/// * It shows that a target's assertions ran, not that they are right.
mod census {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Mutex, OnceLock};

    /// Set on every child the census spawns. A child that reaches
    /// [`executables`] panics, so a censused test never runs the census
    /// itself; guard-on-guard edges use [`Tier::Listed`] for this reason.
    const CHILD: &str = "MOCHIMO_CENSUS_CHILD";

    /// How much of libtest's answer a given edge consumes.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum Tier {
        /// The name is in that binary's own `--list`.
        ///
        /// Catches a non-test `fn`, a `cfg`-out, a comment-out and a rename,
        /// but not `#[ignore]` or a hollow body. Used only where executing the
        /// target would re-enter the census.
        Listed,
        /// Spawned, `1 passed`, `0 ignored`, and it printed its measurement.
        Executed,
    }

    /// One guard's demand on one test.
    pub struct Row {
        /// The guard that owns this demand, so renaming a guard is caught.
        pub guard: &'static str,
        pub target: &'static str,
        /// The cargo *target* name, i.e. `tests/compile_fail.rs` is `compile_fail`.
        pub bin: &'static str,
        pub tier: Tier,
        /// A substring the target must print. It is removed before the
        /// integer scan, so digits inside it (`ripemd-160`) cannot meet the
        /// floor.
        pub evidence: &'static str,
        /// The largest integer the target printed must be at least this,
        /// which catches a target that runs over an empty set and reports `0`.
        ///
        /// Every integer printed in the target's block counts, diagnostics
        /// included, so a new print under a censused name can meet the floor
        /// by accident.
        pub floor: u64,
    }

    /// Every demand in this file, in one place.
    ///
    /// `censused_rows_are_bound_to_live_guards` asserts each `guard` is a test
    /// libtest lists. Each floor is set well under the measured value, which is
    /// noted beside it where useful.
    pub const ROWS: &[Row] = &[
        // --- I6's two compiler-held absences and the drop witness ---
        Row {
            guard: "secret_has_no_equality_and_nothing_enforces_it",
            target: "every_ui_case_compiles_or_fails_for_its_pinned_reason",
            bin: "compile_fail",
            tier: Tier::Executed,
            evidence: "compile-fail partition:",
            floor: 4, // the largest integer printed is the fail-case total
        },
        Row {
            guard: "zeroization_has_no_reference_counterpart",
            target: "secret_bytes_are_gone_after_drop",
            bin: "invariants",
            tier: Tier::Executed,
            evidence: "zeroization:",
            floor: 96, // 32 + 64 bytes witnessed across the two widths
        },
        Row {
            guard: "secret_holder_debug_redaction_is_enforced_by_the_scan",
            target: "no_holder_of_key_material_derives_debug",
            bin: "invariants",
            tier: Tier::Executed,
            evidence: "Debug-holder scan:",
            floor: 1,
        },
        Row {
            guard: "key_material_copies_are_enforced_by_the_scan",
            target: "no_key_material_is_copied_into_an_unprotected_buffer",
            bin: "invariants",
            tier: Tier::Executed,
            evidence: "key-material copy scan:",
            floor: 8, // measured 15 expose() sites the AST walk reaches
        },
        // --- oracle-class routing over the corpus ---
        Row {
            guard: "group_c_crosscheck_is_an_executed_oracle",
            target: "group_rx_is_an_oracle_with_no_reference_side",
            bin: "invariants",
            tier: Tier::Executed,
            evidence: "group RX:",
            floor: 10, // measured 26 vectors
        },
        Row {
            guard: "group_f_is_specification_not_crosscheck",
            target: "group_rx_is_an_oracle_with_no_reference_side",
            bin: "invariants",
            tier: Tier::Executed,
            evidence: "group RX:",
            floor: 10, // measured 26 vectors
        },
        Row {
            // Guard-on-guard: executing the target would re-enter the census.
            guard: "group_f_is_specification_not_crosscheck",
            target: "group_c_crosscheck_is_an_executed_oracle",
            bin: "invariants",
            tier: Tier::Listed,
            evidence: "",
            floor: 0,
        },
        // --- group E's 33 constants, compared with the reference fixture ---
        //
        // The comparison lives in `tests/kat.rs`. The row requires that it
        // runs: a `#[cfg]`-ed out checker still contains every constant's name.
        Row {
            guard: "group_e_constants_stay_anchored",
            target: "group_e_constants_match_the_reference",
            bin: "kat",
            tier: Tier::Executed,
            evidence: "group E constants anchored",
            floor: 32, // every integer the constants block carries but sizeof_TX
        },
        // --- Miri's domain over the native backend ---
        Row {
            guard: "memory_safety_is_established_only_for_the_native_paths_miri_walks",
            target: "native_backend_is_clean_under_miri",
            bin: "miri",
            tier: Tier::Executed,
            evidence: "native functions",
            floor: 26, // two thirds of the 39 of 41 measured on this tree
        },
        // --- the transaction codec, in the binary gated on `native` alone ---
        Row {
            guard: "native_transaction_path_is_checked_on_layout_not_acceptance",
            target: "native_transaction_round_trip_needs_no_reference",
            bin: "txwire",
            tier: Tier::Executed,
            evidence: "C-free transaction round trip:",
            // Group D has 49 wire images; the reference rejects 4 (one
            // one-byte-long form and three unknown types), leaving 45 that can
            // round-trip. The proof test asserts the exact count.
            floor: 45,
        },
        // --- I8 ---
        Row {
            guard: "imported_account_restore_is_checked_in_memory_not_on_disk",
            target: "imported_account_restores_from_stored_seed",
            bin: "invariants",
            tier: Tier::Executed,
            evidence: "restore path:",
            floor: 1,
        },
        Row {
            guard: "imported_first_key_is_verified_against_the_root_not_against_an_mcm_capture",
            target: "imported_index_zero_pk_reproduces_the_first_address",
            bin: "invariants",
            tier: Tier::Executed,
            evidence: "I8 first key:",
            floor: 1, // one imported account whose position-0 pk equals its faddress pk
        },
        // --- I2, I3, I4, I5: crash consistency and restore. Each floor comes
        // --- from the invariant's own text; see each guard's doc comment.
        Row {
            guard: "index_is_durable_before_the_receipt_under_syscall_kill_not_power_loss",
            target: "signature_is_not_released_before_the_index_is_durable",
            bin: "invariants",
            tier: Tier::Executed,
            evidence: "I2 durability:",
            floor: 1, // at least one injected crash point between persist and return
        },
        Row {
            guard: "spend_state_is_atomic_under_syscall_kill_not_power_loss",
            target: "spend_state_is_never_observed_half_advanced",
            bin: "invariants",
            tier: Tier::Executed,
            evidence: "I3 atomicity:",
            floor: 4, // temp write, fsync file, rename, fsync dir -- I3's own clause
        },
        Row {
            guard: "startup_refuses_divergence_at_the_wallet_layer_not_at_the_keystore",
            target: "startup_refuses_to_start_on_index_divergence",
            bin: "invariants",
            tier: Tier::Executed,
            evidence: "I4 reconciliation:",
            floor: 2, // local ahead and local behind -- I4's own Test clause
        },
        Row {
            guard: "restore_derives_the_index_within_the_scan_bound_never_from_zero",
            target: "restore_derives_the_index_from_chain_state",
            bin: "invariants",
            tier: Tier::Executed,
            evidence: "I5 restore scan:",
            // Twenty positions, each found by its own restore. One restore per
            // position costs n(n+1)/2 derivations, so the proof walks a short
            // range rather than the default bound.
            floor: 20,
        },
        // --- I4's acknowledged path, run through the shipped binary under a
        // pty against a loopback ledger. The floor is the nine prompts the run
        // answers: nine commands, each opening the store once.
        Row {
            guard: "startup_refuses_divergence_at_the_wallet_layer_not_at_the_keystore",
            target: "pty::reconcile_on_a_real_pty_takes_the_acknowledged_path_the_report_names",
            bin: "cli",
            tier: Tier::Executed,
            evidence: "tty reconcile:",
            floor: 9,
        },
        // --- I6 at rest: needs a real store on disk, so the target lives with
        // the keystore's round-trip tests.
        Row {
            guard: "imported_roots_and_the_master_seed_are_encrypted_at_rest",
            target: "snapshot_bytes_never_contain_the_imported_root",
            bin: "keystore",
            tier: Tier::Executed,
            evidence: "I6 at rest:",
            floor: 1, // one root witnessed absent from the file and present after restore
        },
        // --- I1: four instruments under one guard ---
        Row {
            guard: "key_signs_once_per_keystore_with_the_raw_signer_crate_private_not_absent",
            target: "each_wots_key_signs_once_through_the_receipt_gate",
            bin: "signing",
            tier: Tier::Executed,
            evidence: "I1 one signature:",
            floor: 2, // I1's test clause: sign twice at one index, the second refused
        },
        Row {
            guard: "key_signs_once_per_keystore_with_the_raw_signer_crate_private_not_absent",
            target: "every_ui_case_compiles_or_fails_for_its_pinned_reason",
            bin: "compile_fail",
            tier: Tier::Executed,
            evidence: "compile-fail partition:",
            floor: 4, // the four signing_* cases; their own floor is inside the partition
        },
        Row {
            guard: "key_signs_once_per_keystore_with_the_raw_signer_crate_private_not_absent",
            target: "raw_signer_is_unreachable_from_a_default_features_dependent",
            bin: "signing",
            tier: Tier::Executed,
            evidence: "downstream probe:",
            floor: 2, // the two spellings of the raw signer a dependent can write
        },
        Row {
            guard: "key_signs_once_per_keystore_with_the_raw_signer_crate_private_not_absent",
            target: "no_wallet_visible_fn_hands_out_a_wots_signature",
            bin: "invariants",
            tier: Tier::Executed,
            evidence: "raw-signer route scan:",
            floor: 2, // the two ports of the reference's signer the scan must find private
        },
        // --- I1 across accounts ---
        Row {
            guard: "duplicate_key_streams_are_refused_within_one_keystore_not_across_stores",
            target: "duplicate_key_streams_are_refused_across_kinds_after_reopen",
            bin: "signing",
            tier: Tier::Executed,
            evidence: "I1 stream identity:",
            floor: 2, // both kinds: the two constructors that would carry the identity
        },
        // --- the mesh Reader permission, backed by an executed refusal ---
        Row {
            guard: "mesh_reader_permission_is_backed_by_a_refusing_check",
            target: "attach_refuses_every_mismatched_component",
            bin: "spend",
            tier: Tier::Executed,
            evidence: "attach refusals:",
            floor: 5, // position, public key, signature bytes, public seed, source hash
        },
        // --- The binary's `Terminal` impl, backed by an executed pty run ---
        //
        // The print ban in `the_cli_cannot_reach_around_the_wallet` is a text
        // property; this row shows the impl reaches the operator. The shipped
        // binary runs under script(1)'s pseudo-terminal and answers six prompts
        // across `create` and `create --from-phrase` (3 + 3). It prints no
        // other integer.
        Row {
            guard: "the_cli_cannot_reach_around_the_wallet",
            target: "pty::create_on_a_real_pty_shows_a_phrase_that_recovers_the_store",
            bin: "cli",
            tier: Tier::Executed,
            evidence: "tty create:",
            floor: 6, // measured 6 prompts
        },
        // --- The shared password prompt of the store-opening commands, run
        // under a pty with stderr redirected ---
        //
        // Shows the prompt reaches the screen and not the stderr file. The
        // floor is the prompt count (3 for `create`, 1 for `address`); the test
        // prints no other integer.
        Row {
            guard: "the_cli_cannot_reach_around_the_wallet",
            target: "pty::address_on_a_real_pty_needs_no_node_and_its_prompt_survives_a_redirected_stderr",
            bin: "cli",
            tier: Tier::Executed,
            evidence: "tty password:",
            floor: 4, // measured 4 prompts
        },
    ];

    /// Targets actually spawned this process, for the census's own report.
    static SPAWNED: AtomicUsize = AtomicUsize::new(0);

    pub fn spawned() -> usize {
        SPAWNED.load(Ordering::Relaxed)
    }

    fn repo_root() -> PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("crate lives at <repo>/crates/mochimo-crypto")
            .to_path_buf()
    }

    fn same_file(a: &std::path::Path, b: &std::path::Path) -> bool {
        let ca = std::fs::canonicalize(a).unwrap_or_else(|_| a.to_path_buf());
        let cb = std::fs::canonicalize(b).unwrap_or_else(|_| b.to_path_buf());
        ca == cb
    }

    /// `target name -> current executable`, straight from cargo.
    ///
    /// # Panics
    ///
    /// On any failure to identify the current test binaries, so a guard never
    /// reads "not found" as "the property is unmet".
    pub fn executables() -> &'static BTreeMap<String, Target> {
        static EXES: OnceLock<BTreeMap<String, Target>> = OnceLock::new();
        EXES.get_or_init(|| {
            assert!(
                std::env::var_os(CHILD).is_none(),
                "{CHILD} is set, so this process is a census child, and a \
                 censused test has re-entered the census. Whatever edge led \
                 here must be declared Tier::Listed instead. This is a defect \
                 in the census table, not in the test that tripped it."
            );

            let cargo = std::env::var("CARGO").unwrap_or_else(|_| {
                panic!(
                    "CARGO is unset. Cargo sets it for every test process it \
                     runs, so this test is not being run by cargo and the \
                     census cannot identify the current test binaries. Run the \
                     suite with `cargo test`, not by invoking the binary."
                )
            });

            // Match the outer run's profile. A mismatch fails the identity
            // check below rather than passing silently.
            let me = std::env::current_exe().expect("current_exe");
            let release = me.components().any(|c| c.as_os_str() == "release");

            let mut cmd = Command::new(&cargo);
            cmd.current_dir(repo_root())
                .args(["test", "--workspace", "--no-run", "--message-format=json"]);
            if release {
                cmd.arg("--release");
            }
            let out = cmd
                .output()
                .unwrap_or_else(|e| panic!("could not run `{cargo} test --no-run`: {e}"));
            assert!(
                out.status.success(),
                "`cargo test --workspace --no-run` failed ({}). The census \
                 cannot identify the current test binaries, so no guard built \
                 on it can report anything about its subject.\n{}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            );

            let mut map: BTreeMap<String, Target> = BTreeMap::new();
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };
                if v.get("reason").and_then(|r| r.as_str()) != Some("compiler-artifact") {
                    continue;
                }
                if v.get("profile").and_then(|p| p.get("test")).and_then(|t| t.as_bool())
                    != Some(true)
                {
                    continue;
                }
                let (Some(exe), Some(name), Some(manifest)) = (
                    v.get("executable").and_then(|e| e.as_str()),
                    v.get("target").and_then(|t| t.get("name")).and_then(|n| n.as_str()),
                    v.get("manifest_path").and_then(|m| m.as_str()),
                ) else {
                    continue;
                };
                // The package root, which cargo makes the current directory
                // when it runs this binary; see `run`.
                let pkg_dir = PathBuf::from(manifest)
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new("."))
                    .to_path_buf();
                let t = Target {
                    exe: PathBuf::from(exe),
                    pkg_dir,
                };
                if let Some(prev) = map.insert(name.to_owned(), t) {
                    assert_eq!(
                        prev.exe.as_path(),
                        std::path::Path::new(exe),
                        "cargo reported two different executables for target \
                         `{name}`; the census cannot tell which one the run \
                         used"
                    );
                }
            }
            assert!(
                !map.is_empty(),
                "cargo reported no test executables. Every census result would \
                 be vacuous, so this is a panic and not an empty answer."
            );

            // If the nested resolution differs from the running build
            // (features, profile, target dir), cargo names a different
            // `invariants-<hash>` and the census stops here.
            let theirs = map.get("invariants").unwrap_or_else(|| {
                panic!(
                    "cargo listed no `invariants` test target, but this code is \
                     running inside it. The census cannot establish that it is \
                     looking at the build it is part of."
                )
            });
            assert!(
                same_file(&theirs.exe, &me),
                "cargo resolves the `invariants` test binary to\n  {}\nbut this \
                 process is\n  {}\nso the nested resolution is a different build \
                 configuration from the one running. The sibling paths it \
                 reports would be that other build's, and every census verdict \
                 would be about a tree nobody ran. Re-run the suite with the \
                 same features and profile, as plain `cargo test`; \
                 `cargo test --all-features` is the usual way to arrive here, \
                 because the nested resolution above does not carry that flag.",
                theirs.exe.display(),
                me.display()
            );
            map
        })
    }

    /// One cargo test target: the binary, and the directory cargo runs it in.
    pub struct Target {
        pub exe: PathBuf,
        /// The owning package's root, which cargo runs the binary in; see `run`.
        pub pkg_dir: PathBuf,
    }

    fn exe_for(bin: &str) -> &'static Target {
        executables().get(bin).unwrap_or_else(|| {
            panic!(
                "cargo reported no test executable named `{bin}`. The census \
                 table names it as a binary; either the target was renamed or \
                 removed, or the table is wrong."
            )
        })
    }

    /// libtest's own enumeration for one binary, from `--list`.
    ///
    /// The runner's names are the population the guards are checked against;
    /// a parser can miss a nested or macro-emitted name.
    pub fn listed(bin: &str) -> BTreeSet<String> {
        static LISTS: OnceLock<Mutex<BTreeMap<String, BTreeSet<String>>>> = OnceLock::new();
        let cache = LISTS.get_or_init(|| Mutex::new(BTreeMap::new()));
        let mut g = cache.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(hit) = g.get(bin) {
            return hit.clone();
        }
        let t = exe_for(bin);
        let out = Command::new(&t.exe)
            .args(["--list", "--format", "terse"])
            .env(CHILD, "1")
            .output()
            .unwrap_or_else(|e| panic!("could not list tests in {}: {e}", t.exe.display()));
        assert!(
            out.status.success(),
            "`{} --list` failed ({})",
            t.exe.display(),
            out.status
        );
        let names: BTreeSet<String> = String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| l.strip_suffix(": test"))
            .map(|s| s.to_owned())
            .collect();
        // No floor here: the lib unittest targets legitimately hold zero
        // tests. `check` asserts a non-empty list for the binary it is about
        // to draw a conclusion from.
        g.insert(bin.to_owned(), names.clone());
        names
    }

    /// What libtest said when the target was run on its own.
    #[derive(Clone)]
    pub struct Outcome {
        pub running: usize,
        pub passed: usize,
        pub failed: usize,
        pub ignored: usize,
        /// The `---- <name> stdout ----` block, if the target printed anything.
        pub stdout_block: Option<String>,
        pub raw: String,
    }

    fn parse_outcome(name: &str, text: &str) -> Outcome {
        let mut running = None;
        let (mut passed, mut failed, mut ignored) = (0usize, 0usize, 0usize);
        for line in text.lines() {
            if let Some(rest) = line.trim().strip_prefix("running ") {
                // "running 1 test" / "running 0 tests"
                if let Some(n) = rest.split_whitespace().next().and_then(|n| n.parse().ok()) {
                    running = Some(n);
                }
            }
            if let Some(rest) = line.trim().strip_prefix("test result:") {
                // Read the last two tokens of each segment: the first segment
                // is `ok. 1 passed`, with the verdict in front of the count.
                // Counting `passed` rather than matching `ok` also rejects an
                // ignored test.
                for part in rest.split(';') {
                    let tok: Vec<&str> = part.split_whitespace().collect();
                    let [.., n, what] = tok[..] else { continue };
                    let Ok(n) = n.trim_end_matches('.').parse::<usize>() else {
                        continue;
                    };
                    match what {
                        "passed" => passed = n,
                        "failed" => failed = n,
                        "ignored" => ignored = n,
                        _ => {}
                    }
                }
            }
        }
        // The `--show-output` block ends at the next `---- ` marker or at
        // libtest's `successes:` / `failures:` roll-up.
        let marker = format!("---- {name} stdout ----");
        let block = text.split_once(&marker).map(|(_, after)| {
            after
                .lines()
                .skip(1)
                .take_while(|l| {
                    !l.starts_with("---- ") && *l != "successes:" && *l != "failures:"
                })
                .collect::<Vec<_>>()
                .join("\n")
        });
        Outcome {
            running: running.unwrap_or_else(|| {
                panic!(
                    "libtest printed no `running N tests` line for {name}. The \
                     harness output could not be read, so nothing is known \
                     about whether it ran.\n{text}"
                )
            }),
            passed,
            failed,
            ignored,
            stdout_block: block,
            raw: text.to_owned(),
        }
    }

    /// Run one target on its own and read libtest's verdict.
    pub fn run(bin: &str, name: &str) -> Outcome {
        static RUNS: OnceLock<Mutex<BTreeMap<(String, String), Outcome>>> = OnceLock::new();
        let cache = RUNS.get_or_init(|| Mutex::new(BTreeMap::new()));
        let key = (bin.to_owned(), name.to_owned());
        let mut g = cache.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(hit) = g.get(&key) {
            return hit.clone();
        }
        let t = exe_for(bin);
        // The child inherits this process's environment, which is cargo's:
        // `every_ui_case_compiles_or_fails_for_its_pinned_reason` drives
        // trybuild, which needs `$CARGO`.
        //
        // The working directory is `pkg_dir`, the owning package's root, as
        // cargo uses. From the workspace root trybuild finds no cases and
        // reports `ok` without testing anything.
        let out = Command::new(&t.exe)
            .args(["--exact", name, "--show-output", "--test-threads=1"])
            .env(CHILD, "1")
            .current_dir(&t.pkg_dir)
            .output()
            .unwrap_or_else(|e| panic!("could not run {} --exact {name}: {e}", t.exe.display()));
        SPAWNED.fetch_add(1, Ordering::Relaxed);
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        let outcome = parse_outcome(name, &text);
        g.insert(key, outcome.clone());
        outcome
    }

    /// The largest integer in `block`, with the first occurrence of `needle`
    /// blanked out first, so a digit in the needle (`ripemd-160`) cannot meet
    /// a floor on its own.
    fn max_int(block: &str, needle: &str) -> u64 {
        let scrubbed = if needle.is_empty() {
            block.to_owned()
        } else {
            block.replacen(needle, " ", 1)
        };
        let mut best = 0u64;
        let mut cur = String::new();
        for ch in scrubbed.chars().chain(std::iter::once(' ')) {
            if ch.is_ascii_digit() {
                cur.push(ch);
            } else {
                if !cur.is_empty() {
                    best = best.max(cur.parse().unwrap_or(0));
                    cur.clear();
                }
            }
        }
        best
    }

    fn row(guard: &str, target: &str) -> &'static Row {
        ROWS.iter()
            .find(|r| r.guard == guard && r.target == target)
            .unwrap_or_else(|| {
                panic!(
                    "no census row for ({guard}, {target}). A guard asking for a \
                     target it never declared would otherwise be answered by \
                     silence, which reads exactly like a pass."
                )
            })
    }

    /// The census's answer for one edge.
    ///
    /// `Ok` carries the evidence the target printed, for the guard's own
    /// output. `Err` names which condition failed.
    ///
    /// # Panics
    ///
    /// If the target's binary lists no tests at all, or the row is unknown.
    pub fn check(guard: &str, target: &str) -> Result<String, String> {
        let r = row(guard, target);
        let listed = listed(r.bin);
        assert!(
            !listed.is_empty(),
            "`{}` lists no tests at all, and the census is about to draw a \
             conclusion about `{target}` from that binary. Every verdict would \
             be \"absent\", which is the vacuous answer this module exists to \
             prevent -- so it is a panic about the instrument, not a finding \
             about the subject.",
            r.bin
        );
        if !listed.contains(target) {
            return Err(format!(
                "`{target}` is not in the run list of the `{}` test binary. \
                 libtest lists {} tests there and this is not one of them, so \
                 nothing of that name RUNS -- a plain `fn` with the right name, \
                 a helper that is not a `#[test]`, a `cfg`-ed out item or a \
                 commented-out copy all look like this.",
                r.bin,
                listed.len()
            ));
        }
        if r.tier == Tier::Listed {
            return Ok(format!("listed in `{}`", r.bin));
        }

        let o = run(r.bin, target);
        // Defensive: `--exact <name>` matching nothing prints `running 0
        // tests` and exits 0. The run-list check above normally fires first,
        // but the two are separate processes, so the count is checked here too.
        if o.running != 1 {
            return Err(format!(
                "running `{}` with `--exact {target}` matched {} tests, not 1. \
                 A filter that matches nothing exits 0 and reads exactly like a \
                 pass, which is why this is counted rather than trusted.",
                r.bin, o.running
            ));
        }
        if o.ignored != 0 {
            return Err(format!(
                "`{target}` is #[ignore]d: libtest reported `{} passed; {} \
                 ignored` and still printed `test result: ok`. See \
                 no_test_in_the_suite_is_ignored.",
                o.passed, o.ignored
            ));
        }
        if o.passed != 1 || o.failed != 0 {
            return Err(format!(
                "`{target}` ran and did not pass: {} passed, {} failed.\n{}",
                o.passed,
                o.failed,
                o.raw.trim()
            ));
        }
        let Some(block) = o.stdout_block.as_deref().map(str::trim).filter(|b| !b.is_empty())
        else {
            return Err(format!(
                "`{target}` ran and passed but printed nothing. An EMPTY \
                 `#[test]` body runs and passes -- measured -- so execution \
                 alone does not distinguish it from a real test. The target \
                 must report what it measured on stdout, in a line containing \
                 `{}`.",
                r.evidence
            ));
        };
        if !r.evidence.is_empty() && !block.contains(r.evidence) {
            return Err(format!(
                "`{target}` ran and passed and printed, but its output does not \
                 contain `{}`. Either the target stopped reporting what it \
                 measures, or the census row's needle is stale.\nIt printed: {block}",
                r.evidence
            ));
        }
        let n = max_int(block, r.evidence);
        if n < r.floor {
            return Err(format!(
                "`{target}` reported {n} as its largest measurement, under the \
                 floor of {}. A test that runs over an empty set passes exactly \
                 like one that does the work.\nIt printed: {block}",
                r.floor
            ));
        }
        Ok(block.to_owned())
    }
}

/// The census's population is libtest's run list.
///
/// The witness is a name that libtest and a source parser spell differently:
/// a test inside a `cfg`-gated inline module, listed under its module path.
#[test]
fn execution_census_population_is_libtests_run_list() {
    let mut total = 0usize;
    let mut per_bin: Vec<(String, usize)> = Vec::new();
    for bin in census::executables().keys() {
        let n = census::listed(bin);
        total += n.len();
        per_bin.push((bin.clone(), n.len()));
    }
    // The floor is about two thirds of the measured population, so a
    // truncated population fails while a removed target does not.
    assert!(
        total >= 255,
        "libtest lists {total} tests across {} binaries; it is 383 across 16 \
         on the tree this floor was derived from, and the floor is two thirds \
         of that. Two-sided in spirit: too few and the census is reading a \
         truncated population, and the likeliest cause is that it stopped \
         asking libtest. Re-derive by running this test and reading what it \
         printed, not by arithmetic on the old value: the figure in this \
         message was stale at every one of its previous re-derivations.",
        per_bin.len()
    );

    // A test inside a `cfg`-gated inline module is listed by libtest under
    // its module path; a parser that ignored the gate or the module would
    // spell it differently or list a test the gate removed.
    const MODULE_PATHED: &str = "pty::create_on_a_real_pty_shows_a_phrase_that_recovers_the_store";
    assert!(
        census::listed("cli").contains(MODULE_PATHED),
        "`{MODULE_PATHED}` is not in the `cli` binary's run list under its \
         module path. libtest prints a nested test as `module::name`; a \
         census reading a parse of items rather than libtest's list would not \
         spell it that way, and a `cfg`-removed module would not appear at all."
    );

    println!(
        "  execution census population: {total} tests across {} binaries \
         (libtest's own --list, not a parse); {} target(s) spawned so far in \
         this process",
        per_bin.len(),
        census::spawned()
    );
}

/// Every census row belongs to a guard that runs, and every row is reachable.
///
/// Catches a guard renamed away from its row (its call site moves with it,
/// so nothing else notices the orphaned row), a duplicate row, and a row
/// naming a binary cargo does not build. The row-count floor rises with the
/// table so a table that shed rows fails.
#[test]
fn censused_rows_are_bound_to_live_guards() {
    use std::collections::BTreeSet;

    let rows = census::ROWS;
    assert!(
        rows.len() >= 25,
        "the census table holds {} row(s); this tree's table holds 26, over 20 \
         guards. A table that shrank is \
         guards that stopped being censused.",
        rows.len()
    );

    let mut seen: BTreeSet<(&str, &str)> = BTreeSet::new();
    for r in rows {
        assert!(
            seen.insert((r.guard, r.target)),
            "duplicate census row for ({}, {}). `census::check` takes the \
             first, so the second would be unreachable and its floor and \
             needle would never be applied.",
            r.guard,
            r.target
        );
        assert!(
            census::executables().contains_key(r.bin),
            "census row ({}, {}) names test binary `{}`, which cargo does not \
             build.",
            r.guard,
            r.target,
            r.bin
        );
    }

    let guards = census::listed("invariants");
    let orphans: Vec<&str> = rows
        .iter()
        .map(|r| r.guard)
        .filter(|g| !guards.contains(*g))
        .collect();
    assert!(
        orphans.is_empty(),
        "these census rows name guards that libtest does not list in the \
         `invariants` binary: {orphans:?}.\n\
         A row whose guard was renamed or deleted is a demand nothing makes any \
         more -- it sits in the table looking like coverage. This is the census's \
         own question asked of itself: the set it counts must be the set \
         it checks."
    );

    let owners: BTreeSet<&str> = rows.iter().map(|r| r.guard).collect();
    println!(
        "  census table: {} edge(s) over {} guard(s), every guard live in \
         libtest's run list",
        rows.len(),
        owners.len()
    );
}

/// I1: a WOTS+ secret key signs at most once.
///
/// `wots::sign` and `wots::internals` are `pub(crate)`. `backend` is
/// `pub(crate)` unless the `raw-backend` feature is on, which only the test
/// tree enables. The one public path to a signature is `Keystore::sign_spend`,
/// which consumes an `AdvanceReceipt` (evidence that the key's index advanced
/// durably) and refuses a receipt that does not name the store's live state.
///
/// The bounds in the name:
///
/// * **Per keystore.** Two stores on one seed can each sign position k once;
///   that is I4's and I5's subject. Within one store,
///   `duplicate_key_streams_are_refused_within_one_keystore_not_across_stores`
///   refuses one key stream under two tags, using the identity stored in every
///   record.
/// * **Crate-private, not absent.** In-crate code can call the signer, and a
///   dependent holding secret bytes through `Secret::expose` or `into_records`
///   can re-implement WOTS+. What is enforced is that this crate offers no
///   signer outside `sign_spend`.
///
/// Four census rows enforce it:
/// * `each_wots_key_signs_once_through_the_receipt_gate` (`tests/signing.rs`):
///   two positions signed once each, every second receipt at a spent position
///   refused. Floor 2.
/// * `every_ui_case_compiles_or_fails_for_its_pinned_reason`: the trybuild
///   `signing_*` cases pin `wots::sign` and `wots::internals` private and the
///   receipt consumed and not `Clone`. Floor 4.
/// * `raw_signer_is_unreachable_from_a_default_features_dependent`: a real
///   `cargo check` of a dependent built without `raw-backend` refuses both
///   spellings of the raw signer with E0603. Floor 2. This is the only one that
///   sees the default-features build.
/// * `no_wallet_visible_fn_hands_out_a_wots_signature`: a `syn` scan of the
///   wallet-visible surface for any route to a signature. Floor 2, the two
///   ports of the reference `wots_sign`, both required private.
///
/// Not covered: two keystores on one seed; whether the signed digest is the
/// transaction broadcast; in-crate misuse; fsync that lies and power loss.
/// A refused `sign_spend` consumes its receipt, so the key is skipped, never
/// reused.
#[test]
fn key_signs_once_per_keystore_with_the_raw_signer_crate_private_not_absent() {
    // Anchor A: the raw signer is declared crate-private. Overlaps
    // `ui/fail/signing_raw_signer_is_not_reachable.rs` but names the subject
    // directly.
    const SIGNER: &str = "sign";
    let wots_rs = code_only(&read_crate_file("crates/mochimo-crypto/src/wots.rs"));
    assert!(
        wots_rs.contains(&format!("pub(crate) fn {SIGNER}(")),
        "wots.rs no longer declares `pub(crate) fn {SIGNER}(`. If the raw signer went \
         public again, I1 is unenforced at the source; if it was renamed, this anchor \
         and the compile-fail case both need the new name."
    );
    // Anchor B: the backend seam is crate-private outside the feature.
    const BACKEND: &str = "backend";
    let lib_rs = code_only(&read_crate_file("crates/mochimo-crypto/src/lib.rs"));
    assert!(
        lib_rs.contains(&format!("pub(crate) mod {BACKEND};")),
        "lib.rs no longer declares `pub(crate) mod {BACKEND};` for the build without \
         `raw-backend`. A public backend is a public raw signer."
    );
    // Anchor C: the manifest. `default` does not carry `raw-backend`, which
    // keeps it out of a wallet build, and the dev-dependency on this crate
    // carries it with default features off, which keeps the C-free and Miri
    // configuration free of the C.
    let manifest: toml::Value = toml::from_str(&read_crate_file("crates/mochimo-crypto/Cargo.toml"))
        .unwrap_or_else(|e| panic!("Cargo.toml does not parse: {e}"));
    let default_features: Vec<String> = manifest["features"]["default"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect())
        .unwrap_or_default();
    assert!(
        !default_features.iter().any(|f| f == "raw-backend"),
        "Cargo.toml's `default` features are {default_features:?} and include `raw-backend`: \
         every dependent, wallet included, would see the raw signer."
    );
    assert!(
        manifest["features"].get("raw-backend").is_some(),
        "Cargo.toml declares no `raw-backend` feature; the test tree's route to the \
         backend is gone, and with it the test tree's route to the native primitives."
    );
    let self_dep = &manifest["dev-dependencies"]["mochimo-crypto"];
    assert_eq!(
        self_dep.get("default-features").and_then(|v| v.as_bool()),
        Some(false),
        "the dev-dependency on mochimo-crypto itself must carry `default-features = false`; \
         without it `cargo test --no-default-features --features native` unifies `default` \
         back in and the C-free build links the C."
    );
    let self_features: Vec<&str> = self_dep
        .get("features")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    assert!(
        self_features.contains(&"raw-backend"),
        "the dev-dependency on mochimo-crypto itself no longer turns on `raw-backend`: \
         found {self_features:?}. The test tree would lose the backend."
    );

    let mut owed: Vec<String> = Vec::new();
    const GUARD: &str = "key_signs_once_per_keystore_with_the_raw_signer_crate_private_not_absent";
    for (target, what) in [
        (
            "each_wots_key_signs_once_through_the_receipt_gate",
            "the receipt gate executed over a fixture-anchored account: two positions \
             signed once each under a TypeScript-recorded address, every second receipt \
             at a spent position refused; prints `I1 one signature:` with the count of \
             refusals (floor 2)",
        ),
        (
            "every_ui_case_compiles_or_fails_for_its_pinned_reason",
            "the trybuild partition with its four `signing_*` cases (the raw signer and \
             its internals unnameable, the receipt consumed and not Clone); prints \
             `compile-fail partition:` (floor 4)",
        ),
        (
            "raw_signer_is_unreachable_from_a_default_features_dependent",
            "a `cargo check` of a dependent built WITHOUT `raw-backend`: both spellings \
             of the raw signer refused with E0603, the legitimate `sign_spend` path \
             compiled; prints `downstream probe:` (floor 2)",
        ),
        (
            "no_wallet_visible_fn_hands_out_a_wots_signature",
            "the route scan over the wallet-visible surface: no unrestricted `pub` fn \
             outside the allow-list produces a signature or reaches the signer; prints \
             `raw-signer route scan:` (floor 3)",
        ),
    ] {
        if let Err(why) = census::check(GUARD, target) {
            owed.push(format!("\x20 - {target}: {what}.\n\x20   {why}"));
        }
    }

    assert!(
        owed.is_empty(),
        "I1's enforcement has REGRESSED. Once this red meant `wots::sign` was public \
         and no path demanded a receipt; the signing path demoted the signer to `pub(crate)`, put \
         `backend` behind `raw-backend`, and landed `Keystore::sign_spend` behind the \
         `AdvanceReceipt` -- so this firing means one of the four instruments below, or \
         the demotion itself, went away.\n{}\n\
         Two signatures under one WOTS+ key make forgery tractable and there is no repair \
         after the fact. docs/specification.md I1.",
        owed.join("\n")
    );
}

/// Direct Unix APIs and platform gates are confined to five files.
///
/// * `keystore/perms.rs`: Unix metadata, creation modes and the effective
///   user ID used to check the opened directory's owner.
/// * `keystore/directory.rs`: `rustix` directory-relative operations that keep
///   every store access attached to the verified directory handle. The
///   `rustix::` row covers both this module and the permission model.
/// * `bin/tawara.rs`: the device paths and the `stty` subprocess. The library
///   reaches neither: entropy is a parameter and prompts go through
///   `cli::create::Terminal`.
/// * `lib.rs` and `keystore/mod.rs`: the two `compile_error!` gates. `lib.rs`
///   also matches `/dev/` because its gate's message names the device paths.
///
/// A port can find the direct platform dependencies here. It may also need to
/// change code that relies on platform durability semantics behind standard
/// library APIs; this check only keeps new direct Unix APIs inside the
/// declared boundary.
#[test]
fn the_unix_surface_is_confined_to_the_files_a_port_would_touch() {
    const PERMS: &str = "crates/mochimo-crypto/src/keystore/perms.rs";
    const DIRECTORY: &str = "crates/mochimo-crypto/src/keystore/directory.rs";
    const BIN: &str = "crates/mochimo-crypto/src/bin/tawara.rs";
    const LIB: &str = "crates/mochimo-crypto/src/lib.rs";
    const KEYSTORE: &str = "crates/mochimo-crypto/src/keystore/mod.rs";
    const SURFACE: [(&str, &[&str]); 5] = [
        ("std::os::unix", &[PERMS]),
        ("rustix::", &[DIRECTORY, PERMS]),
        ("/dev/", &[BIN, LIB]),
        ("\"stty\"", &[BIN]),
        ("cfg(not(unix))", &[KEYSTORE, LIB]),
    ];

    let files = crate_sources();
    assert!(
        files.len() >= 10,
        "the walk of crates/*/src found only {} files; an enumeration taken over it is vacuous",
        files.len()
    );

    for (needle, expected) in SURFACE {
        let mut found: Vec<&str> = files
            .iter()
            .filter(|(_, code)| code.contains(needle))
            .map(|(name, _)| name.as_str())
            .collect();
        found.sort_unstable();
        let mut want: Vec<&str> = expected.to_vec();
        want.sort_unstable();
        assert_eq!(
            found, want,
            "the Unix surface moved: `{needle}` is named by a different set of files than this \
             check enumerates.\n  found:    {found:?}\n  expected: {want:?}\nA new file here is \
             another place a port has to find. Put permission checks in `keystore::perms`, \
             directory operations in `keystore::directory`, or terminal and entropy code in \
             the binary; otherwise add the file here with the reason it needs a separate boundary."
        );
    }
}

/// The decision layer carries no prose.
///
/// `cli::outcome` is what a command established and `cli::render` is what
/// the program says about it. A `String` in an outcome variant would let a
/// rendered page pass through a type that claims to be a decision, so no
/// `String` may appear anywhere in `cli/outcome.rs` (comments stripped).
/// `&'static str` is allowed: a fixed string is a readable discriminant.
///
/// `render::outcome` matches `Outcome` exhaustively, so a variant without a
/// rendering is a compile error.
#[test]
fn the_decision_layer_carries_no_prose() {
    let src = code_only(&read_crate_file("crates/mochimo-crypto/src/cli/outcome.rs"));
    assert!(
        src.contains("pub enum Outcome"),
        "the scan did not find `Outcome` in cli/outcome.rs; it is reading the wrong file \
         or the module moved, and a scan that matches nothing holds nothing"
    );
    let hits: Vec<(usize, &str)> = src
        .lines()
        .enumerate()
        .filter(|(_, l)| l.contains("String"))
        .map(|(i, l)| (i + 1, l.trim()))
        .collect();
    assert!(
        hits.is_empty(),
        "cli/outcome.rs names `String`, so a decision can carry a page through the type that \
         says it is a decision:\n{}\nPut the value the sentence is made of in the variant and \
         the sentence in `cli::render`.",
        hits.iter()
            .map(|(n, l)| format!("\x20 - line {n}: {l}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// The route scan behind I1: no wallet-visible function hands out a WOTS+
/// signature except the allow-listed routes. It ranges over the real surface,
/// so a new route fails without anyone having guessed its name.
///
/// # The predicate
///
/// A function is flagged when it is **wallet-visible** and either
/// **produces** a signature-bearing value or **reaches the signer**:
///
/// * *wallet-visible*: declared bare `pub`, inside modules that are bare `pub`
///   all the way up in the wallet view. A `mod` under
///   `cfg(feature = "raw-backend")` is dropped and its `cfg(not(..))` twin
///   kept, so `backend` resolves to `pub(crate)` as a dependent sees it. An
///   impl method needs a bare-`pub` self type; a `pub use` in a visible module
///   lifts what it names.
/// * *produces*: the return type, or a non-`self` `&mut` parameter, mentions a
///   **bearing** type: the fixpoint from the tokens `SIG_LEN`, `WOTSSIGBYTES`
///   and the literal `2144` through type aliases (`Signature`) and fields
///   (`SpendSignature`, `WotsVal`, `Transaction`).
/// * *reaches the signer*: the body fixpoint from the idents `wots_sign`,
///   `wots_sign_counted`, `sign_spend` and the path `wots::sign`, through
///   every function whose body names a tainted one.
///
/// The allow-list is keyed by file and name; an unused entry fails. Each
/// class is checked mechanically (see `Class`).
///
/// # Limits
///
/// In-crate code could re-implement a signer over
/// `backend::native::gen_chain` and `Secret::expose` returning a
/// `PublicKey`-typed value (the same type as `Signature`); that is the
/// "crate-private, not absent" bound of I1. A function taking its secret as a
/// bare `&[u8; 32]` passes the reader check.
///
/// # Controls
///
/// Both ports of the reference `wots_sign` must be found and crate-private;
/// `backend` must resolve restricted; `Signature` must be bearing; at least
/// 150 signatures examined. An embedded control crate checks that a visible
/// wrapper over `wots::sign` and a visible `-> Box<[u8; SIG_LEN]>` flag, and
/// the same under a `pub(crate)` module does not.
#[test]
fn no_wallet_visible_fn_hands_out_a_wots_signature() {
    let files = crate_source_files();
    assert!(files.len() >= 10, "the walk of crates/*/src found only {} files; vacuous", files.len());
    let a = route_scan::analyse(&files, "crates/mochimo-crypto/src/");

    // Controls over the real tree.
    assert!(a.bearing.contains("Signature"), "`Signature` is not a bearing type; the type arm sees nothing");
    assert_eq!(
        a.modules.get("backend").copied(),
        Some(false),
        "`backend` does not resolve to a restricted module in the wallet view: {:?}",
        a.modules.get("backend")
    );
    // The native port and the crate-private wrapper over it.
    for port in ["wots.rs::sign", "backend/native.rs::wots_sign"] {
        assert!(
            a.signers_found.contains(port),
            "the signer port `{port}` was not found; the two ports of wots.c's wots_sign \
             are the scan's positive control, found: {:?}",
            a.signers_found
        );
        assert!(
            !a.visible.contains(port),
            "the signer port `{port}` is wallet-visible; I1's demotion is undone"
        );
    }
    assert!(a.signatures >= 150, "only {} signatures examined; the walk is not reading the tree", a.signatures);

    // The allow-list, keyed `file::Type::fn` (free functions `file::fn`).
    #[derive(Clone, Copy, PartialEq, Debug)]
    enum Class {
        Signer,
        Reader,
        /// A wallet-visible function that reaches the signer only through
        /// `Keystore::sign_spend`, and so inherits its receipt gate.
        ///
        /// Checked below: it must name `sign_spend` and must not name a raw
        /// signer port.
        Composer,
        /// A signer that re-produces a signature the store already released,
        /// with no digest parameter.
        ///
        /// The digest and position come from `Pending`, and WOTS+ is
        /// deterministic, so the output is byte-identical to the signature
        /// already released. Checked below: it takes no 32-byte array
        /// parameter and its body reads `pending`.
        ReSigner,
        /// A wallet-visible entry point that reaches the signer only through a
        /// `Wallet` and returns rendered text.
        ///
        /// Checked below: it must name `Wallet` and must name neither
        /// `sign_spend`/`resign_reserved` nor a raw signer port.
        Entrypoint,
    }
    const ALLOWED: &[(&str, Class, &str)] = &[
        (
            "keystore/sign.rs::Keystore::sign_spend",
            Class::Signer,
            "the one public path to a signature: behind the receipt, re-checking the store's live state",
        ),
        (
            "tx/wire.rs::Transaction::new",
            Class::Reader,
            "assembles a transaction from parts the caller already holds, the WotsVal among them",
        ),
        (
            "tx/wire.rs::Transaction::with_body",
            Class::Reader,
            "Transaction::new's general form: a transaction around a payload the caller already \
             holds -- destinations, a delegate tag, nothing, or a claimed amount -- with a zero \
             WotsVal. It takes no key material and reaches no signer, as `new`, which is now \
             `with_body(Body::Transfer(..))`",
        ),
        (
            "tx/wire.rs::Transaction::from_wire",
            Class::Reader,
            "decodes a wire image, signature included, and produces no signature of its own",
        ),
        (
            "keystore/sign.rs::Keystore::resign_reserved",
            Class::ReSigner,
            "re-produces the signature an outstanding reservation already released, from the \
             store's own Pending record. No digest parameter -- checked below -- so it cannot \
             sign anything but the reserved digest, and determinism makes the bytes identical \
             to what sign_spend already emitted. It exists because rolling the index back to \
             the reserved key is correctly forbidden, so this is the ONLY route by which the \
             funds at that key's address can ever move",
        ),
        (
            "wallet.rs::Wallet::resign_pending",
            Class::Composer,
            "the wallet's half of the recovery: rebuilds the plan from the caller's remembered \
             parameters, REQUIRES the rebuilt digest to equal the reserved one, and only then \
             calls resign_reserved. Composer, not ReSigner: it reaches the signer through the \
             gated one rather than beside it",
        ),
        (
            "wallet.rs::Wallet::reserve_and_sign",
            Class::Composer,
            "the wallet's spend path: persist_advance mints the receipt, sign_spend consumes it, \
             attach assembles the image. It reaches the signer through the gate rather than \
             beside it, so I1's one-receipt-one-signature holds through it -- and a second \
             reservation is refused while the first is unresolved. Composer, not Reader: it \
             takes a KeyAccess, and a permission that pretended otherwise would be the \
             smuggling the Reader check exists to stop",
        ),
        (
            "mesh/spend.rs::SignedTransaction::attach",
            Class::Reader,
            "assembles the wire image from an unsigned plan and a SpendSignature the keystore already \
             released; pk_from_sig is a verifier, every parameter is public data, and the \
             permission is backed by an executed refusing check -- \
             mesh_reader_permission_is_backed_by_a_refusing_check censuses \
             spend.rs::attach_refuses_every_mismatched_component",
        ),
        (
            "cli/mod.rs::run",
            Class::Entrypoint,
            "the CLI's one-line entry: `render(decide(..))` and nothing else. It names no              `Wallet` itself and reaches the signer only through `decide`, whose Entrypoint              permission is checked on its own row below; it hands back a Report, which is text              and an exit code and nothing a signature can be read out of. This is the              delegation clause's only user, and the reason the clause exists",
        ),
        (
            "cli/mod.rs::decide",
            Class::Entrypoint,
            "the CLI's dispatch: it opens a Wallet -- which reconciles every account, partitions              them, and refuses outright only when none reconciled -- and calls              the wallet's own methods, so every route to a signature it has is one the gate              already holds. It hands back a Report, which is text and an exit code; nothing a              signature can be read out of. Eleven commands return before a Wallet exists              (`address`, `restore`, `discover`, `status`, `reconcile`, `submit` and the five              read-only verbs), and `create` never reaches this function at all because there is              no store to hand it; none of those paths signs --              the_cli_cannot_reach_around_the_wallet checks both halves mechanically",
        ),
    ];
    let mut unlisted: Vec<String> = Vec::new();
    let mut used: Vec<&str> = Vec::new();
    let mut readers_verified = 0usize;
    let mut signers_allowed = 0usize;
    let mut composers_verified = 0usize;
    let mut resigners_verified = 0usize;
    let mut entrypoints_verified = 0usize;
    for f in &a.flagged {
        match ALLOWED.iter().find(|(name, _, _)| name == &f.name) {
            None => unlisted.push(format!("{} -> {} [{}]", f.name, f.output, f.why)),
            Some((name, Class::Signer, _)) => {
                used.push(name);
                signers_allowed += 1;
            }
            Some((name, Class::ReSigner, _)) => {
                used.push(name);
                assert!(
                    !f.takes_digest,
                    "{name} is allow-listed as a ReSigner but takes a 32-byte array parameter. \
                     Its ENTIRE safety argument is that the digest is not an input -- it comes \
                     from the store's reservation -- so a digest parameter makes it the \
                     second-signature-under-one-key hole this scan exists to catch"
                );
                assert!(
                    f.reads_pending,
                    "{name} is allow-listed as a ReSigner but its body never names `pending`; \
                     a ReSigner's permission is that it reads the reservation rather than a \
                     caller's argument"
                );
                resigners_verified += 1;
            }
            Some((name, Class::Composer, _)) => {
                used.push(name);
                assert!(
                    f.names_sign_spend,
                    "{name} is allow-listed as a Composer but its body never names `sign_spend`; \
                     a Composer's whole permission is that it reaches the signer THROUGH the \
                     receipt gate"
                );
                assert!(
                    !f.names_raw_signer,
                    "{name} is allow-listed as a Composer but its body names a RAW signer port; \
                     that is a route around the gate, which is the I1 hole this scan exists to \
                     catch"
                );
                composers_verified += 1;
            }
            Some((name, Class::Entrypoint, _)) => {
                used.push(name);
                assert!(
                    !f.names_sign_spend,
                    "{name} is allow-listed as an Entrypoint but its body names `sign_spend` or                      `resign_reserved` directly. An Entrypoint's permission is that it reaches                      the signer only THROUGH a wallet; one that calls the gate itself is a                      Composer and must be listed as one, with that class's checks."
                );
                assert!(
                    !f.names_raw_signer,
                    "{name} is allow-listed as an Entrypoint but its body names a RAW signer                      port; that is a route around the gate, which is the I1 hole this scan                      exists to catch"
                );
                // The gate must be on its path: the body names `Wallet`, or
                // names another allow-listed Entrypoint whose permission is
                // checked on its own row. `run` is `render(decide(..))`, and
                // `decide` opens the `Wallet`.
                let delegates_to_entrypoint = f.body_idents.iter().any(|id| {
                    ALLOWED.iter().any(|(n, c, _)| {
                        matches!(c, Class::Entrypoint)
                            && n.rsplit("::").next().is_some_and(|short| short == id)
                    })
                });
                assert!(
                    f.body_names_wallet || delegates_to_entrypoint,
                    "{name} is allow-listed as an Entrypoint but its body neither names `Wallet`                      nor calls another allow-listed Entrypoint. The permission rests on the gate                      being ON its path; without that it is an unlisted route to a signature."
                );
                entrypoints_verified += 1;
            }
            Some((name, Class::Reader, _)) => {
                used.push(name);
                assert!(
                    !f.reaches_signer,
                    "{name} is allow-listed as a Reader but its body reaches the signer"
                );
                assert!(
                    f.holder_params.is_empty(),
                    "{name} is allow-listed as a Reader but takes key material: {:?}",
                    f.holder_params
                );
                readers_verified += 1;
            }
        }
    }
    let unused: Vec<&str> = ALLOWED
        .iter()
        .map(|(n, _, _)| *n)
        .filter(|n| !used.contains(n))
        .collect();
    assert!(
        unused.is_empty(),
        "allow-list entries matched nothing: {unused:?}. An entry the scan never reaches is a \
         permission nobody is using -- the function moved, was renamed, or stopped being \
         flagged, and the entry would silently cover a newcomer of the same name. Flagged: {:?}",
        a.flagged.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()
    );
    assert_eq!(signers_allowed, 1, "exactly one wallet-visible signer is permitted; found {signers_allowed}");
    assert!(
        unlisted.is_empty(),
        "a wallet-visible function hands out a WOTS+ signature or reaches the signer and is \
         not allow-listed:\n  {}\nEvery such route is a second signer beside `sign_spend`; \
         either it is a reader (takes no key material, reaches no signer -- add it as one, \
         argued) or it is the I1 hole this scan exists to catch.",
        unlisted.join("\n  ")
    );

    // The embedded control: the same `analyse` over a small crate in which a
    // visible wrapper over the signer and a visible bearing return must flag,
    // and the same under a restricted module must not.
    let control: Vec<(String, String)> = vec![
        (
            "ctl/src/lib.rs".to_owned(),
            "pub mod p; pub mod q; pub(crate) mod r; pub mod wots; pub mod consts;".to_owned(),
        ),
        (
            "ctl/src/consts.rs".to_owned(),
            "pub const SIG_LEN: usize = 2144;".to_owned(),
        ),
        (
            "ctl/src/wots.rs".to_owned(),
            "pub type Signature = Box<[u8; crate::consts::SIG_LEN]>; \
             pub(crate) fn sign() -> Signature { todo!() }"
                .to_owned(),
        ),
        (
            "ctl/src/p.rs".to_owned(),
            "pub fn leak(s: &crate::Secret<32>) -> [u8; 32] { let _ = crate::wots::sign(); [0; 32] }".to_owned(),
        ),
        (
            "ctl/src/q.rs".to_owned(),
            "pub fn leak2() -> crate::wots::Signature { todo!() } \
             pub fn fine() -> [u8; 32] { [0; 32] }"
                .to_owned(),
        ),
        (
            "ctl/src/r.rs".to_owned(),
            "pub fn hidden() -> crate::wots::Signature { todo!() }".to_owned(),
        ),
    ];
    let c = route_scan::analyse(&control, "ctl/src/");
    let flagged: Vec<&str> = c.flagged.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(
        flagged,
        vec!["p.rs::leak", "q.rs::leak2"],
        "the embedded control did not flag exactly the visible wrapper (body arm) and the \
         visible bearing return (type arm): {flagged:?}. `r.rs::hidden` is under a \
         pub(crate) module and must not flag; `q.rs::fine` returns nothing bearing."
    );

    println!(
        "  raw-signer route scan: {} crate-private signer(s) recognised, {signers_allowed} \
         wallet-visible signer allow-listed, {readers_verified} reader(s) verified free of key \
         material, {composers_verified} composer(s) verified to reach the signer only through \
         a gated one, {resigners_verified} re-signer(s) verified to take no digest parameter \
         and to read the reservation, {entrypoints_verified} entrypoint(s) verified to reach \
         the signer only through a Wallet, 0 unlisted route(s)",
        a.signers_found.len()
    );
}

/// The machinery of [`no_wallet_visible_fn_hands_out_a_wots_signature`],
/// factored so the same `analyse` runs over the real tree and over the
/// embedded control crate.
mod route_scan {
    use quote::ToTokens;
    use std::collections::{BTreeMap, BTreeSet};

    pub struct Flagged {
        /// `file::Type::fn` or `file::fn`, the file relative to the src root.
        pub name: String,
        pub output: String,
        pub why: &'static str,
        pub reaches_signer: bool,
        /// Parameter types (rendered) that are key-material holders.
        pub holder_params: Vec<String>,
        /// The body names `sign_spend` -- it goes through the gated signer.
        pub names_sign_spend: bool,
        /// Any parameter is a 32-byte array, so a digest could be passed in.
        /// A ReSigner must have this false.
        pub takes_digest: bool,
        /// The body names `pending`: it reads the store's reservation rather
        /// than a caller's argument.
        pub reads_pending: bool,
        /// The body names `Wallet` — the gate is on its path.
        pub body_names_wallet: bool,
        /// Every identifier the body mentions, for the Entrypoint delegation
        /// check.
        pub body_idents: Vec<String>,
        /// The body names a raw signer port (`wots::sign` or a
        /// `backend::*::wots_sign`), which bypasses the receipt gate. A
        /// Composer must have this false.
        pub names_raw_signer: bool,
    }

    pub struct Analysis {
        pub flagged: Vec<Flagged>,
        pub bearing: BTreeSet<String>,
        /// Module path (`a::b`) -> unrestricted in the wallet view.
        pub modules: BTreeMap<String, bool>,
        pub signers_found: BTreeSet<String>,
        pub visible: BTreeSet<String>,
        pub signatures: usize,
    }

    /// `crates/mochimo-crypto/src/keystore/sign.rs` -> (`keystore/sign.rs`, `keystore::sign`).
    fn module_of(rel: &str) -> String {
        let stem = rel.trim_end_matches(".rs");
        if stem == "lib" {
            return String::new();
        }
        let stem = stem.strip_suffix("/mod").unwrap_or(stem);
        stem.replace('/', "::")
    }

    fn idents(tokens: &proc_macro2::TokenStream) -> Vec<proc_macro2::TokenTree> {
        let mut out = Vec::new();
        fn walk(ts: proc_macro2::TokenStream, out: &mut Vec<proc_macro2::TokenTree>) {
            for tt in ts {
                match tt {
                    proc_macro2::TokenTree::Group(g) => walk(g.stream(), out),
                    other => out.push(other),
                }
            }
        }
        walk(tokens.clone(), &mut out);
        out
    }

    fn mentions(tokens: &proc_macro2::TokenStream, names: &BTreeSet<String>) -> bool {
        idents(tokens).iter().any(|t| match t {
            proc_macro2::TokenTree::Ident(i) => names.contains(&i.to_string()),
            proc_macro2::TokenTree::Literal(l) => names.contains(&l.to_string()),
            _ => false,
        })
    }

    /// Does the token stream contain the path `wots :: sign`?
    fn names_wots_sign(tokens: &proc_macro2::TokenStream) -> bool {
        let flat = idents(tokens);
        let texts: Vec<String> = flat.iter().map(|t| t.to_string()).collect();
        texts.windows(3).any(|w| w[0] == "wots" && w[1] == ":" && w[2] == "sign")
            || texts.windows(4).any(|w| w[0] == "wots" && w[1] == ":" && w[2] == ":" && w[3] == "sign")
    }

    /// `#[cfg(...)]` attrs: keep the item in the wallet view unless it is
    /// gated ON `raw-backend`.
    fn kept_in_wallet_view(attrs: &[syn::Attribute]) -> bool {
        for a in attrs {
            if a.path().is_ident("cfg") {
                let text = a.meta.to_token_stream().to_string();
                if text.contains("raw-backend") && !text.contains("not") {
                    return false;
                }
            }
        }
        true
    }

    fn is_pub(vis: &syn::Visibility) -> bool {
        matches!(vis, syn::Visibility::Public(_))
    }

    struct Fn_ {
        name: String,
        module: String,
        vis_pub: bool,
        /// The self type's name for impl methods, checked for `pub`.
        self_ty: Option<String>,
        sig: syn::Signature,
        body: Option<proc_macro2::TokenStream>,
    }

    pub fn analyse(files: &[(String, String)], src_prefix: &str) -> Analysis {
        // Parse everything; a parse failure is a hard stop.
        let mut parsed: Vec<(String, String, syn::File)> = Vec::new();
        for (name, text) in files {
            let rel = name.strip_prefix(src_prefix).unwrap_or(name).to_owned();
            let module = module_of(&rel);
            let ast = syn::parse_file(text).unwrap_or_else(|e| panic!("syn could not parse {name}: {e}"));
            parsed.push((rel, module, ast));
        }

        // --- module visibility in the wallet view ---------------------------
        // declarations: (parent module, name) -> surviving declarations' pub-ness
        let mut decls: BTreeMap<(String, String), Vec<bool>> = BTreeMap::new();
        let mut inline_mods: Vec<(String, bool)> = Vec::new(); // (path, pub)
        fn collect_mods(
            items: &[syn::Item],
            here: &str,
            decls: &mut BTreeMap<(String, String), Vec<bool>>,
            inline_mods: &mut Vec<(String, bool)>,
        ) {
            for item in items {
                if let syn::Item::Mod(m) = item {
                    if !kept_in_wallet_view(&m.attrs) {
                        continue;
                    }
                    let name = m.ident.to_string();
                    match &m.content {
                        None => decls
                            .entry((here.to_owned(), name))
                            .or_default()
                            .push(is_pub(&m.vis)),
                        Some((_, inner)) => {
                            let path = if here.is_empty() { name.clone() } else { format!("{here}::{name}") };
                            inline_mods.push((path.clone(), is_pub(&m.vis)));
                            collect_mods(inner, &path, decls, inline_mods);
                        }
                    }
                }
            }
        }
        for (_, module, ast) in &parsed {
            collect_mods(&ast.items, module, &mut decls, &mut inline_mods);
        }
        let mut modules: BTreeMap<String, bool> = BTreeMap::new();
        modules.insert(String::new(), true);
        // Resolve file modules by path depth, parents first.
        let mut file_modules: Vec<String> = parsed.iter().map(|(_, m, _)| m.clone()).filter(|m| !m.is_empty()).collect();
        file_modules.sort_by_key(|m| m.matches("::").count());
        for m in &file_modules {
            let (parent, name) = match m.rsplit_once("::") {
                Some((p, n)) => (p.to_owned(), n.to_owned()),
                None => (String::new(), m.clone()),
            };
            let survivors = decls.get(&(parent.clone(), name.clone())).cloned().unwrap_or_default();
            assert!(
                survivors.len() <= 1,
                "module `{m}` has {} surviving declarations in the wallet view; the cfg pair is \
                 not exclusive",
                survivors.len()
            );
            let parent_pub = modules.get(&parent).copied().unwrap_or(false);
            let vis = match survivors.first() {
                Some(p) => *p && parent_pub,
                // A file with no surviving declaration is not compiled into
                // the wallet view at all.
                None => false,
            };
            modules.insert(m.clone(), vis);
        }
        for (path, p) in &inline_mods {
            let parent = path.rsplit_once("::").map(|(a, _)| a.to_owned()).unwrap_or_default();
            let parent_pub = modules.get(&parent).copied().unwrap_or(false);
            modules.insert(path.clone(), *p && parent_pub);
        }

        // --- pub use lifting: (target module, name or "*") from visible modules
        let mut lifted: BTreeSet<(String, String)> = BTreeSet::new();
        fn use_paths(tree: &syn::UseTree, prefix: Vec<String>, out: &mut Vec<(Vec<String>, String)>) {
            match tree {
                syn::UseTree::Path(p) => {
                    let mut pre = prefix;
                    pre.push(p.ident.to_string());
                    use_paths(&p.tree, pre, out);
                }
                syn::UseTree::Name(n) => out.push((prefix, n.ident.to_string())),
                syn::UseTree::Rename(r) => out.push((prefix, r.ident.to_string())),
                syn::UseTree::Glob(_) => out.push((prefix, "*".to_owned())),
                syn::UseTree::Group(g) => {
                    for t in &g.items {
                        use_paths(t, prefix.clone(), out);
                    }
                }
            }
        }
        for (_, module, ast) in &parsed {
            if !modules.get(module).copied().unwrap_or(false) {
                continue;
            }
            for item in &ast.items {
                if let syn::Item::Use(u) = item {
                    if !is_pub(&u.vis) || !kept_in_wallet_view(&u.attrs) {
                        continue;
                    }
                    let mut out = Vec::new();
                    use_paths(&u.tree, Vec::new(), &mut out);
                    for (segs, name) in out {
                        let mut segs = segs;
                        let target = match segs.first().map(String::as_str) {
                            Some("crate") => {
                                segs.remove(0);
                                segs.join("::")
                            }
                            Some("self") => {
                                segs.remove(0);
                                if segs.is_empty() {
                                    module.clone()
                                } else if module.is_empty() {
                                    segs.join("::")
                                } else {
                                    format!("{module}::{}", segs.join("::"))
                                }
                            }
                            _ => {
                                if segs.is_empty() {
                                    module.clone()
                                } else if module.is_empty() {
                                    segs.join("::")
                                } else {
                                    format!("{module}::{}", segs.join("::"))
                                }
                            }
                        };
                        lifted.insert((target, name));
                    }
                }
            }
        }

        // --- bearing types ----------------------------------------------------
        let mut bearing: BTreeSet<String> = ["SIG_LEN", "WOTSSIGBYTES", "2144"].iter().map(|s| s.to_string()).collect();
        let mut type_items: Vec<(String, proc_macro2::TokenStream)> = Vec::new();
        fn collect_types(items: &[syn::Item], out: &mut Vec<(String, proc_macro2::TokenStream)>) {
            for item in items {
                match item {
                    syn::Item::Type(t) => out.push((t.ident.to_string(), t.ty.to_token_stream())),
                    syn::Item::Struct(s) => out.push((s.ident.to_string(), s.fields.to_token_stream())),
                    syn::Item::Enum(e) => out.push((e.ident.to_string(), e.variants.to_token_stream())),
                    syn::Item::Mod(m) => {
                        if let Some((_, inner)) = &m.content {
                            collect_types(inner, out);
                        }
                    }
                    _ => {}
                }
            }
        }
        for (_, _, ast) in &parsed {
            collect_types(&ast.items, &mut type_items);
        }
        loop {
            let before = bearing.len();
            for (name, tokens) in &type_items {
                if !bearing.contains(name) && mentions(tokens, &bearing) {
                    bearing.insert(name.clone());
                }
            }
            if bearing.len() == before {
                break;
            }
        }
        // Key-material holders: the transitive closure over `Secret` and
        // `Zeroizing`, computed independently of the Debug-holder scan.
        let mut holders: BTreeSet<String> = ["Secret", "Zeroizing"].iter().map(|s| s.to_string()).collect();
        loop {
            let before = holders.len();
            for (name, tokens) in &type_items {
                if !holders.contains(name) && mentions(tokens, &holders) {
                    holders.insert(name.clone());
                }
            }
            if holders.len() == before {
                break;
            }
        }

        // --- every fn, with its module and visibility ------------------------
        let mut fns: Vec<(String, Fn_)> = Vec::new(); // (file rel, fn)
        fn collect_fns(items: &[syn::Item], rel: &str, module: &str, out: &mut Vec<(String, Fn_)>) {
            for item in items {
                match item {
                    syn::Item::Fn(f) => out.push((
                        rel.to_owned(),
                        Fn_ {
                            name: f.sig.ident.to_string(),
                            module: module.to_owned(),
                            vis_pub: is_pub(&f.vis) && kept_in_wallet_view(&f.attrs),
                            self_ty: None,
                            sig: f.sig.clone(),
                            body: Some(f.block.to_token_stream()),
                        },
                    )),
                    syn::Item::Impl(i) => {
                        let self_name = match &*i.self_ty {
                            syn::Type::Path(p) => p.path.segments.last().map(|s| s.ident.to_string()),
                            _ => None,
                        };
                        // Trait impls: the methods' visibility is the trait's;
                        // a trait method can still be a route, so it is
                        // examined with the trait's name as the self type.
                        for it in &i.items {
                            if let syn::ImplItem::Fn(f) = it {
                                let vis_pub = if i.trait_.is_some() {
                                    true
                                } else {
                                    is_pub(&f.vis) && kept_in_wallet_view(&f.attrs)
                                };
                                out.push((
                                    rel.to_owned(),
                                    Fn_ {
                                        name: f.sig.ident.to_string(),
                                        module: module.to_owned(),
                                        vis_pub,
                                        self_ty: self_name.clone(),
                                        sig: f.sig.clone(),
                                        body: Some(f.block.to_token_stream()),
                                    },
                                ));
                            }
                        }
                    }
                    syn::Item::Trait(t) => {
                        for it in &t.items {
                            if let syn::TraitItem::Fn(f) = it {
                                out.push((
                                    rel.to_owned(),
                                    Fn_ {
                                        name: f.sig.ident.to_string(),
                                        module: module.to_owned(),
                                        vis_pub: is_pub(&t.vis),
                                        self_ty: Some(t.ident.to_string()),
                                        sig: f.sig.clone(),
                                        body: f.default.as_ref().map(|b| b.to_token_stream()),
                                    },
                                ));
                            }
                        }
                    }
                    syn::Item::Mod(m) => {
                        if let Some((_, inner)) = &m.content {
                            let path = if module.is_empty() {
                                m.ident.to_string()
                            } else {
                                format!("{module}::{}", m.ident)
                            };
                            collect_fns(inner, rel, &path, out);
                        }
                    }
                    _ => {}
                }
            }
        }
        for (rel, module, ast) in &parsed {
            collect_fns(&ast.items, rel, module, &mut fns);
        }
        // Public item names per module, for the self-type check.
        let mut pub_items: BTreeSet<(String, String)> = BTreeSet::new();
        fn collect_pub_items(items: &[syn::Item], module: &str, out: &mut BTreeSet<(String, String)>) {
            for item in items {
                let (vis, name) = match item {
                    syn::Item::Struct(s) => (&s.vis, s.ident.to_string()),
                    syn::Item::Enum(e) => (&e.vis, e.ident.to_string()),
                    syn::Item::Type(t) => (&t.vis, t.ident.to_string()),
                    syn::Item::Trait(t) => (&t.vis, t.ident.to_string()),
                    syn::Item::Mod(m) => {
                        if let Some((_, inner)) = &m.content {
                            let path = if module.is_empty() {
                                m.ident.to_string()
                            } else {
                                format!("{module}::{}", m.ident)
                            };
                            collect_pub_items(inner, &path, out);
                        }
                        continue;
                    }
                    _ => continue,
                };
                if is_pub(vis) {
                    out.insert((module.to_owned(), name));
                }
            }
        }
        for (_, module, ast) in &parsed {
            collect_pub_items(&ast.items, module, &mut pub_items);
        }

        // --- reaches-the-signer: body fixpoint over fn names ------------------
        let mut tainted: BTreeSet<String> = ["wots_sign", "wots_sign_counted", "sign_spend"].iter().map(|s| s.to_string()).collect();
        let mut signers_found: BTreeSet<String> = BTreeSet::new();
        for (rel, f) in &fns {
            if f.name == "wots_sign" || (f.name == "sign" && rel.ends_with("wots.rs")) {
                signers_found.insert(format!("{rel}::{}", f.name));
            }
        }
        loop {
            let before = tainted.len();
            for (rel, f) in &fns {
                if let Some(body) = &f.body {
                    if !tainted.contains(&f.name) && (mentions(body, &tainted) || names_wots_sign(body)) {
                        tainted.insert(f.name.clone());
                        let _ = rel;
                    }
                }
            }
            if tainted.len() == before {
                break;
            }
        }
        // `wots.rs::sign` is tainted by name too, for the visibility set below.
        tainted.insert("sign".to_owned());

        // --- the verdicts ------------------------------------------------------
        let mut flagged = Vec::new();
        let mut visible = BTreeSet::new();
        let mut signatures = 0usize;
        for (rel, f) in &fns {
            signatures += 1;
            let key = match &f.self_ty {
                Some(t) => format!("{rel}::{t}::{}", f.name),
                None => format!("{rel}::{}", f.name),
            };
            let module_visible = modules.get(&f.module).copied().unwrap_or(false);
            // The self type may be defined in a parent module (`Keystore` in
            // `keystore/mod.rs`, its methods in `keystore/sign.rs`), so it is
            // resolved by name across the crate; a name that is `pub` anywhere
            // counts, which errs toward flagging.
            let self_ok = match &f.self_ty {
                Some(t) => pub_items.iter().any(|(_, n)| n == t),
                None => true,
            };
            let lifted_here = lifted.contains(&(f.module.clone(), f.name.clone()))
                || lifted.contains(&(f.module.clone(), "*".to_owned()));
            let wallet_visible = f.vis_pub && self_ok && (module_visible || lifted_here);
            if wallet_visible {
                visible.insert(key.clone());
            }
            let output = match &f.sig.output {
                syn::ReturnType::Type(_, ty) => ty.to_token_stream().to_string(),
                syn::ReturnType::Default => "()".to_owned(),
            };
            // `-> Self` / `-> Result<Self>` inside an impl of a bearing type is
            // a bearing return spelled without the name; resolved through the
            // impl's self type.
            let self_bearing = f.self_ty.as_ref().is_some_and(|t| bearing.contains(t));
            let self_only: BTreeSet<String> = ["Self".to_owned()].into_iter().collect();
            let produces_ret = matches!(&f.sig.output, syn::ReturnType::Type(_, ty)
                if mentions(&ty.to_token_stream(), &bearing) || (self_bearing && mentions(&ty.to_token_stream(), &self_only)));
            let produces_mut = f.sig.inputs.iter().any(|arg| match arg {
                syn::FnArg::Typed(t) => matches!(&*t.ty, syn::Type::Reference(r) if r.mutability.is_some())
                    && mentions(&t.ty.to_token_stream(), &bearing),
                syn::FnArg::Receiver(_) => false,
            });
            let reaches = tainted.contains(&f.name)
                || f.body.as_ref().is_some_and(|b| mentions(b, &tainted) || names_wots_sign(b));
            let why = if produces_ret {
                "returns a signature-bearing type"
            } else if produces_mut {
                "writes a signature-bearing value through &mut"
            } else if reaches {
                "reaches the signer"
            } else {
                continue;
            };
            if !wallet_visible {
                continue;
            }
            let holder_params: Vec<String> = f
                .sig
                .inputs
                .iter()
                .filter_map(|arg| match arg {
                    syn::FnArg::Typed(t) if mentions(&t.ty.to_token_stream(), &holders) => {
                        Some(t.ty.to_token_stream().to_string())
                    }
                    _ => None,
                })
                .chain(f.self_ty.iter().filter(|t| holders.contains(*t)).map(|t| format!("self: {t}")))
                .collect();
            let body_names_sign_spend = f.body.as_ref().is_some_and(|b| {
                idents(b)
                    .iter()
                    .any(|t| matches!(t.to_string().as_str(), "sign_spend" | "resign_reserved"))
            });
            let body_names_raw = f.body.as_ref().is_some_and(|b| {
                names_wots_sign(b)
                    || idents(b).iter().any(|t| t.to_string() == "wots_sign")
            });
            let body_names_wallet = f
                .body
                .as_ref()
                .is_some_and(|b| idents(b).iter().any(|t| t.to_string() == "Wallet"));
            let body_idents: Vec<String> = f
                .body
                .as_ref()
                .map(|b| idents(b).iter().map(|t| t.to_string()).collect())
                .unwrap_or_default();
            let takes_digest = f.sig.inputs.iter().any(|arg| match arg {
                syn::FnArg::Typed(t) => {
                    let rendered = t.ty.to_token_stream().to_string().replace(' ', "");
                    rendered.contains("[u8;32]") || rendered.contains("[u8;HASHLEN]")
                }
                syn::FnArg::Receiver(_) => false,
            });
            let reads_pending = f
                .body
                .as_ref()
                .is_some_and(|b| idents(b).iter().any(|t| t.to_string() == "pending"));
            flagged.push(Flagged {
                name: key,
                output,
                why,
                reaches_signer: reaches,
                body_names_wallet,
                body_idents,
                takes_digest,
                reads_pending,
                holder_params,
                names_sign_spend: body_names_sign_spend,
                names_raw_signer: body_names_raw,
            });
        }
        flagged.sort_by(|a, b| a.name.cmp(&b.name));
        Analysis {
            flagged,
            bearing,
            modules,
            signers_found,
            visible,
            signatures,
        }
    }
}

/// I1 across accounts: one key stream cannot sit in one keystore twice.
///
/// A rotation key is `derive_wots_key(seed, r)`, a function of the 32-byte
/// seed alone, so one root under two tags, or a derived account's seed
/// re-imported under another tag, would be two slots with independent
/// indices over one key stream. Tag uniqueness is not stream uniqueness.
///
/// Every format-v2 record carries the stream's public identity, the
/// rotation-0 public key's hash (`derive::stream_id`), computed in
/// `Account::derive` from the master and in `Account::import` from the root.
/// `Keystore::add` recomputes the incoming account's identity from its own
/// key material, never from the record, and refuses a duplicate across
/// kinds, in either insertion order, through a reopen.
///
/// The constant-time root comparison in `add` still runs first: it compares
/// key material, so it holds where a stored identity was tampered with, and
/// it reports one root under two tags as such. A derived record's identity
/// needs the master, so `sign_spend` re-derives it and refuses a
/// disagreement (`StreamIdNotReproduced`).
///
/// The bound in the name: the same stream in two stores (a copied directory,
/// `into_records` into a second store, a seed re-derived into a fresh store)
/// is out of reach of one store; that is I4's and I5's subject. A stored
/// identity is trusted between `open` and the next signature for the derived
/// kind; the trailer is integrity, not authenticity.
#[test]
fn duplicate_key_streams_are_refused_within_one_keystore_not_across_stores() {
    // Anchor: the record still carries the identity. `RECORD_LEN` names the
    // stream field by width.
    let format_rs = code_only(&read_crate_file("crates/mochimo-crypto/src/keystore/format.rs"));
    assert!(
        format_rs.contains("ADDR_TAG_LEN + 1 + 32 + FIRST_KEY_LEN + ADDR_TAG_LEN + 4 + 1 + 4 + 32"),
        "keystore/format.rs's RECORD_LEN no longer carries the second ADDR_TAG_LEN -- the \
         key-stream identity. Without it `Keystore::add` has nothing to compare a derived \
         account against after a reopen and one seed can sit under two tags again; re-read \
         the signing path's and format v2's module docs before treating this as a layout change."
    );
    // The identity of the account being added comes from its own key
    // material, never from a record, so a forged record cannot pass `add`.
    let keystore_rs = code_only(&read_crate_file("crates/mochimo-crypto/src/keystore/mod.rs"));
    assert!(
        keystore_rs.contains("fn recomputed_stream_id"),
        "Keystore no longer recomputes the incoming account's stream identity; reading it \
         off the record would make the check satisfiable by whoever wrote the file"
    );

    let mut owed: Vec<String> = Vec::new();
    const PROOF: &str = "duplicate_key_streams_are_refused_across_kinds_after_reopen";
    if let Err(why) = census::check(
        "duplicate_key_streams_are_refused_within_one_keystore_not_across_stores",
        PROOF,
    ) {
        owed.push(format!(
            "\x20 - no test named {PROOF} exists. It has to derive an account, spend from \
             it, import its seed under another tag, reopen, and show that both `add` and \
             `sign_spend` refuse the duplicate stream in both kinds -- which needs a \
             stream identity carried in the record. It must report how many kinds it \
             drove; the floor is 2.\n\x20   {why}"
        ));
    }

    assert!(
        owed.is_empty(),
        "I1 ACROSS ACCOUNTS has REGRESSED: before format v2 this red meant one key stream could \
         sit under two tags in one keystore -- the same root imported twice, a derived seed \
         re-imported, or one root under a first address built from junk components -- with \
         each slot's index advancing independently while one key signed twice. Format v2 \
         carries the stream's public identity in every record and `Keystore::add` refuses a \
         duplicate across kinds, so this firing means the proof, its census row, or the \
         identity went away.\n{}\n\
         What must still hold: the identity is in the record for both kinds, `add` \
         recomputes it for the incoming account rather than reading it, and the refusal \
         survives a drop-and-reopen in both insertion orders. Two stores over one seed is \
         NOT this -- that is I4's and I5's. The signing path found it, format v2 landed it; \
         docs/specification.md I1.",
        owed.join("\n")
    );
}

// ---------------------------------------------------------------------------
// I2 - I5: crash consistency and restore.
//
// These fail by reusing a WOTS+ key rather than by producing a wrong byte:
// nothing goes red at the time, and the loss surfaces later as funds that
// can no longer be moved. The specification's I4 and I5 sections give the
// design behind them.
// ---------------------------------------------------------------------------

/// How many files under `crates/*/src` name a durable-write primitive.
///
/// Reported in failure messages rather than asserted, as context for I2
/// and I3.
fn files_naming_a_durable_write() -> (usize, Vec<String>) {
    const PRIMITIVES: [&str; 5] = ["sync_all", "sync_data", "fsync", "persist(", "rename("];
    let files = crate_sources();
    assert!(
        files.len() >= 10,
        "the walk of crates/*/src found only {} files; any count taken over it \
         is vacuous",
        files.len()
    );
    let hits: Vec<String> = files
        .iter()
        .filter(|(_, code)| PRIMITIVES.iter().any(|p| code.contains(p)))
        .map(|(name, _)| name.clone())
        .collect();
    (files.len(), hits)
}

/// I2: the key index is durably persisted before a signature is released.
///
/// A crash between signing and persisting leaves the on-disk index at a key
/// that has already signed, and the next spend reuses it.
///
/// I1 is satisfied by advancing the index in memory; I2 requires it on disk
/// and flushed before the signature reaches the caller, so the two are
/// separate checks.
///
/// The released artefact is the receipt, and the crash model is a kill at a
/// syscall boundary, not power loss. There is no reference oracle: the C
/// reference is a node and persists a ledger, not a key index.
///
/// `signature_is_not_released_before_the_index_is_durable` drives four crash
/// points between the first write and the receipt return, reopens from disk,
/// and shows the previous index unreachable and no receipt escaped. Not
/// covered: power loss, an fsync that lies, and fsyncgate (the keystore's
/// poisoned handle answers the last). The census confirms the proof ran,
/// not that its assertions are right.
#[test]
fn index_is_durable_before_the_receipt_under_syscall_kill_not_power_loss() {
    let mut owed: Vec<String> = Vec::new();

    const PROOF: &str = "signature_is_not_released_before_the_index_is_durable";
    if let Err(why) = census::check("index_is_durable_before_the_receipt_under_syscall_kill_not_power_loss", PROOF) {
        owed.push(format!(
            "\x20 - no test named {PROOF} exists. It has to drive a signing call \
             that crashes between the index write and the return, restart from \
             the on-disk state, and assert the previous key is not reachable \
             again -- reporting how many crash points it exercised. Asserting \
             that a persist function was CALLED is not this: the property is \
             ordering plus durability, and a call that is ordered right and \
             never flushed loses the same key.\n\x20   {why}"
        ));
    }

    let (scanned, durable) = files_naming_a_durable_write();

    assert!(
        owed.is_empty(),
        "I2's enforcement has REGRESSED: once this red meant nothing in \
         the tree persisted a key index; src/keystore and the proof landed, \
         so this firing means the proof, its census row, or the keystore went \
         away.\n{}\n\x20 - premise, measured: {} file(s) under \
         crates/*/src, {} of them naming any durable-write primitive{}.\n\
         A signature released before its index reaches stable storage is a key \
         that signs twice across the next crash. WOTS+ leaks secret material \
         with each use and two signatures under one key make forgery tractable, \
         so this is not a recoverable error class -- there is no repair after \
         the fact, only the funds that key holds, exposed. See \
         docs/specification.md I2.",
        owed.join("\n"),
        scanned,
        durable.len(),
        if durable.is_empty() {
            String::new()
        } else {
            format!(" ({})", durable.join(", "))
        }
    );
}

/// I3: spend-related state advances atomically.
///
/// Index, keystore metadata and any pending-transaction record must not
/// disagree; a partial write is indistinguishable from corruption at the
/// next startup. The enforcement is the standard four steps (write a temp
/// file in the same directory, `fsync` it, `rename` over the target, `fsync`
/// the directory), with all spend-related state in one write. The floor of
/// 4 is those four interruption points.
///
/// The proof kills at each step's syscall boundary, reopens, and finds
/// index, pending record and generation fully pre or fully post together.
/// Not covered: power loss, an fsync that lies, a spend-related member
/// added later without a test, and whether the test observed across members
/// rather than each one alone.
#[test]
fn spend_state_is_atomic_under_syscall_kill_not_power_loss() {
    let mut owed: Vec<String> = Vec::new();

    const PROOF: &str = "spend_state_is_never_observed_half_advanced";
    if let Err(why) = census::check("spend_state_is_atomic_under_syscall_kill_not_power_loss", PROOF) {
        owed.push(format!(
            "\x20 - no test named {PROOF} exists. It has to interrupt the spend \
             write at each point in the sequence docs/specification.md I3 names -- \
             temp file written, file fsynced, renamed over the target, directory \
             fsynced -- and assert that what a fresh reader finds on disk is \
             always FULLY pre-spend or FULLY post-spend, across every member of \
             the spend state and not one at a time. It must report the number of \
             interruption points it drove; the floor is 4, which is the count \
             the invariant's own enforcement clause names.\n\x20   {why}"
        ));
    }

    let (scanned, durable) = files_naming_a_durable_write();

    assert!(
        owed.is_empty(),
        "I3's enforcement has REGRESSED: once this red meant there was no \
         spend-state write in the tree; the keystore's atomic commit landed \
         and the proof, so this firing means the proof, its census row, or the \
         commit sequence went away.\n{}\n\x20 - premise, measured: \
         {} file(s) under crates/*/src, {} of them naming any durable-write or \
         atomic-rename primitive{}.\n\
         A half-advanced spend state is indistinguishable from corruption, and \
         the two have different correct recoveries -- one resumes, one refuses. \
         A wallet that cannot tell them apart will guess, and the wrong guess \
         reuses a key. See docs/specification.md I3.",
        owed.join("\n"),
        scanned,
        durable.len(),
        if durable.is_empty() {
            String::new()
        } else {
            format!(" ({})", durable.join(", "))
        }
    );
}

/// I3's proof: interrupt the commit at each of the four steps, reopen from
/// disk, and find every member of the spend state fully pre- or fully
/// post-spend, never mixed.
///
/// Each interruption is a kill at a syscall boundary: `Instrumented` performs
/// the primitive and then returns an error, and the keystore's error path
/// makes no further filesystem call (asserted from the recorder). Not
/// driven: power loss, an fsync that lies, fsyncgate (after `EIO` the pages
/// may be gone, hence the poisoned handle), and rename atomicity on
/// filesystems that do not journal it.
///
/// The recorder holds arguments, not just names, so an `fsync_file` on the
/// wrong path is caught by the sequence assertion.
///
/// The store is encrypted, but the salt and nonce seed are parameters and
/// the harness fixes them, so identical contents give identical files. The
/// byte comparisons (`pre_bytes` / `post_bytes`) therefore depend on that
/// fixed entropy and catch a target that moved before the rename. The state
/// comparisons after a reopen (`view()`, `generation()`, `into_records()`)
/// are what "fully pre or fully post" means, and hold for any nonce.
#[test]
fn spend_state_is_never_observed_half_advanced() {
    use keystore_harness::{
        derived_account, imported_account, ScratchDir, DERIVED_POSITION, DERIVED_TAG, DIGEST,
        FIGURES, IMPORTED_TAG, ROOT,
    };
    use mochimo_crypto::account::{AccountRecord, WotsIndex};
    use mochimo_crypto::keystore::{Call, Disk, Instrumented, Keystore, Pending};

    const STEPS: [&str; 4] = ["write_temp", "fsync_file", "rename", "fsync_dir"];
    /// The digest of the reservation the seed settles and retains, so that
    /// `settled` is a live member of the walk: the interrupted reservation
    /// moves the index, the generation, `pending` 0 -> 1 and `settled` 1 -> 0.
    const SETTLED_DIGEST: [u8; 32] = [0xD0; 32];
    let retained = Pending {
        spent_index: WotsIndex::ZERO,
        digest: SETTLED_DIGEST,
        figures: Some(FIGURES),
    };
    let one = WotsIndex::ZERO.advanced().unwrap_or_else(|e| panic!("{e}"));

    // Seed a keystore: imported with one reservation settled and retained
    // (index 1, no open reservation, a settled block at 0); derived at
    // position 9, advanced to 5 in memory before it is added, so a reset to
    // zero is visible.
    fn seed(dir: &ScratchDir) -> Keystore<Instrumented<Disk>> {
        let mut ks = Keystore::create_with(dir.path(), Instrumented::new(Disk), &keystore_harness::init())
            .unwrap_or_else(|e| panic!("create: {e}"));
        ks.add(imported_account()).unwrap_or_else(|e| panic!("add imported: {e}"));
        let mut d = derived_account();
        for _ in 0..5 {
            d.advance().unwrap_or_else(|e| panic!("advance: {e}"));
        }
        ks.add(d).unwrap_or_else(|e| panic!("add derived: {e}"));
        let _ = ks
            .persist_advance(&IMPORTED_TAG, &SETTLED_DIGEST, FIGURES)
            .unwrap_or_else(|e| panic!("seed reserve: {e}"));
        ks.persist_settled(&IMPORTED_TAG).unwrap_or_else(|e| panic!("seed settle: {e}"));
        ks.medium_mut().reset_calls();
        ks
    }
    // The same store one commit further, with the reservation open, for the
    // settle walk.
    fn seed_open(dir: &ScratchDir) -> Keystore<Instrumented<Disk>> {
        let mut ks = seed(dir);
        let _ = ks
            .persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES)
            .unwrap_or_else(|e| panic!("seed open: {e}"));
        ks.medium_mut().reset_calls();
        ks
    }

    // Control run: the uninterrupted reservation commit, its bytes and its
    // sequence.
    let control = ScratchDir::new("i3-control");
    let mut ks = seed(&control);
    let pre_bytes = control.snapshot_bytes();
    let pre_gen = ks.generation().unwrap_or_else(|e| panic!("{e}"));
    let receipt = ks
        .persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES)
        .unwrap_or_else(|e| panic!("control persist: {e}"));
    assert_eq!(receipt.tag(), IMPORTED_TAG);
    assert_eq!(receipt.index().get(), 2);
    let post_bytes = control.snapshot_bytes();
    let post_gen = ks.generation().unwrap_or_else(|e| panic!("{e}"));
    assert_ne!(pre_bytes, post_bytes, "the control commit changed nothing on disk");
    assert_eq!(post_gen, pre_gen + 1);
    let tmp = control.path().join("accounts.mks.tmp");
    let snap = control.path().join("accounts.mks");
    assert_eq!(
        ks.medium().calls(),
        &[
            Call::WriteTemp {
                path: tmp.clone(),
                len: post_bytes.len()
            },
            Call::FsyncFile { path: tmp.clone() },
            Call::Rename {
                from: tmp.clone(),
                to: snap.clone()
            },
            Call::FsyncDir {
                dir: control.path().to_path_buf()
            },
        ],
        "the uninterrupted commit must be exactly the four steps, in order, \
         on these paths -- an fsync on the wrong path is visible only here"
    );
    drop(ks);

    let mut driven = 0usize;
    for k in 1..=4usize {
        let dir = ScratchDir::new("i3-interrupt");
        let mut ks = seed(&dir);
        assert_eq!(
            dir.snapshot_bytes(),
            pre_bytes,
            "seeding is not deterministic; the byte comparisons below are void"
        );
        ks.medium_mut().stop_after(Some(k));
        let err = ks
            .persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES)
            .err()
            .unwrap_or_else(|| panic!("interruption point {k}: persist returned Ok"));
        assert_eq!(
            err,
            mochimo_crypto::Error::Io {
                op: STEPS[k - 1],
                kind: std::io::ErrorKind::Interrupted
            },
            "interruption point {k}: not the injected error"
        );
        assert_eq!(
            ks.medium().calls().len(),
            k,
            "interruption point {k}: the error path made a further medium call"
        );
        let listing = dir.listing();
        let has_tmp = listing.iter().any(|n| n == "accounts.mks.tmp");
        if k < 3 {
            assert!(has_tmp, "interruption point {k}: the temp should still exist: {listing:?}");
            assert_eq!(dir.snapshot_bytes(), pre_bytes, "interruption point {k}: target moved before rename");
        } else {
            assert!(!has_tmp, "interruption point {k}: the temp should have been renamed away: {listing:?}");
            assert_eq!(dir.snapshot_bytes(), post_bytes, "interruption point {k}: target is not the committed image");
        }
        // A handle that saw the error is poisoned; nothing more happens on it.
        assert!(matches!(ks.persist_settled(&IMPORTED_TAG), Err(mochimo_crypto::Error::Poisoned { .. })));
        drop(ks);

        // Restart from the on-disk state through the harness's bounded
        // reopen: census children running beside this proof can make a
        // just-released flock look held briefly. Only `Locked` is retried.
        let ks = keystore_harness::reopen_with("I3 interruption point", dir.path(), || Instrumented::new(Disk))
            .result
            .unwrap_or_else(|e| panic!("interruption point {k}: reopen: {e}"));
        let view = ks
            .view(&IMPORTED_TAG)
            .unwrap_or_else(|e| panic!("{e}"))
            .unwrap_or_else(|| panic!("interruption point {k}: imported account vanished"));
        let gen = ks.generation().unwrap_or_else(|e| panic!("{e}"));
        let index_is_pre = view.wots_index == one;
        let pending_is_pre = view.pending.is_none();
        let settled_is_pre = view.settled.is_some();
        let gen_is_pre = gen == pre_gen;
        assert!(
            index_is_pre == pending_is_pre && pending_is_pre == settled_is_pre && settled_is_pre == gen_is_pre,
            "interruption point {k}: spend state observed HALF-advanced -- index pre={index_is_pre}, \
             pending pre={pending_is_pre}, settled pre={settled_is_pre}, generation pre={gen_is_pre}"
        );
        let expect_pre = k < 3;
        assert_eq!(index_is_pre, expect_pre, "interruption point {k}: wrong side of the commit");
        if expect_pre {
            assert_eq!(view.settled, Some(retained), "interruption point {k}: the pre-spend state lost its retained block");
        } else {
            let p = view.pending.unwrap_or_else(|| panic!("post-spend state without a pending record"));
            assert_eq!(p.spent_index, one);
            assert_eq!(p.digest, DIGEST);
            assert_eq!(p.figures, Some(FIGURES), "interruption point {k}: the figures did not commit with the reservation");
            assert_eq!(view.wots_index.get(), 2);
            assert_eq!(view.settled, None, "interruption point {k}: the retained block survived the reservation that releases it");
        }
        assert!(
            !dir.listing().iter().any(|n| n == "accounts.mks.tmp"),
            "interruption point {k}: reopen left the stale temp in place"
        );
        let derived = ks
            .view(&DERIVED_TAG)
            .unwrap_or_else(|e| panic!("{e}"))
            .unwrap_or_else(|| panic!("interruption point {k}: derived account vanished"));
        assert_eq!(derived.wots_index.get(), 5, "interruption point {k}: the sibling account moved");
        let mut roots = 0;
        for r in ks.into_records().unwrap_or_else(|e| panic!("{e}")) {
            match r {
                AccountRecord::Imported { root, .. } => {
                    assert_eq!(root.expose(), &ROOT, "interruption point {k}: the root did not survive");
                    roots += 1;
                }
                AccountRecord::Derived { account_index, .. } => {
                    assert_eq!(account_index, DERIVED_POSITION);
                }
                AccountRecord::Sdk { .. } => panic!("interruption point {k}: no SDK account was stored"),
            }
        }
        assert_eq!(roots, 1);
        driven += 1;
    }
    assert_eq!(driven, 4, "the loop drove {driven} points, not the four I3 names");

    // The settle commit's own four points. A settle writes state 1 -> 2 and
    // the block it moves is the only record of that key's one signature.
    // Seeded with the reservation open; at each point a fresh reader finds
    // it fully open (state 1, no settled block) or fully settled (state 2,
    // no open reservation), and the index never moves.
    let open_block = Pending {
        spent_index: one,
        digest: DIGEST,
        figures: Some(FIGURES),
    };
    let control2 = ScratchDir::new("i3-settle-control");
    let mut ks = seed_open(&control2);
    let pre2_bytes = control2.snapshot_bytes();
    let pre2_gen = ks.generation().unwrap_or_else(|e| panic!("{e}"));
    ks.persist_settled(&IMPORTED_TAG).unwrap_or_else(|e| panic!("control settle: {e}"));
    let post2_bytes = control2.snapshot_bytes();
    assert_ne!(pre2_bytes, post2_bytes, "the control settle changed nothing on disk");
    assert_eq!(ks.generation().unwrap_or_else(|e| panic!("{e}")), pre2_gen + 1);
    assert_eq!(ks.medium().calls().len(), 4, "the settle commit is the same four steps");
    drop(ks);
    for k in 1..=4usize {
        let dir = ScratchDir::new("i3-settle-interrupt");
        let mut ks = seed_open(&dir);
        assert_eq!(dir.snapshot_bytes(), pre2_bytes, "seeding is not deterministic; the byte comparisons below are void");
        ks.medium_mut().stop_after(Some(k));
        let err = ks
            .persist_settled(&IMPORTED_TAG)
            .err()
            .unwrap_or_else(|| panic!("settle point {k}: persist_settled returned Ok"));
        assert_eq!(
            err,
            mochimo_crypto::Error::Io {
                op: STEPS[k - 1],
                kind: std::io::ErrorKind::Interrupted
            },
            "settle point {k}: not the injected error"
        );
        assert_eq!(ks.medium().calls().len(), k, "settle point {k}: the error path made a further medium call");
        if k < 3 {
            assert_eq!(dir.snapshot_bytes(), pre2_bytes, "settle point {k}: target moved before rename");
        } else {
            assert_eq!(dir.snapshot_bytes(), post2_bytes, "settle point {k}: target is not the committed image");
        }
        assert!(matches!(
            ks.persist_advance(&DERIVED_TAG, &DIGEST, FIGURES),
            Err(mochimo_crypto::Error::Poisoned { .. })
        ));
        drop(ks);
        let ks = keystore_harness::reopen_with("I3 settle point", dir.path(), || Instrumented::new(Disk))
            .result
            .unwrap_or_else(|e| panic!("settle point {k}: reopen: {e}"));
        let view = ks
            .view(&IMPORTED_TAG)
            .unwrap_or_else(|e| panic!("{e}"))
            .unwrap_or_else(|| panic!("settle point {k}: imported account vanished"));
        let gen = ks.generation().unwrap_or_else(|e| panic!("{e}"));
        let open_is_pre = view.pending.is_some();
        let retained_is_post = view.settled.is_some();
        let gen_is_pre = gen == pre2_gen;
        assert!(
            open_is_pre != retained_is_post && open_is_pre == gen_is_pre,
            "settle point {k}: settle observed HALF-done -- open={open_is_pre}, retained={retained_is_post}, generation pre={gen_is_pre}"
        );
        assert_eq!(open_is_pre, k < 3, "settle point {k}: wrong side of the commit");
        if k < 3 {
            assert_eq!(view.pending, Some(open_block), "settle point {k}: the open reservation is not what was sealed");
        } else {
            assert_eq!(view.settled, Some(open_block), "settle point {k}: the settled block is not the reservation, figures included");
        }
        assert_eq!(view.wots_index.get(), 2, "settle point {k}: settle moved the index");
        assert!(!dir.listing().iter().any(|n| n == "accounts.mks.tmp"), "settle point {k}: reopen left the stale temp in place");
        driven += 1;
    }
    assert_eq!(driven, 8, "the two loops drove {driven} points, not eight");

    // Every integer on this line is a small count; the largest is read
    // against the census floor of 4.
    println!(
        "  I3 atomicity: {driven} interruption point(s) driven -- 4 over the reservation, 4 over \
         the settle -- 4 member(s) observed across each, 2 account(s) reopened at every point"
    );
}

/// I2's proof: the receipt that `Keystore::sign_spend` consumes is never
/// released for an index that is not durable.
///
/// The [`AdvanceReceipt`] is minted only after the directory fsync, with a
/// `Durable` witness constructed at one site. The signer demands the receipt
/// and re-checks it against the store's live state (`tests/signing.rs`), so
/// the signature is withheld because the receipt is.
///
/// Broadcasting before persisting is unrepresentable: anything standing in
/// for a broadcast takes `&AdvanceReceipt`, and nothing outside the crate
/// can mint one (`ui/fail/account_advance_receipt_is_not_constructible.rs`).
/// Same crash model and limits as the I3 proof above.
#[test]
fn signature_is_not_released_before_the_index_is_durable() {
    use keystore_harness::{derived_account, imported_account, ScratchDir, DIGEST, FIGURES, IMPORTED_TAG};
    use mochimo_crypto::account::{AdvanceReceipt, WotsIndex};
    use mochimo_crypto::keystore::{Disk, Instrumented, Keystore};

    fn broadcast(_r: &AdvanceReceipt) -> &'static str {
        "broadcast requires the receipt; it cannot precede persistence"
    }

    fn seed(dir: &ScratchDir) -> Keystore<Instrumented<Disk>> {
        let mut ks = Keystore::create_with(dir.path(), Instrumented::new(Disk), &keystore_harness::init())
            .unwrap_or_else(|e| panic!("create: {e}"));
        ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
        ks.add(derived_account()).unwrap_or_else(|e| panic!("{e}"));
        ks.medium_mut().reset_calls();
        ks
    }

    let mut receipts_escaped = 0usize;
    let mut driven = 0usize;
    for k in 1..=4usize {
        let dir = ScratchDir::new("i2-crash");
        let mut ks = seed(&dir);
        ks.medium_mut().stop_after(Some(k));
        if ks.persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES).is_ok() {
            receipts_escaped += 1;
        }
        drop(ks);
        // Bounded reopen, retrying only `Locked`: census children can make a
        // just-released flock look held briefly.
        let mut ks = keystore_harness::reopen_with("I2 crash point", dir.path(), || Instrumented::new(Disk))
            .result
            .unwrap_or_else(|e| panic!("crash point {k}: reopen: {e}"));
        let view = ks
            .view(&IMPORTED_TAG)
            .unwrap_or_else(|e| panic!("{e}"))
            .unwrap_or_else(|| panic!("crash point {k}: account vanished"));
        if k >= 3 {
            // Durable before the return: the index advanced, the previous
            // key is not reachable, and the one receipt that would have named
            // it was never released.
            assert_eq!(view.wots_index.get(), 1, "crash point {k}: durable state not advanced");
            ks.persist_settled(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}"));
            let back = ks.persist_advance_to(&IMPORTED_TAG, WotsIndex::ZERO).err();
            assert!(
                matches!(back, Some(mochimo_crypto::Error::Range { what: "wots index for tag", min: 2, got: 0, .. })),
                "crash point {k}: the previous index was reachable again: {back:?}"
            );
            let equal = ks.persist_advance_to(&IMPORTED_TAG, view.wots_index).err();
            assert!(matches!(equal, Some(mochimo_crypto::Error::Range { .. })));
        } else {
            assert_eq!(view.wots_index.get(), 0, "crash point {k}: pre-commit crash advanced the index");
            let equal = ks.persist_advance_to(&IMPORTED_TAG, WotsIndex::ZERO).err();
            assert!(matches!(equal, Some(mochimo_crypto::Error::Range { .. })));
            let next = WotsIndex::ZERO.advanced().unwrap_or_else(|e| panic!("{e}"));
            let r = ks
                .persist_advance_to(&IMPORTED_TAG, next)
                .unwrap_or_else(|e| panic!("crash point {k}: liveness after a pre-commit crash: {e}"));
            assert_eq!(r.index(), next);
            let _ = broadcast(&r);
            drop(ks);
            let ks = keystore_harness::reopen("I2 liveness", dir.path())
                .result
                .unwrap_or_else(|e| panic!("{e}"));
            let v = ks.view(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("vanished"));
            assert_eq!(v.wots_index, next, "the receipt named an index a fresh reopen does not read");
        }
        driven += 1;
    }
    assert_eq!(driven, 4);
    assert_eq!(receipts_escaped, 0, "a receipt escaped an interrupted persist");

    // Control: the uninterrupted run releases exactly one receipt, and it
    // names what a fresh reopen reads.
    let dir = ScratchDir::new("i2-control");
    let mut ks = seed(&dir);
    let r = ks.persist_advance(&IMPORTED_TAG, &DIGEST, FIGURES).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(r.tag(), IMPORTED_TAG);
    let _ = broadcast(&r);
    drop(ks);
    let ks = keystore_harness::reopen("I2 control", dir.path())
        .result
        .unwrap_or_else(|e| panic!("{e}"));
    let v = ks.view(&IMPORTED_TAG).unwrap_or_else(|e| panic!("{e}")).unwrap_or_else(|| panic!("vanished"));
    assert_eq!(v.wots_index, r.index());

    println!(
        "  I2 durability: {driven} crash point(s) driven between the first write and the \
         receipt return, {receipts_escaped} receipt(s) escaped, 1 receipt from the \
         uninterrupted run naming the index a fresh reopen reads"
    );
}

/// `Durable`, the witness `AdvanceReceipt::attesting` demands, is
/// constructed at exactly one non-test site: the `Ok` arm after the
/// directory fsync in `Keystore::commit`. Items under `#[cfg(test)]` are
/// skipped, since a test-only mint cannot reach a release build.
#[test]
fn durable_witness_has_one_construction_site() {
    use quote::ToTokens;

    fn is_cfg_test(attrs: &[syn::Attribute]) -> bool {
        attrs.iter().any(|a| {
            let s = a.to_token_stream().to_string().replace(' ', "");
            s.contains("cfg(test)")
        })
    }
    fn count_in(tokens: proc_macro2::TokenStream) -> usize {
        let s = tokens.to_string().replace(' ', "");
        s.matches("Durable(())").count()
    }
    fn walk(items: &[syn::Item], sites: &mut Vec<(String, usize)>, file: &str) {
        for item in items {
            match item {
                syn::Item::Mod(m) => {
                    if is_cfg_test(&m.attrs) {
                        continue;
                    }
                    if let Some((_, inner)) = &m.content {
                        walk(inner, sites, file);
                    }
                }
                syn::Item::Fn(f) => {
                    if !is_cfg_test(&f.attrs) {
                        let n = count_in(f.block.to_token_stream());
                        if n > 0 {
                            sites.push((format!("{file}::{}", f.sig.ident), n));
                        }
                    }
                }
                syn::Item::Impl(im) => {
                    if is_cfg_test(&im.attrs) {
                        continue;
                    }
                    for it in &im.items {
                        if let syn::ImplItem::Fn(f) = it {
                            if !is_cfg_test(&f.attrs) {
                                let n = count_in(f.block.to_token_stream());
                                if n > 0 {
                                    sites.push((format!("{file}::{}", f.sig.ident), n));
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    let files = crate_source_files();
    assert!(files.len() >= 10, "the walk found only {} files", files.len());
    let mut sites: Vec<(String, usize)> = Vec::new();
    let mut saw_definition = false;
    for (name, text) in &files {
        let parsed = syn::parse_file(text).unwrap_or_else(|e| panic!("{name} does not parse: {e}"));
        if text.contains("pub struct Durable(());") {
            saw_definition = true;
        }
        walk(&parsed.items, &mut sites, name);
    }
    assert!(saw_definition, "the Durable witness type is gone; re-read the specification's I2 before deciding what I2 now means");
    let total: usize = sites.iter().map(|(_, n)| n).sum();
    assert_eq!(
        total,
        1,
        "Durable(()) must be constructed at exactly one non-test site (Keystore::commit's Ok arm); found: {sites:?}"
    );
    assert!(
        sites[0].0.ends_with("keystore/mod.rs::commit"),
        "the one construction site moved out of Keystore::commit: {sites:?}"
    );
}

/// I6 at rest: the imported root and the master seed reach the snapshot
/// encrypted.
///
/// The proof, `keystore.rs::snapshot_bytes_never_contain_the_imported_root`,
/// writes a store with a patterned root and asserts the root's bytes appear
/// nowhere in the file, checking offset 43 (where the plaintext record body
/// places it) first.
///
/// The record body is still assembled in the clear and then sealed, so the
/// anchors check that the encoder seals the image and that the trailer is
/// the AEAD tag rather than a hash.
///
/// Not claimed: that key material is safe in memory (I6's other half);
/// rollback protection (an older valid snapshot copied back still verifies,
/// which is I4's to detect); or password strength
/// (`cli::create::MIN_PASSWORD_LEN` is a floor, not a guarantee).
#[test]
fn imported_roots_and_the_master_seed_are_encrypted_at_rest() {
    const PROOF: &str = "snapshot_bytes_never_contain_the_imported_root";

    // Anchor 1: the encoder still seals. The proof would fail on its own if
    // encryption were removed; this names the mechanism.
    let format_rs = read_crate_file("crates/mochimo-crypto/src/keystore/format.rs");
    let code = code_only(&format_rs);
    // Anchored on the call, not its argument list: `crypt::seal(` and
    // `crypt::open(` are the property, and argument spelling changes with
    // ordinary refactors.
    for call in ["crypt::seal(", "crypt::open("] {
        assert!(
            code.contains(call),
            "keystore/format.rs no longer calls `{call}`. If the AEAD was removed, the at-rest \
             property is gone and {PROOF} is the test that should be red; re-read the \
             keystore's and crypt's module docs."
        );
    }
    // Anchor 2: the plaintext record path is still there, since the body is
    // assembled before it is sealed; checked so a reshaped encoder is noticed.
    assert!(
        code.contains("image.extend_from_slice(root.secret().expose());"),
        "the encoder no longer writes the root through the path this marker has anchored on \
         since the keystore landed. That may be fine, but it means the proof and the anchor are describing \
         different code; re-derive before trusting either."
    );

    // And the proof runs, passes, and reports what it measured.
    if let Err(why) = census::check("imported_roots_and_the_master_seed_are_encrypted_at_rest", PROOF) {
        panic!(
            "I6 at rest is claimed but unproven: {PROOF} must be in tests/keystore.rs, run, pass \
             and print `I6 at rest:`.\n{why}"
        );
    }
    println!("  I6 at rest: sealed by the AEAD, {PROOF} censused");
}

/// I4: startup reconciles local state against the chain and fails closed.
///
/// The wallet refuses to start and requires explicit operator action,
/// printing what diverged, by how much, and what to do. Divergence has three
/// causes with different recoveries: a crash between signing and persisting
/// (I2), a restored seed with incomplete history (I5), and two wallet
/// instances live on one seed. Advancing to match the chain is right for the
/// first and catastrophic for the third, where the other instance will reuse
/// every key skipped past.
///
/// `wallet::Wallet::open` is the only constructor and it reconciles every
/// account or refuses, so an existing `Wallet` has been reconciled.
/// `recon::reconcile_account` is the comparison, `recon::Divergence`'s
/// `Display` is the report, and `wallet::OperatorAcknowledgement`, which can
/// only be built from a `Divergence`, is the sole route to
/// `persist_advance_to`.
///
/// The bound in the name: the raw `Keystore` is still reachable in-crate and
/// from the test tree, and its own proofs call `persist_advance` and
/// `sign_spend` directly. What is enforced is that a `Wallet`'s users cannot
/// spend unreconciled.
///
/// The proof asserts the rendered refusal names the divergence, both
/// indices, the gap and the action. Whether the wording is clear enough for
/// an operator is not mechanically checked.
#[test]
fn startup_refuses_divergence_at_the_wallet_layer_not_at_the_keystore() {
    // The wallet reconciles its own record's position, specified in
    // docs/specification.md; the proofs below are the mechanism.
    let mut owed: Vec<String> = Vec::new();

    const PROOF: &str = "startup_refuses_to_start_on_index_divergence";
    if let Err(why) = census::check(
        "startup_refuses_divergence_at_the_wallet_layer_not_at_the_keystore",
        PROOF,
    ) {
        owed.push(format!(
            "\x20 - no test named {PROOF} exists. It has to construct local \
             state AHEAD of chain state and local state BEHIND it, assert the \
             wallet refuses to start in both directions, and assert the refusal \
             names what diverged, by how much, and what the operator should do. \
             It must report how many divergence cases it drove; the floor is 2, \
             which is both directions and is the minimum that distinguishes \
             fail-closed from a one-sided check. A test that only builds the \
             behind case passes over the direction that means another instance \
             is live.\n\x20   {why}"
        ));
    }

    // The acknowledged path, through the shipped binary: the operator can
    // take the path the report names.
    const PTY: &str = "pty::reconcile_on_a_real_pty_takes_the_acknowledged_path_the_report_names";
    if let Err(why) = census::check(
        "startup_refuses_divergence_at_the_wallet_layer_not_at_the_keystore",
        PTY,
    ) {
        owed.push(format!(
            "\x20 - {PTY} is not running. It must build the shipped binary, drive it \
             under a pty against a loopback ledger through `balance` (refused, the \
             report naming index 2), `reconcile --advance-to 7` (refused, nothing \
             written), `reconcile --advance-to 2` (advanced), `balance` (in sync), \
             then the far-along search and the verified advance, and print `tty \
             reconcile:` with the prompts it answered (floor 9).\n\x20   {why}"
        ));
    }

    assert!(
        owed.is_empty(),
        "I4 has REGRESSED: once this red meant nothing reconciled a local \
         key index against chain state and there was no startup path to \
         reconcile in. Reconciliation landed `wallet::Wallet::open`, whose only \
         constructor reconciles every account or refuses, so this firing means \
         the proof, its census row, or the gate went away.\n{}\n\
         What must still hold: both divergence directions refuse (local ahead \
         is the one that means another instance is live), the refusal names \
         what diverged and by how much and what to do, and advancing past a \
         divergence goes through an acknowledgement built FROM the divergence. \
         The policy is NOT open: refuse to start, chosen over advance-and-warn \
         because divergence has three causes with three different correct \
         recoveries and silently advancing is right for the first and loses the \
         keys for the third. It was decided before the wallet layer existed and landed with it; see \
         docs/specification.md I4.",
        owed.join("\n")
    );
}

/// I5: restore derives the index from the chain and never assumes zero.
///
/// A restored wallet starting at index zero would re-sign with every key the
/// original already used.
///
/// The chain cannot report a tag's usage history, but it can report the
/// tag's current address in one query, so `recon::restore_account_index`
/// resolves the tag and walks positions `0..SCAN_BOUND`, stopping on the
/// position whose derived address matches. Every failing path is a failure,
/// never a fallback: an unreachable chain, a tag the ledger does not hold,
/// an address no position reproduces.
///
/// The bound in the name: by default 10,000 positions are tried (the
/// recovery ceiling, `RECOVERY_CEILING`, which the operator can set for one
/// invocation). This is not BIP-44's gap limit, which bounds unused
/// addresses. Past the bound the failure is reported; it cannot tell apart
/// an account that has spent that many times, a seed that does not own the
/// tag, and a wallet on another chain. Zero is returned only when position
/// 0's address is the one the chain holds. The proof walks twenty positions
/// at a ceiling it names, because one restore per position is quadratic.
///
/// There is no gap-scan comparison: `le_find` answers whether an address is
/// the tag's current address, never whether an address was ever used, so a
/// gap scan's stopping signal does not exist on this chain.
#[test]
fn restore_derives_the_index_within_the_scan_bound_never_from_zero() {
    // What the node's balance handler returns is stated in
    // docs/specification.md under I5 ("Why the scan has this shape"); the
    // proof below is the mechanism.
    let mut owed: Vec<String> = Vec::new();

    const PROOF: &str = "restore_derives_the_index_from_chain_state";
    if let Err(why) = census::check(
        "restore_derives_the_index_within_the_scan_bound_never_from_zero",
        PROOF,
    ) {
        owed.push(format!(
            "\x20 - no test named {PROOF} exists. It has to restore a seed whose \
             tag already resolves to a known non-zero index and assert the \
             derived index matches; assert restore FAILS rather than proceeding \
             when chain state is unavailable; and assert it never falls back to \
             zero on any path. It must report the scan bound it exercised; the \
             floor is 20 positions, which is what the proof walks at a named \
             ceiling -- not the default recovery ceiling, which is 10,000 and \
             would cost hours of derivation to exhaust.\n\x20   {why}"
        ));
    }

    assert!(
        owed.is_empty(),
        "I5 has REGRESSED: once this red meant nothing derived a restored \
         wallet's key index from chain state. Reconciliation landed \
         `recon::restore_account_index`, so this firing means the proof, its \
         census row, or the scan went away.\n{}\n\
         What must still hold: the scan is TARGET-DIRECTED and stops on the \
         match (the tag's current address is one query away, so it is not an \
         absence scan); the recovery ceiling -- 10,000 by default, settable for \
         one invocation and never silently -- limits only the FAILING search and is \
         reported rather than guessed past, with all three causes of that \
         failure named and none preferred; and restore fails -- never falls \
         back to zero -- when the chain is unreachable, when the ledger does \
         not hold the tag, and when no position under the ceiling reproduces \
         its address. A restore that assumes zero re-signs with every key the \
         original wallet already used. It was decided before the wallet layer existed and \
         landed with it; the module doc records why the gap-scan contrast has no case to \
         make, and the scan-bound findings the message and the ceiling; see docs/specification.md I5.",
        owed.join("\n")
    );
}

// ---------------------------------------------------------------------------
// I4 and I5 proofs, against a scriptable chain. Reconciliation's cases are
// chain states, and faking at the `Transport` keeps the real codec and the
// real `MeshClient` in every case.
// ---------------------------------------------------------------------------

mod recon_proof {
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    use mochimo_crypto::account::{Account, WotsIndex};
    use mochimo_crypto::addr::{Address, Tag};
    use mochimo_crypto::consts::SEED_LEN;
    use mochimo_crypto::keystore::Keystore;
    use mochimo_crypto::mesh::Transport;
    use mochimo_crypto::recon;
    use mochimo_crypto::{Error, Secret};

    /// `F-address-widths` (`group_f_derivation.json`): master, account 0, and
    /// the recorded `account_tag`. The chain states below are built from this
    /// seed's derived addresses, so every value traces to a recorded vector.
    pub const MASTER: [u8; SEED_LEN] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    pub const TAG: Tag = [
        0x05, 0xff, 0x0f, 0x69, 0xd4, 0xc1, 0xcd, 0x68, 0x2e, 0xd3, 0x34, 0x1c, 0x0b, 0x77, 0x73,
        0x05, 0x4b, 0x58, 0x80, 0x0f,
    ];

    #[derive(Clone, Copy)]
    pub enum ChainState {
        At(Address, u64),
        Absent,
        Unreachable,
    }

    pub struct Chain {
        pub states: RefCell<BTreeMap<Tag, ChainState>>,
    }

    impl Chain {
        pub fn new(states: &[(Tag, ChainState)]) -> Chain {
            Chain {
                states: RefCell::new(states.iter().copied().collect()),
            }
        }
    }

    impl Transport for Chain {
        fn post(&self, path: &str, body: &[u8]) -> mochimo_crypto::Result<Vec<u8>> {
            if path != "/call" {
                return Err(Error::MeshResponse { what: "proof: only /call" });
            }
            let req: serde_json::Value = serde_json::from_slice(body)
                .map_err(|_| Error::MeshResponse { what: "proof: request" })?;
            let asked = req["parameters"]["tag"]
                .as_str()
                .ok_or(Error::MeshResponse { what: "proof: parameters.tag" })?;
            let tag: Tag = mochimo_crypto::mesh::hex::decode_prefixed(asked, "proof tag")?;
            match self.states.borrow().get(&tag).copied() {
                Some(ChainState::At(address, balance)) => Ok(format!(
                    r#"{{"result":{{"address":"0x{}","amount":{}}},"idempotent":true}}"#,
                    hexs(&address),
                    balance
                )
                .into_bytes()),
                Some(ChainState::Absent) | None => {
                    Ok(br#"{"code":4,"message":"Account not found","retriable":false}"#.to_vec())
                }
                Some(ChainState::Unreachable) => Err(Error::Transport {
                    op: "connect",
                    kind: mochimo_crypto::TransportKind::Io(std::io::ErrorKind::ConnectionRefused),
                }),
            }
        }
    }

    pub fn hexs(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    pub fn master() -> Secret<SEED_LEN> {
        Secret::new(MASTER)
    }

    pub fn pos(i: u32) -> WotsIndex {
        let mut p = WotsIndex::ZERO;
        for _ in 0..i {
            p = p.advanced().unwrap_or_else(|e| panic!("{e}"));
        }
        p
    }

    pub fn addr_at(i: u32) -> Address {
        recon::derived_address_at(&master(), 0, pos(i))
    }

    pub fn store(dir: &std::path::Path) -> Keystore {
        let mut ks = Keystore::create(dir, &super::keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
        ks.add(Account::derive(&master(), 0)).unwrap_or_else(|e| panic!("{e}"));
        ks
    }

    pub use super::keystore_harness::{reopen, ScratchDir};
    // Re-exported so the proofs below can name them directly.
    pub use mochimo_crypto::consts::ADDR_TAG_LEN as TAGLEN;
    pub use mochimo_crypto::mesh::MeshClient as MC;
    pub use mochimo_crypto::recon::{
        ChainPosition as CP, Divergence as D, RestoreFailure as RF, ScanScope as SS,
        RECOVERY_CEILING as BOUND,
    };

    /// The ceiling the two proofs below walk, instead of the default `BOUND`
    /// of 10,000. Both drive walks that must exhaust the ceiling, and the I5
    /// proof runs `n(n+1)/2` derivations, so the default would take hours.
    /// The properties hold at any ceiling; the default's value is pinned in
    /// `tests/recon.rs` without a walk.
    pub const WALK: u32 = 20;
    pub use mochimo_crypto::wallet::Wallet as W;
    pub use mochimo_crypto::recon as recon_api;
}

/// I4's proof: the wallet refuses to start on index divergence in both
/// directions, and the refusal names what diverged, by how much, and what to
/// do.
///
/// Local ahead of the chain means a second wallet on this seed has spent
/// keys this one has not, so both directions are driven (floor 2), plus the
/// constructor's other refusal paths. The refusal is asserted as rendered
/// text from a real run.
#[test]
fn startup_refuses_to_start_on_index_divergence() {
    use recon_proof::*;

    let m = master();
    let mut cases = 0usize;

    // (1) Local behind: the chain is at index 3, the store at 0; a spend
    // landed that was never recorded here.
    let d1 = ScratchDir::new("i4-behind");
    let ks = store(d1.path());
    let refusal = W::open(ks, MC::new(Chain::new(&[(TAG, ChainState::At(addr_at(3), 1))])), Some(&m))
        .expect_err("local behind must refuse");
    let behind_text = format!("{refusal}");
    assert!(
        matches!(refusal.diverged[0], D::IndexMismatch { found: CP::Ahead { gap: 3, .. }, .. }),
        "{:?}",
        refusal.diverged[0]
    );
    cases += 1;

    // (2) Local ahead: the store advanced to 3, the chain still at 0.
    let d2 = ScratchDir::new("i4-ahead");
    let mut ks = store(d2.path());
    let _ = ks.persist_advance_to(&TAG, pos(3)).unwrap_or_else(|e| panic!("{e}"));
    drop(ks);
    let ks = reopen("I4 ahead", d2.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let refusal2 = W::open(ks, MC::new(Chain::new(&[(TAG, ChainState::At(addr_at(0), 1))])), Some(&m))
        .expect_err("local ahead must refuse");
    let ahead_text = format!("{refusal2}");
    assert!(
        matches!(refusal2.diverged[0], D::IndexMismatch { found: CP::Behind { gap: 3, .. }, .. }),
        "{:?}",
        refusal2.diverged[0]
    );
    cases += 1;

    // (3) The chain holds an address no index of this seed reproduces.
    // Driven through the reconciler `W::open` calls, at a ceiling this case
    // names, because `open`'s default ceiling of 10,000 would make this case
    // slow. `open` refusing on the reconciler's result is covered by cases
    // (1), (2), (4), (5) and (6).
    let d3 = ScratchDir::new("i4-alien");
    let ks = store(d3.path());
    let mut alien = addr_at(0);
    alien[TAGLEN] ^= 0x01;
    let div3 = recon_api::reconcile_account_with(
        &ks,
        &MC::new(Chain::new(&[(TAG, ChainState::At(alien, 1))])),
        &TAG,
        &mochimo_crypto::keystore::KeyAccess::Master(&m),
        &SS::DIAGNOSTIC.with_ceiling(WALK),
        &recon_api::Cancel::NEVER,
    )
    .expect_err("an alien address must diverge");
    assert!(matches!(div3, D::IndexMismatch { found: CP::Unlocated { .. }, .. }), "{div3:?}");
    cases += 1;

    // (4) the ledger has no entry for the tag
    let d4 = ScratchDir::new("i4-absent");
    let ks = store(d4.path());
    let refusal4 = W::open(ks, MC::new(Chain::new(&[(TAG, ChainState::Absent)])), Some(&m))
        .expect_err("an absent tag must refuse");
    assert!(matches!(refusal4.diverged[0], D::TagUnresolved { .. }));
    cases += 1;

    // (5) the chain cannot be reached -- an unreconciled wallet must not sign
    let d5 = ScratchDir::new("i4-unreachable");
    let ks = store(d5.path());
    let refusal5 = W::open(ks, MC::new(Chain::new(&[(TAG, ChainState::Unreachable)])), Some(&m))
        .expect_err("an unreachable chain must refuse");
    assert!(matches!(refusal5.diverged[0], D::ChainUnreachable { .. }));
    cases += 1;

    // (6) a derived account with no master to derive its addresses from
    let d6 = ScratchDir::new("i4-nomaster");
    let ks = store(d6.path());
    let refusal6 = W::open(ks, MC::new(Chain::new(&[(TAG, ChainState::At(addr_at(0), 1))])), None)
        .expect_err("no master must refuse");
    assert!(
        matches!(refusal6.diverged[0], D::NoMasterForDerivedAccount { .. }),
        "a derived account with no master must be refused as unreconcilable, not skipped: {:?}",
        refusal6.diverged[0]
    );
    cases += 1;

    // (7) Local behind, far along: the store at 22, the chain at 24, past
    // the recovery range. The diagnostic searches a window around the local
    // index, so it finds the position rather than reporting a foreign tag.
    let d8 = ScratchDir::new("i4-far-along");
    let mut ks = store(d8.path());
    let _ = ks.persist_advance_to(&TAG, pos(22)).unwrap_or_else(|e| panic!("{e}"));
    drop(ks);
    let ks = reopen("I4 far along", d8.path()).result.unwrap_or_else(|e| panic!("{e}"));
    let refusal7 = W::open(ks, MC::new(Chain::new(&[(TAG, ChainState::At(addr_at(24), 1))])), Some(&m))
        .expect_err("a gap of two at position 22 must refuse");
    assert!(
        matches!(refusal7.diverged[0], D::IndexMismatch { found: CP::Ahead { gap: 2, .. }, .. }),
        "a gap of two at position 22 was not located as two ahead: {:?}",
        refusal7.diverged[0]
    );
    cases += 1;

    // Control: with the chain where the store is, the wallet opens, so the
    // refusals above are not a constructor that refuses everything.
    let d7 = ScratchDir::new("i4-control");
    let ks = store(d7.path());
    let w = W::open(ks, MC::new(Chain::new(&[(TAG, ChainState::At(addr_at(0), 42))])), Some(&m))
        .unwrap_or_else(|e| panic!("the healthy case must open:\n{e}"));
    assert_eq!(w.accounts().len(), 1);

    // Message content, from the rendered text of a real run.
    for (text, direction) in [(&behind_text, "4"), (&ahead_text, "4")] {
        let _ = direction;
        assert!(text.contains("WALLET WILL NOT START"), "the refusal does not say so:\n{text}");
        assert!(text.contains(&hexs(&TAG)), "the account is not named:\n{text}");
        assert!(text.contains("three causes"), "the reason is not given:\n{text}");
        assert!(text.contains("ACTION:"), "no action is named:\n{text}");
        assert!(
            text.contains("Do not delete local state"),
            "the workaround I4's decision names is not warned against:\n{text}"
        );
    }
    // What diverged, both indices, and the size of the gap.
    assert!(behind_text.contains("local index 0"), "the local index is missing:\n{behind_text}");
    assert!(behind_text.contains("key at index 3"), "the chain's index is missing:\n{behind_text}");
    assert!(behind_text.contains("3 ahead of local"), "the gap is missing:\n{behind_text}");
    assert!(behind_text.contains(&hexs(&addr_at(0))), "the local address is missing");
    assert!(behind_text.contains(&hexs(&addr_at(3))), "the chain's address is missing");
    assert!(ahead_text.contains("local index 3"), "the local index is missing:\n{ahead_text}");
    assert!(ahead_text.contains("3 BEHIND local"), "the direction is missing:\n{ahead_text}");
    assert!(
        ahead_text.contains("roll back to 0 through the acknowledged path") && ahead_text.contains("has signed before"),
        "the ahead case does not name the rollback and its cost:\n{ahead_text}"
    );

    // Every integer on this line is a count of divergence cases.
    println!(
        "  I4 reconciliation: {cases} divergence case(s) driven, both directions among them, \
         1 healthy control that opened"
    );
}

/// I5's proof: restore derives the index from chain state, never assumes
/// zero, and the scan stops on the match rather than after a run of misses.
///
/// `RECOVERY_CEILING` (10,000 positions by default) bounds the failing
/// search. An address no walked position reproduces means an account
/// further along than the walk, a seed that does not own the tag, or a
/// wallet on another chain; the failure names all three. Both edges are
/// asserted: the last position inside the bound is found and the first
/// outside it is refused with the bound reported. This proof walks the
/// ceiling named in its body; the default's value and a raised ceiling are
/// covered in `tests/recon.rs`.
///
/// There is no gap-scan comparison: per-index usage is unobservable on this
/// chain (see the `recon` module doc).
#[test]
fn restore_derives_the_index_from_chain_state() {
    use recon_proof::*;

    // The ceiling is `WALK`, from `recon_proof`: this loop runs one restore
    // per position, `n(n+1)/2` derivations in all. The census floor matches.
    let scope = SS::RESTORE.with_ceiling(WALK);

    // (1) Every position inside the bound is found exactly, and the scan
    // stops on the match: one query, then a local walk.
    let mut found_at = 0u32;
    for i in 0..WALK {
        let client = MC::new(Chain::new(&[(TAG, ChainState::At(addr_at(i), 1_000 + u64::from(i)))]));
        let r = recon_api::restore_account_index_with(&client, &master(), 0, &scope, &recon_api::Cancel::NEVER).unwrap_or_else(|e| {
            panic!("the scan did not reach position {i} inside the bound:\n{e}")
        });
        assert_eq!(r.index, pos(i), "the scan derived the wrong index at position {i}");
        assert_eq!(r.tag, TAG, "the scan derived the wrong tag");
        assert_eq!(r.balance, 1_000 + u64::from(i));
        found_at = i;
    }
    let scan_bound_exercised = found_at + 1;
    assert_eq!(scan_bound_exercised, WALK, "the whole bound was not walked");

    // (2) Never zero on any failing path: each of the three is a failure,
    // never a fallback.
    let mut refusals = 0usize;
    let client = MC::new(Chain::new(&[(TAG, ChainState::Unreachable)]));
    assert!(
        matches!(
            recon_api::restore_account_index(&client, &master(), 0),
            Err(RF::ChainUnreachable { .. })
        ),
        "an unreachable chain must fail rather than assume an index"
    );
    refusals += 1;
    let client = MC::new(Chain::new(&[(TAG, ChainState::Absent)]));
    assert!(
        matches!(
            recon_api::restore_account_index(&client, &master(), 0),
            Err(RF::TagUnresolved { .. })
        ),
        "a tag the ledger does not hold must fail rather than assume an index"
    );
    refusals += 1;
    let mut alien = addr_at(0);
    alien[TAGLEN] ^= 0x01;
    let client = MC::new(Chain::new(&[(TAG, ChainState::At(alien, 1))]));
    match recon_api::restore_account_index_with(&client, &master(), 0, &scope, &recon_api::Cancel::NEVER) {
        Err(RF::NoIndexReproducesTheAddress { scanned, .. }) => {
            assert_eq!(scanned, WALK, "the bound reported is not the bound walked");
        }
        other => panic!("an unreproducible address must fail: {other:?}"),
    }
    refusals += 1;
    assert_eq!(refusals, 3);

    // (3) The last position inside the bound is found; the first outside is
    // refused.
    let client = MC::new(Chain::new(&[(TAG, ChainState::At(addr_at(WALK - 1), 1))]));
    assert_eq!(
        recon_api::restore_account_index_with(&client, &master(), 0, &scope, &recon_api::Cancel::NEVER)
            .unwrap_or_else(|e| panic!("the last position INSIDE the bound was not reached:\n{e}"))
            .index,
        pos(WALK - 1)
    );
    let client = MC::new(Chain::new(&[(TAG, ChainState::At(addr_at(WALK), 1))]));
    assert!(
        matches!(
            recon_api::restore_account_index_with(&client, &master(), 0, &scope, &recon_api::Cancel::NEVER),
            Err(RF::NoIndexReproducesTheAddress { .. })
        ),
        "the first position OUTSIDE the bound was reached; the bound stopped bounding"
    );

    // (4) The failure text, read from a real run.
    let client = MC::new(Chain::new(&[(TAG, ChainState::Unreachable)]));
    let text = match recon_api::restore_account_index(&client, &master(), 0) {
        Err(e) => format!("{e}"),
        Ok(_) => panic!("must fail"),
    };
    assert!(text.contains("does NOT fall back to index zero"), "{text}");

    // Every integer on this line but the last is a scan position: the bound
    // walked and the positions found. The last is the default recovery
    // ceiling, which this proof does not walk.
    println!(
        "  I5 restore scan: {scan_bound_exercised} scan position(s) exercised, every one found \
         exactly, {refusals} failing path(s) that returned no index at all; the shipped default \
         ceiling is {BOUND} and is not walked here"
    );
}

/// `syn` is a dev-dependency and stays one.
///
/// `syn` is already in the build graph through a proc macro:
///
/// ```text
/// mochimo-crypto -> zeroize -> zeroize_derive (proc-macro) -> syn
/// ```
///
/// That path is build-time only and never linked into the rlib, so the
/// property is narrower than "no `syn` in the graph":
///
/// 1. No `syn` in `crates/*/src/` (comment-stripped).
/// 2. `syn` is a direct dependency only under `[dev-dependencies]`, in every
///    workspace member.
///
/// Assertion 2's `[dependencies]` arm is the only part rustc would not catch:
/// `syn::` in `src/` with `syn` dev-only fails to resolve, and removing `syn`
/// from `[dev-dependencies]` stops this file compiling. The other arms give a
/// clearer message for those failures.
///
/// Not covered: a transitive normal dependency that itself pulls `syn` as a
/// linked library, which would need `cargo tree -e normal`.
#[test]
fn syn_is_confined_to_the_test_targets() {
    // 1. No use from library code.
    let mut users: Vec<String> = Vec::new();
    for (name, code) in crate_sources() {
        if code.contains("syn::") || code.contains("use syn") {
            users.push(name);
        }
    }
    assert!(
        users.is_empty(),
        "these library sources reference `syn`: {users:?}\n\
         It is a dev-dependency, added so that the I7 signature scan \
         parses Rust instead of approximating it. It has no business in the \
         shipped crate. See Cargo.toml's note."
    );

    // 2. Direct-dependency placement, in every workspace member.
    let root = repo_root();
    let crates = root.join("crates");
    let mut members = 0usize;
    let mut dev_declarations = 0usize;
    let entries = std::fs::read_dir(&crates)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", crates.display()));
    for member in entries.flatten() {
        let manifest = member.path().join("Cargo.toml");
        if !manifest.is_file() {
            continue;
        }
        members += 1;
        let text = std::fs::read_to_string(&manifest)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", manifest.display()));
        let doc: toml::Value = text
            .parse()
            .unwrap_or_else(|e| panic!("cannot parse {}: {e}", manifest.display()));
        let name = member.file_name().to_string_lossy().into_owned();
        for table in ["dependencies", "build-dependencies"] {
            assert!(
                doc.get(table).and_then(|t| t.get("syn")).is_none(),
                "{name}/Cargo.toml declares `syn` under [{table}]. It is a \
                 dev-dependency: it exists to make the I7 signature scan parse \
                 Rust rather than approximate it, and it never ships. If a \
                 library genuinely needs it, that is a decision recorded in the \
                 specification, not a moved line."
            );
        }
        if doc
            .get("dev-dependencies")
            .and_then(|t| t.get("syn"))
            .is_some()
        {
            dev_declarations += 1;
        }
    }

    // Vacuity guards: no manifests found, or `syn` gone from the tree, would
    // let the assertions above pass over nothing.
    assert!(
        members >= 1,
        "found no workspace member manifest under {}; the walk is broken and \
         the placement assertions above ran over nothing",
        crates.display()
    );
    assert_eq!(
        dev_declarations, 1,
        "expected exactly one [dev-dependencies] declaration of `syn` across \
         the workspace, found {dev_declarations}. Zero means the I7 signature \
         scan has lost its parser and is silently back to a substring walk; \
         more than one means a second crate acquired it and this check's \
         reasoning about why it is safe has not been re-done."
    );

    println!(
        "  syn confinement: {members} workspace members checked, \
         {dev_declarations} dev-dependency declaration, 0 library references. \
         NOTE: syn is already in the normal graph via zeroize -> \
         zeroize_derive (proc-macro); see this test's docs."
    );
}

/// Count `#[ignore]` attributes inside a macro invocation's token stream.
///
/// Recursive over nested groups. Matches `#` followed by a bracket group
/// whose sole token is the ident `ignore`, which a comment or string literal
/// cannot produce.
fn ignore_attrs_in_tokens(tokens: proc_macro2::TokenStream) -> usize {
    attrs_in_tokens(tokens, "ignore")
}

/// The `#[test]` counterpart, so the vacuity floor counts the same population
/// the ban walks.
fn count_test_attrs_in_tokens(tokens: proc_macro2::TokenStream) -> usize {
    attrs_in_tokens(tokens, "test")
}

fn attrs_in_tokens(tokens: proc_macro2::TokenStream, want: &str) -> usize {
    let mut found = 0usize;
    let mut prev_was_hash = false;
    for tree in tokens {
        match tree {
            proc_macro2::TokenTree::Punct(ref p) if p.as_char() == '#' => {
                prev_was_hash = true;
                continue;
            }
            proc_macro2::TokenTree::Group(g) => {
                if prev_was_hash && g.delimiter() == proc_macro2::Delimiter::Bracket {
                    let inner: Vec<_> = g.stream().into_iter().collect();
                    if inner.len() == 1 {
                        if let proc_macro2::TokenTree::Ident(id) = &inner[0] {
                            if id == want {
                                found += 1;
                            }
                        }
                    }
                }
                found += attrs_in_tokens(g.stream(), want);
            }
            _ => {}
        }
        prev_was_hash = false;
    }
    found
}

/// No test in this crate's suite is `#[ignore]`d.
///
/// An ignored test is not a failed one: libtest prints `ignored` and the run
/// still ends `ok`. The census catches an ignored censused target (it counts
/// `passed`); this ban covers every test in the tree, including those no
/// guard names. A genuinely needed exception must be argued at this test.
///
/// Items are walked with `syn`, so `#[ignore]` in a doc comment or string
/// literal does not count. Macro invocation bodies are walked as tokens,
/// since `syn` cannot parse them as items; tokenization has already dropped
/// comments, and a string literal is one `Literal` token. The count walked is
/// printed from the run.
///
/// Not covered: a test renamed together with its census row is green over
/// whatever the new test does.
#[test]
fn no_test_in_the_suite_is_ignored() {
    let mut ignored: Vec<String> = Vec::new();
    let mut tests = 0usize;
    let mut files = 0usize;

    for (name, text) in test_source_files() {
        files += 1;
        // Parsed, not searched: `kat.rs` documents its choice to be
        // "deliberately not `#[ignore]`", which a text needle would report.
        let Ok(ast) = syn::parse_file(&text) else {
            // A test file that does not parse is reported, not skipped.
            ignored.push(format!("\x20 - {name}: syn could not parse this file"));
            continue;
        };
        let mut items: Vec<&syn::Item> = ast.items.iter().collect();
        while let Some(item) = items.pop() {
            match item {
                syn::Item::Mod(m) => {
                    if let Some((_, inner)) = &m.content {
                        items.extend(inner.iter());
                    }
                }
                syn::Item::Fn(f) => {
                    if f.attrs.iter().any(|a| a.path().is_ident("test")) {
                        tests += 1;
                        if f.attrs.iter().any(|a| a.path().is_ident("ignore")) {
                            ignored.push(format!("\x20 - {name}::{}", f.sig.ident));
                        }
                    }
                }
                // Macro invocation bodies, which are not parseable as items,
                // walked as tokens. Tokenization has dropped comments, and a
                // string literal containing "#[ignore]" is one Literal token.
                syn::Item::Macro(m) => {
                    let hits = ignore_attrs_in_tokens(m.mac.tokens.clone());
                    tests += count_test_attrs_in_tokens(m.mac.tokens.clone());
                    for _ in 0..hits {
                        ignored.push(format!(
                            "\x20 - {name}: an #[ignore] inside a `{}!` block",
                            m.mac
                                .path
                                .segments
                                .last()
                                .map_or_else(|| "?".to_string(), |s| s.ident.to_string())
                        ));
                    }
                }
                _ => {}
            }
        }
    }

    // Vacuity guards: no files, or no `#[test]` items parsed, would satisfy
    // the assertion below over nothing.
    assert!(
        files >= 14,
        "the tests/ walk found only {files} file(s); the tree holds 22 and this \
         floor is two thirds of that, so the walk has lost a third of the \
         suite's files and this check is running over what is left"
    );
    // Floor calibrated against the measured population the ban walks
    // (item-level `#[test]` plus any inside a macro invocation body).
    assert!(
        tests >= 226,
        "found only {tests} #[test] functions across {files} files; the \
         collector is broken and any result from it is vacuous. Measured at 340 \
         across 22 files, and this floor is two thirds of that."
    );

    assert!(
        ignored.is_empty(),
        "these tests are #[ignore]d:\n{}\n\
         An ignored test is invisible debt: it prints `ignored` in a run whose \
         last line says `ok`, a run is read by the names of its failures, and \
         nothing here consumes libtest's ignored count.\n\
         The second half of this message used to say that fourteen guards would \
         go on certifying an #[ignore]d test, because they searched for \
         `fn <name>` in source. Those fourteen now key on the census, and \
         an ignored censused target reddens its own guard as well as this ban. \
         What this ban still covers, and the census does not, is every test no \
         guard names -- which is most of them.\n\
         If an ignored test is genuinely wanted, that is a decision recorded in \
         the specification and an exception argued here, not an attribute.",
        ignored.join("\n")
    );

    println!(
        "  ignored-test ban: {tests} #[test] functions across {files} files, \
         0 ignored. This is EXISTENCE over the whole suite; EXECUTION is the \
         census, and it covers the sixteen edges the guards name rather than \
         all {tests}. See this test's documentation."
    );
}

/// Group E constants that this crate has no literal for, each with the
/// reason it is not this wallet's to pin. See
/// [`group_e_constants_stay_anchored`] for the two guards that keep each row
/// honest.
const NOT_THIS_WALLETS_TO_PIN: [(&str, &str); 1] = [(
    "sizeof_TX",
    "the size of the node's network packet container, 65,664 bytes. This wallet never builds \
     or reads such a packet -- it speaks to the Mesh over HTTP, and the node's own framing is \
     the specification's open item -- and the two ways to pin the number here, a literal \
     transcribed from the fixture or an expression transcribed from the reference's types.h, \
     both compare the fixture to itself.",
)];

/// Every group E constant is compared with the reference fixture by a
/// checker that runs.
///
/// `kat.rs::group_e_constants_match_the_reference` compares the fixture's
/// constants with the crate's own literals. Names are read from the fixture,
/// so a constant added later is owed automatically, and the checker's
/// execution is required through the census, since a checker removed by
/// `#[cfg]` still contains every name. Exclusions live in
/// [`NOT_THIS_WALLETS_TO_PIN`], each with its reason; a row the fixture does
/// not carry, or one the checker compares anyway, fails.
#[test]
fn group_e_constants_stay_anchored() {
    // Prose, not a value: the reference records `valid_op_rule` as a
    // sentence. The predicate is tested in tests/net.rs and listed in
    // kat.rs::WEAKLY_ANCHORED.
    let path = repo_root().join("fixtures/group_e_net.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let root: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("{} is not JSON: {e}", path.display()));

    let consts = root
        .get("constants")
        .and_then(|c| c.as_object())
        .unwrap_or_else(|| panic!("{} has no `constants` object", path.display()));

    // Flatten `constants` and the nested `opcodes`, keeping only names that
    // denote a value. `note` and `valid_op_rule` are prose.
    let mut names: Vec<String> = Vec::new();
    for (k, v) in consts {
        match v {
            serde_json::Value::Object(inner) => names.extend(
                inner
                    .iter()
                    .filter(|(_, v)| v.is_number())
                    .map(|(k, _)| k.clone()),
            ),
            v if v.is_number() => names.push(k.clone()),
            _ => {}
        }
    }
    assert!(
        names.len() > 20,
        "group_e_net.json yielded only {} constant names; the flatten above is \
         probably wrong and this test would pass vacuously",
        names.len()
    );

    // The comparison itself, read as source: a value assertion cannot see a
    // constant nobody wrote an assertion for.
    const CHECKER: &str = "group_e_constants_match_the_reference";
    // `test_sources()` already strips comments.
    //
    // The needle is deliberately unterminated (no closing paren). It only
    // locates the start of the checker's body; the body is then bounded to
    // the next item, length-checked on both sides, and searched for every
    // constant name, so a wrong match is caught by what follows. A terminated
    // needle would fail on a harmless suffix rename. An unterminated one could
    // only mis-locate on a `fn` sharing this exact prefix in a file sorting
    // before `kat.rs`.
    let all = test_sources();
    let start = all.find(&format!("fn {CHECKER}")).unwrap_or_else(|| {
        panic!(
            "{CHECKER} no longer exists. It is the only thing comparing group \
             E's constants to the C; without it the fixture is back to agreeing \
             with itself."
        )
    });

    // Scoped to that one function rather than all of `tests/`, where an
    // unrelated mention of a name (such as OP_HASH in `tests/net.rs`) would
    // count as coverage.
    let body = &all[start..];
    // The nearest following item boundary, whichever kind it is.
    let end = [body[1..].find("\nfn "), body[1..].find("\n#[test]")]
        .into_iter()
        .flatten()
        .min()
        .map(|i| i + 1)
        .unwrap_or_else(|| {
            // Fail closed: with no boundary the slice would become the rest
            // of the corpus and every name would be "found".
            panic!(
                "no item boundary follows {CHECKER} in the corpus, so its body \
                 cannot be bounded. Extracting to the end of the corpus would \
                 make every group E constant read as present."
            )
        });
    let checker = &body[..end];
    // Two-sided, and both sides name the measured length so a failure says
    // which direction it moved.
    assert!(
        (500..8_000).contains(&checker.len()),
        "the {CHECKER} body extracted to {} chars, outside 500..8000; it \
         measures 3,569 on the tree this bound was derived from. Too short and every name \
         reads as missing; too long and the slice has run into neighbouring \
         functions, where a name found is not a name this checker asserts.",
        checker.len()
    );

    // Each declared exclusion is checked both ways before it excuses
    // anything: a row naming a constant the fixture does not carry permits
    // nothing, and a row naming a constant the checker compares is false.
    for (name, reason) in NOT_THIS_WALLETS_TO_PIN {
        assert!(
            names.iter().any(|n| n == name),
            "NOT_THIS_WALLETS_TO_PIN excludes `{name}`, which fixtures/group_e_net.json does \
             not carry: a stale exclusion row is a permit for nothing. Remove the row. Its \
             reason read: {reason}"
        );
        assert!(
            !checker.contains(&format!("\"{name}\"")),
            "NOT_THIS_WALLETS_TO_PIN excludes `{name}` -- {reason} -- but {CHECKER} names and \
             compares it after all: an exclusion for a thing that is compared is a lie. Remove \
             the row."
        );
    }
    let excluded = |n: &String| NOT_THIS_WALLETS_TO_PIN.iter().any(|(x, _)| x == n);
    let missing: Vec<&String> = names
        .iter()
        .filter(|n| !excluded(n) && !checker.contains(&format!("\"{n}\"")))
        .collect();

    let n = missing.len();
    assert!(
        missing.is_empty(),
        "{n} of group E's constants are in fixtures/group_e_net.json but not \
         named in {CHECKER}: {missing:?}.\n\
         A constant no assertion mentions is pinned against nothing: the fixture \
         and the crate's literal agree with each other and neither is compared \
         to the other, so a transcription error in it is undetectable. Add it \
         to the comparison in tests/kat.rs -- or, if it is not this wallet's to \
         pin, a row to NOT_THIS_WALLETS_TO_PIN with the reason, which this \
         check prints and holds honest."
    );

    // Execution, not text: a checker compiled out by a `#[cfg]` still
    // contains every name. The census floor is 32, the count the checker
    // asserts; `sizeof_TX` has no native literal.
    if let Err(why) = census::check("group_e_constants_stay_anchored", CHECKER) {
        panic!(
            "group E's {} constants are named by {CHECKER} and compared by nothing that \
             runs: the checker must be in tests/kat.rs's run list, run, pass and print \
             `group E constants anchored` with 32.\n{why}\n\
             Until it runs, `consts::net`'s literals and fixtures/group_e_net.json's \
             `constants` block agree only with themselves.",
            names.len()
        );
    }

    let compared = names.len() - NOT_THIS_WALLETS_TO_PIN.len();
    let excluded_names: Vec<&str> = NOT_THIS_WALLETS_TO_PIN.iter().map(|(n, _)| *n).collect();
    println!(
        "  {} group E constants anchored: {compared} compared by the checker, {} excluded by \
         name with a reason ({}); checker censused",
        names.len(),
        NOT_THIS_WALLETS_TO_PIN.len(),
        excluded_names.join(", ")
    );
}

/// The suite's independence, enforced.
///
/// Every other oracle traces to the same C reference, so a misreading of it
/// propagates identically into every fixture derived from it.
/// `crosscheck_typescript_expected` is the exception: a separate
/// implementation produced that string from the same tag. It equals
/// `base58_of_tag22`, so it looks like a duplicated literal.
///
/// What this catches:
///
/// - *Allow-listing.* Coverage forces every field to be read, so silencing
///   coverage is how a crosscheck could be dropped without a red. This test
///   reads `METADATA_KEYS` and `PROSE_KEYS` from the support module and fails
///   if a crosscheck name appears in either.
/// - *Name removal.* Dropping a name from `crosscheck_verdicts` should leave
///   the field mentioned nowhere in `tests/`. That holds for five of the nine
///   fields. `crosscheck_typescript_executed`, `crosscheck_typescript_expected`,
///   `crosscheck_executed_matches_literal` and `crosschecks_vector` also
///   appear in the fixture-shape scan's required-keys list in this file, so
///   for those four the enforcing mechanism is `Ctx::check_coverage`: the
///   field goes unread and `active_groups_replay` fails naming it.
///
/// Not caught here: *assertion removal*. Deleting the `eq_str` but keeping
/// `ctx.has(...)` leaves the name present. `Ctx::check_coverage` reports the
/// field as unread instead, because `has()` does not record a read.
///
/// The domain is read from the fixtures, so a crosscheck field added later
/// is covered automatically.
#[test]
fn crosscheck_fields_stay_asserted() {
    // Every crosscheck field the fixtures carry, read from them so the domain
    // grows with the fixtures.
    let dir = repo_root().join("fixtures");
    let mut names: BTreeSet<String> = BTreeSet::new();
    let mut files = 0usize;
    for e in std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .flatten()
    {
        let p = e.path();
        if p.extension().is_none_or(|x| x != "json") {
            continue;
        }
        files += 1;
        let text = std::fs::read_to_string(&p).unwrap_or_default();
        let root: serde_json::Value = serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("{} is not JSON: {e}", p.display()));
        let Some(vectors) = root.get("vectors").and_then(|v| v.as_array()) else {
            continue;
        };
        for v in vectors {
            let Some(obj) = v.as_object() else { continue };
            names.extend(
                obj.keys()
                    .filter(|k| k.contains("crosscheck") || k.contains("matches_reference"))
                    // `*_source` is a file:line locator pointing at the other
                    // implementation, not a value or verdict, so it is prose.
                    // Excluded by suffix so later locators are covered too.
                    .filter(|k| !k.ends_with("_source"))
                    .cloned(),
            );
        }
    }

    assert!(
        files >= 5 && names.len() >= 5,
        "the fixture walk found {files} json file(s) and {} crosscheck field(s); \
         it is probably broken and this test would pass vacuously",
        names.len()
    );

    // `support/mod.rs` is read raw here, so it is stripped explicitly.
    let harness = test_sources();
    let support = code_only(
        &std::fs::read_to_string(repo_root().join("crates/mochimo-crypto/tests/support/mod.rs"))
            .expect("cannot read tests/support/mod.rs"),
    );

    // The two allow-lists, located once and fail-closed. A conditional
    // lookup inside the loop would let a renamed constant silently remove
    // the arm.
    let allow_lists: Vec<(&str, &str)> = ["METADATA_KEYS", "PROSE_KEYS"]
        .into_iter()
        .map(|list| {
            let Some(start) = support.find(&format!("const {list}")) else {
                panic!(
                    "tests/support/mod.rs has no `const {list}`. This arm reads \
                     that declaration by name, so not finding it means the arm \
                     does not run at all. If the constant was renamed, rename it \
                     here; do not let the lookup fail quietly."
                )
            };
            let Some(end) = support[start..].find("];").map(|i| start + i) else {
                panic!(
                    "`const {list}` is not terminated by `];` anywhere after it \
                     in tests/support/mod.rs. Falling back to the end of the \
                     file -- which is what this once did -- makes the \
                     span the rest of the module and every crosscheck name read \
                     as allow-listed."
                )
            };
            let span = &support[start..end];
            // Bounded both ways, from measured lengths: a span grown into the
            // surrounding module would find names not on the list, and a
            // collapsed one would find nothing and pass.
            assert!(
                (20..1_000).contains(&span.len()) && span.matches('"').count() >= 2,
                "the `const {list}` span extracted to {} chars with {} quoted \
                 entr(y/ies); on this tree METADATA_KEYS measures 74 chars over \
                 5 entries and PROSE_KEYS 271 over 8. Outside that range this \
                 arm is reading something other than the declaration.",
                span.len(),
                span.matches('"').count() / 2
            );
            (list, span)
        })
        .collect();

    let mut gone: Vec<String> = Vec::new();
    for name in &names {
        let quoted = format!("\"{name}\"");
        if !harness.contains(&quoted) {
            gone.push(format!("\x20 - {name} is named by no assertion in tests/"));
        }
        // Silencing coverage, rather than deleting the assertion, is the
        // way a crosscheck could be dropped without a vector going red.
        for (label, span) in &allow_lists {
            if span.contains(&quoted) {
                gone.push(format!("\x20 - {name} has been allow-listed into {label}"));
            }
        }
    }

    assert!(
        gone.is_empty(),
        "the suite's independence has been undone:\n{}\n\
         These are the only oracles in the suite that are not derived from the \
         same C. Two C-derived vectors cannot disagree with each other, so a \
         misreading of the C propagates identically into both; only an \
         independent implementation can catch it. Every one of these fields \
         duplicates a value that is computed elsewhere -- \
         `crosscheck_typescript_expected` equals `base58_of_tag22`, \
         `crosscheck_typescript_executed` equals what the C computes -- and \
         that duplication is the entire point. Removing one reads as deleting a \
         repeated literal and is actually deleting a cross-implementation \
         anchor.\n\
         Note the two are not interchangeable: `_expected` is a literal read \
         out of the upstream test file, `_executed` is a return value from \
         running it. The independence rule was amended because a read literal is the floor \
         and an executed second implementation is the standard.",
        gone.join("\n")
    );
}

// =========================================================================
// Facts the tree states about itself
//
// Each check holds a statement about the tree's current state to a
// mechanism: the manifest's `reference_pin`, every fixture's `reference`
// and `pin` blocks, and the counts the documents quote.
//
// Commits are compared against what the documents state, since the
// submodules those commits named are not in this repository. Not
// checkable here: whether the stated commit is the one the generator ran.
// =========================================================================

/// A 40-hex commit a document states for a named subject, read from the
/// document at run time.
///
/// `phrase` introduces the commit, which is the run of hex digits after it.
/// Whitespace is collapsed first, since documents hard-wrap prose.
///
/// # Panics
///
/// If the phrase occurs nowhere, or introduces different commits in
/// different places.
fn stated_commit(doc: &str, text: &str, phrase: &str) -> String {
    let flat: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut found: BTreeSet<String> = BTreeSet::new();
    let mut from = 0usize;
    while let Some(i) = flat[from..].find(phrase) {
        let at = from + i + phrase.len();
        let hex: String = flat[at..].chars().take_while(char::is_ascii_hexdigit).collect();
        if hex.len() == 40 {
            found.insert(hex);
        }
        from = at;
    }
    assert!(
        !found.is_empty(),
        "{doc} states no 40-hex commit after {phrase:?}. Either the document was \
         reworded -- move this needle with it -- or the statement was dropped, \
         in which case the corpus's provenance is recorded by one document fewer."
    );
    assert_eq!(
        found.len(),
        1,
        "{doc} states {} different commits after {phrase:?}: {found:?}",
        found.len()
    );
    found.into_iter().next().unwrap_or_default()
}

/// The commits the specification states, keyed by the name the fixtures use.
///
/// Each phrase must introduce one commit wherever it occurs. Keys the
/// fixtures carry that the specification does not state are listed in
/// [`UNDOCUMENTED_PIN_KEYS`].
fn stated_commits() -> BTreeMap<&'static str, String> {
    let root = repo_root();
    let doc = "docs/specification.md";
    let spec = std::fs::read_to_string(root.join(doc)).expect("cannot read docs/specification.md");
    // (fixture key, the phrase the specification introduces the commit with)
    let table: &[(&str, &str)] = &[
        ("mochimo_core", "`mochimo-core` at commit `"),
        ("mochimo_wots_ts", "`mochimo-wots` at `"),
        ("mochimo_wallet_commit", "`mochimo-wallet` at `"),
        ("mochiwallet_commit", "`mochiwallet` at `"),
        ("mesh_api_client_commit", "`mochimo-mesh-api-client` at `"),
    ];
    let mut out = BTreeMap::new();
    for (key, phrase) in table {
        out.insert(*key, stated_commit(doc, &spec, phrase));
    }
    // `mochimo_wots_commit` is the pin-block spelling of the reference
    // block's `mochimo_wots_ts`; one document statement covers both.
    let wots = out.get("mochimo_wots_ts").cloned().unwrap_or_default();
    out.insert("mochimo_wots_commit", wots);
    out
}

/// Provenance keys the fixtures carry that no document states a commit for,
/// with the reason. Every fixture carrying such a key must agree, and the
/// value must be a 40-hex object id. A key in neither this list nor
/// [`stated_commits`] stops the run.
const UNDOCUMENTED_PIN_KEYS: &[(&str, &str)] = &[
    (
        "crypto_c",
        "the C reference's `include/crypto-c` submodule; the reference and its submodules are \
         not here, and the documents pin the reference by its own commit only",
    ),
    (
        "extended_c",
        "the C reference's `include/extended-c` submodule, as above",
    ),
    (
        "mochimo_mesh_commit",
        "the Mesh middleware group N was captured against; the specification records group N \
         as a live capture at one block and names the deployment, not the middleware's commit",
    ),
    (
        "go_mcminterface_commit",
        "the Go module that middleware delegates its wire work to; recorded only by group N's \
         pin block",
    ),
];

/// `[corpus] reference_pin` names the mochimo-core commit the corpus came
/// from, and it is the commit the documents state.
#[test]
fn corpus_reference_pin_matches_the_commit_the_documents_state() {
    let root = repo_root();
    let manifest = std::fs::read_to_string(root.join("fixtures/manifest.toml"))
        .expect("cannot read fixtures/manifest.toml");

    // Needle assembled from parts so this test's own text cannot satisfy it.
    // Terminated on `=` so a longer key cannot match.
    let key = format!("{}_{}", "reference", "pin");
    let line = manifest
        .lines()
        .find(|l| l.trim_start().starts_with(&format!("{key} ")) || l.trim_start().starts_with(&format!("{key}=")))
        .unwrap_or_else(|| {
            panic!(
                "fixtures/manifest.toml has no `{key}` line. The field is the \
                 corpus's only record of which mochimo-core it was generated \
                 against; removing it does not remove the question."
            )
        });
    let pin = line
        .split('=')
        .nth(1)
        .and_then(|v| v.trim().strip_prefix('"'))
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or_else(|| panic!("cannot parse a quoted value out of `{line}`"))
        .to_string();

    assert!(
        pin.len() >= 7 && pin.chars().all(|c| c.is_ascii_hexdigit()),
        "`{key}` is {pin:?}, which is not a hex object id of at least 7 \
         characters. A pin nobody reads is a pin that can name a commit the \
         reference does not have, and every citation resting on it then \
         points at nothing; this arm is what reads it."
    );

    let stated = stated_commits();
    let want = &stated["mochimo_core"];
    assert!(
        want.starts_with(&pin),
        "fixtures/manifest.toml's `{key}` is {pin}, but the specification states the C \
         reference at {want}. The corpus and the specification disagree about the \
         corpus's own provenance."
    );

    println!("  reference_pin: {pin} agrees with the commit the specification states");
}

/// Every fixture's `reference` block names the same four commits, and the two
/// the documents state are the ones stated.
///
/// Each C-generated `*.json` carries a `reference` object with four
/// submodule SHAs, written from the generator's `build/refver.h`. Every file
/// must agree with every other, and the two commits the documents state (the
/// reference and the TypeScript `mochimo-wots`) must be what every file
/// records. The other two keys are declared in [`UNDOCUMENTED_PIN_KEYS`].
///
/// Every `*.json` under `fixtures/` is walked. A file with no `reference`
/// block fails unless it carries a `pin` block or a `reference_commit`
/// instead, so a fixture declaring no provenance cannot pass.
#[test]
fn fixture_reference_blocks_agree_with_each_other_and_with_the_documents() {
    const KEYS: [&str; 4] = ["mochimo_core", "crypto_c", "extended_c", "mochimo_wots_ts"];
    let stated = stated_commits();
    for key in KEYS {
        assert!(
            stated.contains_key(key) || UNDOCUMENTED_PIN_KEYS.iter().any(|(k, _)| *k == key),
            "`reference.{key}` is neither stated by a document nor declared undocumented"
        );
    }

    let root = repo_root();
    let dir = root.join("fixtures");
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();

    let mut problems: Vec<String> = Vec::new();
    let mut values_checked = 0usize;
    let mut with_pin_instead = 0usize;
    let mut with_commit_instead = 0usize;
    // key -> (value, first file that stated it)
    let mut seen: BTreeMap<&str, (String, String)> = BTreeMap::new();

    for path in &files {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("?");
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        let json: serde_json::Value =
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("{name}: not JSON: {e}"));

        let Some(block) = json.get("reference").and_then(|r| r.as_object()) else {
            if json.get("pin").is_some() {
                with_pin_instead += 1;
            } else if let Some(commit) = json.get("reference_commit").and_then(|c| c.as_str()) {
                // Group V's and group S's form: a tree other than the corpus's
                // pinned reference (the proof-of-stake node, the v4.1
                // reference client), named by one top-level string whose first
                // word is the commit. The specification defers to that string
                // rather than stating the commit, so only its shape is held.
                with_commit_instead += 1;
                let id = commit.split_whitespace().next().unwrap_or("");
                if id.len() < 7 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
                    problems.push(format!(
                        "\x20 - {name}: `reference_commit` is {commit:?}, whose first word is not a commit id"
                    ));
                }
            } else {
                problems.push(format!(
                    "\x20 - {name} carries neither a `reference` block nor a `pin` \
                     block, so it records no provenance at all and cannot be \
                     paired with any version of anything"
                ));
            }
            continue;
        };

        for key in KEYS {
            let Some(value) = block.get(key).and_then(|v| v.as_str()) else {
                problems.push(format!(
                    "\x20 - {name}: `reference` carries no `{key}`, so the \
                     submodule it names went unrecorded for this fixture"
                ));
                continue;
            };
            values_checked += 1;
            if value.len() != 40 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
                problems.push(format!("\x20 - {name}: `reference.{key}` is {value:?}, not a 40-hex object id"));
            }
            match seen.get(key) {
                None => {
                    seen.insert(key, (value.to_owned(), name.to_owned()));
                }
                Some((first, first_file)) if first != value => problems.push(format!(
                    "\x20 - {name}: `reference.{key}` is {value}, but {first_file} records {first}. \
                     Two fixtures were generated from different trees."
                )),
                Some(_) => {}
            }
            if let Some(want) = stated.get(key) {
                if value != want {
                    problems.push(format!(
                        "\x20 - {name}: `reference.{key}` is {value}, but the documents state \
                         {want}. The fixture was generated from a different tree than the \
                         one the documents describe."
                    ));
                }
            }
        }
    }

    assert!(
        problems.is_empty(),
        "fixture provenance blocks disagree with each other or with the documents:\n{}",
        problems.join("\n")
    );
    // Vacuity floor, so a walk that stopped matching cannot report agreement
    // about nothing: eight C-sourced fixtures (A, AK, B, BK, C, D, E, HS)
    // times four SHAs.
    assert_eq!(
        values_checked, 32,
        "{values_checked} provenance value(s) were compared across {} fixture \
         file(s); the corpus has eight C-sourced fixtures carrying four SHAs \
         each. Fewer means the walk stopped finding the block rather than \
         finding it correct; more means a fixture gained one and this number is \
         owed a deliberate move.",
        files.len()
    );
    println!(
        "  fixture provenance: {values_checked} SHA(s) across {} file(s) agree with each other, \
         2 of 4 keys with the documents; {with_pin_instead} file(s) declare a `pin` block instead, \
         {with_commit_instead} a `reference_commit` naming a commit",
        files.len()
    );
    assert_eq!(
        with_commit_instead, 2,
        "{with_commit_instead} fixture(s) name their tree by a top-level `reference_commit`; group V \
         (the proof-of-stake node) and group S (`stake-tx.mjs`) are the two, and a third is owed a \
         deliberate move here"
    );
}

/// Counts a document quotes about a countable artifact agree with the
/// artifact.
///
/// Three subjects:
///
/// * every "N vectors" claim in `docs/specification.md` and `README.md`,
///   against the vectors on disk;
/// * every row of the specification's corpus table, `| group | file |
///   subject | vectors | oracles |`, against that file's `vectors` array;
/// * the absence of the removed `ffi-oracle` feature: no `cfg` attribute and
///   no `cfg!()` read under `crates/` names it.
///
/// The vector total is summed from every fixture's `vectors` array, not
/// taken from `manifest.toml`. The `cfg` walk lexes every `.rs` under
/// `crates/` and examines each `#[cfg(..)]`, `#![cfg(..)]` and `cfg!(..)`,
/// so a mention in a comment or string cannot count. Its positive control is
/// that the walk finds `cfg` attributes at all.
#[test]
fn documented_counts_match_the_artifacts() {
    let root = repo_root();

    // --- the truths, each derived from the artifact ---------------------
    let fx = root.join("fixtures");
    let mut vector_total = 0usize;
    let mut per_file: BTreeMap<String, usize> = BTreeMap::new();
    for e in std::fs::read_dir(&fx).expect("cannot read fixtures/") {
        let p = e.expect("dir entry").path();
        if p.extension().is_some_and(|x| x == "json") {
            let v: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&p).expect("read"))
                    .expect("fixture is not JSON");
            let n = v["vectors"].as_array().map_or(0, Vec::len);
            vector_total += n;
            per_file.insert(p.file_name().unwrap_or_default().to_string_lossy().into_owned(), n);
        }
    }
    assert!(per_file.len() >= 10, "the fixture walk found {} file(s)", per_file.len());

    // `#[cfg(..)]` / `#![cfg(..)]` attributes and `cfg!(..)` reads over the
    // token streams of every `.rs` under `crates/`: how many there are (the
    // positive control), and how many name the removed feature (must be 0).
    fn cfg_walk(
        tokens: &[proc_macro2::TokenTree],
        file: &str,
        all_attrs: &mut usize,
        named: &mut Vec<String>,
    ) {
        use proc_macro2::TokenTree as T;
        for (i, tree) in tokens.iter().enumerate() {
            let T::Group(g) = tree else { continue };
            let inner: Vec<T> = g.stream().into_iter().collect();
            let punct_at = |k: usize, want: char| {
                matches!(tokens.get(i.wrapping_sub(k)), Some(T::Punct(p)) if p.as_char() == want)
            };
            let attr_position = g.delimiter() == proc_macro2::Delimiter::Bracket
                && (punct_at(1, '#') || (punct_at(1, '!') && punct_at(2, '#')));
            let is_cfg_attr = attr_position && matches!(inner.first(), Some(T::Ident(id)) if id == "cfg");
            let is_cfg_read = g.delimiter() == proc_macro2::Delimiter::Parenthesis
                && punct_at(1, '!')
                && matches!(tokens.get(i.wrapping_sub(2)), Some(T::Ident(id)) if id == "cfg");
            if is_cfg_attr {
                *all_attrs += 1;
            }
            if (is_cfg_attr || is_cfg_read) && names_feature(&inner) {
                let line = g.span().start().line;
                named.push(format!("{file}:{line} ({})", if is_cfg_attr { "attribute" } else { "cfg!() read" }));
            }
            cfg_walk(&inner, file, all_attrs, named);
        }
    }
    fn names_feature(tokens: &[proc_macro2::TokenTree]) -> bool {
        tokens.iter().any(|t| match t {
            proc_macro2::TokenTree::Literal(l) => l.to_string() == "\"ffi-oracle\"",
            proc_macro2::TokenTree::Group(g) => {
                let inner: Vec<_> = g.stream().into_iter().collect();
                names_feature(&inner)
            }
            _ => false,
        })
    }
    let mut cfg_attrs = 0usize;
    let mut naming_the_dead_feature: Vec<String> = Vec::new();
    let mut lexed = 0usize;
    for (name, text) in all_crate_rust_sources_raw() {
        let stream: proc_macro2::TokenStream = text
            .parse()
            .unwrap_or_else(|e| panic!("{name} did not lex as Rust ({e}); the cfg walk cannot examine it"));
        let trees: Vec<proc_macro2::TokenTree> = stream.into_iter().collect();
        cfg_walk(&trees, &name, &mut cfg_attrs, &mut naming_the_dead_feature);
        lexed += 1;
    }
    // Positive controls: the walk lexed the tree and saw `cfg` attributes.
    // Both floors are about two thirds of the measured counts.
    assert!(
        lexed >= 56,
        "the cfg walk lexed only {lexed} file(s) under crates/; the tree holds 84 and this floor \
         is two thirds of that"
    );
    assert!(
        cfg_attrs >= 88,
        "the cfg walk saw only {cfg_attrs} `cfg` attribute(s) across {lexed} files; the tree \
         carries 133 and this floor is two thirds of that. An absence \
         reported over a walk that finds nothing is not an absence"
    );
    assert!(
        naming_the_dead_feature.is_empty(),
        "the dead `ffi-oracle` feature is named by {} cfg site(s):\n  {}\n\
         The feature is not declared and a \
         site naming it is an `unexpected_cfgs` error under the clippy gates as well.",
        naming_the_dead_feature.len(),
        naming_the_dead_feature.join("\n  ")
    );

    // --- the claims, scanned out of the documents ----------------------
    //
    // Logical lines, not physical ones: documents are hard-wrapped, so
    // consecutive prose lines are joined, a table row is its own logical
    // line, and the first physical line of each is kept for the failure
    // message.
    fn logical_lines(text: &str) -> Vec<(usize, String)> {
        let mut logical: Vec<(usize, String)> = Vec::new();
        let mut joining = false;
        for (i, line) in text.lines().enumerate() {
            let t = line.trim();
            if t.is_empty() {
                logical.push((i + 1, String::new()));
                joining = false;
            } else if line.starts_with('|') || line.starts_with('#') {
                logical.push((i + 1, t.to_string()));
                joining = false;
            } else if joining && !is_list_item(t) {
                let last = logical.last_mut().expect("joining implies a previous entry");
                last.1.push(' ');
                last.1.push_str(t);
            } else {
                logical.push((i + 1, t.to_string()));
                joining = true;
            }
        }
        logical
    }
    /// Up to 60 characters either side of byte `at`, so a failure quotes the
    /// claim and not the paragraph around it.
    fn excerpt(line: &str, at: usize) -> String {
        let lo = line[..at].char_indices().rev().nth(60).map_or(0, |(i, _)| i);
        let hi = line[at..].char_indices().nth(60).map_or(line.len(), |(i, _)| at + i);
        line[lo..hi].to_string()
    }
    /// A markdown list item opens its own logical line: `- `, `* `, or `N. `.
    fn is_list_item(t: &str) -> bool {
        t.starts_with("- ")
            || t.starts_with("* ")
            || t.split_once(". ").is_some_and(|(n, _)| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
    }
    /// The integer (commas allowed) immediately preceding byte `at` in `line`.
    fn integer_before(line: &str, at: usize) -> Option<usize> {
        let before = line[..at].trim_end();
        let digits: String = before
            .chars()
            .rev()
            .take_while(|c| c.is_ascii_digit() || *c == ',')
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .filter(|c| c.is_ascii_digit())
            .collect();
        digits.parse().ok()
    }

    let mut problems: Vec<String> = Vec::new();
    let mut vector_claims = 0usize;
    let mut table_rows = 0usize;

    for doc in ["docs/specification.md", "README.md"] {
        let text = std::fs::read_to_string(root.join(doc)).unwrap_or_else(|e| panic!("cannot read {doc}: {e}"));
        for (n, line) in logical_lines(&text) {
            // The corpus table: `| A | `group_a_keygen.json` | subject | 11 | 4 |`.
            if line.starts_with('|') {
                let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
                if cells.len() == 5 {
                    let file = cells[1].trim_matches('`');
                    if let (Some(&on_disk), Ok(stated)) = (per_file.get(file), cells[3].parse::<usize>()) {
                        table_rows += 1;
                        if stated != on_disk {
                            problems.push(format!(
                                "\x20 - {doc}:{n}: the corpus table says {file} has {stated} \
                                 vectors; the file has {on_disk}"
                            ));
                        }
                    }
                }
                continue;
            }
            // "N vectors" in prose, every occurrence; "N of M" totals included.
            let mut from = 0usize;
            while let Some(i) = line[from..].find(" vectors") {
                let at = from + i;
                if let Some(stated) = integer_before(&line, at) {
                    // A per-group figure ("11 vectors") is a table matter; prose
                    // quotes only the total.
                    if stated > 1000 {
                        vector_claims += 1;
                        if stated != vector_total {
                            problems.push(format!(
                                "\x20 - {doc}:{n}: claims {stated} vectors ({:?}); the corpus \
                                 on disk has {vector_total}",
                                excerpt(&line, at)
                            ));
                        }
                    }
                }
                from = at + " vectors".len();
            }
        }
    }

    assert!(
        problems.is_empty(),
        "a document quotes a count that disagrees with the artifact:\n{}\n\n\
         This is the drift class: a figure correct when written and invalidated \
         by a change elsewhere. The remedy is to re-derive the number, never to \
         move the artifact to match the sentence.",
        problems.join("\n")
    );
    // Floors, one per claim family, so a scan that stopped matching says which.
    assert!(
        vector_claims >= 1,
        "no vector-total claim matched in docs/specification.md or README.md; the specification \
         states the corpus total, so the scan stopped matching"
    );
    assert!(
        table_rows >= 10,
        "only {table_rows} corpus-table row(s) matched in docs/specification.md; the table's shape moved"
    );

    println!(
        "  documented counts: {vector_claims} vector-total claim(s) and {table_rows} table row(s) \
         agree with {vector_total} vectors in {} files; {cfg_attrs} cfg attribute(s) across \
         {lexed} files, 0 naming the dead feature",
        per_file.len()
    );
}

/// Every `.rs` under `crates/`, comment-stripped, in sorted path order.
///
/// Wider than [`crate_source_files`] and `test_source_files()`, because a
/// name cited in `src/` may be a test, a `ui/` case's helper or a downstream
/// probe's function. Definitions come from this stripped view and citations
/// from the raw one, so a doc comment naming `fn foo` cannot satisfy another
/// citing `foo`.
fn all_crate_rust_sources() -> Vec<(String, String)> {
    all_crate_rust_sources_raw()
        .into_iter()
        .map(|(name, text)| (name, code_only(&text)))
        .collect()
}

/// [`all_crate_rust_sources`] before the strip: the raw text, for a consumer
/// that lexes rather than searches.
fn all_crate_rust_sources_raw() -> Vec<(String, String)> {
    let root = repo_root();
    let mut out: Vec<(String, String)> = Vec::new();
    let mut stack = vec![root.join("crates")];
    while let Some(d) = stack.pop() {
        let entries = std::fs::read_dir(&d)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", d.display()));
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                // `target/` under a nested manifest (ui/downstream) is build
                // output.
                if p.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                let text = std::fs::read_to_string(&p)
                    .unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()));
                let name = p
                    .strip_prefix(&root)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .into_owned();
                out.push((name, text));
            }
        }
    }
    // Sorted, so the corpus is the same on every run.
    out.sort();
    out
}

/// Lower `snake_case` identifiers of at least `words` underscore-separated
/// segments, as whole tokens.
///
/// The token is the maximal `[A-Za-z0-9_]` run, then filtered, not a search
/// for the shape inside a longer run. A name hard-wrapped across a line
/// break (a trailing underscore) or written with an elided prefix (a leading
/// underscore) therefore fails a filter instead of yielding a partial name.
fn lower_snake_names_of_at_least(words: usize, text: &str) -> BTreeSet<String> {
    let b = text.as_bytes();
    let mut out = BTreeSet::new();
    let mut i = 0usize;
    while i < b.len() {
        if !(b[i].is_ascii_alphanumeric() || b[i] == b'_') {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
            i += 1;
        }
        let tok = &text[start..i];
        if !tok.starts_with(|c: char| c.is_ascii_lowercase()) {
            continue;
        }
        if tok.bytes().any(|c| c.is_ascii_uppercase()) {
            continue;
        }
        let segments: Vec<&str> = tok.split('_').collect();
        if segments.len() < words || segments.iter().any(|s| s.is_empty()) {
            continue;
        }
        out.insert(tok.to_owned());
    }
    out
}

/// What a row's reason opens with when the row permits history prose rather
/// than a live fixture key, dependency method or lint name. Spelled once so
/// the rows, the printed remedy and [`MarkerClass::DeclaredName`]'s
/// population cannot drift apart.
const HISTORY_ROW_MARK: &str = "CORRECT HISTORY";

/// Names cited in `crates/*/src/` that name no `fn` in the tree, declared
/// here with the reason each is not a dangling citation.
///
/// When a test is renamed, every citation of the old name becomes a claim
/// about a test that does not exist. The rule is resolve or declare: a
/// legitimate citation is listed here with its reason, and the next rename
/// fails until each citation is fixed or declared.
///
/// Limits:
///
/// * It matches a name shape, not a resolved path: a four-word `snake_case`
///   token counts as a citation wherever it appears, so an ordinary four-word
///   function in another module needs a row.
/// * `src/` only; `tests/` is not scanned.
/// * Four segments or more. At three, almost every unresolved name is a
///   `std` or dependency method.
/// * A definition is any `fn` under `crates/`; it does not check that the
///   cited `fn` is the right one, only that the name is not dead.
const DECLARED_UNRESOLVED_SRC_NAMES: &[(&str, &str)] = &[
    (
        "decrypt_padded_vec_mut",
        "a dependency method: `cbc`'s block-mode decryptor, through `cipher`'s \
         `BlockDecryptMut`, which `extension_export::decrypt_record` calls to undo the browser \
         extension's AES-256-CBC with PKCS#7. No `fn` in this tree carries it, and a renamed \
         upstream method is a compile error at that call.",
    ),
    (
        "mochimo_storage_key_v1",
        "a domain-separation string the browser extension hashes ahead of its master seed when it \
         derives the storage key (`MasterSeed.deriveStorageKey`); `extension_export` writes it as \
         a byte literal and names it in its doc. A protocol constant of another program, not a \
         name of this one.",
    ),
    (
        "keystore_v3_reserved_snapshot",
        "a testdata file name, `testdata/keystore_v3_reserved_snapshot.bin`: \
         the version-3 capture with a reservation open, embedded by `format.rs`'s version-dispatch \
         test through `include_bytes!`. A file name and no `fn` carries it; a renamed file is a \
         compile error at the `include_bytes!`, not a dangling citation. The three older captures \
         have three-segment names and never reached this table.",
    ),
    (
        "account_literal_is_not_constructible",
        "a trybuild compile-fail case, `ui/fail/account_literal_is_not_constructible.rs`. \
         Case stems are file names and no `fn` carries them; the partition test reads the \
         directory, so a renamed case is caught there rather than here.",
    ),
    (
        "account_wots_index_is_not_assignable",
        "a trybuild compile-fail case, as above.",
    ),
    (
        "broken_intra_doc_links",
        "a rustdoc lint name, in `mochimo-crypto`'s crate-level `deny`. Dependency surface, as \
         with `unsafe_op_in_unsafe_fn` below -- and load-bearing for the same kind of reason: it \
         is what makes a doc link to a deleted item an error instead of plain text that renders \
         and says nothing. It fires under `cargo doc` alone, which neither `cargo test` nor clippy \
         runs.",
    ),
    (
        "private_intra_doc_links",
        "a rustdoc lint name, in the same crate-level block, allowed rather than denied. Its \
         argument is written at the site: the links it names resolve, the `deny` above is what \
         makes them resolve, and dropping the brackets to satisfy it would turn the tree's only \
         assertion that those private names exist into prose nothing checks. Dependency surface \
         like the two lints beside it, and visible under `cargo doc` alone.",
    ),
    (
        "decrypt_in_place_detached",
        "a `chacha20poly1305` method (the `AeadInPlace` trait). Dependency surface: nothing in \
         this tree defines it, and a rename upstream is a compile error, not a dangling citation.",
    ),
    (
        "durable_is_not_constructible",
        "a trybuild compile-fail case, as above.",
    ),
    (
        "encrypt_in_place_detached",
        "a `chacha20poly1305` method, as above.",
    ),
    (
        "eq_ignore_ascii_case",
        "a `std` method on `str`. Dependency surface, as above.",
    ),
    (
        "group_n_mesh_live",
        "a file stem, not a function: `fixtures/group_n_mesh_live.json`. The manifest's file \
         list is asserted against the directory in `kat.rs`.",
    ),
    (
        "hash_password_into_with_memory",
        "an `argon2` method -- the one entry point that survives `default-features = false`, \
         which is why `Cargo.toml` and two keystore modules name it. Dependency surface.",
    ),
    (
        "http_status_as_error",
        "a `ureq` config builder method. Dependency surface.",
    ),
    (
        "medium_steps_are_not_reorderable",
        "a trybuild compile-fail case, as above.",
    ),
    (
        "unsafe_op_in_unsafe_fn",
        "a rustc lint name, in `mochimo-crypto`'s crate-level `deny`. As above -- and this one \
         is load-bearing: it is what makes every `unsafe` block inside an `unsafe fn` state its \
         own SAFETY.",
    ),
];

/// Every four-plus-word `snake_case` name cited in `crates/*/src/` names an
/// `fn` somewhere under `crates/`, or is declared in
/// [`DECLARED_UNRESOLVED_SRC_NAMES`] with a reason.
///
/// Both directions are checked. An undeclared citation that resolves to
/// nothing fails, naming the file. A declared row that now resolves, or that
/// nothing cites, also fails, so the table cannot keep a permit for the next
/// rename to hide under.
///
/// See [`DECLARED_UNRESOLVED_SRC_NAMES`] for the limits: by shape, not by
/// path.
#[test]
fn names_cited_in_src_resolve_to_a_fn_or_are_declared_matched_by_shape_not_by_path() {
    // Four segments; see the table's doc for why not three.
    const MIN_SEGMENTS: usize = 4;

    // A list of pairs plus this assert, so a duplicate permit is reported
    // rather than silently merged.
    let mut names: Vec<&str> = DECLARED_UNRESOLVED_SRC_NAMES.iter().map(|(n, _)| *n).collect();
    let declared_rows = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(
        names.len(),
        declared_rows,
        "DECLARED_UNRESOLVED_SRC_NAMES carries a duplicate name. A second row for one \
         name is a permit nobody can see: the reason that reads as governing the \
         citation may be the one that is never consulted."
    );
    for (name, reason) in DECLARED_UNRESOLVED_SRC_NAMES {
        assert!(
            !reason.trim().is_empty(),
            "{name} is declared with an empty reason. The reason IS the declaration; \
             a row without one is a bare permit."
        );
    }

    // The definitions: every `fn` under `crates/`, from comment-stripped code
    // so no doc comment can satisfy another.
    let sources = all_crate_rust_sources();
    let mut defined: BTreeSet<String> = BTreeSet::new();
    for (_, code) in &sources {
        let mut previous_was_fn = false;
        let b = code.as_bytes();
        let mut i = 0usize;
        while i < b.len() {
            if !(b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
                continue;
            }
            let start = i;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
            let tok = &code[start..i];
            if previous_was_fn {
                defined.insert(tok.to_owned());
            }
            previous_was_fn = tok == "fn";
        }
    }

    // The citations: the raw `crates/*/src` view, since the subject is text
    // in doc comments.
    let src = crate_source_files();
    let mut cited: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (file, text) in &src {
        for name in lower_snake_names_of_at_least(MIN_SEGMENTS, text) {
            cited.entry(name).or_default().insert(file.clone());
        }
    }

    // --- vacuity floors, each over a quantity a broken walk drives to zero ---
    assert!(
        sources.len() >= 40,
        "the crates/ walk found only {} .rs file(s); the `fn` set it builds is the \
         resolving side of this check, so a short walk makes every citation look dead.",
        sources.len()
    );
    assert!(
        defined.len() >= 800,
        "only {} `fn` name(s) were extracted from crates/. The tokenizer stopped \
         recognising definitions, which would report live citations as dangling.",
        defined.len()
    );
    assert!(
        src.len() >= 30 && cited.len() >= 80,
        "the src/ walk found {} file(s) and {} cited name(s). Too few of either and \
         this check passes over an empty corpus rather than over a clean one \
         .",
        src.len(),
        cited.len()
    );

    // --- direction 1: a citation that resolves to nothing must be declared ---
    let declared: BTreeSet<&str> = DECLARED_UNRESOLVED_SRC_NAMES.iter().map(|(n, _)| *n).collect();
    let mut dangling: Vec<String> = Vec::new();
    let mut unresolved_total = 0usize;
    for (name, files) in &cited {
        if defined.contains(name) {
            continue;
        }
        unresolved_total += 1;
        if declared.contains(name.as_str()) {
            continue;
        }
        let mut where_ = files.iter().cloned().collect::<Vec<_>>();
        where_.sort();
        dangling.push(format!("\x20 - {name}\n\x20     cited in: {}", where_.join(", ")));
    }
    // --- direction 2: a declared row must still be a citation that dangles ---
    //
    // A row for a name nothing cites, or for a name that now resolves, is a
    // stale permit.
    let mut stale: Vec<String> = Vec::new();
    // The rows whose subject is history, and the files whose sentences keep
    // them alive. Also declared in DECLARED_HISTORY_MARKER_SITES so a sweep of
    // that table finds them.
    let mut history_rows: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for (name, reason) in DECLARED_UNRESOLVED_SRC_NAMES {
        let short = reason.split_once(". ").map_or(*reason, |(a, _)| a);
        // A history row and the sentence it permits are removed together:
        // removing the sentence alone leaves a row permitting nothing, and
        // removing the row alone leaves a dangling citation.
        let remedy = if reason.starts_with(HISTORY_ROW_MARK) {
            format!(
                "\n\x20     this is a {HISTORY_ROW_MARK} row. It permits nothing but the sentence \
                 under src/ that names the retired marker, so the row and that sentence are \
                 removed in one change: delete the sentence alone and the row permits nothing, \
                 delete the row alone and the sentence is the dangling citation this check \
                 exists to catch."
            )
        } else {
            String::new()
        };
        if reason.starts_with(HISTORY_ROW_MARK) {
            // A `BTreeSet` of paths, so the order is the sorted one already.
            let files: Vec<String> = cited
                .get(*name)
                .into_iter()
                .flatten()
                .map(|f| format!("\x20     cited in: {f}"))
                .collect();
            if !files.is_empty() {
                history_rows.insert(*name, files);
            }
        }
        match cited.get(*name) {
            None => stale.push(format!(
                "\x20 - {name}: declared, but no file under crates/*/src cites it.\n\
                 \x20     the row says: {short}.{remedy}"
            )),
            Some(_) if defined.contains(*name) => stale.push(format!(
                "\x20 - {name}: declared as naming no `fn`, but the tree now defines one.\n\
                 \x20     the row says: {short}.{remedy}"
            )),
            Some(_) => {}
        }
    }
    // The table's own staleness is reported first, so a defect in this
    // check's data does not hide behind a failure about the tree.
    assert!(
        stale.is_empty(),
        "DECLARED_UNRESOLVED_SRC_NAMES carries a row that is no longer about anything.\n\
         {}\n\n\
         Permitting a name nobody writes establishes nothing, and a permit \
         left behind is what the next stale citation hides under. Delete the row, or say \
         at it what changed.",
        stale.join("\n")
    );

    assert!(
        dangling.is_empty(),
        "a name cited in crates/*/src names no `fn` in the tree and is not declared.\n\
         {}\n\n\
         This is the shape a rename leaves behind: the marker moved, the sentence \
         asserting it did not, and a reader is told an obligation is owed by a test \
         that no longer exists. Either point the sentence at the live name, or add a \
         row to DECLARED_UNRESOLVED_SRC_NAMES saying why the dead one belongs there \
         -- history, a fixture key, a dependency method, a lint. What is not \
         available is leaving it undeclared.",
        dangling.join("\n")
    );

    let declared_history = assert_against_baseline(MarkerClass::DeclaredName, &history_rows);

    println!(
        "  cited-name resolution: {} name(s) of >= {MIN_SEGMENTS} segments across {} src \
         file(s); {} resolve to one of {} `fn`(s) in {} crates/ file(s); {} declared \
         unresolved, all cited and all still dead, {} of them history rows against a \
         baseline of {declared_history}",
        cited.len(),
        src.len(),
        cited.len() - unresolved_total,
        defined.len(),
        sources.len(),
        declared_rows,
        history_rows.values().map(Vec::len).sum::<usize>()
    );
}

/// I8: an imported account keeps a path back to its key material.
///
/// The extension has two kinds of account. A standard account carries
/// `index`, and its seed is a pure function of the master seed at that
/// index. An imported account carries `index: undefined`, and its `seed` is
/// the only copy of its key material: it came from an `.mcm` file, not from
/// the master seed.
///
/// A wallet that models every account as "master seed + index" would
/// restore a mnemonic and silently produce only the standard accounts; the
/// imported accounts' funds would stay on chain with no key to move them.
/// No derivation vector can express this, so it is checked as a shape of
/// the model.
///
/// Cleared by two conditions:
///
/// 1. a Rust account model that names the non-derived variant,
///    `KeyMaterial::Imported` in `src/account.rs`;
/// 2. `imported_account_restores_from_stored_seed`, census-checked.
///
/// The bound in the name: that round trip is in memory, over the persistent
/// content types, not through a keystore or a disk. Durability is covered by
/// the keystore's own checks.
#[test]
fn imported_account_restore_is_checked_in_memory_not_on_disk() {
    // The premise is recorded in docs/specification.md under I8; the model
    // and the proof below are the mechanism.
    // The variant as Rust would spell it, derived rather than typed.
    let mut needle = String::new();
    for (i, c) in "imported".chars().enumerate() {
        needle.extend(if i == 0 {
            c.to_uppercase().collect::<Vec<_>>()
        } else {
            vec![c]
        });
    }

    let mut owed: Vec<String> = Vec::new();

    let files = crate_sources();
    assert!(
        files.len() >= 10,
        "the walk of crates/*/src found only {} files; any result from it is \
         vacuous",
        files.len()
    );
    let modelled = files
        .iter()
        .any(|(_, code)| code.contains(&format!("{needle},")) || code.contains(&format!("{needle} ")));
    if !modelled {
        owed.push(format!(
            "\x20 - no file under crates/*/src names an account kind spelled \
             `{needle}`. \
             There is no Rust account model at all yet; when there is, it must \
             distinguish an account whose key material is stored from one whose \
             key material is derived."
        ));
    }

    const PROOF: &str = "imported_account_restores_from_stored_seed";
    // Execution, not existence: `census::check` runs the named test on its
    // own and reads libtest's verdict and the reported measurement. An empty
    // `#[test]` body would satisfy a search for its name.
    if let Err(why) = census::check("imported_account_restore_is_checked_in_memory_not_on_disk", PROOF) {
        let owes = format!(
            "\x20 - no test named {PROOF} exists. It has to build a wallet \
             holding one derived and one imported account, round-trip it \
             through restore, and assert the imported account's stored seed \
             comes back byte-identical -- not merely that the account is \
             listed. An enum variant nothing exercises satisfies the check \
             above and loses the funds anyway."
        );
        owed.push(format!("{owes}\n\x20   {why}"));
    }

    assert!(
        owed.is_empty(),
        "I8's enforcement has regressed: the account model or its restore \
         proof is gone.\n{}\n\
         An imported account's `seed` is the only copy of its key material in \
         existence -- it came from an .mcm file, not from the master seed, and \
         `index: undefined` (walletActions.ts:374) is how the extension marks \
         that. A wallet modelled as master-seed-plus-index restores the \
         mnemonic, rebuilds the standard accounts, and drops these entries with \
         no error: the funds stay addressable on chain and the key that could \
         move them is gone. See docs/specification.md I8.",
        owed.join("\n")
    );
}

/// The proof behind I8: an imported account's stored root survives the
/// restore path byte-for-byte.
///
/// `Account::to_record` into `Account::restore_from_record` carries an
/// imported root through unchanged, preserves the rotation index, and
/// rebuilds a derived account from its position alone (the derived record
/// has no root field by type). The root is compared with an independent
/// literal in this test, never with a value read from the pre-restore
/// account.
///
/// Not established: durability. The round trip is in memory; the record type
/// is the persistent content, not an on-disk format.
///
/// The imported account is `F-address-widths`: its account seed as the
/// root and its recorded 2208-byte first address as the `faddress`. It is
/// advanced once before the snapshot, so a restore that resets the index to
/// zero fails the index assertion.
#[test]
fn imported_account_restores_from_stored_seed() {
    use mochimo_crypto::account::{Account, AccountKind, AccountRecord};

    const ROOT: [u8; SEED_LEN] = [
        0x66, 0x4e, 0xdd, 0x3d, 0x3b, 0xf1, 0xa0, 0xe2, 0x9c, 0x93, 0x98, 0xdd, 0xc1, 0x61,
        0x14, 0xab, 0xc6, 0xd6, 0xb4, 0x32, 0xb1, 0xe5, 0xe4, 0xde, 0x26, 0x7c, 0x7e, 0x2a,
        0xe5, 0x3f, 0x58, 0x0b,
    ];
    const IMPORTED_TAG: [u8; 20] = [
        0x05, 0xff, 0x0f, 0x69, 0xd4, 0xc1, 0xcd, 0x68, 0x2e, 0xd3, 0x34, 0x1c, 0x0b, 0x77,
        0x73, 0x05, 0x4b, 0x58, 0x80, 0x0f,
    ];
    const IMPORTED_FIRST_ADDRESS: &[u8; mochimo_crypto::consts::WOTS_ADDR_LEN] =
        include_bytes!("../../../fixtures/F-widths_account_address.bin");
    // Master, position and tag are group F's `F-derive-account-1` triple, a
    // tag recorded from the reference implementation, not read back from
    // `Account::derive`.
    const DERIVED_MASTER: [u8; SEED_LEN] = [
        0x40, 0x8b, 0x28, 0x5c, 0x12, 0x38, 0x36, 0x00, 0x4f, 0x4b, 0x88, 0x42, 0xc8, 0x93,
        0x24, 0xc1, 0xf0, 0x13, 0x82, 0x45, 0x0c, 0x0d, 0x43, 0x9a, 0xf3, 0x45, 0xba, 0x7f,
        0xc4, 0x9a, 0xcf, 0x70,
    ];
    const DERIVED_POSITION: u32 = 1;
    const DERIVED_TAG: [u8; 20] = [
        0x4d, 0x9b, 0x31, 0xe4, 0x78, 0x74, 0x66, 0x8e, 0x45, 0x89, 0x5a, 0x1b, 0x93, 0x38,
        0x8e, 0x5a, 0xa9, 0xb6, 0xfb, 0xe9,
    ];

    let mut imported = Account::import(Secret::new(ROOT), IMPORTED_FIRST_ADDRESS)
        .unwrap_or_else(|e| panic!("F-address-widths' root and first address are a pair: {e}"));
    assert_eq!(
        imported.tag(),
        IMPORTED_TAG,
        "Account::import no longer computes the fixture's recorded account tag"
    );
    let advanced = imported
        .advance()
        .unwrap_or_else(|e| panic!("advance from 0 cannot overflow: {e}"));
    assert_eq!(advanced.get(), 1, "advance from a fresh account must yield 1");

    let derived = Account::derive(&Secret::new(DERIVED_MASTER), DERIVED_POSITION);
    assert_eq!(derived.tag(), DERIVED_TAG, "Account::derive no longer reproduces the fixture tag");

    // The restore path under test: content out, account back.
    let restored_imported = Account::restore_from_record(imported.to_record())
        .unwrap_or_else(|e| panic!("the imported record must restore: {e}"));
    let restored_derived = Account::restore_from_record(derived.to_record())
        .unwrap_or_else(|e| panic!("the derived record must restore: {e}"));

    assert_eq!(restored_imported.kind(), AccountKind::Imported);
    assert_eq!(restored_derived.kind(), AccountKind::Derived);
    assert_ne!(
        restored_imported.kind(),
        restored_derived.kind(),
        "a restore that collapses the two kinds is the I8 loss mode"
    );
    assert_eq!(
        restored_imported.wots_index().get(),
        1,
        "restore reset the rotation index; a reset index re-signs a used key"
    );

    match restored_derived.to_record() {
        AccountRecord::Derived {
            tag, account_index, ..
        } => {
            assert_eq!(account_index, DERIVED_POSITION, "derived position lost in restore");
            assert_eq!(tag, DERIVED_TAG, "derived tag lost in restore");
        }
        AccountRecord::Imported { .. } | AccountRecord::Sdk { .. } => {
            panic!("derived account restored as another kind")
        }
    }

    let mut accounts_round_tripped = 0u32;
    let mut roots_byte_identical = 0u32;
    match restored_imported.to_record() {
        AccountRecord::Imported { tag, root, .. } => {
            assert_eq!(tag, IMPORTED_TAG, "imported tag lost in restore");
            assert_eq!(
                root.expose(),
                &ROOT,
                "the stored root did not come back byte-identical; an \
                 imported account whose root mutates in restore is funds \
                 lost with no diagnostic (docs/specification.md I8)"
            );
            roots_byte_identical += 1;
        }
        AccountRecord::Derived { .. } | AccountRecord::Sdk { .. } => {
            panic!("imported account restored as another kind")
        }
    }
    accounts_round_tripped += 2;

    // Every integer below is an account count; the census floor reads the
    // largest integer after the needle, so nothing else may print a number.
    println!(
        "  restore path: {accounts_round_tripped} account(s) round-tripped \
         in memory, {roots_byte_identical} imported root byte-identical, 1 \
         derived rebuilt from its position"
    );
}

/// I8's proof at the first key: an imported account's position-0 key is the
/// one its stored first address names, through a keystore round trip.
///
/// The pair is `F-address-widths`' account seed and recorded 2208-byte first
/// address, the shape an `.mcm` entry carries, taken from group F because
/// nothing in this crate reads `.mcm` files. It is a derived account's pair
/// seen from the imported side.
///
/// Established:
///
/// * `Account::import` refuses a first address the root does not reproduce,
///   so the tag is computed, not supplied;
/// * the key at `WotsIndex::ZERO` has that address's public key and the
///   account's tag, checked after `add`, drop and reopen;
/// * a signature made at position 0 recovers to the same public key.
///
/// Not established: that an `.mcm` file is read correctly. At-rest secrecy is
/// covered by `imported_roots_and_the_master_seed_are_encrypted_at_rest`.
#[test]
fn imported_index_zero_pk_reproduces_the_first_address() {
    use keystore_harness::{imported_account, reopen, ScratchDir, IMPORTED_FIRST_ADDRESS, IMPORTED_TAG, ROOT};
    use mochimo_crypto::account::{Account, WotsIndex};
    use mochimo_crypto::keystore::{KeyAccess, Keystore};
    use mochimo_crypto::{addr, wots};

    const PK_LEN: usize = 2144;

    // (1) The verifying constructor refuses a pair with one public-key byte
    // flipped, so only the reproduction check can fail.
    let mut forged = *IMPORTED_FIRST_ADDRESS;
    forged[0] ^= 0x01;
    assert_eq!(
        Account::import(Secret::new(ROOT), &forged).err(),
        Some(mochimo_crypto::Error::FirstAddressNotReproduced),
        "import accepted a first address the root does not reproduce"
    );

    // (2) The real pair, through a keystore round trip.
    let dir = ScratchDir::new("i8-first-key");
    let mut ks = Keystore::create(dir.path(), &keystore_harness::init()).unwrap_or_else(|e| panic!("{e}"));
    ks.add(imported_account()).unwrap_or_else(|e| panic!("{e}"));
    drop(ks);
    let mut ks = reopen("I8 first key", dir.path())
        .result
        .unwrap_or_else(|e| panic!("reopen: {e}"));
    let view = ks
        .view(&IMPORTED_TAG)
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("the imported account did not survive the reopen"));
    assert_eq!(view.wots_index, WotsIndex::ZERO, "a never-spent account is at position 0");

    // (3) Position 0 signs, and the key it signed with is the stored one.
    let r = ks.persist_advance(&IMPORTED_TAG, &[0xD1u8; 32], keystore_harness::FIGURES).unwrap_or_else(|e| panic!("{e}"));
    let sig = ks
        .sign_spend(&[0xD1u8; 32], r, KeyAccess::StoredRoot)
        .unwrap_or_else(|e| panic!("position 0 after a reopen: {e}"));
    assert_eq!(sig.spent_index, WotsIndex::ZERO);
    let mut adrs = sig.adrs;
    let recovered = wots::pk_from_sig(&sig.signature, &[0xD1u8; 32], &sig.pub_seed, &mut adrs);
    assert_eq!(
        &recovered[..],
        &IMPORTED_FIRST_ADDRESS[..PK_LEN],
        "position 0's signature does not recover the stored first public key"
    );
    let implicit = addr::from_wots(&recovered);
    assert_eq!(
        addr::tag_of(&implicit),
        &IMPORTED_TAG[..],
        "the first key's address is not implicit under the account tag"
    );

    let accounts = 1u32;
    // Every integer on this line is an account count.
    println!(
        "  I8 first key: {accounts} imported account(s) whose position-0 public key is the \
         stored first address's, through a keystore reopen"
    );
}

/// I8 at the first key: an imported account can spend from its first
/// address.
///
/// An account's first key is `WOTS.generateRandomAddress(_, account_seed,
/// generator)`, where the generator is the one `deriveSeed(master,
/// account_index)` left behind. Its public components (public seed and hash
/// address) are a function of the master seed and account index, which an
/// imported account does not hold. The reference wallet stores `faddress`
/// beside `seed` on import and rebuilds the first key from it. The funds an
/// imported account held at import sit at the first address, so a model
/// holding the root alone could not spend them.
///
/// Format v2 stores the 64-byte tail of `faddress` beside the root.
/// `Account::import(root, first_address)` refuses a pair the root does not
/// reproduce and computes the tag from the verified public key, and
/// `sign_spend` rebuilds position 0 from the stored components. Only 64 bytes
/// are needed because the public key is `wots::pkgen(root, pub_seed, adrs)`
/// and the reference writes address words 5, 6 and 7 before every use.
///
/// The bound in the name: the proof's pair is group F's, a derived account
/// seen from the imported side, since no capture of a genuinely imported
/// account exists. Parsing an `.mcm` file into that pair is not checked here.
#[test]
fn imported_first_key_is_verified_against_the_root_not_against_an_mcm_capture() {
    // The premise is recorded in docs/specification.md under I8; the proof
    // below is the mechanism.
    let mut owed: Vec<String> = Vec::new();

    const PROOF: &str = "imported_index_zero_pk_reproduces_the_first_address";
    if let Err(why) = census::check(
        "imported_first_key_is_verified_against_the_root_not_against_an_mcm_capture",
        PROOF,
    ) {
        owed.push(format!(
            "\x20 - no test named {PROOF} exists. It has to build an imported \
             account from a 32-byte root AND a 2208-byte first address (the \
             .mcm entry's pair), through a constructor that refuses a first \
             address the root does not reproduce; assert the key at \
             WotsIndex::ZERO has that address's public key and the account's \
             tag; and assert the same after a keystore round trip. It must \
             report how many such accounts it drove; the floor is 1.\n\x20   {why}"
        ));
    }

    assert!(
        owed.is_empty(),
        "I8 at the first key has REGRESSED: before format v2 this red meant an \
         imported account's position-0 key was unreachable -- its public seed \
         and hash address came from the master seed's generator and were not \
         in the stored root, so the funds it was imported holding could not \
         be moved. Format v2 stores those 64 bytes beside the root and \
         `Account::import` verifies them against it, so this firing means the \
         proof, its census row, or the stored components went away.\n{}\n\
         What must still hold: the record carries the components, the \
         constructor refuses a first address the root does not reproduce, and \
         the key at WotsIndex::ZERO is the one that address names -- after a \
         keystore reopen, not just in memory. The index decision found it, the signing \
         path settled that the components must be stored, format v2 landed it.",
        owed.join("\n")
    );
}

/// Group F is a specification capture. It must not become an oracle.
///
/// Most fixtures are derived from the C reference, so two of them cannot
/// disagree. Group F is derived from the TypeScript, of which there is one
/// implementation: a Rust port agreeing with it proves the port matches the
/// extension, not that the extension is right.
///
/// This walk routes on `oracle.class`; an unrecognised class fails. It owns
/// the `specification-capture` arm, and
/// `group_c_crosscheck_is_an_executed_oracle` owns the other. A
/// `crosscheck_`-named field added to a group F vector would make
/// `crosscheck_fields_stay_asserted` count it as an independent anchor, so
/// that is refused here.
///
/// The domain is derived: every fixture with its own `pin` block is outside
/// `manifest.toml`'s `reference_pin`, hence not C-derived, hence must declare
/// an `oracle`. A non-C fixture that pins nothing is caught by
/// `group_e_constants_stay_anchored`'s concern instead: a fixture pinned
/// against nothing.
#[test]
fn group_f_is_specification_not_crosscheck() {
    let dir = repo_root().join("fixtures");
    // Counts fixtures with a provenance claim of either kind (a `pin` or an
    // `oracle` block), so deleting group F's `oracle` block reaches the
    // precise arm below instead of tripping the vacuity floor.
    let mut claims = 0usize;
    let mut files = 0usize;
    let mut problems: Vec<String> = Vec::new();

    // Files this test's own arm is responsible for: pinned, and not routed to
    // the executed-crosscheck test. A file whose `oracle` block was deleted
    // still counts, so the floor cannot fire on the defect the arm reports.
    let mut spec_arm = 0usize;
    let mut routed = 0usize;

    let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    paths.sort();

    for p in &paths {
        files += 1;
        let name = p.file_name().unwrap_or_default().to_string_lossy().into_owned();
        let text = std::fs::read_to_string(p).unwrap_or_default();
        let root: serde_json::Value = serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("{} is not JSON: {e}", p.display()));

        let has_pin = root.get("pin").is_some_and(|v| v.is_object());
        let oracle = root.get("oracle");
        if has_pin || oracle.is_some() {
            claims += 1;
        }

        // Both directions. A `pin` without an `oracle` is an undeclared
        // non-C fixture; an `oracle` without a `pin` is a declaration about a
        // provenance nothing records.
        if !has_pin {
            if oracle.is_some() {
                problems.push(format!(
                    "\x20 - {name} declares an `oracle` block but pins nothing. \
                     A statement about where these values came from is worth \
                     something only next to a record of what produced them."
                ));
            }
            continue;
        }

        // Routing is read before the `oracle` block is required to be well
        // formed, so a deleted block routes here.
        let class = oracle
            .and_then(|v| v.get("class"))
            .and_then(serde_json::Value::as_str);
        if class == Some(EXECUTED_CROSSCHECK) || class == Some(EXECUTED_CROSSCHECK_NO_REFERENCE) {
            // Owned by group_c_crosscheck_is_an_executed_oracle and
            // group_rx_is_an_oracle_with_no_reference_side; both are required
            // to run at the end of this function, so routing cannot exempt a
            // fixture.
            routed += 1;
            continue;
        }
        spec_arm += 1;

        let Some(oracle) = oracle.and_then(|v| v.as_object()) else {
            problems.push(format!(
                "\x20 - {name} carries its own `pin` block, so it is not covered \
                 by manifest.toml's reference_pin and is not derived from the \
                 vendored C -- but it declares no `oracle` block saying what it \
                 is instead. Every non-C fixture must state whether it is an \
                 independent oracle or a specification capture, because the \
                 next reader will otherwise decide by guessing."
            ));
            continue;
        };

        let flag = |k: &str| oracle.get(k).and_then(serde_json::Value::as_bool);
        // Fail-closed routing: anything not routed away above must be a
        // specification capture, so an invented class is reported.
        if class != Some(SPECIFICATION_CAPTURE) {
            problems.push(format!(
                "\x20 - {name}: oracle.class is {:?}. The only classes with a \
                 test behind them are {SPECIFICATION_CAPTURE:?} (this test), \
                 {EXECUTED_CROSSCHECK:?} \
                 (group_c_crosscheck_is_an_executed_oracle) and \
                 {EXECUTED_CROSSCHECK_NO_REFERENCE:?} \
                 (group_rx_is_an_oracle_with_no_reference_side). A fourth class \
                 is a fixture making a provenance claim nothing checks.",
                oracle.get("class")
            ));
        }
        if flag("is_independent_oracle") != Some(false) {
            problems.push(format!(
                "\x20 - {name}: oracle.is_independent_oracle is {:?}, not false",
                oracle.get("is_independent_oracle")
            ));
        }
        if flag("second_implementation_exists") != Some(false) {
            problems.push(format!(
                "\x20 - {name}: oracle.second_implementation_exists is {:?}, not \
                 false",
                oracle.get("second_implementation_exists")
            ));
        }
        // The reasoning, not just the flags.
        let why = oracle.get("why").and_then(serde_json::Value::as_str).unwrap_or("");
        if why.len() < 200 {
            problems.push(format!(
                "\x20 - {name}: oracle.why is {} chars. It has to carry the \
                 argument, because the flags above are only as durable as the \
                 reason next to them.",
                why.len()
            ));
        }

        // A crosscheck-named field here would be collected by
        // crosscheck_fields_stay_asserted as an independent anchor with one
        // implementation behind it. Same two substrings that check uses.
        if let Some(vectors) = root.get("vectors").and_then(|v| v.as_array()) {
            for v in vectors {
                let Some(obj) = v.as_object() else { continue };
                let id = obj.get("id").and_then(serde_json::Value::as_str).unwrap_or("?");
                for k in obj.keys() {
                    if k.contains("crosscheck") || k.contains("matches_reference") {
                        problems.push(format!(
                            "\x20 - {name} vector {id} carries `{k}`. There is no \
                             second implementation of this derivation, so \
                             nothing here can be a crosscheck; naming a field \
                             this way makes crosscheck_fields_stay_asserted \
                             count it as one of the suite's independent anchors."
                        ));
                    }
                }
            }
        }
    }

    // Vacuity floor: with no such fixture found, every assertion above is
    // skipped.
    assert!(
        files >= 5,
        "the fixture walk found {files} json file(s); it is broken and this \
         check would pass vacuously"
    );
    assert!(
        claims >= 1,
        "no fixture under {} carries a `pin` block or an `oracle` block. \
         group_f_derivation.json is supposed to carry both -- it is one of two \
         groups not derived from the vendored C, and those blocks are how that \
         is recorded. Either they were removed or this walk stopped finding \
         them; both are failures, neither is agreement.",
        dir.display()
    );
    assert!(
        spec_arm >= 1,
        "the walk found {claims} pinned fixture(s) but routed every one of them \
         away as an executed crosscheck, so the specification-capture arm below \
         ran against nothing. group_f_derivation.json is supposed to land in it.",
    );

    // Routing is only sound if the target tests run, so both are checked
    // through the census. `EXECUTED_CROSSCHECK_TEST` is itself a census
    // caller, so it is `Tier::Listed` (in the run list; `#[ignore]` is covered
    // by `no_test_in_the_suite_is_ignored`). `NO_REFERENCE_TEST` is executed
    // and its reported vector count is read.
    if let Err(why) = census::check(
        "group_f_is_specification_not_crosscheck",
        EXECUTED_CROSSCHECK_TEST,
    ) {
        panic!(
            "this test routes {routed} fixture(s) with oracle.class == \
             {EXECUTED_CROSSCHECK:?} to {EXECUTED_CROSSCHECK_TEST}, and that \
             test does not run. The routing is now an exemption.\n\x20  {why}"
        );
    }
    if let Err(why) = census::check("group_f_is_specification_not_crosscheck", NO_REFERENCE_TEST) {
        panic!(
            "this test routes fixture(s) with oracle.class == \
             {EXECUTED_CROSSCHECK_NO_REFERENCE:?} to {NO_REFERENCE_TEST}, and \
             that test does not run and report. The routing is now an \
             exemption.\n\x20  {why}"
        );
    }

    assert!(
        problems.is_empty(),
        "a specification capture is being treated as an oracle:\n{}\n\
         Group F records what the published extension's TypeScript does. There \
         is one implementation of that derivation and no second opinion \
         anywhere, so these vectors carry none of a second implementation's error-detecting \
         power: a Rust port agreeing with them proves it matches the extension, \
         not that the extension is right. The suite's cross-implementation \
         anchor is group_c_crosscheck.json, where the second implementation is \
         executed rather than read; group F is not it and shares none of its \
         error-detecting power just by being TypeScript too.",
        problems.join("\n")
    );

    println!(
        "  {claims} non-C fixture(s): {spec_arm} specification capture(s), \
         {routed} routed to the executed-crosscheck test"
    );
}

/// The `oracle.class` values that have a test behind them, named once so the
/// routing in `group_f_is_specification_not_crosscheck` and the selection in
/// `group_c_crosscheck_is_an_executed_oracle` agree exactly.
const SPECIFICATION_CAPTURE: &str = "specification-capture";
const EXECUTED_CROSSCHECK: &str = "executed-crosscheck";

/// The class for an executed crosscheck with no C side.
///
/// Group RX records `@noble/hashes`' RIPEMD-160 for the input lengths where
/// the C reference overflows its stack, so the other side is this port, not
/// the C, and `EXECUTED_CROSSCHECK`'s claim would be false of it.
const EXECUTED_CROSSCHECK_NO_REFERENCE: &str = "executed-crosscheck-no-reference";

/// The test that owns the `executed-crosscheck` class.
const EXECUTED_CROSSCHECK_TEST: &str = "group_c_crosscheck_is_an_executed_oracle";

/// The test that owns the `executed-crosscheck-no-reference` class.
const NO_REFERENCE_TEST: &str = "group_rx_is_an_oracle_with_no_reference_side";

/// Group CX is an executed crosscheck. It must not decay into a
/// transcription.
///
/// `fixtures/group_c_crosscheck.json` is generated by running the TypeScript,
/// not by reading literals from its test file, which would pin only what the
/// reader believed it returns. Pasted values would satisfy every field-shape
/// check, so provenance is what is checked here.
///
/// The domain is derived: every fixture declaring
/// `oracle.class == "executed-crosscheck"` is selected, and
/// `group_f_is_specification_not_crosscheck` guarantees every pinned fixture
/// declares a known class. A crosscheck whose second implementation is not
/// TypeScript fails on the required `crosscheck_typescript_executed` field.
#[test]
fn group_c_crosscheck_is_an_executed_oracle() {
    let dir = repo_root().join("fixtures");
    let mut problems: Vec<String> = Vec::new();
    let mut found = 0usize;
    let mut vectors_checked = 0usize;
    let mut literals = 0usize;

    let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    paths.sort();

    // Every fixture, so a file cannot claim `is_independent_oracle: true`
    // without declaring the class whose checks come with it.
    for p in &paths {
        let name = p.file_name().unwrap_or_default().to_string_lossy().into_owned();
        let text = std::fs::read_to_string(p).unwrap_or_default();
        let root: serde_json::Value = serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("{} is not JSON: {e}", p.display()));

        let oracle = root.get("oracle").and_then(|v| v.as_object());
        let class = oracle
            .and_then(|o| o.get("class"))
            .and_then(serde_json::Value::as_str);
        let claims_independence = oracle
            .and_then(|o| o.get("is_independent_oracle"))
            .and_then(serde_json::Value::as_bool)
            == Some(true);

        if class != Some(EXECUTED_CROSSCHECK) {
            // A file may claim independence only if some test checks the
            // claim and runs (see the `census` module). `census::check` is
            // memoised per target, so this loop spawns at most one child.
            let owned_elsewhere = class == Some(EXECUTED_CROSSCHECK_NO_REFERENCE)
                && census::check("group_c_crosscheck_is_an_executed_oracle", NO_REFERENCE_TEST)
                    .is_ok();
            if claims_independence && !owned_elsewhere {
                problems.push(format!(
                    "\x20 - {name} declares is_independent_oracle: true with \
                     oracle.class {class:?}. Independence is the strongest claim \
                     in the suite and every file making it must be checked by \
                     some test. This one reaches {EXECUTED_CROSSCHECK:?} \
                     (here) and {EXECUTED_CROSSCHECK_NO_REFERENCE:?} \
                     ({NO_REFERENCE_TEST}); {name} matches neither, or matches \
                     the second while that test no longer exists."
                ));
            }
            continue;
        }
        found += 1;

        let Some(oracle) = oracle else { continue };
        let flag = |k: &str| oracle.get(k).and_then(serde_json::Value::as_bool);
        // The three claims, each false of a specification capture.
        if flag("is_independent_oracle") != Some(true) {
            problems.push(format!(
                "\x20 - {name}: oracle.is_independent_oracle is {:?}, not true",
                oracle.get("is_independent_oracle")
            ));
        }
        if flag("second_implementation_exists") != Some(true) {
            problems.push(format!(
                "\x20 - {name}: oracle.second_implementation_exists is {:?}, \
                 not true",
                oracle.get("second_implementation_exists")
            ));
        }
        let why = oracle.get("why").and_then(serde_json::Value::as_str).unwrap_or("");
        if why.len() < 200 {
            problems.push(format!(
                "\x20 - {name}: oracle.why is {} chars. The flags are only as \
                 durable as the argument written next to them.",
                why.len()
            ));
        }
        // What is not an oracle is recorded too: the Python hashlib check on
        // the addr_from_wots vector is the same two primitives in the same
        // order, not a third implementation.
        if oracle
            .get("not_an_oracle")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .len()
            < 100
        {
            problems.push(format!(
                "\x20 - {name}: oracle.not_an_oracle is missing or too short. An \
                 executed crosscheck attracts near-misses -- a second call to \
                 the same primitives, a value read out of a test file -- and the \
                 file has to say which of its neighbours are not oracles, or the \
                 next reader counts them."
            ));
        }

        // Provenance: the generator must be the TypeScript one, and the file
        // it crosschecks must exist. `derived_from` makes the domain derived,
        // so a dangling value fails.
        let generator = root
            .get("generator")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        if !generator.ends_with(".ts") {
            problems.push(format!(
                "\x20 - {name}: generator is {generator:?}, not a TypeScript \
                 program. An executed crosscheck is executed by something; if \
                 the generator is the C, the second implementation is the first."
            ));
        }
        match root.get("derived_from").and_then(serde_json::Value::as_str) {
            Some(src) if dir.join(src).exists() => {}
            other => problems.push(format!(
                "\x20 - {name}: derived_from is {other:?}, which is not a fixture \
                 on disk. The whole domain of this crosscheck is read out of that \
                 file; without it the generator is choosing its own inputs."
            )),
        }

        // Per vector: the executed value, the transcribed literal, and the
        // verdict that they agree.
        let Some(vs) = root.get("vectors").and_then(|v| v.as_array()) else {
            problems.push(format!("\x20 - {name} has no vectors array"));
            continue;
        };
        for v in vs {
            let Some(obj) = v.as_object() else { continue };
            let id = obj.get("id").and_then(serde_json::Value::as_str).unwrap_or("?");
            vectors_checked += 1;
            for k in [
                "crosscheck_typescript_executed",
                "crosschecks_vector",
                "source",
            ] {
                if !obj.contains_key(k) {
                    problems.push(format!("\x20 - {name} vector {id} has no `{k}`"));
                }
            }

            // The transcription leg is an exclusive or: either the vector
            // carries a literal and a verdict that it agrees with the
            // executed value, or it declares `literal_absent` and carries
            // neither. Both or neither is reported, so a literal that stopped
            // being compared is distinguishable from one that never existed.
            let has_literal = obj.contains_key("crosscheck_typescript_expected");
            let declares_absent = obj.get("literal_absent").and_then(serde_json::Value::as_bool)
                == Some(true);
            match (has_literal, declares_absent) {
                (true, false) => {
                    if !obj.contains_key("crosscheck_executed_matches_literal") {
                        problems.push(format!(
                            "\x20 - {name} vector {id} carries a transcribed \
                             literal but no `crosscheck_executed_matches_literal`. \
                             The verdict is the only record that the \
                             transcription was ever checked."
                        ));
                    } else if obj
                        .get("crosscheck_executed_matches_literal")
                        .and_then(serde_json::Value::as_bool)
                        != Some(true)
                    {
                        problems.push(format!(
                            "\x20 - {name} vector {id}: the executed TypeScript \
                             and the literal transcribed into group C disagree. \
                             Regenerating did not paper over it, which is the \
                             point."
                        ));
                    }
                    literals += 1;
                }
                (false, true) => {
                    if obj.contains_key("crosscheck_executed_matches_literal") {
                        problems.push(format!(
                            "\x20 - {name} vector {id} declares `literal_absent` \
                             and carries a verdict about a literal it does not \
                             have."
                        ));
                    }
                }
                (true, true) => problems.push(format!(
                    "\x20 - {name} vector {id} both carries a transcribed \
                     literal and declares `literal_absent`."
                )),
                (false, false) => problems.push(format!(
                    "\x20 - {name} vector {id} has neither a transcribed literal \
                     nor `literal_absent`. One must hold: silence here is how a \
                     literal that stopped being asserted would look."
                )),
            }
            // The second implementation must be a different one, stated as an
            // allow-list of provenances: "not the C" would accept an empty
            // source. `bs58` is the Base58 codec `addrTagToBase58` calls, used
            // for lengths other than 20 and the all-'1' class where the
            // reference faults; it shares no code with the C reference.
            const SECOND_IMPLEMENTATIONS: [&str; 2] = ["reference/mochimo-wots", "bs58 6.0.0"];
            let source = obj.get("source").and_then(serde_json::Value::as_str).unwrap_or("");
            if !SECOND_IMPLEMENTATIONS.iter().any(|k| source.contains(k)) {
                problems.push(format!(
                    "\x20 - {name} vector {id}: source is {source:?}, which names \
                     none of {SECOND_IMPLEMENTATIONS:?}. Two vectors derived from \
                     one implementation cannot disagree, so a crosscheck against \
                     it detects nothing."
                ));
            }
            if source.contains("reference/mochimo-core") {
                problems.push(format!(
                    "\x20 - {name} vector {id}: source names \
                     reference/mochimo-core. That is the implementation this \
                     group exists to be independent OF."
                ));
            }
        }
    }

    assert!(
        problems.is_empty(),
        "the executed crosscheck is not one:\n{}\n\
         fixtures/group_c_crosscheck.json is the suite's independent oracle in \
         its strong form -- a second implementation that was run, not read. \
         Every problem above turns it back into something weaker while leaving \
         the word \"crosscheck\" on it.",
        problems.join("\n")
    );

    // Vacuity floors come after the report above, so a specific finding is
    // not replaced by a generic one. A non-empty `problems` already proves
    // the walk is not vacuous; only a clean run needs a floor.
    assert!(
        found >= 1,
        "no fixture under {} declares oracle.class == {EXECUTED_CROSSCHECK:?}, \
         and nothing above objected. The suite's independence would then rest \
         entirely on literals read out of an upstream test file, which is the \
         floor the independence rule was amended to stop treating as the standard. \
         group_c_crosscheck.json was removed, or the walk stopped finding it.",
        dir.display()
    );
    // Most vectors in this group carry no literal, so a floor on
    // `vectors_checked` alone would be met even if the few vectors that do
    // carry one vanished.
    assert_eq!(
        literals, 3,
        "the crosscheck carries {literals} transcribed literal(s), expected 3 \
         (C7, C9, C-addr-from-wots-fill42). Those literals are the ONLY thing \
         in the suite that checks the transcription itself -- whether the \
         strings someone read out of the upstream test file were read \
         correctly. The executed values cannot check them, because a \
         transcription error and a correct transcription produce the same \
         executed value."
    );
    assert!(
        vectors_checked >= 2,
        "the executed crosscheck holds {vectors_checked} vector(s). One vector \
         is a check that a single value round-trips; the file exists to cover \
         every group C vector carrying a transcribed literal, and there is more \
         than one of those."
    );

    println!("  {found} executed crosscheck(s), {vectors_checked} vectors, all independent");
}

// -------------------------------------------------------------------------
// Oracle-blind properties
//
// Each is an absence (nothing left in memory, no comparison trait, no holder
// printing its secret), which no recorded value can witness. Each guard
// names the deciding mechanism and requires its execution through the
// census.
// -------------------------------------------------------------------------

/// `crates/mochimo-crypto/src/secret.rs`, comments stripped: the type's doc
/// comment explains that `PartialEq` is absent, and a raw search would match
/// it.
fn secret_rs_code() -> String {
    let p = repo_root().join("crates/mochimo-crypto/src/secret.rs");
    let text =
        std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()));
    code_only(&text)
}

/// The `ui/fail` trybuild cases, by file stem.
///
/// Two markers below clear with a compile-fail case, so their needle is a
/// filename in `ui/fail/`. `ui/` is outside the `tests/` walk so its
/// intentionally broken contents do not pollute symbol searches (see
/// tests/compile_fail.rs).
fn ui_fail_stems() -> Vec<String> {
    let dir = repo_root().join("crates/mochimo-crypto/ui/fail");
    let entries = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()));
    let mut out: Vec<String> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .filter_map(|p| p.file_stem().map(|s| s.to_string_lossy().into_owned()))
        .collect();
    out.sort();
    // Vacuity floor: an empty directory would make both trybuild-keyed
    // markers report a missing case for the wrong reason.
    assert!(
        out.len() >= 4,
        "ui/fail holds {} cases; I7's four are the floor. An empty or moved \
         directory makes every marker keyed on this walk report a missing case \
         when the real finding is that the walk broke.",
        out.len()
    );
    out
}

/// Zeroization is an absence property with no C counterpart.
///
/// `Secret<N>` wraps `Zeroizing`, so the bytes are overwritten on drop. The
/// observable is that freed storage no longer contains something, which
/// safe Rust cannot look at and no differential can compare.
///
/// Cleared by a drop-witness test that reads the secret's storage after the
/// drop inside one `unsafe` block. The compiler may elide a store nothing
/// reads (hence `zeroize`'s volatile writes and fence), so the test also
/// checks the guarantee survives optimisation; run it in release too.
#[test]
fn zeroization_has_no_reference_counterpart() {
    // Anchor A: our side of the property still exists.
    assert!(
        secret_rs_code().contains("Zeroizing<[u8; N]>"),
        "Secret no longer wraps Zeroizing. This marker demands evidence that \
         key bytes are cleared on drop; if the mechanism was removed, the \
         finding is the removal, not the missing test."
    );
    let mut owed: Vec<String> = Vec::new();
    const PROOF: &str = "secret_bytes_are_gone_after_drop";
    // Execution, not existence: `census::check` runs the named test on its
    // own and reads libtest's verdict and the reported measurement.
    if let Err(why) = census::check("zeroization_has_no_reference_counterpart", PROOF) {
        let owes = format!(
            "\x20 - no test named {PROOF} exists. It must observe the memory a \
             Secret occupied AFTER the drop and show the key bytes are not \
             there. Asserting that `Zeroizing` is in the type is not evidence: \
             that is a claim about our source, and the property is about what \
             the optimiser left behind."
        );
        owed.push(format!("{owes}\n\x20   {why}"));
    }

    assert!(
        owed.is_empty(),
        "Zeroization is oracle-blind and unwitnessed.\n{}",
        owed.join("\n")
    );
}

/// The bytes a `Secret` held are gone from its storage after the drop.
///
/// The proof `zeroization_has_no_reference_counterpart` requires.
///
/// Reading a dead local is undefined behaviour, and `drop(x)` moves `x`, so
/// the zeroing would happen in the callee's frame and the original address
/// would still hold the pattern. The witness therefore owns the storage
/// explicitly; see `tests/support/drop_witness.rs` for its soundness claims
/// and `tests/miri.rs::secret_drop_witness_is_sound_under_miri` for their
/// check.
///
/// Limits:
///
///   * One allocation is observed. Register spills, temporaries made moving
///     the `Secret` into the slot, and the witness's own `pattern` array are
///     not.
///   * `expand_seed`'s output and every chain intermediate are separate
///     allocations with their own `Zeroizing`, not witnessed here.
///   * It shows `Drop` cleared that storage, not that no copy of the secret
///     survives in the process.
#[test]
fn secret_bytes_are_gone_after_drop() {
    // Two widths, so an implementation special-casing one N cannot pass.
    let a = drop_witness::observe_secret_drop::<32>();
    let b = drop_witness::observe_secret_drop::<64>();

    let mut witnessed = 0usize;
    for obs in [&a, &b] {
        assert!(
            obs.pattern_seen_before_drop,
            "the witness did not see the pattern in the Secret's storage BEFORE \
             the drop, so it is reading the wrong bytes and nothing it says \
             about the state afterwards is about the right memory. Either \
             `Secret` stopped being a transparent wrapper over `[u8; N]` -- \
             which the witness checks with size_of -- or the read is misaligned."
        );
        assert!(
            obs.all_zero_after_drop,
            "{} of {} bytes still match the pattern after the drop. `Secret` \
             wraps `Zeroizing`, whose Drop writes zeros with volatile stores; \
             if this is red either that mechanism is gone or the optimiser \
             removed it.",
            obs.surviving_pattern_bytes,
            obs.bytes
        );
        assert_eq!(
            obs.surviving_pattern_bytes, 0,
            "a partial clear is not a clear"
        );
        witnessed += obs.bytes;
    }

    // The pattern has no zero byte, so "all zero afterwards" cannot be met by
    // bytes that were already zero.
    assert_eq!(
        witnessed, 96,
        "expected 32 + 64 bytes witnessed across two widths; got {witnessed}"
    );

    // Every integer on this line is a byte count; the census reads the
    // largest against its floor of 96.
    println!(
        "  zeroization: {witnessed} bytes witnessed across 2 widths, \
         {} surviving. Storage owned by the test; Miri adjudicates the \
         construction in tests/miri.rs.",
        a.surviving_pattern_bytes + b.surviving_pattern_bytes
    );
}

/// `Secret` has no `PartialEq`; enforced by a compile-fail case and a parse
/// of `secret.rs`.
///
/// A derived comparison over key material short-circuits on the first
/// differing byte, so secrets are compared only through
/// `subtle::ConstantTimeEq` (`Secret::ct_eq`). A future
/// `#[derive(PartialEq)]` is a one-word change no runtime assertion can see.
///
/// `ui/fail/secret_is_not_partial_eq.rs` and
/// `ui/fail/secret_is_not_partial_ord.rs` pin both operator families with
/// the compiler. The anchor below parses `secret.rs` and matches only item
/// forms that grant comparison: a `derive(..)` naming `PartialEq`, `Eq`,
/// `PartialOrd` or `Ord` on any item (inside `cfg_attr` too), or an `impl` of
/// one of those traits for any type. A substring search would also match
/// `ConstantTimeEq`, which is the required remedy, so `impl ConstantTimeEq`
/// and a method named `ct_eq` pass.
#[test]
fn secret_has_no_equality_and_nothing_enforces_it() {
    // The anchor checks the property itself: a derive or impl of a
    // comparison trait fails here as a broken rule. Parsed, not searched,
    // because `ConstantTimeEq` contains `Eq`.
    const COMPARISON_TRAITS: [&str; 4] = ["PartialEq", "Eq", "PartialOrd", "Ord"];
    let raw = read_crate_file("crates/mochimo-crypto/src/secret.rs");
    let ast = syn::parse_file(&raw).unwrap_or_else(|e| panic!("secret.rs does not parse: {e}"));
    let mut granted: Vec<String> = Vec::new();
    let mut items_seen = 0usize;
    for item in &ast.items {
        items_seen += 1;
        // Derives, including `#[cfg_attr(.., derive(..))]`: the attribute's
        // whole token stream is searched for `derive` followed by a group
        // naming a comparison trait.
        let attrs: &[syn::Attribute] = match item {
            syn::Item::Struct(s) => &s.attrs,
            syn::Item::Enum(e) => &e.attrs,
            syn::Item::Union(u) => &u.attrs,
            syn::Item::Type(t) => &t.attrs,
            _ => &[],
        };
        for a in attrs {
            use quote::ToTokens;
            // Only the attribute forms that can grant a derive: `derive(..)`
            // itself and `cfg_attr(.., derive(..))`. Doc comments are
            // attributes too (`#[doc = ".."]`), and secret.rs's doc names
            // `PartialEq` in the sentence forbidding it -- found by this
            // anchor's first run, which read the prose as a derive.
            if !(a.path().is_ident("derive") || a.path().is_ident("cfg_attr")) {
                continue;
            }
            let text = a.meta.to_token_stream().to_string();
            if text.contains("derive") {
                for t in COMPARISON_TRAITS {
                    // The derive list is a comma-separated group; match the
                    // ident as a whole word so `PartialEq` does not also fire
                    // as `Eq`.
                    let words: Vec<String> = text
                        .split(|c: char| !c.is_alphanumeric() && c != '_')
                        .map(str::to_owned)
                        .collect();
                    if words.iter().any(|w| w == t) {
                        granted.push(format!("derive({t})"));
                    }
                }
            }
        }
        if let syn::Item::Impl(i) = item {
            if let Some((_, path, _)) = &i.trait_ {
                if let Some(last) = path.segments.last() {
                    let name = last.ident.to_string();
                    if COMPARISON_TRAITS.contains(&name.as_str()) {
                        use quote::ToTokens;
                        granted.push(format!("impl {name} for {}", i.self_ty.to_token_stream()));
                    }
                }
            }
        }
    }
    assert!(items_seen >= 3, "secret.rs parsed to {items_seen} items; the walk is not reading the file");
    assert!(
        granted.is_empty(),
        "secret.rs grants comparison: {granted:?}. Comparison over key material is \
         variable-time and short-circuits; secret.rs's own doc comment says so, and it \
         names the remedy -- `subtle::ConstantTimeEq`, which this anchor deliberately \
         does not match. This is the violation, not a missing test."
    );

    let mut owed: Vec<String> = Vec::new();
    const CASE: &str = "secret_is_not_partial_eq";
    let stems = ui_fail_stems();
    if !stems.iter().any(|s| s == CASE) {
        owed.push(format!(
            "\x20 - ui/fail/{CASE}.rs does not exist. The rule currently holds \
             by nobody having broken it, which is indistinguishable from it \
             being enforced right up until someone does. The case must compare \
             two Secrets with `==` and pin a .stderr naming the missing trait."
        ));
    } else if !repo_root()
        .join(format!("crates/mochimo-crypto/ui/fail/{CASE}.stderr"))
        .is_file()
    {
        owed.push(format!(
            "\x20 - ui/fail/{CASE}.rs has no .stderr beside it, so it asserts \
             only that something failed to compile -- a typo in the case would \
             satisfy it just as well as the missing trait."
        ));
    }

    // The two checks above only show that a `.rs` and a `.stderr` exist. A
    // case typo'd into a no-op, or a `.stderr` no longer naming `PartialEq`,
    // would leave them green. A `compile_fail` case passes on any compilation
    // failure, so the enforcement is trybuild with the pinned `.stderr`: the
    // test that registers `ui/fail/*.rs` must run, pass, and report its case
    // count.
    if let Err(why) = census::check(
        "secret_has_no_equality_and_nothing_enforces_it",
        "every_ui_case_compiles_or_fails_for_its_pinned_reason",
    ) {
        owed.push(format!(
            "\x20 - the trybuild run that compiles ui/fail/{CASE}.rs did not run \
             and pass. The case file existing is a claim about the filesystem; \
             this is the claim that the compiler was actually asked, and \
             refused.\n\x20   {why}"
        ));
    }

    assert!(
        owed.is_empty(),
        "The no-comparison rule on Secret is documented but unenforced.\n{}\n\
         Note that the anchor above is passing: \
         the rule HOLDS today. What is owed is the thing that would notice if \
         it stopped.",
        owed.join("\n")
    );
}

/// No secret may reach a `Debug` output, including through a holder struct.
///
/// `Secret` has a hand-written `Debug` that redacts, pinned by `secret.rs`'s
/// unit test. A `#[derive(Debug)]` on a struct holding raw bytes beside a
/// `Secret`, or deriving over a field the redaction does not cover, would
/// not be.
///
/// The census-checked scan, `no_holder_of_key_material_derives_debug`, walks
/// `crates/*/src`, closes transitively over holders of `Secret`/`Zeroizing`,
/// rejects derived `Debug`, and asserts it found at least one direct struct
/// holder. Whether a hand-written `Debug` redacts is pinned per type by the
/// `debug_never_reveals_*` unit tests beside each impl.
#[test]
fn secret_holder_debug_redaction_is_enforced_by_the_scan() {
    // Anchor: the redaction this marker extends still exists.
    assert!(
        secret_rs_code().contains("impl<const N: usize> fmt::Debug for Secret<N>"),
        "Secret no longer hand-writes Debug. The holder obligation below is an \
         extension of that redaction; if the base was removed or derived, that \
         is the finding."
    );

    let mut owed: Vec<String> = Vec::new();
    const PROOF: &str = "no_holder_of_key_material_derives_debug";
    // Execution, not existence: `census::check` runs the named test on its
    // own and reads libtest's verdict and the reported measurement.
    if let Err(why) = census::check("secret_holder_debug_redaction_is_enforced_by_the_scan", PROOF) {
        let owes = format!(
            // Not glob-spelled. A glob inside a string literal is safe for
            // `code_only` (see
            // `stripper_does_not_open_a_comment_inside_a_string`); the
            // spelling is simply unchanged.
            "\x20 - no test named {PROOF} exists. It must walk every crate's \
             src/ directory, identify structs with a field typed Secret<..> or \
             Zeroizing<..>, and reject a derived Debug on them. It must also \
             assert it found \
             at least one such struct: with none in the tree it would pass over \
             an empty set and read as coverage."
        );
        owed.push(format!("{owes}\n\x20   {why}"));
    }

    assert!(
        owed.is_empty(),
        "Debug-leakage enforcement has REGRESSED. Once this red \
         meant a designed absence — no holder existed yet. That \
         state is over: the account model landed src/account.rs's holders and the scan, so \
         this firing now means the scan, the census row, or the holders \
         themselves went away.\n{}\n\
         Do not clear it by \
         weakening the scan's at-least-one clause — that produces the \
         green-over-an-empty-set this marker exists to prevent.",
        owed.join("\n")
    );
}

/// The proof behind the Debug-holder marker: every holder of key material
/// hand-writes `Debug`, and at least one holder exists.
///
/// Covers structs and enums and closes transitively: an item is a holder if
/// any field or variant type mentions `Secret`, `Zeroizing` or a type already
/// found to be a holder. `Account` holds key material through `KeyMaterial`
/// through `ImportedRoot`, and a derived `Debug` at any level prints the
/// whole chain.
///
/// A derived `Debug` on a holder is rejected and a hand-written one is
/// trusted; whether it redacts is pinned per type by the
/// `debug_never_reveals_*` unit tests in `secret.rs` and `account.rs`.
#[test]
fn no_holder_of_key_material_derives_debug() {
    use quote::ToTokens;

    // Types permitted to derive Debug while holding key material. Empty; a
    // row naming no holder in the tree fails below. A future entry must
    // argue its redaction here.
    const ALLOWED_DERIVED_DEBUG_HOLDERS: &[(&str, &str)] = &[];

    let files = crate_source_files();
    assert!(
        files.len() >= 10,
        "the walk of crates/*/src found only {} files; any result from it is vacuous",
        files.len()
    );

    struct Holder {
        file: String,
        name: String,
        field_type_idents: Vec<String>,
        derives_debug: bool,
        is_struct: bool,
    }

    fn ident_tokens(ty: &syn::Type) -> Vec<String> {
        ty.to_token_stream()
            .into_iter()
            .flat_map(|t| match t {
                proc_macro2::TokenTree::Ident(i) => vec![i.to_string()],
                proc_macro2::TokenTree::Group(g) => g
                    .stream()
                    .into_iter()
                    .filter_map(|t| match t {
                        proc_macro2::TokenTree::Ident(i) => Some(i.to_string()),
                        _ => None,
                    })
                    .collect(),
                _ => vec![],
            })
            .collect()
    }

    fn attr_derives_debug(attrs: &[syn::Attribute]) -> bool {
        attrs.iter().any(|a| {
            let idents: Vec<String> = a
                .to_token_stream()
                .into_iter()
                .flat_map(|t| match t {
                    proc_macro2::TokenTree::Ident(i) => vec![i.to_string()],
                    proc_macro2::TokenTree::Group(g) => g
                        .stream()
                        .into_iter()
                        .flat_map(|t| match t {
                            proc_macro2::TokenTree::Ident(i) => vec![i.to_string()],
                            proc_macro2::TokenTree::Group(g2) => g2
                                .stream()
                                .into_iter()
                                .filter_map(|t| match t {
                                    proc_macro2::TokenTree::Ident(i) => Some(i.to_string()),
                                    _ => None,
                                })
                                .collect(),
                            _ => vec![],
                        })
                        .collect(),
                    _ => vec![],
                })
                .collect();
            // Matches #[derive(.., Debug, ..)] and
            // #[cfg_attr(.., derive(.., Debug, ..))]. Over-matching an
            // attribute that names both idents fails, the safe direction.
            idents.iter().any(|i| i == "derive") && idents.iter().any(|i| i == "Debug")
        })
    }

    let mut items: Vec<Holder> = Vec::new();
    for (name, text) in &files {
        let parsed = syn::parse_file(text)
            .unwrap_or_else(|e| panic!("{name} does not parse as Rust: {e}"));
        let mut stack: Vec<&syn::Item> = parsed.items.iter().collect();
        while let Some(item) = stack.pop() {
            match item {
                syn::Item::Mod(m) => {
                    if let Some((_, inner)) = &m.content {
                        stack.extend(inner.iter());
                    }
                }
                syn::Item::Struct(s) => {
                    let mut idents = Vec::new();
                    for f in &s.fields {
                        idents.extend(ident_tokens(&f.ty));
                    }
                    items.push(Holder {
                        file: name.clone(),
                        name: s.ident.to_string(),
                        field_type_idents: idents,
                        derives_debug: attr_derives_debug(&s.attrs),
                        is_struct: true,
                    });
                }
                syn::Item::Enum(e) => {
                    let mut idents = Vec::new();
                    for v in &e.variants {
                        for f in &v.fields {
                            idents.extend(ident_tokens(&f.ty));
                        }
                    }
                    items.push(Holder {
                        file: name.clone(),
                        name: e.ident.to_string(),
                        field_type_idents: idents,
                        derives_debug: attr_derives_debug(&e.attrs),
                        is_struct: false,
                    });
                }
                _ => {}
            }
        }
    }

    // Transitive taint closure, seeded on the two key-material types.
    let mut tainted: BTreeSet<String> =
        ["Secret".to_string(), "Zeroizing".to_string()].into();
    let direct: BTreeSet<String> = items
        .iter()
        .filter(|i| i.field_type_idents.iter().any(|t| tainted.contains(t)))
        .map(|i| i.name.clone())
        .collect();
    loop {
        let before = tainted.len();
        for item in &items {
            if item.field_type_idents.iter().any(|t| tainted.contains(t)) {
                tainted.insert(item.name.clone());
            }
        }
        if tainted.len() == before {
            break;
        }
    }

    let holders: Vec<&Holder> = items.iter().filter(|i| tainted.contains(&i.name)).collect();
    let direct_structs = holders
        .iter()
        .filter(|h| h.is_struct && direct.contains(&h.name))
        .count();
    assert!(
        direct_structs >= 1,
        "the scan found no struct holding Secret<..> or Zeroizing<..> under \
         crates/*/src. With nothing to scan this test passes over an empty \
         set, which is the vacuity the marker forbids clearing through \
         ; if the holders were renamed or moved, re-derive the \
         taint seed before trusting any green here."
    );

    let violations: Vec<String> = holders
        .iter()
        .filter(|h| h.derives_debug)
        .filter(|h| {
            !ALLOWED_DERIVED_DEBUG_HOLDERS
                .iter()
                .any(|(allowed, _)| allowed == &h.name)
        })
        .map(|h| format!("  - {} in {}", h.name, h.file))
        .collect();
    assert!(
        violations.is_empty(),
        "these types hold key material (directly or through another holder) \
         and derive Debug, which is how a root reaches a log file \
         (docs/specification.md I6):\n{}\n\
         Hand-write the impl and pin its rendering with a unit test, the way \
         secret.rs and account.rs do.",
        violations.join("\n")
    );
    let unused: Vec<&str> = ALLOWED_DERIVED_DEBUG_HOLDERS
        .iter()
        .filter(|(allowed, _)| !holders.iter().any(|h| &h.name == allowed))
        .map(|(allowed, _)| *allowed)
        .collect();
    assert!(
        unused.is_empty(),
        "these allow-list rows name no holder in the tree: {unused:?}. An \
         unused permission is a hole waiting for an occupant; remove the row."
    );

    // Every integer below is a holder count. The census floor reads the
    // largest integer after the needle, so the file floor above is an assert,
    // not a print.
    println!(
        "  Debug-holder scan: {} holder(s) of key material ({} direct \
         struct(s)), 0 derived Debug",
        holders.len(),
        direct_structs
    );
}

/// I6: key material that leaves a `Secret` or a `Zeroizing` does not land in
/// a buffer nothing scrubs.
///
/// The other guarantees are held by the holder scan (`Debug` redaction),
/// `ui/fail` cases (no `PartialEq` or `PartialOrd`) and a `MaybeUninit`
/// witness under Miri (clearing). This one cannot be a type: `[u8; 32]` is
/// the same type for a seed and a block hash, so the scan watches where the
/// bytes get out.
#[test]
fn key_material_copies_are_enforced_by_the_scan() {
    // Anchor: `expose`, the only way to a `Secret`'s bytes, still exists. If
    // it were renamed, the scan below would walk an empty population.
    assert!(
        secret_rs_code().contains("pub fn expose(&self)"),
        "Secret no longer exposes its bytes through `expose`. The scan below \
         keys on that name as the one route out of a Secret; if the route was \
         renamed or a second one was added, the scan is measuring a chokepoint \
         that is no longer the chokepoint."
    );

    let mut owed: Vec<String> = Vec::new();
    const PROOF: &str = "no_key_material_is_copied_into_an_unprotected_buffer";
    if let Err(why) = census::check("key_material_copies_are_enforced_by_the_scan", PROOF) {
        owed.push(format!(
            "\x20 - no test named {PROOF} exists. It must walk every crate's \
             src/ directory and reject an owning copy taken from a `Secret` \
             through `expose`, or from a binding known to be `Zeroizing`, \
             into a buffer that is neither. It must also report how many \
             `expose` sites it examined: with none it would pass over an \
             empty set and read as coverage.\n\x20   {why}"
        ));
    }

    assert!(
        owed.is_empty(),
        "the zeroization scan has REGRESSED. The property it holds is the one \
         guarantee of the four that no compiler and no interpreter can reach, \
         so its absence is not a smaller gap than the others -- it is the only \
         one where nothing else is watching.\n{}",
        owed.join("\n")
    );
}

/// The proof behind the copy marker: no owning copy of key material lands in
/// an unprotected buffer, and the scan reports the population it examined.
///
/// Two shapes are rejected:
///
/// * **Out of a `Secret`, through `expose`.** `s.expose().to_vec()` and
///   `let b = *s.expose()` (a copy of the fixed-width array).
/// * **Out of a `Zeroizing` binding.** `Zeroizing<T>` derefs to `T`, so a
///   local annotated or constructed as one is tracked per function body, and
///   `to_vec`, `to_owned`, `clone` and `to_string` on it are rejected.
///
/// A copy placed straight into a `Zeroizing` or `Secret` (inside
/// `Zeroizing::new(..)`, a `Secret::..` call, or the initializer of a `let`
/// annotated with either) is accepted.
///
/// Limits:
///
/// * `crates/*/src` only; `tests/` is not walked.
/// * Syntactic, not dataflow: key material passed through a function and
///   copied on the far side is not seen.
/// * Key material is known only by `Secret` and `Zeroizing`. `os_bytes` and
///   `os_create_entropy` both return `Zeroizing`, which is not asserted here.
/// * A `Zeroizing` binding is tracked by name within one function body; a
///   secret moved into a field, tuple or closure capture is not followed.
/// * Macro bodies (`assert_eq!`, `assert!`, `matches!`, `format!`) are
///   opaque to `syn`. The `expose` calls inside them are in `cfg(test)`
///   modules.
#[test]
fn no_key_material_is_copied_into_an_unprotected_buffer() {
    use syn::spanned::Spanned;
    use syn::visit::{self, Visit};

    // Functions permitted to take an unprotected copy. Empty; a row naming a
    // function the scan finds nothing in fails below. A future entry must
    // argue here why its copy is not key material or cannot be a `Zeroizing`.
    const ALLOWED_UNPROTECTED_COPIES: &[(&str, &str)] = &[];

    // Conversions that borrow and return a value owning a copy of the bytes.
    // `to_string` covers `Phrase`, a `Zeroizing<String>`.
    const OWNING: &[&str] = &["to_vec", "to_owned", "clone", "to_string"];

    let files = crate_source_files();
    assert!(
        files.len() >= 10,
        "the walk of crates/*/src found only {} files; any result from it is vacuous",
        files.len()
    );

    fn mentions_protector(ty: &syn::Type) -> bool {
        use quote::ToTokens;
        ty.to_token_stream()
            .into_iter()
            .any(|t| matches!(&t, proc_macro2::TokenTree::Ident(i) if i == "Zeroizing" || i == "Secret"))
    }

    fn is_expose(e: &syn::Expr) -> bool {
        matches!(e, syn::Expr::MethodCall(m) if m.method == "expose" && m.args.is_empty())
    }

    // `Zeroizing::new(..)`, `Secret::new(..)`, and their qualified spellings.
    // Every constructor of either returns the protecting wrapper.
    fn is_protecting_call(f: &syn::Expr) -> bool {
        matches!(f, syn::Expr::Path(p)
            if p.path.segments.iter().any(|s| s.ident == "Zeroizing" || s.ident == "Secret"))
    }

    fn bare_ident(e: &syn::Expr) -> Option<String> {
        match e {
            syn::Expr::Path(p) if p.qself.is_none() => p.path.get_ident().map(|i| i.to_string()),
            _ => None,
        }
    }

    fn bound_name(p: &syn::Pat) -> Option<String> {
        match p {
            syn::Pat::Ident(i) => Some(i.ident.to_string()),
            syn::Pat::Type(t) => bound_name(&t.pat),
            _ => None,
        }
    }

    struct Scan {
        file: String,
        in_fn: String,
        protected: usize,
        tracked: std::collections::BTreeSet<String>,
        expose_sites: usize,
        protected_bindings: usize,
        candidates: Vec<(String, String)>,
    }

    impl Scan {
        fn scoped<F: FnOnce(&mut Self)>(&mut self, name: String, f: F) {
            let outer_tracked = std::mem::take(&mut self.tracked);
            let outer_fn = std::mem::replace(&mut self.in_fn, name);
            f(self);
            self.tracked = outer_tracked;
            self.in_fn = outer_fn;
        }
        fn flag(&mut self, line: usize, what: &str) {
            let site = format!("\x20 - {}:{} in `{}`: {}", self.file, line, self.in_fn, what);
            self.candidates.push((self.in_fn.clone(), site));
        }
    }

    impl<'ast> Visit<'ast> for Scan {
        fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
            let n = f.sig.ident.to_string();
            self.scoped(n, |s| visit::visit_item_fn(s, f));
        }
        fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
            let n = f.sig.ident.to_string();
            self.scoped(n, |s| visit::visit_impl_item_fn(s, f));
        }
        fn visit_trait_item_fn(&mut self, f: &'ast syn::TraitItemFn) {
            let n = f.sig.ident.to_string();
            self.scoped(n, |s| visit::visit_trait_item_fn(s, f));
        }

        fn visit_local(&mut self, l: &'ast syn::Local) {
            let annotated = matches!(&l.pat, syn::Pat::Type(t) if mentions_protector(&t.ty));
            let constructed = l.init.as_ref().is_some_and(|i| match &*i.expr {
                syn::Expr::Call(c) => is_protecting_call(&c.func),
                _ => false,
            });
            if annotated || constructed {
                if let Some(n) = bound_name(&l.pat) {
                    self.tracked.insert(n);
                }
                self.protected_bindings += 1;
            } else if let Some(i) = &l.init {
                // `let b = *s.expose();`: the fixed-width array is `Copy`, so
                // the deref copies every byte into a bare array.
                if let syn::Expr::Unary(u) = &*i.expr {
                    if matches!(u.op, syn::UnOp::Deref(_)) && is_expose(&u.expr) {
                        let line = i.expr.span().start().line;
                        self.flag(line, "a deref copy of `expose()` into an unprotected binding");
                    }
                }
            }
            if annotated {
                self.protected += 1;
                visit::visit_local(self, l);
                self.protected -= 1;
            } else {
                visit::visit_local(self, l);
            }
        }

        fn visit_expr(&mut self, e: &'ast syn::Expr) {
            match e {
                syn::Expr::Call(c) if is_protecting_call(&c.func) => {
                    self.protected += 1;
                    visit::visit_expr(self, e);
                    self.protected -= 1;
                    return;
                }
                syn::Expr::MethodCall(m) if m.method == "expose" && m.args.is_empty() => {
                    self.expose_sites += 1;
                }
                syn::Expr::MethodCall(m)
                    if OWNING.iter().any(|o| m.method == o) && m.args.is_empty() =>
                {
                    let from_expose = is_expose(&m.receiver);
                    let from_tracked =
                        bare_ident(&m.receiver).is_some_and(|n| self.tracked.contains(&n));
                    if self.protected == 0 && (from_expose || from_tracked) {
                        let line = m.span().start().line;
                        let src = if from_expose { "`expose()`" } else { "a `Zeroizing` binding" };
                        let what = format!("`.{}()` takes an owning copy from {src}", m.method);
                        self.flag(line, &what);
                    }
                }
                _ => {}
            }
            visit::visit_expr(self, e);
        }
    }

    let mut expose_sites = 0usize;
    let mut protected_bindings = 0usize;
    let mut candidates: Vec<(String, String)> = Vec::new();
    for (name, text) in &files {
        let parsed =
            syn::parse_file(text).unwrap_or_else(|e| panic!("{name} does not parse as Rust: {e}"));
        let mut scan = Scan {
            file: name.clone(),
            in_fn: "<item scope>".to_string(),
            protected: 0,
            tracked: std::collections::BTreeSet::new(),
            expose_sites: 0,
            protected_bindings: 0,
            candidates: Vec::new(),
        };
        scan.visit_file(&parsed);
        expose_sites += scan.expose_sites;
        protected_bindings += scan.protected_bindings;
        candidates.extend(scan.candidates);
    }

    // Vacuity, both halves: with no chokepoint and no protected binding found,
    // zero violations would mean nothing.
    assert!(
        expose_sites >= 8,
        "the scan found {expose_sites} `expose()` call site(s) under crates/*/src; \
         this walk sees 15. Under the floor the zero below is not a finding \
         about the tree, it is a finding about the scan -- `expose` renamed, or \
         the walk pointed somewhere else. (A text search finds 21. The six it \
         finds and this does not are each inside a macro invocation, which is \
         the bound the doc above states rather than a miscount here.)"
    );
    assert!(
        protected_bindings >= 5,
        "the scan tracked {protected_bindings} protected binding(s); this tree \
         carries more. The `Zeroizing` half of the scan is reporting about \
         nothing."
    );

    let violations: Vec<String> = candidates
        .iter()
        .filter(|(f, _)| !ALLOWED_UNPROTECTED_COPIES.iter().any(|(a, _)| a == f))
        .map(|(_, site)| site.clone())
        .collect();
    assert!(
        violations.is_empty(),
        "key material is copied into a buffer that is never scrubbed \
         (docs/specification.md I6):\n{}\n\
         Put the copy in a `Zeroizing` -- `Zeroizing::new(x.expose().to_vec())` \
         -- or keep the borrow and drop the copy. A bare `Vec` or array holding \
         a seed is returned to the allocator with the bytes still in it.",
        violations.join("\n")
    );
    let unused: Vec<&str> = ALLOWED_UNPROTECTED_COPIES
        .iter()
        .filter(|(a, _)| !candidates.iter().any(|(f, _)| f == a))
        .map(|(a, _)| *a)
        .collect();
    assert!(
        unused.is_empty(),
        "these allow-list rows name a function the scan finds no copy in: \
         {unused:?}. An unused permission is a hole waiting for an occupant; \
         remove the row."
    );

    // Both integers are population counts for the census floor; nothing else
    // is printed (see `Row::floor`).
    println!(
        "  key-material copy scan: {expose_sites} expose() call site(s) and \
         {protected_bindings} protected binding(s) examined, 0 unprotected copies"
    );
}

/// Memory safety is established for the native paths Miri walks, and no
/// further.
///
/// The C reads fixed-size buffers through raw pointers, so an over-read
/// returns a wrong answer or nothing observable; the Rust port indexes
/// slices, where the same bug panics. Differential testing cannot decide
/// this.
///
/// Claimed: the functions `tests/miri.rs::MIRI_DOMAIN` marks covered execute
/// under Miri without undefined behaviour. Not claimed: that the crate is
/// memory-safe. `crate::base58`, most of `crate::bytes`, `addr::sha3`, the
/// transaction surface and the diagnostic-string functions panic on entry
/// in the only configuration Miri can run.
///
/// Every `pub fn` in `src/backend/native.rs` must have a `MIRI_DOMAIN` row,
/// covered or excluded with a reason; the function list is parsed from the
/// backend, so a new function fails here until its status is decided.
/// `miri.rs` asserts at runtime that every covered function actually ran.
///
/// Nothing in `cargo test` runs Miri. This test checks the harness and its
/// domain; the run itself is
///
/// ```sh
/// cargo +nightly miri test -p mochimo-crypto
/// ```
#[test]
fn memory_safety_is_established_only_for_the_native_paths_miri_walks() {
    let mut owed: Vec<String> = Vec::new();
    const PROOF: &str = "native_backend_is_clean_under_miri";
    // Execution, not existence: `census::check` runs the named test on its
    // own and reads libtest's verdict and the reported measurement.
    if let Err(why) = census::check("memory_safety_is_established_only_for_the_native_paths_miri_walks", PROOF) {
        let owes = format!(
            "\x20 - no test named {PROOF} exists. It must exercise the native \
             primitives under `cfg(miri)` with the ffi backend's feature \
             switched off, since Miri cannot execute the linked C. Running the \
             existing KATs under Miri unchanged would fail on the ffi calls and \
             say nothing about the port."
        );
        owed.push(format!("{owes}\n\x20   {why}"));
    }

    // The domain, derived from the backend rather than from the table.
    let harness = read_crate_file("crates/mochimo-crypto/tests/miri.rs");
    // Whitespace removed before matching, since a `MIRI_DOMAIN` row may span
    // several lines. The needle is anchored on `("` and terminated by `",`.
    let declared: String = code_only(&harness)
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let mut undeclared: Vec<String> = Vec::new();
    let mut surface = 0usize;
    // `backend/native.rs`, the one backend module.
    for file in ["backend/native.rs"] {
        let text = read_crate_file(&format!("crates/mochimo-crypto/src/{file}"));
        // Raw text: syn handles comments itself.
        for name in public_fn_names(&text) {
            surface += 1;
            // The row's opening tuple, not the bare name, which would match
            // any mention of the function.
            if !declared.contains(&format!("(\"{name}\",")) {
                undeclared.push(format!(
                    "\x20 - {file}::{name} has no row in tests/miri.rs::MIRI_DOMAIN. \
                     Every backend function is either walked under Miri or \
                     excluded with a reason; there is no third state."
                ));
            }
        }
    }
    assert!(
        surface >= 30,
        "parsed only {surface} public functions out of the native backend \
         module; this tree's `backend/native.rs` declares 41 bare-`pub` \
         functions at item level, and this floor sits above two thirds of that \
         rather than at it -- the measurement moved by nothing across this \
         re-derivation, and a floor is not lowered to meet a rule. The walk \
         that derives this domain is broken, and every name it failed to see \
         would have read as declared."
    );
    owed.extend(undeclared);

    assert!(
        owed.is_empty(),
        "Miri's domain over the native backend is incomplete.\n{}\n\
         {surface} public backend functions were parsed.",
        owed.join("\n")
    );
}

/// The little-endian rule: no native-endian conversion anywhere under
/// `crates/*/src`.
///
/// This check is the only enforcement. On a little-endian host
/// `to_le_bytes` and `to_ne_bytes` compile to the same thing, so no output
/// comparison can tell them apart. `put32`'s output is recorded in
/// `group_d_tx.json` (`identity.adrs_tail12`), which catches a `to_be_bytes`
/// port; a `to_ne_bytes` port, `get32`, and any other byte-order code are
/// caught only here.
///
/// The scan lexes every file with `proc_macro2` and compares identifiers,
/// so spacing does not matter, a name outside call position
/// (`xs.map(u32::to_ne_bytes)`) is seen, and a doc comment or string
/// literal (a `Literal` token) cannot match. The forbidden set is
/// `from_ne_bytes`, `to_ne_bytes` and `target_endian`; a
/// `cfg(target_endian)` pair would reproduce the reference's host dependence
/// without either conversion. A file that does not lex fails the check
/// rather than shrinking its domain.
///
/// Not seen, because none uses a forbidden name:
///
/// * `core::mem::transmute::<[u8; 4], u32>(..)`;
/// * byte-order arithmetic written by hand, such as `(b[3] as u32) << 24`;
/// * a cast through `bytemuck`, `zerocopy`, a union, or a raw pointer;
/// * a rename, a type alias, or a helper in another crate.
///
/// Hand-written byte assembly is how the reference does this, so these are
/// listed in the specification's standing properties.
#[test]
fn no_native_endian_conversions_anywhere_in_the_crate() {
    // `target_endian` joins the two conversions: it is the `cfg` that would
    // select between them per host.
    const FORBIDDEN: [&str; 3] = ["from_ne_bytes", "to_ne_bytes", "target_endian"];

    fn idents(stream: proc_macro2::TokenStream, out: &mut Vec<proc_macro2::Ident>) {
        for tree in stream {
            match tree {
                proc_macro2::TokenTree::Ident(id) => out.push(id),
                proc_macro2::TokenTree::Group(g) => idents(g.stream(), out),
                // Punct and Literal tokens cannot be identifiers, so a
                // Literal holding one of these names as text does not match.
                _ => {}
            }
        }
    }

    let mut found: Vec<String> = Vec::new();
    let mut per_file: Vec<(String, usize)> = Vec::new();
    let mut examined = 0usize;
    for (name, text) in crate_source_files() {
        // Fail closed: skipping a file that will not lex would silently
        // shrink the domain.
        let stream: proc_macro2::TokenStream = text.parse().unwrap_or_else(|e| {
            panic!(
                "{name} did not lex as Rust ({e}). This scan is the sole \
                 enforcement of the little-endian decision and it examines tokens, so a file it \
                 cannot read is a file nothing checks. It is not skipped."
            )
        });
        let mut ids = Vec::new();
        idents(stream, &mut ids);
        examined += ids.len();
        per_file.push((name.clone(), ids.len()));
        for id in ids {
            let spelled = id.to_string();
            if FORBIDDEN.contains(&spelled.as_str()) {
                let at = id.span().start();
                found.push(format!("\x20 - {name}:{} names `{spelled}`", at.line));
            }
        }
    }

    // The floor counts identifiers examined, one per token compared, not
    // files or bytes, so it measures the population actually inspected.
    let breakdown = per_file
        .iter()
        .map(|(n, c)| format!("\x20 - {c:>5}  {n}"))
        .collect::<Vec<_>>()
        .join("\n");
    let empty: Vec<&str> = per_file
        .iter()
        .filter(|(_, c)| *c == 0)
        .map(|(n, _)| n.as_str())
        .collect();
    assert!(
        empty.is_empty(),
        "these file(s) lexed to zero identifiers: {empty:?}. A .rs file that \
         yields no identifier was not read; the total floor below cannot see \
         one file going empty among fifteen, which is the population question \
         the census's own question applied per member."
    );
    assert!(
        per_file.len() >= 25 && examined >= 24_400,
        "the walk saw {} file(s) and compared {examined} identifier(s):\n{breakdown}\n\
         Both are far below the tree's real size, so this is the walk or the \
         lexer failing, not the crate being clean -- and a search over nothing \
         finds nothing, which is also what a compliant crate looks like.\n\
         \n\
         This tree measures 36,640 identifiers across 38 files, and both floors \
         are two thirds of that. Two thirds also settles the single-file \
         question the old floor argued separately: the largest file here is \
         `keystore/format.rs` at 4,873 identifiers, an eighth of the total, so \
         no walk that found one file can reach this floor. Re-derive both if \
         the tree grows; do not lower either to make a run pass.",
        per_file.len()
    );

    assert!(
        found.is_empty(),
        "native-endian conversions are forbidden by decision and these were \
         found:\n{}\n\
         \n\
         The decision was to NORMALIZE, not to reproduce the reference's host \
         dependence: `from_le_bytes`/`to_le_bytes`, everywhere, so the wallet \
         is byte-identical on every host rather than bug-compatible on the one \
         it was built on. Big-endian serialisation is retained only inside \
         `addr_to_bytes`, where the reference put it explicitly.\n\
         \n\
         Read `backend::native::put16`'s doc before changing this. In particular: a differential \
         against the FFI CANNOT catch a native-endian conversion, because on a \
         little-endian host the two produce identical bytes. This scan is the \
         only mechanism that can.",
        found.join("\n")
    );

    println!(
        "  endianness scan: {} files, {examined} identifiers \
         compared against {} forbidden name(s), 0 native-endian conversions",
        per_file.len(),
        FORBIDDEN.len()
    );
}

/// Every construct in `crates/*/src` that can end execution (panic-family
/// macros, `.unwrap()`/`.expect()`, `handle_alloc_error`), declared with the
/// reason it stays, so the panic surface cannot grow silently.
///
/// Each row is `(file, construct, count, reason)`. The four seam `assert!`s
/// fire in release too. A construct found but not declared fails naming the
/// site; a declared row the walk cannot find fails naming the row, so a
/// broken walk reports every row missing rather than passing.
const DECLARED_PANIC_SITES: &[(&str, &str, usize, &str)] = &[
    (
        "crates/mochimo-crypto/src/keystore/directory.rs",
        ".unwrap()",
        9,
        "inside the test-only parent-directory durability regression: setup, \
         descriptor inspection, flush and cleanup failures must fail the test. \
         The production directory operations return errors.",
    ),
    (
        "crates/mochimo-crypto/src/keystore/directory.rs",
        "assert_eq!",
        2,
        "inside the same test-only module: compare the held parent's device \
         and inode to the actual parent of the store, and check a parent \
         flush is refused on a handle opened without a parent.",
    ),
    (
        "crates/mochimo-crypto/src/keystore/directory.rs",
        "assert!",
        1,
        "inside the same test-only module: an existing-store open retains \
         no parent handle, so it needs no read permission on the parent.",
    ),
    (
        "crates/mochimo-crypto/src/backend/native.rs",
        "assert!",
        3,
        "ull_to_bytes's empty-out guard and base_w's geometry guard: contract \
         guards on the caller's own buffer geometry -- no path from network or \
         disk bytes chooses these lengths, so a failure here is a caller \
         defect and never an input, and a Result would put a branch at every \
         call site for a condition no input can reach. The \
         third is the `const _` width assertion over the chunked chain loops: \
         const-evaluated, so it fails a build and can never fail a run. It is \
         counted here rather than parsed around, because a construct the \
         census cannot see is one nobody is told about.",
    ),
    (
        "crates/mochimo-crypto/src/backend/native.rs",
        "assert_eq!",
        1,
        "expand_seed_into's out.len() == PK_LEN, a private helper whose three \
         callers all pass constant-sized buffers; it fires only on constant \
         drift.",
    ),
    (
        "crates/mochimo-crypto/src/error.rs",
        "unimplemented!",
        3,
        "the three diagnostic-string functions (ve2str, errno_name, \
         errno_text), knowledge not debt -- see DECLARED_UNIMPLEMENTED. \
         Counted by unimplemented_sites_are_declared_with_a_reason \
         too; this census sees the same three through a different instrument.",
    ),
    (
        "crates/mochimo-crypto/src/secret.rs",
        "assert!",
        1,
        "inside the #[cfg(test)] unit-test module. Test-only; kept in the \
         census rather than parsed around, because a skip is a blind spot and \
         a row is visible.",
    ),
    (
        "crates/mochimo-crypto/src/secret.rs",
        "assert_eq!",
        1,
        "same #[cfg(test)] module.",
    ),
    (
        "crates/mochimo-crypto/src/account.rs",
        ".expect()",
        4,
        "inside the #[cfg(test)] unit-test module: unwrapping \
         `Account::import` on `F-address-widths`' recorded pair, which the \
         constructor verifies, and `restore_from_record` on records this \
         module just built. Test-only; kept in the census rather than parsed \
         around, same reasoning as secret.rs's rows. The account module's \
         NON-test code still contains no panicking construct at all -- \
         `import` and `restore_from_record` return Result rather than \
         asserting the pair, which is the whole shape of format v2.",
    ),
    (
        "crates/mochimo-crypto/src/account.rs",
        "assert!",
        3,
        "inside the #[cfg(test)] unit-test module (the Debug-redaction \
         negative-containment checks, and format v2's control that an untouched \
         imported record still restores). Test-only; kept in the census \
         rather than parsed around, same reasoning as secret.rs's rows.",
    ),
    (
        "crates/mochimo-crypto/src/account.rs",
        "assert_eq!",
        36,
        "same #[cfg(test)] module: pinned Debug renderings, advance \
         monotonicity, receipt binding, the in-module record round-trip, \
          the ten edge assertions of the shipped-index mapping, and \
          the import verification's two refusals, the aliasing case's \
         stream equality and the restore refusals; plus the two of the \
         ceiling test: the whole Range the refusal at \
         u32::MAX carries, and the position below it advancing to it.",
    ),
    (
        "crates/mochimo-crypto/src/account.rs",
        "assert_ne!",
        1,
        "same #[cfg(test)] module: a first address built from junk \
         components yields a DIFFERENT tag over the same key stream -- the \
         one assertion that says why a verifying import does not close the \
         aliasing.",
    ),
    (
        "crates/mochimo-crypto/src/account.rs",
        "panic!",
        3,
        "same #[cfg(test)] module: the two wrong-variant arms of the \
         round-trip test, where the test must fail loudly if a restored \
         account comes back as the other kind; and the ceiling test's \
         `unwrap_or_else(|e| panic!(..))` on the advance that must succeed.",
    ),
    (
        "crates/mochimo-crypto/src/account.rs",
        "unreachable!",
        2,
        "same #[cfg(test)] module: the derived arms of two matches on \
         a record this module built as imported three lines above. Not a \
         wildcard -- the match is exhaustive and the arm states that the \
         other kind cannot occur here, which is the same reason the module \
         doc gives for refusing `#[non_exhaustive]`.",
    ),
    (
        "crates/mochimo-crypto/src/keystore/mod.rs",
        "assert_eq!",
        3,
        "inside the #[cfg(test)] unit-test module: the \
         premise generation, the generation a fresh open reads after the \
         failed application, and the position it reads.",
    ),
    (
        "crates/mochimo-crypto/src/keystore/mod.rs",
        "assert!",
        2,
        "same #[cfg(test)] module: the application's refusal is the Range \
         `advance_to` gives, and the handle's next call is Poisoned -- the \
         assertion the item exists for.",
    ),
    (
        "crates/mochimo-crypto/src/cli/args.rs",
        "assert!",
        48,
        "inside the #[cfg(test)] parser tests: the help \
         spellings recognised before the verb, and refused by name after it; \
         the repeated-flag test's control, each flag once parsing; the \
         `--ref` test's four: a refusal names the flag \
         and the value, carries the rule's words, a seventeenth character and \
         a non-ASCII value are refused by their own reasons; nine \
         over the destination list -- the odd-token and duplicate refusals \
         and their words, the 257th destination, `--ref` and `all` each \
         refused with several, `all` parsing as an unknown amount, and the \
         file parser's four refusals by line. Six over the explorer verbs: \
         the count flag's default, its ceiling and its two refusals carrying the \
         endpoint's own reason; `block 0` refused as the tip's index; and a short \
         hash refused. Four over `discover`'s `--to`: the refusal named \
         across three bad values, and the flag held to the parser's own \
         rules -- given twice, given without a value, and a positional \
         argument where the flag belongs. Its fifth asserted ONE reason for \
         both ends of that range, which is exactly the defect a live run \
         found, and it is eight now: four per arm, \
         being the bounds with the value echoed, that arm's own reason, the \
         sentence saying what to do about it or what already answers it, and \
         the ABSENCE of the other arm's reason -- the assertion the defect \
         needed and the one that was not being made. Five more over the \
         plaintext-node gate: the seven spellings it lets through, and per \
         refused spelling the flag named, the decisions the link carries, the \
         balance a spend is laid out against, and the flag clearing it. \
         Five over `recent-transactions`' `--from`: per value above the \
         Mesh's int64, the bounds with the value echoed and the endpoint's \
         own reason; `--count`'s window holding beside it; the flag given \
         twice; and `blocks` refusing it. Two over `reconcile`'s direction: \
         `--rollback-to` and `--advance-to` each parsed to their own \
         `Command`.",
    ),
    (
        "crates/mochimo-crypto/src/cli/args.rs",
        "assert_eq!",
        37,
        "same #[cfg(test)] module: the repeated-flag refusal, named flag by \
         flag; `address --account N`'s parsed shape and its missing-value \
         refusal; the `--ref` test's two: the \
         node's examples laid out NUL-padded, and the zero field without the \
         flag; and fifteen over the destination list -- three pairs \
         parsed in order with their amounts and tags, the fee defaulting to \
         the floor for three and to 500 for one, the single-destination \
         shape `all` parses to, and the file's three columns line by line. Six more: the two default counts, the ceiling \
         taken, `block 1` and the two hash spellings parsed. Three over \
         `discover`'s default `--to`, its ceiling and its floor, each parsed \
         to the `Command` it should be. Six over `--from`: its default, a \
         value, the two orders beside `--count`, the ceiling taken, and the \
         ceiling's value written out. Two over `reconcile`: both directions \
         refused together, and neither given.",
    ),
    (
        "crates/mochimo-crypto/src/cli/args.rs",
        "panic!",
        24,
        "same #[cfg(test)] module: `refusal`'s arm for argv that parsed when \
         the case expected a refusal; the `--ref` test's four, the \
         arms for a value that parsed to another command, was refused, or \
         read as help when the case expected a spend; and three more -- \
         `sent`'s two arms, for argv that parsed to another command or did \
         not parse at all, and the file parser's arm for text that was \
         expected to parse. Nine over the explorer parser tests: the arms for \
         argv that parsed to another command or did not parse at all. Three \
         more over `discover`'s \
         default, ceiling and floor. Two over `--from`: the arms for argv \
         that parsed to another command or did not parse at all. Two over \
         `reconcile`'s direction: the arms for argv that did not parse to \
         the direction it names.",
    ),
    (
        "crates/mochimo-crypto/src/keystore/mod.rs",
        "panic!",
        7,
        "same #[cfg(test)] module: `unwrap_or_else(|e| panic!(..))` on the \
         steps that must succeed around the one that must fail -- create, \
         add, the generation reads, the reopen and the view.",
    ),
    (
        "crates/mochimo-crypto/src/keystore/medium.rs",
        "assert_eq!",
        6,
        "inside the #[cfg(test)] unit-test module: `parent_of`'s six shapes -- a \
         bare name, the same with the slash shell completion adds, `./name`, a \
         relative and an absolute path with a parent, and the root. Test-only; the \
         medium's non-test code contains no panicking construct, and every failure \
         of its primitives is an `Error::Io` naming the step.",
    ),
    (
        "crates/mochimo-crypto/src/keystore/format.rs",
        ".expect()",
        40,
        "inside the #[cfg(test)] KAT module: unwrapping encode/parse on the \
         known-good image, and `Account::import` on the fixture pair the KAT \
         builds its imported record from. Encryption at rest added ten, all in the \
         encryption tests: deriving the module's cached test key, sealing and \
         opening in the KAT and the RFC 8439 replay, the Argon2 parameter \
         arms, and `reseal`'s four -- which decrypts, edits the plaintext and \
         seals it again, because reaching a canonicality check now means \
         producing a file a legitimate writer could have produced. The anchors added fourteen, all in the anchor and provenance tests: the RFC 9106 replay's one, the bridge test's two, and eleven in `published_vector_literals_match_the_vendored_rfc_text` and its helpers -- two `from_utf8` on the vendored texts, and unwraps behind counts the same function has just asserted (`rfc_section`, `hex_run_between`, `hex_run_to_end`, the tag line). The encoder refusal added three: the image-cap test's `image_len(MAX_ACCOUNTS + 1)` (one record past the cap does not overflow), and the encode-refusal test's parse of a consistent reservation and its slot lookup. Format version 4 added nine, net: `captured_key`'s one (the KDF over the version-3 reservation capture's header, at CHEAP_FOR_TESTS -- hours under Miri otherwise); three in the dispatch test's new arms (the v3 capture's header and its parse, the v4-image-under-a-forged-3 open); `reseal`'s four moved into `reseal_with` (which takes the key, so the v3 capture can be re-sealed too) and `reseal` became a call to it, -3 +3; four in the encode-refusal test's new round trips (a reservation with figures, the migrated shape, a settled block); and one in the both-blocks refusal test's account derivation. Test-only; kept in the census rather than parsed \
         around. The format's non-test code contains no panicking construct \
         -- every read goes through a bounded cursor and every failure is a \
         Result, and that is unchanged by the AEAD: `crypt`'s \
         two entry points return `Result` and its one unreachable arm is a \
         zero rather than a panic.",
    ),
    (
        "crates/mochimo-crypto/src/keystore/format.rs",
        "assert!",
        32,
        "same #[cfg(test)] KAT module: the malformation rows (each prefix \
         truncation and the variant-specific refusals), which format v2 grew by \
         the derived first-key padding, the two imported-record \
         reproductions, the kind domain, the pending-flag domain and the \
         v1 file's third arm. Encryption at rest moved this DOWN by one \
         and the direction is the point: the malformation table's rows that \
         mutated an image and recomputed a hash became `assert_eq!` rows \
         against one `WrongPassword`, because the AEAD gives every \
         unauthenticated change the same answer. What is left is the AAD-tamper \
         refusal, the m_cost cap and the canonicality rows that re-seal. The anchors added seven, all in `published_vector_literals_match_the_vendored_rfc_text` and its `hex_tokens` helper: the version and parameter-line needles, the README's copy of each hash, the RFC 8439 hexdump rows, the two-hex-digit token guard and its non-empty floor, and the tag-line token guard. The encoder refusal added four: the image-cap test's one-record-more arm and its two gate probes (a zeroed buffer of exactly `MAX_IMAGE_LEN` bytes passes the length gate to the magic check; one byte more is `Range` naming both bounds), and the encode-refusal test's loop over four inconsistent reservations. Format version 4 added nine: the malformation table's seven new rows -- the state byte's domain (`bad_state`), the relation in the settled state (`settled_relation`), the figures byte's domain (`bad_figures`), the two `figures == 0 => zeros` rows (a dirty balance, a dirty block-to-live), the state-0 zero rule over the figures flag (`figures_without_block`) and the version-3 arm refusing state 2 on the real capture (`v3_state_2`) -- the dispatch test's forged-word arm over the v4 image (`WrongPassword`, because the version word is inside the AAD), and the both-blocks refusal test's `matches!` on the variant.",
    ),
    (
        "crates/mochimo-crypto/src/keystore/format.rs",
        "assert_eq!",
        67,
        "same #[cfg(test)] KAT module: the hand-assembled image against \
         encode, the parsed fields against the literals, and the \
         image length against the closed formula plus the captured v1 \
         file's shape and its two version-dispatch verdicts. Encryption at rest added \
         eight: the hand-assembled v3 header, the plaintext body through a \
         decryption, RFC 8439's ciphertext and tag, the KDF's determinism \
         arm, the version-2 upgrade verdict, and the malformation table's \
         five-into-one collapse onto `WrongPassword`. The 28th is \
         `the_nonce_does_not_repeat_across_a_forked_store`'s closing arm, \
         asserting `nonce_for` is a function at all -- without it the two \
         inequalities above it are satisfied by a nonce that simply varies, \
         and nothing repeatable was shown. The anchors added eighteen: the RFC 9106 tag through `crypt::argon2id_v13`, the bridge's agreement, and sixteen in the provenance test and its helpers -- two file hashes, two column-zero heading counts, three label-uniqueness counts, the one-vector and one-tag floors, five RFC 9106 byte runs, the RFC 8439 tag count and its parsed tag. The encoder refusal added four: `image_len(MAX_ACCOUNTS) == MAX_IMAGE_LEN` -- the arm the image-cap defect fails, and the reason the test exists -- and `image_len(0) == MIN_IMAGE_LEN`; and the encode-refusal test's round trip of a consistent reservation, `wots_index` and `pending` each read back. The version refusal added one: the captured version-2 file's verdict -- `UnsupportedVersion` naming its first account -- beside the forged-word arm that names none. Format version 4 added fifteen: nine in the dispatch test -- `read_header` on the v3 pin (version 3, `Kdf::RECOMMENDED`) and the reserved capture read through the public parser (its generation, one derived slot, index 1, the open reservation with `figures: None`, no settled block) -- five in the encode-refusal test's round trips (the figures read back, the migrated shape's `None`, the settled block and both index fields), and one in the both-blocks test (each half alone seals and reads back as itself). The SDK record kind added one: the round-trip test's count of SDK records, which the two-account image must hold none of.",
    ),
    (
        "crates/mochimo-crypto/src/keystore/format.rs",
        "assert_ne!",
        6,
        "Same #[cfg(test)] module, and every one is a NEGATIVE control \
         rather than an assertion about a value: the ciphertext is not the \
         plaintext (which is what would catch an encoder that forgot to call \
         the AEAD at all), and the KDF's three arms showing that the \
         password, the salt and the parameters each change the key. A test \
         that only asserted equalities would be satisfied by a KDF that \
         ignored its inputs. The last two are \
         `the_nonce_does_not_repeat_across_a_forked_store`'s, and they are \
         the reason that test exists rather than decoration: a fault-injection \
         row found that `expected_header` computed the KAT's nonce with \
         `crypt::nonce_for` -- the same function the encoder calls -- so a \
         bare generation counter substituted for the hash left the KAT green. \
         The literal `KAT_NONCE` closed that, and these two arms are what now \
         holds `nonce_for` itself: a nonce differing across two opens of a \
         forked store at ONE generation, and differing across generations \
         within one open. The first is the keystream-reuse hazard the AEAD \
         introduced and is exactly what a counter breaks. Test-only, and \
         negative by construction; the format's non-test code still contains \
         no panicking construct, and the v2-to-v3 migration refusal is NOT \
         among these -- it is `Error::UnsupportedVersion` returned from \
         `read_header`, a Result and not a panic, because a v2 store carries \
         no master seed and an upgrade would produce a v3 file that opens and \
         then refuses every command needing one.",
    ),
    (
        "crates/mochimo-crypto/src/keystore/format.rs",
        "panic!",
        2,
        "The first `panic!` in this file and both inside the #[cfg(test)] \
         module: `encode_refuses_both_an_open_and_a_settled_block_in_one_record`'s control, \
         which seals each half of the refused pair alone and names the half in its message \
         (`unwrap_or_else(|e| panic!(..))`, the harness's idiom, so a failing control says \
         which half rather than `called Result::unwrap()`). The format's non-test code still \
         contains no panicking construct; the both-blocks refusal itself is `Error::Corrupt` \
         returned from `encode`.",
    ),
    (
        "crates/mochimo-crypto/src/derive.rs",
        "assert!",
        8,
        "inside the #[cfg(test)] unit-test module: the Debug-redaction \
         negative-containment checks for the four secret holders. Test-only; \
         kept in the census rather than parsed around, same reasoning as \
         secret.rs's rows. The derivation's non-test code contains no \
         panicking construct; its two implicit panic classes -- constant slice \
         indexing and copy_from_slice over fixed-width buffers -- are declared \
         at the module head.",
    ),
    (
        "crates/mochimo-crypto/src/derive.rs",
        "assert_eq!",
        3,
        "same #[cfg(test)] module: the pinned generator Debug rendering and \
         the zero-length fill's state count.",
    ),
    (
        "crates/mochimo-crypto/src/mnemonic/mod.rs",
        "assert!",
        8,
        "inside the #[cfg(test)] unit-test module: wordlist order, the \
         Phrase redaction, and the six refusal-by-variant matches (entropy \
         width, word count, unknown word, checksum, non-ASCII phrase, \
         non-ASCII passphrase). Test-only; the module's non-test code \
         returns Result everywhere. Counted two ways (a script over the \
         file and this census) before the row was written.",
    ),
    (
        "crates/mochimo-crypto/src/mnemonic/mod.rs",
        "assert_eq!",
        4,
        "same #[cfg(test)] module: the wordlist length, the pinned Phrase \
         rendering, the seed being a pure function of (phrase, passphrase), \
         and one rendered refusal message.",
    ),
    (
        "crates/mochimo-crypto/src/mnemonic/mod.rs",
        "assert_ne!",
        1,
        "same #[cfg(test)] module: a non-empty passphrase changes the seed \
         -- the one place the parameter is shown to reach the salt.",
    ),
    (
        "crates/mochimo-crypto/src/mnemonic/mod.rs",
        "panic!",
        7,
        "same #[cfg(test)] module: unwrapping known-good phrases and seeds \
         in the three tests that need them, loudly rather than through \
         .unwrap().",
    ),
    (
        "crates/mochimo-crypto/src/cli/create.rs",
        "assert!",
        3,
        "inside the #[cfg(test)] unit-test module: the phrase notice starts \
         and ends with its fixed text and holds the phrase between them. \
         Test-only.",
    ),
    (
        "crates/mochimo-crypto/src/cli/create.rs",
        "assert_eq!",
        1,
        "same #[cfg(test)] module: the phrase notice's capacity equals its \
         length, so it was built in one allocation.",
    ),
    (
        "crates/mochimo-crypto/src/extension_export.rs",
        "assert!",
        1,
        "inside the #[cfg(test)] unit-test module: a seed that is not a \
         string is not taken. Test-only.",
    ),
    (
        "crates/mochimo-crypto/src/extension_export.rs",
        "assert_eq!",
        3,
        "same #[cfg(test)] module: the taken seed's text, that it is the \
         parsed string's own allocation, and the empty string left behind.",
    ),
];

/// The walk behind [`DECLARED_PANIC_SITES`]: every ident-followed-by-`!`
/// whose name is a panic-family macro, every `.unwrap()`/`.expect(..)`
/// method call, and every appearance of `handle_alloc_error`, over the token
/// stream of each file in `crates/*/src`.
///
/// * `crates/*/src` only: a panic in a test is the test failing.
/// * Tokens, not text, so a literal or comment spelling `unwrap` is not
///   counted.
/// * Slice indexing and overflowing arithmetic are not counted, since every
///   `[i]` and `+` would enrol. Load-bearing sites (`wots_checksum`'s
///   wrapping accumulator, the consts-derived ranges) are documented where
///   they stand.
#[test]
fn panicking_constructs_are_declared_at_their_sites() {
    const MACROS: [&str; 10] = [
        "panic",
        "unreachable",
        "todo",
        "unimplemented",
        "assert",
        "assert_eq",
        "assert_ne",
        "debug_assert",
        "debug_assert_eq",
        "debug_assert_ne",
    ];
    const METHODS: [&str; 2] = ["unwrap", "expect"];

    // (file, construct) -> lines found at. Lookahead over a flattened
    // Vec<TokenTree> per group, recursing into groups, so `assert !` and
    // `.unwrap ()` match as shapes, not spellings.
    fn walk(
        trees: &[proc_macro2::TokenTree],
        file: &str,
        hits: &mut Vec<(String, String, usize)>,
        examined: &mut usize,
    ) {
        use proc_macro2::TokenTree as T;
        for (i, tree) in trees.iter().enumerate() {
            *examined += 1;
            match tree {
                T::Ident(id) => {
                    let name = id.to_string();
                    let line = id.span().start().line;
                    let next_is = |what: char| {
                        matches!(trees.get(i + 1), Some(T::Punct(p)) if p.as_char() == what)
                    };
                    if MACROS.contains(&name.as_str()) && next_is('!') {
                        hits.push((file.to_string(), format!("{name}!"), line));
                    }
                    if name == "handle_alloc_error" {
                        hits.push((file.to_string(), name.clone(), line));
                    }
                    // `.unwrap()` / `.expect(..)`: a dot before, parens after.
                    if METHODS.contains(&name.as_str()) {
                        let dot_before = i > 0
                            && matches!(&trees[i - 1], T::Punct(p) if p.as_char() == '.');
                        let parens_after = matches!(
                            trees.get(i + 1),
                            Some(T::Group(g))
                                if g.delimiter() == proc_macro2::Delimiter::Parenthesis
                        );
                        if dot_before && parens_after {
                            hits.push((file.to_string(), format!(".{name}()"), line));
                        }
                    }
                }
                T::Group(g) => {
                    let inner: Vec<proc_macro2::TokenTree> = g.stream().into_iter().collect();
                    walk(&inner, file, hits, examined);
                }
                _ => {}
            }
        }
    }

    let mut hits: Vec<(String, String, usize)> = Vec::new();
    let mut examined = 0usize;
    let mut files = 0usize;
    for (name, text) in crate_source_files() {
        // Fail closed: a file that will not lex must not shrink the domain.
        let stream: proc_macro2::TokenStream = text.parse().unwrap_or_else(|e| {
            panic!(
                "{name} did not lex as Rust ({e}). This census is the sole \
                 mechanism keeping the panic surface enumerated, so a file it \
                 cannot read is not skipped."
            )
        });
        let trees: Vec<proc_macro2::TokenTree> = stream.into_iter().collect();
        walk(&trees, &name, &mut hits, &mut examined);
        files += 1;
    }

    assert!(
        files >= 25 && examined >= 77_200,
        "the walk saw {files} file(s) and {examined} token(s); both are far \
         below the tree's real size, so this is the walk failing, not the \
         crate being clean. This tree measures 115,827 tokens across 38 files \
         and both floors are two thirds of that. The file floor matches the \
         endianness scan's because the corpus is the same 38 files; the other \
         one cannot, because that scan counts identifiers and this one counts \
         every token."
    );
    assert!(
        !DECLARED_PANIC_SITES.is_empty(),
        "the declared table is empty; the crate is not panic-free (error.rs \
         carries three declared unimplemented! sites at minimum), so an empty \
         table means the table was emptied, not that the surface closed."
    );

    // Aggregate to (file, construct) -> count and compare in both directions.
    let mut counted: std::collections::BTreeMap<(String, String), Vec<usize>> =
        std::collections::BTreeMap::new();
    for (file, construct, line) in hits {
        counted.entry((file, construct)).or_default().push(line);
    }

    let mut problems: Vec<String> = Vec::new();
    for ((file, construct), lines) in &counted {
        match DECLARED_PANIC_SITES
            .iter()
            .find(|(f, c, _, _)| f == file && c == construct)
        {
            None => problems.push(format!(
                "\x20 - {file} uses {construct} at line(s) {lines:?} and no row \
                 declares it. Either remove it or add a row stating why it \
                 stays -- a panic on input the crate did not choose is a \
                 denial of service in a wallet."
            )),
            Some((_, _, count, _)) if *count != lines.len() => problems.push(format!(
                "\x20 - {file}: {construct} declared {count} time(s), found {} \
                 (line(s) {lines:?}). The census and the table must move \
                 together.",
                lines.len()
            )),
            Some(_) => {}
        }
    }
    for (file, construct, count, _) in DECLARED_PANIC_SITES {
        if !counted.contains_key(&((*file).to_string(), (*construct).to_string())) {
            problems.push(format!(
                "\x20 - the table declares {count} x {construct} in {file} and \
                 the walk found none. If the construct was removed, remove the \
                 row with it; if the walk broke, every row goes missing at \
                 once, which is what you are looking at."
            ));
        }
    }

    assert!(
        problems.is_empty(),
        "the panic-surface census disagrees with DECLARED_PANIC_SITES \
         :\n{}",
        problems.join("\n")
    );

    let total: usize = DECLARED_PANIC_SITES.iter().map(|(_, _, c, _)| c).sum();
    println!(
        "  panic-surface census: {files} files, {examined} tokens, \
         {total} declared construct(s) across {} row(s), 0 undeclared",
        DECLARED_PANIC_SITES.len()
    );
}

/// No `unsafe` anywhere under `src/`, in particular not in
/// `backend/native.rs`.
///
/// The allow-list is empty, so any `unsafe` keyword under `src/` fails naming
/// the file. A file floor keeps an empty walk from passing. An `unsafe` block
/// in `native.rs` would change what "native is clean under Miri" means
/// rather than widen what Miri checks; the failure message says so.
///
/// Token walk, not text search, so `unsafe` in a SAFETY comment or doc string
/// does not count.
#[test]
fn unsafe_is_confined_to_declared_files() {
    // Empty. A row added here must state which boundary needs `unsafe` and
    // why Miri cannot walk it.
    const ALLOWED: [(&str, &str); 0] = [];

    fn count_unsafe(stream: proc_macro2::TokenStream, lines: &mut Vec<usize>) {
        for tree in stream {
            match tree {
                proc_macro2::TokenTree::Ident(id) => {
                    if id == "unsafe" {
                        lines.push(id.span().start().line);
                    }
                }
                proc_macro2::TokenTree::Group(g) => count_unsafe(g.stream(), lines),
                _ => {}
            }
        }
    }

    let mut problems: Vec<String> = Vec::new();
    let mut per_allowed: Vec<(String, usize)> = Vec::new();
    let mut files = 0usize;
    for (name, text) in crate_source_files() {
        let stream: proc_macro2::TokenStream = text.parse().unwrap_or_else(|e| {
            panic!(
                "{name} did not lex as Rust ({e}). This walk is the sole \
                 enforcement of where unsafe may live, so an unreadable file \
                 is not skipped."
            )
        });
        let mut lines = Vec::new();
        count_unsafe(stream, &mut lines);
        files += 1;

        match ALLOWED.iter().find(|(f, _)| *f == name) {
            Some(_) => per_allowed.push((name, lines.len())),
            None if lines.is_empty() => {}
            None => {
                let miri_note = if name.ends_with("backend/native.rs") {
                    "\n    This file is what the Miri run interprets, and its \
                     having NO unsafe is part of what that run's green means: \
                     `memory_safety_is_established_only_for_the_native_paths_miri_walks` \
                     claims safe code checked by an interpreter, not unsafe \
                     code vouched for by its author. Do not move the boundary \
                     by adding a row here; whatever needs unsafe belongs on \
                     the ffi side of the seam."
                } else {
                    ""
                };
                problems.push(format!(
                    "\x20 - {name} contains `unsafe` at line(s) {lines:?} and \
                     is not on the allow-list.{miri_note}"
                ));
            }
        }
    }

    // The other direction: an allow-listed file with zero occurrences is a
    // stale permission.
    for (file, why) in ALLOWED {
        match per_allowed.iter().find(|(f, _)| f == file) {
            None => problems.push(format!(
                "\x20 - allow-listed file {file} was not walked at all; the \
                 corpus shrank under this check"
            )),
            Some((_, 0)) => problems.push(format!(
                "\x20 - {file} is allow-listed for {why} but contains no \
                 `unsafe` any more. Remove its row; an unused permission is a \
                 hole waiting for an occupant."
            )),
            Some(_) => {}
        }
    }

    assert!(
        files >= 10,
        "the walk saw {files} file(s), far below the tree's real size"
    );
    assert!(
        problems.is_empty(),
        "`unsafe` has moved relative to the declared boundary:\n{}",
        problems.join("\n")
    );

    println!(
        "  unsafe confinement: {files} files walked, {} allow-listed file(s), \
         0 `unsafe` keywords outside the allow-list",
        per_allowed.len()
    );
}

/// Every `pub fn sha3*` takes one `&[u8]` and returns a fixed-size array, so
/// no caller-controlled `outlen` is expressible on the SHA3 surface.
///
/// The reference's `sha3_init` computes `rsiz = 200 - 2*outlen` with no range
/// check, and from `outlen == 100` the final-block write is out of bounds.
/// Here the width is part of the type (four fixed-width functions over one
/// private funnel; see `addr.rs`). This check keeps the shape closed:
/// `syn` over the two files with a sha3-named public surface requires every
/// `pub fn` whose name starts with `sha3` to have exactly one parameter, of
/// type `&[u8]`, and an array return type. A caller-chosen width would need
/// a parameter or an out-buffer.
#[test]
fn sha3_width_is_a_type_not_a_parameter() {
    // The property is about the surface a caller can reach.
    const FILES: [&str; 2] = [
        "crates/mochimo-crypto/src/backend/native.rs",
        "crates/mochimo-crypto/src/addr.rs",
    ];

    let mut problems: Vec<String> = Vec::new();
    let mut found = 0usize;
    for rel in FILES {
        let text = read_crate_file(rel);
        let ast = syn::parse_file(&text)
            .unwrap_or_else(|e| panic!("{rel} did not parse as Rust: {e}"));
        let mut here = 0usize;
        for item in &ast.items {
            let syn::Item::Fn(f) = item else { continue };
            if !matches!(f.vis, syn::Visibility::Public(_)) {
                continue;
            }
            let name = f.sig.ident.to_string();
            if !name.starts_with("sha3") {
                continue;
            }
            here += 1;

            if f.sig.inputs.len() != 1 {
                problems.push(format!(
                    "\x20 - {rel}::{name} takes {} parameters. One `&[u8]` is \
                     the whole legal surface; a second parameter is where a \
                     runtime width would live.",
                    f.sig.inputs.len()
                ));
            }
            for arg in &f.sig.inputs {
                let syn::FnArg::Typed(pt) = arg else { continue };
                match &*pt.ty {
                    syn::Type::Reference(r) if r.mutability.is_none() => {}
                    other => problems.push(format!(
                        "\x20 - {rel}::{name} takes `{}`, not an immutable \
                         reference. An out-buffer parameter is how the \
                         old signature let every caller name an outlen, \
                         including >= 100.",
                        quote::ToTokens::to_token_stream(other)
                    )),
                }
            }
            match &f.sig.output {
                syn::ReturnType::Type(_, ty) if matches!(**ty, syn::Type::Array(_)) => {}
                other => problems.push(format!(
                    "\x20 - {rel}::{name} returns `{}`, not a fixed-size \
                     array. The width being in the return TYPE is the \
                     mechanism; a Vec or a slice would put it back in a value.",
                    quote::ToTokens::to_token_stream(other)
                )),
            }
        }
        if here < 4 {
            problems.push(format!(
                "\x20 - {rel} declares {here} public sha3-named fn(s); the four \
                 widths of `sha3.h:44` are 224/256/384/512, so fewer than 4 \
                 means the surface shrank or the parse saw the wrong file."
            ));
        }
        found += here;
    }

    // Nothing here reaches the reference's streaming SHA3 API.
    assert!(
        found >= 8,
        "the shape arm examined {found} public sha3-named fn(s) across two \
         files; 8 is the floor (four widths x two files), so the walk or \
         the parse is broken"
    );
    assert!(
        problems.is_empty(),
        "a caller-controlled SHA3 width is expressible again:\n{}",
        problems.join("\n")
    );

    println!(
        "  sha3 width shape: {found} public sha3-named fn(s) checked across \
         {} files",
        FILES.len()
    );
}

/// Every `unimplemented!()` in the crate is declared, and says why.
///
/// An `unimplemented!()` is invisible in a green build, so the sites are
/// enumerated fail-closed, each either owed or excluded with a reason. A
/// count of the token `unimplemented!(` in comment-stripped source catches a
/// site in a module not listed.
#[test]
fn unimplemented_sites_are_declared_with_a_reason() {
    // The enumerated sites.
    let declared: &[(&str, &str, Owing)] = DECLARED_UNIMPLEMENTED;

    // Any `unimplemented!()` in an undeclared module moves this count.
    let mut tokens = 0usize;
    let mut files = 0usize;
    for (name, text) in crate_sources() {
        if !name.starts_with("crates/mochimo-crypto/src/") {
            continue;
        }
        files += 1;
        tokens += code_only(&text).matches("unimplemented!(").count();
    }
    assert!(
        files >= 10,
        "walked only {files} files under crates/mochimo-crypto/src/. The walk is \
         broken, and a token count over nothing is zero — which is also what a \
         crate with no stubs looks like."
    );
    assert_eq!(
        tokens,
        declared.len(),
        "counted {tokens} `unimplemented!(` tokens under \
         crates/mochimo-crypto/src/ but DECLARED_UNIMPLEMENTED has {} rows. An \
         undeclared stub is a hole in the native-only build that nothing \
         reports: the build is green, and the tests that would have caught it \
         are gated off with the C they needed.",
        declared.len()
    );
}

/// Whether a declared `unimplemented!()` is debt or a settled exclusion.
#[derive(PartialEq, Eq, Clone, Copy)]
enum Owing {
    /// Someone can state what turns it green, so it belongs in the tooling.
    Owed,
    /// Nobody can, so it is knowledge rather than debt.
    Excluded,
}

/// `(module, function, owing)` for every `unimplemented!()` in the crate,
/// grouped by module. The reasons are at the sites.
const DECLARED_UNIMPLEMENTED: &[(&str, &str, Owing)] = &[
    // The backend gap is empty.
    //
    // Excluded: these three return the reference's own diagnostic
    // spellings. A Rust restatement would compare our naming with itself, so
    // nothing could turn a native version green.
    ("error", "ve2str", Owing::Excluded),
    ("error", "errno_name", Owing::Excluded),
    ("error", "errno_text", Owing::Excluded),
];

/// Every `unimplemented!()` left in the crate is `Owing::Excluded`.
///
/// `crate::base58`, `crate::bytes` and `crate::addr` work natively, and the
/// `tx` accessors are ported into `backend::native`, each backed by a group D
/// or group E vector. The transaction path itself is checked by
/// `native_transaction_path_is_checked_on_layout_not_acceptance`. `TxEntry`
/// is `#[cfg]`-absent rather than stubbed: I7 forbids a `TXENTRY` ever being
/// a Rust value, so a stub constructor would construct what the invariant
/// forbids.
///
/// Some of `crate::bytes` and the transaction wrappers are unreachable in a
/// native-only build. That is intended: the configuration exists for Miri,
/// and `tests/miri.rs` drives `backend::native::*` directly.
#[test]
fn every_unimplemented_site_is_knowledge_not_debt() {
    let mut by_module: std::collections::BTreeMap<&str, Vec<&str>> =
        std::collections::BTreeMap::new();
    for (module, function, owing) in DECLARED_UNIMPLEMENTED {
        if *owing == Owing::Owed {
            by_module.entry(module).or_default().push(function);
        }
    }

    let owed: Vec<String> = by_module
        .iter()
        .map(|(module, fns)| format!("\x20 - {module}: {}", fns.join(", ")))
        .collect();
    let count: usize = by_module.values().map(Vec::len).sum();

    assert!(
        owed.is_empty(),
        "{count} public function(s) panic with `unimplemented!()` and are \
         declared OWED rather than excluded:\n{}\n\
         \n\
         This set was empty once the accessors were ported, so a non-empty one means a stub was added \
         or an existing one was reclassified. Neither is wrong on its face; \
         both are decisions. What is wrong is a stub that nobody classified, \
         which `unimplemented_sites_are_declared_with_a_reason` catches by \
         count.\n\
         \n\
         The seven `tx` accessors that used to be here are ported, and so \
         is the native transaction path (`tx::wire`, checked by \
         `native_transaction_path_is_checked_on_layout_not_acceptance`). \
         Neither was discharged by adding stubs here, and nothing else should \
         be either.\n\
         \n\
         error::ve2str, errno_name and errno_text panic in the C-free build and \
         are `Owing::Excluded`: no condition turns a Rust restatement of \
         upstream's own spellings green, so they are knowledge.",
        owed.join("\n")
    );
}

/// The native transaction path exists and is checked on layout, encoding and
/// the two offline validators, not on acceptance.
///
/// The proof, `txwire.rs::native_transaction_round_trip_needs_no_reference`,
/// must run and report: the native round trip over every accepted group D
/// wire image with every recorded fixture field asserted, in a binary gated
/// on `native` alone (it also runs under Miri).
///
/// The codec agrees with the C on layout and encoding (71 wire images: 67
/// byte-identical both ways and 4 rejections reproduced), and the corpus
/// carries the offline validators' verdicts (`mdst_val`, `tx_val__wots`).
/// `tx_val` needs an open ledger and was never run, so a transaction that
/// passes here can still be rejected by a node for a ledger reason, a
/// balance tally or a block-to-live range. `tx::wire`'s module doc states
/// the same limit.
#[test]
fn native_transaction_path_is_checked_on_layout_not_acceptance() {
    let mut owed: Vec<String> = Vec::new();

    // What remains is the codec's own round trip in the binary gated on
    // `native` alone.
    const C_FREE_PROOF: &str = "native_transaction_round_trip_needs_no_reference";
    if let Err(why) = census::check(
        "native_transaction_path_is_checked_on_layout_not_acceptance",
        C_FREE_PROOF,
    ) {
        owed.push(format!(
            "\x20 - {C_FREE_PROOF} stopped holding: it is the mechanism behind \
             the claim that the transaction path works in a build where the C \
             is absent, so without it that sentence is prose.\n\x20   {why}"
        ));
    }

    assert!(
        owed.is_empty(),
        "The native transaction path's arrangement came apart:\n{}\n\
         \n\
         WHAT THIS TEST HOLDS: tx::wire is the native construction path \
         (ordinary Rust types, serializer at the boundary), and \
         the proof test keeps the codec checked against group D -- 71 named \
         wire images, 67 byte-identical both ways and 4 rejections reproduced, \
         recorded fields asserted.\n\
         \n\
         WHAT A GREEN HERE DOES NOT SAY: tx_val needs an open ledger and never \
         ran, so nothing in the corpus is a transaction the C accepted end to \
         end. Checked on layout, encoding and two offline validators is not \
         known-to-work; the difference surfaces at testnet.\n\
         \n\
         This was no_native_transaction_path_exists until tx::wire cleared and \
         renamed it in the same commit.",
        owed.join("\n")
    );
}
/// A file under the repository root, read or panicking with its path.
fn read_crate_file(rel: &str) -> String {
    let p = repo_root().join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
}

/// The names of every bare-`pub` `fn` defined at item level, parsed from the
/// AST.
///
/// Definitions, not resolvable paths: a re-export would resolve a name the
/// file does not define. Parsed rather than prefix-matched, because
/// `strip_prefix("pub fn ")` misses `pub unsafe fn`, `pub const fn` and
/// `pub async fn`; [`syn::Signature`] carries the qualifiers as fields, so
/// every combination is covered by not looking at them.
///
/// `pub(crate)` is not collected, so the set means what its name says. A
/// `pub(crate) unsafe fn` in the backend is caught by
/// [`no_restricted_visibility_fn_in_the_backend`] instead; `tests/miri.rs`
/// cannot call it, so it cannot be in the Miri domain.
///
/// Item level only: a `fn` inside an `impl` is not collected. The backend
/// module declares no inline `mod` blocks.
fn public_fn_names(code: &str) -> Vec<String> {
    let ast = syn::parse_file(code).unwrap_or_else(|e| {
        panic!(
            "syn could not parse a backend module: {e}\n\
             This parser feeds the Miri domain and the ffi/native set \
             difference; a file it cannot read would silently contribute an \
             empty name set, which reads as \"nothing to declare\"."
        )
    });
    ast.items
        .iter()
        .filter_map(|item| match item {
            // `Visibility::Public` is bare `pub` only; `pub(crate)`,
            // `pub(super)` and `pub(in path)` are `Visibility::Restricted`.
            // The qualifiers live in `sig` and are not consulted.
            syn::Item::Fn(f) if matches!(f.vis, syn::Visibility::Public(_)) => {
                Some(f.sig.ident.to_string())
            }
            _ => None,
        })
        .collect()
}

/// No backend function hides behind a restricted visibility.
///
/// [`public_fn_names`] collects bare `pub` only, so a `pub(crate) unsafe fn`
/// in `backend/native.rs` would enter neither the Miri domain nor any other
/// set; this check names that case. The native backend currently has no
/// restricted-visibility functions, so the check has not fired; its
/// polarity was confirmed by injection.
#[test]
fn no_restricted_visibility_fn_in_the_backend() {
    let mut found: Vec<String> = Vec::new();
    let mut items = 0usize;
    // `backend/native.rs`, the one backend module.
    for file in ["backend/native.rs"] {
        let text = read_crate_file(&format!("crates/mochimo-crypto/src/{file}"));
        let ast = syn::parse_file(&text)
            .unwrap_or_else(|e| panic!("syn could not parse {file}: {e}"));
        for item in &ast.items {
            if let syn::Item::Fn(f) = item {
                items += 1;
                if let syn::Visibility::Restricted(r) = &f.vis {
                    use quote::ToTokens;
                    found.push(format!(
                        "\x20 - {file}::{} is `{} fn`",
                        f.sig.ident,
                        r.to_token_stream()
                    ));
                }
            }
        }
    }

    // Vacuity guard: an empty parse would satisfy the assertion below.
    assert!(
        items >= 30,
        "parsed only {items} item-level functions out of the native backend \
         module; this tree's `backend/native.rs` holds 45 and this floor is two \
         thirds of that. The walk is broken and any \
         result from it is vacuous"
    );

    assert!(
        found.is_empty(),
        "these backend functions have a restricted visibility:\n{}\n\
         `public_fn_names` collects bare `pub` only, so these enter neither the \
         Miri domain nor the ffi/native set difference -- deliberately, since \
         tests/miri.rs is an external crate and cannot call them. That makes \
         them invisible to both, which is fine for an ordinary helper and NOT \
         fine for anything doing pointer work. Decide which this is: make it \
         `pub` and give it a MIRI_DOMAIN row, make it private, or add it here \
         with an argument.",
        found.join("\n")
    );

    println!(
        "  backend visibility: {items} item-level fns in the native backend, \
         0 restricted. VACUOUSLY TRUE -- the tree has never contained one; \
         see this test's documentation."
    );
}

// -------------------------------------------------------------------------
// The test-source walk itself
// -------------------------------------------------------------------------

/// Every `.rs` under this crate's `tests/`, as `(path, text)`, sorted by path.
///
/// `test_sources()` is this joined. File boundaries are kept so damage can
/// be reported by location. Sorted because `read_dir` order is not stable
/// across filesystems, so an unsorted concatenation would give a different
/// corpus on each machine.
fn test_source_files() -> Vec<(String, String)> {
    let root = repo_root();
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut out = Vec::new();
    let mut stack = vec![dir];
    while let Some(d) = stack.pop() {
        let entries = std::fs::read_dir(&d)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", d.display()));
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                let text = std::fs::read_to_string(&p).unwrap_or_default();
                let name = p
                    .strip_prefix(&root)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .into_owned();
                out.push((name, text));
            }
        }
    }
    out.sort();
    out
}

/// `code_only` must not mistake a construct in its inputs for a comment.
///
/// A stripper that read a slash-star inside a string literal as a comment
/// opener once silently removed code across file boundaries, turning
/// unrelated checks red without emptying the corpus. Two properties are
/// asserted over every file `code_only` is given:
///
/// * Stripping distributes over concatenation: `code_only(a + b)` equals
///   `code_only(a) + code_only(b)`. An opener whose closer is in the next
///   file breaks this with no threshold needed.
/// * A second reader, [`raw_extent`], agrees with `code_only` about the
///   extent of every raw string.
///
/// It says the stripper does not damage its inputs, not that the checks
/// reading the stripped corpus are correct.
#[test]
fn code_only_understands_every_construct_its_inputs_contain() {
    // Both tokens are built from chars so this file does not contain them as
    // literals in the corpus it scans.
    let opener: String = ['/', '*'].iter().collect();
    let closer: String = ['*', '/'].iter().collect();
    let line_comment: String = ['/', '/'].iter().collect();

    // ---------------------------------------------------------------------
    // The domain, derived from the call sites: every `code_only` argument in
    // this file resolves to a file in one of these two sets.
    // ---------------------------------------------------------------------
    let root = repo_root();
    let mut inputs: Vec<(String, String)> = Vec::new();

    // 1. tests/**.rs -- the concatenated corpus. Kept as separate files here
    //    because the distributivity check below needs the boundaries.
    let corpus_files = test_source_files();

    // The input must be raw: measuring the stripper against its own output
    // could not fail. Doc-comment openers are the signal, since a raw
    // `tests/` corpus has many and a stripped one has none; a floor rather
    // than a single occurrence, because `///` can appear inside a string.
    let doc_openers: usize = corpus_files
        .iter()
        .map(|(_, t)| t.lines().filter(|l| l.trim_start().starts_with("///")).count())
        .sum();
    assert!(
        doc_openers >= 200,
        "the tests/ corpus reached this check with only {doc_openers} doc-comment \
         openers. It is supposed to arrive RAW -- `test_source_files()` must not \
         strip, because this is the check that measures the stripper, and a \
         stripper measured against its own output cannot fail. Something has \
         routed this walk through `code_only`."
    );

    inputs.extend(corpus_files.iter().cloned());

    // 2. crates/*/src/**.rs, raw; secret.rs is a member of this set.
    let mut stack = vec![root.join("crates")];
    let mut crate_src = 0usize;
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                // Only descend into a member's src/, never into target/.
                let name = p.file_name().unwrap_or_default().to_string_lossy().into_owned();
                if name == "target" || (d == root.join("crates") && name.starts_with('.')) {
                    continue;
                }
                if p.parent() == Some(root.join("crates").as_path()) {
                    stack.push(p.join("src"));
                } else {
                    stack.push(p);
                }
            } else if p.extension().is_some_and(|x| x == "rs") {
                let rel = p.strip_prefix(&root).unwrap_or(&p).to_string_lossy().into_owned();
                inputs.push((rel, std::fs::read_to_string(&p).unwrap_or_default()));
                crate_src += 1;
            }
        }
    }

    // Vacuity floors, one per set, so an empty walk says which.
    assert!(
        corpus_files.len() >= 5,
        "the tests/ walk found {} file(s); the distributivity check below needs \
         at least two files to have a boundary to cross",
        corpus_files.len()
    );
    assert!(
        crate_src >= 10,
        "the crates/*/src walk found {crate_src} .rs file(s); code_only is \
         called on this set from two sites and this test would be scanning \
         almost none of it"
    );

    // ---------------------------------------------------------------------
    // Property 1: code_only distributes over concatenation.
    // ---------------------------------------------------------------------
    let mut joined = String::new();
    let mut piecewise = String::new();
    for (_, text) in &corpus_files {
        joined.push_str(text);
        joined.push('\n');
        piecewise.push_str(&code_only(text));
        piecewise.push('\n');
    }
    let at_once = code_only(&joined);
    if at_once != piecewise {
        // Report where they diverge, not only that they do.
        let split = at_once
            .char_indices()
            .zip(piecewise.char_indices())
            .find(|((_, a), (_, b))| a != b)
            .map_or(at_once.len().min(piecewise.len()), |((i, _), _)| i);
        let mut which = String::from("<before the first file>");
        let mut acc = 0usize;
        for (name, text) in &corpus_files {
            let stripped = code_only(text).len() + 1;
            if split < acc + stripped {
                which = format!("{name} (+{} stripped chars in)", split - acc);
                break;
            }
            acc += stripped;
        }
        panic!(
            "code_only does not distribute over concatenation: stripping the \
             joined corpus gives {} chars, stripping each file and joining \
             gives {}. They first differ at {which}.\n\
             That difference is a comment opened in one file and closed in \
             another -- the corpus the slicing checks read is not the corpus \
             its files contain. Fix code_only, do not relax this.",
            at_once.len(),
            piecewise.len()
        );
    }

    // ---------------------------------------------------------------------
    // Property 2: a second reader agrees with code_only about the extent of
    // every raw string in the inputs.
    //
    // Whatever this reader takes a raw string's extent to be, that exact text
    // must survive stripping, so the check fires when a mis-parse deletes
    // code. A mis-parse that deletes nothing leaves the output unchanged. The
    // grammar itself is pinned by the constructed unit tests above.
    // ---------------------------------------------------------------------
    let mut findings: Vec<String> = Vec::new();
    let mut agree_raw = 0usize;
    for (name, text) in &inputs {
        let stripped = code_only(text);
        let b = text.as_bytes();
        let mut i = 0usize;
        while i < b.len() {
            // Comments and the constructs code_only handles: skip.
            if b[i..].starts_with(opener.as_bytes()) {
                match text[i + 2..].find(closer.as_str()) {
                    Some(rel) => i += 2 + rel + 2,
                    None => break,
                }
                continue;
            }
            if b[i..].starts_with(line_comment.as_bytes()) {
                match text[i..].find('\n') {
                    Some(rel) => i += rel,
                    None => break,
                }
                continue;
            }
            if b[i] == b'"' {
                let mut j = i + 1;
                while j < b.len() {
                    match b[j] {
                        b'\\' => j += 2,
                        b'"' => break,
                        _ => j += 1,
                    }
                }
                i = (j + 1).min(b.len());
                continue;
            }
            // A bare `'` is a lifetime, one token wide, with nothing inside
            // it to hide a comment.
            if let Some(end) = raw_extent(b, i) {
                let inner = &text[i..end.min(text.len())];
                if stripped.contains(inner) {
                    agree_raw += 1;
                } else {
                    let line = text[..i].matches('\n').count() + 1;
                    findings.push(format!(
                        "\x20 - {name}:{line} holds a raw string that code_only did not emit \
                         verbatim. The two readers disagree about where it ends, so either \
                         `raw_string_len` or this scan has the delimiter rule wrong -- and \
                         the bytes between the two answers were deleted from the corpus \
                         every check downstream reads."
                    ));
                }
                i = end.max(i + 1);
                continue;
            }
            if b[i] == b'\'' {
                if let Some(n) = char_literal_len(b, i) {
                    i += n;
                    continue;
                }
            }
            i += text[i..].chars().next().map_or(1, char::len_utf8);
        }
    }

    assert!(
        findings.is_empty(),
        "code_only is pointed at {} files, and {} raw string(s) in them are \
         parsed to a different extent than this reader gives them:\n{}\n\
         A disagreement about extent means bytes were deleted from the corpus \
         every downstream check reads. Do not add an exception here -- the \
         previous version of this hazard was handled by a comment saying it \
         was acceptable, and it was not.",
        inputs.len(),
        findings.len(),
        findings.join("\n")
    );

    // Reported, not only asserted: both properties are about internal
    // consistency, which a uniformly short corpus would also satisfy.
    println!(
        "  code_only: {} inputs, tests/ corpus {} chars stripped from {} raw",
        inputs.len(),
        at_once.len(),
        joined.len()
    );
    // The raw-string population, printed because zero and "the scan never
    // ran" look the same from a pass. Reported rather than asserted; the
    // constructed unit tests above are the enforcement.
    println!("  code_only: agreement checked on {agree_raw} raw string(s)");
}

/// Group RX is an oracle with no reference side, and must not be read as
/// either of the other two kinds.
///
/// `group_c_crosscheck.json` pairs the C's values with a second
/// implementation's; `group_f_derivation.json` has one implementation and no
/// second opinion. In group RX, the C reference's `ripemd160_final`
/// overflows a one-block stack buffer for every input length with
/// `len % 64 >= 56`, so there is no reference answer for those lengths. The
/// file records `@noble/hashes`, so RustCrypto's `ripemd` is checked against
/// an independent implementation of the published algorithm. This is
/// evidence about RIPEMD-160, not about anything Mochimo-specific.
#[test]
fn group_rx_is_an_oracle_with_no_reference_side() {
    let dir = repo_root().join("fixtures");
    let path = dir.join("group_rx_ripemd.json");
    let root: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!("{} is unreadable: {e}", path.display())
        }))
        .unwrap_or_else(|e| panic!("{} is not JSON: {e}", path.display()));

    let mut problems: Vec<String> = Vec::new();
    let oracle = root
        .get("oracle")
        .and_then(|v| v.as_object())
        .unwrap_or_else(|| panic!("group_rx_ripemd.json carries no oracle block"));

    let flag = |k: &str| oracle.get(k).and_then(serde_json::Value::as_bool);
    let text = |k: &str| {
        oracle
            .get(k)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string()
    };

    if oracle.get("class").and_then(serde_json::Value::as_str)
        != Some(EXECUTED_CROSSCHECK_NO_REFERENCE)
    {
        problems.push(format!(
            "\x20 - oracle.class is {:?}, not {EXECUTED_CROSSCHECK_NO_REFERENCE:?}. \
             group_f_is_specification_not_crosscheck routes this file here by \
             that exact string; a different one lands it in the \
             specification-capture arm, where every claim it makes is false.",
            oracle.get("class")
        ));
    }
    // The three flags. `reference_side_exists: false` separates this class
    // from `executed-crosscheck`.
    for (k, want) in [
        ("is_independent_oracle", true),
        ("second_implementation_exists", true),
        ("reference_side_exists", false),
    ] {
        if flag(k) != Some(want) {
            problems.push(format!(
                "\x20 - oracle.{k} is {:?}, not {want}",
                oracle.get(k)
            ));
        }
    }
    // The arguments behind the flags. `why_not_group_cx` is required, since
    // folding these vectors into CX is the tempting mistake.
    for (k, min) in [("why", 200usize), ("why_not_group_cx", 200), ("domain", 150)] {
        let n = text(k).len();
        if n < min {
            problems.push(format!(
                "\x20 - oracle.{k} is {n} chars, under {min}. The flags above are \
                 only as durable as the argument written beside them."
            ));
        }
    }
    // The fixture's `disclosure` and `errata` fields are read so the walk
    // stays fail-closed over the block's shape; nothing more is claimed.
    for k in ["disclosure", "errata"] {
        assert!(
            oracle.get(k).is_some(),
            "group_rx_ripemd.json's oracle block carries no `{k}`; the block's shape moved"
        );
    }

    // No reference side: nothing in the file may cite the C as having
    // produced a value, and `derived_from` must be null (a crosscheck derived
    // from a C fixture is CX).
    if root.get("derived_from") != Some(&serde_json::Value::Null) {
        problems.push(format!(
            "\x20 - derived_from is {:?}, not null. A group derived from a C \
             fixture has a reference side by construction.",
            root.get("derived_from")
        ));
    }

    let vectors = root
        .get("vectors")
        .and_then(|v| v.as_array())
        .unwrap_or_else(|| panic!("group_rx_ripemd.json has no vectors array"));
    let mut checked = 0usize;
    for v in vectors {
        let Some(obj) = v.as_object() else { continue };
        let id = obj.get("id").and_then(serde_json::Value::as_str).unwrap_or("?");
        checked += 1;

        if obj.get("reference_can_compute").and_then(serde_json::Value::as_bool) != Some(false) {
            problems.push(format!(
                "\x20 - vector {id}: reference_can_compute is not false. Every \
                 vector in this group is here BECAUSE the reference cannot \
                 answer; one that says otherwise belongs in group C, where it \
                 would be checked against two implementations instead of one."
            ));
        }
        if obj
            .get("reference_cannot_compute_reason")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .len()
            < 80
        {
            problems.push(format!(
                "\x20 - vector {id}: reference_cannot_compute_reason is missing or \
                 too short. 'The reference cannot answer' is the strongest \
                 claim in the file and the easiest to assert without grounds."
            ));
        }
        // The class is recomputed rather than read from the vector, so a
        // length that drifted out of the faulting class is noticed.
        let len = obj.get("in_len").and_then(serde_json::Value::as_u64).unwrap_or(0) as usize;
        if len % 64 < 56 {
            problems.push(format!(
                "\x20 - vector {id} is {len} bytes, residue {}, which is OUTSIDE \
                 the faulting class. The reference can compute this one.",
                len % 64
            ));
        }
        let source = obj.get("source").and_then(serde_json::Value::as_str).unwrap_or("");
        if !source.contains("@noble/hashes") {
            problems.push(format!(
                "\x20 - vector {id}: source is {source:?}, which does not name \
                 @noble/hashes. It is the only implementation behind this group; \
                 if the values came from somewhere else the pin block is wrong."
            ));
        }
        if source.contains("reference/mochimo-core") {
            problems.push(format!(
                "\x20 - vector {id}: source names reference/mochimo-core, which \
                 cannot have produced it -- the call aborts."
            ));
        }
    }

    // The pin: a version-less record of one implementation's output is not
    // reproducible.
    let pin = root.get("pin").and_then(|v| v.as_object());
    if pin
        .and_then(|p| p.get("noble_hashes_version"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .is_empty()
    {
        problems.push(
            "\x20 - pin.noble_hashes_version is missing. Every value in this file \
             is one library's output; without its version the file records an \
             answer without recording who gave it."
                .to_string(),
        );
    }

    // Vacuity floor, before the problems assertion: an empty vectors array
    // would make `problems.is_empty()` true about nothing.
    assert!(
        checked >= 24,
        "group RX holds {checked} vector(s), fewer than the 24 faulting-class \
         lengths in 0..=200. The group shrank, and a shrunk oracle for a class \
         the reference cannot answer is worse than a missing one: the marker \
         that used to demand it is gone."
    );

    assert!(
        problems.is_empty(),
        "group RX is not the kind of oracle it says it is:\n{}\n\
         This is the only group in the corpus with no reference side. Its \
         claims are (1) two independent implementations of a published \
         algorithm, neither being the other's specification, and (2) no \
         evidence about Mochimo whatsoever. Both are easy to drop and dropping \
         either spreads: the first makes the group look weaker than it is, the \
         second makes it look like a second opinion about Mochimo, which it is \
         not.",
        problems.join("\n")
    );

    println!("  group RX: {checked} vectors, no reference side, @noble/hashes only");
}

// ===========================================================================
// The pin blocks of the TypeScript- and Mesh-sourced groups
// ===========================================================================

/// Every `*_commit` a fixture's `pin` block records is the commit the
/// documents state for that subject, or is declared undocumented and then
/// held consistent across the files that carry it.
///
/// The domain is every key ending in `_commit` inside every `pin` object
/// under `fixtures/*.json`. A key neither stated by a document nor declared
/// in [`UNDOCUMENTED_PIN_KEYS`] stops the run, and so does a declared row no
/// fixture carries. The count of values compared is stated, not derived.
#[test]
fn pin_block_commits_match_the_commits_the_documents_state() {
    let root = repo_root();
    let stated = stated_commits();
    let dir = root.join("fixtures");
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();

    let mut problems: Vec<String> = Vec::new();
    let mut values_checked = 0usize;
    let mut documented = 0usize;
    let mut pinned_files = 0usize;
    let mut keys_seen: BTreeSet<String> = BTreeSet::new();
    let mut undocumented_seen: BTreeMap<String, (String, String)> = BTreeMap::new();

    for path in &files {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("?");
        let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        let json: serde_json::Value = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{name}: not JSON: {e}"));
        let Some(pin) = json.get("pin").and_then(|p| p.as_object()) else { continue };
        pinned_files += 1;
        let mut commits = 0usize;
        for (key, value) in pin {
            if !key.ends_with("_commit") {
                continue;
            }
            commits += 1;
            values_checked += 1;
            keys_seen.insert(key.clone());
            let value = value.as_str().unwrap_or("");
            if value.len() != 40 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
                problems.push(format!("\x20 - {name}: pin.{key} is {value:?}, not a 40-hex object id"));
            }
            if let Some(want) = stated.get(key.as_str()) {
                documented += 1;
                if value != want {
                    problems.push(format!(
                        "\x20 - {name}: pin.{key} is {value}, but the documents state {want}. The \
                         fixture was generated from a different tree than the one the documents \
                         describe -- regenerate, and read the diff."
                    ));
                }
            } else if UNDOCUMENTED_PIN_KEYS.iter().any(|(k, _)| k == key) {
                match undocumented_seen.get(key) {
                    None => {
                        undocumented_seen.insert(key.clone(), (value.to_owned(), name.to_owned()));
                    }
                    Some((first, first_file)) if first != value => problems.push(format!(
                        "\x20 - {name}: pin.{key} is {value}, but {first_file} records {first}"
                    )),
                    Some(_) => {}
                }
            } else {
                problems.push(format!(
                    "\x20 - {name}: pin.{key} is stated by no document and declared by no row; \
                     add it to one rather than leaving a recorded commit compared to nothing"
                ));
            }
        }
        if commits == 0 {
            problems.push(format!(
                "\x20 - {name}: a `pin` block with no `*_commit` key records versions against no tree"
            ));
        }
    }

    for (key, _) in UNDOCUMENTED_PIN_KEYS {
        // Reference-block keys are walked by the sibling check; only pin-block
        // keys are owed here.
        if key.ends_with("_commit") && !keys_seen.contains(*key) {
            problems.push(format!(
                "\x20 - the undocumented-key table declares {key} and no fixture records it; a \
                 row nothing matches is a permission nobody is using"
            ));
        }
    }

    assert!(
        problems.is_empty(),
        "fixture pin blocks disagree with the documents or with each other:\n{}",
        problems.join("\n")
    );
    // Stated, not derived: F 3 (wallet, wots, mochiwallet), CX 2 (wots,
    // mochiwallet), RX 1 (wots), M 3 (client, wots, mochiwallet), N 2 (mesh,
    // go_mcminterface), AKX 2 and CK 2 (wots, mochiwallet): fifteen, over
    // seven pinned files, thirteen of them stated by a document.
    assert_eq!(
        values_checked, 15,
        "{values_checked} pin-block commit(s) were compared across {pinned_files} pinned file(s); the \
         corpus records fifteen (F 3, CX 2, RX 1, M 3, N 2, AKX 2, CK 2). Fewer means the walk stopped \
         finding them; more means a fixture gained one and this number is owed a deliberate move."
    );
    assert_eq!(documented, 13, "{documented} of the fifteen were stated by a document; expected 13");
    println!(
        "  pin-block commits: {values_checked} across {pinned_files} file(s), {documented} agree with \
         the documents, the rest consistent across files"
    );
}

/// The Reader permission for `SignedTransaction::attach` (which returns a
/// signature-bearing value) is backed by an executed refusing check, not only
/// by its allow-list entry, which says nothing about verifying what it
/// assembles.
///
/// Floor 5: the five components a mismatched signature can differ in
/// (position, public key, signature bytes, public seed, source hash).
#[test]
fn mesh_reader_permission_is_backed_by_a_refusing_check() {
    const GUARD: &str = "mesh_reader_permission_is_backed_by_a_refusing_check";
    const TARGET: &str = "attach_refuses_every_mismatched_component";
    if let Err(why) = census::check(GUARD, TARGET) {
        panic!(
            "the Reader permission for mesh/spend.rs::SignedTransaction::attach in the I1 route scan is \
             backed by nothing that runs: {TARGET} must be in tests/spend.rs, run, pass and print \
             `attach refusals:` with at least 5.\n{why}"
        );
    }
    println!("  mesh reader permission: {TARGET} censused, attach's five refusals executed");
}

/// Every print-macro invocation in `code`, as (byte offset, macro name).
///
/// Located at an identifier boundary, so `eprintln!` is not reported as
/// `println!`, and `print!` cannot match inside `println!` because the `!`
/// must follow the name directly.
fn print_sites(code: &str) -> Vec<(usize, &'static str)> {
    let bytes = code.as_bytes();
    let mut out = Vec::new();
    for name in ["println", "print", "eprintln", "eprint"] {
        let needle = format!("{name}!");
        let mut from = 0usize;
        while let Some(i) = code[from..].find(&needle) {
            let at = from + i;
            let boundary = at == 0 || !(bytes[at - 1].is_ascii_alphanumeric() || bytes[at - 1] == b'_');
            if boundary {
                out.push((at, name));
            }
            from = at + needle.len();
        }
    }
    out.sort_unstable();
    out
}

/// The body of an `impl` block, by brace matching from its header.
///
/// An unmatched header returns the empty string, and the caller's floor
/// fires.
fn impl_block(code: &str, header: &str) -> String {
    let Some(start) = code.find(header) else {
        return String::new();
    };
    let rest = &code[start..];
    let Some(open) = rest.find('{') else {
        return String::new();
    };
    let mut depth = 0usize;
    for (i, c) in rest[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return rest[open..open + i + 1].to_string();
                }
            }
            _ => {}
        }
    }
    String::new()
}

/// The CLI cannot reach around the wallet.
///
/// `Wallet` exposes no `&mut Keystore`, but a consumer could open its own
/// store and call `persist_advance` and `sign_spend` around the gate, and
/// the route scan cannot flag a function that returns no signature-bearing
/// type. The rule for the CLI:
///
/// * no CLI file names `into_parts`, `persist_advance`,
///   `persist_advance_to`, `persist_rollback_to`, `sign_spend`,
///   `resign_reserved`, or a raw signer port;
/// * each store-writing name is permitted only in the pre-gate module that
///   owns it: `add` in `create` and `restore`, `Keystore::create` in
///   `create`, and `advance_after_operator_review` and
///   `rollback_after_operator_review` (the routes from a report to a moved
///   index) in `reconcile`;
/// * every pre-gate module (`create`, `address`, `discover`, `restore`,
///   `reconcile`) names no `Wallet`.
///
/// So no command holds a `Wallet` and a mutable store at once, and no
/// command holding a mutable store signs. `restore` needs [`Keystore::add`],
/// which `Wallet` does not expose.
///
/// Needles use the method-call spelling `.name(`, since `persist_advance` is
/// a prefix of `persist_advance_to`; positive controls assert each needle
/// matches somewhere.
#[test]
fn the_cli_cannot_reach_around_the_wallet() {
    let files: Vec<(String, String)> = crate_source_files()
        .into_iter()
        .filter(|(p, _)| {
            p.contains("mochimo-crypto/src/cli/") || p.ends_with("src/bin/tawara.rs")
        })
        .collect();
    assert!(
        files.len() >= 4,
        "the CLI walk found {} file(s); it should find src/cli/{{mod,args,restore}}.rs and \
         src/bin/tawara.rs. A vacuous walk passes every arm below.",
        files.len()
    );
    // The floor above is met by `src/cli/` alone, so this keeps the
    // binary's three arms below (the impl print ban, the census demand, the
    // main-only ban) from passing if the walk misses `tawara.rs`.
    assert_eq!(
        files.iter().filter(|(p, _)| p.ends_with("src/bin/tawara.rs")).count(),
        1,
        "the CLI walk did not reach src/bin/tawara.rs; every arm scoped to the binary \
         below is then a verdict over nothing."
    );

    /// Forbidden in every CLI file, with why.
    ///
    /// `store_mut` is not listed because no such method exists; its absence
    /// is asserted over `wallet.rs` below.
    const FORBIDDEN: [(&str, &str); 7] = [
        (".into_parts(", "takes the keystore back out of the gated type"),
        (".persist_advance(", "reserves an index with no plan behind it"),
        (
            ".persist_advance_to(",
            "moves an index with no acknowledgement behind it; the CLI's one route to a moved \
             index is `advance_after_operator_review`, in `reconcile`",
        ),
        (
            ".persist_rollback_to(",
            "moves an index back with no acknowledgement behind it; the CLI's one route to a \
             rolled-back index is `rollback_after_operator_review`, in `reconcile`",
        ),
        (".sign_spend(", "signs without going through the wallet"),
        (".resign_reserved(", "the raw re-signer, below `resign_pending`"),
        ("wots_sign", "a raw signer port"),
    ];
    /// Names that mutate the store, and the modules permitted to write each.
    ///
    /// Keyed per name, so widening the pre-gate set does not widen what any
    /// member may write. `advance_after_operator_review(` has no leading dot:
    /// it is a free function in `recon` as well as a `Wallet` method, and
    /// either spelling outside `reconcile` is the defect.
    const STORE_WRITERS: [(&str, &[&str]); 4] = [
        (".add(", &["src/cli/create.rs", "src/cli/restore.rs"]),
        ("advance_after_operator_review(", &["src/cli/reconcile.rs"]),
        ("rollback_after_operator_review(", &["src/cli/reconcile.rs"]),
        ("Keystore::create", &["src/cli/create.rs"]),
    ];

    /// The modules that run before a `Wallet` exists. Each must name no
    /// `Wallet` and no signer, so none holds a wallet and a mutable store at
    /// once, and its only store writes are those STORE_WRITERS permits.
    ///
    /// `create` and `address` need no reconciled state; `restore` constructs
    /// one; `reconcile` repairs one (through a function taking an
    /// `OperatorAcknowledgement` built from a `Divergence`) and so cannot run
    /// behind a constructor that refuses that state; `discover` asks the node
    /// about tags the store does not hold.
    const PRE_GATE: [&str; 5] = [
        "src/cli/create.rs",
        "src/cli/address.rs",
        "src/cli/discover.rs",
        "src/cli/restore.rs",
        "src/cli/reconcile.rs",
    ];

    let all = crate_source_files();
    let all_named = |suffix: &str| -> String {
        all.iter()
            .find(|(p, _)| p.ends_with(suffix))
            .map(|(_, t)| code_only(t))
            .unwrap_or_default()
    };

    let mut pre_gate_seen = 0usize;
    for (path, text) in &files {
        let code = code_only(text);

        for (needle, why) in FORBIDDEN {
            assert!(
                !code.contains(needle),
                "{path} names `{needle}` -- {why}. The CLI's structure is what keeps the \
                 keystore behind the wallet (once an injection green); if this call is \
                 genuinely needed, that is a finding about the gate's shape and belongs in \
                 the errata before it belongs in the code."
            );
        }
        for (needle, permitted) in STORE_WRITERS {
            if !permitted.iter().any(|m| path.ends_with(m)) {
                assert!(
                    !code.contains(needle),
                    "{path} names `{needle}`, which mutates the store. Only {permitted:?} may, \
                     and only because those run before the wallet exists and sign nothing."
                );
            }
        }
        // Everything the operator sees in `create` must go through the
        // `Terminal` seam; a bare print would reach stdout, where the
        // no-phrase-without-a-terminal test cannot see it.
        if path.ends_with("src/cli/create.rs") {
            for construct in ["println!", "print!", "eprintln!", "eprint!"] {
                assert!(
                    !code.contains(construct),
                    "{path} contains `{construct}`. The phrase must reach the operator only \
                     through `Terminal::show`, or `create_without_a_terminal_writes_nothing_\
                     and_shows_no_phrase` is blind to whatever the print emits."
                );
            }
        }
        // The binary's `Terminal` implementation may not print either. Scoped
        // to the impl because `main` legitimately prints the report. The
        // phrase must go to the acquired terminal descriptor; a `println!`
        // would send it into redirected stdout (`create > seed.txt`).
        if path.ends_with("src/bin/tawara.rs") {
            let block = impl_block(&code, "impl create_cmd::Terminal for Tty");
            assert!(
                block.len() > 200,
                "{path}: the `Terminal for Tty` impl was not found, so its print ban is \
                 asserted over {} character(s) of nothing.",
                block.len()
            );
            for construct in ["println!", "print!", "eprintln!", "eprint!"] {
                assert!(
                    !block.contains(construct),
                    "{path}: `impl Terminal for Tty` contains `{construct}`. Everything this \
                     impl shows the operator must go to the terminal it acquired -- a \
                     process-wide stream can be redirected, and the phrase then lands in a \
                     file while the question that asks about it does not."
                );
            }
            // The ban above is the cheap early signal. Naming the descriptor
            // in source does not show the impl writes to it, so the
            // enforcement is `tests/cli.rs`'s pty harness: it runs the shipped
            // binary under a pseudo-terminal, asserts prompts, phrase and echo
            // on the screen, and finds the phrase in neither redirected
            // stream. The census demand below requires it to have run.
            const PTY: &str = "pty::create_on_a_real_pty_shows_a_phrase_that_recovers_the_store";
            if let Err(why) = census::check("the_cli_cannot_reach_around_the_wallet", PTY) {
                panic!(
                    "{path}: the print ban over `impl Terminal for Tty` is a text property and \
                     the thing that establishes the impl actually shows the operator anything \
                     is the pty harness -- which is not running: {PTY} must be in tests/cli.rs, \
                     run, pass and print `tty create:` with at least 6.\n{why}"
                );
            }
            println!("  tty display: {PTY} censused, the shipped binary answered its prompts on a pty");

            // The domain is the file, not one impl: the four print macros may
            // occur only inside `fn main`, which prints the report and the
            // usage, so no prompt anywhere in the binary (such as
            // `read_secret_line`'s password prompt) can reach a process-wide
            // stream. Sites are located at identifier boundaries so the
            // message names the actual macro.
            //
            // The runtime check is
            // `pty::address_on_a_real_pty_needs_no_node_and_its_prompt_survives_a_redirected_stderr`,
            // which redirects stderr inside a pty and finds the prompt on the
            // screen and not in the file. A print inside `impl Terminal for
            // Tty` trips the impl ban above first; both fail on such a site.
            let main_at = code.find("fn main()").unwrap_or(0);
            let main_block = impl_block(&code, "fn main()");
            assert!(
                main_block.len() > 200,
                "{path}: `fn main()` was not found, so the print ban over the rest of the binary \
                 is asserted against {} character(s) of nothing.",
                main_block.len()
            );
            // `impl_block` brace-matches with no string awareness, so an
            // unmatched `{` in a string in `main` could swallow the rest of
            // the file; the next function's header must not be inside the
            // block.
            assert!(
                !main_block.contains("fn run_from_argv"),
                "{path}: `fn main()`'s block ran into `fn run_from_argv`, so the main-only \
                 ban is scoped over more than main and its verdict is vacuous."
            );
            // Three spellings of a process-wide write that are not print
            // macros, including `dbg!`, which writes to stderr. None occurs in
            // `crates/*/src`, so nothing demonstrates these needles match.
            for needle in ["io::stderr(", "io::stdout(", "dbg!"] {
                assert!(
                    !code.contains(needle),
                    "{path}: `{needle}` reaches a process-wide stream around the macro ban; \
                     a prompt written this way is redirectable exactly as `eprint!` was."
                );
            }
            let main_open = main_at + code[main_at..].find('{').unwrap_or(0);
            let main_range = main_open..main_open + main_block.len();
            let sites = print_sites(&code);
            let inside = sites.iter().filter(|(at, _)| main_range.contains(at)).count();
            assert!(
                inside >= 2,
                "{path}: `fn main` prints from {inside} site(s); it renders the usage and the \
                 report, so fewer than two means this scan is not seeing the sites it is \
                 scoped by, and its verdict over the rest of the file is over nothing."
            );
            let outside: Vec<String> = sites
                .iter()
                .filter(|(at, _)| !main_range.contains(at))
                .map(|(at, name)| format!("`{name}!` at byte offset {at}"))
                .collect();
            assert!(
                outside.is_empty(),
                "{path}: a print macro outside `fn main`: {}. Every prompt in this binary goes \
                 to the terminal it acquired -- a process-wide stream can be redirected, and \
                 `balance 2>file` then asks for a password on no screen.",
                outside.join(", ")
            );
            println!("  print sites: {inside} inside fn main, {} outside", outside.len());
            // The runtime check that the store-opening commands' password
            // prompt reaches the terminal is the second pty test, required
            // here because a scan is only a text property.
            const PTY_PASSWORD: &str =
                "pty::address_on_a_real_pty_needs_no_node_and_its_prompt_survives_a_redirected_stderr";
            if let Err(why) = census::check("the_cli_cannot_reach_around_the_wallet", PTY_PASSWORD) {
                panic!(
                    "{path}: the main-only print ban is a text property and the thing that \
                     establishes the shared password prompt reaches the terminal is the pty \
                     harness -- which is not running: {PTY_PASSWORD} must be in tests/cli.rs, \
                     run, pass and print `tty password:` with at least 4.\n{why}"
                );
            }
            println!("  tty password: {PTY_PASSWORD} censused, the shared prompt reached a pty with stderr redirected");
        }
        if PRE_GATE.iter().any(|m| path.ends_with(m)) {
            pre_gate_seen += 1;
            assert!(
                !code.contains("Wallet"),
                "{path} names `Wallet`, and it is a pre-gate module. Holding both a wallet and \
                 a mutable store is the state this check exists to forbid."
            );
        }
    }
    assert_eq!(
        pre_gate_seen,
        PRE_GATE.len(),
        "the walk saw {pre_gate_seen} of {} pre-gate module(s); a module missing from the walk \
         has its no-Wallet arm asserted over nothing.",
        PRE_GATE.len()
    );

    // There is no `store_mut` on `Wallet`. Controlled by the read-only
    // accessor, which must be present, so a `wallet.rs` that lost both does
    // not pass.
    let wallet = all_named("mochimo-crypto/src/wallet.rs");
    assert!(
        !wallet.contains("fn store_mut"),
        "`Wallet::store_mut` exists. The CLI containment scan is written on the premise that          the only way to a mutable store is `Keystore::open`, which restore alone calls; a          `store_mut` hands one out from inside a reconciled wallet and defeats it."
    );
    assert!(
        wallet.contains("fn store("),
        "`Wallet::store` is gone, so the arm above would pass over a wallet with no store          accessor at all."
    );

    // Positive controls: every needle must match somewhere, or it forbids
    // nothing.
    let find = |needle: &str| -> bool {
        all.iter()
            .any(|(p, t)| !p.contains("/cli/") && !p.ends_with("tawara.rs") && code_only(t).contains(needle))
    };
    for (needle, _) in FORBIDDEN {
        assert!(
            find(needle),
            "the needle `{needle}` matches nothing outside the CLI, so its absence inside the \
             CLI establishes nothing."
        );
    }
    for (needle, permitted) in STORE_WRITERS {
        let used = files.iter().any(|(p, t)| {
            permitted.iter().any(|m| p.ends_with(m)) && code_only(t).contains(needle)
        });
        assert!(
            used,
            "`{needle}` appears in none of {permitted:?}, so the places it is allowed do not \
             use it and its allow-list arm is vacuous."
        );
    }

    println!(
        "CLI containment: {} file(s) scanned, {} forbidden name(s), {} store-writing name(s) \
         over {} pre-gate module(s), plus the binary's Terminal impl",
        files.len(),
        FORBIDDEN.len(),
        STORE_WRITERS.len(),
        PRE_GATE.len()
    );
}

/// The wallet has exactly one route to Argon2, the one RFC 9106's vector is
/// replayed through.
///
/// `format::tests::derive_key_agrees_with_the_anchored_argon2id_at_cheap_parameters`
/// compares the wallet's entry point with `crypt::argon2id_v13` numerically,
/// which a faithful re-inline of the constructor would also pass. This
/// checks the structure: across every `.rs` under `crates/`,
/// comment-stripped, the Argon2 context is constructed exactly once, in
/// `keystore/crypt.rs`, by `new_with_secret`, the call the anchor drives. A
/// second construction anywhere fails by file.
///
/// The needles are the type-path spellings of the two constructors,
/// terminated on the paren. Aliasing the type (`use argon2::Argon2 as A;`)
/// would escape them, so the alias form is forbidden too. Test modules are
/// inside the walk: `format.rs`'s tests call `crypt::argon2id_v13`, never a
/// constructor.
#[test]
fn the_wallet_has_one_route_to_argon2_and_it_is_the_anchored_one() {
    const CRYPT: &str = "crates/mochimo-crypto/src/keystore/crypt.rs";
    // Constructed, never written literally: this file is inside its own walk
    // and `code_only` keeps string literals, so a literal needle would be a
    // site the scan reports.
    let plain_needle = format!("Argon2::{}(", "new");
    let secret_needle = format!("Argon2::{}(", "new_with_secret");
    let alias_needle = format!("Argon2 {} ", "as");
    let sources = all_crate_rust_sources();
    assert!(
        sources.len() >= 40,
        "the source walk saw {} file(s), far below the tree's size; this is the walk failing, \
         not the crate having one route",
        sources.len()
    );
    let mut plain: Vec<(String, usize)> = Vec::new();
    let mut with_secret: Vec<(String, usize)> = Vec::new();
    let mut aliases: Vec<String> = Vec::new();
    for (path, code) in &sources {
        let n = code.matches(plain_needle.as_str()).count();
        if n > 0 {
            plain.push((path.clone(), n));
        }
        let m = code.matches(secret_needle.as_str()).count();
        if m > 0 {
            with_secret.push((path.clone(), m));
        }
        if code.contains(alias_needle.as_str()) {
            aliases.push(path.clone());
        }
    }
    assert!(
        aliases.is_empty(),
        "{alias_needle:?} appears in {aliases:?}: an alias for the Argon2 type would let a \
         second constructor call escape the two needles below. Spell the type path."
    );
    assert!(
        plain.is_empty(),
        "{plain_needle} is called in {plain:?}: a second route to Argon2 exists beside \
         crypt::argon2id_v13. RFC 9106's vector is replayed through the one construction in \
         keystore/crypt.rs and says nothing about this one, whatever bytes it computes today \
         ."
    );
    assert_eq!(
        with_secret,
        vec![(CRYPT.to_string(), 1)],
        "the Argon2 context must be constructed exactly once, by `new_with_secret` in {CRYPT}; \
         found {with_secret:?}. More than one is a second route to Argon2 the RFC 9106 anchor \
         does not reach; none means the anchored path was removed or respelled."
    );
    println!("  argon2 route: one construction, {CRYPT}, the one the RFC 9106 anchor drives");
}

// ---------------------------------------------------------------------------
// Development-history text bans under `src/`, `tests/`, `ui/` and `examples/`.
//
// Absence checks over the comment text and string literals of every `.rs`
// under `crates/*/src`, this crate's `tests/`, its `ui/` cases and its
// `examples/`: no errata entry cited by number, no citation of a document
// not in this repository, no session label or fault-matrix row name, and no
// narrative about the code's own development. Fixtures and the pinned
// `.stderr` files under `ui/` are not walked. Each check floors the files
// walked and the comment and string lines examined, so an empty or
// comment-stripped walk cannot pass, and every needle is constructed from
// fragments so the checks cannot match themselves.
// ---------------------------------------------------------------------------

/// What one unit of text is: a comment line or a string literal.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TextKind {
    Comment,
    Str,
}

/// One line of comment or of string-literal contents, with its file and
/// 1-based line number.
///
/// `span` numbers the lexical unit the line came from (one string literal,
/// one block comment, one `//` line), shared by every line of that unit, so
/// a literal continued across source lines can be rejoined by
/// [`joined_text_by_file`].
struct TextUnit {
    file: String,
    line: usize,
    kind: TextKind,
    text: String,
    span: usize,
}

/// Every `.rs` under this crate's `ui/` and `examples/`, as `(path, text)`,
/// sorted by path: the compile-fail and pass cases, the downstream probe's
/// sources and the Mesh probe. `target/` under `ui/downstream` is skipped,
/// and the pinned `.stderr` files are never read. These are inputs to
/// `tests/compile_fail.rs`, not tests, so `test_source_files()` does not
/// carry them; the text walk does.
fn ui_and_example_source_files() -> Vec<(String, String)> {
    let root = repo_root();
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    let mut stack = vec![crate_dir.join("ui"), crate_dir.join("examples")];
    while let Some(d) = stack.pop() {
        let entries = std::fs::read_dir(&d)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", d.display()));
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                if p.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                let text = std::fs::read_to_string(&p)
                    .unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()));
                let name = p
                    .strip_prefix(&root)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .into_owned();
                out.push((name, text));
            }
        }
    }
    out.sort();
    out
}

/// Every comment line and every line of every string literal under
/// `crates/*/src`, this crate's `tests/`, its `ui/` cases and its
/// `examples/`, in file order, plus the number of files walked.
///
/// The lexer mirrors `strip_comments`, reading strings, char literals and
/// raw strings through the same helpers. A block comment or multi-line
/// string gives one unit per line. Line comments keep their opener; string
/// units carry their contents without the delimiters.
fn crate_text_units() -> (usize, Vec<TextUnit>) {
    let mut out: Vec<TextUnit> = Vec::new();
    let mut files = 0usize;
    // Counted over the whole walk, so two units share a number only if they
    // came from the same literal.
    let mut span = 0usize;
    let mut sources = crate_source_files();
    sources.extend(test_source_files());
    sources.extend(ui_and_example_source_files());
    sources.sort();
    for (name, text) in sources {
        files += 1;
        let b = text.as_bytes();
        let mut i = 0usize;
        let mut line = 1usize;
        let advance = |i: &mut usize, line: &mut usize, to: usize| {
            *line += text[*i..to].matches('\n').count();
            *i = to;
        };
        let push_lines = |out: &mut Vec<TextUnit>, kind: TextKind, first_line: usize, body: &str, span: usize| {
            for (k, l) in body.split('\n').enumerate() {
                out.push(TextUnit { file: name.clone(), line: first_line + k, kind, text: l.to_string(), span });
            }
        };
        while i < b.len() {
            // One number per lexical unit.
            span += 1;
            if b[i..].starts_with(b"/*") {
                let rel = text[i + 2..]
                    .find("*/")
                    .unwrap_or_else(|| panic!("{name}: block comment opened at byte {i} and never closed"));
                let end = i + 2 + rel + 2;
                push_lines(&mut out, TextKind::Comment, line, &text[i..end], span);
                advance(&mut i, &mut line, end);
            } else if b[i..].starts_with(b"//") {
                let end = text[i..].find('\n').map_or(b.len(), |rel| i + rel);
                out.push(TextUnit { file: name.clone(), line, kind: TextKind::Comment, text: text[i..end].to_string(), span });
                advance(&mut i, &mut line, end);
            } else if (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_'))
                && matches!(b[i], b'r' | b'b' | b'c')
                && matches!(raw_string_len(b, i), Some(RawString::Terminated(_)))
            {
                let Some(RawString::Terminated(n)) = raw_string_len(b, i) else { unreachable!() };
                // Contents: after the opening quote, before the closing quote
                // and its hashes.
                let open = text[i..i + n].find('"').map_or(0, |q| q + 1);
                let hashes = text[i + open - 1..i + n].matches('#').count() / 2;
                let close = n - 1 - hashes;
                if open < close {
                    push_lines(&mut out, TextKind::Str, line, &text[i + open..i + close], span);
                }
                let to = i + n;
                advance(&mut i, &mut line, to);
            } else if b[i] == b'"' {
                let mut j = i + 1;
                loop {
                    assert!(j < b.len(), "{name}: string opened at byte {i} and never closed");
                    match b[j] {
                        b'\\' => j += 2,
                        b'"' => break,
                        _ => j += 1,
                    }
                }
                push_lines(&mut out, TextKind::Str, line, &text[i + 1..j], span);
                let to = j + 1;
                advance(&mut i, &mut line, to);
            } else if b[i] == b'\'' {
                let to = i + char_literal_len(b, i).unwrap_or(1);
                advance(&mut i, &mut line, to);
            } else {
                let to = i + text[i..].chars().next().map_or(1, char::len_utf8);
                advance(&mut i, &mut line, to);
            }
        }
    }
    (files, out)
}

/// The floors the four walks share.
///
/// The comment-line and string-line floors are about two thirds of the
/// measured volumes, well above what a walk that dropped a directory, a
/// kind, or the strip would report. Re-measure when they move.
///
/// The files floor bounds a structure (four roots), so it must exceed the
/// largest total a walk missing one of `src/`, `tests/` or `ui/` could
/// report. `examples/` holds one file, below this floor's resolution; its
/// coverage comes from the synthetic corpora in the four checks.
fn assert_text_walk_floors(what: &str, files: usize, units: &[TextUnit]) -> (usize, usize) {
    let comment_lines = units.iter().filter(|u| u.kind == TextKind::Comment).count();
    let string_lines = units.iter().filter(|u| u.kind == TextKind::Str).count();
    assert!(
        files >= 70,
        "{what}: walked {files} file(s). The four roots hold 84, and 70 is above the 62 a walk \
         that lost `tests/` would report -- the largest of the three root losses a count can \
         see. Either a root is missing from the walk or the tree has shrunk by fourteen files."
    );
    assert!(
        comment_lines >= 12_900,
        "{what}: examined {comment_lines} comment line(s). The four roots carry 19,365, and this \
         floor is two thirds of that, so the walk is not seeing comments"
    );
    assert!(
        string_lines >= 9_750,
        "{what}: examined {string_lines} string line(s). The four roots carry 14,648, and this \
         floor is two thirds of that, so the walk is not seeing string literals"
    );
    (comment_lines, string_lines)
}

/// The class of development-history marker a declared site carries.
#[derive(Clone, Copy, PartialEq, Eq)]
enum MarkerClass {
    /// A session label, found by [`phase_tag_len`].
    SessionLabel,
    /// A citation of an open-item list by number, found by
    /// [`board_item_hit`].
    BoardItem,
    /// A citation of the errata document by number, found by
    /// [`errata_number_hit`].
    ErrataNumber,
    /// A row of [`DECLARED_UNRESOLVED_SRC_NAMES`] that permits a name no
    /// longer defined anywhere, cited only by history prose under `src/`.
    /// The subject is the name, and the count is the number of `src/` files
    /// citing it.
    DeclaredName,
    /// Prose about the code's own development, naming no marker. Found by
    /// [`narrative_hits`] against [`NARRATIVE_PHRASES`]; the subject is the
    /// file.
    Narrative,
}

impl MarkerClass {
    /// What the class is called in a failure message and an evidence line.
    fn label(self) -> &'static str {
        match self {
            MarkerClass::SessionLabel => "session label",
            MarkerClass::BoardItem => "open-item citation",
            MarkerClass::ErrataNumber => "errata citation",
            MarkerClass::DeclaredName => "declared dead name",
            MarkerClass::Narrative => "self-narrative passage",
        }
    }
}


/// Sites under `crates/` permitted to carry a development-history marker,
/// as `(class, subject, count, sweep)`.
///
/// The subject is a path under `crates/` for the text classes and a name
/// for [`MarkerClass::DeclaredName`]; a duplicate subject per class is
/// refused. More sites than a row declares is a new violation; fewer is a
/// stale row that must be lowered or deleted, so the table can only shrink.
///
/// The table is empty, so each check is an absence check over the whole
/// tree. Each check first exercises its matcher on constructed text, so a
/// pass means the matcher ran, fired, and then found nothing in the tree.
const DECLARED_HISTORY_MARKER_SITES: &[(MarkerClass, &str, usize, &str)] = &[];

/// The rows declared for one class, with the duplicate refused.
fn baseline_rows(class: MarkerClass) -> Vec<(&'static str, usize, &'static str)> {
    let rows: Vec<(&str, usize, &str)> = DECLARED_HISTORY_MARKER_SITES
        .iter()
        .filter(|(c, ..)| *c == class)
        .map(|(_, subject, count, sweep)| (*subject, *count, *sweep))
        .collect();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for (subject, ..) in &rows {
        assert!(
            seen.insert(subject),
            "DECLARED_HISTORY_MARKER_SITES carries two {} rows for `{subject}`. Two rows for one \
             subject add their ceilings together, so the second one raises the first's permit \
             without saying so. Merge them.",
            class.label()
        );
    }
    rows
}

/// The baseline compared with what a matcher found, in both directions.
///
/// `found` maps a subject to one description per site, in report order.
/// Returns the sites no row covers and the rows the tree no longer supports,
/// each as a block of message lines, plus the total the rows declare.
fn baseline_verdict(class: MarkerClass, found: &BTreeMap<&str, Vec<String>>) -> (Vec<String>, Vec<String>, usize) {
    let rows = baseline_rows(class);
    let what = class.label();
    let mut undeclared: Vec<String> = Vec::new();
    for (subject, sites) in found {
        match rows.iter().find(|(s, ..)| s == subject) {
            Some((_, declared, sweep)) if sites.len() > *declared => undeclared.push(format!(
                "\x20 - {subject}: {} {what}(s), and the baseline declares {declared}, owned by \
                 {sweep}. {} site(s) beyond that count are new.\n{}",
                sites.len(),
                sites.len() - declared,
                sites.join("\n")
            )),
            None => undeclared.push(format!(
                "\x20 - {subject}: {} {what}(s), and the baseline declares none for it.\n{}",
                sites.len(),
                sites.join("\n")
            )),
            Some(_) => {}
        }
    }
    let mut stale: Vec<String> = Vec::new();
    for (subject, declared, sweep) in &rows {
        let actual = found.get(subject).map_or(0, Vec::len);
        if actual < *declared {
            stale.push(format!(
                "\x20 - {subject}: the row declares {declared} {what}(s) and the tree now has \
                 {actual}. {} Owned by {sweep}.",
                if actual == 0 {
                    "Delete the row.".to_string()
                } else {
                    format!("Lower the row to {actual}.")
                }
            ));
        }
    }
    (undeclared, stale, rows.iter().map(|(_, n, _)| n).sum())
}

/// The two assertions every baselined check makes, reporting the table's
/// own staleness first. Returns the declared total for the evidence line.
fn assert_against_baseline(class: MarkerClass, found: &BTreeMap<&str, Vec<String>>) -> usize {
    let (undeclared, stale, declared_total) = baseline_verdict(class, found);
    let what = class.label();
    assert!(
        stale.is_empty(),
        "DECLARED_HISTORY_MARKER_SITES declares more {what}(s) than the tree carries:\n{}\n\n\
         The baseline only shrinks, and a row left at its old count is a permit for markers \
         that are gone -- exactly the room a marker needs to come back unnoticed. Lower each \
         row to what its subject holds now, or delete the row when nothing is left.",
        stale.join("\n")
    );
    assert!(
        undeclared.is_empty(),
        "{what}(s) under crates/ that DECLARED_HISTORY_MARKER_SITES does not declare:\n{}\n\n\
         This repository ships without its development history, so a marker naming a session, \
         an open-item entry or an entry of a document that is not here points at nothing a reader \
         can follow. The baseline is the count that existed when the matchers were repaired \
         and it only shrinks: write the sentence without the marker. Raising a row is not the \
         remedy -- if the count genuinely belongs, that is a decision argued here, not a number \
         edited.",
        undeclared.join("\n")
    );
    declared_total
}

/// How many bytes of filler may sit between a citation's word and its number
/// before the two stop being one citation.
///
/// A backstop: the loop stops at the first byte that is neither a separator
/// nor a permitted word. 64 allows for a string literal continued across
/// source lines, which spends a space, a backslash, a newline and the next
/// line's indentation before the number.
const CITATION_GAP: usize = 64;

/// The word the matchers look for, built from fragments so it never appears
/// whole in this file's text.
fn errata_word() -> String {
    ["err", "ata"].concat()
}

/// Whether `text` names an entry of the errata document by number: the
/// document's name, in any case and in its singular spelling too, then,
/// across at most [`CITATION_GAP`] bytes of whitespace, comment openers
/// (`/`, `!`, `#`), the backslash that continues a string literal, markup
/// that decorates a number (`*`, `_`, `(`, `[`), `§`, `:` and the words
/// `entry`, `entries`, `no.` and `number`, a decimal digit. Spans a line
/// break, so a citation wrapped across two comment lines or two halves of
/// one string literal is one hit. Returns the byte offset of the word.
///
/// The markup and the backslash are included because a bold number or a
/// citation at the end of a continued source line is still a citation. The
/// digit is what makes a citation, so a generic mention of an errata entry
/// stays legal; the self-test asserts both directions, wrapped and flat.
fn errata_number_hit(text: &str) -> Option<usize> {
    let lower = text.to_ascii_lowercase();
    let b = lower.as_bytes();
    let stem = errata_word();
    let stem = &stem[..stem.len() - 1]; // the shared stem of both spellings
    let mut from = 0usize;
    while let Some(rel) = lower[from..].find(stem) {
        let at = from + rel;
        from = at + stem.len();
        if at > 0 && (b[at - 1].is_ascii_alphanumeric() || b[at - 1] == b'_') {
            continue;
        }
        let mut j = at + stem.len();
        if lower[j..].starts_with('a') {
            j += 1;
        } else if lower[j..].starts_with("um") {
            j += 2;
        } else {
            continue;
        }
        if j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
            continue;
        }
        let window_end = b.len().min(j + CITATION_GAP);
        let mut k = j;
        while k < window_end {
            let rest = &lower[k..window_end];
            if let Some(w) = ["entries", "entry", "number", "no."].iter().find(|w| rest.starts_with(*w)) {
                k += w.len();
            } else if rest.starts_with('§') {
                k += '§'.len_utf8();
            } else if matches!(b[k], b' ' | b'\t' | b'\n' | b'\r' | b'/' | b'!' | b'#' | b':' | b'*' | b'_' | b'(' | b'[' | b'\\') {
                k += 1;
            } else {
                break;
            }
        }
        if k < b.len() && b[k].is_ascii_digit() && k > j {
            return Some(at);
        }
    }
    None
}

/// The name of the open-item list that citations use, built from fragments
/// so it never appears whole in this file's text.
fn board_item_word() -> String {
    ["Known", "-open"].concat()
}

/// Whether `text` cites an entry of the open-item list by number: the
/// list's name, in any case, then, across at most [`CITATION_GAP`] bytes of
/// whitespace, comment openers (`/`, `!`, `#`), the backslash that continues
/// a string literal, markup (`*`, `_`, `(`, `[`), `:` and the words `item`,
/// `items` and `no.`, a decimal digit. Spans a line break, so a citation
/// wrapped across two comment lines or two halves of one string literal is
/// one hit. Returns the byte offset of the word.
///
/// Uses the same window and gap rules as [`errata_number_hit`], so the two
/// matchers agree about what a gap is.
fn board_item_hit(text: &str) -> Option<usize> {
    let lower = text.to_ascii_lowercase();
    let b = lower.as_bytes();
    let word = board_item_word().to_ascii_lowercase();
    let mut from = 0usize;
    while let Some(rel) = lower[from..].find(&word) {
        let at = from + rel;
        from = at + word.len();
        if at > 0 && (b[at - 1].is_ascii_alphanumeric() || b[at - 1] == b'_') {
            continue;
        }
        let j = at + word.len();
        if j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
            continue;
        }
        let window_end = b.len().min(j + CITATION_GAP);
        let mut k = j;
        while k < window_end {
            let rest = &lower[k..window_end];
            if let Some(w) = ["items", "item", "no."].iter().find(|w| rest.starts_with(*w)) {
                k += w.len();
            } else if matches!(b[k], b' ' | b'\t' | b'\n' | b'\r' | b'/' | b'!' | b'#' | b':' | b'*' | b'_' | b'(' | b'[' | b'\\') {
                k += 1;
            } else {
                break;
            }
        }
        if k < b.len() && b[k].is_ascii_digit() && k > j {
            return Some(at);
        }
    }
    None
}

/// One file's share of the walk: its path, its units joined into one string,
/// the offset each unit starts at paired with its index, and the units
/// themselves.
type JoinedFile<'a> = (&'a str, String, Vec<(usize, usize)>, Vec<&'a TextUnit>);

/// The alternatives that may stand at one position of a phrase.
type Seg = &'static [&'static str];
/// One phrasing: segments in order, with filler permitted between them.
type Shape = &'static [Seg];

/// The sentinel alternative that matches a run of decimal digits.
const DIGITS: &str = "<digits>";

/// One class of prose about the code's own development.
struct NarrativeRow {
    /// What the row is called in a failure message. Rows are referred to by
    /// index and name, never by quoting what they match, since a quoted
    /// phrase would itself be a site.
    name: &'static str,
    /// Alternative phrasings. A row matches if any one of them does.
    shapes: &'static [Shape],
    /// Words that, standing immediately after a match, mean the match is not
    /// narrative after all.
    not_followed_by: Seg,
}

/// The spelled cardinals row 4 counts in, beside a run of digits.
const CARDINALS: Seg = &[
    "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven",
    "twelve", "thirteen", "fourteen", "fifteen", "sixteen", "seventeen", "eighteen", "nineteen",
    "twenty", DIGITS,
];

/// Prose about the code's own development, matched as phrases.
///
/// The token bans beside this one match a session label or a numbered
/// citation; a sentence can narrate development without either. A reader of
/// a shipping wallet cannot act on what the code looked like before.
///
/// Rows are chosen for precision, not recall: each was measured over the
/// tree before it was admitted, and broad candidates that fire on live
/// prose (bare negations of currency, adverbs of singularity, comparatives
/// of preference, past-tense verbs of speech, adjectives of age, colour
/// words for test state) were refused. Rows 2 and 3 use measured closed
/// sets; purpose constructions such as "used to sign" are excluded.
///
/// A row's count is hits, not sentences. Lower it only by deleting prose,
/// not by merging sentences or rewording with a synonym.
///
/// Limits:
///
/// * Comments only, not string literals: `src/mnemonic/english.rs` carries
///   the BIP-39 wordlist, which contains words several rows match, and must
///   ship byte for byte. Narrative inside assertion messages is therefore
///   not seen.
/// * A failure can be evaded by moving a sentence into an assertion message.
const NARRATIVE_PHRASES: &[NarrativeRow] = &[
    NarrativeRow { name: "a duration of the past", shapes: &[&[&["for"], &["a", "some"], &["time", "while"]]], not_followed_by: &[] },
    NarrativeRow {
        name: "a piece of prose in the past tense",
        shapes: &[&[
            &["this", "the"],
            &["comment", "note", "paragraph", "section", "header", "bullet", "sentence", "test", "arm"],
            &[
                "said", "asserted", "claimed", "stated", "read", "called", "recorded", "demanded",
                "promised", "was", "were", "did", "held", "outlived", "passed", "prescribed",
                "went", "argued", "carried", "became", "documented", "closed", "measured",
                "returned",
            ],
        ]],
        not_followed_by: &[],
    },
    NarrativeRow {
        name: "a former behaviour",
        shapes: &[&[
            &["used"],
            &["to"],
            &[
                "assert", "be", "claim", "come", "compute", "defeat", "defer", "live", "read",
                "receive", "rely", "say", "sit", "stand", "treat", "demand", "name", "call",
                "hold", "carry", "mean", "report", "print", "exist", "run", "pin", "spell",
                "point", "list", "cover", "walk",
            ],
        ]],
        not_followed_by: &[],
    },
    NarrativeRow { name: "a count of work periods", shapes: &[&[CARDINALS, &["sessions"]]], not_followed_by: &[] },
    NarrativeRow { name: "an earlier version of the text", shapes: &[&[&["draft", "drafts"]]], not_followed_by: &[] },
    NarrativeRow { name: "the first exercise against a live chain", shapes: &[&[&["first"], &["live"], &["run"]]], not_followed_by: &[] },
    NarrativeRow {
        name: "the work period this text was written in",
        shapes: &[&[&["before", "until"], &["this"], &["session"]], &[&["this"], &["session's"]]],
        not_followed_by: &[],
    },
    NarrativeRow { name: "a state in the past", shapes: &[&[&["was", "were"], &["once"]]], not_followed_by: &[] },
    NarrativeRow { name: "an initial state", shapes: &[&[&["at"], &["first"]]], not_followed_by: &["spend", "spends"] },
    NarrativeRow { name: "the state preceding a repair", shapes: &[&[&["before"], &["the"], &["fix", "repair"]]], not_followed_by: &[] },
    NarrativeRow { name: "a former location of the text", shapes: &[&[&["stood", "lived", "sat", "hung"], &["here", "there"]]], not_followed_by: &[] },
    NarrativeRow {
        name: "a review ritual",
        shapes: &[&[&["design"], &["panel"]], &[&["adversarial"], &["pass", "passes"]], &[&["first"], &["sketched"]]],
        not_followed_by: &[],
    },
    NarrativeRow { name: "an acknowledged correction", shapes: &[&[&["corrected"], &["since"]]], not_followed_by: &[] },
];

/// Whether `c` continues a word for the purpose of a phrase boundary.
///
/// Digits and letters only. `_` is handled as filler below, so it cannot
/// also be a word byte.
fn is_word_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric()
}

/// Whether byte `k` may sit between two segments of a phrase.
///
/// Whitespace and the comment openers, because a phrase wrapped across two
/// comment lines is one phrase (`TextUnit::text` keeps the `//` prefix).
/// `*` and `_` because markdown emphasis does not change a phrase.
///
/// `_` is filler only at the edge of a word; joining two word bytes it is
/// part of a snake_case name.
fn is_phrase_filler(b: &[u8], k: usize) -> bool {
    match b[k] {
        b' ' | b'\t' | b'\n' | b'\r' | b'/' | b'!' | b'#' | b'*' => true,
        b'_' => !(k > 0 && b[k - 1].is_ascii_alphanumeric() && k + 1 < b.len() && b[k + 1].is_ascii_alphanumeric()),
        _ => false,
    }
}

/// The end offset of the longest alternative of `seg` matching at `at`.
fn segment_match(b: &[u8], at: usize, seg: Seg) -> Option<usize> {
    let mut best: Option<usize> = None;
    for alt in seg {
        let end = if *alt == DIGITS {
            let mut j = at;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            if j == at {
                continue;
            }
            j
        } else {
            if !b[at..].starts_with(alt.as_bytes()) {
                continue;
            }
            at + alt.len()
        };
        if end < b.len() && is_word_byte(b[end]) {
            continue;
        }
        best = Some(best.map_or(end, |x: usize| x.max(end)));
    }
    best
}

/// The end offset of `shape` matching at `at`, filler permitted between
/// segments but required -- two segments running together are one word.
fn shape_match(b: &[u8], at: usize, shape: Shape) -> Option<usize> {
    let mut pos = at;
    for (k, seg) in shape.iter().enumerate() {
        if k > 0 {
            let from = pos;
            let limit = b.len().min(pos + CITATION_GAP);
            while pos < limit && is_phrase_filler(b, pos) {
                pos += 1;
            }
            if pos == from {
                return None;
            }
        }
        pos = segment_match(b, pos, seg)?;
    }
    Some(pos)
}

/// Every `(row index, byte offset)` a row of [`NARRATIVE_PHRASES`] matches in
/// `text`, lower-cased first so a sentence-initial phrase is a hit.
///
/// The scan advances one byte at a time, since the rows have no common
/// length and a longer advance could step over a second row's hit.
fn narrative_hits(text: &str) -> Vec<(usize, usize)> {
    let lower = text.to_ascii_lowercase();
    let b = lower.as_bytes();
    let mut out = Vec::new();
    for i in 0..b.len() {
        if i > 0 && is_word_byte(b[i - 1]) {
            continue;
        }
        for (r, row) in NARRATIVE_PHRASES.iter().enumerate() {
            let Some(end) = row.shapes.iter().find_map(|s| shape_match(b, i, s)) else {
                continue;
            };
            if !row.not_followed_by.is_empty() {
                let mut k = end;
                let limit = b.len().min(end + CITATION_GAP);
                while k < limit && is_phrase_filler(b, k) {
                    k += 1;
                }
                if segment_match(b, k, row.not_followed_by).is_some() {
                    continue;
                }
            }
            out.push((r, i));
        }
    }
    out
}

/// The canonical text of one row: the first alternative of every segment of
/// its first shape, single-spaced. Built from the table so a self-test vector
/// cannot drift from the row it is supposed to exercise.
fn narrative_vector(row: &NarrativeRow) -> String {
    row.shapes[0]
        .iter()
        .map(|seg| if seg[0] == DIGITS { "7" } else { seg[0] })
        .collect::<Vec<_>>()
        .join(" ")
}

/// One unit of text built by a test rather than read from the tree.
///
/// Every text ban's baseline is empty, so the tree alone cannot tell a
/// working collection path from one that has stopped seeing a kind, lost a
/// line in the join, or mislaid a unit offset. Constructed units can.
fn synthetic_unit(line: usize, kind: TextKind, span: usize, text: &str) -> TextUnit {
    TextUnit { file: "<constructed>".to_string(), line, kind, text: text.to_string(), span }
}

/// Consecutive comment units of one file, on consecutive lines, as runs.
///
/// The row-name needle works per run, not per line: a parenthesised row
/// name two lines below the word *matrix* is part of the same sentence. A
/// function so tests can exercise the grouping directly.
fn comment_runs(units: &[TextUnit]) -> Vec<&[TextUnit]> {
    let mut out: Vec<&[TextUnit]> = Vec::new();
    let mut i = 0usize;
    while i < units.len() {
        if units[i].kind != TextKind::Comment {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        while j < units.len()
            && units[j].kind == TextKind::Comment
            && units[j].file == units[i].file
            && units[j].line == units[j - 1].line + 1
        {
            j += 1;
        }
        out.push(&units[i..j]);
        i = j;
    }
    out
}

/// Each file's text units joined in order, with the offset every unit starts
/// at, so a matcher whose window spans a line break sees one string and a hit
/// is still reported at the unit it starts in.
///
/// Comment lines are joined with their line breaks, so a citation wrapped
/// across two is one citation. Each string literal is fenced by NUL bytes,
/// which no matcher's window crosses; the fence goes around the whole
/// literal (one [`TextUnit::span`]), not each of its lines, so a literal
/// continued across source lines stays one sentence.
fn joined_text_by_file(units: &[TextUnit]) -> Vec<JoinedFile<'_>> {
    let mut by_file: BTreeMap<&str, Vec<&TextUnit>> = BTreeMap::new();
    for u in units {
        by_file.entry(u.file.as_str()).or_default().push(u);
    }
    by_file
        .into_iter()
        .map(|(file, us)| {
            let mut joined = String::new();
            let mut starts: Vec<(usize, usize)> = Vec::new(); // (offset, unit index)
            for (idx, u) in us.iter().enumerate() {
                let opens = idx == 0 || us[idx - 1].span != u.span;
                let closes = idx + 1 == us.len() || us[idx + 1].span != u.span;
                starts.push((joined.len(), idx));
                if u.kind == TextKind::Str && opens {
                    joined.push('\u{0}');
                }
                joined.push_str(&u.text);
                if u.kind == TextKind::Str && closes {
                    joined.push('\u{0}');
                }
                joined.push('\n');
            }
            (file, joined, starts, us)
        })
        .collect()
}

/// Every hit `matcher` finds in the joined text of each file, as the unit the
/// hit starts in. `advance` is added to a hit's offset before searching on,
/// so a matcher that returns a word's offset does not find it again.
fn window_hits(units: &[TextUnit], matcher: fn(&str) -> Option<usize>, advance: usize) -> Vec<(&str, &TextUnit)> {
    let mut out: Vec<(&str, &TextUnit)> = Vec::new();
    for (file, joined, starts, us) in joined_text_by_file(units) {
        let mut from = 0usize;
        while let Some(rel) = matcher(&joined[from..]) {
            let at = from + rel;
            let idx = starts.iter().rev().find(|(o, _)| *o <= at).map_or(0, |(_, i)| *i);
            out.push((file, us[idx]));
            from = at + advance;
        }
    }
    out
}

/// No comment or string literal under `src/`, `tests/`, `ui/` or `examples/`
/// cites an entry of the errata document by number.
///
/// That document is not in this repository, so such a citation points
/// nowhere. A sentence that needs the content states the reason itself or
/// points to the specification by section. Assertion messages and operator
/// pages are string literals and are walked too.
#[test]
fn no_comment_or_string_under_the_crate_cites_an_errata_entry_by_number() {
    // The matcher, both directions, on constructed needles.
    let er = errata_word();
    let cap = { let mut s = er.clone(); s.replace_range(0..1, "E"); s };
    let um = format!("{}um", &er[..er.len() - 1]);
    for hit in [
        format!("see {er} 213 §5"),
        format!("{cap} 182."),
        format!("({er}\n/// 213 §5)"),
        format!("{er} entry 51"),
        format!("{um} #4"),
        // Decorated numbers, including the bold form.
        format!("{cap} **146** records"),
        format!("{er} (146)"),
        format!("{er} [146]"),
        format!("{er} _146_"),
        // Continued across two source lines: a space, a backslash, a newline
        // and the next line's indent, which [`CITATION_GAP`] is sized for.
        format!("{er} \\\n                                     213)."),
        format!("{er} \\\n             213 §3's declared-absent state"),
    ] {
        assert!(errata_number_hit(&hit).is_some(), "the matcher missed {hit:?}");
    }
    for miss in [
        format!("{er}-style discipline"),
        // Markup with no number behind it is not a citation.
        format!("{er} **the whole document**"),
        format!("the {er} number to a page that carried four"),
        format!("the old repository's {er} entry, not these lines"),
        format!("an {er} document, 20,799 lines"),
        format!("in{er} 5"),
        format!("\u{0}{er}\u{0}\n213"),
        // The generic mention, wrapped: `entry` is a permitted word and no
        // digit follows, so this stays legal.
        format!("a decision with an {er} \\\n                 entry, not a moved line."),
    ] {
        assert!(errata_number_hit(&miss).is_none(), "the matcher fired on {miss:?}");
    }

    // --- the same needles, through the collection path ---
    //
    // The calls above test `errata_number_hit` alone. `window_hits` adds the
    // per-file join, the NUL fence around each string literal, and the
    // mapping from an offset back to its unit; with the baseline empty, the
    // tree cannot exercise them. This ban reads comments and strings alike,
    // so the property is that a citation in a unit of either kind is found
    // and reported at that unit, asserted as the exact set of lines.
    let corpus = vec![
        synthetic_unit(10, TextKind::Comment, 1, &format!("/// see {er} 213")),
        synthetic_unit(20, TextKind::Str, 2, &format!("{cap} 182, in a literal")),
        // Two adjacent literals, the first ending in the word and the second
        // opening with a number: the fence between spans keeps them apart.
        synthetic_unit(30, TextKind::Str, 3, &format!("a bare {er}")),
        synthetic_unit(31, TextKind::Str, 4, "213 is a count"),
    ];
    let seen: Vec<usize> = window_hits(&corpus, errata_number_hit, errata_word().len() - 1)
        .iter()
        .map(|(_, u)| u.line)
        .collect();
    assert_eq!(
        seen,
        vec![10, 20],
        "the collection path reported citations at {seen:?} rather than at the comment on line \
         10 and the literal on line 20. Missing 10 or 20 means a kind is not reaching the join; \
         an extra 30 means the fence between two literals is gone and a word ending one runs \
         into a number opening the next; a line that is neither means the offset-to-unit \
         mapping is wrong and every hit this check reports names the wrong place."
    );

    let (files, units) = crate_text_units();
    let (comment_lines, string_lines) = assert_text_walk_floors("errata citations", files, &units);
    // The advance is the stem's length, so searching on does not find the
    // same word again.
    let mut found: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for (file, u) in window_hits(&units, errata_number_hit, errata_word().len() - 1) {
        found
            .entry(file)
            .or_default()
            .push(format!("\x20     {file}:{} ({:?}): {}", u.line, u.kind, u.text.trim()));
    }
    let declared = assert_against_baseline(MarkerClass::ErrataNumber, &found);
    println!(
        "  errata citations: {files} files walked, {comment_lines} comment lines and {string_lines} \
         string lines examined, {} numbered citation(s) in {} file(s), all declared in \
         DECLARED_HISTORY_MARKER_SITES against a baseline of {declared}",
        found.values().map(Vec::len).sum::<usize>(),
        found.len()
    );
}

/// Documents this repository does not carry. A comment or page citing one
/// points nowhere; the content belongs in `docs/specification.md` or at the
/// site.
const DOCUMENTS_NOT_IN_THIS_REPOSITORY: [&str; 5] =
    ["errata", "handoff", "port-inventory", "invariants", "protocol-survey"];

/// No comment or string literal under `src/`, `tests/`, `ui/` or `examples/`
/// cites a document named in `DOCUMENTS_NOT_IN_THIS_REPOSITORY` by its path.
///
/// The needles are built as `docs/<name>.md` at run time, so this file never
/// spells one. If one of these documents is added to the repository, this
/// check should be re-scoped.
#[test]
fn no_comment_or_string_under_the_crate_cites_a_document_that_is_not_in_this_repository() {
    let root = repo_root();
    let needles: Vec<String> = DOCUMENTS_NOT_IN_THIS_REPOSITORY.iter().map(|d| format!("docs/{d}.md")).collect();
    for n in &needles {
        assert!(
            !root.join(n).exists(),
            "{n} exists in this repository; this check's premise (that citing it is a \
             pointer into nothing) no longer holds -- re-scope it rather than appease it"
        );
    }
    // The matcher, both directions, on constructed needles.
    let hit = format!("see {}", needles[0]);
    assert!(needles.iter().any(|n| hit.contains(n.as_str())), "the matcher missed {hit:?}");
    let miss = "see docs/specification.md, section I3";
    assert!(!needles.iter().any(|n| miss.contains(n.as_str())), "the matcher fired on {miss:?}");

    // --- the same needles, through the collection path ---
    //
    // This scan has no join or window; it asks every unit whether its text
    // contains one of the paths. The property is that it reads units of
    // both kinds and that a document the repository does carry is not a
    // hit.
    let corpus = [
        synthetic_unit(10, TextKind::Comment, 1, &format!("/// see {}", needles[0])),
        synthetic_unit(20, TextKind::Str, 2, &format!("a page naming {}", needles[1])),
        synthetic_unit(30, TextKind::Comment, 3, "/// see docs/specification.md, section I3"),
    ];
    let seen: Vec<usize> = corpus
        .iter()
        .filter(|u| needles.iter().any(|n| u.text.contains(n.as_str())))
        .map(|u| u.line)
        .collect();
    assert_eq!(
        seen,
        vec![10, 20],
        "the collection path reported citations at {seen:?} rather than at the comment on line \
         10 and the literal on line 20. A missing 10 or 20 means one of the two kinds is no \
         longer read; a 30 means the scan matches a document that is in this repository, which \
         is the one thing its premise forbids."
    );

    let (files, units) = crate_text_units();
    let (comment_lines, string_lines) = assert_text_walk_floors("dead-document citations", files, &units);
    let problems: Vec<String> = units
        .iter()
        .filter(|u| needles.iter().any(|n| u.text.contains(n.as_str())))
        .map(|u| format!("\x20 - {}:{} ({:?}): {}", u.file, u.line, u.kind, u.text.trim()))
        .collect();
    assert!(
        problems.is_empty(),
        "comment(s) or string(s) under the crate cite a document that is not in this repository:\n{}",
        problems.join("\n")
    );
    println!(
        "  dead-document citations: {files} files walked, {comment_lines} comment lines and \
         {string_lines} string lines examined, 0 citations of the {} absent documents",
        needles.len()
    );
}

/// The byte length of a session label starting at `i`, if one starts there:
/// a `W`, `1`, dash and digits; a `P` with one or two digits and an optional
/// dash-number; an `H`, `L` or `V` with one digit; a `Q`, digit, dash and
/// lower-case letter; or an `S` with one or two digits. Each takes an
/// optional lower-case suffix and must be delimited by non-word characters
/// on both sides.
///
/// The `S` arm takes a bare label: over the walked roots, every `S`
/// immediately followed by a digit is a session label. A letter before the
/// `S` rejects `AES256`, a word character after the digits rejects an
/// identifier, and a third digit rejects the match.
fn phase_tag_len(b: &[u8], i: usize) -> Option<usize> {
    if i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_') {
        return None;
    }
    let digits = |from: usize, max: usize| -> usize { b[from..].iter().take(max).take_while(|c| c.is_ascii_digit()).count() };
    let mut j;
    match b.get(i) {
        Some(b'W') if b.get(i + 1) == Some(&b'1') && b.get(i + 2) == Some(&b'-') => {
            let n = digits(i + 3, 3);
            if n == 0 {
                return None;
            }
            j = i + 3 + n;
        }
        Some(b'P') => {
            let n = digits(i + 1, 2);
            if n == 0 {
                return None;
            }
            j = i + 1 + n;
            if b.get(j) == Some(&b'-') {
                let m = digits(j + 1, 2);
                if m == 0 {
                    return None;
                }
                j += 1 + m;
            }
        }
        // `S` labels: one or two digits, as `P` takes; a third digit rejects
        // the match below rather than truncating it.
        Some(b'S') => {
            let n = digits(i + 1, 2);
            if n == 0 {
                return None;
            }
            j = i + 1 + n;
        }
        Some(b'H') | Some(b'L') | Some(b'V') if b.get(i + 1).is_some_and(u8::is_ascii_digit) => j = i + 2,
        Some(b'Q')
            if b.get(i + 1).is_some_and(u8::is_ascii_digit)
                && b.get(i + 2) == Some(&b'-')
                && b.get(i + 3).is_some_and(u8::is_ascii_lowercase) =>
        {
            j = i + 4
        }
        _ => return None,
    }
    if b.get(j).is_some_and(u8::is_ascii_lowercase) && !b.get(j + 1).is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_') {
        j += 1;
    }
    if b.get(j).is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_') {
        return None;
    }
    Some(j - i)
}

/// Every session label in `s`, as slices.
fn phase_tags_in(s: &str) -> Vec<&str> {
    let b = s.as_bytes();
    (0..b.len()).filter_map(|i| phase_tag_len(b, i).map(|n| &s[i..i + n])).collect()
}

/// The byte length of a fault-matrix row name starting at `i`: an `R` with
/// one to three digits and an optional `b`, or an `E` with one digit,
/// delimited by non-word characters on both sides.
fn row_name_len(b: &[u8], i: usize) -> Option<usize> {
    if i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_') {
        return None;
    }
    let j = match b.get(i) {
        Some(b'R') => {
            let n = b[i + 1..].iter().take(3).take_while(|c| c.is_ascii_digit()).count();
            if n == 0 {
                return None;
            }
            let mut j = i + 1 + n;
            if b.get(j) == Some(&b'b') {
                j += 1;
            }
            j
        }
        Some(b'E') if b.get(i + 1).is_some_and(u8::is_ascii_digit) => i + 2,
        _ => return None,
    };
    if b.get(j).is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_') {
        return None;
    }
    Some(j - i)
}

/// Whether `text` carries `word` as a whole word, in any case.
fn has_word(text: &str, word: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let b = lower.as_bytes();
    let mut from = 0usize;
    while let Some(rel) = lower[from..].find(word) {
        let at = from + rel;
        let end = at + word.len();
        let left_ok = at == 0 || !(b[at - 1].is_ascii_alphanumeric() || b[at - 1] == b'_');
        let right_ok = end >= b.len() || !(b[end].is_ascii_alphanumeric() || b[end] == b'_');
        if left_ok && right_ok {
            return true;
        }
        from = end;
    }
    false
}

/// The row names in a run of comment lines that also mentions a matrix or a
/// row, so a bare `R`-plus-digits elsewhere (a register, a revision, a table
/// cell) is not a hit.
fn row_names_in_run(lines: &[&str]) -> Vec<String> {
    if !lines.iter().any(|l| has_word(l, "matrix") || has_word(l, "row")) {
        return Vec::new();
    }
    let mut out = Vec::new();
    for l in lines {
        let b = l.as_bytes();
        for i in 0..b.len() {
            if let Some(n) = row_name_len(b, i) {
                out.push(l[i..i + n].to_string());
            }
        }
    }
    out
}

/// No comment or string literal under `src/`, `tests/`, `ui/` or `examples/`
/// carries a session label or cites the open-item list by number beyond
/// what [`DECLARED_HISTORY_MARKER_SITES`] declares, and no comment run that
/// mentions a fault matrix or a row names one of its rows.
///
/// Row names are qualified by `matrix` or `row` in the same comment run and
/// checked in comments only. Open-item citations are matched over each
/// file's joined text, since a citation can wrap across comment lines;
/// a session label is one token and needs no join.
#[test]
fn no_comment_or_string_under_the_crate_carries_a_phase_tag_or_a_row_name() {
    // The matchers, both directions, on constructed needles.
    let tagged = [
        format!("({}1-3)", "W"),
        format!("since {}13", "P"),
        format!("{}1, total", "H"),
        format!("{}3-2 narrowed", "P"),
        format!("until {}1-14b;", "W"),
        format!("({}6b).", "P"),
        format!("{}3 submitted", "L"),
        format!("{}2-c pinned", "Q"),
        format!("as {}1 did", "V"),
    ];
    // `S` labels, built from fragments like the rest.
    let s = "S";
    let own = [
        format!("closed at {s}6)"),
        format!("({s}10)."),
        format!("the {s}11-gated tests"),
        format!("since {s}15 the ceiling is"),
        format!("re-derived at {s}9:"),
    ];
    for hit in tagged.iter().chain(own.iter()) {
        assert!(!phase_tags_in(hit).is_empty(), "the tag matcher missed {hit:?}");
    }
    // `AES256` and `HS256`: a letter precedes the `S`, so the left delimiter
    // refuses them before the digits are read.
    let mut missed: Vec<String> = ["SHA3-224", "P2P", "RFC 9106", "MP13", "P13_OFF", "TXHDR", "V1_SNAPSHOT", "Q6", "IPv6", "E0603", "AES256", "HS256"]
        .iter()
        .map(|m| (*m).to_string())
        .collect();
    missed.push(format!("{s}6_LIMIT"));
    missed.push(format!("{s}123 is three digits"));
    missed.push(format!("_{s}6"));
    for miss in &missed {
        assert!(phase_tags_in(miss).is_empty(), "the tag matcher fired on {miss:?}");
    }
    // The open-item matcher, both directions. The second hit is the wrapped
    // form; the last miss is the NUL fence between two adjacent string
    // literals.
    let ko = board_item_word();
    for hit in [
        format!("(the notes, {ko} 22, closed"),
        format!("({ko}\n/// 31)."),
        format!("{ko} item 7"),
        // Continued across two source lines, so the two matchers agree about
        // what a gap is.
        format!("{ko} \\\n                                     44)."),
    ] {
        assert!(board_item_hit(&hit).is_some(), "the open-item matcher missed {hit:?}");
    }
    for miss in [
        format!("{ko} items, all of them"),
        format!("the {ko} list"),
        format!("un{ko} 3"),
        format!("\u{0}{ko}\u{0}\n22"),
    ] {
        assert!(board_item_hit(&miss).is_none(), "the open-item matcher fired on {miss:?}");
    }
    let r = "R";
    let e = "E";
    let run_hit = [format!("// the matrix's {r}17 removes the check"), "// and this one still refuses".to_string()];
    let run_hit: Vec<&str> = run_hit.iter().map(String::as_str).collect();
    assert_eq!(row_names_in_run(&run_hit), vec![format!("{r}17")], "the row-name matcher missed a qualified run");
    let run_hit2 = ["// (matrix rows)".to_string(), format!("// the {e}5 injection found it, and ({r}10b) too")];
    let run_hit2: Vec<&str> = run_hit2.iter().map(String::as_str).collect();
    assert_eq!(row_names_in_run(&run_hit2), vec![format!("{e}5"), format!("{r}10b")]);
    let run_miss = [format!("// {r}1 in a comment with neither word beside it"), format!("// {e}0603 is a compiler error code")];
    let run_miss: Vec<&str> = run_miss.iter().map(String::as_str).collect();
    assert!(row_names_in_run(&run_miss).is_empty(), "the row-name matcher fired without its qualifier");
    let run_miss2 = [format!("// a row of {e}0603 errors")];
    let run_miss2: Vec<&str> = run_miss2.iter().map(String::as_str).collect();
    assert!(row_names_in_run(&run_miss2).is_empty(), "the row-name matcher fired on a five-digit code");

    // --- the same needles, through the three collection paths ---
    //
    // Each path fails differently, so each gets its own corpus; with the
    // baseline empty, the tree reports zero whether the paths work or not.
    //
    // (1) Labels are read per unit, over both kinds. The property is that a
    //     unit of either kind reaches `phase_tags_in`.
    let label_corpus = [
        synthetic_unit(10, TextKind::Comment, 1, &format!("// closed at {s}6")),
        synthetic_unit(20, TextKind::Str, 2, &format!("a page naming {s}11")),
        synthetic_unit(30, TextKind::Comment, 3, "// AES256 is not a label"),
    ];
    let seen: Vec<usize> = label_corpus
        .iter()
        .filter(|u| !phase_tags_in(&u.text).is_empty())
        .map(|u| u.line)
        .collect();
    assert_eq!(
        seen,
        vec![10, 20],
        "the label scan reported {seen:?} rather than the comment on line 10 and the literal on \
         line 20; a missing one of those is a kind this check has stopped reading."
    );

    // (2) Row names are read per run, and the run carries the qualifier: the
    //     word `matrix` on one line licenses a name on the next. That needs
    //     consecutive comment units of one file grouped by `comment_runs`.
    let run_corpus = vec![
        synthetic_unit(10, TextKind::Comment, 1, "// the matrix below"),
        synthetic_unit(11, TextKind::Comment, 2, &format!("// names {r}17")),
        synthetic_unit(12, TextKind::Str, 3, "a literal between the runs"),
        synthetic_unit(13, TextKind::Comment, 4, "// the matrix below"),
        synthetic_unit(99, TextKind::Comment, 5, &format!("// names {r}18")),
    ];
    let grouped = comment_runs(&run_corpus);
    let shapes: Vec<(usize, usize)> = grouped.iter().map(|r| (r[0].line, r.len())).collect();
    assert_eq!(
        shapes,
        vec![(10, 2), (13, 1), (99, 1)],
        "`comment_runs` grouped {shapes:?}. Two consecutive comment lines of one file are one \
         run; a string literal between them ends a run; and a gap in the line numbers ends one \
         too. Grouping too little hides a name from the qualifier a line above it, and grouping \
         too much lends a qualifier to a name three hundred lines away."
    );
    let across: Vec<String> = row_names_in_run(&grouped[0].iter().map(|u| u.text.as_str()).collect::<Vec<_>>());
    assert_eq!(
        across,
        vec![format!("{r}17")],
        "the qualifier on the first line of a run did not reach the name on its second: {across:?}"
    );

    // (3) Open-item citations go through the join, which makes one wrapped
    //     across two comment lines a single hit; a per-line scan finds
    //     neither half.
    let item_corpus = vec![
        synthetic_unit(10, TextKind::Comment, 1, &format!("// (the notes, {ko}")),
        synthetic_unit(11, TextKind::Comment, 1, "//  22, closed)."),
        synthetic_unit(20, TextKind::Str, 2, &format!("a page naming {ko} 9")),
    ];
    let seen: Vec<usize> = window_hits(&item_corpus, board_item_hit, board_item_word().len())
        .iter()
        .map(|(_, u)| u.line)
        .collect();
    assert_eq!(
        seen,
        vec![10, 20],
        "the open-item collection path reported {seen:?} rather than the wrapped citation at \
         line 10 and the literal at line 20. A missing 10 means the join is not putting two \
         comment lines of one span together and every wrapped citation is invisible; a missing \
         20 means string literals are not reaching it."
    );

    let (files, units) = crate_text_units();
    let (comment_lines, string_lines) = assert_text_walk_floors("phase tags", files, &units);
    let mut problems: Vec<String> = Vec::new();
    let mut labels: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for u in &units {
        let tags = phase_tags_in(&u.text);
        if !tags.is_empty() {
            labels
                .entry(u.file.as_str())
                .or_default()
                .push(format!("\x20     {}:{} ({:?}): {tags:?} in {}", u.file, u.line, u.kind, u.text.trim()));
        }
    }
    // Comment runs, through the same grouping the corpus above exercises.
    let grouped_runs = comment_runs(&units);
    let runs = grouped_runs.len();
    for run in &grouped_runs {
        let lines: Vec<&str> = run.iter().map(|u| u.text.as_str()).collect();
        let names = row_names_in_run(&lines);
        if !names.is_empty() {
            problems.push(format!(
                "\x20 - {}:{}-{}: fault-matrix row name(s) {names:?} in a comment run that speaks of a matrix or a row",
                run[0].file,
                run[0].line,
                run[run.len() - 1].line
            ));
        }
    }
    assert!(
        runs >= 1_990,
        "the walk formed {runs} comment run(s). The four roots form 2,990, and this floor is two \
         thirds of that -- a walk that lost a root, or one that stopped joining consecutive \
         comment lines into a run, reports well under it"
    );
    // Open-item citations, over each file's joined text so a wrapped one is
    // one hit. The advance past a hit is the name's own length.
    let mut items: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for (file, u) in window_hits(&units, board_item_hit, board_item_word().len()) {
        items
            .entry(file)
            .or_default()
            .push(format!("\x20     {file}:{} ({:?}): {}", u.line, u.kind, u.text.trim()));
    }
    // Row names first and unconditionally: that half is a hard zero, and a
    // failure about the baseline must not hide it.
    assert!(
        problems.is_empty(),
        "comment run(s) under the crate name a fault-matrix row of the old repository:\n{}",
        problems.join("\n")
    );
    let declared_labels = assert_against_baseline(MarkerClass::SessionLabel, &labels);
    let declared_items = assert_against_baseline(MarkerClass::BoardItem, &items);
    println!(
        "  phase tags: {files} files walked, {comment_lines} comment lines ({runs} runs) and {string_lines} \
         string lines examined, 0 row names, {} session label(s) in {} file(s) against a baseline of \
         {declared_labels}, {} open-item citation(s) in {} file(s) against a baseline of {declared_items}",
        labels.values().map(Vec::len).sum::<usize>(),
        labels.len(),
        items.values().map(Vec::len).sum::<usize>(),
        items.len()
    );
}

/// No comment under `src/`, `tests/`, `ui/` or `examples/` narrates the
/// project's own development beyond what [`DECLARED_HISTORY_MARKER_SITES`]
/// declares.
///
/// With nothing in the tree to find, a pass could not distinguish a working
/// matcher from a misspelled phrase, an inverted filter or a lost root. So
/// the matcher first runs on comment units built from the table itself, on
/// which every row must fire, and on a control paragraph on which none may.
#[test]
fn no_comment_under_the_crate_narrates_its_own_development() {
    // --- the table is its own vector source ---
    //
    // A row removed to silence a failure takes its whole class with it, so
    // the row count is floored and every vector is derived from the table.
    assert!(
        NARRATIVE_PHRASES.len() >= 13,
        "NARRATIVE_PHRASES carries {} row(s). Thirteen classes were measured over this tree \
         before any was admitted, and a row deleted to answer a red takes its class out of the \
         ban with it. Removing one is a decision argued at the table, not an edit.",
        NARRATIVE_PHRASES.len()
    );
    let vectors: Vec<String> = NARRATIVE_PHRASES.iter().map(narrative_vector).collect();
    assert_eq!(
        vectors.len(),
        NARRATIVE_PHRASES.len(),
        "a row exists that no vector exercises; the vectors are built from the table so that \
         cannot happen quietly"
    );

    // --- each row fires on its own canonical text, and on no other row's ---
    //
    // So a widened row cannot swallow a neighbour and hide its removal.
    for (r, v) in vectors.iter().enumerate() {
        let hits = narrative_hits(v);
        assert_eq!(
            hits.len(),
            1,
            "row {r} ({}) matches its own canonical text {} time(s), not once. A row that \
             matches its vector twice double-counts every site it finds; one that matches it \
             not at all is spelled wrong and will report nothing for its whole class.",
            NARRATIVE_PHRASES[r].name,
            hits.len()
        );
        assert_eq!(
            hits[0].0, r,
            "row {r} ({})'s canonical text is matched by row {} ({}) instead. Two rows that \
             overlap report one passage twice and let one of them go to zero unnoticed.",
            NARRATIVE_PHRASES[r].name, hits[0].0, NARRATIVE_PHRASES[hits[0].0].name
        );
    }

    // --- the spellings a line-at-a-time, case-sensitive matcher would miss ---
    //
    // A phrase wrapped across two comment lines, a capitalised phrase
    // opening a sentence, and a phrase inside markdown emphasis.
    for (r, v) in vectors.iter().enumerate() {
        let mut spellings = vec![
            format!("// {}", v.to_uppercase()),
            format!("// {}{}", v[..1].to_uppercase(), &v[1..]),
            format!("// **{v}**"),
        ];
        if let Some(sp) = v.find(' ') {
            spellings.push(format!("// {}\n    /// {}", &v[..sp], &v[sp + 1..]));
        }
        for s in &spellings {
            assert!(
                narrative_hits(s).iter().any(|(row, _)| *row == r),
                "row {r} ({}) does not match {s:?}. A matcher blind to one of these spellings \
                 goes green on the one it was written against and silent on the rest.",
                NARRATIVE_PHRASES[r].name
            );
        }
    }

    // --- and a control that must stay clean ---
    const CONTROL: &str = "// The index advances before the signature is released, and the \n\
                           // receipt is minted only after the advanced index is durable. A \n\
                           // second signature at one position is refused rather than \n\
                           // reported, because the key is a one-time key and the store is \n\
                           // the only thing that knows it has been used.";
    let control = narrative_hits(CONTROL);
    assert!(
        control.is_empty(),
        "the control paragraph carries no prose about this project's development and {} row(s) \
         fired on it: {:?}. A row this loose reports live sentences, and a maintainer who reads \
         one red as noise reads the next one that way too.",
        control.len(),
        control.iter().map(|(r, _)| NARRATIVE_PHRASES[*r].name).collect::<Vec<_>>()
    );

    // --- the synthetic corpus, through the collection path itself ---
    //
    // Units of the kind the walk produces, joined as the walk joins them, so
    // a filter admitting the wrong kind or a join losing a line is caught.
    let synthetic: Vec<TextUnit> = vectors
        .iter()
        .enumerate()
        .map(|(r, v)| TextUnit {
            file: "<constructed>".to_string(),
            line: r + 1,
            kind: TextKind::Comment,
            text: format!("/// {v}"),
            span: r,
        })
        .collect();
    let joined: String = synthetic
        .iter()
        .filter(|u| u.kind == TextKind::Comment)
        .map(|u| u.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let fired: BTreeSet<usize> = narrative_hits(&joined).into_iter().map(|(r, _)| r).collect();
    let silent: Vec<&str> = NARRATIVE_PHRASES
        .iter()
        .enumerate()
        .filter(|(r, _)| !fired.contains(r))
        .map(|(_, row)| row.name)
        .collect();
    assert!(
        silent.is_empty(),
        "these row(s) found nothing in a corpus built out of their own text: {silent:?}. This is \
         the check that a green means the matcher ran, and it is the whole reason this test does \
         not simply walk the tree and report zero."
    );

    // --- now the tree ---
    let (files, units) = crate_text_units();
    let (comment_lines, string_lines) = assert_text_walk_floors("self-narrative", files, &units);
    let mut by_file: BTreeMap<&str, Vec<&TextUnit>> = BTreeMap::new();
    for u in units.iter().filter(|u| u.kind == TextKind::Comment) {
        by_file.entry(u.file.as_str()).or_default().push(u);
    }
    let walked: usize = by_file.values().map(Vec::len).sum();
    // What this check reads must equal the walk's comment count: a filter
    // inverted to keep strings would clear the shared floor, since the tree
    // has more string lines than that floor requires.
    assert_eq!(
        walked, comment_lines,
        "the comment-only filter kept {walked} unit(s) where the walk counted {comment_lines} \
         comment line(s). A filter that admits a string literal puts the BIP-39 wordlist inside \
         row 5's reach; one that drops comments silently shrinks every row's corpus."
    );

    let mut found: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for (file, us) in &by_file {
        let mut joined = String::new();
        let mut starts: Vec<(usize, usize)> = Vec::new();
        for (idx, u) in us.iter().enumerate() {
            starts.push((joined.len(), idx));
            joined.push_str(&u.text);
            joined.push('\n');
        }
        for (r, at) in narrative_hits(&joined) {
            let idx = starts.iter().rev().find(|(o, _)| *o <= at).map_or(0, |(_, i)| *i);
            let u = us[idx];
            found
                .entry(file)
                .or_default()
                .push(format!("\x20     {file}:{} [{}]: {}", u.line, NARRATIVE_PHRASES[r].name, u.text.trim()));
        }
    }
    let declared = assert_against_baseline(MarkerClass::Narrative, &found);

    println!(
        "  self-narrative: {files} files walked, {walked} comment lines of {comment_lines} \
         examined ({string_lines} string lines skipped), {} row(s) exercised on constructed \
         text, {} passage(s) in {} file(s) against a baseline of {declared}",
        NARRATIVE_PHRASES.len(),
        found.values().map(Vec::len).sum::<usize>(),
        found.len()
    );
}
