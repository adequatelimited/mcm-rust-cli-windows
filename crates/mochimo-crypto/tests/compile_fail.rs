// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

#![cfg(not(miri))]
//! Compile-fail tests: every `ui/fail` case is rejected by rustc for the
//! reason its `.stderr` records, and every `ui/pass` case builds.
//!
//! Excluded under Miri because trybuild spawns `cargo`.
//!
//! The cases enforce at compile time parts of the invariants in
//! `docs/specification.md`: I1 (the raw signer and its internals are
//! unreachable, the receipt is consumed and not `Clone`), I2 and I3 (the
//! advance receipt and `Durable` witness cannot be constructed, the medium
//! steps cannot be reordered), I6 (`Secret` has no equality or ordering), and
//! properties of the account model, keystore and terminal.
//!
//! The cases live in `ui/` rather than `tests/` because source-scanning
//! checks in `tests/invariants.rs` search `tests/` for symbol names, and these
//! files name forbidden symbols on purpose.
//!
//! Each fail case has a checked-in `.stderr`, so a case that fails for an
//! unrelated reason (a typo, a renamed import) is caught. `ui/pass` must
//! compile, so a broken build cannot make every fail case pass at once. Each
//! subject family has its own minimum count, and every case must belong to a
//! family. On failure, trybuild names the offending file.
//!
//! The `.stderr` files pin rustc's exact wording. Regenerate with
//! `TRYBUILD=overwrite cargo test --test compile_fail` and review the diff.

/// Runs the pass and fail cases in one `trybuild` invocation.
#[test]
fn every_ui_case_compiles_or_fails_for_its_pinned_reason() {
    // Check that the cases exist and every fail case has a `.stderr`, since
    // an empty glob would pass.
    let fails = cases("ui/fail");
    let passes = cases("ui/pass");

    // Count cases per subject family, so deleting one case and adding an
    // unrelated one does not go unnoticed.
    let secret_cases = fails
        .iter()
        .filter(|p| stem(p).starts_with("secret_"))
        .count();
    let account_cases = fails
        .iter()
        .filter(|p| stem(p).starts_with("account_"))
        .count();
    let keystore_cases = fails
        .iter()
        .filter(|p| stem(p).starts_with("keystore_") || stem(p).starts_with("durable_") || stem(p).starts_with("medium_"))
        .count();
    let signing_cases = fails
        .iter()
        .filter(|p| stem(p).starts_with("signing_"))
        .count();
    let terminal_cases = fails
        .iter()
        .filter(|p| stem(p).starts_with("terminal_"))
        .count();
    assert!(
        secret_cases >= 3,
        "ui/fail holds {secret_cases} `secret_*` case(s); expected the two \
         comparison families (PartialEq, PartialOrd) and the duplication one \
         (Clone, whose named replacement is `Secret::duplicate`). \
         `secret_has_no_equality_and_nothing_enforces_it` in tests/invariants.rs \
         reports itself cleared when ui/fail/secret_is_not_partial_eq.rs exists \
         with a .stderr beside it; if a case was deleted, that marker is green \
         over nothing and this is the only place that would notice."
    );
    // Account model: no Clone (two spend paths over one index), no Default
    // (an account at index zero from nothing), no struct literal, no
    // writable wots_index (rewinding re-signs a used key), no forgeable
    // AdvanceReceipt, no unverified imported constructor, and an
    // `AccountRecord::Imported` literal must carry its first-key components
    // and stream identity. Copy needs no case: Clone is its supertrait.
    assert!(
        account_cases >= 7,
        "ui/fail holds {account_cases} `account_*` cases; expected the five \
         account-model absences (Clone, Default, struct literal, wots_index \
         write, AdvanceReceipt forgery) plus format v2's two (the unverified \
         imported constructor gone, the imported record's new fields \
         required). If one was deleted, the absence it pinned is one derive \
         or one `pub` away from silently returning."
    );
    // Keystore: no Clone (a second writer), no Default (an empty store from
    // nothing), no forgeable `Durable` witness (a receipt for an advance not
    // on disk), and no reordering of the commit steps (a torn write).
    assert!(
        keystore_cases >= 4,
        "ui/fail holds {keystore_cases} keystore/durable/medium cases; expected the \
         four keystore absences (Clone, Default, Durable forgery, step reorder)."
    );
    // Signing: `wots::sign` and its internals are not reachable, the receipt
    // is consumed by `sign_spend`, and the receipt is not `Clone`.
    // `backend::native::wots_sign` is checked by the downstream probe in
    // tests/signing.rs instead, because trybuild inherits `raw-backend`.
    assert!(
        signing_cases >= 4,
        "ui/fail holds {signing_cases} `signing_*` cases; expected the four signing \
         absences (raw signer private, internals private, receipt consumed, receipt \
         not Clone). If one was deleted, the absence it pinned is one `pub` or one \
         derive away from silently returning."
    );
    // Terminal: `create`'s word confirmation echoes, and
    // `Terminal::read_visible_line` takes `self` so no secret can be read
    // from the terminal afterwards.
    assert!(
        terminal_cases >= 1,
        "ui/fail holds no `terminal_*` case. The claim that no secret read can \
         follow the echoing confirmation is held by ONE `self` in a trait \
         method, and this case is the only thing that would notice it becoming \
         `&mut self` -- after which `create` would compile with the phrase \
         prompt running visibly."
    );
    assert_eq!(
        secret_cases + account_cases + keystore_cases + signing_cases + terminal_cases,
        fails.len(),
        "ui/fail holds {} cases but only {} were recognised by the five \
         subject filters above. An unrecognised case is still compiled by the \
         glob, so it is enforced but uncounted -- give it a floor, or the next \
         deletion is invisible.",
        fails.len(),
        secret_cases + account_cases + keystore_cases + signing_cases + terminal_cases
    );
    assert!(
        !passes.is_empty(),
        "ui/pass is empty. Without a case that must compile, every compile_fail \
         case would pass at the moment nothing in this directory built at all."
    );
    for case in &fails {
        assert!(
            case.with_extension("stderr").is_file(),
            "{} has no .stderr beside it. A compile_fail case without pinned \
             output asserts only that something went wrong -- a typo in the \
             case would satisfy it.",
            case.display()
        );
    }

    // Printed before trybuild runs (on drop of `TestCases`); `invariants.rs`
    // reads this line to confirm the test ran and measured something.
    println!(
        "\x20 compile-fail partition: {} fail case(s) ({secret_cases} secret, \
         {account_cases} account, {keystore_cases} keystore, {signing_cases} signing, \
         {terminal_cases} terminal), {} pass case(s), every fail case with a pinned .stderr",
        fails.len(),
        passes.len()
    );

    let t = trybuild::TestCases::new();

    // Must compile. Registered first so a broken build is reported first.
    t.pass("ui/pass/*.rs");

    // Must not compile, each for the reason its .stderr records.
    t.compile_fail("ui/fail/*.rs");
}

/// A case's file stem, for the per-subject counts.
fn stem(p: &std::path::Path) -> String {
    p.file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// The `.rs` cases in a `ui/` subdirectory, as absolute paths.
fn cases(dir: &str) -> Vec<std::path::PathBuf> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(dir);
    let entries = std::fs::read_dir(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let mut out: Vec<std::path::PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .collect();
    out.sort();
    out
}
