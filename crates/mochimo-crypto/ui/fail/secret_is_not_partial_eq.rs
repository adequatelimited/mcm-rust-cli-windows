// `Secret` cannot be compared with `==`, and this is the only thing that says so.
//
// `secret.rs` states the rule in prose: a derived comparison over key material
// is variable-time and short-circuits on the first differing byte, so a `==`
// that returns `false` leaks how many leading bytes matched. Prose is not
// enforcement. A `#[derive(PartialEq)]` on `Secret` is a one-word change, it
// would compile, every existing test would stay green, and no runtime assertion
// can observe the difference -- the property being asserted here is that a
// program *does not build*.
//
// Both operands are the same length and the same type, so the only thing that
// can reject this line is the missing trait. The expected stderr must name
// `Secret` and `PartialEq`; a failure for any other reason -- a typo, a moved
// import, a changed constructor signature -- means this file stopped testing
// what it claims to, and the pinned `.stderr` is what turns that into a red.
//
// The remedy this rule steers toward is `subtle::ConstantTimeEq`, NOT a derived
// `PartialEq`. Note before reaching for it that
// `secret_has_no_equality_and_nothing_enforces_it`'s anchor bans the substring
// `"Eq"` in `secret.rs`, and `"ConstantTimeEq"` contains it; that collision is
// recorded on the marker itself. It is a defect in the
// check, not a reason to avoid the trait.
//
// ---------------------------------------------------------------------------
// What actually enforces this, measured rather than assumed
// ---------------------------------------------------------------------------
//
// The rule is that a check says what enforces its property, and says so when
// the check itself is not it. Four faults were injected and each was
// watched at two named tests rather than at a whole target -- `invariants.rs`
// is red anyway from the markers still owed, so a target-level exit code would
// have reported all four as "detected" including one that changed nothing:
//
//   injected                          trybuild   the marker
//   --------------------------------  --------   ----------
//   1  Secret derives PartialEq         RED         RED
//   2  .stderr stops naming PartialEq   RED        green
//   3  this file stops comparing        RED        green
//   4  this file deleted                RED         RED
//
// Row 1 is the property being broken, and both halves catch it. Rows 2 and 3
// are the case *decaying into a case that proves nothing*, and the marker does
// not catch either: it is cleared by this file and a `.stderr` existing, which
// is a statement about the filesystem, not about what either contains.
//
// So the marker is the reminder and **trybuild is the enforcement.** The pinned
// `.stderr` is the part that carries the weight, because a `compile_fail` case
// passes on any compilation failure whatsoever -- rows 2 and 3 both still fail
// to compile, and both are caught only because the recorded output no longer
// matches.
//
// Row 4 is why `tests/compile_fail.rs` censuses `ui/fail` by subject rather
// than by count: deleting this file turns the marker red, where a bare
// `fails.len() >= 4` over the directory would stay green with the count made
// up by unrelated cases.

fn main() {
    let a = mochimo_crypto::Secret::<32>::new([0u8; 32]);
    let b = mochimo_crypto::Secret::<32>::new([1u8; 32]);
    let _ = a == b;
}
