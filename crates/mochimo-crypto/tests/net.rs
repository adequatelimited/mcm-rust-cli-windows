// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! `valid_op` over its entire input domain.
//!
//! `mochimo_crypto::net::valid_op` is restated in Rust rather than checked
//! against fixtures: it is a macro inside the reference's `network.c`, and
//! fixture group E records only the opcode constants, not the predicate.
//!
//! So this file enumerates every input, with the expectation written in terms
//! of `FIRST_OP` and `LAST_OP` rather than literals. Those constants are
//! checked against group E by `kat.rs::group_e_constants_match_the_reference`,
//! so a change to the reference range is followed here. The predicate is
//! listed in `kat.rs::WEAKLY_ANCHORED`.

use mochimo_crypto::consts::net::{FIRST_OP, LAST_OP};
use mochimo_crypto::net::valid_op;

/// An empty range would let the enumeration below pass while `valid_op`
/// rejected everything. Checked at compile time since both operands are
/// constants.
const _: () = assert!(
    FIRST_OP <= LAST_OP,
    "FIRST_OP exceeds LAST_OP: the opcode range is empty"
);

/// Every `u8` value.
#[test]
// Written in the same shape as the C macro, not as a range expression, so the
// two can be compared side by side.
#[allow(clippy::manual_range_contains)]
fn valid_op_agrees_with_its_bounds_over_the_entire_domain() {
    let mut accepted = 0usize;

    for op in u8::MIN..=u8::MAX {
        // Uses the bound constants, not literals, so the test has no second
        // copy of the range.
        let expected = op >= FIRST_OP && op <= LAST_OP;
        assert_eq!(
            valid_op(op),
            expected,
            "valid_op({op}) is {}, but FIRST_OP = {FIRST_OP} and LAST_OP = \
             {LAST_OP} make it {expected}",
            valid_op(op)
        );
        if expected {
            accepted += 1;
        }
    }

    // The accepted set must be exactly the closed interval and must not be
    // the whole domain.
    assert_eq!(
        accepted,
        usize::from(LAST_OP - FIRST_OP) + 1,
        "the accepted set is not the closed interval [FIRST_OP, LAST_OP]"
    );
    assert!(
        accepted < 256,
        "valid_op accepts the entire u8 domain, so it distinguishes nothing"
    );

    println!("  valid_op: 256 inputs enumerated, {accepted} accepted ([{FIRST_OP}, {LAST_OP}])");
}

/// Both bounds are inclusive, and the values just outside them are rejected.
/// Separate assertions show which edge failed.
#[test]
fn valid_op_boundaries_are_closed() {
    assert!(valid_op(FIRST_OP), "FIRST_OP itself must be accepted");
    assert!(valid_op(LAST_OP), "LAST_OP itself must be accepted");

    if let Some(below) = FIRST_OP.checked_sub(1) {
        assert!(!valid_op(below), "the value below FIRST_OP must be rejected");
    }
    if let Some(above) = LAST_OP.checked_add(1) {
        assert!(!valid_op(above), "the value above LAST_OP must be rejected");
    }
}

/// Every named opcode in `consts::net` is inside the range except the three
/// pre-handshake codes.
///
/// `valid_op` means "usable after a successful 3-way handshake", so
/// `OP_NULL`, `OP_HELLO` and `OP_HELLO_ACK` must stay outside it.
#[test]
fn handshake_opcodes_are_outside_the_valid_range() {
    use mochimo_crypto::consts::net as k;

    for (name, op) in [
        ("OP_NULL", k::OP_NULL),
        ("OP_HELLO", k::OP_HELLO),
        ("OP_HELLO_ACK", k::OP_HELLO_ACK),
    ] {
        assert!(
            !valid_op(op),
            "{name} ({op}) is inside [{FIRST_OP}, {LAST_OP}]. These three are \
             the pre-handshake codes; valid_op exists to exclude them."
        );
    }

    for (name, op) in [
        ("OP_TX", k::OP_TX),
        ("OP_FOUND", k::OP_FOUND),
        ("OP_GET_BLOCK", k::OP_GET_BLOCK),
        ("OP_GET_IPL", k::OP_GET_IPL),
        ("OP_SEND_FILE", k::OP_SEND_FILE),
        ("OP_SEND_IPL", k::OP_SEND_IPL),
        ("OP_BUSY", k::OP_BUSY),
        ("OP_NACK", k::OP_NACK),
        ("OP_GET_TFILE", k::OP_GET_TFILE),
        ("OP_BALANCE", k::OP_BALANCE),
        ("OP_SEND_BAL", k::OP_SEND_BAL),
        ("OP_RESOLVE", k::OP_RESOLVE),
        ("OP_GET_CBLOCK", k::OP_GET_CBLOCK),
        ("OP_MBLOCK", k::OP_MBLOCK),
        ("OP_HASH", k::OP_HASH),
        ("OP_TF", k::OP_TF),
        ("OP_IDENTIFY", k::OP_IDENTIFY),
    ] {
        assert!(
            valid_op(op),
            "{name} ({op}) is outside [{FIRST_OP}, {LAST_OP}] but is a \
             post-handshake operation code"
        );
    }
}
