// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! Whether an opcode is usable after a successful handshake.
//!
//! [`valid_op`] is restated from the reference rather than checked against a
//! fixture. Its only inputs are `FIRST_OP` and `LAST_OP` in `consts::net`,
//! which `kat.rs::group_e_constants_match_the_reference` checks against
//! fixture group E, so a change to the opcode range moves the predicate and
//! its test together. `docs/specification.md` lists this under *Open items*.

use crate::consts::net::{FIRST_OP, LAST_OP};

/// Whether `op` is an operation code usable after a successful 3-way handshake.
///
/// Mirrors the reference macro:
///
/// ```c
/// #define valid_op(op)  ((op) >= FIRST_OP && (op) <= LAST_OP)
/// ```
///
/// `tests/net.rs` checks every `u8` input.
#[must_use]
// Written as two comparisons, not a range, to match the C macro above.
#[allow(clippy::manual_range_contains)]
pub fn valid_op(op: u8) -> bool {
    op >= FIRST_OP && op <= LAST_OP
}
