// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! The zeroization drop-witness, shared by two test binaries.
//!
//! `tests/invariants.rs` runs it as `secret_bytes_are_gone_after_drop`, and
//! `tests/miri.rs` runs it under Miri to check that the construction is sound.
//!
//! # Why the construction is sound
//!
//! Two simpler versions do not work. Over a local, `drop(x)` moves `x` into
//! the callee, so the zeroing happens in another frame and the kept address
//! still holds the original bytes: a false negative. Over a `Box`, the read
//! is of freed memory, which Miri reports as a dangling pointer.
//!
//! This version owns the storage explicitly:
//!
//!   * `slot` is live for the whole function. `drop_in_place` ends the
//!     object's lifetime but does not deallocate `slot`, so no freed memory
//!     is read.
//!   * `MaybeUninit<T>` never requires its contents to be a valid `T`.
//!   * The bytes read afterwards are initialized: `Zeroizing`'s `Drop` writes
//!     zeros with volatile stores.
//!   * A fresh pointer is derived after the drop, because the `&mut slot`
//!     taken for `drop_in_place` invalidates earlier pointers.
//!
//! # Limits
//!
//!   * It sees one allocation. Compiler copies (register spills, temporaries
//!     from moving the `Secret` into the slot, the caller's `pattern` array)
//!     are not observed.
//!   * It does not cover `expand_seed`'s output buffer or chain
//!     intermediates, which have their own `Zeroizing`.
//!   * It shows that `Drop` cleared this storage, not that no copy of the
//!     secret survives elsewhere in the process.

use core::mem::{size_of, MaybeUninit};

use mochimo_crypto::Secret;

/// What the witness observed. Returned rather than asserted so each caller
/// can report it in its own way.
pub struct DropObservation {
    /// Number of bytes compared.
    pub bytes: usize,
    /// False if the bytes before the drop did not match the pattern, which
    /// means the layout assumption is wrong.
    pub pattern_seen_before_drop: bool,
    pub all_zero_after_drop: bool,
    /// Bytes still matching the pattern after the drop; should be zero.
    pub surviving_pattern_bytes: usize,
}

/// Drop a `Secret` in storage this function owns, and read the storage back.
///
/// The pattern has no zero bytes, so an all-zero result cannot come from
/// bytes that were already zero.
#[must_use]
pub fn observe_secret_drop<const N: usize>() -> DropObservation {
    let pattern: [u8; N] = core::array::from_fn(|i| ((i as u8) ^ 0xa7) | 1);

    // If `Secret` is not exactly N bytes, the reads below look at the wrong
    // bytes; the caller reports that as a layout failure.
    let layout_ok = size_of::<Secret<N>>() == N;

    let mut slot: MaybeUninit<Secret<N>> = MaybeUninit::new(Secret::new(pattern));

    // SAFETY: `slot` holds an initialized `Secret<N>`, whose sole field is a
    // `Zeroizing<[u8; N]>`: all bytes initialized, no padding. Reading them as
    // `[u8; N]` copies initialized memory from storage this function owns.
    let before: [u8; N] = unsafe { core::ptr::read(slot.as_ptr().cast::<[u8; N]>()) };

    // SAFETY: `slot` holds an initialized `Secret<N>` and has not been dropped.
    // This ends the object's lifetime; `slot`'s storage stays owned by this
    // frame.
    unsafe { core::ptr::drop_in_place(slot.as_mut_ptr()) };

    // SAFETY: a fresh pointer, derived after the `&mut` above. The storage is
    // still owned here, and `Zeroizing`'s volatile zeroing wrote all N bytes,
    // so they are initialized.
    let after: [u8; N] = unsafe { core::ptr::read(slot.as_ptr().cast::<[u8; N]>()) };

    DropObservation {
        bytes: N,
        pattern_seen_before_drop: layout_ok && before == pattern,
        all_zero_after_drop: after.iter().all(|&b| b == 0),
        surviving_pattern_bytes: (0..N).filter(|&i| after[i] == pattern[i]).count(),
    }
}
