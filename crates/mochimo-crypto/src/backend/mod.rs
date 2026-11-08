// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! Backend selection.
//!
//! There is one backend, [`native`], in pure safe Rust; [`selected`] is an
//! alias for it.
//!
//! [`native`] contains no `unsafe`, which Miri coverage of this crate relies
//! on; `invariants.rs::unsafe_is_confined_to_declared_files` checks it.
//!
//! # Visibility
//!
//! This is not the wallet API; that is [`crate::wots`]. `lib.rs` makes this
//! module `pub` only under the `raw-backend` feature, which only the test
//! targets enable (through the crate's dev-dependency on itself), and
//! `pub(crate)` otherwise. So tests can reach the raw signer through
//! `backend::selected`, while a normal build cannot name this module and the
//! raw signer stays unreachable from outside the crate.

#[cfg(feature = "native")]
pub mod native;

/// The backend every caller uses: an alias for [`native`]. Modules in `src/`
/// import it as `backend`, and `tests/kat.rs` replays the fixtures through
/// it. A few call sites use [`native`] directly where that implementation
/// specifically is required.
#[cfg(feature = "native")]
pub use native as selected;
