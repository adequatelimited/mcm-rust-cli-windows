// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! Safe Rust API for the Mochimo cryptographic primitives.
//!
//! Every operation delegates to [`backend::native`] through the alias
//! [`backend::selected`]. That module is pure safe Rust (no `unsafe`, no C,
//! no linked library) and is held to the protocol by the fixture corpus under
//! `fixtures/`, replayed by `tests/kat.rs`. `docs/specification.md` describes
//! what each fixture group establishes.
//!
//! # Dependencies that contain `unsafe` code
//!
//! The `mesh-https` feature, used by the release binary for TLS, adds
//! `ring`, `rustls`, `rustls-webpki`, `rustls-pki-types`, `webpki-roots`,
//! `untrusted`, `once_cell` and `getrandom`. The layer that parses untrusted
//! input (`rustls-webpki` for X.509 and ASN.1, and `untrusted` beneath it) is
//! pure safe Rust; `ring`'s C and assembly is fixed-size constant-time
//! arithmetic over values that layer has already validated. No test
//! completes a TLS handshake.
//!
//! On every Unix build the keystore holds its directory open through
//! `rustix` (with `linux-raw-sys` on Linux, or `libc` and `errno` on macOS,
//! plus `bitflags`). Their `unsafe` code is system-call wrappers and kernel
//! type definitions. They receive only the store path the operator named, the
//! store's fixed file names, and descriptors this crate opened.

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![deny(unsafe_op_in_unsafe_fn)]
// A doc link that resolves to nothing renders as plain text; only `cargo doc`
// detects it, so it is an error.
#![deny(rustdoc::broken_intra_doc_links)]
// Public docs may link to private items (the crate-private backend,
// `KeyMaterial`, and private helpers such as `Keystore::commit` that explain
// public behaviour). The links are kept so the deny above checks they still
// resolve; this crate ships a binary and is not published as a library.
#![allow(rustdoc::private_intra_doc_links)]

#[cfg(not(feature = "native"))]
compile_error!(
    "no backend selected: mochimo-crypto requires the `native` feature. \
     Building with --no-default-features would silently produce a crate that \
     cannot compute anything."
);

// Platform check. `keystore` has its own for the storage guarantees it
// relies on.
#[cfg(not(unix))]
compile_error!(
    "mochimo-crypto targets Unix, and is built and tested on Linux and macOS. \
     Windows is not a goal. Three interfaces it needs have no portable \
     stand-in here: the keystore's permission model is Unix mode bits and \
     owners -- the store is created 0600 and its directory 0700, and a store \
     whose directory is group- or world-writable, owned by another user or \
     named by a symbolic link is refused, as is a store file owned by another \
     user or readable or writable by group or others, which is a check \
     against another local user rather than a convenience; the password and \
     the recovery phrase are read from /dev/tty by path, so that neither can \
     be piped or redirected; and entropy is read from /dev/urandom. The BSDs \
     have all three and are untested."
);

/// The raw primitives. Public only under the `raw-backend` feature, which the
/// test tree uses; otherwise crate-private, so no dependent can call a raw
/// primitive, in particular the raw WOTS+ signer.
#[cfg(feature = "raw-backend")]
pub mod backend;
/// The raw primitives, crate-private. The module carries every primitive the
/// fixture corpus replays, most unused by the wallet, so dead-code warnings
/// are off.
#[cfg(not(feature = "raw-backend"))]
#[allow(dead_code)]
pub(crate) mod backend;
mod error;

pub mod account;
pub mod addr;
pub mod base58;
pub mod bytes;
pub mod crc16;
#[cfg(feature = "native")]
pub mod derive;
#[cfg(feature = "native")]
pub mod entitlement;
#[cfg(feature = "native")]
pub mod extension_export;
#[cfg(feature = "native")]
pub mod keystore;
#[cfg(feature = "native")]
pub mod mesh;
#[cfg(feature = "native")]
pub mod mnemonic;
#[cfg(feature = "native")]
pub mod cli;
#[cfg(feature = "native")]
pub mod recon;
#[cfg(feature = "native")]
pub mod staking;
#[cfg(feature = "native")]
pub mod wallet;
pub mod net;
pub mod secret;
pub mod tx;
pub mod wots;

pub use error::{errno_name, errno_text, ve2str, Error, Result, TransportKind, Verdict};
pub use secret::Secret;

/// The protocol's constants, as Rust literals.
///
/// Checked against the fixture corpus:
/// `tests/kat.rs::constants_match_the_reference` compares the WOTS+ and
/// address widths with group A's `constants` block, printed from the
/// reference's macros, and `tests/kat.rs::group_e_constants_match_the_reference`
/// does the same for the network constants against group E's.
pub mod consts {
    /// Declares each constant once, as a Rust literal.
    ///
    /// Emits `mod native` and the `pub use` of it.
    macro_rules! declare_consts {
        ($(
            $(#[doc = $doc:literal])*
            $name:ident : $ty:ty = $native:expr;
        )*) => {
            /// The Rust literals.
            pub mod native {
                $($(#[doc = $doc])* pub const $name: $ty = $native;)*
            }

            pub use native::*;
        };
    }

    declare_consts! {
        /// WOTS+ hash output and seed width.
        PARAMSN: usize = 32;
        /// Winternitz parameter.
        WOTSW: usize = 16;
        /// `log2(WOTSW)`.
        WOTSLOGW: usize = 4;
        /// Message chains: `(8 * PARAMSN / WOTSLOGW)`, written as the
        /// expression so it follows `PARAMSN`.
        WOTSLEN1: usize = 8 * PARAMSN / WOTSLOGW;
        /// Checksum chains.
        WOTSLEN2: usize = 3;
        /// `(WOTSLEN1 + WOTSLEN2)`.
        WOTSLEN: usize = WOTSLEN1 + WOTSLEN2;
        /// `(WOTSLEN * PARAMSN)`.
        WOTSSIGBYTES: usize = WOTSLEN * PARAMSN;
        /// Legacy full WOTS+ address length.
        WOTS_ADDR_LEN: usize = 2208;
        /// Full v3 address: a tag then a hash.
        ADDR_LEN: usize = 40;
        /// Address tag.
        ADDR_TAG_LEN: usize = 20;
        /// Address hash.
        ADDR_HASH_LEN: usize = 20;
        /// A destination's optional reference field.
        ADDR_REF_LEN: usize = 16;
        /// Where an address's tag half starts.
        ADDR_TAG_OFF: usize = 0;
        /// Where an address's hash half starts. Stated independently of
        /// `ADDR_TAG_LEN`, although the two are equal.
        ADDR_HASH_OFF: usize = 20;
        /// Digest length of the core hashes.
        HASHLEN: usize = 32;
        SHA256LEN: usize = 32;
        /// SHA3-224.
        SHA3LEN224: usize = 28;
        /// SHA3-256.
        SHA3LEN256: usize = 32;
        /// SHA3-384.
        SHA3LEN384: usize = 48;
        /// SHA3-512.
        SHA3LEN512: usize = 64;
        RIPEMDLEN160: usize = 20;
        CRC16LEN: usize = 2;
        /// The success status code; `c_int`, the type the reference's
        /// validators return.
        VEOK: core::ffi::c_int = 0;
        /// The multi-destination (transfer) transaction-data type.
        TXDAT_MDST: u8 = 0x00;
        /// The proof-of-stake chain's set-delegate type: the payload is one
        /// 20-byte delegate tag, signed by the validator's cold key. See
        /// `consts::pos`.
        TXDAT_SET_DELEGATE: u8 = 0x01;
        /// The proof-of-stake chain's clear-delegate type: an empty payload.
        TXDAT_CLEAR_DELEGATE: u8 = 0x02;
        /// The proof-of-stake chain's claim type: the payload is one
        /// little-endian 64-bit amount released from the entitlement column.
        TXDAT_CLAIM: u8 = 0x06;
        /// The v4.1 stake type: the payload is `MSTAKE` (amount, tier,
        /// network, five reserved bytes).
        TXDAT_STAKE: u8 = 0x0C;
        /// The v4.1 unstake type: the payload is `MUNSTAKE` (network,
        /// fourteen reserved bytes).
        TXDAT_UNSTAKE: u8 = 0x0D;
        /// The v4.1 consent type, which also revokes: the payload is
        /// `MACCEPT`.
        TXDAT_ACCEPT: u8 = 0x0E;
        /// The one signature-algorithm type `tx__init` accepts.
        TXDSA_WOTS: u8 = 0x00;
        /// The minimum transaction fee, in nanoMochimo (`MFEE64` in the
        /// reference). `mdst_val` requires one per destination.
        MFEE: u64 = 500;
    }

    /// The wire-struct sizes, as the reference's `STATIC_ASSERT`s state them.
    ///
    /// Written as the asserted expressions, since the native backend has no
    /// C structs to take `sizeof` of:
    ///
    /// ```text
    /// sizeof(MDST)    == ADDR_REF_LEN + ADDR_TAG_LEN + 8
    /// sizeof(WOTSVAL) == WOTS_SIG_LEN + 32 + 32
    /// sizeof(TXHDR)   == 4 + (ADDR_LEN * 2) + (8 * 4)
    /// sizeof(TXTLR)   == 8 + HASHLEN
    /// ```
    ///
    /// `tests/kat.rs::reference_verdicts_native` and `tests/txwire.rs` check
    /// each against the offsets in `group_d_tx.json`'s layout table.
    pub mod wire {
        use super::{ADDR_LEN, ADDR_REF_LEN, ADDR_TAG_LEN, HASHLEN, SIG_LEN};
        pub const SIZEOF_TXHDR: usize = 4 + (ADDR_LEN * 2) + (8 * 4);
        pub const SIZEOF_MDST: usize = ADDR_REF_LEN + ADDR_TAG_LEN + 8;
        /// `WOTS_SIG_LEN` is this crate's [`SIG_LEN`].
        pub const SIZEOF_WOTSVAL: usize = SIG_LEN + 32 + 32;
        pub const SIZEOF_TXTLR: usize = 8 + HASHLEN;
        /// `sizeof(MSDLG) == ADDR_TAG_LEN`: the set-delegate payload, one
        /// delegate tag.
        pub const SIZEOF_MSDLG: usize = ADDR_TAG_LEN;
        /// `sizeof(MCLAIM) == 8`: the claim payload, one amount.
        pub const SIZEOF_MCLAIM: usize = 8;
        /// `sizeof(MSTAKE) == 16`: amount 8, tier 1, network 2, reserved 5
        /// (`v41.h`).
        pub const SIZEOF_MSTAKE: usize = 8 + 1 + 2 + 5;
        /// `sizeof(MUNSTAKE) == 16`: network 2, reserved 14.
        pub const SIZEOF_MUNSTAKE: usize = 2 + 14;
        /// `sizeof(MACCEPT) == 36`: kind 1, peer 20, action 1, slot 4, ip 4,
        /// port 2, flags 1, network 2, reserved 1.
        pub const SIZEOF_MACCEPT: usize = 1 + ADDR_TAG_LEN + 1 + 4 + 4 + 2 + 1 + 2 + 1;
    }

    /// Proof-of-stake constants.
    ///
    /// `TXDAT_SET_DELEGATE`, `TXDAT_CLEAR_DELEGATE`, `TXDAT_CLAIM`,
    /// `wire::SIZEOF_MSDLG` and `wire::SIZEOF_MCLAIM` come from the
    /// proof-of-stake node's `types.h` and `tx.c`. Fixture group V checks
    /// them: it records each of the three transactions as built by the node's
    /// own `tx_read`, `tx_hash` and `wots_sign`, and `tests/kat.rs` reproduces
    /// every wire image and both digests. `DELEGATE_MIN_BALANCE` is not
    /// checked by any replay.
    pub mod pos {
        /// The minimum balance, in nanoMochimo (one MCM), a delegate tag must
        /// hold for the node to accept a set-delegate naming it. The Mesh API
        /// does not expose this check, so it is shown as a requirement and
        /// never checked.
        pub const DELEGATE_MIN_BALANCE: u64 = 1_000_000_000;
    }

    /// WOTS+ seed, message digest, and public seed width.
    pub const SEED_LEN: usize = PARAMSN;
    /// A WOTS+ public key length (`WOTS_PK_LEN` in the reference).
    pub const PK_LEN: usize = WOTSSIGBYTES;
    /// A WOTS+ signature length (`WOTS_SIG_LEN`); the same value as
    /// [`PK_LEN`].
    pub const SIG_LEN: usize = WOTSSIGBYTES;

    /// The network surface: protocol version, framing marks, ports and
    /// operation codes.
    ///
    /// Typed `u16`/`u8` because each is a wire value of fixed width.
    /// `kat.rs::group_e_constants_match_the_reference` checks every one
    /// against the `constants` block the reference printed into
    /// `fixtures/group_e_net.json`.
    pub mod net {
        declare_consts! {
            /// Protocol version number.
            PVERSION: u16 = 5;
            /// Capability bits for TX.
            CBITS: u16 = 0;
            /// Network TX protocol version.
            TXNETWORK: u16 = 1337;
            /// End-of-transmission id for packets.
            TXEOT: u16 = 0xabcd;
            /// Default TCP listening port.
            PORT1: u16 = 2095;
            /// Secondary port, primarily for testnet.
            PORT2: u16 = 2096;
            /// First valid operation code.
            FIRST_OP: u8 = 3;
            /// Last valid operation code.
            LAST_OP: u8 = 19;
            OP_NULL: u8 = 0;
            OP_HELLO: u8 = 1;
            OP_HELLO_ACK: u8 = 2;
            OP_TX: u8 = 3;
            OP_FOUND: u8 = 4;
            OP_GET_BLOCK: u8 = 5;
            OP_GET_IPL: u8 = 6;
            OP_SEND_FILE: u8 = 7;
            OP_SEND_IPL: u8 = 8;
            OP_BUSY: u8 = 9;
            OP_NACK: u8 = 10;
            OP_GET_TFILE: u8 = 11;
            OP_BALANCE: u8 = 12;
            OP_SEND_BAL: u8 = 13;
            OP_RESOLVE: u8 = 14;
            OP_GET_CBLOCK: u8 = 15;
            OP_MBLOCK: u8 = 16;
            OP_HASH: u8 = 17;
            OP_TF: u8 = 18;
            OP_IDENTIFY: u8 = 19;
        }

        /// `WORD16_MAX` (`WORD16_C(0xFFFF)` in the reference).
        #[must_use]
        pub const fn word16_max() -> u16 {
            word16_max_native()
        }

        /// The native `WORD16_MAX`; [`word16_max`] forwards here.
        #[must_use]
        pub const fn word16_max_native() -> u16 {
            0xFFFF
        }
    }
}
