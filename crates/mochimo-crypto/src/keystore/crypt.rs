// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! The store's encryption at rest: an Argon2id KDF over an operator password
//! and a ChaCha20-Poly1305 AEAD over the record body.
//!
//! # What the security rests on
//!
//! The sealed file holds the master seed and every imported root, so it
//! yields every account to whoever knows the password and nothing to whoever
//! does not. Password strength is part of the threat model, and
//! [`Kdf::RECOMMENDED`]'s parameters are what make each guess expensive.
//!
//! # Pure Rust
//!
//! Both cryptographic crates used here are pure Rust, so no plaintext passes
//! through C code. Nothing in this module uses `backend::selected`.
//!
//! # Entropy is a parameter
//!
//! This crate declares no random-number generator dependency and opens no
//! device. Entropy arrives as arguments (`Init`'s `salt` and `nonce_seed`,
//! `Unlock`'s `nonce_seed`), which the binary fills from `/dev/urandom`.
//! `getrandom` is in the TLS-enabled build's dependency graph, but this crate
//! cannot name a crate it does not declare.
//!
//! This keeps a store image deterministic under fixed entropy, which the
//! format known-answer test, `records_are_addressed_by_tag_not_position` and
//! the crash-consistency test rely on to compare images byte for byte.

use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Salt width: RFC 9106's recommended sixteen bytes. Stored in the header.
pub const SALT_LEN: usize = 16;
/// ChaCha20-Poly1305's nonce is 96 bits.
pub const NONCE_LEN: usize = 12;
/// Poly1305's tag.
pub const TAG_LEN: usize = 16;
/// The derived key, and ChaCha20's key width.
pub const KEY_LEN: usize = 32;
/// The per-open entropy the nonce is derived from. See [`nonce_for`].
pub const NONCE_SEED_LEN: usize = 32;

/// The KDF identifier written into the header. Checked before use, so a file
/// naming an unknown KDF reports `UnsupportedVersion`.
pub(crate) const KDF_ARGON2ID_V13: u8 = 1;

/// The largest `m_cost` this build accepts from a file, in KiB (1 GiB).
///
/// `m_cost` sizes an allocation and comes from a file that may be hostile,
/// so it is bounded before anything is allocated. The bound leaves room to
/// raise [`Kdf::RECOMMENDED`] sixteen-fold without a format change.
pub(crate) const MAX_M_COST_KIB: u32 = 1024 * 1024;

/// The most passes this build accepts from a file.
pub(crate) const MAX_T_COST: u32 = 64;

/// The most lanes this build accepts from a file. The lanes run one after
/// another (`argon2` is built without threads), so more of them only add
/// overhead.
pub(crate) const MAX_P_COST: u32 = 16;

/// The most work this build accepts from a file, as `m_cost_kib * t_cost`:
/// 64 passes over 64 MiB, or 4 passes over 1 GiB. About one and a half
/// seconds on a current laptop.
///
/// The header is read before the key exists, so its costs are not
/// authenticated when the derivation runs. Bounding the work keeps a
/// tampered header to a refusal within seconds rather than a derivation
/// that never ends.
pub(crate) const MAX_WORK_KIB: u64 = 64 * 65536;

/// The KDF parameters, as the header carries them.
///
/// Stored in the file, so new stores can use stronger parameters while
/// existing stores keep opening. A file with tampered parameters fails in one
/// of two ways:
///
/// * above [`MAX_M_COST_KIB`], [`MAX_T_COST`], [`MAX_P_COST`] or
///   [`MAX_WORK_KIB`]: refused by [`Kdf::checked`] as `Range` before anything
///   is allocated or derived;
/// * in bounds: derives a different key, so decryption fails as a wrong
///   password.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kdf {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Kdf {
    /// The parameters for a new store: 64 MiB, three passes, one lane.
    ///
    /// Memory and passes follow RFC 9106's second recommended option.
    /// Parallelism is 1 rather than 4 because `argon2` is built without
    /// threads: extra lanes would run sequentially, costing the defender the
    /// same time while an attacker with more cores runs them in parallel.
    /// About 70 ms per command in a release build on a current laptop.
    ///
    /// Applies to new stores only; an existing store uses its own header.
    pub const RECOMMENDED: Kdf = Kdf {
        m_cost_kib: 65536,
        t_cost: 3,
        p_cost: 1,
    };

    /// The cheapest parameters Argon2 accepts, for tests only. The binary
    /// always uses [`Kdf::RECOMMENDED`].
    pub const CHEAP_FOR_TESTS: Kdf = Kdf {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    };

    /// Refuse parameters this build will not honour, before anything is
    /// allocated or derived.
    ///
    /// The ceilings are [`MAX_M_COST_KIB`], [`MAX_P_COST`], and for `t_cost`
    /// the smaller of [`MAX_T_COST`] and [`MAX_WORK_KIB`] divided by
    /// `m_cost_kib`. `argon2::Params::new` enforces the floors
    /// (`Params::MIN_M_COST`, 8 KiB, one pass, one lane). Its refusal is
    /// mapped to the parameter it names, with that parameter's value as
    /// `got`.
    ///
    /// # Errors
    ///
    /// [`Error::Range`] naming the offending parameter.
    pub fn checked(self) -> Result<Kdf> {
        use argon2::Params;
        if self.m_cost_kib > MAX_M_COST_KIB {
            return Err(Error::Range {
                what: "keystore kdf m_cost",
                min: u64::from(Params::MIN_M_COST),
                max: u64::from(MAX_M_COST_KIB),
                got: u64::from(self.m_cost_kib),
            });
        }
        let max_t_cost =
            (MAX_WORK_KIB / u64::from(self.m_cost_kib.max(1))).min(u64::from(MAX_T_COST));
        if u64::from(self.t_cost) > max_t_cost {
            return Err(Error::Range {
                what: "keystore kdf t_cost",
                min: u64::from(Params::MIN_T_COST),
                max: max_t_cost,
                got: u64::from(self.t_cost),
            });
        }
        if self.p_cost > MAX_P_COST {
            return Err(Error::Range {
                what: "keystore kdf p_cost",
                min: u64::from(Params::MIN_P_COST),
                max: u64::from(MAX_P_COST),
                got: u64::from(self.p_cost),
            });
        }
        Params::new(self.m_cost_kib, self.t_cost, self.p_cost, Some(KEY_LEN)).map_err(|e| match e {
            argon2::Error::MemoryTooLittle | argon2::Error::MemoryTooMuch => Error::Range {
                what: "keystore kdf m_cost",
                min: u64::from(Params::MIN_M_COST),
                max: u64::from(MAX_M_COST_KIB),
                got: u64::from(self.m_cost_kib),
            },
            argon2::Error::TimeTooSmall => Error::Range {
                what: "keystore kdf t_cost",
                min: u64::from(Params::MIN_T_COST),
                max: max_t_cost,
                got: u64::from(self.t_cost),
            },
            argon2::Error::ThreadsTooFew | argon2::Error::ThreadsTooMany => Error::Range {
                what: "keystore kdf p_cost",
                min: u64::from(Params::MIN_P_COST),
                max: u64::from(MAX_P_COST),
                got: u64::from(self.p_cost),
            },
            _ => Error::Range {
                what: "keystore kdf parameters",
                min: 0,
                max: u64::from(MAX_M_COST_KIB),
                got: u64::from(self.m_cost_kib),
            },
        })?;
        Ok(self)
    }
}

/// The Argon2 variant and version, named only here. [`argon2id_v13`] is a
/// single straight-line path, so the RFC 9106 §5.3 test vector
/// (`format::tests::argon2id_v13_matches_the_rfc9106_vector`) exercises the
/// same code as every store's key derivation.
const ALGORITHM: argon2::Algorithm = argon2::Algorithm::Argon2id;
const VERSION: argon2::Version = argon2::Version::V0x13;

/// Argon2id v1.3 into `out`: the only place a [`Kdf`] becomes hashing
/// parameters. [`Kdf::checked`] maps the same three fields, but only to
/// refuse them; keep the two in the same order.
///
/// [`derive_key`] calls this with an empty secret and no associated data.
/// The secret and associated-data parameters exist so the RFC 9106 §5.3
/// vector, which uses both, is replayed through this same function.
///
/// [`Kdf::checked`] runs first, so parameters above its ceilings are refused
/// before the block buffer `m_cost` sizes is allocated. The working memory
/// is `Zeroizing`, so Argon2's password-derived blocks are cleared on drop.
///
/// # Errors
///
/// [`Error::Range`] for out-of-range parameters, secret, associated data or
/// output length; [`Error::Io`] with `OutOfMemory` if the block buffer cannot
/// be allocated; [`Error::Corrupt`] if hashing fails.
pub(crate) fn argon2id_v13(
    kdf: Kdf,
    secret: &[u8],
    associated_data: &[u8],
    password: &[u8],
    salt: &[u8],
    out: &mut [u8],
) -> Result<()> {
    let kdf = kdf.checked()?;
    let data = argon2::AssociatedData::new(associated_data).map_err(|_| Error::Range {
        what: "keystore kdf associated data",
        min: 0,
        max: argon2::Params::MAX_DATA_LEN as u64,
        got: associated_data.len() as u64,
    })?;
    let mut builder = argon2::ParamsBuilder::new();
    builder
        .m_cost(kdf.m_cost_kib)
        .t_cost(kdf.t_cost)
        .p_cost(kdf.p_cost)
        .output_len(out.len())
        .data(data);
    // `checked` has already run `Params::new` over m, t and p, so the only
    // thing left for `build` to refuse is the output length.
    let params = builder.build().map_err(|_| Error::Range {
        what: "keystore kdf output length",
        min: argon2::Params::MIN_OUTPUT_LEN as u64,
        max: argon2::Params::MAX_OUTPUT_LEN as u64,
        got: out.len() as u64,
    })?;
    // Reserved fallibly, so a machine that cannot provide the memory gets a
    // refusal instead of an aborted process.
    let mut blocks: Zeroizing<Vec<argon2::Block>> = Zeroizing::new(Vec::new());
    blocks
        .try_reserve_exact(params.block_count())
        .map_err(|_| Error::Io {
            op: "allocate key derivation memory",
            kind: std::io::ErrorKind::OutOfMemory,
        })?;
    blocks.resize(params.block_count(), argon2::Block::default());
    // One constructor for both callers: with an empty secret,
    // `new_with_secret` hashes the same bytes as `Argon2::new`.
    let hasher = argon2::Argon2::new_with_secret(secret, ALGORITHM, VERSION, params).map_err(|_| {
        Error::Range {
            what: "keystore kdf secret",
            min: 0,
            max: argon2::MAX_SECRET_LEN as u64,
            got: secret.len() as u64,
        }
    })?;
    hasher
        .hash_password_into_with_memory(password, salt, out, &mut blocks)
        .map_err(|_| Error::Corrupt {
            what: "key derivation",
            offset: 0,
        })
}

/// Derive the store key from a password and the header's salt.
///
/// Called once per open, with the result held in `Zeroizing`, so the KDF
/// cost is not paid on every commit. This is [`argon2id_v13`] with an empty
/// secret and no associated data.
///
/// # Errors
///
/// As [`argon2id_v13`].
pub(crate) fn derive_key(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    kdf: Kdf,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let mut key: Zeroizing<[u8; KEY_LEN]> = Zeroizing::new([0u8; KEY_LEN]);
    argon2id_v13(kdf, &[], &[], password, salt, key.as_mut())?;
    Ok(key)
}

/// The nonce for one commit: `sha3_256(seed || generation)` truncated to
/// twelve bytes.
///
/// ChaCha20-Poly1305 fails catastrophically on nonce reuse. The generation
/// alone is not enough: two copies of a store (for example a restored
/// backup) share a salt, and so a key, and can advance from the same
/// generation with different contents. This crate takes no per-write
/// randomness (see the module docs), so 32 bytes of entropy are supplied once
/// per open. Separate opens get different seeds, and within one open the
/// generation strictly increases, so the input never repeats. A constant
/// seed, as tests use, gives deterministic nonces.
pub(crate) fn nonce_for(seed: &[u8; NONCE_SEED_LEN], generation: u64) -> [u8; NONCE_LEN] {
    let mut input = [0u8; NONCE_SEED_LEN + 8];
    let (head, tail) = input.split_at_mut(NONCE_SEED_LEN);
    head.copy_from_slice(seed);
    tail.copy_from_slice(&generation.to_le_bytes());
    let digest = crate::backend::native::sha3_256(&input);
    let mut nonce = [0u8; NONCE_LEN];
    // Always matches (32-byte digest, 12-byte nonce). `if let` rather than
    // `expect` avoids a panic path; the unreachable else would leave a zero
    // nonce, which round-trip tests would catch.
    if let Some((head, _)) = digest.split_first_chunk::<NONCE_LEN>() {
        nonce.copy_from_slice(head);
    }
    nonce
}

/// Encrypt `plaintext` in place and return the tag. `aad` is the header.
pub(crate) fn seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &mut [u8],
) -> Result<[u8; TAG_LEN]> {
    use chacha20poly1305::aead::AeadInPlace;
    use chacha20poly1305::KeyInit;
    let cipher = chacha20poly1305::ChaCha20Poly1305::new(key.into());
    let tag = cipher
        .encrypt_in_place_detached(nonce.into(), aad, plaintext)
        .map_err(|_| Error::Corrupt {
            what: "keystore encryption",
            offset: 0,
        })?;
    let mut out = [0u8; TAG_LEN];
    out.copy_from_slice(&tag);
    Ok(out)
}

/// Decrypt `ciphertext` in place.
///
/// # Errors
///
/// [`Error::WrongPassword`] for any failure. A wrong password, a flipped bit
/// and a tampered header all produce the same tag mismatch; distinguishing
/// them would be a decryption oracle.
pub(crate) fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &mut [u8],
    tag: &[u8; TAG_LEN],
) -> Result<()> {
    use chacha20poly1305::aead::AeadInPlace;
    use chacha20poly1305::KeyInit;
    let cipher = chacha20poly1305::ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt_in_place_detached(nonce.into(), aad, ciphertext, tag.into())
        .map_err(|_| Error::WrongPassword)
}
