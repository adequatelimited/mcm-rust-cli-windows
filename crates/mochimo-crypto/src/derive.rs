// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! Seed derivation: a master seed and an account index to an account's
//! secret, its permanent tag and its first WOTS+ key.
//!
//! This reproduces, byte for byte, the scheme the Mochimo browser extension
//! uses. Which scheme a wallet implements decides whose funds a recovery
//! phrase reaches.
//!
//! # What this is checked against
//!
//! Group F (`fixtures/group_f_derivation.json`) records the extension's own
//! code executed over fixed inputs. Agreement proves this port matches the
//! extension, not that the extension is correct. The C reference wallet
//! derives keys by an unrelated scheme, so there is no reference counterpart.
//! Coverage is the group F known-answer tests, the three vectors for the
//! conventions below, boundary enumeration (`tests/derive.rs`), and fault
//! injection on every convention in this file.
//!
//! # The scheme
//!
//! `deriveSeed(seed, id)`: `SHA-512(seed ‖ intToBytes(id))` is fed as seed
//! material to a fresh [`DigestRandomGenerator`], which then draws the 32-byte
//! WOTS+ secret. The generator continues: the same stream supplies the 2208
//! bytes `generateRandomAddress` asks for, of which bytes `2144..2176` become
//! the WOTS+ public seed and `2176..2208` the hash address, read as eight
//! little-endian words. `wots_pkgen(secret, pub_seed, adrs)` then gives the
//! public key; the v3 address hash is over those 2144 bytes alone.
//!
//! An account is `deriveSeed(master, account_index)`; its tag is the tag half
//! of the implicit address of that first key. A rotation is
//! `deriveSeed(account_seed, rotation)` through the same construction. This
//! crate's [`crate::account::WotsIndex`] is the extension's index plus one.
//!
//! # Three conventions that coexist in one scheme
//!
//! Each is reproduced deliberately and pinned by its own vector:
//!
//! 1. **Two integer encodings.** [`index_bytes`] is four bytes big-endian
//!    (`intToBytes`) and carries the account or rotation index;
//!    [`counter_bytes`] is four bytes little-endian in an eight-byte buffer
//!    (`digestAddCounter`) and carries the generator's counters. Using one
//!    convention for both produces valid-looking, wrong keys.
//!    `F-counter-endianness`.
//! 2. **The seed cycles on the ninth call, not the tenth.** `stateCounter`
//!    starts at 1 and is post-incremented, so the `% 10 == 0` test first
//!    passes when the counter entering the call was 9. `F-prng-cycle-phase`.
//! 3. **Chunking is visible.** `nextBytes(n)` runs `ceil(n / 64)` whole states
//!    and discards what the last did not need; two calls of 32 are not one
//!    call of 64. `F-prng-chunking`.
//!
//! `WOTSWallet.componentsGenerator`'s ASCII round-trip, which corrupts bytes
//! ≥ 0x80, is not ported: both live entry points pass a random generator to
//! `WOTSWallet.create` and never reach it.
//!
//! # Secrets
//!
//! The generator's state and seed are derived from key material and can
//! reproduce every downstream key, so both are `Zeroizing` and `Debug`
//! redacts them. [`DerivedSeed`], [`WotsKey`] and [`DerivedAccount`] hold a
//! [`Secret`] and implement `Debug` by hand for the same reason.
//!
//! Slice indexing and `copy_from_slice` in this file use only constant
//! layout widths (or chunks of at most 64 bytes), so they cannot panic.

use core::fmt;

use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

use crate::account::StreamId;
use crate::addr::{self, Address, Tag};
use crate::consts::{ADDR_TAG_LEN, PK_LEN, SEED_LEN, WOTS_ADDR_LEN};
use crate::secret::Secret;
use crate::wots::{self, Adrs, PublicKey};

/// SHA-512's output width, which is also the generator's state and seed width
/// (both buffers are 64 zero bytes).
const STATE_LEN: usize = 64;

/// The legacy 12-byte tag's width and position: the last twelve bytes of a
/// 2208-byte address.
const LEGACY_TAG_LEN: usize = 12;

/// `intToBytes(id)`: four bytes, big-endian.
///
/// Carries the account index into `deriveSeed` and the rotation index into
/// `deriveWotsSeedAndAddress`. JS `>>` treats the value as a 32-bit integer,
/// so a `u32` covers every value the extension can produce (its `-1` is
/// `u32::MAX` here).
#[must_use]
pub fn index_bytes(id: u32) -> [u8; 4] {
    id.to_be_bytes()
}

/// `digestAddCounter(counter)`: the low 32 bits little-endian, then four
/// zero bytes.
///
/// `u64` because the extension's counters are JS numbers that never wrap;
/// the `as u32` matches JS's ToUint32 truncation (a wrap needs 2^32 states,
/// 256 GiB of output).
#[must_use]
pub fn counter_bytes(counter: u64) -> [u8; 8] {
    let low = (counter as u32).to_le_bytes();
    [low[0], low[1], low[2], low[3], 0, 0, 0, 0]
}

fn sha512(parts: &[&[u8]]) -> [u8; STATE_LEN] {
    let mut h = Sha512::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// The extension's `DigestRandomGenerator`, a BouncyCastle-style digest PRNG
/// over SHA-512.
///
/// Both buffers start as 64 zero bytes and both counters at 1.
pub struct DigestRandomGenerator {
    seed: Zeroizing<[u8; STATE_LEN]>,
    state: Zeroizing<[u8; STATE_LEN]>,
    /// `stateCounter`, read before increment.
    state_counter: u64,
    /// `seedCounter`, read before increment.
    seed_counter: u64,
}

impl DigestRandomGenerator {
    /// `CYCLE_COUNT`.
    pub const CYCLE_COUNT: u64 = 10;

    /// A fresh generator: zero state, zero seed, both counters at 1.
    #[must_use]
    pub fn new() -> Self {
        DigestRandomGenerator {
            seed: Zeroizing::new([0u8; STATE_LEN]),
            state: Zeroizing::new([0u8; STATE_LEN]),
            state_counter: 1,
            seed_counter: 1,
        }
    }

    /// `cycleSeed()`: `seed = SHA-512(seed ‖ counter_bytes(seedCounter++))`.
    fn cycle_seed(&mut self) {
        let ctr = counter_bytes(self.seed_counter);
        self.seed_counter = self.seed_counter.wrapping_add(1);
        *self.seed = sha512(&[&*self.seed, &ctr]);
    }

    /// `generateState()`:
    /// `state = SHA-512(counter_bytes(stateCounter++) ‖ state ‖ seed)`, then
    /// the cycle test on the incremented counter.
    fn generate_state(&mut self) {
        let ctr = counter_bytes(self.state_counter);
        self.state_counter = self.state_counter.wrapping_add(1);
        *self.state = sha512(&[&ctr, &*self.state, &*self.seed]);
        if self.state_counter.is_multiple_of(Self::CYCLE_COUNT) {
            self.cycle_seed();
        }
    }

    /// `addSeedMaterial(m)`: `seed = SHA-512(m ‖ seed)`, material first.
    pub fn add_seed_material(&mut self, material: &[u8]) {
        *self.seed = sha512(&[material, &*self.seed]);
    }

    /// `nextBytes(out.len())`: one fresh state per 64-byte chunk, the unused
    /// tail of the last state discarded rather than buffered.
    pub fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(STATE_LEN) {
            self.generate_state();
            chunk.copy_from_slice(&self.state[..chunk.len()]);
        }
    }

    /// How many times the seed has cycled.
    #[must_use]
    pub fn seed_cycles(&self) -> u64 {
        self.seed_counter.saturating_sub(1)
    }

    /// How many states have been generated so far.
    #[must_use]
    pub fn states_generated(&self) -> u64 {
        self.state_counter.saturating_sub(1)
    }
}

impl Default for DigestRandomGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for DigestRandomGenerator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DigestRandomGenerator")
            .field("states_generated", &self.states_generated())
            .field("seed_cycles", &self.seed_cycles())
            .field("state", &"<redacted>")
            .field("seed", &"<redacted>")
            .finish()
    }
}

/// What `deriveSeed` returns: the 32-byte secret and the generator as it was
/// left, which the first-key construction keeps drawing from.
pub struct DerivedSeed {
    secret: Secret<SEED_LEN>,
    prng: DigestRandomGenerator,
}

impl DerivedSeed {
    /// The 32-byte secret the generator produced first.
    #[must_use]
    pub fn secret(&self) -> &Secret<SEED_LEN> {
        &self.secret
    }

    /// Take the secret and the continuing generator apart.
    #[must_use]
    pub fn into_parts(self) -> (Secret<SEED_LEN>, DigestRandomGenerator) {
        (self.secret, self.prng)
    }
}

impl fmt::Debug for DerivedSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DerivedSeed")
            .field("secret", &self.secret)
            .field("prng", &self.prng)
            .finish()
    }
}

/// `Derivation.deriveSeed(seed, id)`.
///
/// `SHA-512(seed ‖ index_bytes(id))` → a fresh generator's seed material →
/// 32 bytes drawn. `seed` is a slice because the function is called with both
/// a master seed and an account seed (32 bytes each in practice).
#[must_use]
pub fn derive_seed(seed: &[u8], id: u32) -> DerivedSeed {
    let local = Zeroizing::new(sha512(&[seed, &index_bytes(id)]));
    let mut prng = DigestRandomGenerator::new();
    prng.add_seed_material(&*local);
    let mut secret = Zeroizing::new([0u8; SEED_LEN]);
    prng.fill(&mut *secret);
    DerivedSeed {
        secret: Secret::new(*secret),
        prng,
    }
}

/// A WOTS+ key as the extension constructs one: the secret, the public seed
/// and hash address the generator supplied, and the public key they produce.
pub struct WotsKey {
    secret: Secret<SEED_LEN>,
    pub_seed: [u8; SEED_LEN],
    /// The words `wots_pkgen` started from: the generator's bytes as a
    /// little-endian image. Signing re-runs the same addressing from here.
    adrs: Adrs,
    pk: PublicKey,
}

impl WotsKey {
    /// The signing secret.
    #[must_use]
    pub fn secret(&self) -> &Secret<SEED_LEN> {
        &self.secret
    }

    /// The public seed: generator bytes `2144..2176`.
    #[must_use]
    pub fn pub_seed(&self) -> &[u8; SEED_LEN] {
        &self.pub_seed
    }

    /// The hash address `wots_pkgen` started from: generator bytes
    /// `2176..2208` as eight little-endian words.
    #[must_use]
    pub fn adrs(&self) -> Adrs {
        self.adrs
    }

    /// The 2144-byte WOTS+ public key.
    #[must_use]
    pub fn public_key(&self) -> &[u8; PK_LEN] {
        &self.pk
    }

    /// `addr_from_wots(pk)`: the implicit v3 address, tag half equal to hash
    /// half. For an account's first key, its tag half is the account tag.
    #[must_use]
    pub fn implicit_address(&self) -> Address {
        addr::from_wots(&self.pk)
    }

    /// The tag half of [`WotsKey::implicit_address`].
    #[must_use]
    pub fn tag(&self) -> Tag {
        let mut tag = [0u8; ADDR_TAG_LEN];
        tag.copy_from_slice(addr::tag_of(&self.implicit_address()));
        tag
    }

    /// The 40-byte v3 address under an account tag: `tag ‖ hash_of(pk)`, which
    /// is what `deriveWotsSeedAndAddress` returns as `address`
    /// (`WotsAddress.setTag` then `bytes()[..40]`).
    #[must_use]
    pub fn address(&self, tag: &Tag) -> Address {
        let implicit = self.implicit_address();
        let mut out = [0u8; ADDR_TAG_LEN * 2];
        out[..ADDR_TAG_LEN].copy_from_slice(tag);
        out[ADDR_TAG_LEN..].copy_from_slice(addr::hash_of(&implicit));
        out
    }

    /// The 2208-byte legacy address `generateRandomAddress` returns:
    /// `pk ‖ pub_seed ‖ adrs`, with the twelve-byte tag overlaid on the last
    /// twelve bytes.
    ///
    /// `wots_pkgen` mutates only address words 5, 6 and 7, which are exactly
    /// the bytes `2196..2208` the overlay covers, so the pre- and post-pkgen
    /// images agree on every remaining byte.
    #[must_use]
    pub fn legacy_address(&self, tag12: &[u8; LEGACY_TAG_LEN]) -> Box<[u8; WOTS_ADDR_LEN]> {
        let mut out = Box::new([0u8; WOTS_ADDR_LEN]);
        out[..PK_LEN].copy_from_slice(&self.pk[..]);
        out[PK_LEN..PK_LEN + SEED_LEN].copy_from_slice(&self.pub_seed);
        out[PK_LEN + SEED_LEN..].copy_from_slice(&self.adrs.le_image());
        out[WOTS_ADDR_LEN - LEGACY_TAG_LEN..].copy_from_slice(tag12);
        out
    }
}

impl fmt::Debug for WotsKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WotsKey")
            .field("secret", &self.secret)
            .field("pub_seed", &"<redacted>")
            .field("adrs", &"<redacted>")
            .field("tag", &TagHex(self.tag()))
            .finish()
    }
}

/// The first-key construction: `WOTSWallet.create(name, secret, v3tag,
/// generator)` → `WOTS.generateRandomAddress`, driven by the generator
/// `deriveSeed` left behind.
///
/// The generator fills a 2208-byte buffer in one call (35 states, the last
/// 32 bytes of the 35th discarded); `pub_seed` is bytes `2144..2176`, the
/// address words are `2176..2208`, and `wots_pkgen` writes the public key
/// over `0..2144`. The 12-byte tag never reaches the public key, so
/// `deriveAccountTag`'s key and `deriveAccount`'s first address are the same
/// key under two tags.
#[must_use]
pub fn first_key(derived: DerivedSeed) -> WotsKey {
    let (secret, mut prng) = derived.into_parts();
    let mut buf = Zeroizing::new([0u8; WOTS_ADDR_LEN]);
    prng.fill(&mut *buf);

    let mut pub_seed = [0u8; SEED_LEN];
    pub_seed.copy_from_slice(&buf[PK_LEN..PK_LEN + SEED_LEN]);
    let mut image = [0u8; 32];
    image.copy_from_slice(&buf[PK_LEN + SEED_LEN..WOTS_ADDR_LEN]);
    let adrs = Adrs::from_le_image(&image);

    let mut working = adrs;
    let pk = wots::pkgen(&secret, &pub_seed, &mut working);
    WotsKey {
        secret,
        pub_seed,
        adrs,
        pk,
    }
}

/// The first key rebuilt from stored public components rather than from a
/// generator, as the extension does at `wotsIndex === -1` by copying
/// `faddress` back into the generation buffer.
///
/// This is an imported account's route to position 0, and the reason
/// [`crate::account::Account::import`] takes the 2208-byte address: the
/// components derive from the master seed and cannot be recovered from
/// `secret`. The caller supplies them from a record already verified against
/// the root (`Account::import`, `Account::restore_from_record`), so nothing
/// is re-checked here.
///
/// Produces the same `WotsKey` shape as [`first_key`], so both account kinds
/// share one signing path.
#[must_use]
pub fn first_key_from_components(
    secret: Secret<SEED_LEN>,
    pub_seed: &[u8; SEED_LEN],
    adrs: Adrs,
) -> WotsKey {
    let mut working = adrs;
    let pk = wots::pkgen(&secret, pub_seed, &mut working);
    WotsKey {
        secret,
        pub_seed: *pub_seed,
        adrs,
        pk,
    }
}

/// `Derivation.deriveAccountTag(master, account_index)`:
/// the tag half of the first key's implicit address.
#[must_use]
pub fn derive_account_tag(master: &Secret<SEED_LEN>, account_index: u32) -> Tag {
    first_key(derive_seed(master.expose(), account_index)).tag()
}

/// One rotation of an account's key: `deriveSeed(account_seed, rotation)`
/// through the first-key construction (the key half of
/// `Derivation.deriveWotsSeedAndAddress`).
///
/// `rotation` is the extension's `wotsIndex`, from 0; see
/// [`crate::account::WotsIndex::rotation`]. The tag does not enter the key,
/// so it is not a parameter; the caller applies it with
/// [`WotsKey::address`].
#[must_use]
pub fn derive_wots_key(account_seed: &Secret<SEED_LEN>, rotation: u32) -> WotsKey {
    first_key(derive_seed(account_seed.expose(), rotation))
}

/// The key stream a 32-byte seed defines, identified by the rotation-0
/// public key's hash.
///
/// One seed held under two tags is one key stream with two independent
/// indices, which would let a key sign twice. The identity must be the same
/// for derived and imported accounts and computable from the master
/// ([`crate::account::Account::derive`]) or the root
/// ([`crate::account::Account::import`]).
///
/// Position 0 cannot serve: its public components come from the master's
/// generator for a derived account but from the stored `faddress` for an
/// imported one. Rotation 0 (this crate's [`crate::account::WotsIndex`] 1) is
/// the first key that is a pure function of the seed.
///
/// The value is a public address hash, not a commitment to the secret.
///
/// Costs one WOTS+ key generation (`wots::pkgen`, about 3,000 SHA-256 calls)
/// per account construction.
#[must_use]
pub fn stream_id(seed: &Secret<SEED_LEN>) -> StreamId {
    StreamId::from_bytes(derive_wots_key(seed, 0).tag())
}

/// What `MasterSeed.deriveAccount` returns: the tag,
/// the account seed, and the first key.
pub struct DerivedAccount {
    tag: Tag,
    seed: Secret<SEED_LEN>,
    first: WotsKey,
}

impl DerivedAccount {
    /// The 20-byte account tag.
    #[must_use]
    pub fn tag(&self) -> Tag {
        self.tag
    }

    /// The account seed: the root every rotation derives from.
    #[must_use]
    pub fn seed(&self) -> &Secret<SEED_LEN> {
        &self.seed
    }

    /// The first key — the account's `faddress`, whose secret
    /// is the account seed itself.
    #[must_use]
    pub fn first_key(&self) -> &WotsKey {
        &self.first
    }

    /// Take the three apart.
    #[must_use]
    pub fn into_parts(self) -> (Tag, Secret<SEED_LEN>, WotsKey) {
        (self.tag, self.seed, self.first)
    }
}

impl fmt::Debug for DerivedAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DerivedAccount")
            .field("tag", &TagHex(self.tag))
            .field("seed", &self.seed)
            .field("first", &self.first)
            .finish()
    }
}

/// `MasterSeed.deriveAccount(account_index)`.
///
/// The extension derives twice (`deriveAccountTag`, then `deriveSeed` again
/// for the address) from the same seed material, producing the same key, so
/// one derivation suffices here.
#[must_use]
pub fn derive_account(master: &Secret<SEED_LEN>, account_index: u32) -> DerivedAccount {
    let derived = derive_seed(master.expose(), account_index);
    let seed = derived.secret().duplicate();
    let first = first_key(derived);
    DerivedAccount {
        tag: first.tag(),
        seed,
        first,
    }
}

/// The account seed the Mochimo SDK derives for `account_index`:
/// `Derivation.deriveAccountSeed(master, index)`, the first 32 bytes of
/// `deriveSeed`'s generator.
///
/// This is the scheme of `getAccountFromMasterSeed` in the `mochimo` npm
/// package (2.1.1). It shares the generator with the extension's scheme and
/// nothing after it: the extension continues the generator into a key's
/// public components, while the SDK hashes the secret ([`sdk_wots_key`]). One
/// master seed therefore yields two unrelated wallets under the two schemes.
#[must_use]
pub fn sdk_account_seed(master: &Secret<SEED_LEN>, account_index: u32) -> Secret<SEED_LEN> {
    derive_seed(master.expose(), account_index).secret().duplicate()
}

/// The SDK's spend key `spend` for an account seed:
/// `Derivation.deriveWotsKeypair(account_seed, spend, tag)` without the tag,
/// which the SDK carries beside the key and never feeds into it.
///
/// `secret` is `deriveSeed(account_seed, spend)`'s 32 bytes. The SDK's
/// `componentsGenerator` then gives the WOTS+ private seed
/// `SHA-256(secret ‖ "seed")`, the public seed `SHA-256(secret ‖ "publ")` and
/// the hash address `SHA-256(secret ‖ "addr")` read as eight little-endian
/// words. The SDK's concatenation is byte-exact; unlike the extension's copy,
/// it applies no 7-bit masking.
///
/// Spend 0 is the implicit key: its address hash is the account tag
/// ([`sdk_account_tag`]). The SDK's spend `i` is therefore this crate's
/// position `i`, with no shift.
#[must_use]
pub fn sdk_wots_key(account_seed: &Secret<SEED_LEN>, spend: u32) -> WotsKey {
    let derived = derive_seed(account_seed.expose(), spend);
    let component = |suffix: &[u8; 4]| -> Zeroizing<[u8; SEED_LEN]> {
        let mut input = Zeroizing::new([0u8; SEED_LEN + 4]);
        input[..SEED_LEN].copy_from_slice(derived.secret().expose());
        input[SEED_LEN..].copy_from_slice(suffix);
        Zeroizing::new(crate::backend::selected::sha256(&*input))
    };
    let private = component(b"seed");
    let pub_seed = *component(b"publ");
    let adrs = Adrs::from_le_image(&component(b"addr"));
    first_key_from_components(Secret::new(*private), &pub_seed, adrs)
}

/// The SDK's account tag for an account seed: the address hash of spend 0,
/// which is `Derivation.deriveAccountTag`.
#[must_use]
pub fn sdk_account_tag(account_seed: &Secret<SEED_LEN>) -> Tag {
    sdk_wots_key(account_seed, 0).tag()
}

/// Lowercase hex for a tag in Debug output. Tags are public.
struct TagHex(Tag);

impl fmt::Debug for TagHex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Skipped under Miri, where the key generation in `derive_account` is
    /// too slow; `tests/derive.rs` covers that path under Miri.
    #[cfg(not(miri))]
    #[test]
    fn debug_never_reveals_generator_state_or_secrets() {
        // Non-zero material, so leaked bytes are recognisable.
        let mut g = DigestRandomGenerator::new();
        g.add_seed_material(&[0xA5u8; 32]);
        let mut out = [0u8; 64];
        g.fill(&mut out);
        let rendered = format!("{g:?}");
        assert_eq!(
            rendered,
            "DigestRandomGenerator { states_generated: 1, seed_cycles: 0, \
             state: \"<redacted>\", seed: \"<redacted>\" }"
        );
        let hex_out: String = out.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!rendered.contains(&hex_out[..8]));

        let d = derive_seed(&[0xA5u8; 32], 7);
        let secret_hex: String = d.secret().expose().iter().map(|b| format!("{b:02x}")).collect();
        let rendered = format!("{d:?}");
        assert!(rendered.starts_with("DerivedSeed { secret: Secret<32>(<redacted>), prng: "));
        assert!(!rendered.contains(&secret_hex[..8]));

        let key = first_key(d);
        let rendered = format!("{key:?}");
        assert!(rendered.starts_with("WotsKey { secret: Secret<32>(<redacted>), pub_seed: \"<redacted>\""));
        assert!(!rendered.contains(&secret_hex[..8]));
        let ps: String = key.pub_seed().iter().map(|b| format!("{b:02x}")).collect();
        assert!(!rendered.contains(&ps[..8]));

        let acct = derive_account(&Secret::new([0xA5u8; 32]), 0);
        let rendered = format!("{acct:?}");
        assert!(rendered.starts_with("DerivedAccount { tag: "));
        assert!(rendered.contains("seed: Secret<32>(<redacted>)"));
    }

    #[test]
    fn fill_of_zero_bytes_generates_no_state() {
        let mut g = DigestRandomGenerator::new();
        g.fill(&mut []);
        assert_eq!(g.states_generated(), 0);
        let mut one = [0u8; 1];
        g.fill(&mut one);
        assert_eq!(g.states_generated(), 1);
    }
}
