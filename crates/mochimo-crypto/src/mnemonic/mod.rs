// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! BIP39, as the Mochimo browser extension's restore path uses it
//! (`MasterSeed` over `@scure/bip39` 1.5.0).
//!
//! # The master seed
//!
//! `fromPhrase` runs `mnemonicToSeed` (PBKDF2-HMAC-SHA512 over the phrase
//! with salt `"mnemonic" ‖ passphrase`, 2048 rounds, 64 bytes) and keeps the
//! first 32 bytes as the master seed. The mnemonic's entropy is a different
//! value and is not the seed. A seed exported as a phrase via
//! [`phrase_from_seed_as_entropy`] does not restore as itself.
//!
//! [`master_seed_from_phrase`] is the master seed source; using the entropy
//! or any other part of the 64-byte seed would derive different accounts.
//!
//! # Scope
//!
//! English wordlist only ([`english::WORDLIST`]). Input must be ASCII and
//! single-space separated; non-ASCII input is refused rather than
//! NFKD-normalised, since normalisation is the identity for English phrases.
//!
//! PBKDF2 and HMAC are RustCrypto's `pbkdf2` and `hmac`, on the same
//! `digest` 0.10 line as `sha2`. The group F BIP39 vectors check this
//! composition against the extension's library.

pub mod english;

use core::fmt;

use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

use crate::consts::SEED_LEN;
use crate::error::{Error, Result};
use crate::secret::Secret;

/// `mnemonicToSeed`'s round count (`c: 2048`).
pub const PBKDF2_ROUNDS: u32 = 2048;
/// `mnemonicToSeed`'s output width (`dkLen: 64`); the master seed is the
/// first [`SEED_LEN`] bytes of it.
pub const BIP39_SEED_LEN: usize = 64;
/// The salt prefix.
const SALT_PREFIX: &str = "mnemonic";

/// A recovery phrase, zeroized on drop because it determines the master
/// seed. `Debug` redacts it.
pub struct Phrase(Zeroizing<String>);

impl Phrase {
    /// The words, space-separated.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Phrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Phrase(<redacted>)")
    }
}

/// `entropyToMnemonic(entropy, english)`: 16, 20, 24, 28 or 32 bytes of
/// entropy → 12, 15, 18, 21 or 24 words. The checksum is the first
/// `len / 4` bits of `SHA-256(entropy)`; entropy bits then checksum bits are
/// read in 11-bit groups as wordlist indices.
///
/// # Errors
///
/// [`Error::Mnemonic`] if the entropy is not 16, 20, 24, 28 or 32 bytes.
pub fn phrase_from_entropy(entropy: &[u8]) -> Result<Phrase> {
    let len = entropy.len();
    if !((16..=32).contains(&len) && len.is_multiple_of(4)) {
        return Err(Error::Mnemonic {
            what: "entropy is not 16, 20, 24, 28 or 32 bytes",
        });
    }
    let checksum_bits = len / 4;
    let digest = Sha256::digest(entropy);

    // Bit string: entropy, then the checksum's leading bits. The phrase is
    // built directly in zeroizing storage; an intermediate word list would
    // reveal the entropy and not be zeroized.
    let total_bits = len * 8 + checksum_bits;
    let mut phrase = Zeroizing::new(String::with_capacity(total_bits / 11 * 9));
    let bit_at = |i: usize| -> u16 {
        let byte = if i < len * 8 { entropy[i / 8] } else { digest[(i - len * 8) / 8] };
        u16::from((byte >> (7 - (i % 8))) & 1)
    };
    let mut i = 0;
    while i + 11 <= total_bits {
        let mut idx: u16 = 0;
        for k in 0..11 {
            idx = (idx << 1) | bit_at(i + k);
        }
        if !phrase.is_empty() {
            phrase.push(' ');
        }
        phrase.push_str(english::WORDLIST[usize::from(idx)]);
        i += 11;
    }
    Ok(Phrase(phrase))
}

/// `mnemonicToEntropy(phrase, english)`: the inverse of
/// [`phrase_from_entropy`].
///
/// # Errors
///
/// [`Error::Mnemonic`] for non-ASCII input, a word count outside {12, 15,
/// 18, 21, 24}, a word not in the list, or a checksum mismatch.
pub fn entropy_from_phrase(phrase: &str) -> Result<Zeroizing<Vec<u8>>> {
    if !phrase.is_ascii() {
        return Err(Error::Mnemonic {
            what: "phrase is not ASCII",
        });
    }
    let words: Vec<&str> = phrase.split(' ').collect();
    let count = words.len();
    if !((12..=24).contains(&count) && count.is_multiple_of(3)) {
        return Err(Error::Mnemonic {
            what: "word count is not 12, 15, 18, 21 or 24",
        });
    }
    let entropy_len = count * 11 * 32 / 33 / 8;
    let checksum_bits = entropy_len / 4;

    // One bit per byte, entropy plus checksum; zeroized like the entropy.
    let mut bits: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(count * 11));
    for w in &words {
        let Ok(idx) = english::WORDLIST.binary_search(w) else {
            return Err(Error::Mnemonic {
                what: "a word is not in the English wordlist",
            });
        };
        for k in (0..11).rev() {
            bits.push(((idx >> k) & 1) as u8);
        }
    }

    let mut entropy = Zeroizing::new(vec![0u8; entropy_len]);
    for (i, bit) in bits.iter().take(entropy_len * 8).enumerate() {
        entropy[i / 8] |= bit << (7 - (i % 8));
    }
    let digest = Sha256::digest(&*entropy);
    for (k, bit) in bits.iter().skip(entropy_len * 8).take(checksum_bits).enumerate() {
        let want = (digest[k / 8] >> (7 - (k % 8))) & 1;
        if *bit != want {
            return Err(Error::Mnemonic {
                what: "checksum mismatch",
            });
        }
    }
    Ok(entropy)
}

/// `mnemonicToSeed(phrase, passphrase)`: the full 64-byte BIP39 seed.
///
/// The phrase is validated first, as `fromPhrase` does, so a phrase with a
/// bad checksum is refused.
///
/// # Errors
///
/// The errors of [`entropy_from_phrase`], and [`Error::Mnemonic`] if the
/// passphrase is not ASCII.
pub fn bip39_seed(phrase: &str, passphrase: &str) -> Result<Zeroizing<[u8; BIP39_SEED_LEN]>> {
    let _entropy = entropy_from_phrase(phrase)?;
    if !passphrase.is_ascii() {
        return Err(Error::Mnemonic {
            what: "passphrase is not ASCII",
        });
    }
    let salt = Zeroizing::new(format!("{SALT_PREFIX}{passphrase}"));
    let mut out = Zeroizing::new([0u8; BIP39_SEED_LEN]);
    pbkdf2_hmac::<Sha512>(phrase.as_bytes(), salt.as_bytes(), PBKDF2_ROUNDS, &mut *out);
    Ok(out)
}

/// The master seed `MasterSeed.fromPhrase` holds: the first [`SEED_LEN`]
/// bytes of [`bip39_seed`]. The extension passes an empty passphrase; the
/// parameter is explicit so callers must choose.
///
/// `passphrase` must never be the keystore password. The extension uses no
/// passphrase, so salting the phrase with a password would produce a
/// different master seed and the phrase would restore an empty wallet in any
/// other client. The test
/// `derive::the_store_password_never_reaches_seed_derivation` checks this.
///
/// # Errors
///
/// The errors of [`bip39_seed`].
pub fn master_seed_from_phrase(phrase: &str, passphrase: &str) -> Result<Secret<SEED_LEN>> {
    let full = bip39_seed(phrase, passphrase)?;
    let mut head = Zeroizing::new([0u8; SEED_LEN]);
    head.copy_from_slice(&full[..SEED_LEN]);
    Ok(Secret::new(*head))
}

/// `toPhrase` with no stored entropy: the seed's 32 bytes are used as
/// entropy. This and [`master_seed_from_phrase`] are not inverses.
///
/// # Errors
///
/// None in practice: 32 bytes is a valid entropy length.
pub fn phrase_from_seed_as_entropy(seed: &Secret<SEED_LEN>) -> Result<Phrase> {
    phrase_from_entropy(seed.expose())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_is_sorted_and_complete() {
        assert_eq!(english::WORDLIST.len(), 2048);
        assert!(english::WORDLIST.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn debug_never_reveals_the_phrase() {
        let p = phrase_from_entropy(&[0xA5u8; 16]).unwrap_or_else(|e| panic!("{e}"));
        let rendered = format!("{p:?}");
        assert_eq!(rendered, "Phrase(<redacted>)");
        assert!(!rendered.contains(p.expose().split(' ').next().unwrap_or("")));
    }

    #[test]
    fn passphrase_reaches_the_salt() {
        // A non-empty passphrase changes the seed, and the result is a pure
        // function of (phrase, passphrase). The salt format is checked by
        // the group F passphrase vector.
        let valid = phrase_from_entropy(&[0u8; 32]).unwrap_or_else(|e| panic!("{e}"));
        let empty = bip39_seed(valid.expose(), "").unwrap_or_else(|e| panic!("{e}"));
        let with = bip39_seed(valid.expose(), "x").unwrap_or_else(|e| panic!("{e}"));
        assert_ne!(empty[..], with[..], "the passphrase did not reach the salt");
        assert_eq!(
            bip39_seed(valid.expose(), "").unwrap_or_else(|e| panic!("{e}"))[..],
            empty[..],
            "the seed is not a pure function of (phrase, passphrase)"
        );
    }

    #[test]
    fn refusals_are_by_variant() {
        assert!(matches!(
            phrase_from_entropy(&[0u8; 15]),
            Err(Error::Mnemonic { what: "entropy is not 16, 20, 24, 28 or 32 bytes" })
        ));
        assert!(matches!(
            entropy_from_phrase("abandon abandon"),
            Err(Error::Mnemonic { what: "word count is not 12, 15, 18, 21 or 24" })
        ));
        let bad_word = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zzzz";
        assert!(matches!(
            entropy_from_phrase(bad_word),
            Err(Error::Mnemonic { what: "a word is not in the English wordlist" })
        ));
        // Twelve valid words whose checksum is wrong: swap the last word of a
        // valid phrase for its neighbour.
        let valid = phrase_from_entropy(&[0u8; 16]).unwrap_or_else(|e| panic!("{e}"));
        let mut words: Vec<&str> = valid.expose().split(' ').collect();
        let last = words[11];
        let i = english::WORDLIST.binary_search(&last).unwrap_or(0);
        words[11] = english::WORDLIST[(i + 1) % 2048];
        assert!(matches!(
            entropy_from_phrase(&words.join(" ")),
            Err(Error::Mnemonic { what: "checksum mismatch" })
        ));
        assert!(matches!(
            entropy_from_phrase("abandón"),
            Err(Error::Mnemonic { what: "phrase is not ASCII" })
        ));
        assert!(matches!(
            bip39_seed(
                phrase_from_entropy(&[0u8; 16]).unwrap_or_else(|e| panic!("{e}")).expose(),
                "pässword"
            ),
            Err(Error::Mnemonic { what: "passphrase is not ASCII" })
        ));
        // Check the rendered error text.
        let rendered = format!("{}", Error::Mnemonic { what: "phrase is not ASCII" });
        assert_eq!(rendered, "bip39: phrase is not ASCII");
    }
}
