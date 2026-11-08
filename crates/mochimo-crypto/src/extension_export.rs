// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! Reading the JSON file the Mochimo browser extension exports, so an account
//! it holds can be imported into a keystore here.
//!
//! # File format
//!
//! The extension's `exportWalletJSONAction` writes one object:
//!
//! ```text
//! { "version": "1.0.0", "timestamp": <ms>,
//!   "encrypted": { "data", "iv", "salt" },                 the master seed
//!   "accounts": { "<tag hex>": { "tag", "encryptedData": { "data", "iv", "salt" } } } }
//! ```
//!
//! Every byte field is standard base64.
//!
//! * **Master seed** (`MasterSeed.export`): AES-256-GCM with a key from
//!   PBKDF2-SHA256 over the export password, 100,000 iterations, 16-byte
//!   salt. The 16-byte IV is the GCM nonce (WebCrypto's GHASH derivation for
//!   a non-96-bit nonce); the tag is the last 16 bytes of `data`; the
//!   plaintext is the raw 32-byte seed.
//! * **Storage key** (`MasterSeed.deriveStorageKey`): `prk =
//!   HMAC-SHA256(key = "mochimo_storage_salt", msg = SHA-256(
//!   "mochimo_storage_key_v1" ‖ seed))`, then `HMAC-SHA256(key = prk, msg =
//!   "mochimo_storage_info")`. Its lowercase hex string is the password for
//!   the account records.
//! * **Account record** (`webCrypto.encrypt`): AES-256-CBC with PKCS#7, key
//!   from PBKDF2-SHA256 over that hex string, 100,000 iterations. The
//!   plaintext is the base64 text of the account's JSON; the fields read are
//!   `tag`, `index`, `wotsIndex`, `seed` (32-byte account seed, hex) and
//!   `faddress` (2,208-byte first address, hex).
//!
//! # Verification
//!
//! [`ExtensionExport::account`] decrypts and then requires that the record's
//! tag is the requested tag, that `Account::import` regenerates `faddress`
//! from the account seed with an address hash equal to the tag, and that the
//! master seed at the record's `index` derives the same account seed and tag
//! under this crate's scheme.
//!
//! # Secret handling
//!
//! The master seed, the storage key and every decrypted record are held in
//! zeroizing buffers and dropped when the import returns. The master seed is
//! not stored: the account is kept as an imported root (its account seed and
//! its first key's public components).

use aes_gcm::aead::{Aead, KeyInit};
use base64::Engine;
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::account::{Account, WotsIndex};
use crate::addr::Tag;
use crate::consts::{SEED_LEN, WOTS_ADDR_LEN};
use crate::error::{Error, Result};
use crate::secret::Secret;

/// PBKDF2 iterations both of the extension's ciphers use.
pub const PBKDF2_ITERATIONS: u32 = 100_000;

/// The largest export accepted, checked before parsing. One megabyte holds
/// thousands of accounts.
pub const MAX_EXPORT_BYTES: usize = 1 << 20;

/// One encrypted blob of the export: `{data, iv, salt}`, decoded.
struct Blob {
    data: Vec<u8>,
    iv: Vec<u8>,
    salt: Vec<u8>,
}

/// An export file, parsed but not yet decrypted. Holds nothing secret.
pub struct ExtensionExport {
    master: Blob,
    /// `(tag, encrypted record)`, in file order.
    accounts: Vec<(Tag, Blob)>,
}

/// The account an export holds for a tag, decrypted and verified.
pub struct ExtensionAccount {
    /// The imported account at position 0, built by `Account::import`.
    pub account: Account,
    /// The record's `index`: the account index the extension derived it at.
    pub index: u32,
    /// The position the extension last recorded: its `wotsIndex + 1`.
    pub position: WotsIndex,
}

fn malformed(what: &'static str) -> Error {
    Error::ExtensionExport { what }
}

fn b64(v: &Value, what: &'static str) -> Result<Vec<u8>> {
    let s = v.as_str().ok_or(malformed(what))?;
    base64::engine::general_purpose::STANDARD.decode(s).map_err(|_| malformed(what))
}

fn blob(v: &Value, what: &'static str) -> Result<Blob> {
    let o = v.as_object().ok_or(malformed(what))?;
    let get = |k: &str| o.get(k).ok_or(malformed(what));
    Ok(Blob {
        data: b64(get("data")?, what)?,
        iv: b64(get("iv")?, what)?,
        salt: b64(get("salt")?, what)?,
    })
}

fn tag_from_hex(s: &str) -> Option<Tag> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = crate::mesh::hex::decode(s, "tag").ok()?;
    bytes.try_into().ok()
}

fn pbkdf2_key(password: &[u8], salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, PBKDF2_ITERATIONS, &mut *key);
    key
}

impl ExtensionExport {
    /// Parse the file's JSON. Refuses a file over [`MAX_EXPORT_BYTES`], one
    /// that is not the extension's shape, and one holding no accounts.
    pub fn parse(text: &str) -> Result<ExtensionExport> {
        if text.len() > MAX_EXPORT_BYTES {
            return Err(Error::PayloadTooLarge {
                what: "extension export",
                max: MAX_EXPORT_BYTES,
                got: text.len(),
            });
        }
        let root: Value = serde_json::from_str(text).map_err(|_| malformed("not JSON"))?;
        let master = blob(root.get("encrypted").ok_or(malformed("encrypted"))?, "encrypted")?;
        let accounts_v = root
            .get("accounts")
            .and_then(Value::as_object)
            .ok_or(malformed("accounts"))?;
        let mut accounts = Vec::new();
        for (key, rec) in accounts_v {
            let tag = tag_from_hex(key).ok_or(malformed("accounts: a key is not a 20-byte hex tag"))?;
            let data = rec.get("encryptedData").ok_or(malformed("accounts[].encryptedData"))?;
            accounts.push((tag, blob(data, "accounts[].encryptedData")?));
        }
        if accounts.is_empty() {
            return Err(malformed("accounts: the export holds none"));
        }
        Ok(ExtensionExport { master, accounts })
    }

    /// Every tag the export lists, in file order. Tags are stored in the
    /// clear.
    pub fn tags(&self) -> Vec<Tag> {
        self.accounts.iter().map(|(t, _)| *t).collect()
    }

    /// The master seed, decrypted with the export password. A wrong password
    /// and a damaged blob give the same error.
    pub fn master_seed(&self, password: &[u8]) -> Result<Secret<SEED_LEN>> {
        type Aes256Gcm16 = aes_gcm::AesGcm<aes::Aes256, aes_gcm::aead::consts::U16>;
        if self.master.iv.len() != 16 {
            return Err(malformed("encrypted.iv: not 16 bytes"));
        }
        let key = pbkdf2_key(password, &self.master.salt);
        let cipher = Aes256Gcm16::new_from_slice(&*key).map_err(|_| malformed("encrypted: key"))?;
        let nonce = aes_gcm::Nonce::<aes_gcm::aead::consts::U16>::from_slice(&self.master.iv);
        let plain = Zeroizing::new(
            cipher
                .decrypt(nonce, self.master.data.as_slice())
                .map_err(|_| Error::ExtensionExportPassword)?,
        );
        Secret::from_slice(&plain).map_err(|_| malformed("encrypted: the plaintext is not a 32-byte seed"))
    }

    /// The account the export holds for `tag`, decrypted under `master` and
    /// verified. The record must exist, decrypt, and name
    /// `tag`; its account seed and first address must make an imported
    /// account whose tag is `tag`; and `master` at its `index` must derive
    /// the same seed and tag.
    pub fn account(&self, master: &Secret<SEED_LEN>, tag: &Tag) -> Result<ExtensionAccount> {
        let blob = self
            .accounts
            .iter()
            .find(|(t, _)| t == tag)
            .map(|(_, b)| b)
            .ok_or(Error::ExtensionExportMismatch { what: "the export holds no account for that tag" })?;
        let password = storage_key_hex(master)?;
        let record = decrypt_record(blob, password.as_bytes())?;
        let json: Zeroizing<Vec<u8>> = Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(record.as_slice())
                .map_err(|_| malformed("account record: not base64 text"))?,
        );
        let mut v: Value = serde_json::from_slice(&json).map_err(|_| malformed("account record: not JSON"))?;
        let seed_hex = take_seed(&mut v);
        let field = |k: &'static str| v.get(k).ok_or(malformed(k));

        let record_tag = field("tag")?.as_str().and_then(tag_from_hex).ok_or(malformed("tag"))?;
        if record_tag != *tag {
            return Err(Error::ExtensionExportMismatch { what: "the record's own tag is not the one asked for" });
        }
        let index = field("index")?
            .as_u64()
            .and_then(|i| u32::try_from(i).ok())
            .ok_or(malformed("index: not an account index; only accounts the extension derived are imported"))?;
        let wots_index = field("wotsIndex")?.as_i64().ok_or(malformed("wotsIndex"))?;
        let position = WotsIndex::from_shipped(wots_index)?;

        let seed_hex = seed_hex.ok_or(malformed("seed"))?;
        let seed_bytes = Zeroizing::new(
            crate::mesh::hex::decode(seed_hex.trim_start_matches("0x"), "seed").map_err(|_| malformed("seed: not hex"))?,
        );
        let seed = Secret::<SEED_LEN>::from_slice(&seed_bytes).map_err(|_| malformed("seed: not 32 bytes"))?;
        let faddress_hex = field("faddress")?.as_str().ok_or(malformed("faddress"))?;
        let faddress_bytes =
            crate::mesh::hex::decode(faddress_hex.trim_start_matches("0x"), "faddress").map_err(|_| malformed("faddress: not hex"))?;
        let faddress: Box<[u8; WOTS_ADDR_LEN]> = faddress_bytes
            .into_boxed_slice()
            .try_into()
            .map_err(|_| malformed("faddress: not 2,208 bytes"))?;

        // The master seed must derive the same account seed and tag.
        let derived = crate::derive::derive_account(master, index);
        if !derived.seed().ct_eq(&seed) {
            return Err(Error::ExtensionExportMismatch {
                what: "the master seed at the record's index does not derive the record's account seed",
            });
        }
        if derived.tag() != *tag {
            return Err(Error::ExtensionExportMismatch {
                what: "the master seed at the record's index does not derive the requested tag",
            });
        }
        // `faddress` must regenerate from the account seed and hash to the
        // tag (`Account::import` computes the tag).
        let account = Account::import(seed, &faddress).map_err(|_| Error::ExtensionExportMismatch {
            what: "the record's account seed does not regenerate its first address",
        })?;
        if account.tag() != *tag {
            return Err(Error::ExtensionExportMismatch {
                what: "the record's first address does not hash to the requested tag",
            });
        }
        Ok(ExtensionAccount { account, index, position })
    }
}

/// Moves the record's `seed` string out of the parsed JSON into zeroizing
/// storage, leaving an empty string in its place, so the parsed value holds
/// no copy of the account seed when it is dropped. `None` if the field is
/// missing or not a string.
fn take_seed(v: &mut Value) -> Option<Zeroizing<String>> {
    match v.get_mut("seed") {
        Some(Value::String(s)) => Some(Zeroizing::new(core::mem::take(s))),
        _ => None,
    }
}

/// The extension's storage key as the lowercase hex text the account records
/// are encrypted under (`MasterSeed.deriveStorageKey`).
pub fn storage_key_hex(master: &Secret<SEED_LEN>) -> Result<Zeroizing<String>> {
    let mut first = Sha256::new();
    first.update(b"mochimo_storage_key_v1");
    first.update(master.expose());
    let initial: Zeroizing<[u8; 32]> = Zeroizing::new(first.finalize().into());
    let mut prk_mac = <Hmac<Sha256> as Mac>::new_from_slice(b"mochimo_storage_salt").map_err(|_| malformed("hmac key"))?;
    prk_mac.update(&*initial);
    let prk: Zeroizing<[u8; 32]> = Zeroizing::new(prk_mac.finalize().into_bytes().into());
    let mut key_mac = <Hmac<Sha256> as Mac>::new_from_slice(&*prk).map_err(|_| malformed("hmac key"))?;
    key_mac.update(b"mochimo_storage_info");
    let key: Zeroizing<[u8; 32]> = Zeroizing::new(key_mac.finalize().into_bytes().into());
    let mut hex = Zeroizing::new(String::with_capacity(64));
    for b in key.iter() {
        for nibble in [b >> 4, b & 0x0f] {
            hex.push(char::from_digit(u32::from(nibble), 16).unwrap_or('0'));
        }
    }
    Ok(hex)
}

/// One account record's plaintext: AES-256-CBC with PKCS#7 under
/// PBKDF2-SHA256 of `password`. A wrong storage key shows up as bad padding
/// or as non-base64 text.
fn decrypt_record(blob: &Blob, password: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    use cbc::cipher::{BlockDecryptMut, KeyIvInit};
    if blob.iv.len() != 16 {
        return Err(malformed("accounts[].encryptedData.iv: not 16 bytes"));
    }
    let key = pbkdf2_key(password, &blob.salt);
    let decryptor = cbc::Decryptor::<aes::Aes256>::new_from_slices(&*key, &blob.iv)
        .map_err(|_| malformed("accounts[].encryptedData: key"))?;
    let plain = decryptor
        .decrypt_padded_vec_mut::<cbc::cipher::block_padding::Pkcs7>(&blob.data)
        .map_err(|_| Error::ExtensionExportMismatch {
            what: "the account record does not decrypt under the storage key this master seed gives",
        })?;
    Ok(Zeroizing::new(plain))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_seed_moves_the_parsed_string_and_leaves_no_copy() {
        let mut v: Value = serde_json::from_str(r#"{"tag":"00","seed":"0x0123456789abcdef"}"#).unwrap_or(Value::Null);
        let parsed_at = v.get("seed").and_then(Value::as_str).map(str::as_ptr);
        let seed = take_seed(&mut v);
        assert_eq!(seed.as_ref().map(|s| s.as_str()), Some("0x0123456789abcdef"));
        assert_eq!(seed.as_ref().map(|s| s.as_ptr()), parsed_at);
        assert_eq!(v.get("seed").and_then(Value::as_str), Some(""));
        let mut not_a_string: Value = serde_json::from_str(r#"{"seed":7}"#).unwrap_or(Value::Null);
        assert!(take_seed(&mut not_a_string).is_none());
    }
}
