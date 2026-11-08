// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! A synthetic Mochimo browser-extension export built from throwaway values
//! with the extension's cryptography: AES-256-GCM with a 16-byte IV over the
//! raw master seed, the extension's storage key, and AES-256-CBC over the
//! base64 text of each account's JSON, all keys from PBKDF2-SHA256 at 100,000
//! iterations.

#![allow(dead_code)]

use aes_gcm::aead::{Aead, KeyInit};
use base64::Engine;
use cbc::cipher::{BlockEncryptMut, KeyIvInit};
use sha2::Sha256;

use mochimo_crypto::derive;
use mochimo_crypto::Secret;

pub const PASSWORD: &str = "a throwaway export password";

/// One account record before encryption, with the fields the extension
/// writes. Tests edit a field to create a mismatch.
pub struct Record {
    pub key_tag: String,
    pub tag: String,
    pub index: u64,
    pub wots_index: i64,
    pub seed: String,
    pub faddress: String,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The record the extension writes for account `index` of `master`.
pub fn record(master: &Secret<32>, index: u32, wots_index: i64) -> Record {
    let acct = derive::derive_account(master, index);
    let tag = hex(&acct.tag());
    Record {
        key_tag: tag.clone(),
        tag,
        index: u64::from(index),
        wots_index,
        seed: hex(acct.seed().expose()),
        faddress: hex(&acct.first_key().legacy_address(&[1u8; 12])[..]),
    }
}

fn key(password: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, 100_000, &mut k);
    k
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// The whole export file, as text.
pub fn export(master: &Secret<32>, password: &str, records: &[Record]) -> String {
    type Gcm16 = aes_gcm::AesGcm<aes::Aes256, aes_gcm::aead::consts::U16>;
    let salt = [0x51u8; 16];
    let iv = [0x52u8; 16];
    let cipher = Gcm16::new_from_slice(&key(password.as_bytes(), &salt)).unwrap_or_else(|e| panic!("{e}"));
    let data = cipher
        .encrypt(aes_gcm::Nonce::<aes_gcm::aead::consts::U16>::from_slice(&iv), master.expose().as_slice())
        .unwrap_or_else(|e| panic!("{e}"));
    let storage = mochimo_crypto::extension_export::storage_key_hex(master).unwrap_or_else(|e| panic!("{e}"));
    let mut accounts = serde_json::Map::new();
    for (n, r) in records.iter().enumerate() {
        let json = serde_json::json!({
            "name": format!("Account {n}"), "type": "standard", "faddress": r.faddress, "balance": "0",
            "index": r.index, "tag": r.tag, "source": "mnemonic", "wotsIndex": r.wots_index,
            "seed": r.seed, "order": n,
        })
        .to_string();
        let plaintext = b64(json.as_bytes());
        let rsalt = [0x60u8 + n as u8; 16];
        let riv = [0x70u8 + n as u8; 16];
        let enc = cbc::Encryptor::<aes::Aes256>::new_from_slices(&key(storage.as_bytes(), &rsalt), &riv)
            .unwrap_or_else(|e| panic!("{e}"))
            .encrypt_padded_vec_mut::<cbc::cipher::block_padding::Pkcs7>(plaintext.as_bytes());
        accounts.insert(
            r.key_tag.clone(),
            serde_json::json!({ "tag": r.key_tag, "encryptedData": { "data": b64(&enc), "iv": b64(&riv), "salt": b64(&rsalt) } }),
        );
    }
    serde_json::json!({
        "version": "1.0.0",
        "timestamp": 1_761_400_000_000u64,
        "encrypted": { "data": b64(&data), "iv": b64(&iv), "salt": b64(&salt) },
        "accounts": accounts,
    })
    .to_string()
}
