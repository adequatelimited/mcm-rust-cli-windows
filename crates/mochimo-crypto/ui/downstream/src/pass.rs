//! The legitimate path, as a dependent writes it: derive, reserve, sign
//! through the receipt. Must compile with the crate's default features; only
//! checked, never run.
use mochimo_crypto::account::Account;
use mochimo_crypto::keystore::{KeyAccess, Keystore};
use mochimo_crypto::Secret;

fn main() {
    let master = Secret::<32>::new([1u8; 32]);
    let account = Account::derive(&master, 0);
    let tag = account.tag();
    let dir = std::env::temp_dir().join("mochimo-downstream-probe");
    let mut ks = Keystore::create(&dir, &mochimo_crypto::keystore::Init {
            password: b"ui-case-password-not-for-real-use",
            salt: [0x5A; mochimo_crypto::keystore::SALT_LEN],
            nonce_seed: [0x4E; mochimo_crypto::keystore::NONCE_SEED_LEN],
            kdf: mochimo_crypto::keystore::Kdf::CHEAP_FOR_TESTS,
        }).expect("create");
    ks.add(account).expect("add");
    let receipt = ks.persist_advance(&tag, &[0xD1u8; 32], mochimo_crypto::keystore::Figures { reserved_balance: 5_000_000, blk_to_live: 0 }).expect("reserve");
    ks.check_spend(&[0xD1u8; 32], &receipt, &KeyAccess::Master(&master)).expect("check");
    let signed = ks.sign_spend(&[0xD1u8; 32], receipt, KeyAccess::Master(&master)).expect("sign");
    println!("signed at position {}", signed.spent_index.get());
}
