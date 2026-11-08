// The inverse case for the four `signing_*` fail cases: every compile-fail
// case passes when compilation fails, so all four would go green the moment
// `mochimo_crypto::keystore::sign` stopped building. This file exercises the
// intended signing surface end to end -- derive, reserve, check, sign at
// position 0, settle, reserve, sign at position 1 -- and must compile and run.
// trybuild compiles it as its own crate, so it uses the system temp
// directory.

use mochimo_crypto::account::{Account, WotsIndex};
use mochimo_crypto::keystore::{KeyAccess, Keystore};
use mochimo_crypto::Secret;

fn main() {
    let dir = std::env::temp_dir().join(format!("mochimo-signing-pass-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let master = Secret::<32>::new([0x42u8; 32]);
    let account = Account::derive(&master, 3);
    let tag = account.tag();
    let mut ks = Keystore::create(&dir, &mochimo_crypto::keystore::Init {
            password: b"ui-case-password-not-for-real-use",
            salt: [0x5A; mochimo_crypto::keystore::SALT_LEN],
            nonce_seed: [0x4E; mochimo_crypto::keystore::NONCE_SEED_LEN],
            kdf: mochimo_crypto::keystore::Kdf::CHEAP_FOR_TESTS,
        }).expect("create");
    ks.add(account).expect("add");

    let receipt = ks.persist_advance(&tag, &[0xD1u8; 32], mochimo_crypto::keystore::Figures { reserved_balance: 5_000_000, blk_to_live: 0 }).expect("reserve");
    ks.check_spend(&[0xD1u8; 32], &receipt, &KeyAccess::Master(&master)).expect("check");
    let first = ks.sign_spend(&[0xD1u8; 32], receipt, KeyAccess::Master(&master)).expect("sign");
    assert_eq!(first.spent_index, WotsIndex::ZERO);
    assert_eq!(first.signature.len(), 2144);

    ks.persist_settled(&tag).expect("settle");
    let receipt = ks.persist_advance(&tag, &[0xD2u8; 32], mochimo_crypto::keystore::Figures { reserved_balance: 5_000_000, blk_to_live: 0 }).expect("reserve again");
    let second = ks.sign_spend(&[0xD2u8; 32], receipt, KeyAccess::Master(&master)).expect("sign again");
    assert_eq!(second.spent_index.get(), 1);
    assert_ne!(&first.public_key[..], &second.public_key[..]);
    let _ = std::fs::remove_dir_all(&dir);
}
