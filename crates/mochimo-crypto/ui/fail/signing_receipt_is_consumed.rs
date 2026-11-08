// A receipt signs at most once: `sign_spend` takes it by value (I1).
//
// The second call below is a use after move (E0382 naming `r`). Everything
// else in this file is well-typed on purpose, so the pinned stderr holds
// exactly that one error and a case that starts failing for another reason
// is a red, not a pass.

use mochimo_crypto::account::Account;
use mochimo_crypto::keystore::{KeyAccess, Keystore};
use mochimo_crypto::Secret;

fn main() {
    let master = Secret::<32>::new([1u8; 32]);
    let account = Account::derive(&master, 0);
    let tag = account.tag();
    let mut ks = Keystore::create(
        std::path::Path::new("/nonexistent"),
        &mochimo_crypto::keystore::Init {
            password: b"ui-case-password-not-for-real-use",
            salt: [0x5A; mochimo_crypto::keystore::SALT_LEN],
            nonce_seed: [0x4E; mochimo_crypto::keystore::NONCE_SEED_LEN],
            kdf: mochimo_crypto::keystore::Kdf::CHEAP_FOR_TESTS,
        },
    ).unwrap();
    ks.add(account).unwrap();
    let r = ks.persist_advance(&tag, &[0xD1u8; 32], mochimo_crypto::keystore::Figures { reserved_balance: 5_000_000, blk_to_live: 0 }).unwrap();
    let _first = ks.sign_spend(&[0xD1u8; 32], r, KeyAccess::Master(&master));
    let _second = ks.sign_spend(&[0xD1u8; 32], r, KeyAccess::Master(&master));
}
