// The inverse case for the four keystore fail cases: every compile-fail case
// passes when compilation fails, so all four would go green the moment
// `mochimo_crypto::keystore` stopped building. This file exercises the
// intended public surface end to end and must compile. trybuild compiles it as
// its own crate, so it cannot see CARGO_TARGET_TMPDIR and uses the system temp
// directory.

use mochimo_crypto::account::{Account, AccountRecord, WotsIndex};
use mochimo_crypto::keystore::Keystore;
use mochimo_crypto::Secret;

fn main() {
    let dir = std::env::temp_dir().join(format!("mochimo-keystore-pass-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut ks = Keystore::create(&dir, &mochimo_crypto::keystore::Init {
            password: b"ui-case-password-not-for-real-use",
            salt: [0x5A; mochimo_crypto::keystore::SALT_LEN],
            nonce_seed: [0x4E; mochimo_crypto::keystore::NONCE_SEED_LEN],
            kdf: mochimo_crypto::keystore::Kdf::CHEAP_FOR_TESTS,
        }).expect("create");
    // The verified pair from `F-address-widths`; `Account::import` refuses
    // anything else, so a dependent cannot store an account under a tag it
    // chose (format v2).
    const ROOT: [u8; 32] = [
        0x66, 0x4e, 0xdd, 0x3d, 0x3b, 0xf1, 0xa0, 0xe2, 0x9c, 0x93, 0x98, 0xdd, 0xc1, 0x61,
        0x14, 0xab, 0xc6, 0xd6, 0xb4, 0x32, 0xb1, 0xe5, 0xe4, 0xde, 0x26, 0x7c, 0x7e, 0x2a,
        0xe5, 0x3f, 0x58, 0x0b,
    ];
    const FIRST_ADDRESS: &[u8; 2208] =
        include_bytes!("../../../../fixtures/F-widths_account_address.bin");
    const TAG: [u8; 20] = [
        0x05, 0xff, 0x0f, 0x69, 0xd4, 0xc1, 0xcd, 0x68, 0x2e, 0xd3, 0x34, 0x1c, 0x0b, 0x77,
        0x73, 0x05, 0x4b, 0x58, 0x80, 0x0f,
    ];
    ks.add(Account::import(Secret::<32>::new(ROOT), FIRST_ADDRESS).expect("a real pair"))
        .expect("add");
    let receipt = ks.persist_advance(&TAG, &[0xD1; 32], mochimo_crypto::keystore::Figures { reserved_balance: 5_000_000, blk_to_live: 0 }).expect("advance");
    assert_eq!(receipt.index().get(), 1);
    ks.persist_settled(&TAG).expect("settle");
    let next = receipt.index().advanced().expect("next");
    let r2 = ks.persist_advance_to(&TAG, next).expect("advance_to");
    assert_eq!(r2.index().get(), 2);
    assert_eq!(ks.view(&TAG).expect("view").map(|v| v.wots_index), Some(WotsIndex::ZERO.advanced().unwrap().advanced().unwrap()));
    let records = ks.into_records().expect("records");
    assert!(matches!(records.as_slice(), [AccountRecord::Imported { .. }]));
    let _ = std::fs::remove_dir_all(&dir);
}
