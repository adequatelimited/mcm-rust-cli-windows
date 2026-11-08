// The inverse case for the five `account_*` fail cases, and not decorative:
// every compile-fail case passes when compilation fails, so all five would go
// green the moment `mochimo_crypto::account` stopped building at all. This
// file exercises the intended public surface and must compile, which is what
// makes the rejections boundaries rather than rubble.

use mochimo_crypto::account::{Account, AccountKind};
use mochimo_crypto::Secret;

/// `F-address-widths`' account seed, and the 2208-byte first address it
/// produces. `Account::import` verifies the pair, so a dependent cannot build
/// an imported account out of a root and a tag it made up -- which is exactly
/// what this file has to show still compiles for a *real* pair.
const ROOT: [u8; 32] = [
    0x66, 0x4e, 0xdd, 0x3d, 0x3b, 0xf1, 0xa0, 0xe2, 0x9c, 0x93, 0x98, 0xdd, 0xc1, 0x61, 0x14,
    0xab, 0xc6, 0xd6, 0xb4, 0x32, 0xb1, 0xe5, 0xe4, 0xde, 0x26, 0x7c, 0x7e, 0x2a, 0xe5, 0x3f,
    0x58, 0x0b,
];
const FIRST_ADDRESS: &[u8; 2208] = include_bytes!("../../../../fixtures/F-widths_account_address.bin");
const TAG: [u8; 20] = [
    0x05, 0xff, 0x0f, 0x69, 0xd4, 0xc1, 0xcd, 0x68, 0x2e, 0xd3, 0x34, 0x1c, 0x0b, 0x77, 0x73,
    0x05, 0x4b, 0x58, 0x80, 0x0f,
];

fn main() {
    let root = Secret::<32>::new(ROOT);
    let mut imported = Account::import(root, FIRST_ADDRESS).expect("a real pair verifies");
    let derived = Account::derive(&Secret::<32>::new([0x5Au8; 32]), 3);

    assert_eq!(imported.kind(), AccountKind::Imported);
    assert_eq!(derived.kind(), AccountKind::Derived);
    assert_eq!(imported.tag(), TAG);
    assert_eq!(imported.wots_index().get(), 0);

    // Forward-only rotation, and the debug renderings are total.
    let advanced = imported.advance().expect("advance from zero cannot overflow");
    assert_eq!(advanced.get(), 1);
    let _rendered = format!("{imported:?} {derived:?}");

    // The restore path round-trips through the persistent-content type.
    let restored = Account::restore_from_record(imported.to_record()).expect("a real record");
    assert_eq!(restored.wots_index().get(), 1);
}
