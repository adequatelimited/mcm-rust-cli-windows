// An `AccountRecord::Imported` literal cannot omit the first-key components
// or the key-stream identity.
//
// The record's fields are public because a record is data rather than
// authority, and that stays true only while a forged record
// restores to an account the public constructors would build -- which is why
// `Account::restore_from_record` verifies the imported triple. This case pins
// the other half: the fields cannot be *left out*. A record missing them
// would be an imported account with no path to position 0, which is I8's loss
// mode, and E0063 is the compiler refusing to let it be spelled.
//
// The expected stderr names both fields, so adding a third field to the
// variant changes this file and forces a review the day the shape moves.
// It is the compiler's half of I8.

use mochimo_crypto::account::{AccountRecord, WotsIndex};
use mochimo_crypto::Secret;

fn main() {
    let _ = AccountRecord::Imported {
        tag: [0u8; 20],
        root: Secret::<32>::new([0u8; 32]),
        wots_index: WotsIndex::ZERO,
    };
}
