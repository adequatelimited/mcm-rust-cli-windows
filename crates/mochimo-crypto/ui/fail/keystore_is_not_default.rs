// `Keystore` cannot be defaulted, and this is the only thing that says so.
//
// A defaulted keystore is a store with no directory, no lock and an empty
// state: an absent snapshot treated as zero accounts, which is I5's forbidden
// index-zero assumption reached through a derive instead of the filesystem.
// `create` and `open` are the only constructors, and `open` refuses a missing
// snapshot for the same reason. The stderr must name `Keystore`
// and `Default`.

fn assert_default<T: Default>() {}

fn main() {
    assert_default::<mochimo_crypto::keystore::Keystore<mochimo_crypto::keystore::Disk>>();
}
