// `Keystore` cannot be cloned, and this is the only thing that says so.
//
// A cloned handle is a second writer over one snapshot: exactly the shipped
// wallet's race, where a second un-awaited writer clobbered the spend write
// on one shared blob every block. Within a process `&mut self`
// makes two writers unrepresentable; across processes the kernel lock does;
// this case pins that the type does not hand out a second writer by derive.
// The stderr must name `Keystore` and `Clone`.

fn assert_clone<T: Clone>() {}

fn main() {
    assert_clone::<mochimo_crypto::keystore::Keystore<mochimo_crypto::keystore::Disk>>();
}
