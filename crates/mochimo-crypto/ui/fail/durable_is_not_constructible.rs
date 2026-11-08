// `Durable` — the witness `AdvanceReceipt::attesting` demands — cannot be
// constructed from outside the crate.
//
// It is constructed at exactly one site in the crate, the `Ok` arm after the
// directory fsync in `Keystore::commit`, and a source scan holds that count at
// one. A forged witness would be a receipt for an advance that never reached
// disk: I2's crash window reopened by construction. Private field, no public
// constructor. The stderr must name `Durable` and privacy.

fn main() {
    let _ = mochimo_crypto::keystore::Durable(());
}
