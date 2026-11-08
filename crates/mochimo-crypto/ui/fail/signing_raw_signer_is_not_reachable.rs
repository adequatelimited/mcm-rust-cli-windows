// The raw WOTS+ signer is not nameable from outside the crate (I1).
//
// `wots::sign` is `pub(crate)`: the only public path to a signature
// is `Keystore::sign_spend`, behind an `AdvanceReceipt`. This case pins the
// privacy of the function itself (E0603 naming `sign`), which holds whatever
// features the build has -- unlike the backend route, which trybuild cannot
// see because it inherits the test build's `raw-backend` and which the
// downstream probe in tests/signing.rs pins instead.

fn main() {
    let secret = mochimo_crypto::Secret::<32>::new([7u8; 32]);
    let mut adrs = mochimo_crypto::wots::Adrs::ZERO;
    let _ = mochimo_crypto::wots::sign(&[0u8; 32], &secret, &[0u8; 32], &mut adrs);
}
