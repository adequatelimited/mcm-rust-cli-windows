//! Both spellings of the raw WOTS+ signer a dependent can write, and the
//! test tree's constructor of spend addresses that came out of no keystore.
//! None may compile in a build without `raw-backend`; the test pins exactly
//! three errors: two E0603, one naming `backend`, one naming `sign`, and one
//! E0599 naming `unverified` (an associated function that does not exist
//! without the feature).
fn main() {
    let secret = mochimo_crypto::Secret::<32>::new([7u8; 32]);
    let mut adrs = mochimo_crypto::wots::Adrs::ZERO;
    let _ = mochimo_crypto::wots::sign(&[0u8; 32], &secret, &[0u8; 32], &mut adrs);
    let _ = mochimo_crypto::backend::native::wots_sign(&[0u8; 32], secret.expose(), &[0u8; 32], &mut adrs.0);
    let _ = mochimo_crypto::keystore::SpendAddresses::unverified(
        [0u8; 20],
        mochimo_crypto::account::WotsIndex::ZERO,
        [0u8; 40],
        [0u8; 40],
    );
}
