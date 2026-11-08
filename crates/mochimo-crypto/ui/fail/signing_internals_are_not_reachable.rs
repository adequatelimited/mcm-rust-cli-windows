// `wots::internals` is not nameable from outside the crate (I1).
//
// `prf` keyed with the secret IS `expand_seed`, and with `thash_f` and
// `chain_lengths` a caller has a complete signer by composition -- so demoting
// `sign` alone would have been decorative. The module went `pub(crate)` with
// it, `expand_seed` being the one named first. The stderr must
// name `internals` and privacy (E0603).

fn main() {
    let secret = mochimo_crypto::Secret::<32>::new([7u8; 32]);
    let _ = mochimo_crypto::wots::internals::expand_seed(&secret);
}
