// The rotation index cannot be written from outside the crate.
//
// A writable index is a rewindable one, and a rewound index re-derives and
// re-signs with a key that already signed -- the loss mode every invariant in
// the specification's invariants orbit. `Account::advance` is the only mutation and it is
// forward-only (overflow is an error, not a wrap).
//
// This case is the one that turns "someone made the field pub" into an
// unoverwritable red: the file then *compiles*, and `TRYBUILD=overwrite`
// cannot regenerate a compile-fail out of a success -- the failure has to be
// confronted, not re-pinned. The stderr must name `wots_index`, `Account` and
// privacy (E0616).

fn rewind(a: &mut mochimo_crypto::account::Account) {
    a.wots_index = todo!();
}

fn main() {
    let _ = rewind;
}
