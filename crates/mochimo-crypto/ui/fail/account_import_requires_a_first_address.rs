// An imported account cannot be built from a root and a chosen tag.
//
// `Account::import_with_unverified_tag(root, tag)` existed until format v2 and was
// the one constructor in the crate that stored a value nothing checked: any
// twenty bytes became an account's permanent identity. It could not be
// verified while the first key's public components were absent from the
// record -- the tag is the first key's hash, and the first key is a function
// of the master seed -- so the caveat lived in the name.
//
// Format v2 stores the components, so `Account::import(root, first_address)`
// recomputes the public key from the pair and derives the tag from it. This
// case pins that the old shape is gone rather than merely deprecated: a
// forged imported tag is unconstructible, not discouraged (I8).
//
// `todo!()` coerces to any type, so an argument-type mismatch cannot be what
// rejects this -- the missing function is the only failing property here.

fn main() {
    let _ = mochimo_crypto::account::Account::import_with_unverified_tag(todo!(), todo!());
}
