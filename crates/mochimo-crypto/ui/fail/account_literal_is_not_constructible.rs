// An `Account` cannot be assembled by struct literal from outside the crate.
//
// The literal is the bypass around every constructor: a forged tag beside key
// material that never produced it, at an index nothing validated. Field
// privacy is what makes the constructors non-optional, and this case pins the
// privacy of all three fields at once -- the expected stderr carries E0451
// three times, naming `tag`, `key` and `wots_index`. A fourth field added
// later changes this stderr (E0063, missing field), so the case also forces a
// review the day the shape moves.
//
// `todo!()` coerces to any type, so field-type visibility cannot be what
// rejects this -- privacy is the only failing property in the file.

fn main() {
    let _ = mochimo_crypto::account::Account {
        tag: todo!(),
        key: todo!(),
        wots_index: todo!(),
    };
}
