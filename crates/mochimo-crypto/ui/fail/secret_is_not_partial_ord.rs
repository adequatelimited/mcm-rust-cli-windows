// `Secret` cannot be ordered, and this is the only thing that says so at the
// compiler.
//
// `secret_is_not_partial_eq.rs` pins `==`; this pins `<`. Comparison over key
// material is variable-time and short-circuits, so `secret.rs` implements
// neither family (its `ct_eq` is `subtle::ConstantTimeEq`, a different thing).
// The stderr must name the operator and `Secret`. Added with the
// repair of `secret_has_no_equality_and_nothing_enforces_it`'s anchor.

fn main() {
    let a = mochimo_crypto::Secret::<4>::new([1u8; 4]);
    let b = mochimo_crypto::Secret::<4>::new([2u8; 4]);
    let _ = a < b;
}
