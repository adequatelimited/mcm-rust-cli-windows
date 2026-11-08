// `Account` cannot be defaulted, and this is the only thing that says so.
//
// A `Default` account is an account from nothing: fabricated key material and
// a fresh index zero, which is I5's forbidden assumption -- a wallet state
// that assumes index zero re-signs with every key the real account already
// used (I5, docs/specification.md). One derive would compile it.
// This case is the compiler's half of that invariant.
//
// Same turbofish shape as `account_is_not_clone.rs`, same reason. The stderr
// must name `Account` and `Default`.

fn assert_default<T: Default>() {}

fn main() {
    assert_default::<mochimo_crypto::account::Account>();
}
