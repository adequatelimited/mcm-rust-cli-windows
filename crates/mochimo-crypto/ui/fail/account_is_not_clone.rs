// `Account` cannot be cloned, and this is the only thing that says so.
//
// A cloned account is two spend paths advancing one index independently: both
// copies derive the same key at the same position, and two signatures under
// one WOTS+ key make forgery tractable (I1, docs/specification.md). The absence of
// `Clone` is one `#[derive]` away from gone, every existing test would stay
// green, and no runtime assertion can see it -- the property is that a program
// does not build.
//
// The probe is a turbofish over a bound, not a value: it needs no constructor,
// so it cannot decay when constructor signatures change. The expected stderr
// must name `Account` and `Clone`; a failure for any other reason means this
// file stopped testing what it claims, and the pinned .stderr turns that red.

fn assert_clone<T: Clone>() {}

fn main() {
    assert_clone::<mochimo_crypto::account::Account>();
}
