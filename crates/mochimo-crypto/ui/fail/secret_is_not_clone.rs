// `Secret` cannot be cloned, and this is the only thing that says so.
//
// The type's convention is that reaching key material is conspicuous at the
// call site: no `Display`, no `AsRef`, and the one route to the bytes spelled
// out as `expose`. A derived `Clone` undid that at the point where it mattered
// most. `s.clone()` reads exactly like `name.clone()`, so duplicating a seed
// looked like duplicating a string, and a reviewer grepping for every place
// key material is duplicated got back every place anything is duplicated.
//
// Duplication is still available and still necessary -- the restore path has
// to hand an imported root back, and `cli` has to keep a master alive across a
// move that consumes the store. It is spelled `Secret::duplicate`, which is a
// name that greps. What this case pins is that the anonymous spelling is gone:
// `#[derive(Clone)]` on `Secret` is a one-word change, it would compile, every
// existing test would stay green, and no runtime assertion can observe it --
// the property being asserted here is that a program *does not build*.
//
// The probe is a turbofish over a bound, not a value, exactly as
// `account_is_not_clone.rs` does it: it needs no constructor, so it cannot
// decay when a constructor signature changes. The expected stderr must name
// `Secret` and `Clone`; a failure for any other reason -- a typo, a moved
// import -- means this file stopped testing what it claims, and the pinned
// `.stderr` is what turns that into a red.
//
// Note what this does NOT pin. `duplicate` returning a real copy is not
// asserted here, and neither is the scrubbing of either copy: the first is
// ordinary code, and the second is `secret_bytes_are_gone_after_drop` under
// Miri. This case is about one absence and nothing else.

fn assert_clone<T: Clone>() {}

fn main() {
    assert_clone::<mochimo_crypto::Secret<32>>();
}
