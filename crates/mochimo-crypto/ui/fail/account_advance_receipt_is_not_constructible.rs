// An `AdvanceReceipt` cannot be forged from outside the crate.
//
// The receipt is the signing seam's evidence that an index advance is durable
// (src/account.rs module doc): the future `sign_spend` releases a signature
// only against one, so a forged receipt is a claim that persistence happened
// when it did not -- I2's crash window reopened by construction. It has no
// public constructor, no `Clone`, and private fields; this case pins the
// fields' privacy (E0451, naming `tag` and `index` on `AdvanceReceipt`),
// which also forecloses functional-record-update.

fn main() {
    let _ = mochimo_crypto::account::AdvanceReceipt {
        tag: todo!(),
        index: todo!(),
    };
}
