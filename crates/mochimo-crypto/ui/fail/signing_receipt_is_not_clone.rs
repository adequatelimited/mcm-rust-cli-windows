// `AdvanceReceipt` cannot be cloned, and this is the only thing that says so.
//
// The E0382 case beside this one stays red for as long as `r.clone()` does
// not compile; a derived `Clone` on the receipt is the one line that reopens
// I1 while every other pin holds. The five `account_*` cases pinned the
// receipt's constructor and fields, not this. The stderr must name
// `AdvanceReceipt` and `Clone`.

fn assert_clone<T: Clone>() {}

fn main() {
    assert_clone::<mochimo_crypto::account::AdvanceReceipt>();
}
