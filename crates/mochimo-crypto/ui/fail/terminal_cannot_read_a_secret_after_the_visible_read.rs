// The `create` confirmation ECHOES, and the whole safety
// argument for that is a signature: `Terminal::read_visible_line` takes `self`
// by value, so nothing can read from the terminal after echo has come back on.
//
// `create` made "the terminal is present and silent" a precondition the compiler
// holds. Echoing anything appears to reopen it, because something has to turn
// echo back on and a later secret read would then be visible. This case is the
// only thing that says the reopening cannot be written: the program below asks
// for a secret AFTER the visible read, and it must not compile.
//
// A statement-order convention would have no such case, which is the point.
// The stderr must name `read_visible_line` as the move and `read_secret_line`
// as the use after it (E0382).

use mochimo_crypto::cli::create::Terminal;
use zeroize::Zeroizing;

struct Fake;

impl Terminal for Fake {
    fn show(&mut self, _text: &str) -> Result<(), String> { Ok(()) }
    fn read_secret_line(&mut self, _prompt: &str) -> Result<Zeroizing<String>, String> {
        Ok(Zeroizing::new(String::new()))
    }
    fn read_visible_line(self, _prompt: &str) -> Result<Zeroizing<String>, String> {
        Ok(Zeroizing::new(String::new()))
    }
}

fn main() {
    let mut term = Fake;
    let _confirmation = term.read_visible_line("type three words: ");
    let _seed = term.read_secret_line("mnemonic (24 words): ");
}
