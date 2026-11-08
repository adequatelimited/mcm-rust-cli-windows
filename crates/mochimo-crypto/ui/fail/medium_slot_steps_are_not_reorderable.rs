// The slot layout's steps cannot be reordered either, and on Windows the type
// system is what says so.
//
// `write_slot -> SlotWritten`, `flush_slot(SlotWritten) -> Flushed`: a flush
// consumes the token of the write it flushes. A write taken as durable
// without its own flush is the power-loss hazard the layout exists to close,
// and this program tries the shape of it: it hands `flush_slot` the `Flushed`
// of an earlier flush, as if that stood for a write. That is E0308, not a
// review finding. The stderr must name the mismatched token types.
//
// Windows-only, as the steps are: `tests/compile_fail.rs` registers it there
// and registers the rename layout's pin in its place everywhere else.

use mochimo_crypto::keystore::{Disk, Medium};

fn main() {
    let mut m = Disk;
    let dir = std::path::Path::new("C:\\nonexistent");
    let mut held = None;
    let written = m.write_slot(dir, 1, &mut held, &[]).unwrap();
    let flushed = m.flush_slot(written).unwrap();
    let _ = m.flush_slot(flushed);
}
