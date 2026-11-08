// The four durable steps cannot be reordered, and the type system is what
// says so.
//
// `write_temp -> Written`, `fsync_file(Written) -> Synced`,
// `rename(Synced) -> Renamed`, `fsync_dir(Renamed)`: each step consumes the
// token the previous one produced. Renaming an un-synced temp is the classic
// torn write (the directory entry can commit before the data does), and this
// program tries it: it hands `rename` a `Written`. That is E0308, not a
// review finding. The stderr must name the mismatched token
// types.

use mochimo_crypto::keystore::{Directory, Disk, Medium};

fn out_of_order(dir: &Directory) {
    let mut m = Disk;
    let written = m.write_temp(dir, &[]).unwrap();
    let _ = m.rename(written, dir);
}

fn main() {}
