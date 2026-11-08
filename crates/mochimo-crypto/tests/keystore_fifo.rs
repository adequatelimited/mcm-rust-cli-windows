// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

#![cfg(all(unix, feature = "native", not(miri)))]
//! A FIFO in place of the snapshot is refused without blocking.
//!
//! The FIFO is created with the `mkfifo` command because the safe filesystem
//! wrapper does not expose FIFO creation on every supported Unix. This is a
//! separate test target because a spawned child briefly inherits open lock
//! descriptions before exec, which could make other keystore tests' locks
//! appear held.

#[path = "support/keystore_harness.rs"]
mod keystore_harness;

use std::sync::mpsc;
use std::time::Duration;

use keystore_harness::ScratchDir;
use mochimo_crypto::keystore::Keystore;
use mochimo_crypto::Error;

#[test]
fn unix_nonregular_snapshot_is_refused_without_blocking() {
    let root = ScratchDir::new("store-fifo");
    std::fs::create_dir(root.path()).unwrap();
    let path = root.path().join("store");
    drop(Keystore::create(&path, &keystore_harness::init()).unwrap());
    std::fs::remove_file(path.join("accounts.mks")).unwrap();
    assert!(std::process::Command::new("mkfifo")
        .arg(path.join("accounts.mks")).status().unwrap().success());

    // Run the open on a worker so a blocking open fails the test instead of
    // hanging it.
    let (send, receive) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let error = Keystore::open(&path, &keystore_harness::unlock()).err();
        let _ = send.send(error);
    });
    let error = receive.recv_timeout(Duration::from_secs(5))
        .expect("opening a FIFO snapshot blocked or the worker stopped");
    worker.join().expect("snapshot open worker panicked");
    assert!(matches!(error,
        Some(Error::Io { op: "open snapshot", kind: std::io::ErrorKind::InvalidInput })),
        "unexpected FIFO snapshot result: {error:?}");
}
