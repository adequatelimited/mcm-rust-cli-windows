// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! `tawara`, the command-line binary.
//!
//! Parses argv, opens the store when the command needs one, builds the
//! transport, hands off to [`mochimo_crypto::cli::run`], prints the report
//! and exits. Every decision is made in `src/cli/`, where tests drive it
//! against a scriptable chain.
//!
//! The binary requires the `mesh-https` feature, which pulls in rustls and
//! `ring`. `tests/cli.rs` builds it in a subprocess and drives it under a
//! pseudo-terminal.
//!
//! # Secrets
//!
//! The master seed is held in the encrypted keystore and unlocked by a
//! password read from the controlling terminal. The recovery phrase is shown
//! once at creation and is needed only to restore a lost store. Anyone with
//! both the store file and the password holds every account, so
//! `cli::create::MIN_PASSWORD_LEN` is enforced; see `keystore::crypt`.
//!
//! Secrets are never taken from:
//!
//! * **argv**, which `ps`, `/proc/pid/cmdline` and shell history expose;
//! * **an environment variable**, which `/proc/pid/environ`, child processes
//!   and crash handlers see, and which is usually set from a plaintext file;
//! * **a file**, which is plaintext at rest and would undo the store's
//!   encryption.
//!
//! They are read from `/dev/tty`, not stdin, so a pipe or redirect cannot
//! supply them. The binary is therefore not scriptable: every command that
//! opens a store prompts for the password.
//!
//! [`read_scrubbed_line`] zeroizes every buffer a secret line passes through
//! before releasing it. Out of reach: the terminal driver's input buffer, and
//! process memory until the `Secret` is dropped (a core dump or an attached
//! debugger can see it).

// `std::process::exit` does not run destructors, and every scrub of key
// material here is a `Drop` (`Zeroizing`, `Secret`, the keystore handle), so
// an exit call would skip zeroization. `main` returns `ExitCode` instead.
// `clippy::exit` is a restriction lint, off by default; it forbids the call
// in every function except `main`, which the lint exempts. `main` holds no
// key material when it returns.
#![deny(clippy::exit)]

use std::io::{self, Write};
use std::process::ExitCode;

use mochimo_crypto::cli::create::{self as create_cmd, Terminal as _, ENTROPY_LEN};
use mochimo_crypto::cli::{self, args, Code};
use mochimo_crypto::keystore::Keystore;
use mochimo_crypto::mesh::http::UreqTransport;
use mochimo_crypto::mesh::{MeshClient, Transport};
use mochimo_crypto::{Error, TransportKind};
use zeroize::Zeroizing;

/// The size of each read a secret line is gathered from, and the line
/// buffer's initial capacity.
///
/// A 24-word BIP-39 phrase is at most about 215 bytes, so no phrase makes the
/// line grow. A longer password can; [`read_scrubbed_line`] then moves the
/// line into a fresh buffer of twice the size and zeroizes the old one.
const PHRASE_CAPACITY: usize = 512;

/// The refusal for end-of-file at a prompt before any byte was read, so
/// Ctrl-D is reported as missing input rather than as a wrong password.
const END_OF_INPUT: &str =
    "end of input at the prompt: the terminal reported end-of-file (Ctrl-D) before a line was \
     typed, so nothing was read and nothing was compared. Type the answer and press Enter, or \
     run the command again.";

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let report = match run_from_argv(&argv) {
        Ok(r) => r,
        Err(usage) => {
            eprintln!("{usage}");
            return ExitCode::from(Code::Usage as u8);
        }
    };
    if report.code == Code::Ok {
        println!("{}", report.text);
    } else {
        eprintln!("{}", report.text);
    }
    // `as u8` is exact: `Code`'s discriminants are 0..=3.
    ExitCode::from(report.code as u8)
}

fn run_from_argv(argv: &[String]) -> Result<cli::Report, args::Usage> {
    let inv = match args::parse(argv)? {
        // Help is an outcome, not an error: it prints and exits 0.
        args::ParsedArgv::Help => {
            return Ok(cli::Report {
                text: args::HELP.to_string(),
                code: Code::Ok,
            })
        }
        args::ParsedArgv::Run(inv) => inv,
    };

    // A supplied node is validated first, whatever the command.
    // `UreqTransport::new` opens no socket; it checks the scheme and
    // authority, so an unusable URL is refused before the password prompt and
    // the key derivation. The parser has already refused a command that needs
    // a node and has none, so `None` reaches here only for commands that
    // never dial.
    let node = match &inv.node {
        Some(url) => match UreqTransport::new(url) {
            Ok(t) => Node::Named(t),
            Err(e) => {
                return Ok(cli::Report {
                    text: format!("cannot use node {url}: {e}"),
                    code: Code::StartupRefused,
                })
            }
        },
        None => Node::Absent,
    };

    // `create` makes the store, so it is dispatched before the open below.
    if let args::Command::Create { from_phrase } = inv.command {
        return Ok(run_create(&inv.dir, from_phrase));
    }
    // `submit` opens no store: the artifact is its input. The parser requires
    // `--dir`, but the directory is not read, created or locked here.
    if let args::Command::Submit { artifact } = &inv.command {
        return Ok(cli::run_submit(&MeshClient::new(node), artifact));
    }

    // Read-only explorer commands: the node is the whole input, so there is
    // nothing to unlock and `--dir` is not touched.
    if inv.command.opens_no_store() {
        return Ok(cli::run_explorer(&MeshClient::new(node), &inv.command));
    }

    // A rollback signs again with a key that has signed, so the operator
    // confirms it on the terminal before the store is opened.
    if let args::Command::Rollback { rollback_to, .. } = &inv.command {
        if let Err(e) = confirm_rollback(*rollback_to) {
            return Ok(cli::Report {
                text: e,
                code: Code::Refused,
            });
        }
    }

    // Every command that opens a store needs the password: the file is
    // encrypted, so not even the account list can be read without it.
    let password = match read_secret_line("password: ") {
        Ok(p) => p,
        Err(e) => {
            return Ok(cli::Report {
                text: e,
                code: Code::StartupRefused,
            })
        }
    };
    let nonce_seed = match os_bytes::<{ mochimo_crypto::keystore::NONCE_SEED_LEN }>() {
        Ok(b) => *b,
        Err(e) => {
            return Ok(cli::Report {
                text: e,
                code: Code::StartupRefused,
            })
        }
    };
    let store = match Keystore::open(
        std::path::Path::new(&inv.dir),
        &mochimo_crypto::keystore::Unlock {
            password: password.as_bytes(),
            nonce_seed,
        },
    ) {
        Ok(s) => s,
        Err(e) => {
            return Ok(cli::Report {
                text: format!("cannot open the keystore at {}: {e}", inv.dir),
                code: Code::StartupRefused,
            })
        }
    };

    // `import --sdk` takes a second secret, the SDK master seed, read from
    // the terminal with echo off, never from argv.
    if let args::Command::Import(from) = &inv.command {
        match from {
            args::ImportFrom::Sdk { account, scan_to } => {
                let seed = match read_sdk_master() {
                    Ok(s) => s,
                    Err(e) => {
                        return Ok(cli::Report {
                            text: format!("{e} Nothing was written."),
                            code: Code::Refused,
                        })
                    }
                };
                return Ok(cli::run_import(store, MeshClient::new(node), &seed, *account, *scan_to));
            }
            // The export file is encrypted; its password is read from the
            // terminal like every other secret.
            args::ImportFrom::ExtensionExport { path, tag, scan_to } => {
                let text = match std::fs::read_to_string(path) {
                    Ok(t) => t,
                    Err(e) => {
                        return Ok(cli::Report {
                            text: format!("cannot read the export file {path}: {e}. Nothing was written."),
                            code: Code::Refused,
                        })
                    }
                };
                let password = match read_secret_line("extension export password (not echoed): ") {
                    Ok(p) => p,
                    Err(e) => {
                        return Ok(cli::Report {
                            text: format!("{e} Nothing was written."),
                            code: Code::Refused,
                        })
                    }
                };
                return Ok(cli::run_import_extension(
                    store,
                    MeshClient::new(node),
                    &text,
                    password.as_bytes(),
                    tag,
                    *scan_to,
                ));
            }
        }
    }

    Ok(cli::run(store, MeshClient::new(node), &inv.command))
}

/// `reconcile --rollback-to`'s warning, shown on the terminal, and the
/// operator's answer: the rollback goes ahead only on `yes`.
fn confirm_rollback(to: u32) -> Result<(), String> {
    let mut tty = open_terminal()?;
    tty.show(&cli::reconcile::rollback_warning(to))?;
    let answer = tty.read_visible_line("Type yes to roll back: ")?;
    if answer.as_str() == "yes" {
        Ok(())
    } else {
        Err("Not rolled back: the answer was not yes. Nothing was written.".to_string())
    }
}

/// The SDK master seed `import --sdk` takes: sixty-four hex characters read
/// from the terminal with echo off, decoded into a buffer that is zeroized
/// when it is dropped. Surrounding whitespace is ignored and an optional
/// `0x` is accepted; anything else is refused without echoing what was read.
fn read_sdk_master() -> Result<mochimo_crypto::Secret<32>, String> {
    let line = read_secret_line("SDK master seed (64 hex characters, not echoed): ")?;
    let text = line.trim();
    let text = text.strip_prefix("0x").unwrap_or(text);
    if text.len() != 64 {
        return Err(format!(
            "the SDK master seed must be 64 hex characters; {} were read.",
            text.len()
        ));
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    for (i, pair) in text.as_bytes().chunks(2).enumerate() {
        let digit = |c: u8| -> Option<u8> { (c as char).to_digit(16).and_then(|d| u8::try_from(d).ok()) };
        match (pair.first().copied().and_then(digit), pair.get(1).copied().and_then(digit), bytes.get_mut(i)) {
            (Some(hi), Some(lo), Some(slot)) => *slot = (hi << 4) | lo,
            _ => return Err("the SDK master seed is not hex.".to_string()),
        }
    }
    Ok(mochimo_crypto::Secret::new(*bytes))
}

/// The transport handed to `cli::run`: a real one when `--node` was given,
/// otherwise one that refuses every request.
///
/// `cli::run` takes a client for every command, including those that never
/// dial. If one of them ever did, the operator would get a refusal naming the
/// missing flag rather than a request sent nowhere.
enum Node {
    Named(UreqTransport),
    Absent,
}

impl Transport for Node {
    fn post(&self, path: &str, body: &[u8]) -> mochimo_crypto::Result<Vec<u8>> {
        match self {
            Node::Named(t) => t.post(path, body),
            Node::Absent => Err(Error::Transport {
                op: "post with no --node given",
                kind: TransportKind::Other,
            }),
        }
    }
}

/// Reads one secret line from the controlling terminal with echo off,
/// writing the prompt to that terminal.
///
/// Echo is turned off, and the call refused if that fails, before the prompt
/// is written; [`open_terminal`] enforces that order. The prompt goes through
/// [`Tty`]'s own `read_secret_line`, not to stderr, so redirecting stderr
/// cannot separate a prompt from its question, and a closed stderr cannot
/// make a print macro panic. Only `main` prints.
fn read_secret_line(prompt: &str) -> Result<Zeroizing<String>, String> {
    let mut tty = open_terminal()?;
    tty.read_secret_line(prompt)
}

/// Terminal echo, off for as long as the guard lives and restored on drop,
/// so an early return cannot leave the terminal silent. Uses `stty` rather
/// than a `termios` dependency.
struct EchoGuard(std::fs::File);

fn echo_off(tty: &std::fs::File) -> Result<EchoGuard, String> {
    let dup = tty
        .try_clone()
        .map_err(|e| format!("cannot duplicate /dev/tty: {e}"))?;
    let off = std::process::Command::new("stty")
        .arg("-echo")
        .stdin(std::process::Stdio::from(
            tty.try_clone()
                .map_err(|e| format!("cannot duplicate /dev/tty: {e}"))?,
        ))
        .status();
    if !matches!(off, Ok(s) if s.success()) {
        return Err(
            "refusing to read a secret with terminal echo on: the words would be visible and \
             may be kept in the terminal's scrollback. Nothing was read."
                .into(),
        );
    }
    Ok(EchoGuard(dup))
}

impl EchoGuard {
    /// Turns echo back on and reports whether it worked.
    ///
    /// The visible confirmation prompt depends on echo, so it calls this
    /// through `?` and refuses before prompting. `Drop` calls it best-effort
    /// for every other path.
    fn restore(&self) -> Result<(), String> {
        let dup = self
            .0
            .try_clone()
            .map_err(|e| format!("cannot duplicate /dev/tty to restore terminal echo: {e}"))?;
        let on = std::process::Command::new("stty")
            .arg("echo")
            .stdin(std::process::Stdio::from(dup))
            .status();
        if !matches!(on, Ok(s) if s.success()) {
            return Err(
                "cannot turn terminal echo back on, so the confirmation would be typed blind. \
                 That is how the words get mistyped. Nothing further was read; run `stty echo` \
                 to restore your terminal."
                    .into(),
            );
        }
        Ok(())
    }
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

/// `N` bytes from the OS CSPRNG, read from `/dev/urandom`.
///
/// The library takes entropy as a parameter and reaches no generator, so the
/// binary supplies it. This build targets Unix (`lib.rs` enforces it at
/// compile time). A failed open or a short read is an error, so a weak draw
/// is never returned in place of a strong one.
///
/// Generic over the width because the phrase entropy, the KDF salt and the
/// per-open nonce seed are separate draws; see `cli::create::CreateEntropy`.
fn os_bytes<const N: usize>() -> Result<Zeroizing<[u8; N]>, String> {
    use std::io::Read;
    let mut buf = Zeroizing::new([0u8; N]);
    std::fs::File::open("/dev/urandom")
        .map_err(|e| format!("cannot open /dev/urandom: {e}"))?
        .read_exact(&mut buf[..])
        .map_err(|e| format!("cannot read /dev/urandom: {e}"))?;
    Ok(buf)
}

/// Everything `create` draws from the OS, in one value.
fn os_create_entropy() -> Result<Zeroizing<create_cmd::CreateEntropy>, String> {
    Ok(Zeroizing::new(create_cmd::CreateEntropy {
        phrase: *os_bytes::<{ ENTROPY_LEN }>()?,
        salt: *os_bytes::<{ mochimo_crypto::keystore::SALT_LEN }>()?,
        nonce_seed: *os_bytes::<{ mochimo_crypto::keystore::NONCE_SEED_LEN }>()?,
    }))
}

/// `create`: supplies the real `/dev/tty` and the OS generator to
/// `cli::create::orchestrate`, which makes every decision. The terminal
/// acquisition is passed in rather than called, so `orchestrate` controls
/// when it happens.
fn run_create(dir: &str, from_phrase: bool) -> cli::Report {
    create_cmd::orchestrate(
        std::path::Path::new(dir),
        from_phrase,
        os_create_entropy,
        acquire_terminal,
    )
}

/// The controlling terminal, with echo off for the `Tty`'s whole life. The
/// guard holds its own duplicated descriptor, so field drop order does not
/// matter.
struct Tty {
    file: std::fs::File,
    _echo: EchoGuard,
}

/// Opens `/dev/tty` for reading and writing, then turns echo off. A
/// read-only descriptor would fail every prompt write with `EBADF`.
///
/// This is the only place the terminal is opened: [`acquire_terminal`] and
/// [`read_secret_line`] both come through it.
fn open_terminal() -> Result<Tty, String> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|e| {
            format!(
                "cannot open /dev/tty: {e}. This program reads secrets from the controlling \
                 terminal and there is none here -- it cannot be driven from a pipe, a cron job \
                 or a harness without one."
            )
        })?;
    let _echo = echo_off(&file)?;
    Ok(Tty { file, _echo })
}

/// `create`'s terminal acquisition. `orchestrate` appends "Nothing was
/// created." to every refusal, so this does not.
fn acquire_terminal() -> Result<Tty, String> {
    open_terminal()
}

/// Reads one line from `from`, trimmed, zeroizing every buffer the line
/// passes through before it is released. Returns `None` when input ends
/// before any byte arrives; the caller refuses that as [`END_OF_INPUT`].
///
/// Otherwise it follows `BufRead::read_line`: bytes then end of input are a
/// line, `Interrupted` is retried, any other error is returned, and a line
/// that is not UTF-8 is refused with `std`'s message. It is generic over
/// `Read` and names no device.
///
/// No `BufReader` is used: dropping one frees its internal buffer with the
/// line still in it, and it offers no way to zeroize that buffer.
///
/// Every `read` is offered the whole chunk, because `Read` does not promise
/// to accept a very small buffer (a transcoding console reader needs room for
/// a whole character). Bytes delivered after the newline are dropped with
/// the zeroized chunk; a terminal in canonical mode delivers at most one line
/// per `read`.
///
/// The line grows by hand, because `Vec`'s own reallocation frees the old
/// allocation without zeroizing it. It starts at [`PHRASE_CAPACITY`] and,
/// when full, moves into a fresh `Zeroizing` buffer of twice the size. A
/// `Vec<u8>` holds at most `isize::MAX` bytes, so doubling cannot overflow.
///
/// Out of reach: the terminal driver's buffers, anything a `Read`
/// implementation holds internally (`File` holds nothing), and copies the
/// compiler makes in registers or spilled stack slots.
fn read_scrubbed_line(mut from: impl io::Read) -> io::Result<Option<Zeroizing<String>>> {
    let mut chunk = Zeroizing::new([0u8; PHRASE_CAPACITY]);
    let mut line: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(PHRASE_CAPACITY));
    let mut ended = false;
    while !ended {
        let n = match from.read(&mut chunk[..]) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        for &byte in chunk.iter().take(n) {
            if line.len() == line.capacity() {
                let mut wider = Zeroizing::new(Vec::with_capacity(line.capacity() * 2));
                wider.extend_from_slice(&line);
                line = wider;
            }
            line.push(byte);
            if byte == b'\n' {
                ended = true;
                break;
            }
        }
    }
    if line.is_empty() {
        return Ok(None);
    }
    let text = std::str::from_utf8(&line).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "stream did not contain valid UTF-8",
        )
    })?;
    Ok(Some(Zeroizing::new(text.trim().to_string())))
}

impl create_cmd::Terminal for Tty {
    /// Writes to the acquired terminal, not stdout, so a redirect cannot
    /// capture the phrase, and the phrase and the confirmation question
    /// appear on the same screen.
    ///
    /// The write's result is returned: a descriptor that cannot be written
    /// fails the confirmation too, so the confirmation alone cannot detect
    /// it. `orchestrate` refuses on this error before anything is written.
    fn show(&mut self, text: &str) -> Result<(), String> {
        use std::io::Write as _;
        let mut out = self
            .file
            .try_clone()
            .map_err(|e| format!("cannot write to /dev/tty: {e}"))?;
        out.write_all(text.as_bytes())
            .and_then(|()| out.write_all(b"\n"))
            .and_then(|()| out.flush())
            .map_err(|e| format!("cannot write to /dev/tty: {e}"))
    }

    /// Reads the confirmation with echo on; see the trait method.
    ///
    /// Consuming `self` releases the echo guard, which restores echo, and
    /// leaves no `Tty` for a later secret read to use.
    fn read_visible_line(self, prompt: &str) -> Result<Zeroizing<String>, String> {
        let Tty { file, _echo } = self;
        // Restore echo, checked, and refuse before prompting if it fails:
        // this method's contract is that the answer is visible.
        _echo.restore()?;
        drop(_echo);
        let mut term = file
            .try_clone()
            .map_err(|e| format!("cannot write to /dev/tty: {e}"))?;
        // A prompt that cannot be written is an error.
        term.write_all(prompt.as_bytes())
            .and_then(|()| term.flush())
            .map_err(|e| format!("cannot write to /dev/tty: {e}"))?;
        let read = read_scrubbed_line(
            file.try_clone()
                .map_err(|e| format!("cannot read /dev/tty: {e}"))?,
        );
        match read {
            Ok(None) => Err(END_OF_INPUT.into()),
            Ok(Some(line)) => Ok(line),
            Err(e) => Err(format!("cannot read from /dev/tty: {e}")),
        }
    }

    /// Writes the prompt to the acquired terminal, not stderr, so a redirect
    /// cannot hide it.
    fn read_secret_line(&mut self, prompt: &str) -> Result<Zeroizing<String>, String> {
        let mut term = self
            .file
            .try_clone()
            .map_err(|e| format!("cannot write to /dev/tty: {e}"))?;
        // Checked: a missing prompt means a secret typed blind or an
        // indefinite wait.
        term.write_all(prompt.as_bytes())
            .and_then(|()| term.flush())
            .map_err(|e| format!("cannot write to /dev/tty: {e}"))?;
        let read = read_scrubbed_line(
            self.file
                .try_clone()
                .map_err(|e| format!("cannot read /dev/tty: {e}"))?,
        );
        // The newline after an echo-off read is cosmetic, so its write is
        // best-effort.
        let _ = term.write_all(b"\n");
        match read {
            Ok(None) => Err(END_OF_INPUT.into()),
            Ok(Some(line)) => Ok(line),
            Err(e) => Err(format!("cannot read from /dev/tty: {e}")),
        }
    }
}
