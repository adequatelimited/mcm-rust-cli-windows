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
//! They are read from the terminal device, not stdin, so a pipe or redirect
//! cannot supply them: `/dev/tty` on Unix, and on Windows the console's own
//! buffers, `CONIN$` and `CONOUT$`, opened by name in the `console` module at
//! the end of this file. [`TERMINAL`] is the one place either device is named
//! in a message. The binary is therefore not scriptable: every command that
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
#[cfg(unix)]
const END_OF_INPUT: &str =
    "end of input at the prompt: the terminal reported end-of-file (Ctrl-D) before a line was \
     typed, so nothing was read and nothing was compared. Type the answer and press Enter, or \
     run the command again.";
/// The refusal for end of input at a console prompt before any character was
/// read. It names the Windows keys: `Ctrl-Z` at the start of a line, which
/// the `console` module's `CTRL_Z` treats as end of input, and `Ctrl-C`,
/// after which a console read can return no characters.
#[cfg(windows)]
const END_OF_INPUT: &str =
    "end of input at the prompt: the console reported end of input (Ctrl-Z at the start of the \
     line, or Ctrl-C) before a line was typed, so nothing was read and nothing was compared. \
     Type the answer and press Enter, or run the command again.";

/// The device secrets are read from, as every message about it names it.
///
/// One constant rather than the path spelled in each message, because the
/// `Terminal` impl below serves both platforms: a message there that named
/// `/dev/tty` would name, on Windows, a device the program never opened.
#[cfg(unix)]
const TERMINAL: &str = "/dev/tty";
/// The device secrets are read from, as every message about it names it.
#[cfg(windows)]
const TERMINAL: &str = "the console (CONIN$ and CONOUT$)";

/// What a [`Tty`] reads and writes through: the terminal device by path on
/// Unix, the console's two buffers on Windows. Both are `Read`, `Write` and
/// `try_clone`, which is all the `Terminal` impl asks of it.
#[cfg(unix)]
type Device = std::fs::File;
#[cfg(windows)]
type Device = console::Console;

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
#[cfg(unix)]
struct EchoGuard(std::fs::File);

#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
impl Drop for EchoGuard {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

/// `N` bytes from the OS CSPRNG, read from `/dev/urandom`.
///
/// The library takes entropy as a parameter and reaches no generator, so the
/// binary supplies it. This is the Unix arm; the Windows arm is
/// `console::os_bytes`. A failed open or a short read is an error, so a weak
/// draw is never returned in place of a strong one.
///
/// Generic over the width because the phrase entropy, the KDF salt and the
/// per-open nonce seed are separate draws; see `cli::create::CreateEntropy`.
#[cfg(unix)]
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

/// `create`: supplies the real terminal and the OS generator to
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

/// The controlling terminal (the console on Windows), with echo off for the
/// `Tty`'s whole life. The guard holds its own duplicated descriptor, so
/// field drop order does not matter.
struct Tty {
    file: Device,
    _echo: EchoGuard,
}

/// Opens `/dev/tty` for reading and writing, then turns echo off. A
/// read-only descriptor would fail every prompt write with `EBADF`.
///
/// This is the only place the terminal is opened on Unix: [`acquire_terminal`]
/// and [`read_secret_line`] both come through it. The Windows arm is
/// `console::open_terminal`.
#[cfg(unix)]
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
            .map_err(|e| format!("cannot write to {TERMINAL}: {e}"))?;
        out.write_all(text.as_bytes())
            .and_then(|()| out.write_all(b"\n"))
            .and_then(|()| out.flush())
            .map_err(|e| format!("cannot write to {TERMINAL}: {e}"))
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
            .map_err(|e| format!("cannot write to {TERMINAL}: {e}"))?;
        // A prompt that cannot be written is an error.
        term.write_all(prompt.as_bytes())
            .and_then(|()| term.flush())
            .map_err(|e| format!("cannot write to {TERMINAL}: {e}"))?;
        let read = read_scrubbed_line(
            file.try_clone()
                .map_err(|e| format!("cannot read {TERMINAL}: {e}"))?,
        );
        match read {
            Ok(None) => Err(END_OF_INPUT.into()),
            Ok(Some(line)) => Ok(line),
            Err(e) => Err(format!("cannot read from {TERMINAL}: {e}")),
        }
    }

    /// Writes the prompt to the acquired terminal, not stderr, so a redirect
    /// cannot hide it.
    fn read_secret_line(&mut self, prompt: &str) -> Result<Zeroizing<String>, String> {
        let mut term = self
            .file
            .try_clone()
            .map_err(|e| format!("cannot write to {TERMINAL}: {e}"))?;
        // Checked: a missing prompt means a secret typed blind or an
        // indefinite wait.
        term.write_all(prompt.as_bytes())
            .and_then(|()| term.flush())
            .map_err(|e| format!("cannot write to {TERMINAL}: {e}"))?;
        let read = read_scrubbed_line(
            self.file
                .try_clone()
                .map_err(|e| format!("cannot read {TERMINAL}: {e}"))?,
        );
        // The newline after an echo-off read is cosmetic, so its write is
        // best-effort.
        let _ = term.write_all(b"\n");
        match read {
            Ok(None) => Err(END_OF_INPUT.into()),
            Ok(Some(line)) => Ok(line),
            Err(e) => Err(format!("cannot read from {TERMINAL}: {e}")),
        }
    }
}

#[cfg(windows)]
use console::{open_terminal, os_bytes, EchoGuard};

/// The Windows console, in place of `/dev/tty`, `stty` and `/dev/urandom`.
///
/// The device is the console's input buffer and active screen buffer, opened
/// by name as `CONIN$` and `CONOUT$`. Neither is a standard stream, so a pipe
/// or a redirect of stdin, stdout or stderr supplies nothing and captures
/// nothing. Echo is the input buffer's `ENABLE_ECHO_INPUT` mode bit. The
/// generator is `BCryptGenRandom` with the system-preferred provider.
///
/// Reads and writes use `ReadConsoleW` and `WriteConsoleW`, not
/// `std::fs::File` over the same handles. `ReadFile` on a console returns
/// bytes in the console's input code page, so a non-ASCII password would be
/// different bytes on Windows than on Unix for the same keystrokes, and a
/// store sealed on one would refuse it on the other. The wide calls deliver
/// UTF-16, which is transcoded here, so a password's bytes are its UTF-8 on
/// every platform. Output is transcoded the same way in the other direction.
///
/// `Console` implements `Read` and `Write`, so the `Terminal` impl above
/// serves both platforms with one copy of its ordering: the refusal before
/// the read, the checked restore before the visible prompt, and end of input
/// refused as such.
///
/// # Assumptions and limits
///
/// No test exercises this module; `tests/cli.rs`'s pseudo-terminal harness
/// covers the Unix arm only.
///
/// * A line longer than one read arrives over several `ReadConsoleW` calls;
///   at the sizes `READ_UNITS`'s doc gives, a 215-character phrase and its
///   CR LF take two. Joining them relies on the console buffering the unread
///   characters of a cooked line until the next read, as Microsoft's
///   documentation of the high-level console functions states.
/// * `Ctrl-Z` ends the input only when it begins a line. `Console` detects a
///   line's start by whether the previous read ended on the line feed a
///   cooked read returns with the Enter that ends the line. With
///   `ENABLE_LINE_INPUT`, a read returns only once a carriage return is read
///   (`SetConsoleMode`'s documentation), and the line feed after it is what
///   `read_scrubbed_line` stops on.
/// * The console mode belongs to the console's input buffer, which the
///   parent shell shares. The guard restores it on every path that unwinds,
///   and the restore is checked where a visible answer depends on it.
/// * `Ctrl-C` at a prompt: the default control handler ends the process,
///   which runs no destructor and can leave echo off in that console, as
///   `SIGINT` can on Unix; the README's limits cover signals. When the read
///   returns first with no characters, the guard restores the mode before
///   the end-of-input refusal is printed. Whether the read always returns
///   first is not established.
/// * Under a terminal that is not a Windows console and hosts no
///   pseudo-console (`mintty` without `winpty`), `CONIN$` may open a console
///   nobody can see, and the prompt would wait for input nobody can type.
///   This module is written for Windows Terminal, the classic console host
///   and editors that host a pseudo-console.
#[cfg(windows)]
mod console {
    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::os::windows::io::AsRawHandle;
    use std::ptr;

    use windows_sys::Win32::Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG};
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, ReadConsoleW, SetConsoleMode, WriteConsoleW, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT,
    };
    use zeroize::Zeroizing;

    use super::Tty;

    /// The most UTF-16 units asked of one `ReadConsoleW`, whatever buffer a
    /// caller offers. This is a ceiling; the smaller bound comes from the
    /// buffer. `Console::read` asks for a third of the buffer it is offered,
    /// less a unit, and `read_scrubbed_line` offers `PHRASE_CAPACITY` bytes,
    /// so one read takes at most 169 units, and one more when it ends on a
    /// high surrogate. A longer line arrives over several reads, which
    /// `read_scrubbed_line` joins: a twenty-four-word phrase can be 215
    /// characters and a CR LF, so a long one takes two. The module doc says
    /// what the joining relies on.
    const READ_UNITS: usize = 4096;

    /// A line beginning with `Ctrl-Z` is end of input at a Windows console,
    /// as it is to `std`'s own console reader. It reaches the shared code as
    /// a zero-byte read, which is refused as `END_OF_INPUT`, since nothing
    /// came before it on the line.
    ///
    /// The test is per line, not per read. A line longer than one read
    /// arrives over several (at the size `READ_UNITS`'s doc gives, the 170th
    /// character of a line with no surrogate pair before it begins the
    /// second), and a `Ctrl-Z` that falls first in a later read is a
    /// character of the line. `Console` tracks whether a read begins a line
    /// from the read before it, so where a line is split into reads does not
    /// change the result.
    const CTRL_Z: u16 = 0x1A;

    /// Where a line ends, as `read_scrubbed_line` reads one: the line feed of
    /// the CR LF a cooked read returns with the Enter that ends the line.
    const LF: u16 = 0x0A;

    /// The console's input buffer and active screen buffer.
    pub(super) struct Console {
        input: File,
        output: File,
        /// Whether the next read begins a line: set when the console is
        /// opened, cleared by a read that ends inside a line, and set again
        /// by one that ends on `LF`. `CTRL_Z`'s test asks it.
        ///
        /// A clone carries the flag of the handle it came from. Every clone
        /// taken here is of a handle the `Terminal` impl never reads
        /// through, so each begins at a line's start, and `read_scrubbed_line`
        /// reads one clone to the end of one line and no further.
        at_line_start: bool,
    }

    impl Console {
        pub(super) fn try_clone(&self) -> io::Result<Console> {
            Ok(Console {
                input: self.input.try_clone()?,
                output: self.output.try_clone()?,
                at_line_start: self.at_line_start,
            })
        }

        fn read_units(&self, out: &mut [u16]) -> io::Result<usize> {
            let len = u32::try_from(out.len()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
            let mut read = 0u32;
            // SAFETY: `out` is `len` writable UTF-16 units, `read` is a valid
            // place for the count, and the input-control argument is
            // optional and null. The handle is `CONIN$`, which `input` owns.
            let ok = unsafe {
                ReadConsoleW(self.input.as_raw_handle(), out.as_mut_ptr().cast(), len, &mut read, ptr::null())
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(read as usize)
        }
    }

    impl Read for Console {
        /// One `ReadConsoleW`, transcoded to UTF-8 into `buf`.
        ///
        /// At most a third of `buf.len()` units are asked for, because one
        /// UTF-16 unit is at most three UTF-8 bytes and a surrogate pair is
        /// four bytes from two units, so the transcoding always fits and no
        /// typed byte is held here between calls. A read that ends on a high
        /// surrogate is completed by one more unit, which the same bound has
        /// room for, so a pair is never split across two reads.
        ///
        /// A read that begins a line with `Ctrl-Z` is end of input; see
        /// `CTRL_Z`. A buffer shorter than six bytes is refused as
        /// `InvalidInput`.
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let want = (buf.len() / 3).min(READ_UNITS);
            if want < 2 {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            let mut units = Zeroizing::new(vec![0u16; want]);
            let mut n = self.read_units(&mut units[..want - 1])?;
            if n > 0 && (0xD800..0xDC00).contains(&units[n - 1]) {
                n += self.read_units(&mut units[n..n + 1])?;
            }
            let begins_a_line = self.at_line_start;
            if let Some(&last) = units[..n].last() {
                self.at_line_start = last == LF;
            }
            if begins_a_line && units[..n].first() == Some(&CTRL_Z) {
                return Ok(0);
            }
            let mut written = 0;
            for c in char::decode_utf16(units[..n].iter().copied()) {
                let c = c.map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
                written += c.encode_utf8(&mut buf[written..]).len();
            }
            Ok(written)
        }
    }

    impl Write for Console {
        /// All of `buf`, as UTF-16, or an error.
        ///
        /// `buf` must be whole UTF-8: every caller writes a `&str`'s bytes in
        /// one call, and a slice that splits a character is refused as
        /// `InvalidData` rather than written as a replacement character. The
        /// wide copy is zeroized, because the phrase passes through here, and
        /// its capacity is reserved before it is filled (a string never has
        /// more UTF-16 units than UTF-8 bytes), so it never reallocates and
        /// never leaves an unzeroized copy behind.
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let text = std::str::from_utf8(buf).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
            let mut units: Zeroizing<Vec<u16>> = Zeroizing::new(Vec::with_capacity(text.len()));
            units.extend(text.encode_utf16());
            let mut done = 0;
            while done < units.len() {
                let rest = &units[done..];
                let len = u32::try_from(rest.len()).unwrap_or(u32::MAX);
                let mut wrote = 0u32;
                // SAFETY: `rest` holds at least `len` readable units, `wrote`
                // is a valid place for the count, and the reserved argument
                // is null as documented. The handle is `CONOUT$`, which
                // `output` owns.
                let ok = unsafe {
                    WriteConsoleW(self.output.as_raw_handle(), rest.as_ptr(), len, &mut wrote, ptr::null())
                };
                if ok == 0 {
                    return Err(io::Error::last_os_error());
                }
                if wrote == 0 {
                    return Err(io::ErrorKind::WriteZero.into());
                }
                done += wrote as usize;
            }
            Ok(buf.len())
        }

        /// `WriteConsoleW` is unbuffered, so there is nothing to flush.
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// The console's echo, off for as long as the guard lives: the Windows
    /// arm of the Unix `EchoGuard`. A failure to turn echo off is a refusal,
    /// and the restore is checked by the one caller whose answer must be
    /// visible.
    pub(super) struct EchoGuard {
        input: File,
        mode: u32,
    }

    /// Turns echo off and line input on.
    ///
    /// Line input is set, not just kept: the console requires it for echo to
    /// be off, and it gives the operator backspace while typing blind, like
    /// the Unix terminal's canonical mode. The guard restores the mode found,
    /// whatever it was.
    pub(super) fn echo_off(console: &Console) -> Result<EchoGuard, String> {
        let input = console
            .input
            .try_clone()
            .map_err(|e| format!("cannot duplicate the console input handle: {e}"))?;
        let handle = input.as_raw_handle();
        let mut mode = 0u32;
        // SAFETY: `handle` is the `CONIN$` handle `input` owns, and `mode` is
        // a valid place for the mode.
        let found = unsafe { GetConsoleMode(handle, &mut mode) } != 0;
        // SAFETY: the same handle, and a mode derived from the one it reported.
        let set = found && unsafe { SetConsoleMode(handle, (mode | ENABLE_LINE_INPUT) & !ENABLE_ECHO_INPUT) } != 0;
        if !set {
            return Err(
                "refusing to read a secret with terminal echo on: the words would be visible and \
                 may be kept in the terminal's scrollback. Nothing was read."
                    .into(),
            );
        }
        Ok(EchoGuard { input, mode })
    }

    impl EchoGuard {
        /// Restores the mode found and reports whether it worked. As on Unix,
        /// the visible confirmation prompt calls this through `?` and refuses
        /// before prompting; `Drop` calls it best-effort.
        pub(super) fn restore(&self) -> Result<(), String> {
            // SAFETY: the `CONIN$` handle `input` owns, and the mode the
            // console itself reported for it.
            if unsafe { SetConsoleMode(self.input.as_raw_handle(), self.mode) } == 0 {
                return Err(
                    "cannot turn console echo back on, so the confirmation would be typed blind. \
                     That is how the words get mistyped. Nothing further was read; close this \
                     console window and open another to restore it."
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

    /// The console, with echo already off: the Windows arm of
    /// `open_terminal`, and like it the only place the device is opened.
    ///
    /// Both names are opened for reading and writing: `SetConsoleMode` needs
    /// the input buffer opened for both, and `GetConsoleMode` on the screen
    /// buffer does too. `std` does not pass either name to `CreateFileW` as
    /// given: its `maybe_verbatim` sends a short relative name through
    /// `GetFullPathNameW` and prefixes the result with `\\?\`. Both names
    /// still open the console through `OpenOptions`; how the prefixed name
    /// resolves to it is not established here.
    pub(super) fn open_terminal() -> Result<Tty, String> {
        let open = |name: &str| {
            std::fs::OpenOptions::new().read(true).write(true).open(name).map_err(|e| {
                format!(
                    "cannot open {name}: {e}. This program reads secrets from the console it runs \
                     in and there is none here -- it cannot be driven from a pipe, a scheduled \
                     task or a harness without one."
                )
            })
        };
        let file = Console {
            input: open("CONIN$")?,
            output: open("CONOUT$")?,
            at_line_start: true,
        };
        let _echo = echo_off(&file)?;
        Ok(Tty { file, _echo })
    }

    /// `N` bytes from the system generator: the Windows arm of `os_bytes`.
    ///
    /// Every way it can fail is loud, as on Unix: a draw too wide for one call
    /// is refused before the call, and a non-zero status is an error, so a
    /// weak draw is never returned in place of a strong one.
    pub(super) fn os_bytes<const N: usize>() -> Result<Zeroizing<[u8; N]>, String> {
        let mut buf = Zeroizing::new([0u8; N]);
        let len = u32::try_from(N).map_err(|_| format!("a {N}-byte draw does not fit one BCryptGenRandom call"))?;
        // SAFETY: a null algorithm handle with the system-preferred flag is
        // the documented form of the call, and `buf` is `len` writable bytes.
        let status = unsafe { BCryptGenRandom(ptr::null_mut(), buf.as_mut_ptr(), len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
        if status != 0 {
            return Err(format!("the system random generator failed (BCryptGenRandom, NTSTATUS {status:#010x})"));
        }
        Ok(buf)
    }
}
