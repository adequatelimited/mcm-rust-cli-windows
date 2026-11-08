// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! `create`: make the store and put account 0 in it.
//!
//! `create` signs nothing and constructs no `Wallet`, so it runs before the
//! account is funded. (Every command that goes through `Wallet::open` refuses
//! a tag the ledger has never held.)
//!
//! # The recovery phrase
//!
//! * It is shown once and cannot be recovered from the store, which holds the
//!   seed derived from it, not the phrase.
//! * It is the only backup that survives a forgotten password: the password
//!   protects the file, and the phrase reconstructs the accounts.
//! * It appears on a terminal, so it may remain in the scrollback, terminal
//!   logs and session recordings.
//!
//! [`mnemonic::Phrase`] is `Zeroizing<String>` with a redacting `Debug`, so
//! the generated phrase is cleared on drop.
//!
//! # Entropy
//!
//! This crate has no RNG dependency, so the caller supplies the entropy; the
//! binary reads it from `/dev/urandom` (the OS CSPRNG). This also makes
//! `create` deterministic under test.

use std::path::Path;

use zeroize::Zeroizing;

use super::{Code, Report};
use crate::account::Account;
use crate::consts::SEED_LEN;
use crate::keystore::Keystore;
use crate::mnemonic;
use crate::{Error, Result, Secret};

/// Phrase entropy in bytes: BIP-39's 24-word case, as the browser extension
/// uses.
pub const ENTROPY_LEN: usize = 32;

/// Everything `create` needs from a random source.
///
/// Three independent draws: the phrase entropy becomes the wallet, the salt
/// makes two stores under one password different files, and the nonce seed
/// keeps a copy of a store from reusing a nonce. Deriving them from each
/// other would tie the store's key to the seed it protects.
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct CreateEntropy {
    pub phrase: [u8; ENTROPY_LEN],
    pub salt: [u8; crate::keystore::SALT_LEN],
    pub nonce_seed: [u8; crate::keystore::NONCE_SEED_LEN],
}

/// The text before and after the phrase on the screen that shows it.
const NOTICE_HEAD: &str = "\nWRITE THIS DOWN. It is shown once.\n\n  ";
const NOTICE_TAIL: &str = "\n\n\
    It is the ONLY backup of this wallet. It cannot be recovered from the store.\n\
    The store is sealed with the password you just chose; forget it and these words \
    are the only way back in.\n\
    These words are now in this terminal's scrollback, and in whatever your terminal \
    emulator keeps.\n";

/// The screen that shows the phrase, in zeroizing storage. The full length
/// is reserved first, so the string never reallocates and leaves no copy of
/// the phrase behind.
fn phrase_notice(phrase: &str) -> Zeroizing<String> {
    let mut text = Zeroizing::new(String::with_capacity(NOTICE_HEAD.len() + phrase.len() + NOTICE_TAIL.len()));
    text.push_str(NOTICE_HEAD);
    text.push_str(phrase);
    text.push_str(NOTICE_TAIL);
    text
}

/// What `create` made. Holds no phrase: [`create`] takes one, and generating
/// and confirming it is the caller's step, taken before anything is written.
pub struct Created {
    /// Account 0's tag — the thing to fund.
    pub tag: crate::addr::Tag,
}

/// Make the store from a phrase, derive account 0 and write it.
///
/// This is the write, and it is the last step of `create`: the phrase has
/// already been generated, shown and confirmed, or was typed by the operator.
/// [`Keystore::create`] refuses an existing store (`Error::Exists`), unsafe
/// directory permissions and a held lock. [`crate::keystore::occupied`],
/// asked by [`orchestrate`] before the password prompt, is the early copy of
/// the existence check.
///
/// The password floor ([`MIN_PASSWORD_LEN`]) is checked here, before the
/// directory is made, so every caller is held to it; the prompt's check in
/// [`read_new_password`] is the early copy. `Keystore::create` itself accepts
/// any password bytes. `password` is `&str` because the floor counts
/// characters.
///
/// # Errors
///
/// `Error::PasswordTooShort` below the floor, a phrase parse error, or any
/// refusal from the keystore.
pub fn create(
    dir: &Path,
    words: &str,
    password: &str,
    salt: [u8; crate::keystore::SALT_LEN],
    nonce_seed: [u8; crate::keystore::NONCE_SEED_LEN],
) -> Result<Created> {
    if let Some(chars) = short_password_chars(password) {
        return Err(Error::PasswordTooShort {
            chars,
            min: MIN_PASSWORD_LEN,
        });
    }
    // Parse the phrase before the directory exists, so a refused phrase
    // leaves nothing on disk
    // (`tests/cli.rs::a_refused_phrase_leaves_nothing_on_disk`).
    let master: Secret<SEED_LEN> = mnemonic::master_seed_from_phrase(words, "")?;

    let mut ks = Keystore::create(
        dir,
        &crate::keystore::Init {
            password: password.as_bytes(),
            salt,
            nonce_seed,
            // The production cost, paid once per command.
            kdf: crate::keystore::Kdf::RECOMMENDED,
        },
    )?;

    // Store the master seed before the account, so a store that holds an
    // account always holds the seed that derives it, even after a crash.
    let _durable = ks.adopt_master(&master)?;
    let account = Account::derive(&master, 0);
    let tag = account.tag();
    ks.add(account)?;
    Ok(Created { tag })
}

/// The shortest password `create` accepts, in characters.
///
/// A length floor and nothing else: no character-class rules, which push
/// people toward `Password1!` and would refuse a long passphrase of ordinary
/// words. The password is the only barrier between a stolen store file and
/// every account in it, so a short one is refused rather than warned about.
/// Argon2id at [`crate::keystore::Kdf::RECOMMENDED`] costs about seventy
/// milliseconds and 64 MiB per guess, which raises the price of each guess
/// but cannot protect a short password found in a wordlist.
///
/// The unit is Unicode scalar values, not UTF-8 bytes (see
/// [`short_password_chars`]).
pub const MIN_PASSWORD_LEN: usize = 12;

/// The character count of a password below [`MIN_PASSWORD_LEN`], or `None`
/// otherwise. The single measurement both [`password_refusal`] and
/// [`create`] use.
///
/// Counts Unicode scalar values (`chars()`). A decomposed accent counts as
/// two, which errs toward accepting; grapheme segmentation would need a
/// dependency.
fn short_password_chars(password: &str) -> Option<usize> {
    let chars = password.chars().count();
    (chars < MIN_PASSWORD_LEN).then_some(chars)
}

/// The refusal text for a password below [`MIN_PASSWORD_LEN`], or `None`.
///
/// The prompt's copy of the floor, asked by [`read_new_password`] before
/// anything is created. [`create`] checks again and is authoritative.
pub fn password_refusal(password: &str) -> Option<String> {
    let chars = short_password_chars(password)?;
    Some(format!(
        "that password is {chars} character(s); this wallet will not take fewer than \
         {MIN_PASSWORD_LEN}.\n  It is not a rule about digits or symbols -- there is none, and a \
         passphrase of ordinary words is a fine answer. It is that this password is now the ONLY \
         thing between somebody holding your store file and every account in it. Nothing was \
         created."
    ))
}

/// The words the confirmation asks for, by one-based position: first, middle
/// and last, so the operator has to look at the whole phrase.
pub const CONFIRM_POSITIONS: [usize; 3] = [1, 12, 24];

/// Whether `answer` gives the words `phrase` has at [`CONFIRM_POSITIONS`]
/// (ASCII case-insensitive).
///
/// This shows the operator was present and could read the phrase. It does not
/// show the phrase was written down; nothing here could, since the phrase is
/// on the same screen.
pub fn confirmation_matches(phrase: &str, answer: &str) -> bool {
    let words: Vec<&str> = phrase.split_whitespace().collect();
    let given: Vec<&str> = answer.split_whitespace().collect();
    if given.len() != CONFIRM_POSITIONS.len() {
        return false;
    }
    for (slot, position) in CONFIRM_POSITIONS.iter().enumerate() {
        match (words.get(position - 1), given.get(slot)) {
            (Some(want), Some(got)) if want.eq_ignore_ascii_case(got) => {}
            _ => return false,
        }
    }
    true
}


/// What `create --from-phrase` shows before it reads anything.
///
/// A warning, not a refusal: Mochimo wallets do not agree on how a phrase
/// becomes a seed, and a phrase carries no mark of its scheme. This program
/// implements the browser extension's scheme. A phrase from another scheme
/// derives a working store whose accounts are empty, with no error, so the
/// text describes that outcome.
pub const SCHEME_WARNING: &str = "\
BEFORE YOU TYPE: this wallet implements one derivation scheme.

Mochimo wallets do not agree on how a recovery phrase becomes a seed. This one
follows the shipped browser extension. A phrase written under a different
scheme is accepted here and derives a working store -- there is no error, and
nothing refuses it. What you get is a wallet whose accounts are empty, which is
exactly what a wallet nobody has ever paid looks like.

If the phrase came from this program or from the browser extension, continue.
If it came from somewhere else, confirm what that wallet derives before you
read an empty balance here as the truth about your funds.
";

/// What `create` needs from a terminal, behind a trait a test can make fail.
///
/// With no controlling terminal, `create` must write nothing and show no
/// phrase. Acquiring the terminal through `acquire` lets a test supply a
/// failing source and check that the directory does not exist and nothing was
/// shown; display goes through [`Terminal::show`] for the same reason.
pub trait Terminal: Sized {
    /// Show text the operator must read, and report whether it was written.
    ///
    /// The confirmation read uses the same descriptor, so it cannot detect a
    /// failed write; this result does. [`orchestrate`] refuses on `Err`
    /// before any store exists.
    fn show(&mut self, text: &str) -> core::result::Result<(), String>;
    /// Read one line without echoing it.
    fn read_secret_line(&mut self, prompt: &str) -> core::result::Result<Zeroizing<String>, String>;
    /// Read one line with echo, consuming the terminal.
    ///
    /// Taking `self` by value means no read can follow, so no secret is ever
    /// read with echo on. An implementation releases its echo guard and
    /// reads.
    ///
    /// The only caller asks for three words of a phrase already on screen, so
    /// echoing exposes nothing new. The answer is still [`Zeroizing`].
    fn read_visible_line(self, prompt: &str) -> core::result::Result<Zeroizing<String>, String>;
}

/// `create`, end to end: acquire the terminal, then everything else.
///
/// Named `orchestrate` rather than `run` because the test suite's source
/// check for signing routes matches functions by bare name, and `cli::run`
/// reaches the signer.
///
/// # Order
///
/// The terminal is acquired first, so no phrase is generated without
/// somewhere to confirm it. The password is read, and the phrase shown and
/// confirmed, before the store is written, so every refusal before the write
/// leaves nothing on disk.
///
/// # Holding the echo guard
///
/// The terminal, and with it echo-off, is held across the password reads and
/// the phrase display; the confirmation consumes it and restores echo before
/// the write.
///
/// * A `SIGKILL` inside that window leaves the terminal silent; `stty echo`
///   restores it. Re-checking the terminal per read would open a gap between
///   check and use.
/// * Echo affects only input, so the phrase displays normally.
/// * Drop order does not matter: the binary's guard holds its own duplicated
///   descriptor.
pub fn orchestrate<T: Terminal>(
    dir: &Path,
    from_phrase: bool,
    entropy: impl FnOnce() -> core::result::Result<Zeroizing<CreateEntropy>, String>,
    acquire: impl FnOnce() -> core::result::Result<T, String>,
) -> Report {
    let refused = |text: String| Report {
        text,
        code: Code::Refused,
    };

    // First: nothing below runs without somewhere to confirm.
    let mut term = match acquire() {
        Ok(t) => t,
        Err(e) => return refused(nothing_was_created(e)),
    };

    // Refuse an occupied directory before anything is asked or shown, so a
    // mistyped `--dir` cannot waste a phrase. The check at write time remains
    // authoritative. A lock file without a snapshot is not checked here: a
    // concurrent `create` holding the lock is refused with `Locked` at the
    // write instead, with nothing written.
    if let Some(what) = crate::keystore::occupied(dir) {
        return refused(nothing_was_created(format!(
            "a keystore already exists at {} (its {what} is present). Nothing was shown and \
             nothing was changed. `create` makes a new store: use a different --dir for one. To \
             add an account to this store, run `restore --account N` against it; `address` \
             lists what it holds.",
            dir.display()
        )));
    }

    if from_phrase {
        // Show the warning before either read, so the operator can stop
        // before typing anything.
        if let Err(e) = term.show(SCHEME_WARNING) {
            return refused(nothing_was_created(e));
        }
        // Read the password first, so a refusal (too short, or the two did
        // not match) comes before the operator types the phrase.
        let password = match read_new_password(&mut term) {
            Ok(p) => p,
            Err(e) => return refused(e),
        };
        // `entropy_from_phrase` accepts 12, 15, 18, 21 and 24 words, the same
        // set as `@scure/bip39`; the prompt names the two common counts.
        let words = match term.read_secret_line("existing recovery phrase (12 or 24 words): ") {
            Ok(w) => w,
            Err(e) => return refused(nothing_was_created(e)),
        };
        let e = match entropy() {
            Ok(e) => e,
            Err(e) => return refused(nothing_was_created(e)),
        };
        return match create(dir, &words, &password, e.salt, e.nonce_seed) {
            Ok(c) => match super::destination(&c.tag) {
                Ok(dest) => Report {
                    text: created_text(dir, &dest, None),
                    code: Code::Ok,
                },
                Err(e) => refused(format!(
                    "the store at {} was created from the phrase you supplied, but its \
                     destination could not be rendered ({e}). `address` with no argument reads \
                     it back from the store.",
                    dir.display()
                )),
            },
            // `create` parses the phrase before it makes the directory.
            Err(e) => refused(nothing_was_created(e)),
        };
    }

    // Read the password before generating the phrase, so a refusal here
    // leaves no phrase on screen.
    let password = match read_new_password(&mut term) {
        Ok(p) => p,
        Err(e) => return refused(e),
    };
    let entropy = match entropy() {
        Ok(e) => e,
        Err(e) => return refused(nothing_was_created(e)),
    };
    let phrase = match mnemonic::phrase_from_entropy(&entropy.phrase) {
        Ok(p) => p,
        Err(e) => return refused(nothing_was_created(e)),
    };

    // Nothing is written yet, so a failed display is an ordinary refusal.
    if let Err(e) = term.show(&phrase_notice(phrase.expose())) {
        return refused(nothing_was_created(e));
    }

    // Confirm before writing, so a wrong answer or a broken display leaves
    // no store on disk. The phrase shown is still one `create --from-phrase`
    // away from its wallet.
    let p = CONFIRM_POSITIONS;
    let answer = match term.read_visible_line(&format!(
        "type words {}, {} and {}, separated by spaces: ",
        p[0], p[1], p[2]
    )) {
        Ok(a) => a,
        Err(e) => return refused(nothing_was_created(e)),
    };
    if !confirmation_matches(phrase.expose(), &answer) {
        return refused(format!(
            "those are not words {}, {} and {}. Nothing was created.\n\n  The phrase above \
             belongs to no store. Run `create` again for a fresh phrase, or `create \
             --from-phrase` to build the store from this one -- and either way, write the \
             phrase down before anything is sent to the wallet.",
            p[0], p[1], p[2]
        ));
    }

    let created = match create(
        dir,
        phrase.expose(),
        &password,
        entropy.salt,
        entropy.nonce_seed,
    ) {
        Ok(c) => c,
        Err(e) => return refused(nothing_was_created(e)),
    };

    let Ok(dest) = super::destination(&created.tag) else {
        return refused(after_the_store_exists(dir));
    };
    Report {
        text: created_text(dir, &dest, Some(p.len())),
        code: Code::Ok,
    }
}

/// The refusal for the one failure after the write: the store is correct but
/// its destination could not be rendered. The text gives the way out first
/// (deleting the directory is free until the account is funded), then the way
/// on.
fn after_the_store_exists(dir: &Path) -> String {
    format!(
        "the confirmation was answered correctly and the store was written, but its \
         destination could not be rendered.\n\nA keystore WAS created at {} and account 0 is in \
         it. The phrase shown above is its only backup and cannot be recovered from the \
         store.\n\n  IF YOU DID NOT WRITE THE PHRASE DOWN: delete {} and run `create` again. \
         That is free right now and stops being possible the moment this account holds \
         funds.\n\nThe destination could not be rendered here. `address` with no argument reads \
         it back from the store, and needs neither a node nor the phrase.",
        dir.display(),
        dir.display()
    )
}

/// Read a new password twice and require the two to agree.
///
/// Echo stays off: unlike the phrase confirmation, a new password is on no
/// screen, so typing it twice replaces seeing it. Both reads come before the
/// visible confirmation, the only read that echoes.
///
/// Every refusal ends with "Nothing was created."
fn read_new_password<T: Terminal>(term: &mut T) -> core::result::Result<Zeroizing<String>, String> {
    let first = term
        .read_secret_line("choose a password for this wallet (it will be needed for every command): ")
        .map_err(nothing_was_created)?;
    if let Some(why) = password_refusal(&first) {
        return Err(why);
    }
    let again = term
        .read_secret_line("type it again: ")
        .map_err(nothing_was_created)?;
    if first.as_bytes() != again.as_bytes() {
        return Err("those two passwords are not the same. Nothing was created.".into());
    }
    Ok(first)
}

/// Append "Nothing was created." to a refusal from another source (the
/// terminal, the entropy source, the phrase parser or the keystore), adding a
/// period first if the text does not already end a sentence. Every refusal
/// [`orchestrate`] returns before the write ends this way.
pub fn nothing_was_created(text: impl core::fmt::Display) -> String {
    let text = text.to_string();
    let text = text.trim_end();
    if text.ends_with(['.', '!', '?']) {
        format!("{text} Nothing was created.")
    } else {
        format!("{text}. Nothing was created.")
    }
}

/// The success page. Takes the rendered Base58 destination rather than the
/// tag, so it cannot print a 40-hex tag, which wallets do not accept as a
/// destination.
fn created_text(dir: &Path, dest: &str, confirmed: Option<usize>) -> String {
    let mut out = format!("created {}\n  destination  {dest}\n", dir.display());
    if let Some(n) = confirmed {
        out.push_str(&format!("  confirmed    {n} words read back\n"));
    }
    out.push_str(
        "\nThat destination is where funds are sent -- Base58 over the tag and its CRC16, the \
         form every Mochimo wallet takes. Give it to whoever is paying you.\n\nNext: `address` \
         with no argument prints it again, and `address <destination>` adds the 40-byte ledger \
         address; both need no `--node` and work before this account has any funds. Every other \
         command asks a node first, requires `--node`, and refuses until the account has been \
         funded at least once.",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_phrase_notice_is_one_exact_allocation_holding_the_phrase() {
        let phrase = "abandon ".repeat(23) + "zoo";
        let notice = phrase_notice(&phrase);
        assert_eq!(notice.capacity(), notice.len());
        assert!(notice.starts_with(NOTICE_HEAD));
        assert!(notice.ends_with(NOTICE_TAIL));
        assert!(notice.contains(&format!("\n\n  {phrase}\n\nIt is the ONLY backup")));
    }
}
