// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! The store's Windows layout: two slots, each rewritten in place, so that no
//! commit creates, renames or deletes a directory entry.
//!
//! On Windows the snapshot is not replaced by a rename. `accounts.mks` is
//! slot 0 and `accounts.mks.1` is slot 1; each holds one frame around one
//! whole image in [`super::format`]'s layout. A commit writes the slot that
//! does not hold the newest image and flushes it, and `open` reads both and
//! takes the image with the higher generation. A crash at any step, including
//! a torn write, leaves at least one intact image once a flush has returned.
//!
//! # The frame
//!
//! ```text
//! magic[8] = "MCMKSLOT" | frame_version u16 = 1 | payload_len u32
//! | payload[payload_len]   version 1: one image, or nothing for the vacant frame
//! | check[32]              SHA3-256 over every byte before it
//! ```
//!
//! A slot file is one frame and nothing after it, so its length is
//! [`OVERHEAD`] plus its payload's, and a file of any other length is torn.
//!
//! **The envelope is fixed and only the payload is versioned.** The magic, the
//! version, the length and the check keep these positions in every frame
//! version, so this build can verify the check of a frame it did not write:
//! an intact frame of a later version is refused, and only a frame whose check
//! fails is torn. If a later version could move the check, this build would
//! call that slot torn and take the older one beside it.
//!
//! **The check is keyless.** The image's own tag also refuses a torn image,
//! but only once a key exists, and it does not distinguish a torn image from
//! an altered one (see `Error::WrongPassword`). The check sorts the slots
//! first. A frame whose check fails is what a crash leaves, and it is never a
//! refusal while the other slot holds an image. A frame whose check passes and
//! whose tag then fails was sealed under another key or altered, which no
//! crash produces, and it is refused as `WrongPassword`, like a damaged
//! snapshot.
//!
//! **No counter in the frame.** The image's `generation` orders the slots. It
//! is inside the ciphertext so that a file does not reveal how often it was
//! written; a plaintext counter would reveal that, so both images are
//! decrypted and compared.
//!
//! # What `open` takes
//!
//! [`take`]'s rules, in order:
//!
//! * a frame in slot 0 with no slot 1 beside it is refused. Slot 1 is created
//!   before slot 0 is ever a frame, so only a deletion leaves that state, and
//!   taking slot 0 would silently roll back to an older image;
//! * with no intact image in either frame, slot 0 is read as a store in the
//!   rename layout is read (the whole file is one image), or, when slot 0 is a
//!   frame, the store is refused;
//! * otherwise every intact image is decrypted under one key, derived from an
//!   intact frame's header, and any that fails is refused. A slot 0 that is not
//!   a frame is also taken if it decrypts and parses; otherwise it is the torn
//!   remainder of an overwrite (a plain image is overwritten only once slot 1
//!   holds a flushed frame) and is skipped;
//! * of the remaining images the higher generation is the newest, and two at
//!   one generation are refused, since the writer never produces that pair.
//!
//! # Where this is compiled
//!
//! On Windows, where `Keystore::open_with` and the commit call it, and under
//! `cfg(test)` on every platform, so these rules are tested on every platform
//! against images the format itself seals. The write path and the reads
//! through held handles are Windows code in `medium` and the keystore, and
//! run only on Windows.

use zeroize::Zeroizing;

use super::{crypt, format};
use crate::error::{Error, Result};

const MAGIC: [u8; 8] = *b"MCMKSLOT";
const FRAME_VERSION: u16 = 1;
/// The magic, the version and the payload's length.
const HEAD_LEN: usize = 8 + 2 + 4;
const CHECK_LEN: usize = 32;

/// What a frame adds to its payload: forty-six bytes.
pub(crate) const OVERHEAD: usize = HEAD_LEN + CHECK_LEN;

/// The longest slot file this build writes, and the most `open` reads of one.
pub(crate) const MAX_FRAME_LEN: usize = OVERHEAD + format::MAX_IMAGE_LEN;

/// The frame around `image`, or around nothing: the vacant frame.
///
/// Built at its exact length, so the buffer never reallocates and leaves no
/// copy of the image behind.
pub(crate) fn frame(image: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let len = u32::try_from(image.len())
        .ok()
        .filter(|_| image.len() <= format::MAX_IMAGE_LEN)
        .ok_or(Error::Range {
            what: "keystore slot payload length",
            min: 0,
            max: format::MAX_IMAGE_LEN as u64,
            got: image.len() as u64,
        })?;
    let mut out: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(OVERHEAD + image.len()));
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&FRAME_VERSION.to_le_bytes());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(image);
    let check = crate::backend::native::sha3_256(&out);
    out.extend_from_slice(&check);
    Ok(out)
}

/// What one slot file holds, as `open` sorts it before any key exists.
pub(crate) enum Content {
    /// No such file. Only slot 1 is ever absent: a store in the rename layout
    /// has none.
    Absent,
    /// An intact frame around nothing.
    Vacant,
    /// An intact frame around an image: the image.
    Image(Zeroizing<Vec<u8>>),
    /// A frame whose length or check does not hold: what a write the device
    /// did not finish leaves.
    Torn,
    /// Bytes that do not begin with the frame's magic. In slot 0, a store in
    /// the rename layout (the whole file is one image) or what an overwrite of
    /// one left; in slot 1, nothing this writer produces.
    Other(Zeroizing<Vec<u8>>),
}

impl Content {
    /// The image an intact frame holds, if this is one.
    fn image(&self) -> Option<&[u8]> {
        match self {
            Content::Image(image) => Some(image),
            _ => None,
        }
    }
}

/// Sort a slot file's bytes, given `None` when the file does not exist.
///
/// An intact frame of a later version is refused rather than sorted: its
/// check holds, so no crash made it, and calling it torn would take the older
/// slot beside it.
pub(crate) fn sort(bytes: Option<Zeroizing<Vec<u8>>>) -> Result<Content> {
    let Some(bytes) = bytes else {
        return Ok(Content::Absent);
    };
    if bytes.get(..MAGIC.len()) != Some(&MAGIC[..]) {
        return Ok(Content::Other(bytes));
    }
    if bytes.len() > MAX_FRAME_LEN {
        return Ok(Content::Torn);
    }
    let Some((body, check)) = bytes
        .len()
        .checked_sub(CHECK_LEN)
        .filter(|&at| at >= HEAD_LEN)
        .map(|at| bytes.split_at(at))
    else {
        return Ok(Content::Torn);
    };
    // `body` is at least `HEAD_LEN` bytes by the filter above, so `head` is
    // exactly `HEAD_LEN`, and the six constant reads below are in bounds.
    let (head, payload) = body.split_at(HEAD_LEN);
    let version = u16::from_le_bytes([head[8], head[9]]);
    let declared = u32::from_le_bytes([head[10], head[11], head[12], head[13]]);
    if usize::try_from(declared).ok() != Some(payload.len()) {
        return Ok(Content::Torn);
    }
    if crate::backend::native::sha3_256(body)[..] != *check {
        return Ok(Content::Torn);
    }
    if version != FRAME_VERSION {
        return Err(Error::Corrupt {
            what: "a slot frame of a version this build does not read, which a newer build wrote",
            offset: MAGIC.len(),
        });
    }
    if payload.is_empty() {
        return Ok(Content::Vacant);
    }
    Ok(Content::Image(Zeroizing::new(payload.to_vec())))
}

/// What `open` takes: the newest image, parsed, and what the handle needs to
/// seal the next one. No `Debug`: it holds the key and the master seed.
pub(crate) struct Taken {
    /// The slot the image came from, which the next commit leaves alone.
    pub(crate) newest: usize,
    /// The format version that image carries.
    pub(crate) version: u16,
    pub(crate) parsed: format::Parsed,
    pub(crate) key: Zeroizing<[u8; crypt::KEY_LEN]>,
    pub(crate) kdf: crypt::Kdf,
    pub(crate) salt: [u8; crypt::SALT_LEN],
}

/// The newest image the two slots hold, by the rules the module doc lists.
pub(crate) fn take(slot0: &Content, slot1: &Content, password: &[u8]) -> Result<Taken> {
    let (image0, image1) = (slot0.image(), slot1.image());
    let slot0_framed = matches!(slot0, Content::Vacant | Content::Image(_) | Content::Torn);
    if slot0_framed && matches!(slot1, Content::Absent) {
        return Err(Error::Corrupt {
            what: "slot 0 holds a frame and slot 1 is missing",
            offset: 0,
        });
    }
    let Some(first) = image1.or(image0) else {
        return match slot0 {
            Content::Other(whole) => read_whole(whole, password),
            _ => Err(Error::Corrupt {
                what: "neither slot holds an intact image",
                offset: 0,
            }),
        };
    };
    let header = format::read_header(first)?.header;
    let (kdf, salt) = (header.kdf, header.salt);
    for image in [image0, image1].into_iter().flatten() {
        let other = format::read_header(image)?.header;
        if other.kdf != kdf || other.salt != salt {
            return Err(Error::Corrupt {
                what: "the two slots disagree on the salt or the key derivation",
                offset: 0,
            });
        }
    }
    let key = crypt::derive_key(password, &salt, kdf)?;
    let mut found: Vec<(usize, u16, format::Parsed)> = Vec::with_capacity(2);
    for (slot, image) in [(0, image0), (1, image1)] {
        if let Some(image) = image {
            let version = format::read_header(image)?.version;
            found.push((slot, version, format::parse_with_key(image, &key)?));
        }
    }
    // Slot 0 not a frame, beside an intact one: the older image if it reads,
    // and the torn remainder of an overwrite if it does not.
    if let Content::Other(whole) = slot0 {
        let version = format::read_header(whole)
            .ok()
            .filter(|framed| framed.header.kdf == kdf && framed.header.salt == salt)
            .map(|framed| framed.version);
        if let Some(version) = version {
            if let Ok(parsed) = format::parse_with_key(whole, &key) {
                found.push((0, version, parsed));
            }
        }
    }
    let mut newest: Option<(usize, u16, format::Parsed)> = None;
    for candidate in found {
        match &newest {
            Some(held) if held.2.generation == candidate.2.generation => {
                return Err(Error::Corrupt {
                    what: "both slots hold one generation",
                    offset: 0,
                });
            }
            Some(held) if held.2.generation > candidate.2.generation => {}
            _ => newest = Some(candidate),
        }
    }
    let (newest, version, parsed) = newest.ok_or(Error::Corrupt {
        what: "neither slot holds an intact image",
        offset: 0,
    })?;
    Ok(Taken {
        newest,
        version,
        parsed,
        key,
        kdf,
        salt,
    })
}

/// Slot 0 read as the rename layout reads a snapshot: the whole file one
/// image, refused by the format's own errors, in the format's own order.
fn read_whole(whole: &[u8], password: &[u8]) -> Result<Taken> {
    let framed = format::read_header(whole)?;
    let (salt, kdf, version) = (framed.header.salt, framed.header.kdf, framed.version);
    let key = crypt::derive_key(password, &salt, kdf)?;
    let parsed = format::parse_with_key(whole, &key)?;
    Ok(Taken {
        newest: 0,
        version,
        parsed,
        key,
        kdf,
        salt,
    })
}

#[cfg(test)]
mod tests {
    //! The rules above, against images [`format::encode`] seals. Each test
    //! builds its own images: the format is deterministic under fixed
    //! entropy, so two calls with one generation are one image.

    use super::*;
    use crate::account::Account;
    use crate::consts::SEED_LEN;
    use crate::secret::Secret;

    const PASSWORD: &[u8] = b"slot-test-password-not-for-use";
    const SALT: [u8; crypt::SALT_LEN] = [5u8; crypt::SALT_LEN];
    const OTHER_SALT: [u8; crypt::SALT_LEN] = [9u8; crypt::SALT_LEN];
    const NONCE_SEED: [u8; crypt::NONCE_SEED_LEN] = [6u8; crypt::NONCE_SEED_LEN];

    /// An image at `generation` holding `accounts` derived accounts, sealed
    /// under [`PASSWORD`] and `salt` with the cheap test parameters.
    fn sealed(generation: u64, accounts: u32, salt: &[u8; crypt::SALT_LEN]) -> Zeroizing<Vec<u8>> {
        let master = Secret::new([7u8; SEED_LEN]);
        let held: Vec<Account> = (0..accounts).map(|i| Account::derive(&master, i)).collect();
        let mut records: Vec<format::RecordRef<'_>> = held
            .iter()
            .map(|account| format::RecordRef {
                tag: account.tag(),
                account,
                wots_index: account.wots_index(),
                pending: None,
                settled: None,
            })
            .collect();
        records.sort_by_key(|record| record.tag);
        let key = crypt::derive_key(PASSWORD, salt, crypt::Kdf::CHEAP_FOR_TESTS).unwrap_or_else(|e| panic!("{e}"));
        let nonce = crypt::nonce_for(&NONCE_SEED, generation);
        format::encode(&records, generation, Some(&master), crypt::Kdf::CHEAP_FOR_TESTS, salt, &key, &nonce)
            .unwrap_or_else(|e| panic!("{e}"))
    }

    fn framed(image: &[u8]) -> Zeroizing<Vec<u8>> {
        frame(image).unwrap_or_else(|e| panic!("{e}"))
    }

    #[test]
    fn a_frame_round_trips_and_the_vacant_frame_is_its_overhead() {
        assert_eq!(OVERHEAD, 46, "the frame's overhead is not the forty-six bytes its doc states");
        let image = sealed(3, 1, &SALT);
        let whole = framed(&image);
        assert_eq!(whole.len(), OVERHEAD + image.len());
        match sort(Some(whole)) {
            Ok(Content::Image(back)) => assert!(back[..] == image[..], "the image did not come back out of its frame"),
            _ => panic!("an intact frame was not sorted as an image"),
        }
        let vacant = framed(&[]);
        assert_eq!(vacant.len(), OVERHEAD);
        assert!(matches!(sort(Some(vacant)), Ok(Content::Vacant)), "the vacant frame was not sorted as vacant");
        assert!(matches!(sort(None), Ok(Content::Absent)), "no file was not sorted as absent");
    }

    #[test]
    fn a_frame_cut_short_lengthened_or_changed_in_one_bit_is_never_an_image() {
        let whole = framed(&sealed(3, 2, &SALT));
        let mut driven = 0usize;
        for cut in 0..whole.len() {
            let got = sort(Some(Zeroizing::new(whole[..cut].to_vec())));
            assert!(matches!(got, Ok(Content::Torn | Content::Other(_))), "a frame cut to {cut} bytes was not torn");
            driven += 1;
        }
        let mut longer = Zeroizing::new(whole.to_vec());
        longer.push(0);
        assert!(matches!(sort(Some(longer)), Ok(Content::Torn)), "a frame with a byte after it was not torn");
        for at in 0..whole.len() {
            for bit in 0..8 {
                let mut changed = Zeroizing::new(whole.to_vec());
                changed[at] ^= 1 << bit;
                let got = sort(Some(changed));
                assert!(
                    matches!(got, Ok(Content::Torn | Content::Other(_))),
                    "a frame with bit {bit} of byte {at} changed was not torn"
                );
                driven += 1;
            }
        }
        assert_eq!(driven, 9 * whole.len(), "the walk did not drive every cut and every bit");
    }

    /// Not run under Miri: the test's cost is wiping the `MAX_FRAME_LEN + 1`
    /// bytes `sort` drops, which `Zeroizing` does one `&mut u8` at a time, and
    /// Miri tracks each of those borrows, so its time and memory grow faster
    /// than the length. The test checks one comparison,
    /// `bytes.len() > MAX_FRAME_LEN`, in safe code and before any hashing, and
    /// runs natively on every platform. Miri still interprets the wipe, at a
    /// few hundred bytes, for every frame
    /// `a_frame_cut_short_lengthened_or_changed_in_one_bit_is_never_an_image`
    /// cuts, lengthens or changes.
    #[cfg(not(miri))]
    #[test]
    fn a_frame_longer_than_any_this_build_writes_is_torn() {
        let mut too_long: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; MAX_FRAME_LEN + 1]);
        too_long[..MAGIC.len()].copy_from_slice(&MAGIC);
        assert!(matches!(sort(Some(too_long)), Ok(Content::Torn)), "a frame longer than any this build writes was not torn");
    }

    /// Every sector-by-sector mix of an old frame and a new one, at the old
    /// length and at the new: what an unfinished write can leave, in whatever
    /// order its sectors landed. Only the two frames themselves sort as images.
    #[test]
    fn an_old_frame_and_a_new_one_mixed_by_sector_are_neither() {
        const SECTOR: usize = 512;
        let old = framed(&sealed(4, 7, &SALT));
        let new = framed(&sealed(5, 8, &SALT));
        let sectors = old.len().max(new.len()).div_ceil(SECTOR);
        assert!(sectors >= 4, "the frames span {sectors} sectors, too few to mix");
        let mut driven = 0usize;
        for mask in 0u32..(1 << sectors) {
            for len in [old.len(), new.len()] {
                let mut torn: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; len]);
                for (at, byte) in torn.iter_mut().enumerate() {
                    let source = if mask & (1 << (at / SECTOR)) != 0 { &new } else { &old };
                    *byte = source.get(at).copied().unwrap_or(0);
                }
                let (is_old, is_new) = (torn[..] == old[..], torn[..] == new[..]);
                match sort(Some(torn)) {
                    Ok(Content::Image(_)) => {
                        assert!(is_old || is_new, "sectors {mask:#b} at {len} bytes sorted as an image")
                    }
                    Ok(Content::Torn | Content::Other(_)) => {
                        assert!(!is_old && !is_new, "an unmixed frame at {len} bytes sorted as torn")
                    }
                    _ => panic!("sectors {mask:#b} at {len} bytes sorted as neither an image nor torn"),
                }
                driven += 1;
            }
        }
        assert_eq!(driven, 2 << sectors, "the walk did not drive every mix at both lengths");
    }

    #[test]
    fn an_intact_frame_of_a_later_version_is_refused_and_not_called_torn() {
        let image = sealed(3, 1, &SALT);
        let mut later: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(OVERHEAD + image.len()));
        later.extend_from_slice(&MAGIC);
        later.extend_from_slice(&2u16.to_le_bytes());
        later.extend_from_slice(&u32::try_from(image.len()).unwrap_or_else(|e| panic!("{e}")).to_le_bytes());
        later.extend_from_slice(&image);
        let check = crate::backend::native::sha3_256(&later);
        later.extend_from_slice(&check);
        let refused = sort(Some(later)).err();
        assert!(
            matches!(refused, Some(Error::Corrupt { offset: 8, .. })),
            "an intact frame of version 2 was not refused at its version: {refused:?}"
        );
    }

    /// What `take` returns for one pair of slots, in a form that compares.
    fn outcome(slot0: &Content, slot1: &Content, password: &[u8]) -> std::result::Result<(usize, u64), Error> {
        take(slot0, slot1, password).map(|taken| (taken.newest, taken.parsed.generation))
    }

    /// Every pair of slot states, and what `take` must make of each: the
    /// module doc's rules as a table, one row per state of slot 0 and one
    /// column per state of slot 1.
    #[test]
    fn take_holds_the_newest_image_and_refuses_what_no_crash_makes() {
        let plain10 = sealed(10, 1, &SALT);
        let mut plain_torn = Zeroizing::new(plain10.to_vec());
        plain_torn[80] ^= 0x40;
        let torn_frame = {
            let whole = framed(&sealed(10, 1, &SALT));
            Zeroizing::new(whole[..whole.len() - 1].to_vec())
        };
        let content = |bytes: &Zeroizing<Vec<u8>>| sort(Some(Zeroizing::new(bytes.to_vec()))).unwrap_or_else(|e| panic!("{e}"));
        let image = |generation| content(&framed(&sealed(generation, 1, &SALT)));
        let slot0: [(&str, Content); 7] = [
            ("vacant", content(&framed(&[]))),
            ("torn", content(&torn_frame)),
            ("image 9", image(9)),
            ("image 10", image(10)),
            ("image 11", image(11)),
            ("plain 10", content(&plain10)),
            ("plain torn", content(&plain_torn)),
        ];
        let slot1: [(&str, Content); 7] = [
            ("absent", Content::Absent),
            ("vacant", content(&framed(&[]))),
            ("torn", content(&torn_frame)),
            ("other", content(&plain10)),
            ("image 9", image(9)),
            ("image 10", image(10)),
            ("image 11", image(11)),
        ];
        let missing = Err(Error::Corrupt { what: "slot 0 holds a frame and slot 1 is missing", offset: 0 });
        let none = Err(Error::Corrupt { what: "neither slot holds an intact image", offset: 0 });
        let same = Err(Error::Corrupt { what: "both slots hold one generation", offset: 0 });
        let wrong = Err(Error::WrongPassword);
        #[rustfmt::skip]
        let expected: [[std::result::Result<(usize, u64), Error>; 7]; 7] = [
            //      absent           vacant           torn             other            image 9          image 10         image 11
            [missing.clone(), none.clone(),    none.clone(),    none.clone(),    Ok((1, 9)),      Ok((1, 10)),     Ok((1, 11))],
            [missing.clone(), none.clone(),    none.clone(),    none.clone(),    Ok((1, 9)),      Ok((1, 10)),     Ok((1, 11))],
            [missing.clone(), Ok((0, 9)),      Ok((0, 9)),      Ok((0, 9)),      same.clone(),    Ok((1, 10)),     Ok((1, 11))],
            [missing.clone(), Ok((0, 10)),     Ok((0, 10)),     Ok((0, 10)),     Ok((0, 10)),     same.clone(),    Ok((1, 11))],
            [missing.clone(), Ok((0, 11)),     Ok((0, 11)),     Ok((0, 11)),     Ok((0, 11)),     Ok((0, 11)),     same.clone()],
            [Ok((0, 10)),     Ok((0, 10)),     Ok((0, 10)),     Ok((0, 10)),     Ok((0, 10)),     same,            Ok((1, 11))],
            [wrong.clone(),   wrong.clone(),   wrong.clone(),   wrong,           Ok((1, 9)),      Ok((1, 10)),     Ok((1, 11))],
        ];
        let mut driven = 0usize;
        for ((name0, state0), row) in slot0.iter().zip(expected.iter()) {
            for ((name1, state1), want) in slot1.iter().zip(row.iter()) {
                let got = outcome(state0, state1, PASSWORD);
                assert_eq!(&got, want, "slot 0 {name0}, slot 1 {name1}");
                driven += 1;
            }
        }
        assert_eq!(driven, 49, "the table did not drive every pair of states");
    }

    /// `take` returns what the newest image was sealed under: its version, its
    /// salt and parameters, and the key they derive, both when it reads an
    /// intact frame and when it reads the whole file.
    #[test]
    fn take_returns_what_the_newest_image_was_sealed_under() {
        let sorted = |bytes: &[u8]| sort(Some(Zeroizing::new(bytes.to_vec()))).unwrap_or_else(|e| panic!("{e}"));
        let key = crypt::derive_key(PASSWORD, &SALT, crypt::Kdf::CHEAP_FOR_TESTS).unwrap_or_else(|e| panic!("{e}"));
        let framed_pair = (sorted(&framed(&sealed(10, 1, &SALT))), sorted(&framed(&sealed(11, 1, &SALT))));
        let whole = (sorted(&sealed(10, 1, &SALT)), Content::Absent);
        for (route, (slot0, slot1)) in [("frames", framed_pair), ("whole file", whole)] {
            let taken = take(&slot0, &slot1, PASSWORD).unwrap_or_else(|e| panic!("{route}: {e}"));
            assert_eq!(taken.version, format::VERSION, "{route}: the version is not the image's");
            assert_eq!(taken.salt, SALT, "{route}: the salt is not the image's");
            assert_eq!(taken.kdf, crypt::Kdf::CHEAP_FOR_TESTS, "{route}: the parameters are not the image's");
            assert!(taken.key[..] == key[..], "{route}: the key is not the one the image was sealed under");
        }
    }

    #[test]
    fn a_wrong_password_and_two_salts_are_refused_whatever_else_the_slots_hold() {
        let sorted = |bytes: &[u8]| sort(Some(Zeroizing::new(bytes.to_vec()))).unwrap_or_else(|e| panic!("{e}"));
        let image10 = sorted(&framed(&sealed(10, 1, &SALT)));
        let image11 = sorted(&framed(&sealed(11, 1, &SALT)));
        let plain10 = sorted(&sealed(10, 1, &SALT));
        assert_eq!(outcome(&image10, &image11, b"not the password"), Err(Error::WrongPassword));
        assert_eq!(outcome(&plain10, &Content::Absent, b"not the password"), Err(Error::WrongPassword));
        let elsewhere = sorted(&framed(&sealed(11, 1, &OTHER_SALT)));
        assert_eq!(
            outcome(&image10, &elsewhere, PASSWORD),
            Err(Error::Corrupt {
                what: "the two slots disagree on the salt or the key derivation",
                offset: 0,
            })
        );
    }
}
