// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

#![cfg(feature = "native")]
//! The transaction wire codec, tested without the C reference.
//!
//! Gated on `native` only, so it runs under
//! `--no-default-features --features native`, the configuration Miri can
//! interpret. The image walk lives in `support/wire_images.rs`, shared with
//! `spend.rs`.
//!
//! # Limits
//!
//! A parser and serializer that share the same wrong offset still round-trip.
//! The recorded-field assertions catch such errors within the corpus only, so
//! a pass means the C-free build round-trips the corpus, not that the codec
//! matches the C everywhere.

#[path = "support/wire_images.rs"]
mod wire_images;

use mochimo_crypto::tx::wire::{Body, Destination, Transaction};
use mochimo_crypto::Error;

/// Every group D wire image, parsed and re-serialized natively with every
/// recorded field asserted, in a test binary that links no C.
///
/// The counts are fixed: 71 images, 67 accepted by the reference and
/// round-tripped byte-identically, and 4 rejected (`D14`'s one-byte-long
/// form, `D15`'s three unknown-type cases) and also rejected natively.
#[test]
fn native_transaction_round_trip_needs_no_reference() {
    let file = wire_images::fixture_json("group_d_tx.json");
    let totals = wire_images::native_round_trip_walk(&file);

    // The full corpus normally; under Miri, whose isolation forbids file
    // access, the ten-image embedded subset (`wire_images::embedded`).
    let (want_accepted, want_rejected, field_floor) =
        if cfg!(miri) { (8, 2, 40) } else { (67, 4, 60) };
    assert_eq!(
        totals.accepted, want_accepted,
        "expected {want_accepted} accepted group D wire images to round-trip; \
         walked {}. If the corpus grew, restate this number deliberately; if \
         it shrank, an image key stopped being walked.",
        totals.accepted
    );
    assert_eq!(
        totals.rejected, want_rejected,
        "expected {want_rejected} reference-rejected group D wire images; saw {}",
        totals.rejected
    );
    assert!(
        totals.field_assertions >= field_floor,
        "only {} recorded-field assertions ran across the walk (floor \
         {field_floor}); the field gate has come apart from the corpus",
        totals.field_assertions
    );

    println!(
        "  C-free transaction round trip: {} images byte-identical, {} \
         rejections reproduced, {} recorded fields asserted",
        totals.accepted, totals.rejected, totals.field_assertions
    );
}

/// The bytes of a group D sidecar file. Under Miri only `Ds1_N1_hashed.bin`
/// is embedded, so one of the five hashed images is checked.
fn hashed_image(name: &str) -> Option<Vec<u8>> {
    #[cfg(miri)]
    {
        if name == "Ds1_N1_hashed.bin" {
            return Some(include_bytes!("../../../fixtures/Ds1_N1_hashed.bin").to_vec());
        }
        None
    }
    #[cfg(not(miri))]
    {
        Some(wire_images::fixture_bytes(name))
    }
}

/// The node's two transaction digests (`tx_hash`), reproduced natively
/// against values recorded from the reference: each `Ds1-N*` vector carries
/// the hashed image (`hashed_wire_file`) and both outputs (`message_hash`,
/// `id_hash`). Then `seal` must keep the prefix and validation data, write a
/// zero nonce, and set the id to the id digest of the sealed image, as
/// `process_tx` does.
#[test]
fn native_digests_match_the_reference_recorded_hashes() {
    let file = wire_images::fixture_json("group_d_tx.json");
    let mut checked = 0usize;
    for v in file["vectors"].as_array().expect("vectors") {
        let (Some(hashed), Some(message_hash), Some(id_hash)) = (
            v.get("hashed_wire_file").and_then(|x| x.as_str()),
            v.get("message_hash").and_then(|x| x.as_str()),
            v.get("id_hash").and_then(|x| x.as_str()),
        ) else {
            continue;
        };
        let id = v["id"].as_str().unwrap_or("?");
        let Some(bytes) = hashed_image(hashed) else { continue };
        let tx = Transaction::from_wire(&bytes).unwrap_or_else(|e| panic!("{id}: {hashed} does not parse: {e:?}"));
        assert_eq!(
            mochimo_crypto::mesh::hex::encode(&tx.message_digest()),
            message_hash,
            "{id}: message_digest is not the recorded TX_HASH_MESSAGE"
        );
        assert_eq!(
            mochimo_crypto::mesh::hex::encode(&tx.id_digest()),
            id_hash,
            "{id}: id_digest is not the recorded TX_HASH_ID (nonce as held)"
        );

        let mut sealed = tx.clone();
        sealed.seal();
        let w = sealed.to_wire();
        assert_eq!(w.len(), bytes.len(), "{id}: sealing changed the image length");
        assert_eq!(&w[..tx.tlr_off()], &bytes[..tx.tlr_off()], "{id}: sealing touched the signed prefix or validation data");
        let t = sealed.trailer.as_ref().unwrap_or_else(|| panic!("{id}: sealed image has no trailer"));
        assert_eq!(t.nonce, 0, "{id}: sealed nonce is not zero");
        assert_eq!(t.id, sealed.id_digest(), "{id}: sealed id is not the id digest of the sealed image");
        checked += 1;
    }
    let want = if cfg!(miri) { 1 } else { 5 };
    assert_eq!(
        checked, want,
        "expected {want} Ds1 hashed images to replay; walked {checked}. If the corpus grew, restate \
         this number; if it shrank, a key stopped being read."
    );
    println!("  C-free digests: {checked} Ds1 image(s), message_hash and id_hash reproduced, seal checked");
}

/// The constructor rejects destination counts the wire cannot encode,
/// returning an error rather than panicking.
#[test]
fn native_transaction_construction_holds_the_count_bound() {
    let d = Destination {
        tag: [0; 20],
        reference: [0; 16],
        amount: 1,
    };

    assert!(
        Transaction::new(vec![]).is_err(),
        "a zero-destination transaction is unrepresentable on the wire \
         (MDST_COUNT = options[2] + 1, types.h:176) and must be rejected"
    );
    assert!(
        Transaction::new(vec![d.clone(); 257]).is_err(),
        "257 destinations cannot be encoded in options[2] and must be rejected"
    );

    for n in [1usize, 2, 256] {
        let tx = Transaction::new(vec![d.clone(); n])
            .unwrap_or_else(|e| panic!("{n} destinations must construct: {e:?}"));
        assert_eq!(tx.dst_count(), n as u16);
        let wire = tx.to_wire();
        assert_eq!(
            wire.len(),
            tx.wire_len(),
            "to_wire's length disagrees with wire_len at n = {n}"
        );
        let back = Transaction::from_wire(&wire)
            .unwrap_or_else(|e| panic!("self round trip failed at n = {n}: {e:?}"));
        assert_eq!(back, tx, "self round trip changed the value at n = {n}");
    }
    println!("  C-free construction bounds: 0 and 257 rejected; 1, 2, 256 built");
}

/// The three validator bodies, laid out as the proof-of-stake node's
/// `tx__init` does: header, payload, WOTS+ block, trailer. Payloads are 20, 0
/// and 8 bytes, so images are 2,384, 2,364 and 2,372 bytes, and 40 fewer
/// without the trailer. The type byte is `options[0]`, `options[2]` is zero,
/// the payload is at offset 116, and the signed digest is SHA-256 over the
/// header and payload.
///
/// These numbers come from the node's `types.h` and `tx.c` (see
/// `consts::pos`). The independent check is group V in `tests/kat.rs`, which
/// reproduces the node's own images byte for byte.
#[test]
fn validator_bodies_lay_out_as_the_proof_of_stake_node_does() {
    let delegate = [0x5d; 20];
    let cases: [(Body, u8, usize, &[u8]); 3] = [
        (Body::SetDelegate { delegate }, 0x01, 2384, &delegate),
        (Body::ClearDelegate, 0x02, 2364, &[]),
        (Body::Claim { amount: 0x0102_0304_0506_0708 }, 0x06, 2372, &[8, 7, 6, 5, 4, 3, 2, 1]),
    ];
    for (body, dat_type, whole, payload) in cases {
        let mut tx = Transaction::with_body(body.clone()).unwrap_or_else(|e| panic!("{body:?}: {e}"));
        tx.src_addr = [0x11; 40];
        tx.chg_addr = [0x22; 40];
        tx.change_total = 7;
        tx.fee_total = 500;
        tx.wots.signature[0] = 0x33;
        tx.seal();
        assert_eq!(tx.dst_count(), 0, "{body:?} names no destinations");
        assert!(tx.dsts().is_empty());
        assert_eq!(tx.dsa_off(), 116 + payload.len(), "{body:?}: dsaoff");
        assert_eq!(tx.tlr_off(), 116 + payload.len() + 2208, "{body:?}: tlroff");
        assert_eq!(tx.tx_sz(), whole, "{body:?}: tx_sz");
        let wire = tx.to_wire();
        assert_eq!(wire.len(), whole);
        assert_eq!(&wire[..4], &[dat_type, 0, 0, 0], "{body:?}: the options bytes");
        assert_eq!(&wire[116..116 + payload.len()], payload, "{body:?}: the payload at offset 116");
        assert_eq!(
            tx.message_digest(),
            mochimo_crypto::backend::selected::sha256(&wire[..116 + payload.len()]),
            "{body:?}: TX_HASH_MESSAGE is not SHA-256 over the header and payload"
        );
        assert_eq!(
            tx.id_digest(),
            mochimo_crypto::backend::selected::sha256(&wire[..whole - 32]),
            "{body:?}: TX_HASH_ID is not SHA-256 up to the trailer's id"
        );
        let back = Transaction::from_wire(&wire).unwrap_or_else(|e| panic!("{body:?}: {e}"));
        assert_eq!(back, tx, "{body:?}: the round trip changed the value");
        let bare = Transaction::from_wire(&wire[..whole - 40]).unwrap_or_else(|e| panic!("{body:?}: {e}"));
        assert_eq!(bare.body(), &body);
        assert!(bare.trailer.is_none());

        // The accepted length range is the body's, not a transfer's.
        for bad in [whole - 41, whole + 1] {
            let mut image = wire.clone();
            image.resize(bad, 0);
            assert!(
                matches!(Transaction::from_wire(&image), Err(Error::Range { what: "transaction wire length", .. })),
                "{body:?}: a {bad}-byte image parsed"
            );
        }
        // A destination count on a type with no destination array.
        let mut counted = wire.clone();
        counted[2] = 1;
        assert!(
            matches!(Transaction::from_wire(&counted), Err(Error::Range { got: 1, .. })),
            "{body:?}: options[2] = 1 parsed"
        );
    }

    // Every type byte the codec does not build is refused as unknown before
    // any length is computed from it, including types the node builds only
    // in blocks or for its delegate signer.
    let mut probe = Transaction::with_body(Body::ClearDelegate).unwrap_or_else(|e| panic!("{e}")).to_wire();
    for t in (0u8..=255).filter(|t| ![0x00, 0x01, 0x02, 0x06, 0x0C, 0x0D, 0x0E].contains(t)) {
        probe[0] = t;
        assert_eq!(
            Transaction::from_wire(&probe).err(),
            Some(Error::UnknownTxType { dat_type: t }),
            "type {t:#04x} was not refused as unknown"
        );
    }
    println!("  validator bodies: set-delegate 2384, clear-delegate 2364, claim 2372 bytes; 249 unknown types refused");
}

/// The three v4.1 bodies match `v41.h`'s structs (`MSTAKE` 16, `MUNSTAKE`
/// 16, `MACCEPT` 36 bytes, integers little-endian), round-trip, and refuse a
/// non-zero reserved byte. Group S checks the bytes against `stake-tx.mjs`.
#[test]
fn staking_bodies_lay_out_as_v41_h_and_refuse_reserved_bytes() {
    use mochimo_crypto::staking::ConsentTerms;
    let terms = ConsentTerms {
        kind: 2,
        peer: [0x22; 20],
        action: 1,
        slot: 9,
        ip: [34, 1, 2, 3],
        port: 2195,
        flags: 1,
        network: 0xACA1,
    };
    let mut maccept = vec![2u8];
    maccept.extend_from_slice(&[0x22; 20]);
    maccept.extend_from_slice(&[1, 9, 0, 0, 0, 34, 1, 2, 3, 0x93, 0x08, 1, 0xA1, 0xAC, 0]);
    let mut mstake = 0x0102_0304_0506_0708u64.to_le_bytes().to_vec();
    mstake.extend_from_slice(&[5, 0xA1, 0xAC, 0, 0, 0, 0, 0]);
    let mut munstake = vec![0xBD, 0x1C];
    munstake.extend_from_slice(&[0; 14]);
    let cases: [(Body, u8, usize, Vec<u8>, usize); 3] = [
        (Body::Stake { amount: 0x0102_0304_0506_0708, tier: 5, network: 0xACA1 }, 0x0C, 2380, mstake, 11),
        (Body::Unstake { network: 7357 }, 0x0D, 2380, munstake, 2),
        (Body::Accept(terms), 0x0E, 2400, maccept, 35),
    ];
    for (body, dat_type, whole, payload, reserved_at) in cases {
        let mut tx = Transaction::with_body(body.clone()).unwrap_or_else(|e| panic!("{body:?}: {e}"));
        tx.src_addr = [0x11; 40];
        tx.chg_addr = [0x22; 40];
        tx.fee_total = 500;
        tx.seal();
        let wire = tx.to_wire();
        assert_eq!(wire.len(), whole, "{body:?}: tx_sz");
        assert_eq!(&wire[..4], &[dat_type, 0, 0, 0], "{body:?}: the options bytes");
        assert_eq!(&wire[116..116 + payload.len()], payload.as_slice(), "{body:?}: the payload at offset 116");
        let back = Transaction::from_wire(&wire).unwrap_or_else(|e| panic!("{body:?}: {e}"));
        assert_eq!(back, tx, "{body:?}: the round trip changed the value");
        let mut dirty = wire.clone();
        dirty[116 + reserved_at] = 1;
        assert!(
            matches!(Transaction::from_wire(&dirty), Err(Error::ReservedNotZero { .. })),
            "{body:?}: a non-zero reserved byte parsed"
        );
    }
    assert_eq!(ConsentTerms::from_image(&terms.image()), Ok(terms));
    println!("  staking bodies: stake 2380, unstake 2380, accept 2400 bytes; reserved bytes refused");
}
