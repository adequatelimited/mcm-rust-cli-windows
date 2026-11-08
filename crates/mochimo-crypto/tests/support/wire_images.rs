// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! The group D wire-image walk, used by `txwire.rs`'s round trip and by
//! `spend.rs` for its loaders.
//!
//! The images are every vector key naming a framed transaction:
//! `wire_file`, `hashed_wire_file`, `baseline_wire_file`,
//! `mutated_wire_file`, `validated_wire_file`, `wire_with_trailer_file`,
//! `wire_without_trailer_file`, `wire_one_byte_long_file`, and `D15`'s
//! per-case `case_wire_file`. The `message_hash_input_file` sidecars (signed
//! prefixes) and `D_identity_pk.bin` (a public key) are excluded. That gives
//! 71 images: 67 the reference accepts and 4 it rejects (`D14`'s
//! one-byte-long form and `D15`'s three unknown-type cases).
//!
//! The walk is by `(vector, key)` and never deduplicates by content: some
//! vectors share identical images on purpose.
//!
//! A pure round trip `to_wire(from_wire(x)) == x` cannot detect a parser and
//! serializer that share the same wrong offset, so the parse is also checked
//! against the field values each vector records (for example `D17`'s
//! distinct address halves and `D18`'s asymmetric header values).

use mochimo_crypto::tx::wire::Transaction;

// Unused under Miri: everything Miri needs is embedded (see `embedded`).
#[cfg_attr(miri, allow(dead_code))]
pub fn repo_root() -> std::path::PathBuf {
    let mut p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf();
    p.pop();
    p.pop();
    p
}

pub fn fixture_json(name: &str) -> serde_json::Value {
    // Miri runs with isolation and cannot open files, so the JSON is
    // embedded at compile time.
    #[cfg(miri)]
    {
        assert_eq!(name, "group_d_tx.json", "only group D is embedded for Miri");
        return serde_json::from_str(include_str!("../../../../fixtures/group_d_tx.json"))
            .expect("embedded group_d_tx.json parses");
    }
    #[cfg(not(miri))]
    {
        let p = repo_root().join("fixtures").join(name);
        let text = std::fs::read_to_string(&p)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()));
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("cannot parse {}: {e}", p.display()))
    }
}

#[cfg_attr(miri, allow(dead_code))]
pub fn fixture_bytes(name: &str) -> Vec<u8> {
    let p = repo_root().join("fixtures").join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
}

/// The images embedded for Miri, which cannot read files.
///
/// The smallest and largest shapes (`D1v`, `D4`), both framing forms and the
/// oversize reject (`D14`), the field-layout images (`D16`, `D17`, `D18`), a
/// wrong-totals image (`D19-totals`), and a type-byte reject (`D15_case2`).
/// Other names return `None` and the walk skips them; the non-Miri walk
/// covers all 71.
#[cfg(miri)]
fn embedded(name: &str) -> Option<&'static [u8]> {
    Some(match name {
        "D1v_tx.bin" => include_bytes!("../../../../fixtures/D1v_tx.bin"),
        "D4_tx.bin" => include_bytes!("../../../../fixtures/D4_tx.bin"),
        "D14_full.bin" => include_bytes!("../../../../fixtures/D14_full.bin"),
        "D14_notlr.bin" => include_bytes!("../../../../fixtures/D14_notlr.bin"),
        "D14_long.bin" => include_bytes!("../../../../fixtures/D14_long.bin"),
        "D16_tx.bin" => include_bytes!("../../../../fixtures/D16_tx.bin"),
        "D17_tx.bin" => include_bytes!("../../../../fixtures/D17_tx.bin"),
        "D18_tx.bin" => include_bytes!("../../../../fixtures/D18_tx.bin"),
        "D19-totals_tx.bin" => include_bytes!("../../../../fixtures/D19-totals_tx.bin"),
        "D15_case2.bin" => include_bytes!("../../../../fixtures/D15_case2.bin"),
        _ => return None,
    })
}

/// Loads an image from disk, or from the embedded subset under Miri.
fn walk_bytes(name: &str) -> Option<Vec<u8>> {
    #[cfg(miri)]
    {
        embedded(name).map(<[u8]>::to_vec)
    }
    #[cfg(not(miri))]
    {
        Some(fixture_bytes(name))
    }
}

pub fn unhex(s: &str) -> Vec<u8> {
    assert!(
        s.len().is_multiple_of(2) && s.bytes().all(|b| b.is_ascii_hexdigit()),
        "not a hex string: {s:?}"
    );
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("checked hex"))
        .collect()
}

/// One named image: which vector, which key, which sidecar, and whether the
/// reference accepted the framing.
pub struct WireImage {
    pub vector_id: String,
    pub key: &'static str,
    pub file: String,
    pub bytes: Vec<u8>,
    pub expect_accept: bool,
}

/// The top-level image keys. `case_wire` is handled separately because it
/// lives inside a `cases` array with a per-case verdict.
const IMAGE_KEYS: [&str; 8] = [
    "wire_file",
    "hashed_wire_file",
    "baseline_wire_file",
    "mutated_wire_file",
    "validated_wire_file",
    "wire_with_trailer_file",
    "wire_without_trailer_file",
    "wire_one_byte_long_file",
];

/// Every named group D wire image, with its recorded `<key>_len` twin already
/// asserted against the file on disk.
pub fn group_d_wire_images(file: &serde_json::Value) -> Vec<WireImage> {
    let mut images = Vec::new();
    for v in file["vectors"].as_array().expect("vectors") {
        let id = v["id"].as_str().unwrap_or("?").to_string();
        for key in IMAGE_KEYS {
            let Some(name) = v.get(key).and_then(|x| x.as_str()) else {
                continue;
            };
            let Some(bytes) = walk_bytes(name) else {
                continue; // outside the embedded Miri subset; see `embedded`
            };
            let len_key = key.replace("_file", "_len");
            assert_eq!(
                bytes.len() as u64,
                v[&len_key].as_u64().unwrap_or_else(|| panic!(
                    "vector {id}: {key} present with no {len_key} twin"
                )),
                "vector {id}: {name} length disagrees with {len_key}"
            );
            // The one top-level image the reference rejects: D14's
            // one-byte-long form, recorded as tx_read VERROR.
            let expect_accept = if key == "wire_one_byte_long_file" {
                assert_eq!(
                    v["tx_read_one_byte_long_rc_name"].as_str(),
                    Some("VERROR"),
                    "vector {id}: expected the one-byte-long probe to record a \
                     tx_read rejection; the premise of treating it as a \
                     rejection case moved"
                );
                false
            } else {
                true
            };
            images.push(WireImage {
                vector_id: id.clone(),
                key,
                file: name.to_string(),
                bytes,
                expect_accept,
            });
        }
        // D15: per-case images, each with its own recorded tx_read verdict.
        if let Some(cases) = v.get("cases").and_then(|x| x.as_array()) {
            for c in cases {
                let Some(name) = c.get("case_wire_file").and_then(|x| x.as_str()) else {
                    continue;
                };
                let Some(bytes) = walk_bytes(name) else {
                    continue; // outside the embedded Miri subset
                };
                assert_eq!(
                    bytes.len() as u64,
                    c["case_wire_len"].as_u64().expect("case_wire_len"),
                    "vector {id}: {name} length disagrees with case_wire_len"
                );
                let rc = c["tx_read_rc_name"].as_str().expect("case tx_read_rc_name");
                images.push(WireImage {
                    vector_id: id.clone(),
                    key: "case_wire_file",
                    file: name.to_string(),
                    bytes,
                    expect_accept: rc == "VEOK",
                });
            }
        }
    }
    images
}

/// Asserts byte identity, naming the first differing offset on failure.
pub fn assert_bytes_identical(id: &str, key: &str, got: &[u8], want: &[u8]) {
    if got == want {
        return;
    }
    if got.len() != want.len() {
        panic!(
            "vector {id} ({key}): serialized {} bytes, the reference emitted {}",
            got.len(),
            want.len()
        );
    }
    let off = got
        .iter()
        .zip(want.iter())
        .position(|(a, b)| a != b)
        .unwrap_or(0);
    panic!(
        "vector {id} ({key}): serialized image differs from the reference's at \
         byte {off} (ours {:#04x}, reference {:#04x})",
        got[off], want[off]
    );
}

/// What the walk measured. Each caller asserts its own expected counts.
pub struct WalkTotals {
    pub accepted: usize,
    pub rejected: usize,
    pub field_assertions: usize,
}

/// The native round trip over every named image, with every recorded field the
/// vector carries asserted against the parse.
///
/// For each accepted image: `Transaction::from_wire` must succeed, the
/// recorded fields must match the parsed value, and `to_wire` must reproduce
/// the sidecar byte for byte. For each rejected image: `from_wire` must
/// reject. `D14`'s two recorded length probes without sidecars (one byte
/// below the acceptance window, one byte short of a header) are reproduced
/// by slicing its full image.
pub fn native_round_trip_walk(file: &serde_json::Value) -> WalkTotals {
    let images = group_d_wire_images(file);
    let mut totals = WalkTotals {
        accepted: 0,
        rejected: 0,
        field_assertions: 0,
    };

    for img in &images {
        let id = img.vector_id.as_str();
        let v = vector(file, id);
        if !img.expect_accept {
            assert!(
                Transaction::from_wire(&img.bytes).is_err(),
                "vector {id} ({} = {}): the reference rejected this image \
                 (recorded tx_read VERROR) and the native parser accepted it",
                img.key,
                img.file
            );
            totals.rejected += 1;
            continue;
        }
        let tx = Transaction::from_wire(&img.bytes).unwrap_or_else(|e| {
            panic!(
                "vector {id} ({} = {}): the reference accepted this image and \
                 the native parser rejected it: {e:?}",
                img.key, img.file
            )
        });

        totals.field_assertions += assert_recorded_fields(v, img, &tx);

        assert_bytes_identical(id, img.key, &tx.to_wire(), &img.bytes);
        totals.accepted += 1;
    }

    totals.field_assertions += d14_length_probes(file);
    totals
}

fn vector<'a>(file: &'a serde_json::Value, id: &str) -> &'a serde_json::Value {
    file["vectors"]
        .as_array()
        .expect("vectors")
        .iter()
        .find(|v| v["id"].as_str() == Some(id))
        .unwrap_or_else(|| panic!("vector {id} disappeared mid-walk"))
}

/// Asserts every recorded field this image's vector carries about the bytes
/// the image holds, returning how many assertions ran.
///
/// Each key describes a specific image: the layout fields and the
/// `*_bytes`/`*_value` pairs describe `wire_file`; `src_addr`, `adrs` and
/// `tag_half_equals_hash_half` describe `validated_wire_file` (the bytes the
/// validator saw); `D14`'s `tx_sz_*` fields describe its two forms.
fn assert_recorded_fields(v: &serde_json::Value, img: &WireImage, tx: &Transaction) -> usize {
    let id = img.vector_id.as_str();
    let mut n = 0usize;

    match img.key {
        "wire_file" => {
            // Layout fields, required on every wire_file vector.
            n += require_u64_field(v, id, "ndst", u64::from(tx.dst_count()));
            n += require_u64_field(v, id, "mdst_count_from_reference", u64::from(tx.dst_count()));
            n += require_u64_field(v, id, "options_byte_2", u64::from(tx.dst_count()) - 1);
            n += require_u64_field(v, id, "tx_sz", tx.tx_sz() as u64);
            n += require_u64_field(v, id, "dsaoff", tx.dsa_off() as u64);
            n += require_u64_field(v, id, "tlroff", tx.tlr_off() as u64);
            n += require_u64_field(v, id, "signed_len", tx.dsa_off() as u64);

            // Value/byte pairs, where a vector records them.
            // `kat.rs::group_d_core_census` checks which vectors carry them.
            n += assert_u64_field(v, id, "send_total_value", tx.send_total);
            n += assert_u64_field(v, id, "change_total_value", tx.change_total);
            n += assert_u64_field(v, id, "fee_total_value", tx.fee_total);
            n += assert_u64_field(v, id, "blk_to_live_value", tx.blk_to_live);
            n += assert_bytes_field(v, id, "send_total_bytes", &tx.send_total.to_le_bytes());
            n += assert_bytes_field(v, id, "change_total_bytes", &tx.change_total.to_le_bytes());
            n += assert_bytes_field(v, id, "fee_total_bytes", &tx.fee_total.to_le_bytes());
            n += assert_bytes_field(v, id, "blk_to_live_bytes", &tx.blk_to_live.to_le_bytes());
            n += assert_bytes_field(v, id, "chg_addr_bytes", &tx.chg_addr);
            for (i, d) in tx.dsts().iter().enumerate() {
                n += assert_u64_field(v, id, &format!("amount{i}_value"), d.amount);
                n += assert_bytes_field(v, id, &format!("amount{i}_bytes"), &d.amount.to_le_bytes());
                n += assert_bytes_field(v, id, &format!("ref{i}_bytes"), &d.reference);
            }

            // D17's booleans, recomputed from the parsed address halves.
            n += assert_bool_field(
                v,
                id,
                "src_chg_tag_equal",
                tag_half(&tx.src_addr) == tag_half(&tx.chg_addr),
            );
            n += assert_bool_field(
                v,
                id,
                "src_chg_hash_equal",
                hash_half(&tx.src_addr) == hash_half(&tx.chg_addr),
            );
            n += assert_bool_field(
                v,
                id,
                "chg_tag_half_equals_hash_half",
                tag_half(&tx.chg_addr) == hash_half(&tx.chg_addr),
            );
        }
        "validated_wire_file" => {
            // The signature negatives record the mutated bytes the
            // validator saw, not the baseline.
            n += assert_bytes_field(v, id, "src_addr", &tx.src_addr);
            n += assert_bytes_field(v, id, "adrs", &tx.wots.adrs);
            n += assert_bool_field(
                v,
                id,
                "tag_half_equals_hash_half",
                tag_half(&tx.src_addr) == hash_half(&tx.src_addr),
            );
        }
        "hashed_wire_file" => {
            n += require_u64_field(v, id, "ndst", u64::from(tx.dst_count()));
        }
        "wire_with_trailer_file" => {
            n += require_u64_field(v, id, "tx_sz_with_trailer", tx.tx_sz() as u64);
            assert!(
                tx.trailer.is_some(),
                "vector {id}: the with-trailer form parsed with no trailer"
            );
            n += 1;
        }
        "wire_without_trailer_file" => {
            n += require_u64_field(v, id, "tx_sz_without_trailer", tx.wire_len() as u64);
            assert!(
                tx.trailer.is_none(),
                "vector {id}: the without-trailer form parsed with a trailer"
            );
            n += 1;
        }
        _ => {}
    }
    n
}

/// The tag half of an address: `ADDR_TAG_OFF = 0` for `ADDR_TAG_LEN = 20`
/// bytes.
fn tag_half(addr: &[u8; 40]) -> &[u8] {
    &addr[..20]
}

/// The hash half of an address: `ADDR_HASH_OFF = 20` for
/// `ADDR_HASH_LEN = 20` bytes.
fn hash_half(addr: &[u8; 40]) -> &[u8] {
    &addr[20..]
}

fn require_u64_field(v: &serde_json::Value, id: &str, key: &str, got: u64) -> usize {
    let want = v
        .get(key)
        .and_then(|x| x.as_u64())
        .unwrap_or_else(|| panic!("vector {id}: required field {key} is absent — the corpus changed shape"));
    assert_eq!(got, want, "vector {id}: {key} disagrees with the parse");
    1
}

fn assert_u64_field(v: &serde_json::Value, id: &str, key: &str, got: u64) -> usize {
    match v.get(key).and_then(|x| x.as_u64()) {
        Some(want) => {
            assert_eq!(got, want, "vector {id}: {key} disagrees with the parse");
            1
        }
        None => 0,
    }
}

fn assert_bytes_field(v: &serde_json::Value, id: &str, key: &str, got: &[u8]) -> usize {
    match v.get(key).and_then(|x| x.as_str()) {
        Some(hex) => {
            assert_eq!(
                unhex(hex),
                got.to_vec(),
                "vector {id}: {key} disagrees with the parse"
            );
            1
        }
        None => 0,
    }
}

fn assert_bool_field(v: &serde_json::Value, id: &str, key: &str, got: bool) -> usize {
    match v.get(key).and_then(|x| x.as_bool()) {
        Some(want) => {
            assert_eq!(got, want, "vector {id}: {key} disagrees with the parse");
            1
        }
        None => 0,
    }
}

/// `D14`'s two rejected length probes are recorded verdicts without
/// sidecars, so they are reproduced by slicing the full image: one byte
/// below the acceptance window, and one byte short of a header.
fn d14_length_probes(file: &serde_json::Value) -> usize {
    let v = vector(file, "D14");
    let full = walk_bytes(
        v["wire_with_trailer_file"]
            .as_str()
            .expect("D14 wire_with_trailer_file"),
    )
    .expect("D14_full is in the embedded Miri subset");
    let notlr_len = v["tx_sz_without_trailer"].as_u64().expect("tx_sz_without_trailer") as usize;
    let hdr = mochimo_crypto::consts::wire::SIZEOF_TXHDR;

    for (probe, len) in [
        ("tx_read_one_byte_short_rc_name", notlr_len - 1),
        ("tx_read_shorter_than_header_rc_name", hdr - 1),
    ] {
        assert_eq!(
            v[probe].as_str(),
            Some("VERROR"),
            "D14: expected {probe} to record a rejection; the premise of \
             reproducing it moved"
        );
        assert!(
            Transaction::from_wire(&full[..len]).is_err(),
            "D14: the reference rejected a {len}-byte slice ({probe}) and the \
             native parser accepted it"
        );
    }
    2
}
