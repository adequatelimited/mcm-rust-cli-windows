// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! Fixture loading and failure reporting for the KAT suite.
//!
//! Nothing in here computes a protocol value. It reads JSON, reads `.bin`
//! sidecars, compares bytes, and formats a failure so that it names the
//! reference `file:line` the vector came from.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde_json::Value;

// --- corpus location ----------------------------------------------------

/// The fixture directory. `MOCHIMO_FIXTURES` overrides it, so the suite can
/// run against a scratch copy without touching the committed corpus.
pub fn fixtures_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("MOCHIMO_FIXTURES") {
        return PathBuf::from(dir);
    }
    repo_root().join("fixtures")
}

pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate lives at <repo>/crates/mochimo-crypto")
        .to_path_buf()
}

// --- manifest -----------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub id: String,
    pub file: String,
    pub name: String,
    pub status: String,
    pub vectors: usize,
    pub sources: usize,
    pub reason: Option<String>,
    /// Known missing fixture data. Not a skip list: the group's vectors all
    /// still run.
    pub pending: Vec<String>,
    /// Vector ids inside a `deferred` group that are nevertheless replayed.
    /// Listed by id rather than counted, so a typo is a hard failure.
    pub activated: Vec<String>,
    /// Vectors in this group that nothing replays.
    ///
    /// Read from the manifest rather than computed as
    /// `vectors - activated.len()`: a derived count would move with the list,
    /// so dropping an id from `activated` would go unnoticed.
    pub still_deferred: usize,
}

impl Group {
    pub fn is_active(&self) -> bool {
        self.status == "active"
    }
}

pub fn load_manifest() -> Vec<Group> {
    let path = fixtures_dir().join("manifest.toml");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let doc: toml::Value = text
        .parse()
        .unwrap_or_else(|e| panic!("{} is not valid TOML: {e}", path.display()));

    let groups = doc
        .get("group")
        .and_then(|g| g.as_array())
        .unwrap_or_else(|| panic!("{} has no [[group]] entries", path.display()));

    let out: Vec<Group> = groups
        .iter()
        .map(|g| {
            let s = |k: &str| -> String {
                g.get(k)
                    .and_then(|v| v.as_str())
                    .unwrap_or_else(|| panic!("manifest group missing string field `{k}`"))
                    .to_string()
            };
            let n = |k: &str| -> usize {
                g.get(k)
                    .and_then(|v| v.as_integer())
                    .unwrap_or_else(|| panic!("manifest group missing integer field `{k}`"))
                    as usize
            };
            // An optional array-of-strings field. Absent is empty; present but
            // malformed is a hard failure.
            let strings = |k: &str| -> Vec<String> {
                g.get(k)
                    .map(|v| {
                        v.as_array()
                            .unwrap_or_else(|| panic!("group `{}`: {k} must be an array", s("id")))
                            .iter()
                            .map(|e| {
                                e.as_str()
                                    .unwrap_or_else(|| {
                                        panic!("group `{}`: {k} entries must be strings", s("id"))
                                    })
                                    .to_string()
                            })
                            .collect()
                    })
                    .unwrap_or_default()
            };

            let status = s("status");
            assert!(
                status == "active" || status == "deferred",
                "manifest group `{}` has status `{status}`; expected \"active\" or \"deferred\"",
                s("id")
            );
            if status == "deferred" {
                assert!(
                    g.get("reason").and_then(|v| v.as_str()).is_some(),
                    "deferred group `{}` must carry a `reason`",
                    s("id")
                );
            }

            let activated = strings("activated");
            assert!(
                status == "deferred" || activated.is_empty(),
                "group `{}` is `{status}` and carries `activated`. Only a deferred \
                 group may: in an active group every vector runs already, so the \
                 list would be a second, weaker statement of the same thing and \
                 the two could drift apart.",
                s("id")
            );
            assert!(
                activated.len() <= n("vectors"),
                "group `{}`: {} activated ids but only {} vectors",
                s("id"),
                activated.len(),
                n("vectors")
            );
            // `still_deferred` is checked whenever it is present, not only
            // when the group is split, so a stale value cannot go unnoticed.
            let stated = g
                .get("still_deferred")
                .and_then(|v| v.as_integer())
                .map(|n| n as usize);
            assert!(
                status == "deferred" || stated.is_none(),
                "group `{}` is active and carries `still_deferred`. An active \
                 group defers nothing, so the field could only ever be 0 and \
                 would be a second, weaker statement of `status`.",
                s("id")
            );
            let still_deferred = match stated {
                Some(stated) => {
                    assert_eq!(
                        activated.len() + stated,
                        n("vectors"),
                        "group `{}`: {} activated + {stated} still deferred != {} vectors",
                        s("id"),
                        activated.len(),
                        n("vectors")
                    );
                    stated
                }
                None if !activated.is_empty() => panic!(
                    "group `{}` carries `activated` but no `still_deferred`. \
                     The remainder must be written down, not computed from \
                     the list: a derived count moves with the list and an id \
                     deleted from it would defer a vector with every total \
                     still agreeing.",
                    s("id")
                ),
                // No split and nothing stated: everything the group has is
                // deferred, or it is active and nothing is.
                None => {
                    if status == "active" {
                        0
                    } else {
                        n("vectors")
                    }
                }
            };

            {
                let mut seen = std::collections::BTreeSet::new();
                for id in &activated {
                    assert!(
                        seen.insert(id.clone()),
                        "group `{}`: `{id}` appears twice in `activated`. A duplicate \
                         inflates the activated count and silently hides a vector in \
                         the deferred remainder.",
                        s("id")
                    );
                }
            }

            Group {
                id: s("id"),
                file: s("file"),
                name: s("name"),
                status,
                vectors: n("vectors"),
                sources: n("sources"),
                reason: g
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                pending: strings("pending"),
                activated,
                still_deferred,
            }
        })
        .collect();

    assert!(!out.is_empty(), "{} lists no groups", path.display());
    out
}

/// Every `*.json` actually present in the fixture directory.
pub fn json_files_on_disk() -> Vec<String> {
    let dir = fixtures_dir();
    let entries = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read fixture directory {}: {e}", dir.display()));
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".json"))
        .collect();
    names.sort();
    names
}

// --- fixture files ------------------------------------------------------

pub struct Fixture {
    pub file: String,
    pub root: Value,
}

impl Fixture {
    pub fn load(file: &str) -> Fixture {
        let path = fixtures_dir().join(file);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read fixture {}: {e}", path.display()));
        assert!(
            !text.trim().is_empty(),
            "fixture {} is empty; a KAT suite that iterates nothing is worse than no suite",
            path.display()
        );
        let root: Value = serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("{} is not valid JSON: {e}", path.display()));
        Fixture {
            file: file.to_string(),
            root,
        }
    }

    pub fn vectors(&self) -> Vec<&Value> {
        let vs = self
            .root
            .get("vectors")
            .and_then(|v| v.as_array())
            .unwrap_or_else(|| panic!("{} has no `vectors` array", self.file));
        assert!(
            !vs.is_empty(),
            "{} has an empty `vectors` array; a KAT run must never pass by iterating nothing",
            self.file
        );
        vs.iter().collect()
    }

    /// Every vector's `id`, in file order.
    pub fn vector_ids(&self) -> Vec<String> {
        self.vectors()
            .iter()
            .map(|v| field_str(v, "id", &self.file).to_string())
            .collect()
    }

    /// The vector with this `id`. A miss is a hard failure, so a typo in
    /// `activated` cannot silently replay nothing.
    pub fn vector_by_id(&self, id: &str) -> &Value {
        self.vectors()
            .into_iter()
            .find(|v| field_str(v, "id", &self.file) == id)
            .unwrap_or_else(|| {
                panic!(
                    "{}: no vector with id `{id}`.\n  \
                     manifest.toml lists it under this group's `activated`, so either \
                     the id is a typo or the vector was renamed upstream. Either way \
                     nothing would have replayed it.",
                    self.file
                )
            })
    }

    pub fn sources(&self) -> Vec<String> {
        let mut set: BTreeMap<String, ()> = BTreeMap::new();
        for v in self.vectors() {
            set.insert(source_of(v, &self.root, &self.file).to_string(), ());
        }
        set.into_keys().collect()
    }
}

/// A vector's `source`: its own, or the file's top-level `source` when the
/// file states one for every vector. A vector with neither is a hard failure.
fn source_of<'a>(v: &'a Value, root: &'a Value, file: &str) -> &'a str {
    match v.get("source").and_then(|x| x.as_str()) {
        Some(s) => s,
        None => match root.get("source").and_then(|x| x.as_str()) {
            Some(s) => s,
            None => field_str(v, "source", file),
        },
    }
}

fn field_str<'a>(v: &'a Value, key: &str, file: &str) -> &'a str {
    v.get(key)
        .and_then(|x| x.as_str())
        .unwrap_or_else(|| panic!("{file}: a vector is missing the required `{key}` field"))
}

// --- hex ----------------------------------------------------------------

pub fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err(format!("odd-length hex string ({} chars)", s.len()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| format!("not hex: {:?}", &s[i..i + 2]))
        })
        .collect()
}

pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Renders a possibly-huge blob around the first byte that differs, so a
/// 2144-byte mismatch stays readable.
fn render(bytes: &[u8], focus: Option<usize>) -> String {
    const WINDOW: usize = 16;
    if bytes.len() <= 48 {
        return to_hex(bytes);
    }
    match focus {
        None => format!("{}… ({} bytes)", to_hex(&bytes[..48]), bytes.len()),
        Some(at) => {
            let start = at.saturating_sub(WINDOW);
            let end = (at + WINDOW).min(bytes.len());
            format!(
                "{}[{}]{} (bytes {}..{} of {})",
                if start > 0 { "…" } else { "" },
                to_hex(&bytes[start..end]),
                if end < bytes.len() { "…" } else { "" },
                start,
                end,
                bytes.len()
            )
        }
    }
}

// --- the per-vector checker --------------------------------------------

/// How much of the reference a vector's replay actually exercised.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Disposition {
    /// Every input came from a machine-readable fixture field.
    Replayed,
    /// At least one input was reconstructed by a rule in the harness rather
    /// than read from a field, because the fixture records it only in prose.
    ///
    /// No handler currently uses this (hence `allow(dead_code)`); it exists
    /// so a future handler can declare such an input, and
    /// `derived_inputs_are_exactly_as_expected` asserts the set is empty.
    #[allow(dead_code)]
    DerivedInput,
    /// The reference was not called. Either the fixture itself records that
    /// (the base58 fault class), or the input does not exist on disk.
    NotCalled,
}

pub struct Ctx<'a> {
    pub file: &'a str,
    pub id: String,
    pub source: String,
    pub v: &'a Value,
    /// The whole fixture file, for the file-level `constants` block that some
    /// vectors reference by name instead of repeating.
    pub root: &'a Value,
    pub disposition: Disposition,
    failures: Vec<String>,
    /// Every key this vector's handler asked the fixture for. A `RefCell`
    /// because the value accessors take `&self`.
    read: RefCell<BTreeSet<String>>,
    /// Every nested key the handler descended into with [`Ctx::cases`].
    ///
    /// Separate from `read`: reading a nested key must not mark its subtree
    /// covered. Only a descent over every element, each with its own child
    /// `Ctx`, adds a key here.
    descended: BTreeSet<String>,
    /// Fields read by child `Ctx`es, counted for the suite-level vacuity
    /// floor. Kept out of `read` so a sub-key cannot mark a same-named parent
    /// key covered.
    nested_fields_read: usize,
}

/// Keys that locate a vector rather than pin a value: `id` and `source`
/// locate it, `note` and `falsifies` are prose, and `i` is a
/// `crc16_base58_corpus` entry's positional identifier.
const METADATA_KEYS: [&str; 5] = ["id", "note", "falsifies", "source", "i"];

/// Fields that are English rather than data, and so can be covered but never
/// asserted. `no_input_is_reconstructed_from_prose` forbids reading any of
/// them as an input.
///
/// - `crosscheck_source`: a `file:line` locator for the second
///   implementation.
/// - `decode_not_called_reason`: why the reference was not invoked; its
///   machine-readable half, `decode_not_called`, is asserted.
/// - `correct_out_expected`: a requirement the C cannot be asked about,
///   because calling it faults.
/// - `reference_behaviour_with_out`: the crash the reference exhibits, not
///   reproducible without crashing the test process.
/// - `rule_not_evaluated`: names the validator these vectors do not reach
///   (`tx_val`, which needs an open ledger).
///   `kat.rs::tx_val_is_absent_from_the_corpus` asserts that no vector claims
///   `tx_val` as its source.
/// - `literal_absent_reason`: why a crosscheck vector carries no literal; its
///   machine-readable half, `literal_absent`, is asserted.
/// - `crc16_derivation`: how the CRC16 was recovered from `addrTagToBase58`'s
///   output; the value, `crc16_typescript_executed`, is asserted.
/// - `reference_cannot_compute_reason`: why group RX has no reference side;
///   its machine-readable half, `reference_can_compute`, is asserted.
///
/// `ref` and `case` are not listed: `ref` is also a protocol field name, and
/// the `cases` handlers in `kat.rs` read both labels and assert they are
/// distinct within a vector.
const PROSE_KEYS: [&str; 8] = [
    "crosscheck_source",
    "decode_not_called_reason",
    "correct_out_expected",
    "reference_behaviour_with_out",
    "rule_not_evaluated",
    "literal_absent_reason",
    "crc16_derivation",
    "reference_cannot_compute_reason",
];

impl<'a> Ctx<'a> {
    pub fn new(file: &'a str, root: &'a Value, v: &'a Value) -> Ctx<'a> {
        Ctx {
            file,
            id: field_str(v, "id", file).to_string(),
            source: source_of(v, root, file).to_string(),
            v,
            root,
            disposition: Disposition::Replayed,
            failures: Vec::new(),
            read: RefCell::new(BTreeSet::new()),
            descended: BTreeSet::new(),
            nested_fields_read: 0,
        }
    }

    /// For entries that carry an index rather than an `id` and take their
    /// `source` from the enclosing block.
    pub fn labelled(file: &'a str, root: &'a Value, v: &'a Value, id: String, source: String) -> Ctx<'a> {
        Ctx {
            file,
            id,
            source,
            v,
            root,
            disposition: Disposition::Replayed,
            failures: Vec::new(),
            read: RefCell::new(BTreeSet::new()),
            descended: BTreeSet::new(),
            nested_fields_read: 0,
        }
    }

    pub fn mark(&mut self, d: Disposition) {
        self.disposition = d;
    }

    /// A named integer from the fixture's file-level `constants` block.
    pub fn constant(&self, path: &[&str]) -> u64 {
        let mut node = self
            .root
            .get("constants")
            .unwrap_or_else(|| panic!("{}: no file-level `constants` block", self.file));
        for key in path {
            node = node
                .get(key)
                .unwrap_or_else(|| panic!("{}: constants has no `{key}`", self.file));
        }
        node.as_u64()
            .unwrap_or_else(|| panic!("{}: constant {path:?} is not an integer", self.file))
    }

    pub fn into_failures(mut self) -> Vec<String> {
        self.check_coverage();
        self.failures
    }

    /// How many distinct fields this vector's handler asked for. Feeds the
    /// suite-level vacuity floor.
    pub fn fields_read(&self) -> usize {
        self.read.borrow().len() + self.nested_fields_read
    }

    /// Descend into an array of case objects, one child [`Ctx`] each.
    ///
    /// Each case gets the same coverage walk as a vector. The child's
    /// failures are folded into this one and reported against `<id>[n]`.
    ///
    /// # Panics
    ///
    /// If the key is missing or not an array, if the array is empty (which
    /// would mark the key covered while covering nothing), or if an element
    /// is not an object (which coverage would skip).
    pub fn cases<F>(&mut self, key: &str, mut each: F)
    where
        F: FnMut(&mut Ctx<'a>),
    {
        let node = self.v.get(key).unwrap_or_else(|| {
            panic!(
                "{}: vector {} has no `{key}` field.\n  source: {}\n  \
                 Either the fixture changed shape or the replay is descending \
                 into the wrong key.",
                self.file, self.id, self.source
            )
        });
        let arr = node.as_array().unwrap_or_else(|| {
            panic!(
                "{}: vector {} -- `{key}` is not an array, so there is nothing \
                 to descend into.",
                self.file, self.id
            )
        });
        assert!(
            !arr.is_empty(),
            "{}: vector {} -- `{key}` is an empty array. Descending over it \
             would mark the key covered while covering nothing, which is the \
             exact state this recursion exists to make impossible.",
            self.file,
            self.id
        );

        // Recorded before the loop so a panic inside a case handler still
        // leaves the descent visible.
        self.descended.insert(key.to_string());

        for (n, case) in arr.iter().enumerate() {
            assert!(
                case.is_object(),
                "{}: vector {} -- `{key}[{n}]` is not an object. Coverage \
                 returns early on a non-object, so this element would be \
                 checked by nothing.",
                self.file,
                self.id
            );
            let mut child = Ctx::labelled(
                self.file,
                self.root,
                case,
                format!("{}[{n}]", self.id),
                self.source.clone(),
            );
            each(&mut child);
            self.nested_fields_read += child.fields_read();
            self.failures.extend(child.into_failures());
        }
    }

    /// Read a field without asserting it, for reference verdicts this crate
    /// has nothing to compare with. The caller marks the vector `NotCalled`.
    pub fn touch(&self, key: &str) -> &'a Value {
        match self.get(key) {
            Some(v) => v,
            None => self.missing(key),
        }
    }

    /// The only place a field is fetched from a vector, so every fetch is
    /// recorded as a read.
    fn get(&self, key: &str) -> Option<&'a Value> {
        self.read.borrow_mut().insert(key.to_string());
        self.v.get(key)
    }

    /// Checks that every field a vector carries is either read by the handler
    /// or listed in `METADATA_KEYS` / `PROSE_KEYS`. The keys come from the
    /// vector itself, so a field added to a fixture needs an assertion as soon
    /// as it appears.
    ///
    /// A nested field (an object, or an array of objects) is covered only if
    /// the handler descended into it with [`Ctx::cases`]; merely reading it
    /// does not count.
    fn check_coverage(&mut self) {
        let Some(obj) = self.v.as_object() else {
            return;
        };
        let read = self.read.borrow().clone();

        let mut unread: Vec<&str> = Vec::new();
        let mut nested: Vec<&str> = Vec::new();
        for (k, val) in obj {
            if METADATA_KEYS.contains(&k.as_str()) || PROSE_KEYS.contains(&k.as_str()) {
                continue;
            }
            let is_nested = val.is_object()
                || val.as_array().is_some_and(|a| a.iter().any(Value::is_object));
            if is_nested {
                // Checked against `descended`, not `read`, so reading the
                // parent node does not cover its contents.
                if !self.descended.contains(k.as_str()) {
                    nested.push(k);
                }
            } else if !read.contains(k.as_str()) {
                unread.push(k);
            }
        }

        if !unread.is_empty() {
            self.failures.push(format!(
                "FIELD NOT COVERED\n  \
                 fixture : {}\n  \
                 vector  : {}\n  \
                 source  : {}\n  \
                 fields  : {}\n  \
                 The vector records these and the handler never read them, so \
                 whatever they pin is not being checked. Either assert them or \
                 argue them onto METADATA_KEYS -- a field that is present and \
                 unread is a green vector with an unexecuted assertion.",
                self.file,
                self.id,
                self.source,
                unread.join(", ")
            ));
        }

        if !nested.is_empty() {
            self.failures.push(format!(
                "NESTED FIELD NOT COVERABLE\n  \
                 fixture : {}\n  \
                 vector  : {}\n  \
                 source  : {}\n  \
                 fields  : {}\n  \
                 Coverage is a flat walk, so reading the parent key once would \
                 mark every sub-key covered while covering none. Descend with \
                 Ctx::cases, which gives every element its own Ctx and its own \
                 coverage walk -- reading the key is not a substitute and does \
                 not clear this.",
                self.file,
                self.id,
                self.source,
                nested.join(", ")
            ));
        }
    }

    // --- required-field accessors: a missing field stops the run.

    fn missing(&self, key: &str) -> ! {
        panic!(
            "{}: vector {} has no `{}` field.\n  source: {}\n  \
             Either the fixture changed shape or the replay is reading the wrong key.",
            self.file, self.id, key, self.source
        )
    }

    /// Whether `key` is present. Deliberately does not record `key` as read,
    /// so checking for a field never counts as covering it.
    pub fn has(&self, key: &str) -> bool {
        self.v.get(key).is_some()
    }

    pub fn str_(&self, key: &str) -> &'a str {
        match self.get(key).and_then(|x| x.as_str()) {
            Some(s) => s,
            None => self.missing(key),
        }
    }

    pub fn hex(&self, key: &str) -> Vec<u8> {
        let raw = self.str_(key);
        from_hex(raw).unwrap_or_else(|e| {
            panic!(
                "{}: vector {} field `{}` is not hex ({e}): {:?}\n  source: {}",
                self.file, self.id, key, raw, self.source
            )
        })
    }

    pub fn arr<const N: usize>(&self, key: &str) -> [u8; N] {
        let v = self.hex(key);
        v.clone().try_into().unwrap_or_else(|_| {
            panic!(
                "{}: vector {} field `{}` is {} bytes, expected {N}\n  source: {}",
                self.file,
                self.id,
                key,
                v.len(),
                self.source
            )
        })
    }

    pub fn words(&self, key: &str) -> [u32; 8] {
        let a = match self.get(key).and_then(|x| x.as_array()) {
            Some(a) => a,
            None => self.missing(key),
        };
        assert_eq!(
            a.len(),
            8,
            "{}: vector {} field `{}` has {} words, expected 8",
            self.file,
            self.id,
            key,
            a.len()
        );
        let mut out = [0u32; 8];
        for (i, w) in a.iter().enumerate() {
            out[i] = w
                .as_u64()
                .unwrap_or_else(|| panic!("{}: {} `{key}`[{i}] is not an integer", self.file, self.id))
                as u32;
        }
        out
    }

    pub fn ints(&self, key: &str) -> Vec<i32> {
        let a = match self.get(key).and_then(|x| x.as_array()) {
            Some(a) => a,
            None => self.missing(key),
        };
        a.iter()
            .enumerate()
            .map(|(i, x)| {
                x.as_i64()
                    .unwrap_or_else(|| {
                        panic!("{}: {} `{key}`[{i}] is not an integer", self.file, self.id)
                    }) as i32
            })
            .collect()
    }

    pub fn u64_(&self, key: &str) -> u64 {
        match self.get(key).and_then(|x| x.as_u64()) {
            Some(n) => n,
            None => self.missing(key),
        }
    }

    pub fn bool_(&self, key: &str) -> bool {
        match self.get(key).and_then(|x| x.as_bool()) {
            Some(b) => b,
            None => self.missing(key),
        }
    }

    /// Loads a `.bin` sidecar named by `<key>_file`, checking `<key>_len`.
    pub fn blob(&self, key: &str) -> Vec<u8> {
        let name = self.str_(&format!("{key}_file"));
        let want = self.u64_(&format!("{key}_len")) as usize;
        let bytes = read_sidecar(name, self.file, &self.id);
        assert_eq!(
            bytes.len(),
            want,
            "{}: vector {} sidecar {} is {} bytes but `{}_len` says {}",
            self.file,
            self.id,
            name,
            bytes.len(),
            key,
            want
        );
        bytes
    }

    // --- assertions -----------------------------------------------------

    pub fn eq_bytes(&mut self, key: &str, actual: &[u8]) {
        let expected = self.hex(key);
        self.compare(key, None, &expected, actual);
    }

    pub fn eq_blob(&mut self, key: &str, actual: &[u8]) {
        let name = self.str_(&format!("{key}_file")).to_string();
        let expected = self.blob(key);
        self.compare(key, Some(&name), &expected, actual);
    }

    pub fn eq_u64(&mut self, key: &str, actual: u64) {
        let expected = self.u64_(key);
        if expected != actual {
            self.record(key, None, &expected.to_string(), &actual.to_string(), None);
        }
    }

    pub fn eq_i64(&mut self, key: &str, actual: i64) {
        let expected = match self.get(key).and_then(|x| x.as_i64()) {
            Some(n) => n,
            None => self.missing(key),
        };
        if expected != actual {
            self.record(key, None, &expected.to_string(), &actual.to_string(), None);
        }
    }

    pub fn eq_bool(&mut self, key: &str, actual: bool) {
        let expected = self.bool_(key);
        if expected != actual {
            self.record(key, None, &expected.to_string(), &actual.to_string(), None);
        }
    }

    /// A string field that may be JSON `null`, recorded as read either way.
    pub fn opt_str(&self, key: &str) -> Option<&'a str> {
        match self.get(key) {
            None => self.missing(key),
            Some(Value::Null) => None,
            Some(v) => Some(v.as_str().unwrap_or_else(|| {
                panic!(
                    "{}: vector {} field `{}` is neither a string nor null.\n  source: {}",
                    self.file, self.id, key, self.source
                )
            })),
        }
    }

    /// Compares an optional string field read with [`Ctx::opt_str`].
    pub fn eq_opt_str(&mut self, key: &str, actual: Option<&str>) {
        let expected = self.opt_str(key).map(str::to_string);
        if expected.as_deref() != actual {
            self.record(
                key,
                None,
                expected.as_deref().unwrap_or("<null>"),
                actual.unwrap_or("<null>"),
                None,
            );
        }
    }

    pub fn eq_str(&mut self, key: &str, actual: &str) {
        let expected = self.str_(key).to_string();
        if expected != actual {
            self.record(key, None, &expected, actual, None);
        }
    }

    pub fn eq_words(&mut self, key: &str, actual: &[u32; 8]) {
        let expected = self.words(key);
        if &expected != actual {
            self.record(
                key,
                None,
                &format!("{expected:?}"),
                &format!("{actual:?}"),
                None,
            );
        }
    }

    pub fn eq_ints(&mut self, key: &str, actual: &[i32]) {
        let expected = self.ints(key);
        if expected != actual {
            let at = expected
                .iter()
                .zip(actual.iter())
                .position(|(a, b)| a != b)
                .map(|i| format!("first differing element: index {i}"));
            self.record(
                key,
                None,
                &format!("{expected:?}"),
                &format!("{actual:?}"),
                at,
            );
        }
    }

    fn compare(&mut self, key: &str, sidecar: Option<&str>, expected: &[u8], actual: &[u8]) {
        if expected == actual {
            return;
        }
        let at = expected
            .iter()
            .zip(actual.iter())
            .position(|(a, b)| a != b);
        let detail = match at {
            Some(i) => Some(format!(
                "first differing byte: offset {i} — expected 0x{:02x}, actual 0x{:02x}",
                expected[i], actual[i]
            )),
            None => Some(format!(
                "lengths differ: expected {} bytes, actual {} bytes",
                expected.len(),
                actual.len()
            )),
        };
        self.record(
            key,
            sidecar,
            &render(expected, at),
            &render(actual, at),
            detail,
        );
    }

    fn record(
        &mut self,
        key: &str,
        sidecar: Option<&str>,
        expected: &str,
        actual: &str,
        detail: Option<String>,
    ) {
        let field = match sidecar {
            Some(f) => format!("{key} ({f})"),
            None => key.to_string(),
        };
        let mut msg = String::new();
        let _ = write!(
            msg,
            "FIXTURE MISMATCH\n  \
             fixture : {}\n  \
             vector  : {}\n  \
             field   : {}\n  \
             source  : {}\n  \
             expected: {}\n  \
             actual  : {}",
            self.file, self.id, field, self.source, expected, actual
        );
        if let Some(d) = detail {
            let _ = write!(msg, "\n  {d}");
        }
        self.failures.push(msg);
    }
}

pub fn read_sidecar(name: &str, file: &str, id: &str) -> Vec<u8> {
    let path = fixtures_dir().join(name);
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "{file}: vector {id} references sidecar {} which cannot be read: {e}",
            path.display()
        )
    })
}
