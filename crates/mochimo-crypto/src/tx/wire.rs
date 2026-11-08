// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! Transaction types and the wire codec.
//!
//! Ordinary owned Rust types with a serializer at the boundary: no stored
//! offsets, no self-referential buffer, no `unsafe`. Offsets are computed
//! from the option bytes, as the reference's `tx__init` and `tx_read` do.
//!
//! Wire layout:
//!
//! - header: `options[4]`, `src_addr[40]`, `chg_addr[40]`, `send_total[8]`,
//!   `change_total[8]`, `fee_total[8]`, `blk_to_live[8]` — 116 bytes;
//! - `MDST_COUNT` destinations of `tag[20]`, `ref[16]`, `amount[8]` — 44
//!   bytes each, where `MDST_COUNT = options[2] + 1` in 1..=256;
//! - WOTS+ validation data: `signature[2144]`, `pub_seed[32]`, `adrs[32]`;
//! - an optional trailer: `nonce[8]`, `id[32]`.
//!   `tx_read` accepts a wire image with the trailer whole, absent, or
//!   partial.
//!
//! Multi-byte numbers are little-endian (`to_le_bytes`/`from_le_bytes`).
//!
//! # The serializer does not compute totals
//!
//! `send_total`, `fee_total` and the other header values are fields, written
//! as given. The node's `mdst_val` checks them; building a transaction a node
//! will accept is the caller's job. This lets the codec reproduce fixture
//! images with deliberately wrong totals (`D19-totals`, `D19-fees`).
//!
//! # Guarantees
//!
//! - The destination count is checked at construction
//!   ([`Transaction::new`](crate::tx::wire::Transaction::new),
//!   [`Transaction::set_dsts`](crate::tx::wire::Transaction::set_dsts)), so
//!   [`Transaction::to_wire`](crate::tx::wire::Transaction::to_wire) is
//!   infallible.
//! - No `unsafe` and no panicking construct: input is caller-controlled, and
//!   a panic would be a denial of service. Parsing uses `split_first_chunk`
//!   and `get`, never indexing.
//!
//! # Verification limits
//!
//! The codec round-trips every fixture group D wire image byte for byte and
//! reproduces the recorded offsets and digests
//! (`tests/kat.rs::reference_verdicts_native`, `tests/txwire.rs`). `tx_val`
//! needs a ledger, so no fixture is a transaction a node accepted end to end;
//! a correctly serialized transaction can still be rejected for ledger,
//! balance or block-to-live reasons.
//!
//! # Digests and the trailer
//!
//! `tx_hash` is `sha256` over one of two prefixes of the wire image:
//! `TX_HASH_MESSAGE` covers the first
//! [`Transaction::dsa_off`](crate::tx::wire::Transaction::dsa_off) bytes (the
//! signed message), and `TX_HASH_ID` stops at the trailer's `id`, so it also
//! covers the nonce. These are
//! [`Transaction::message_digest`](crate::tx::wire::Transaction::message_digest)
//! and [`Transaction::id_digest`](crate::tx::wire::Transaction::id_digest).
//! The node's `process_tx` zeroes the nonce and writes `TX_HASH_ID` into the
//! trailer after validation, so any trailer a wallet sends is ignored;
//! [`Transaction::seal`](crate::tx::wire::Transaction::seal) writes the same
//! pair.
//!
//! The bytes are public, so `backend::selected`'s `sha256` is used. Digests
//! are checked against the `Ds1-N*` fixtures in `tests/txwire.rs`.

use crate::backend::selected as backend;
use crate::consts::wire::{
    SIZEOF_MACCEPT, SIZEOF_MCLAIM, SIZEOF_MDST, SIZEOF_MSDLG, SIZEOF_MSTAKE, SIZEOF_MUNSTAKE, SIZEOF_TXHDR, SIZEOF_TXTLR,
    SIZEOF_WOTSVAL,
};
use crate::consts::{ADDR_LEN, ADDR_REF_LEN, ADDR_TAG_LEN, HASHLEN, SIG_LEN};
use crate::error::{Error, Result};

use super::{
    DAT_ACCEPT, DAT_CLAIM, DAT_CLEAR_DELEGATE, DAT_MDST, DAT_SET_DELEGATE, DAT_STAKE, DAT_UNSTAKE, DSA_WOTS, MAX_DESTINATIONS,
};

/// One destination: `MDST` on the wire.
///
/// The reference field is emitted as given; its grammar is checked before a
/// spend by `mesh::spend::reference_is_valid`, which mirrors the node's
/// `mdst_val__reference`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Destination {
    /// `MDST::tag` — the destination address tag, 20 bytes.
    pub tag: [u8; ADDR_TAG_LEN],
    /// `MDST::ref` — the destination reference, 16 bytes, zero-filled where
    /// unused.
    pub reference: [u8; ADDR_REF_LEN],
    /// `MDST::amount` — little-endian on the wire.
    pub amount: u64,
}

impl Destination {
    /// The 44-byte `MDST` image: `tag ‖ ref ‖ amount`, the amount
    /// little-endian. This is what [`Transaction::to_wire`](crate::tx::wire::Transaction::to_wire)
    /// emits, and the key the node's `mdst_val` sorts by (`memcmp` over the
    /// whole struct).
    pub fn mdst_image(&self) -> [u8; SIZEOF_MDST] {
        let mut out = [0u8; SIZEOF_MDST];
        let (tag, rest) = out.split_at_mut(ADDR_TAG_LEN);
        let (reference, amount) = rest.split_at_mut(ADDR_REF_LEN);
        tag.copy_from_slice(&self.tag);
        reference.copy_from_slice(&self.reference);
        amount.copy_from_slice(&self.amount.to_le_bytes());
        out
    }
}

/// What a transaction carries between its header and its validation data:
/// `TXDAT`, selected by `options[0]`.
///
/// Every type is followed by a WOTS+ block, so the signature covers the
/// header and payload, and the trailer follows the signature. The node's
/// other types (delegate rekey, attestation, payout, reward set) are not
/// built by wallets and are omitted. [`Transaction::from_wire`] refuses an
/// unnamed type before computing any offset.
///
/// | variant | `options[0]` | payload | `options[2]` |
/// | --- | --- | --- | --- |
/// | `Transfer` | `0x00` | 44 bytes per destination | destination count minus one |
/// | `SetDelegate` | `0x01` | the 20-byte delegate tag | 0 |
/// | `ClearDelegate` | `0x02` | nothing | 0 |
/// | `Claim` | `0x06` | the amount, 8 bytes little-endian | 0 |
/// | `Stake` | `0x0C` | `MSTAKE`: amount 8, tier 1, network 2, reserved 5 | 0 |
/// | `Unstake` | `0x0D` | `MUNSTAKE`: network 2, reserved 14 | 0 |
/// | `Accept` | `0x0E` | `MACCEPT`, 36 bytes (`staking::ConsentTerms`) | 0 |
///
/// The last three are v4.1 types (`v41.h`); their reserved bytes are written
/// zero and refused non-zero.
///
/// `options[2]` is read by the node only for transfers. This codec writes
/// zero for every other type and refuses anything else on parse, which is
/// stricter than `tx_read` and keeps `from_wire` and `to_wire` exact
/// inverses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Body {
    /// `TXDAT_MDST`: 1..=256 destinations, held to that count by
    /// [`Transaction::new`] and [`Transaction::set_body`].
    Transfer(Vec<Destination>),
    /// `TXDAT_SET_DELEGATE`: bind this delegate tag to the source's
    /// validator slot.
    SetDelegate {
        /// `MSDLG::delegate_tag`.
        delegate: [u8; ADDR_TAG_LEN],
    },
    /// `TXDAT_CLEAR_DELEGATE`: clear the source's delegate binding.
    ClearDelegate,
    /// `TXDAT_CLAIM`: release this many nanoMochimo from the source's
    /// entitlement column into its spendable balance.
    Claim {
        /// `MCLAIM::amount`, little-endian on the wire.
        amount: u64,
    },
    /// `TXDAT_STAKE` (v4.1): stake `amount` of the spendable balance at
    /// `tier`, on the chain whose `TXNETWORK` is `network`.
    Stake {
        /// `MSTAKE::amount`, little-endian.
        amount: u64,
        /// `MSTAKE::tier`, 0 to 5 for the node.
        tier: u8,
        /// `MSTAKE::network`, little-endian.
        network: u16,
    },
    /// `TXDAT_UNSTAKE` (v4.1): end the source's stake.
    Unstake {
        /// `MUNSTAKE::network`, little-endian.
        network: u16,
    },
    /// `TXDAT_ACCEPT` (v4.1): consent to a designation; kind 0 revokes.
    Accept(crate::staking::ConsentTerms),
}

impl Body {
    /// The `options[0]` this body is written under.
    pub fn dat_type(&self) -> u8 {
        match self {
            Body::Transfer(_) => DAT_MDST,
            Body::SetDelegate { .. } => DAT_SET_DELEGATE,
            Body::ClearDelegate => DAT_CLEAR_DELEGATE,
            Body::Claim { .. } => DAT_CLAIM,
            Body::Stake { .. } => DAT_STAKE,
            Body::Unstake { .. } => DAT_UNSTAKE,
            Body::Accept(_) => DAT_ACCEPT,
        }
    }

    /// The payload's length on the wire: `dsaoff - sizeof(TXHDR)`.
    pub fn payload_len(&self) -> usize {
        match self {
            Body::Transfer(dsts) => SIZEOF_MDST * dsts.len(),
            Body::SetDelegate { .. } => SIZEOF_MSDLG,
            Body::ClearDelegate => 0,
            Body::Claim { .. } => SIZEOF_MCLAIM,
            Body::Stake { .. } => SIZEOF_MSTAKE,
            Body::Unstake { .. } => SIZEOF_MUNSTAKE,
            Body::Accept(_) => SIZEOF_MACCEPT,
        }
    }

    /// The payload length a type byte selects, or `None` for a type this
    /// codec does not build. `ndst` is `MDST_COUNT`, read only for a
    /// transfer.
    fn payload_len_for(dat_type: u8, ndst: usize) -> Option<usize> {
        match dat_type {
            DAT_MDST => Some(SIZEOF_MDST * ndst),
            DAT_SET_DELEGATE => Some(SIZEOF_MSDLG),
            DAT_CLEAR_DELEGATE => Some(0),
            DAT_CLAIM => Some(SIZEOF_MCLAIM),
            DAT_STAKE => Some(SIZEOF_MSTAKE),
            DAT_UNSTAKE => Some(SIZEOF_MUNSTAKE),
            DAT_ACCEPT => Some(SIZEOF_MACCEPT),
            _ => None,
        }
    }

    /// `options[2]` as this body writes it.
    fn count_byte(&self) -> u8 {
        match self {
            // Lossless: a transfer holds 1..=256 destinations, so
            // len - 1 <= 255.
            Body::Transfer(dsts) => (dsts.len() - 1) as u8,
            Body::SetDelegate { .. }
            | Body::ClearDelegate
            | Body::Claim { .. }
            | Body::Stake { .. }
            | Body::Unstake { .. }
            | Body::Accept(_) => 0,
        }
    }

    fn write(&self, w: &mut Vec<u8>) {
        match self {
            Body::Transfer(dsts) => {
                for d in dsts {
                    w.extend_from_slice(&d.mdst_image());
                }
            }
            Body::SetDelegate { delegate } => w.extend_from_slice(delegate),
            Body::ClearDelegate => {}
            Body::Claim { amount } => w.extend_from_slice(&amount.to_le_bytes()),
            Body::Stake { amount, tier, network } => {
                w.extend_from_slice(&amount.to_le_bytes());
                w.push(*tier);
                w.extend_from_slice(&network.to_le_bytes());
                w.extend_from_slice(&[0u8; SIZEOF_MSTAKE - 11]);
            }
            Body::Unstake { network } => {
                w.extend_from_slice(&network.to_le_bytes());
                w.extend_from_slice(&[0u8; SIZEOF_MUNSTAKE - 2]);
            }
            Body::Accept(terms) => w.extend_from_slice(&terms.image()),
        }
    }
}

/// The WOTS+ validation data: `WOTSVAL` on the wire.
///
/// All fields are public wire data, so deriving `Debug` is safe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WotsVal {
    /// `WOTSVAL::signature`, 2144 bytes.
    pub signature: [u8; SIG_LEN],
    /// `WOTSVAL::pub_seed`.
    pub pub_seed: [u8; 32],
    /// `WOTSVAL::adrs`. The node's `tx_val__wots` requires a specific tail
    /// for a valid transaction; this type does not enforce it.
    pub adrs: [u8; 32],
}

/// The transaction trailer: `TXTLR` on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trailer {
    /// `TXTLR::nonce` — little-endian on the wire.
    pub nonce: u64,
    /// `TXTLR::id` — the transaction ID hash.
    pub id: [u8; HASHLEN],
}

/// A transaction with owned fields, serializable to the reference's wire
/// image.
///
/// The body is private because it carries the type's one invariant: a
/// transfer holds **1..=256 destinations**, the range `MDST_COUNT =
/// options[2]+1` can express. Everything else is plain data and public.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    /// `TXHDR::src_addr` — tag half at offset 0, hash half at offset 20.
    pub src_addr: [u8; ADDR_LEN],
    /// `TXHDR::chg_addr`.
    pub chg_addr: [u8; ADDR_LEN],
    /// `TXHDR::send_total`.
    pub send_total: u64,
    /// `TXHDR::change_total`.
    pub change_total: u64,
    /// `TXHDR::fee_total`.
    pub fee_total: u64,
    /// `TXHDR::blk_to_live`.
    pub blk_to_live: u64,
    /// `options[3]`, reserved. Unused by the node but accepted non-zero by
    /// `tx_read`, so it is carried to preserve round trips.
    pub reserved: u8,
    /// The payload; a transfer's 1..=256 destinations enforced at every
    /// write.
    body: Body,
    /// The WOTS+ validation data.
    pub wots: WotsVal,
    /// The trailer, present in the disk form and absent in the network form
    /// (the node accepts both).
    pub trailer: Option<Trailer>,
}

/// Reads the next `N` bytes off the front of `rest`, or reports what was
/// missing. The only cursor this module has; nothing here indexes.
fn take<'a, const N: usize>(rest: &mut &'a [u8], what: &'static str) -> Result<&'a [u8; N]> {
    match rest.split_first_chunk::<N>() {
        Some((head, tail)) => {
            *rest = tail;
            Ok(head)
        }
        None => Err(Error::Length {
            what,
            expected: N,
            got: rest.len(),
        }),
    }
}

impl Transaction {
    /// A transfer to the given destinations with every other field zero. Set
    /// the public fields directly.
    ///
    /// # Errors
    ///
    /// [`Error::Range`] for a destination count outside 1..=256.
    pub fn new(dsts: Vec<Destination>) -> Result<Self> {
        Self::with_body(Body::Transfer(dsts))
    }

    /// A transaction carrying `body` with every other field zero.
    ///
    /// # Errors
    ///
    /// [`Error::Range`] for a transfer with a destination count outside
    /// 1..=256.
    pub fn with_body(body: Body) -> Result<Self> {
        Self::check_body(&body)?;
        Ok(Transaction {
            src_addr: [0; ADDR_LEN],
            chg_addr: [0; ADDR_LEN],
            send_total: 0,
            change_total: 0,
            fee_total: 0,
            blk_to_live: 0,
            reserved: 0,
            body,
            wots: WotsVal {
                signature: [0; SIG_LEN],
                pub_seed: [0; 32],
                adrs: [0; 32],
            },
            trailer: None,
        })
    }

    fn check_count(n: usize) -> Result<()> {
        if n == 0 || n > usize::from(MAX_DESTINATIONS) {
            return Err(Error::Range {
                what: "destination count",
                min: 1,
                max: u64::from(MAX_DESTINATIONS),
                got: n as u64,
            });
        }
        Ok(())
    }

    fn check_body(body: &Body) -> Result<()> {
        match body {
            Body::Transfer(dsts) => Self::check_count(dsts.len()),
            Body::SetDelegate { .. }
            | Body::ClearDelegate
            | Body::Claim { .. }
            | Body::Stake { .. }
            | Body::Unstake { .. }
            | Body::Accept(_) => Ok(()),
        }
    }

    /// The payload.
    pub fn body(&self) -> &Body {
        &self.body
    }

    /// Replaces the payload.
    ///
    /// # Errors
    ///
    /// [`Error::Range`] for a transfer with a destination count outside
    /// 1..=256; the payload is unchanged.
    pub fn set_body(&mut self, body: Body) -> Result<()> {
        Self::check_body(&body)?;
        self.body = body;
        Ok(())
    }

    /// The destination list: a transfer's destinations, and empty for every
    /// other body, which pays no one.
    pub fn dsts(&self) -> &[Destination] {
        match &self.body {
            Body::Transfer(dsts) => dsts,
            _ => &[],
        }
    }

    /// Replaces the payload with a transfer to `dsts`.
    ///
    /// # Errors
    ///
    /// [`Error::Range`] for a destination count outside 1..=256.
    pub fn set_dsts(&mut self, dsts: Vec<Destination>) -> Result<()> {
        self.set_body(Body::Transfer(dsts))
    }

    /// The destination count, as `MDST_COUNT` would report it for a
    /// transfer; zero for every other body.
    pub fn dst_count(&self) -> u16 {
        // Lossless: the constructor and setter bound the length at 256.
        self.dsts().len() as u16
    }

    /// Offset of the validation data: `sizeof(TXHDR)` plus the payload
    /// (`sizeof(MDST) * count` for a transfer). This is the signed length.
    pub fn dsa_off(&self) -> usize {
        SIZEOF_TXHDR + self.body.payload_len()
    }

    /// Offset of the trailer: `dsaoff + sizeof(WOTSVAL)`.
    pub fn tlr_off(&self) -> usize {
        self.dsa_off() + SIZEOF_WOTSVAL
    }

    /// The full transaction size, trailer included: `tlroff + sizeof(TXTLR)`,
    /// whether or not the wire form carries the trailer (as `tx_read`
    /// computes `tx_sz`).
    pub fn tx_sz(&self) -> usize {
        self.tlr_off() + SIZEOF_TXTLR
    }

    /// The length [`Self::to_wire`] will emit: `tx_sz` with the trailer,
    /// `tx_sz - sizeof(TXTLR)` without.
    pub fn wire_len(&self) -> usize {
        match self.trailer {
            Some(_) => self.tx_sz(),
            None => self.tx_sz() - SIZEOF_TXTLR,
        }
    }

    /// The signed prefix: header and payload, the first
    /// [`Self::dsa_off`] bytes of the image and the whole of what
    /// `TX_HASH_MESSAGE` covers.
    fn write_signed_prefix(&self, w: &mut Vec<u8>) {
        w.push(self.body.dat_type()); // options[0]
        w.push(DSA_WOTS); // options[1]
        // options[2]: a transfer's zero-based destination count, else zero.
        w.push(self.body.count_byte());
        w.push(self.reserved); // options[3]
        w.extend_from_slice(&self.src_addr);
        w.extend_from_slice(&self.chg_addr);
        w.extend_from_slice(&self.send_total.to_le_bytes());
        w.extend_from_slice(&self.change_total.to_le_bytes());
        w.extend_from_slice(&self.fee_total.to_le_bytes());
        w.extend_from_slice(&self.blk_to_live.to_le_bytes());
        self.body.write(w);
    }

    /// The validation data, `WOTSVAL`.
    fn write_wots(&self, w: &mut Vec<u8>) {
        w.extend_from_slice(&self.wots.signature);
        w.extend_from_slice(&self.wots.pub_seed);
        w.extend_from_slice(&self.wots.adrs);
    }

    /// Serializes to the wire image, byte for byte as the reference lays it
    /// out. Infallible: the only unrepresentable state is fenced at
    /// construction.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut w = Vec::with_capacity(self.wire_len());
        self.write_signed_prefix(&mut w);
        self.write_wots(&mut w);
        if let Some(t) = &self.trailer {
            w.extend_from_slice(&t.nonce.to_le_bytes());
            w.extend_from_slice(&t.id);
        }
        w
    }

    /// `TX_HASH_MESSAGE`: `sha256` over the header and payload (the first
    /// [`Self::dsa_off`] bytes), the message a WOTS+ signature is over.
    pub fn message_digest(&self) -> [u8; HASHLEN] {
        let mut w = Vec::with_capacity(self.dsa_off());
        self.write_signed_prefix(&mut w);
        backend::sha256(&w)
    }

    /// `TX_HASH_ID`: `sha256` over everything up to the trailer's `id`,
    /// including the nonce. The nonce is this value's, or zero when the
    /// trailer is absent (the form the node's `process_tx` produces).
    pub fn id_digest(&self) -> [u8; HASHLEN] {
        let nonce = self.trailer.as_ref().map_or(0, |t| t.nonce);
        self.id_digest_with_nonce(nonce)
    }

    fn id_digest_with_nonce(&self, nonce: u64) -> [u8; HASHLEN] {
        let mut w = Vec::with_capacity(self.tlr_off() + 8);
        self.write_signed_prefix(&mut w);
        self.write_wots(&mut w);
        w.extend_from_slice(&nonce.to_le_bytes());
        backend::sha256(&w)
    }

    /// Writes the trailer the node writes after validation: nonce zero,
    /// `id = TX_HASH_ID`. The node overwrites any trailer it receives, so this
    /// is for the wallet's own use: the id is what `/mempool` and
    /// `/construction/submit` name the transaction by.
    pub fn seal(&mut self) {
        let id = self.id_digest_with_nonce(0);
        self.trailer = Some(Trailer { nonce: 0, id });
    }

    /// Parses a wire image, accepting exactly what `tx_read` accepts.
    ///
    /// Checks run in the reference's order: header length; the two type
    /// bytes (one of the seven [`Body`] types, and `TXDSA_WOTS`); `options[2]`
    /// zero for a type with no destination array (see [`Body`]); then the
    /// length window `tx_sz - sizeof(TXTLR) <= len <= tx_sz`.
    ///
    /// A partial trailer is zero-extended, as the reference's `memset` and
    /// partial `memcpy` leave it. So `to_wire(from_wire(x)) == x` holds for
    /// the two canonical lengths, and a partial length yields the
    /// full-trailer image.
    ///
    /// # Errors
    ///
    /// [`Error::Length`] for a short header, [`Error::UnknownTxType`] for an
    /// unknown type byte, [`Error::Range`] for a wrong DSA byte, a non-zero
    /// `options[2]` where it is unused, or a length outside the window, and
    /// [`Error::ReservedNotZero`] or a payload error for an invalid v4.1
    /// payload.
    pub fn from_wire(bytes: &[u8]) -> Result<Transaction> {
        if bytes.len() < SIZEOF_TXHDR {
            return Err(Error::Length {
                what: "transaction wire header",
                expected: SIZEOF_TXHDR,
                got: bytes.len(),
            });
        }
        let mut r = bytes;
        let options = take::<4>(&mut r, "options")?;
        let ndst = usize::from(options[2]) + 1; // zero-based
        let Some(payload_len) = Body::payload_len_for(options[0], ndst) else {
            return Err(Error::UnknownTxType { dat_type: options[0] });
        };
        if options[1] != DSA_WOTS {
            return Err(Error::Range {
                what: "TXDSA type byte",
                min: u64::from(DSA_WOTS),
                max: u64::from(DSA_WOTS),
                got: u64::from(options[1]),
            });
        }
        if options[0] != DAT_MDST && options[2] != 0 {
            return Err(Error::Range {
                what: "options[2] of a type with no destination array",
                min: 0,
                max: 0,
                got: u64::from(options[2]),
            });
        }
        let reserved = options[3];
        let tx_sz = SIZEOF_TXHDR + payload_len + SIZEOF_WOTSVAL + SIZEOF_TXTLR;
        if bytes.len() > tx_sz || bytes.len() < tx_sz - SIZEOF_TXTLR {
            return Err(Error::Range {
                what: "transaction wire length",
                min: (tx_sz - SIZEOF_TXTLR) as u64,
                max: tx_sz as u64,
                got: bytes.len() as u64,
            });
        }

        let src_addr = *take::<ADDR_LEN>(&mut r, "src_addr")?;
        let chg_addr = *take::<ADDR_LEN>(&mut r, "chg_addr")?;
        let send_total = u64::from_le_bytes(*take::<8>(&mut r, "send_total")?);
        let change_total = u64::from_le_bytes(*take::<8>(&mut r, "change_total")?);
        let fee_total = u64::from_le_bytes(*take::<8>(&mut r, "fee_total")?);
        let blk_to_live = u64::from_le_bytes(*take::<8>(&mut r, "blk_to_live")?);

        let body = match options[0] {
            DAT_MDST => {
                let mut dsts = Vec::with_capacity(ndst);
                for _ in 0..ndst {
                    let tag = *take::<ADDR_TAG_LEN>(&mut r, "destination tag")?;
                    let reference = *take::<ADDR_REF_LEN>(&mut r, "destination reference")?;
                    let amount = u64::from_le_bytes(*take::<8>(&mut r, "destination amount")?);
                    dsts.push(Destination {
                        tag,
                        reference,
                        amount,
                    });
                }
                Body::Transfer(dsts)
            }
            DAT_SET_DELEGATE => Body::SetDelegate {
                delegate: *take::<SIZEOF_MSDLG>(&mut r, "delegate tag")?,
            },
            DAT_CLEAR_DELEGATE => Body::ClearDelegate,
            DAT_STAKE => {
                let amount = u64::from_le_bytes(*take::<8>(&mut r, "stake amount")?);
                let [tier] = *take::<1>(&mut r, "stake tier")?;
                let network = u16::from_le_bytes(*take::<2>(&mut r, "stake network")?);
                let reserved = take::<{ SIZEOF_MSTAKE - 11 }>(&mut r, "stake reserved")?;
                if reserved.iter().any(|b| *b != 0) {
                    return Err(Error::ReservedNotZero { what: "MSTAKE reserved" });
                }
                Body::Stake { amount, tier, network }
            }
            DAT_UNSTAKE => {
                let network = u16::from_le_bytes(*take::<2>(&mut r, "unstake network")?);
                let reserved = take::<{ SIZEOF_MUNSTAKE - 2 }>(&mut r, "unstake reserved")?;
                if reserved.iter().any(|b| *b != 0) {
                    return Err(Error::ReservedNotZero { what: "MUNSTAKE reserved" });
                }
                Body::Unstake { network }
            }
            DAT_ACCEPT => Body::Accept(crate::staking::ConsentTerms::from_image(take::<SIZEOF_MACCEPT>(
                &mut r,
                "accept terms",
            )?)?),
            // `payload_len_for` admits seven types; six are matched above.
            _ => Body::Claim {
                amount: u64::from_le_bytes(*take::<SIZEOF_MCLAIM>(&mut r, "claim amount")?),
            },
        };

        let signature = *take::<SIG_LEN>(&mut r, "wots signature")?;
        let pub_seed = *take::<32>(&mut r, "wots pub_seed")?;
        let adrs = *take::<32>(&mut r, "wots adrs")?;

        // The window check bounded what remains to 0..=sizeof(TXTLR). Empty
        // is the network form; anything else is a whole or partial trailer,
        // zero-extended.
        let trailer = if r.is_empty() {
            None
        } else {
            let mut padded = [0u8; SIZEOF_TXTLR];
            match padded.get_mut(..r.len()) {
                Some(dst) => dst.copy_from_slice(r),
                // Unreachable given the window check; an error rather than a
                // panic so no input can crash the parser.
                None => {
                    return Err(Error::Length {
                        what: "transaction trailer",
                        expected: SIZEOF_TXTLR,
                        got: r.len(),
                    })
                }
            }
            let mut t: &[u8] = &padded;
            let nonce = u64::from_le_bytes(*take::<8>(&mut t, "trailer nonce")?);
            let id = *take::<HASHLEN>(&mut t, "trailer id")?;
            Some(Trailer { nonce, id })
        };

        Ok(Transaction {
            src_addr,
            chg_addr,
            send_total,
            change_total,
            fee_total,
            blk_to_live,
            reserved,
            body,
            wots: WotsVal {
                signature,
                pub_seed,
                adrs,
            },
            trailer,
        })
    }
}
