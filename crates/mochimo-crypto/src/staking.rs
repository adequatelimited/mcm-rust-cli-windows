// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! Coin staking on the proof-of-stake chain from v4.1: the rules a wallet
//! checks before its one-time key signs, and the consent terms an `ACCEPT`
//! carries.
//!
//! The constants mirror the node's v4.1 contract header `v41.h`. The wire
//! images and consent digest are checked against fixture group S, and the
//! arithmetic (`minstake`, `expiry`, `tier_of`) against the node's own test
//! points in `tests/spend.rs`.
//!
//! A one-time key signs one digest. A staking transaction the node refuses
//! is never included, so the key does not rotate but has signed, and the
//! next transaction from that position must be the same bytes. One the node
//! includes but that has no effect (a stake with unclaimed entitlement, a
//! claim while locked) costs the fee and rotates the key. The wallet checks
//! for both before reserving the key, wherever it can see the state.

use crate::addr::Tag;
use crate::backend::selected as backend;
use crate::error::{Error, Result};

/// The mainnet activation height, `POSV41TRIGGER`: an NG height. The v4.1
/// rules apply to every block **above** it (`POS_V41_ACTIVE(h)`), so the
/// first block that can carry a staking transaction is `T41 + 1`.
pub const MAINNET_T41: u64 = 1_136_384;
/// `TXNETWORK` on mainnet, the network id a staking payload signs.
pub const NETWORK_MAINNET: u16 = 0xACA1;
/// `TXNETWORK` on the proof-of-stake testnet.
pub const NETWORK_TESTNET: u16 = 7357;
/// `POS_STAKE_TIERS`: tiers 0 to 5.
pub const TIERS: u8 = 6;
/// `POS_STAKE_BASE_LOCK`: tier 0's lock in heights; tier `k` locks
/// `BASE_LOCK << k`, to the next neogenesis height.
pub const BASE_LOCK: u64 = 65_536;
/// `POS_MINSTAKE_START_MCM`.
pub const MINSTAKE_START_MCM: u64 = 500;
/// `POS_MINSTAKE_STEP_MCM`.
pub const MINSTAKE_STEP_MCM: u64 = 10;
/// `POS_MINSTAKE_FLOOR_MCM`.
pub const MINSTAKE_FLOOR_MCM: u64 = 10;
/// `POS_MINSTAKE_PERIOD`: heights per step of the minimum stake.
pub const MINSTAKE_PERIOD: u64 = 65_536;
/// nanoMochimo per MCM.
pub const NANO_PER_MCM: u64 = 1_000_000_000;
/// The claim amount that means "everything": `UINT64_MAX`, so an
/// entitlement that grows between signing and inclusion leaves no residue.
pub const CLAIM_ALL: u64 = u64::MAX;
/// `POS_CONSENT_DOMAIN`, its fourteen ASCII bytes without the NUL.
pub const CONSENT_DOMAIN: &[u8; 14] = b"MCM-CONSENT-v1";
/// `POS_CONSENT_DIGEST_LEN`.
pub const CONSENT_DIGEST_LEN: usize = 16;
/// `POS_CONSENT_LAPSE`: a consent lapses this many heights after the block
/// that recorded it.
pub const CONSENT_LAPSE: u64 = 65_536;
/// `POS_SLOT_CAP`: the highest validator slot a consent can name.
pub const SLOT_CAP: u32 = 32;
/// `POS_REG_F_ADEQUATE`: the one flag an election's terms may carry.
pub const FLAG_ADEQUATE: u8 = 0x01;
/// The block rate used to convert heights to time: one block a minute.
/// A display estimate only; pseudoblocks and finality delays lengthen it.
pub const BLOCKS_PER_HOUR: u64 = 60;

/// `POS_CONSENT_NONE`: with every term zero but the network, a revoke.
pub const KIND_REVOKE: u8 = 0;
/// `POS_CONSENT_DELEGATE`: the delegate's consent to a set-delegate by the
/// cold tag named as its peer.
pub const KIND_DELEGATE: u8 = 1;
/// `POS_CONSENT_MEMBER_DELEGATE`: the delegate's consent to an election or
/// recovery naming it beside the cold tag named as its peer.
pub const KIND_MEMBER_DELEGATE: u8 = 2;
/// `POS_CONSENT_MEMBER_COLD`: the cold tag's consent to an election or
/// recovery naming it beside the delegate named as its peer.
pub const KIND_MEMBER_COLD: u8 = 3;
/// `POS_CONSENT_NEW_HOLDER`: the new holder's consent to a slot transfer
/// from the holder named as its peer.
pub const KIND_NEW_HOLDER: u8 = 4;
/// `POS_CONSENT_ACT_ELECT`.
pub const ACTION_ELECT: u8 = 1;
/// `POS_CONSENT_ACT_RECOVER`.
pub const ACTION_RECOVER: u8 = 2;

/// The chain a staking transaction is signed for: the network id its payload
/// carries and the height v4.1 activates at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Network {
    /// `TXNETWORK`.
    pub id: u16,
    /// `POSV41TRIGGER`.
    pub t41: u64,
}

impl Network {
    /// Mainnet: `0xACA1`, activated above 1,136,384.
    pub const MAINNET: Network = Network {
        id: NETWORK_MAINNET,
        t41: MAINNET_T41,
    };

    /// Whether a block at height `h` runs the v4.1 rules: `h > T41`.
    #[must_use]
    pub fn active_at(&self, h: u64) -> bool {
        h > self.t41
    }
}

/// `pos_v41_minstake(h)`, in nanoMochimo:
/// `max(10, 500 - 10 * floor((h - T41) / 65,536))` MCM, and 500 MCM at or
/// below `T41`.
#[must_use]
pub fn minstake(h: u64, t41: u64) -> u64 {
    let steps = if h > t41 { (h - t41) / MINSTAKE_PERIOD } else { 0 };
    let span = (MINSTAKE_START_MCM - MINSTAKE_FLOOR_MCM) / MINSTAKE_STEP_MCM;
    let mcm = if steps >= span {
        MINSTAKE_FLOOR_MCM
    } else {
        MINSTAKE_START_MCM - MINSTAKE_STEP_MCM * steps
    };
    mcm * NANO_PER_MCM
}

/// The first height at which [`minstake`] is lower than at `h`, or `None`
/// once it has reached its floor.
#[must_use]
pub fn minstake_next_step(h: u64, t41: u64) -> Option<u64> {
    if minstake(h, t41) == MINSTAKE_FLOOR_MCM * NANO_PER_MCM {
        return None;
    }
    let steps = if h > t41 { (h - t41) / MINSTAKE_PERIOD } else { 0 };
    // The step boundary is the first h with (h - t41) / period == steps + 1.
    (steps + 1).checked_mul(MINSTAKE_PERIOD)?.checked_add(t41)
}

/// `pos_v41_expiry(h, tier)`: the first neogenesis height (a multiple of
/// 256) at or above `h + (65,536 << tier)`. `None` for a tier above 5 or a
/// height that would overflow, where the node returns zero.
#[must_use]
pub fn expiry(h: u64, tier: u8) -> Option<u64> {
    if tier >= TIERS {
        return None;
    }
    let lock = BASE_LOCK << tier;
    let x = h.checked_add(lock)?.checked_add(255)?;
    Some(x & !255)
}

/// `pos_v41_tier(commit, expiry)`: the `k` with
/// `65,536 << k <= expiry - commit <= (65,536 << k) + 255`, or `None` when no
/// tier matches.
#[must_use]
pub fn tier_of(commit: u64, expiry: u64) -> Option<u8> {
    let span = expiry.checked_sub(commit)?;
    (0..TIERS).find(|&k| {
        let lock = BASE_LOCK << k;
        span >= lock && span <= lock + 255
    })
}

/// A tier's coefficient: `tier + 1`, so 1x to 6x. It persists after expiry.
#[must_use]
pub fn coefficient(tier: u8) -> u64 {
    u64::from(tier) + 1
}

/// Heights as whole days at [`BLOCKS_PER_HOUR`], rounded down, and the
/// remainder in hours, for display.
#[must_use]
pub fn days_and_hours(heights: u64) -> (u64, u64) {
    let hours = heights / BLOCKS_PER_HOUR;
    (hours / 24, hours % 24)
}

/// The terms of an `ACCEPT`: `MACCEPT` field for field, the network included.
///
/// `kind` 0 with every other term zero is a revoke. [`ConsentTerms::check`]
/// enforces which terms each kind may carry: others must be zero, because
/// the digest covers all of them and a designation compares only its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsentTerms {
    /// `POS_CONSENT_*`.
    pub kind: u8,
    /// The counterpart tag.
    pub peer: Tag,
    /// `POS_CONSENT_ACT_*`, kinds 2 and 3 only.
    pub action: u8,
    /// The validator slot, kinds 2, 3 and 4.
    pub slot: u32,
    /// The IPv4 address in network order, as the membership payloads carry
    /// it: kinds 2 and 3 for an election, and kind 4.
    pub ip: [u8; 4],
    /// The validator port, with `ip`.
    pub port: u16,
    /// Kinds 2 and 3 for an election: 0, or [`FLAG_ADEQUATE`].
    pub flags: u8,
    /// `TXNETWORK`, which the digest covers.
    pub network: u16,
}

/// `sizeof(MACCEPT)`.
pub const MACCEPT_LEN: usize = crate::consts::wire::SIZEOF_MACCEPT;

impl ConsentTerms {
    /// The revoke: kind 0, every term zero but the network.
    #[must_use]
    pub fn revoke(network: u16) -> ConsentTerms {
        ConsentTerms {
            kind: KIND_REVOKE,
            peer: [0; 20],
            action: 0,
            slot: 0,
            ip: [0; 4],
            port: 0,
            flags: 0,
            network,
        }
    }

    /// The 36-byte `MACCEPT`: kind 1, peer 20, action 1, slot 4 (LE), ip 4,
    /// port 2 (LE), flags 1, network 2 (LE), reserved 1 (zero).
    #[must_use]
    pub fn image(&self) -> [u8; MACCEPT_LEN] {
        let mut w: Vec<u8> = Vec::with_capacity(MACCEPT_LEN);
        w.push(self.kind);
        w.extend_from_slice(&self.peer);
        w.push(self.action);
        w.extend_from_slice(&self.slot.to_le_bytes());
        w.extend_from_slice(&self.ip);
        w.extend_from_slice(&self.port.to_le_bytes());
        w.push(self.flags);
        w.extend_from_slice(&self.network.to_le_bytes());
        w.push(0);
        let mut out = [0u8; MACCEPT_LEN];
        for (dst, src) in out.iter_mut().zip(w) {
            *dst = src;
        }
        out
    }

    /// Reads a 36-byte `MACCEPT`.
    ///
    /// # Errors
    ///
    /// [`Error::ReservedNotZero`] if the reserved byte is not zero.
    pub fn from_image(image: &[u8; MACCEPT_LEN]) -> Result<ConsentTerms> {
        let (&[kind], rest) = image.split_first_chunk::<1>().ok_or(Error::ReservedNotZero { what: "MACCEPT" })?;
        let (&peer, rest) = rest.split_first_chunk::<20>().ok_or(Error::ReservedNotZero { what: "MACCEPT" })?;
        let (&[action], rest) = rest.split_first_chunk::<1>().ok_or(Error::ReservedNotZero { what: "MACCEPT" })?;
        let (&slot, rest) = rest.split_first_chunk::<4>().ok_or(Error::ReservedNotZero { what: "MACCEPT" })?;
        let (&ip, rest) = rest.split_first_chunk::<4>().ok_or(Error::ReservedNotZero { what: "MACCEPT" })?;
        let (&port, rest) = rest.split_first_chunk::<2>().ok_or(Error::ReservedNotZero { what: "MACCEPT" })?;
        let (&[flags], rest) = rest.split_first_chunk::<1>().ok_or(Error::ReservedNotZero { what: "MACCEPT" })?;
        let (&network, reserved) = rest.split_first_chunk::<2>().ok_or(Error::ReservedNotZero { what: "MACCEPT" })?;
        if reserved.iter().any(|b| *b != 0) {
            return Err(Error::ReservedNotZero { what: "MACCEPT reserved" });
        }
        Ok(ConsentTerms {
            kind,
            peer,
            action,
            slot: u32::from_le_bytes(slot),
            ip,
            port: u16::from_le_bytes(port),
            flags,
            network: u16::from_le_bytes(network),
        })
    }

    /// The node's consent digest: SHA-256 over the fourteen domain bytes, the
    /// kind, the consenting tag and the whole `MACCEPT` (the kind appears
    /// twice), truncated to sixteen bytes. The ledger records it, and a
    /// designation's terms must reproduce it to take effect.
    #[must_use]
    pub fn digest(&self, own: &Tag) -> [u8; CONSENT_DIGEST_LEN] {
        let mut pre = Vec::with_capacity(CONSENT_DOMAIN.len() + 1 + own.len() + MACCEPT_LEN);
        pre.extend_from_slice(CONSENT_DOMAIN);
        pre.push(self.kind);
        pre.extend_from_slice(own);
        pre.extend_from_slice(&self.image());
        let full = backend::sha256(&pre);
        let mut out = [0u8; CONSENT_DIGEST_LEN];
        for (dst, src) in out.iter_mut().zip(full) {
            *dst = src;
        }
        out
    }

    /// Checks the per-kind terms, as the node's designations compare them,
    /// for a consent signed by `own`:
    ///
    /// * kind 0 (revoke): every term zero;
    /// * kind 1: a peer, nothing else;
    /// * kinds 2 and 3: a peer, an action, a slot 1..=32; for an election an
    ///   IP and port the node's `ip_ok` accepts and flags 0 or 1; for a
    ///   recovery no IP, port or flags, as the recovery vote carries none;
    /// * kind 4: a peer, a slot 1..=32, an IP and a port, no action or flags.
    ///
    /// A peer equal to `own` is refused for every kind.
    ///
    /// # Errors
    ///
    /// [`Error::ConsentTerms`] naming the first rule the terms break.
    pub fn check(&self, own: &Tag) -> Result<()> {
        let refuse = |why: &'static str| Err(Error::ConsentTerms { why });
        let no_peer = self.peer.iter().all(|b| *b == 0);
        let no_ip = self.ip.iter().all(|b| *b == 0);
        if self.kind == KIND_REVOKE {
            if !no_peer || self.action != 0 || self.slot != 0 || !no_ip || self.port != 0 || self.flags != 0 {
                return refuse("a revoke carries no term but the network");
            }
            return Ok(());
        }
        if self.kind > KIND_NEW_HOLDER {
            return refuse("the kind must be 0 to 4");
        }
        if no_peer {
            return refuse("a consent names its peer");
        }
        if self.peer == *own {
            return refuse("the peer is the consenting tag itself");
        }
        let slot_ok = (1..=SLOT_CAP).contains(&self.slot);
        let address_ok = || match ip_refusal(&self.ip, self.port) {
            None => Ok(()),
            Some(why) => refuse(why),
        };
        match self.kind {
            KIND_DELEGATE => {
                if self.action != 0 || self.slot != 0 || !no_ip || self.port != 0 || self.flags != 0 {
                    return refuse("a delegate consent (kind 1) carries only its peer");
                }
            }
            KIND_NEW_HOLDER => {
                if !slot_ok {
                    return refuse("the slot must be 1 to 32");
                }
                if self.action != 0 || self.flags != 0 {
                    return refuse("a new-holder consent (kind 4) carries no action and no flags");
                }
                address_ok()?;
            }
            _ => {
                if !slot_ok {
                    return refuse("the slot must be 1 to 32");
                }
                match self.action {
                    ACTION_ELECT => {
                        address_ok()?;
                        if self.flags != 0 && self.flags != FLAG_ADEQUATE {
                            return refuse("an election's flags are 0 or 1");
                        }
                    }
                    ACTION_RECOVER => {
                        if !no_ip || self.port != 0 || self.flags != 0 {
                            return refuse("a recovery consent carries no IP, port or flags");
                        }
                    }
                    _ => return refuse("kinds 2 and 3 need an action: elect or recover"),
                }
            }
        }
        Ok(())
    }
}

/// The node's `ip_ok` for a validator address: the refusal, or `None`.
#[must_use]
pub fn ip_refusal(ip: &[u8; 4], port: u16) -> Option<&'static str> {
    let [a, b, _, _] = *ip;
    if port == 0 {
        return Some("the port is zero");
    }
    match (a, b) {
        (0, _) => Some("0.0.0.0/8 is refused by the node"),
        (10, _) => Some("10.0.0.0/8 is refused by the node"),
        (127, _) => Some("127.0.0.0/8 is refused by the node"),
        (224..=255, _) => Some("224.0.0.0/3 is refused by the node"),
        (100, b) if b & 0xc0 == 64 => Some("100.64.0.0/10 is refused by the node"),
        (169, 254) => Some("169.254.0.0/16 is refused by the node"),
        (172, b) if b & 0xf0 == 16 => Some("172.16.0.0/12 is refused by the node"),
        (192, 168) => Some("192.168.0.0/16 is refused by the node"),
        _ => None,
    }
}
