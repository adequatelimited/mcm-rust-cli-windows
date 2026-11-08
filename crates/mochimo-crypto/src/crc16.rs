// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! CRC-16, the reference's `crc16()`.
//!
//! CRC-16/XMODEM: poly `0x1021`, init `0x0000`, no reflection, xorout
//! `0x0000`. Fixture group E checks it against values measured from the
//! reference.

use crate::backend::selected as backend;

/// The CRC-16/XMODEM checksum of `input`.
pub fn crc16(input: &[u8]) -> u16 {
    backend::crc16(input)
}
