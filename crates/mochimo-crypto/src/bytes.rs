// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! Little-endian integer accessors, matching the reference's `get16`,
//! `put16`, `get32` and `put32`.
//!
//! Every multi-byte field on the Mochimo wire is little-endian.

use crate::backend::selected as backend;

/// Reads a little-endian `u16`.
pub fn get16(bytes: &[u8; 2]) -> u16 {
    backend::get16(bytes)
}

/// Writes `value` as a little-endian `u16`.
pub fn put16(value: u16) -> [u8; 2] {
    backend::put16(value)
}

/// Reads a little-endian `u32`.
pub fn get32(bytes: &[u8; 4]) -> u32 {
    backend::get32(bytes)
}

/// Writes `value` as a little-endian `u32`.
pub fn put32(value: u32) -> [u8; 4] {
    backend::put32(value)
}
