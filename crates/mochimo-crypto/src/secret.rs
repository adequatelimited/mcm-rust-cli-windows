// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

use core::fmt;

use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Key material. Zeroed on drop, and never printable.
///
/// There is no `Display`, no `AsRef<[u8]>`, and `Debug` prints only a
/// redacted placeholder, so a derived `Debug` on a containing struct cannot
/// leak the bytes. Reading the bytes requires the named method
/// [`Secret::expose`].
///
/// There is no `PartialEq`: a derived comparison is variable-time. Secrets
/// are compared only in constant time through `subtle::ConstantTimeEq`.
pub struct Secret<const N: usize>(Zeroizing<[u8; N]>);

impl<const N: usize> Secret<N> {
    /// Wraps `bytes`.
    pub fn new(bytes: [u8; N]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Copies `bytes` into a new secret.
    ///
    /// # Errors
    ///
    /// [`Error::Length`] if `bytes` is not exactly `N` bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; N] = bytes.try_into().map_err(|_| Error::Length {
            what: "secret",
            expected: N,
            got: bytes.len(),
        })?;
        Ok(Self::new(arr))
    }

    /// Borrow the raw bytes. Named to be conspicuous at the call site.
    pub fn expose(&self) -> &[u8; N] {
        &self.0
    }

    /// A second `Secret` holding the same bytes.
    ///
    /// Used instead of `Clone` so that copying key material is explicit and
    /// easy to find. Both copies zeroize on drop, but the copy is a second
    /// live copy of the key material while it is held.
    pub fn duplicate(&self) -> Secret<N> {
        Secret::new(*self.0)
    }

    /// The length in bytes, `N`.
    pub const fn len(&self) -> usize {
        N
    }

    /// Whether `N` is zero.
    pub const fn is_empty(&self) -> bool {
        N == 0
    }

    /// Constant-time equality through `subtle::ConstantTimeEq`. Used to
    /// refuse storing the same key stream twice (`Keystore::add`,
    /// `sign_spend`), since two accounts over one key stream would let a key
    /// sign twice.
    pub(crate) fn ct_eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.0[..].ct_eq(&other.0[..]).into()
    }
}

impl<const N: usize> fmt::Debug for Secret<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret<{N}>(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::Secret;

    #[test]
    fn debug_never_reveals_bytes() {
        let s = Secret::new([0xABu8; 4]);
        let rendered = format!("{s:?}");
        assert_eq!(rendered, "Secret<4>(<redacted>)");
        assert!(!rendered.contains("ab") && !rendered.contains("AB"));
    }
}
