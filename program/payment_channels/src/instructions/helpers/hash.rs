//! Blake3 hashing for distribution commitments.

/// Blake3 digest of `input`. Single source of truth for `open` and `distribute`.
///
/// Uses the bundled implementation instead of the Solana syscall so the
/// program can run on Surfnet runtimes that do not expose `sol_blake3`.
#[inline]
pub fn blake3(input: &[u8]) -> [u8; 32] {
    ::blake3::hash(input).into()
}
