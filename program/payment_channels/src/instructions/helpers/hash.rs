//! Blake3 hashing.
//!
//! Computes the digest with the userspace `blake3` crate on every target.
//! The `sol_blake3` syscall (feature `HTW2pSyErTj4BV6KBM9NZ9VBUJVxt7sacNWcf76wtzb3`)
//! is inactive on devnet/testnet/mainnet, so we compute it in userspace.
//! This should be refactored to use on-chain precompile when the feature lands.

/// Blake3 digest of `input`. Single source of truth for `open` and `distribute`.
#[inline]
pub fn blake3(input: &[u8]) -> [u8; 32] {
    ::blake3::hash(input).into()
}
