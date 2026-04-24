//! Canonical signed-voucher payload bytes.
//!
//! Pure-bytes authority for the 48-byte layout the off-chain signer
//! commits to and the Ed25519 precompile verifies over. Primitive-typed
//! and free of pinocchio / solana-* deps so an SDK can vendor this file
//! verbatim and produce byte-identical payloads without reimplementation.

/// `channel_id (32) || cumulative_amount (8 LE) || expires_at (8 LE)`.
pub const VOUCHER_PAYLOAD_SIZE: usize = 48;

/// Borsh(`Voucher { channel_id, cumulative_amount, expires_at }`).
/// Hand-rolled because the 48-byte layout is part of the off-chain
/// signer contract.
pub fn build_signed_payload(
    channel_id: &[u8; 32],
    cumulative_amount: u64,
    expires_at: i64,
) -> [u8; VOUCHER_PAYLOAD_SIZE] {
    let mut out = [0u8; VOUCHER_PAYLOAD_SIZE];
    out[..32].copy_from_slice(channel_id);
    out[32..40].copy_from_slice(&cumulative_amount.to_le_bytes());
    out[40..48].copy_from_slice(&expires_at.to_le_bytes());
    out
}
