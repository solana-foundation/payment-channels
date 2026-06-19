//! Ed25519 precompile ix parser.
//!
//! Validates the canonical single-signature inline layout and returns
//! borrowed slices into the caller's bytes. Layout constants live in
//! the sibling `consts` submodule; those names are sourced from the
//! official Solana documentation:
//! <https://solana.com/docs/core/programs/precompiles#verify-ed25519-signature>.

use super::{
    MESSAGE_OFFSET, PUBKEY_OFFSET, PUBKEY_SERIALIZED_SIZE, SIGNATURE_OFFSET,
    SIGNATURE_OFFSETS_START,
};
use crate::instructions::VOUCHER_PAYLOAD_SIZE;

/// Canonical inline ix data length.
const CANONICAL_IX_DATA_LEN: usize = MESSAGE_OFFSET + VOUCHER_PAYLOAD_SIZE;

/// Parsed Ed25519 precompile ix data. Sized-array refs let the caller
/// compare against `[u8; 32]` / `[u8; 80]` fixtures without slice-length
/// runtime checks.
pub struct Parsed<'a> {
    pub pubkey: &'a [u8; PUBKEY_SERIALIZED_SIZE],
    pub message: &'a [u8; VOUCHER_PAYLOAD_SIZE],
}

/// Structural rejection reasons for `parse`. Every variant maps 1:1 to
/// a guard below; the enum exists so the test suite can pin which
/// guard fires on each malformed input, catching accidental merging
/// or removal of guards during refactors. Collapsed to a single
/// [`PaymentChannelsError::MalformedEd25519Instruction`] at the caller
/// edge, so on-chain error codes are unaffected.
///
/// [`PaymentChannelsError::MalformedEd25519Instruction`]:
///     crate::errors::PaymentChannelsError::MalformedEd25519Instruction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ed25519ParseError {
    /// `data.len() != CANONICAL_IX_DATA_LEN (= 160)`.
    Length,
    /// `num_signatures != 1`. N = 0 verifies nothing; N > 1 appends
    /// further offsets records whose signatures we never parse, so the
    /// surrounding ix could appear "verified" while those riders covered
    /// arbitrary attacker-chosen bytes.
    NumSignatures,
    /// Header padding byte is non-zero.
    Padding,
    /// One of the three `*_instruction_index` fields is not `u16::MAX`;
    /// the precompile would read from a sibling ix instead of this one.
    CrossInstruction,
    /// `signature_offset`, `public_key_offset`, or `message_data_offset`
    /// doesn't match the canonical single-signature inline layout. The
    /// precompile accepts any in-bounds offsets; without this pin a
    /// non-canonical layout could verify cryptographically while our
    /// hardcoded slices land on different bytes than the precompile
    /// checked.
    NonCanonicalOffsets,
    /// `message_data_size != VOUCHER_PAYLOAD_SIZE (= 48)`.
    MessageSize,
}

/// Parse a single-signature Ed25519 precompile ix with the canonical
/// inline layout. Validates every field of `Ed25519SignatureOffsets`.
pub fn parse(data: &[u8]) -> Result<Parsed<'_>, Ed25519ParseError> {
    // Full canonical inline layout: `[num_sigs=1, pad=0, offsets×1, pubkey, signature, message]`.
    // Guard — length. Pins the full 160-byte canonical layout.
    if data.len() != CANONICAL_IX_DATA_LEN {
        return Err(Ed25519ParseError::Length);
    }

    // Guard — `num_signatures == 1`. N = 0 verifies nothing; N > 1
    // appends further offsets records whose signatures we never parse,
    // so the surrounding ix could appear "verified" while those riders
    // covered arbitrary attacker-chosen bytes.
    if data[0] != 1 {
        return Err(Ed25519ParseError::NumSignatures);
    }

    // Guard — padding byte is zero.
    if data[1] != 0 {
        return Err(Ed25519ParseError::Padding);
    }

    // Read the offset fields.
    let offsets = &data[SIGNATURE_OFFSETS_START..PUBKEY_OFFSET];

    let read = |i: usize| u16::from_le_bytes([offsets[i], offsets[i + 1]]);
    let signature_offset = read(0);
    let sig_ix = read(2);
    let public_key_offset = read(4);
    let pk_ix = read(6);
    let message_data_offset = read(8);
    let message_data_size = read(10);
    let msg_ix = read(12);

    // Guard — cross-instruction indirection.
    // Native sentinel to force the precompile to read from our ix.
    if sig_ix != u16::MAX || pk_ix != u16::MAX || msg_ix != u16::MAX {
        return Err(Ed25519ParseError::CrossInstruction);
    }

    // Guard — canonical byte offsets. The precompile accepts any
    // in-bounds offsets, so without these pins a non-canonical layout
    // could verify cryptographically while our hardcoded
    // `data[16..48]` / `data[48..112]` reads land on different bytes
    // than the precompile checked. Payload-match downstream would
    // still catch the bypass (unless the signer explicitly signed the
    // wrong-position bytes), but pinning here keeps slice bounds
    // compile-time constant and narrows the off-chain signer contract
    // to one wire encoding.
    if public_key_offset as usize != PUBKEY_OFFSET
        || signature_offset as usize != SIGNATURE_OFFSET
        || message_data_offset as usize != MESSAGE_OFFSET
    {
        return Err(Ed25519ParseError::NonCanonicalOffsets);
    }

    // Guard — canonical message length (48 B: `channel_id ||
    // cumulative_amount || expires_at`, LE).
    if message_data_size as usize != VOUCHER_PAYLOAD_SIZE {
        return Err(Ed25519ParseError::MessageSize);
    }

    // Bounds are compile-time constant thanks to the length + offset
    // guards above, so slice → array references are infallible.
    let pubkey: &[u8; PUBKEY_SERIALIZED_SIZE] = data
        [PUBKEY_OFFSET..PUBKEY_OFFSET + PUBKEY_SERIALIZED_SIZE]
        .try_into()
        .expect("length + offset guards pin the canonical pubkey region");
    let message: &[u8; VOUCHER_PAYLOAD_SIZE] = data
        [MESSAGE_OFFSET..MESSAGE_OFFSET + VOUCHER_PAYLOAD_SIZE]
        .try_into()
        .expect("length + offset guards pin the canonical message region");

    Ok(Parsed { pubkey, message })
}
