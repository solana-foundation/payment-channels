//! Ed25519 precompile ix parser.
//!
//! Validates the canonical single-signature inline layout and returns
//! borrowed slices into the caller's bytes. Primitive-typed and free of
//! pinocchio / solana-* deps so an SDK can vendor this file verbatim
//! and reconstruct the same bytes an on-chain verify would accept.
//!
//! All magic constants and layouts are sourced from the official Solana
//! documentation: <https://solana.com/docs/core/programs/precompiles#verify-ed25519-signature>.

use crate::voucher_payload::VOUCHER_PAYLOAD_SIZE;

/// Native program address of the Ed25519SigVerify precompile.
pub const ED25519_PROGRAM_ID: [u8; 32] =
    const_crypto::bs58::decode_pubkey("Ed25519SigVerify111111111111111111111111111");

/// Ed25519 pubkey byte width.
const PUBKEY_SERIALIZED_SIZE: usize = 32;

/// Ed25519 signature byte width.
const SIGNATURE_SERIALIZED_SIZE: usize = 64;

/// Byte position of the `Ed25519SignatureOffsets` array — sits
/// immediately after the `[num_signatures: u8, padding: u8]` header.
const SIGNATURE_OFFSETS_START: usize = 2;

/// Byte width of one `Ed25519SignatureOffsets` record: seven
/// little-endian `u16` fields, in order — `signature_offset`,
/// `signature_instruction_index`, `public_key_offset`,
/// `public_key_instruction_index`, `message_data_offset`,
/// `message_data_size`, `message_instruction_index`.
const SIGNATURE_OFFSETS_SERIALIZED_SIZE: usize = 14;

/// Canonical byte offset of the pubkey region in a single-signature
/// inline ix (= 16): the first byte after the two-byte header plus one
/// offsets record.
const PUBKEY_OFFSET: usize = SIGNATURE_OFFSETS_START + SIGNATURE_OFFSETS_SERIALIZED_SIZE;

/// Canonical byte offset of the signature region (= 48): pubkey region
/// immediately followed by the 64-byte signature.
const SIGNATURE_OFFSET: usize = PUBKEY_OFFSET + PUBKEY_SERIALIZED_SIZE;

/// Canonical byte offset of the message payload (= 112): signature
/// region immediately followed by the message. Message length is taken
/// from `message_data_size` (offsets[10..12]).
const MESSAGE_OFFSET: usize = SIGNATURE_OFFSET + SIGNATURE_SERIALIZED_SIZE;

/// Canonical inline ix data length.
const CANONICAL_IX_DATA_LEN: usize = MESSAGE_OFFSET + VOUCHER_PAYLOAD_SIZE;

/// Parsed Ed25519 precompile ix data.
pub struct Parsed<'a> {
    /// Ed25519 pubkey (32 bytes).
    pub pubkey: &'a [u8; PUBKEY_SERIALIZED_SIZE],
    /// Ed25519 message (`VOUCHER_PAYLOAD_SIZE` bytes).
    pub message: &'a [u8; VOUCHER_PAYLOAD_SIZE],
}

/// Structural rejection reasons for `parse`. Every variant maps 1:1 to
/// a guard below; callers that only need a binary outcome can collapse
/// with `.is_err()`, while an SDK can surface specific failure modes.
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
        .unwrap();
    let message: &[u8; VOUCHER_PAYLOAD_SIZE] = data
        [MESSAGE_OFFSET..MESSAGE_OFFSET + VOUCHER_PAYLOAD_SIZE]
        .try_into()
        .unwrap();

    Ok(Parsed { pubkey, message })
}

#[cfg(test)]
mod tests {
    use pinocchio::Address;

    use super::*;

    /// Round-trip: the hand-hardcoded-via-const_crypto bytes must match
    /// what pinocchio's base58 const decoder produces for the same
    /// Ed25519SigVerify literal. Catches any typo or decoder mismatch
    /// at build time.
    #[test]
    fn ed25519_program_id_matches_address_const_decode() {
        const VIA_ADDRESS: Address =
            Address::from_str_const("Ed25519SigVerify111111111111111111111111111");
        assert_eq!(&ED25519_PROGRAM_ID, VIA_ADDRESS.as_array());
    }
}
