//! Ed25519 precompile layout constants.
//!
//! Byte widths, offsets record position, and canonical inline-ix region
//! offsets for the native `Ed25519SigVerify` program. Sourced from the
//! Solana precompile spec; names mirror the `solana_sdk::ed25519_program`
//! module so off-chain callers and on-chain consumers share a vocabulary.
//!
//! https://solana.com/docs/core/programs/precompiles#verify-ed25519-signature

use pinocchio::Address;

/// Native program address of the `Ed25519SigVerify` precompile.
pub const PROGRAM_ID: Address =
    Address::from_str_const("Ed25519SigVerify111111111111111111111111111");

/// Ed25519 pubkey byte width.
pub const PUBKEY_SERIALIZED_SIZE: usize = 32;

/// Ed25519 signature byte width.
pub const SIGNATURE_SERIALIZED_SIZE: usize = 64;

/// Byte position of the `Ed25519SignatureOffsets` array — sits immediately
/// after the `[num_signatures: u8, padding: u8]` header.
pub const SIGNATURE_OFFSETS_START: usize = 2;

/// Byte width of one `Ed25519SignatureOffsets` record: seven little-endian
/// `u16` fields, in order — `signature_offset`, `signature_instruction_index`,
/// `public_key_offset`, `public_key_instruction_index`, `message_data_offset`,
/// `message_data_size`, `message_instruction_index`.
pub const SIGNATURE_OFFSETS_SERIALIZED_SIZE: usize = 14;

/// Canonical byte offset of the pubkey region in a single-signature inline
/// ix (= 16): first byte after the two-byte header plus one offsets record.
pub const PUBKEY_OFFSET: usize = SIGNATURE_OFFSETS_START + SIGNATURE_OFFSETS_SERIALIZED_SIZE;

/// Canonical byte offset of the signature region (= 48): pubkey region
/// immediately followed by the 64-byte signature.
pub const SIGNATURE_OFFSET: usize = PUBKEY_OFFSET + PUBKEY_SERIALIZED_SIZE;

/// Canonical byte offset of the message payload (= 112): signature region
/// immediately followed by the message. Length comes from the
/// `message_data_size` field in the offsets record.
pub const MESSAGE_OFFSET: usize = SIGNATURE_OFFSET + SIGNATURE_SERIALIZED_SIZE;
