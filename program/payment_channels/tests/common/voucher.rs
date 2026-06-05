//! Voucher + Ed25519 precompile helpers shared across litesvm-driven tests.
//!
//! The on-chain `VoucherArgs` field order
//! (`channel_id || cumulative_amount || expires_at || chain_id`) matches the
//! Ed25519-signed payload byte-for-byte, so the client's Borsh output IS
//! the message the precompile must verify.

use payment_channels::VOUCHER_PAYLOAD_SIZE;
use payment_channels::ed25519;
use payment_channels_client::types::VoucherArgs;
use solana_instruction::Instruction;
use solana_pubkey::Pubkey;

use super::ed25519_program_id;

/// This cluster's [`CHAIN_ID`](payment_channels::CHAIN_ID) as the client
/// `Address`/`Pubkey` type. Every voucher fixture must carry it, or the on-chain
/// chain-binding check rejects the voucher. The program under test is built with
/// the default `localnet` feature, so this is the localnet placeholder.
pub const TEST_CHAIN_ID: Pubkey = Pubkey::new_from_array(*payment_channels::CHAIN_ID.as_array());

/// Borsh-serialize a voucher into the byte string the Ed25519 precompile
/// must verify.
pub fn voucher_payload(voucher: &VoucherArgs) -> [u8; VOUCHER_PAYLOAD_SIZE] {
    borsh::to_vec(voucher)
        .expect("voucher borsh encoding")
        .try_into()
        .expect("voucher payload matches VOUCHER_PAYLOAD_SIZE")
}

/// Canonical single-signature Ed25519 precompile ix with all
/// `*_instruction_index` fields pinned to `u16::MAX` so the precompile reads
/// pubkey/signature/message from this ix's own data.
pub fn build_ed25519_ix(
    pubkey: &[u8; ed25519::PUBKEY_SERIALIZED_SIZE],
    signature: &[u8; ed25519::SIGNATURE_SERIALIZED_SIZE],
    message: &[u8; VOUCHER_PAYLOAD_SIZE],
) -> Instruction {
    let mut data = Vec::with_capacity(ed25519::MESSAGE_OFFSET + VOUCHER_PAYLOAD_SIZE);
    data.push(1u8); // num_signatures
    data.push(0u8); // padding
    data.extend_from_slice(&(ed25519::SIGNATURE_OFFSET as u16).to_le_bytes());
    data.extend_from_slice(&u16::MAX.to_le_bytes()); // signature_instruction_index
    data.extend_from_slice(&(ed25519::PUBKEY_OFFSET as u16).to_le_bytes());
    data.extend_from_slice(&u16::MAX.to_le_bytes()); // public_key_instruction_index
    data.extend_from_slice(&(ed25519::MESSAGE_OFFSET as u16).to_le_bytes());
    data.extend_from_slice(&(VOUCHER_PAYLOAD_SIZE as u16).to_le_bytes());
    data.extend_from_slice(&u16::MAX.to_le_bytes()); // message_instruction_index
    data.extend_from_slice(pubkey);
    data.extend_from_slice(signature);
    data.extend_from_slice(message);
    Instruction {
        program_id: ed25519_program_id(),
        accounts: Vec::new(),
        data,
    }
}
