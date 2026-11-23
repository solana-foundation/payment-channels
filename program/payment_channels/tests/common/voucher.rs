//! Voucher + Ed25519 precompile helpers shared across litesvm-driven tests.
//!
//! The on-chain `VoucherArgs` field order
//! (`magic || channel_id || cumulative_amount || expires_at`)
//! matches the Ed25519-signed payload byte-for-byte, so the client's Borsh
//! output IS the message the precompile must verify.
//!
//! There is no epoch field: `open_slot` is a channel PDA seed, so
//! `channel_id` alone pins the exact incarnation the voucher pays into.

use payment_channels::ed25519;
use payment_channels::{
    CAP_VOUCHER_PAYLOAD_SIZE, CLAIM_VOUCHER_PAYLOAD_SIZE, CapVoucherArgs, ClaimVoucherArgs,
    Transmutable, VOUCHER_MAGIC, VOUCHER_PAYLOAD_SIZE,
};
use payment_channels_client::types::VoucherArgs;
use pinocchio::Address;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;

use super::ed25519_program_id;

/// Convenience constructor: fills the domain magic so call sites only carry
/// the semantic fields.
pub fn voucher(channel_id: Pubkey, cumulative_amount: u64, expires_at: i64) -> VoucherArgs {
    VoucherArgs {
        magic: VOUCHER_MAGIC,
        channel_id,
        cumulative_amount,
        expires_at,
    }
}

/// Borsh-serialize a voucher into the byte string the Ed25519 precompile
/// must verify.
pub fn voucher_payload(voucher: &VoucherArgs) -> [u8; VOUCHER_PAYLOAD_SIZE] {
    borsh::to_vec(voucher)
        .expect("voucher borsh encoding")
        .try_into()
        .expect("voucher payload matches VOUCHER_PAYLOAD_SIZE")
}

fn address(pubkey: &Pubkey) -> Address {
    Address::new_from_array(pubkey.to_bytes())
}

/// 82-byte signed cap: `magic(0x56 0x03) || channel_id || cap_cumulative ||
/// expires_at || operator`.
pub fn cap_voucher_payload(
    channel_id: &Pubkey,
    cap_cumulative: u64,
    expires_at: i64,
    operator: &Pubkey,
) -> [u8; CAP_VOUCHER_PAYLOAD_SIZE] {
    let voucher = CapVoucherArgs::new(
        address(channel_id),
        cap_cumulative,
        expires_at,
        address(operator),
    );
    voucher
        .as_bytes()
        .try_into()
        .expect("cap voucher payload size")
}

/// 50-byte signed claim: `magic(0x56 0x04) || channel_id || claim_cumulative ||
/// expires_at`.
pub fn claim_voucher_payload(
    channel_id: &Pubkey,
    claim_cumulative: u64,
    expires_at: i64,
) -> [u8; CLAIM_VOUCHER_PAYLOAD_SIZE] {
    let voucher = ClaimVoucherArgs::new(address(channel_id), claim_cumulative, expires_at);
    voucher
        .as_bytes()
        .try_into()
        .expect("claim voucher payload size")
}

/// `(ed25519(cap), ed25519(claim))`: the cap signed by `client`, naming
/// `operator`; the claim signed by `operator`. Bundle both, cap first,
/// immediately before the metered instruction.
pub fn build_metered_pair(
    channel_id: &Pubkey,
    client: &Keypair,
    operator: &Keypair,
    cap_cumulative: u64,
    claim_cumulative: u64,
    expires_at: i64,
) -> (Instruction, Instruction) {
    (
        signed_cap_ix(
            client,
            channel_id,
            cap_cumulative,
            expires_at,
            &operator.pubkey(),
        ),
        signed_claim_ix(operator, channel_id, claim_cumulative, expires_at),
    )
}

/// Cap precompile ix with every field and the signer chosen by the caller.
pub fn signed_cap_ix(
    signer: &Keypair,
    channel_id: &Pubkey,
    cap_cumulative: u64,
    expires_at: i64,
    operator: &Pubkey,
) -> Instruction {
    let cap = cap_voucher_payload(channel_id, cap_cumulative, expires_at, operator);
    signed_ed25519_ix(signer, &cap)
}

/// Claim precompile ix with every field and the signer chosen by the caller.
pub fn signed_claim_ix(
    signer: &Keypair,
    channel_id: &Pubkey,
    claim_cumulative: u64,
    expires_at: i64,
) -> Instruction {
    let claim = claim_voucher_payload(channel_id, claim_cumulative, expires_at);
    signed_ed25519_ix(signer, &claim)
}

/// Canonical precompile ix over `message`, signed by `signer`.
pub fn signed_ed25519_ix(signer: &Keypair, message: &[u8]) -> Instruction {
    let signature: [u8; 64] = signer.sign_message(message).into();
    build_ed25519_ix_for_message(&signer.pubkey().to_bytes(), &signature, message)
}

/// Canonical single-signature Ed25519 precompile ix with all
/// `*_instruction_index` fields pinned to `u16::MAX` so the precompile reads
/// pubkey/signature/message from this ix's own data.
pub fn build_ed25519_ix(
    pubkey: &[u8; ed25519::PUBKEY_SERIALIZED_SIZE],
    signature: &[u8; ed25519::SIGNATURE_SERIALIZED_SIZE],
    message: &[u8; VOUCHER_PAYLOAD_SIZE],
) -> Instruction {
    build_ed25519_ix_for_message(pubkey, signature, message)
}

/// Same canonical layout as [`build_ed25519_ix`], for a signed message whose
/// length is not [`VOUCHER_PAYLOAD_SIZE`].
pub fn build_ed25519_ix_for_message(
    pubkey: &[u8; ed25519::PUBKEY_SERIALIZED_SIZE],
    signature: &[u8; ed25519::SIGNATURE_SERIALIZED_SIZE],
    message: &[u8],
) -> Instruction {
    let message_size = u16::try_from(message.len()).expect("ed25519 message length fits u16");
    let mut data = Vec::with_capacity(ed25519::MESSAGE_OFFSET + message.len());
    data.push(1u8); // num_signatures
    data.push(0u8); // padding
    data.extend_from_slice(&(ed25519::SIGNATURE_OFFSET as u16).to_le_bytes());
    data.extend_from_slice(&u16::MAX.to_le_bytes()); // signature_instruction_index
    data.extend_from_slice(&(ed25519::PUBKEY_OFFSET as u16).to_le_bytes());
    data.extend_from_slice(&u16::MAX.to_le_bytes()); // public_key_instruction_index
    data.extend_from_slice(&(ed25519::MESSAGE_OFFSET as u16).to_le_bytes());
    data.extend_from_slice(&message_size.to_le_bytes());
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
