//! Shared `settle` instruction helpers reused across multiple test binaries.
//!
//! Lifted out of `tests/settle_e2e.rs` so other suites (e.g. `distribute`)
//! can advance the `Channel::settled` watermark through the Ed25519
//! precompile + settle bundle.

#![allow(dead_code)]

use std::str::FromStr;

use litesvm::LiteSVM;
use payment_channels::VOUCHER_PAYLOAD_SIZE;
use payment_channels::ed25519;
use payment_channels_client::instructions::{Settle, SettleInstructionArgs};
use payment_channels_client::types::{SettleArgs, VoucherArgs};
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

pub fn instructions_sysvar_id() -> Pubkey {
    Pubkey::from_str("Sysvar1nstructions1111111111111111111111111").unwrap()
}

pub fn ed25519_program_id() -> Pubkey {
    Pubkey::new_from_array(*ed25519::PROGRAM_ID.as_array())
}

/// Borsh-serialize the client `VoucherArgs`. The on-chain struct's field
/// order (`channel_id || cumulative_amount || expires_at`) matches the
/// ed25519-signed payload byte-for-byte, so the client's Borsh output IS
/// the message the precompile must verify.
pub fn voucher_payload(voucher: &VoucherArgs) -> [u8; VOUCHER_PAYLOAD_SIZE] {
    borsh::to_vec(voucher)
        .expect("voucher borsh encoding")
        .try_into()
        .expect("voucher payload matches VOUCHER_PAYLOAD_SIZE")
}

/// Canonical single-signature inline Ed25519 precompile ix:
/// `[num_sigs=1, pad=0, offsets×1, pubkey, signature, message]`; all three
/// `*_instruction_index` fields pinned to `u16::MAX` so the precompile reads
/// from this ix's own data.
pub fn build_ed25519_ix(
    pubkey: &[u8; ed25519::PUBKEY_SERIALIZED_SIZE],
    signature: &[u8; ed25519::SIGNATURE_SERIALIZED_SIZE],
    message: &[u8; VOUCHER_PAYLOAD_SIZE],
) -> Instruction {
    let mut data = Vec::with_capacity(ed25519::MESSAGE_OFFSET + VOUCHER_PAYLOAD_SIZE);
    data.push(1u8);
    data.push(0u8);

    let pubkey_offset = ed25519::PUBKEY_OFFSET as u16;
    let signature_offset = ed25519::SIGNATURE_OFFSET as u16;
    let message_offset = ed25519::MESSAGE_OFFSET as u16;
    let message_size = VOUCHER_PAYLOAD_SIZE as u16;

    data.extend_from_slice(&signature_offset.to_le_bytes());
    data.extend_from_slice(&u16::MAX.to_le_bytes());
    data.extend_from_slice(&pubkey_offset.to_le_bytes());
    data.extend_from_slice(&u16::MAX.to_le_bytes());
    data.extend_from_slice(&message_offset.to_le_bytes());
    data.extend_from_slice(&message_size.to_le_bytes());
    data.extend_from_slice(&u16::MAX.to_le_bytes());

    data.extend_from_slice(pubkey);
    data.extend_from_slice(signature);
    data.extend_from_slice(message);

    Instruction {
        program_id: ed25519_program_id(),
        accounts: Vec::new(),
        data,
    }
}

pub fn build_settle_ix(channel: &Pubkey, voucher: VoucherArgs) -> Instruction {
    Settle {
        channel: *channel,
        instructions_sysvar: instructions_sysvar_id(),
    }
    .instruction(SettleInstructionArgs {
        settle_args: SettleArgs { voucher },
    })
}

/// Sign + bundle + submit `[ed25519_ix, settle_ix]` to advance the channel's
/// `settled` watermark to `cumulative_amount`. Panics if the tx does not
/// succeed — for negative-path settle tests, drive the bundle by hand.
pub fn settle_to(
    svm: &mut LiteSVM,
    fee_payer: &Keypair,
    channel: &Pubkey,
    authorized_signer: &Keypair,
    cumulative_amount: u64,
    expires_at: i64,
) {
    let voucher = VoucherArgs {
        channel_id: *channel,
        cumulative_amount,
        expires_at,
    };
    let payload = voucher_payload(&voucher);
    let signature: [u8; 64] = authorized_signer.sign_message(&payload).into();
    let pubkey = authorized_signer.pubkey().to_bytes();

    let ed25519_ix = build_ed25519_ix(&pubkey, &signature, &payload);
    let settle_ix = build_settle_ix(channel, voucher);

    let tx = Transaction::new_signed_with_payer(
        &[ed25519_ix, settle_ix],
        Some(&fee_payer.pubkey()),
        &[fee_payer],
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).expect("settle should succeed");
}
