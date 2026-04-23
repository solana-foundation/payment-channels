//! End-to-end validation of `settle` against the compiled .so.

#![allow(clippy::result_large_err)]

use std::str::FromStr;

use litesvm::LiteSVM;
use payment_channels::PaymentChannelsError;
use payment_channels_client::instructions::{Settle, SettleInstructionArgs};
use payment_channels_client::types::{SettleArgs, VoucherArgs};
use solana_account::Account;
use solana_instruction::Instruction;
use solana_instruction::error::InstructionError;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;

mod common;
use common::{PROGRAM_ID, load_program};

fn instructions_sysvar_id() -> Pubkey {
    Pubkey::from_str("Sysvar1nstructions1111111111111111111111111").unwrap()
}

fn ed25519_program_id() -> Pubkey {
    Pubkey::from_str("Ed25519SigVerify111111111111111111111111111").unwrap()
}

/// Seed a `Channel` PDA (208-byte `#[repr(C, packed)]` layout) owned by the
/// program. Only the fields `settle` reads are non-zero.
fn seed_channel(
    svm: &mut LiteSVM,
    channel: &Pubkey,
    status: u8,
    deposit: u64,
    settled: u64,
    authorized_signer: &Pubkey,
) {
    let mut data = vec![0u8; 208];
    data[0] = 1; // AccountDiscriminator::Channel
    data[1] = 1; // CURRENT_CHANNEL_VERSION
    data[3] = status;
    data[4..12].copy_from_slice(&deposit.to_le_bytes());
    data[12..20].copy_from_slice(&settled.to_le_bytes());
    data[144..176].copy_from_slice(&authorized_signer.to_bytes());

    svm.set_account(
        *channel,
        Account {
            lamports: 10_000_000,
            data,
            owner: PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        },
    )
    .expect("set_account");
}

/// Borsh-serialize the client `VoucherArgs`. The on-chain struct's field
/// order (`channel_id || cumulative_amount || expires_at`) matches the
/// ed25519-signed payload byte-for-byte, so the client's Borsh output IS
/// the message the precompile must verify.
fn voucher_payload(voucher: &VoucherArgs) -> [u8; 48] {
    borsh::to_vec(voucher)
        .expect("voucher borsh encoding")
        .try_into()
        .expect("48-byte voucher payload")
}

/// Canonical single-signature inline Ed25519 precompile ix:
/// `[num_sigs=1, pad=0, offsets×1, pubkey, signature, message]`; all three
/// `*_instruction_index` fields pinned to `u16::MAX` so the precompile reads
/// from this ix's own data.
fn build_ed25519_ix(pubkey: &[u8; 32], signature: &[u8; 64], message: &[u8; 48]) -> Instruction {
    let mut data = Vec::with_capacity(160);
    data.push(1u8); // num_signatures
    data.push(0u8); // padding

    let header_len: u16 = 2 + 14;
    let pubkey_offset = header_len;
    let signature_offset = pubkey_offset + 32;
    let message_offset = signature_offset + 64;
    let message_size: u16 = 48;

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

fn build_settle_ix(channel: &Pubkey, voucher: VoucherArgs) -> Instruction {
    Settle {
        channel: *channel,
        instructions_sysvar: instructions_sysvar_id(),
    }
    .instruction(SettleInstructionArgs {
        settle_args: SettleArgs { voucher },
    })
}

fn read_settled(svm: &LiteSVM, channel: &Pubkey) -> u64 {
    let acct = svm.get_account(channel).expect("channel exists");
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&acct.data[12..20]);
    u64::from_le_bytes(buf)
}

fn expect_custom_err(
    res: Result<litesvm::types::TransactionMetadata, litesvm::types::FailedTransactionMetadata>,
    expected: PaymentChannelsError,
) {
    let err = res.expect_err("tx should fail");
    match err.err {
        TransactionError::InstructionError(_, InstructionError::Custom(code)) => {
            assert_eq!(code, expected as u32, "wrong custom error code");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn settle_advances_watermark_on_valid_voucher() {
    let mut svm = load_program();
    let fee_payer = Keypair::new();
    svm.airdrop(&fee_payer.pubkey(), 10_000_000_000).unwrap();

    let signer = Keypair::new();
    let channel = Pubkey::new_unique();
    seed_channel(&mut svm, &channel, 0, 1_000_000, 0, &signer.pubkey());

    let cumulative = 500_000u64;
    let voucher = VoucherArgs {
        channel_id: channel,
        cumulative_amount: cumulative,
        expires_at: 0,
    };
    let payload = voucher_payload(&voucher);
    let signature: [u8; 64] = signer.sign_message(&payload).into();
    let pubkey = signer.pubkey().to_bytes();

    let ed25519_ix = build_ed25519_ix(&pubkey, &signature, &payload);
    let settle_ix = build_settle_ix(&channel, voucher);

    let msg = Message::new(&[ed25519_ix, settle_ix], Some(&fee_payer.pubkey()));
    let tx = Transaction::new(&[&fee_payer], msg, svm.latest_blockhash());
    svm.send_transaction(tx).expect("tx ok");

    assert_eq!(read_settled(&svm, &channel), cumulative);
}

#[test]
fn settle_without_preceding_ed25519_ix_rejects() {
    let mut svm = load_program();
    let fee_payer = Keypair::new();
    svm.airdrop(&fee_payer.pubkey(), 10_000_000_000).unwrap();

    let signer = Keypair::new();
    let channel = Pubkey::new_unique();
    seed_channel(&mut svm, &channel, 0, 1_000_000, 0, &signer.pubkey());

    let settle_ix = build_settle_ix(
        &channel,
        VoucherArgs {
            channel_id: channel,
            cumulative_amount: 500_000,
            expires_at: 0,
        },
    );

    let msg = Message::new(&[settle_ix], Some(&fee_payer.pubkey()));
    let tx = Transaction::new(&[&fee_payer], msg, svm.latest_blockhash());
    expect_custom_err(
        svm.send_transaction(tx),
        PaymentChannelsError::MissingEd25519Verification,
    );
}

#[test]
fn settle_on_non_open_status_rejects() {
    let mut svm = load_program();
    let fee_payer = Keypair::new();
    svm.airdrop(&fee_payer.pubkey(), 10_000_000_000).unwrap();

    let signer = Keypair::new();
    let channel = Pubkey::new_unique();
    // status = 1 (Finalized)
    seed_channel(&mut svm, &channel, 1, 1_000_000, 0, &signer.pubkey());

    let cumulative = 500_000u64;
    let voucher = VoucherArgs {
        channel_id: channel,
        cumulative_amount: cumulative,
        expires_at: 0,
    };
    let payload = voucher_payload(&voucher);
    let signature: [u8; 64] = signer.sign_message(&payload).into();
    let pubkey = signer.pubkey().to_bytes();

    let ed25519_ix = build_ed25519_ix(&pubkey, &signature, &payload);
    let settle_ix = build_settle_ix(&channel, voucher);

    let msg = Message::new(&[ed25519_ix, settle_ix], Some(&fee_payer.pubkey()));
    let tx = Transaction::new(&[&fee_payer], msg, svm.latest_blockhash());
    expect_custom_err(
        svm.send_transaction(tx),
        PaymentChannelsError::InvalidChannelStatus,
    );
}
