//! End-to-end validation of `settleAndFinalize` against the compiled .so.

#![allow(clippy::result_large_err)]

use std::str::FromStr;

use litesvm::LiteSVM;
use payment_channels::ed25519;
use payment_channels::state::channel::ChannelStatus;
use payment_channels::{PaymentChannelsError, VOUCHER_PAYLOAD_SIZE};
use payment_channels_client::instructions::{SettleAndFinalize, SettleAndFinalizeInstructionArgs};
use payment_channels_client::types::{SettleAndFinalizeArgs, VoucherArgs};
use solana_account::Account;
use solana_clock::Clock;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

use crate::common::{PROGRAM_ID, ProgramLoader, expect_custom_err};

fn instructions_sysvar_id() -> Pubkey {
    Pubkey::from_str("Sysvar1nstructions1111111111111111111111111").unwrap()
}

fn ed25519_program_id() -> Pubkey {
    Pubkey::new_from_array(*ed25519::PROGRAM_ID.as_array())
}

/// Inject a 216-byte Channel owned by PROGRAM_ID.
///
/// Byte offsets (from channel.rs layout):
///  0  discriminator, 1  version, 3  status
/// 12..20 deposit, 20..28 settled, 36..44 closure_started_at, 52..56 grace_period
/// 88..120 payer, 120..152 payee, 152..184 authorized_signer, 184..216 mint
#[allow(clippy::too_many_arguments)]
fn seed_channel(
    svm: &mut LiteSVM,
    channel: &Pubkey,
    status: ChannelStatus,
    deposit: u64,
    settled: u64,
    closure_started_at: i64,
    grace_period: u32,
    payee: &Pubkey,
    authorized_signer: &Pubkey,
) {
    let mut data = vec![0u8; 216];
    data[0] = 1; // AccountDiscriminator::Channel
    data[1] = 1; // CURRENT_CHANNEL_VERSION
    data[3] = status as u8;
    data[12..20].copy_from_slice(&deposit.to_le_bytes());
    data[20..28].copy_from_slice(&settled.to_le_bytes());
    data[36..44].copy_from_slice(&closure_started_at.to_le_bytes());
    data[52..56].copy_from_slice(&grace_period.to_le_bytes());
    data[120..152].copy_from_slice(&payee.to_bytes());
    data[152..184].copy_from_slice(&authorized_signer.to_bytes());
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

fn read_status(svm: &LiteSVM, channel: &Pubkey) -> u8 {
    svm.get_account(channel).expect("channel exists").data[3]
}

fn read_settled(svm: &LiteSVM, channel: &Pubkey) -> u64 {
    let data = svm.get_account(channel).expect("channel exists").data;
    u64::from_le_bytes(data[20..28].try_into().unwrap())
}

fn read_closure_started_at(svm: &LiteSVM, channel: &Pubkey) -> i64 {
    let data = svm.get_account(channel).expect("channel exists").data;
    i64::from_le_bytes(data[36..44].try_into().unwrap())
}

fn voucher_payload(voucher: &VoucherArgs) -> [u8; VOUCHER_PAYLOAD_SIZE] {
    borsh::to_vec(voucher)
        .expect("voucher borsh encoding")
        .try_into()
        .expect("voucher payload matches VOUCHER_PAYLOAD_SIZE")
}

fn build_ed25519_ix(
    pubkey: &[u8; ed25519::PUBKEY_SERIALIZED_SIZE],
    signature: &[u8; ed25519::SIGNATURE_SERIALIZED_SIZE],
    message: &[u8; VOUCHER_PAYLOAD_SIZE],
) -> Instruction {
    let mut data = Vec::with_capacity(ed25519::MESSAGE_OFFSET + VOUCHER_PAYLOAD_SIZE);
    data.push(1u8);
    data.push(0u8);
    data.extend_from_slice(&(ed25519::SIGNATURE_OFFSET as u16).to_le_bytes());
    data.extend_from_slice(&u16::MAX.to_le_bytes());
    data.extend_from_slice(&(ed25519::PUBKEY_OFFSET as u16).to_le_bytes());
    data.extend_from_slice(&u16::MAX.to_le_bytes());
    data.extend_from_slice(&(ed25519::MESSAGE_OFFSET as u16).to_le_bytes());
    data.extend_from_slice(&(VOUCHER_PAYLOAD_SIZE as u16).to_le_bytes());
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

fn build_saf_ix(channel: &Pubkey, args: SettleAndFinalizeArgs, merchant: &Pubkey) -> Instruction {
    SettleAndFinalize {
        merchant: *merchant,
        channel: *channel,
        instructions_sysvar: instructions_sysvar_id(),
    }
    .instruction(SettleAndFinalizeInstructionArgs {
        settle_and_finalize_args: args,
    })
}

// ─── happy paths ────────────────────────────────────────────────────────────

#[test]
fn open_to_finalized_with_voucher() {
    let mut svm = LiteSVM::load_program();
    let fee_payer = Keypair::new();
    svm.airdrop(&fee_payer.pubkey(), 10_000_000_000).unwrap();

    let merchant = Keypair::new();
    let authorized_signer = Keypair::new();
    let channel = Pubkey::new_unique();
    seed_channel(
        &mut svm,
        &channel,
        ChannelStatus::Open,
        1_000_000,
        0,
        0,
        0,
        &merchant.pubkey(),
        &authorized_signer.pubkey(),
    );

    let cumulative = 600_000u64;
    let voucher = VoucherArgs {
        channel_id: channel,
        cumulative_amount: cumulative,
        expires_at: 0,
    };
    let payload = voucher_payload(&voucher);
    let signature: [u8; 64] = authorized_signer.sign_message(&payload).into();

    let ed25519_ix = build_ed25519_ix(&authorized_signer.pubkey().to_bytes(), &signature, &payload);
    let saf_ix = build_saf_ix(
        &channel,
        SettleAndFinalizeArgs {
            voucher,
            has_voucher: 1,
        },
        &merchant.pubkey(),
    );

    let tx = Transaction::new_signed_with_payer(
        &[ed25519_ix, saf_ix],
        Some(&fee_payer.pubkey()),
        &[&fee_payer, &merchant],
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).expect("tx ok");

    assert_eq!(read_status(&svm, &channel), ChannelStatus::Finalized as u8);
    assert_eq!(read_settled(&svm, &channel), cumulative);
    assert_eq!(read_closure_started_at(&svm, &channel), 0);
}

// ─── error paths ─────────────────────────────────────────────────────────────

#[test]
fn with_voucher_expired_rejects() {
    let mut svm = LiteSVM::load_program();
    let fee_payer = Keypair::new();
    svm.airdrop(&fee_payer.pubkey(), 10_000_000_000).unwrap();

    let expires_at: i64 = 500;
    let mut clock = svm.get_sysvar::<Clock>();
    clock.unix_timestamp = expires_at; // now == expires_at → expired
    svm.set_sysvar::<Clock>(&clock);

    let merchant = Keypair::new();
    let authorized_signer = Keypair::new();
    let channel = Pubkey::new_unique();
    seed_channel(
        &mut svm,
        &channel,
        ChannelStatus::Open,
        1_000_000,
        0,
        0,
        0,
        &merchant.pubkey(),
        &authorized_signer.pubkey(),
    );

    let voucher = VoucherArgs {
        channel_id: channel,
        cumulative_amount: 100_000,
        expires_at,
    };
    let payload = voucher_payload(&voucher);
    let signature: [u8; 64] = authorized_signer.sign_message(&payload).into();

    let ed25519_ix = build_ed25519_ix(&authorized_signer.pubkey().to_bytes(), &signature, &payload);
    let saf_ix = build_saf_ix(
        &channel,
        SettleAndFinalizeArgs {
            voucher,
            has_voucher: 1,
        },
        &merchant.pubkey(),
    );

    let tx = Transaction::new_signed_with_payer(
        &[ed25519_ix, saf_ix],
        Some(&fee_payer.pubkey()),
        &[&fee_payer, &merchant],
        svm.latest_blockhash(),
    );
    expect_custom_err(
        svm.send_transaction(tx),
        PaymentChannelsError::VoucherExpired,
    );
}

#[test]
fn with_voucher_wrong_authorized_signer_rejects() {
    let mut svm = LiteSVM::load_program();
    let fee_payer = Keypair::new();
    svm.airdrop(&fee_payer.pubkey(), 10_000_000_000).unwrap();

    let merchant = Keypair::new();
    let authorized_signer = Keypair::new();
    let impostor_signer = Keypair::new();
    let channel = Pubkey::new_unique();
    seed_channel(
        &mut svm,
        &channel,
        ChannelStatus::Open,
        1_000_000,
        0,
        0,
        0,
        &merchant.pubkey(),
        &authorized_signer.pubkey(),
    );

    let voucher = VoucherArgs {
        channel_id: channel,
        cumulative_amount: 100_000,
        expires_at: 0,
    };
    let payload = voucher_payload(&voucher);
    let signature: [u8; 64] = impostor_signer.sign_message(&payload).into();

    let ed25519_ix = build_ed25519_ix(&impostor_signer.pubkey().to_bytes(), &signature, &payload);
    let saf_ix = build_saf_ix(
        &channel,
        SettleAndFinalizeArgs {
            voucher,
            has_voucher: 1,
        },
        &merchant.pubkey(),
    );

    let tx = Transaction::new_signed_with_payer(
        &[ed25519_ix, saf_ix],
        Some(&fee_payer.pubkey()),
        &[&fee_payer, &merchant],
        svm.latest_blockhash(),
    );
    expect_custom_err(
        svm.send_transaction(tx),
        PaymentChannelsError::VoucherSignerMismatch,
    );
}
