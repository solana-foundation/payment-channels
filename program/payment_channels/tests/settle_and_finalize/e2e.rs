//! End-to-end validation of `settleAndFinalize` against the compiled .so.

#![allow(clippy::result_large_err)]

use litesvm::LiteSVM;
use payment_channels::PaymentChannelsError;
use payment_channels::state::channel::ChannelStatus;
use payment_channels_client::instructions::{SettleAndFinalize, SettleAndFinalizeInstructionArgs};
use payment_channels_client::types::{SettleAndFinalizeArgs, VoucherArgs};
use solana_account::Account;
use solana_clock::Clock;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

use crate::common::{
    ChannelBuilder, INSTRUCTIONS_SYSVAR, PROGRAM_ID, ProgramLoader, expect_custom_err,
    read_channel,
    voucher::{build_ed25519_ix, voucher_payload},
};

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
    let data = ChannelBuilder::new()
        .status(status)
        .deposit(deposit)
        .settled(settled)
        .closure_started_at(closure_started_at)
        .grace_period(grace_period)
        .payee(*payee)
        .authorized_signer(*authorized_signer)
        .build();
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

fn build_saf_ix(channel: &Pubkey, args: SettleAndFinalizeArgs, merchant: &Pubkey) -> Instruction {
    SettleAndFinalize {
        merchant: *merchant,
        channel: *channel,
        instructions_sysvar: INSTRUCTIONS_SYSVAR,
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
        open_slot: 0,
        cumulative_amount: cumulative,
        expires_at: 0,
    };
    let payload = voucher_payload(&voucher);
    let signature: [u8; 64] = authorized_signer.sign_message(&payload).into();

    let ed25519_ix = build_ed25519_ix(&authorized_signer.pubkey().to_bytes(), &signature, &payload);
    let saf_ix = build_saf_ix(
        &channel,
        SettleAndFinalizeArgs {
            has_voucher: 1,
            expected_open_slot: 0,
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

    read_channel(&svm, &channel, |ch| {
        assert_eq!(ch.status, ChannelStatus::Finalized as u8);
        assert_eq!(ch.settled(), cumulative);
        assert_eq!(ch.closure_started_at(), 0);
    });
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
        open_slot: 0,
        cumulative_amount: 100_000,
        expires_at,
    };
    let payload = voucher_payload(&voucher);
    let signature: [u8; 64] = authorized_signer.sign_message(&payload).into();

    let ed25519_ix = build_ed25519_ix(&authorized_signer.pubkey().to_bytes(), &signature, &payload);
    let saf_ix = build_saf_ix(
        &channel,
        SettleAndFinalizeArgs {
            has_voucher: 1,
            expected_open_slot: 0,
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
        open_slot: 0,
        cumulative_amount: 100_000,
        expires_at: 0,
    };
    let payload = voucher_payload(&voucher);
    let signature: [u8; 64] = impostor_signer.sign_message(&payload).into();

    let ed25519_ix = build_ed25519_ix(&impostor_signer.pubkey().to_bytes(), &signature, &payload);
    let saf_ix = build_saf_ix(
        &channel,
        SettleAndFinalizeArgs {
            has_voucher: 1,
            expected_open_slot: 0,
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
