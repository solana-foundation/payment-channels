//! End-to-end validation of `requestClose` against the compiled .so.

#![allow(clippy::result_large_err)]

use litesvm::LiteSVM;
use payment_channels::PaymentChannelsError;
use payment_channels::state::channel::ChannelStatus;
use payment_channels_client::instructions::RequestClose;
use solana_account::Account;
use solana_instruction::error::InstructionError;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;

use crate::common::{PROGRAM_ID, ProgramLoader, expect_custom_err};

/// Inject a 216-byte Channel at `channel` owned by `PROGRAM_ID`.
fn seed_channel(svm: &mut LiteSVM, channel: &Pubkey, status: ChannelStatus, payer: &Pubkey) {
    let mut data = vec![0u8; 216];
    data[0] = 1; // AccountDiscriminator::Channel
    data[1] = 1; // CURRENT_CHANNEL_VERSION
    data[3] = status as u8;
    data[88..120].copy_from_slice(&payer.to_bytes());
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

fn read_channel(svm: &LiteSVM, channel: &Pubkey) -> Vec<u8> {
    svm.get_account(channel).expect("channel exists").data
}

fn build_request_close_ix(payer: &Pubkey, channel: &Pubkey) -> Instruction {
    RequestClose {
        payer: *payer,
        channel: *channel,
    }
    .instruction()
}

#[test]
fn request_close_marks_closing_and_stamps_now() {
    let mut svm = LiteSVM::load_program();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 1_000_000_000).unwrap();

    let channel = Pubkey::new_unique();
    seed_channel(&mut svm, &channel, ChannelStatus::Open, &payer.pubkey());

    let pre_clock_ts = svm.get_sysvar::<solana_clock::Clock>().unix_timestamp;

    let ix = build_request_close_ix(&payer.pubkey(), &channel);
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer],
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).expect("request_close ok");

    let data = read_channel(&svm, &channel);
    assert_eq!(data[3], ChannelStatus::Closing as u8);
    assert_eq!(
        i64::from_le_bytes(data[36..44].try_into().unwrap()),
        pre_clock_ts,
    );
}

#[test]
fn request_close_unsigned_payer_rejects() {
    let mut svm = LiteSVM::load_program();
    let fee_payer = Keypair::new();
    let channel_payer = Keypair::new();
    svm.airdrop(&fee_payer.pubkey(), 1_000_000_000).unwrap();

    let channel = Pubkey::new_unique();
    seed_channel(
        &mut svm,
        &channel,
        ChannelStatus::Open,
        &channel_payer.pubkey(),
    );

    let ix = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new_readonly(channel_payer.pubkey(), false),
            AccountMeta::new(channel, false),
        ],
        data: vec![5], // DISCRIMINATOR
    };
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&fee_payer.pubkey()),
        &[&fee_payer],
        svm.latest_blockhash(),
    );
    let err = svm.send_transaction(tx).expect_err("should fail");
    match err.err {
        TransactionError::InstructionError(_, InstructionError::MissingRequiredSignature) => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn request_close_wrong_payer_rejects() {
    let mut svm = LiteSVM::load_program();
    let alice = Keypair::new(); // channel.payer
    let bob = Keypair::new(); // unauthorized caller
    svm.airdrop(&bob.pubkey(), 1_000_000_000).unwrap();

    let channel = Pubkey::new_unique();
    seed_channel(&mut svm, &channel, ChannelStatus::Open, &alice.pubkey());

    let ix = build_request_close_ix(&bob.pubkey(), &channel);
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&bob.pubkey()),
        &[&bob],
        svm.latest_blockhash(),
    );
    expect_custom_err(
        svm.send_transaction(tx),
        PaymentChannelsError::UnauthorizedPayer,
    );
}

#[test]
fn request_close_non_open_status_rejects() {
    let mut svm = LiteSVM::load_program();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 1_000_000_000).unwrap();

    let channel = Pubkey::new_unique();
    seed_channel(&mut svm, &channel, ChannelStatus::Closing, &payer.pubkey());

    let ix = build_request_close_ix(&payer.pubkey(), &channel);
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer],
        svm.latest_blockhash(),
    );
    expect_custom_err(
        svm.send_transaction(tx),
        PaymentChannelsError::InvalidChannelStatus,
    );
}
