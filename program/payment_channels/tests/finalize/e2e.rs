//! End-to-end validation of `finalize` against the compiled .so.

#![allow(clippy::result_large_err)]

use litesvm::LiteSVM;
use payment_channels::PaymentChannelsError;
use payment_channels::state::channel::ChannelStatus;
use payment_channels_client::instructions::Finalize;
use solana_account::Account;
use solana_clock::Clock;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

use crate::common::{PROGRAM_ID, ProgramLoader,  expect_custom_err};

const CLOSURE_STARTED_AT: i64 = 1_000_000;
const GRACE_PERIOD: u32 = 3_600;
const DEADLINE: i64 = CLOSURE_STARTED_AT + GRACE_PERIOD as i64; // 1_003_600

fn seed_channel(
    svm: &mut LiteSVM,
    channel: &Pubkey,
    status: ChannelStatus,
    closure_started_at: i64,
    grace_period: u32,
) {
    let mut data = vec![0u8; 216];
    data[0] = 1; // AccountDiscriminator::Channel
    data[1] = 1; // CURRENT_CHANNEL_VERSION
    data[3] = status as u8;
    data[36..44].copy_from_slice(&closure_started_at.to_le_bytes());
    data[52..56].copy_from_slice(&grace_period.to_le_bytes());
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

fn set_clock(svm: &mut LiteSVM, unix_timestamp: i64) {
    let mut clock = svm.get_sysvar::<Clock>();
    clock.unix_timestamp = unix_timestamp;
    svm.set_sysvar::<Clock>(&clock);
}

fn send_finalize(
    svm: &mut LiteSVM,
    channel: &Pubkey,
    fee_payer: &Keypair,
) -> Result<litesvm::types::TransactionMetadata, litesvm::types::FailedTransactionMetadata> {
    let ix = Finalize { channel: *channel }.instruction();
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&fee_payer.pubkey()),
        &[fee_payer],
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx)
}

fn read_channel(svm: &LiteSVM, channel: &Pubkey) -> Vec<u8> {
    svm.get_account(channel).expect("channel exists").data
}

#[test]
fn mid_grace_rejects() {
    let mut svm = LiteSVM::load_program();
    let fee_payer = Keypair::new();
    svm.airdrop(&fee_payer.pubkey(), 1_000_000_000).unwrap();

    let channel = Pubkey::new_unique();
    seed_channel(
        &mut svm,
        &channel,
        ChannelStatus::Closing,
        CLOSURE_STARTED_AT,
        GRACE_PERIOD,
    );
    set_clock(&mut svm, DEADLINE - 1); // one second before deadline

    expect_custom_err(
        send_finalize(&mut svm, &channel, &fee_payer),
        PaymentChannelsError::InvalidChannelStatus,
    );
}

#[test]
fn at_exact_deadline_succeeds() {
    let mut svm = LiteSVM::load_program();
    let fee_payer = Keypair::new();
    svm.airdrop(&fee_payer.pubkey(), 1_000_000_000).unwrap();

    let channel = Pubkey::new_unique();
    seed_channel(
        &mut svm,
        &channel,
        ChannelStatus::Closing,
        CLOSURE_STARTED_AT,
        GRACE_PERIOD,
    );
    set_clock(&mut svm, DEADLINE); // now == deadline

    send_finalize(&mut svm, &channel, &fee_payer).expect("finalize at deadline ok");

    let data = read_channel(&svm, &channel);
    assert_eq!(data[3], ChannelStatus::Finalized as u8);
    assert_eq!(i64::from_le_bytes(data[36..44].try_into().unwrap()), 0i64);
}

#[test]
fn post_grace_transitions_and_clears_timestamp() {
    let mut svm = LiteSVM::load_program();
    let fee_payer = Keypair::new();
    svm.airdrop(&fee_payer.pubkey(), 1_000_000_000).unwrap();

    let channel = Pubkey::new_unique();
    seed_channel(
        &mut svm,
        &channel,
        ChannelStatus::Closing,
        CLOSURE_STARTED_AT,
        GRACE_PERIOD,
    );
    set_clock(&mut svm, DEADLINE + 1); // one second past deadline

    send_finalize(&mut svm, &channel, &fee_payer).expect("finalize ok");

    let data = read_channel(&svm, &channel);
    assert_eq!(data[3], ChannelStatus::Finalized as u8);
    assert_eq!(i64::from_le_bytes(data[36..44].try_into().unwrap()), 0i64);
}
