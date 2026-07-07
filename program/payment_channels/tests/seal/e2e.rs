//! End-to-end validation of `seal` against the compiled .so.

#![allow(clippy::result_large_err)]

use litesvm::LiteSVM;
use payment_channels::PaymentChannelsError;
use payment_channels::state::channel::ChannelStatus;
use payment_channels_client::instructions::Seal;
use solana_account::Account;
use solana_clock::Clock;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

use crate::common::{ChannelBuilder, PROGRAM_ID, ProgramLoader, expect_custom_err, read_channel};

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
    let data = ChannelBuilder::new()
        .status(status)
        .closure_started_at(closure_started_at)
        .grace_period(grace_period)
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

fn set_clock(svm: &mut LiteSVM, unix_timestamp: i64) {
    let mut clock = svm.get_sysvar::<Clock>();
    clock.unix_timestamp = unix_timestamp;
    svm.set_sysvar::<Clock>(&clock);
}

fn send_seal(
    svm: &mut LiteSVM,
    channel: &Pubkey,
    fee_payer: &Keypair,
) -> Result<litesvm::types::TransactionMetadata, litesvm::types::FailedTransactionMetadata> {
    let ix = Seal { channel: *channel }.instruction();
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&fee_payer.pubkey()),
        &[fee_payer],
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx)
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
        send_seal(&mut svm, &channel, &fee_payer),
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

    send_seal(&mut svm, &channel, &fee_payer).expect("seal at deadline ok");

    read_channel(&svm, &channel, |ch| {
        assert_eq!(ch.status, ChannelStatus::Sealed as u8);
        assert_eq!(ch.closure_started_at(), 0i64);
    });
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

    send_seal(&mut svm, &channel, &fee_payer).expect("seal ok");

    read_channel(&svm, &channel, |ch| {
        assert_eq!(ch.status, ChannelStatus::Sealed as u8);
        assert_eq!(ch.closure_started_at(), 0i64);
    });
}
