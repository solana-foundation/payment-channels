//! End-to-end validation of `finalize` against the compiled .so.

#![allow(clippy::result_large_err)]

use litesvm::LiteSVM;
use payment_channels::state::channel::ChannelStatus;
use payment_channels_client::instructions::Finalize;
use solana_account::Account;
use solana_clock::Clock;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

use crate::common::{PROGRAM_ID, ProgramLoader};

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

fn read_channel(svm: &LiteSVM, channel: &Pubkey) -> Vec<u8> {
    svm.get_account(channel).expect("channel exists").data
}

#[test]
fn finalize_post_grace_transitions_and_clears_timestamp() {
    let mut svm = LiteSVM::load_program();
    let fee_payer = Keypair::new();
    svm.airdrop(&fee_payer.pubkey(), 1_000_000_000).unwrap();

    let channel = Pubkey::new_unique();
    let closure_started_at: i64 = 1;
    let grace_period: u32 = 100;
    seed_channel(
        &mut svm,
        &channel,
        ChannelStatus::Closing,
        closure_started_at,
        grace_period,
    );

    // Advance clock past the deadline (1 + 100 = 101).
    let mut clock = svm.get_sysvar::<Clock>();
    clock.unix_timestamp = 101;
    svm.set_sysvar::<Clock>(&clock);

    let ix = Finalize { channel }.instruction();
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&fee_payer.pubkey()),
        &[&fee_payer],
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).expect("finalize ok");

    let data = read_channel(&svm, &channel);
    assert_eq!(data[3], ChannelStatus::Finalized as u8);
    assert_eq!(i64::from_le_bytes(data[36..44].try_into().unwrap()), 0i64);
}
