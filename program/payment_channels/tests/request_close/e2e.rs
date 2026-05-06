//! End-to-end validation of `requestClose` against the compiled .so.

#![allow(clippy::result_large_err)]

use litesvm::LiteSVM;
use payment_channels::state::channel::ChannelStatus;
use payment_channels_client::instructions::RequestClose;
use solana_account::Account;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

use crate::common::{PROGRAM_ID, ProgramLoader, canonicalize_channel_blob};

/// Inject a 216-byte Channel at its canonical PDA owned by `PROGRAM_ID`.
fn seed_channel(svm: &mut LiteSVM, status: ChannelStatus, payer: &Pubkey) -> Pubkey {
    let mut data = vec![0u8; 216];
    data[0] = 1; // AccountDiscriminator::Channel
    data[1] = 1; // CURRENT_CHANNEL_VERSION
    data[3] = status as u8;
    data[88..120].copy_from_slice(&payer.to_bytes());
    let channel = canonicalize_channel_blob(&mut data).expect("canonical channel blob");
    svm.set_account(
        channel,
        Account {
            lamports: 10_000_000,
            data,
            owner: PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        },
    )
    .expect("set_account");
    channel
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

    let channel = seed_channel(&mut svm, ChannelStatus::Open, &payer.pubkey());

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
