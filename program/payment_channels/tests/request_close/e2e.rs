//! End-to-end validation of `requestClose` against the compiled .so.

#![allow(clippy::result_large_err)]

use litesvm::LiteSVM;
use payment_channels::state::channel::ChannelStatus;
use payment_channels_client::instructions::{RequestClose, RequestCloseInstructionArgs};
use payment_channels_client::types::RequestCloseArgs;
use solana_account::Account;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

use crate::common::{ChannelBuilder, PROGRAM_ID, ProgramLoader, read_channel};

/// Inject a `Channel` at `channel` owned by `PROGRAM_ID`.
fn seed_channel(svm: &mut LiteSVM, channel: &Pubkey, status: ChannelStatus, payer: &Pubkey) {
    let data = ChannelBuilder::new().status(status).payer(*payer).build();
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

fn build_request_close_ix(
    payer: &Pubkey,
    channel: &Pubkey,
    expected_open_slot: u64,
) -> Instruction {
    RequestClose {
        payer: *payer,
        channel: *channel,
    }
    .instruction(RequestCloseInstructionArgs {
        request_close_args: RequestCloseArgs { expected_open_slot },
    })
}

#[test]
fn request_close_marks_closing_and_stamps_now() {
    let mut svm = LiteSVM::load_program();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 1_000_000_000).unwrap();

    let channel = Pubkey::new_unique();
    seed_channel(&mut svm, &channel, ChannelStatus::Open, &payer.pubkey());

    let pre_clock_ts = svm.get_sysvar::<solana_clock::Clock>().unix_timestamp;

    let ix = build_request_close_ix(&payer.pubkey(), &channel, 0);
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer],
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).expect("request_close ok");

    read_channel(&svm, &channel, |ch| {
        assert_eq!(ch.status, ChannelStatus::Closing as u8);
        assert_eq!(ch.closure_started_at(), pre_clock_ts);
    });
}
