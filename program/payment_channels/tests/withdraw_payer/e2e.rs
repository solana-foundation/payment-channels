//! End-to-end validation of `withdraw_payer` against the compiled .so.

#![allow(clippy::result_large_err)]

use litesvm::LiteSVM;
use litesvm_token::{CreateAssociatedTokenAccount, CreateMint, MintTo};
use payment_channels_client::instructions::WithdrawPayer;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

use crate::common::{ProgramLoader, SPL_TOKEN, cu_tracker, open_channel, set_clock, token_balance};

/// Patch an existing channel account to FINALIZED status with the given settled amount.
fn patch_channel_finalized(svm: &mut LiteSVM, channel: &Pubkey, settled: u64) {
    let mut acct = svm.get_account(channel).expect("channel exists");
    acct.data[3] = 1; // ChannelStatus::Finalized
    acct.data[20..28].copy_from_slice(&settled.to_le_bytes());
    svm.set_account(*channel, acct).expect("set_account");
}

fn read_payer_withdrawn_at(svm: &LiteSVM, channel: &Pubkey) -> i64 {
    let acct = svm.get_account(channel).expect("channel exists");
    i64::from_le_bytes(acct.data[44..52].try_into().unwrap())
}

fn send_withdraw_payer(
    svm: &mut LiteSVM,
    payer: &Keypair,
    channel: &Pubkey,
    channel_ata: &Pubkey,
    payer_ata: &Pubkey,
    mint: &Pubkey,
) -> Result<litesvm::types::TransactionMetadata, litesvm::types::FailedTransactionMetadata> {
    let ix = WithdrawPayer {
        payer: payer.pubkey(),
        channel: *channel,
        channel_token_account: *channel_ata,
        payer_token_account: *payer_ata,
        mint: *mint,
        token_program: SPL_TOKEN,
    }
    .instruction();
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[payer],
        svm.latest_blockhash(),
    );
    cu_tracker::send_and_record(svm, tx)
}

#[test]
fn withdraw_transfers_correct_amount() {
    let mut svm = LiteSVM::load_program();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();

    let payee = Pubkey::new_unique();
    let authorized_signer = Pubkey::new_unique();
    let deposit: u64 = 100_000_000;
    let settled: u64 = 30_000_000;

    let mint = CreateMint::new(&mut svm, &payer)
        .decimals(0)
        .token_program_id(&SPL_TOKEN)
        .send()
        .unwrap();
    let payer_ata = CreateAssociatedTokenAccount::new(&mut svm, &payer, &mint)
        .token_program_id(&SPL_TOKEN)
        .send()
        .unwrap();
    MintTo::new(&mut svm, &payer, &mint, &payer_ata, deposit)
        .token_program_id(&SPL_TOKEN)
        .send()
        .unwrap();

    let (channel, channel_ata) = open_channel(
        &mut svm,
        &payer,
        &payee,
        &authorized_signer,
        1,
        deposit,
        &mint,
        &payer_ata,
        &SPL_TOKEN,
    );

    // After open: payer ATA is empty, escrow has deposit.
    assert_eq!(token_balance(&svm, &payer_ata), 0);
    assert_eq!(token_balance(&svm, &channel_ata), deposit);

    patch_channel_finalized(&mut svm, &channel, settled);
    set_clock(&mut svm, 1_000_000);

    send_withdraw_payer(&mut svm, &payer, &channel, &channel_ata, &payer_ata, &mint)
        .expect("withdraw ok");

    // Payer receives deposit - settled; escrow retains settled (for distribute).
    assert_eq!(token_balance(&svm, &payer_ata), deposit - settled);
    assert_eq!(token_balance(&svm, &channel_ata), settled);
    assert_ne!(read_payer_withdrawn_at(&svm, &channel), 0);
}

#[test]
fn withdraw_zero_refund_stamps_timestamp() {
    let mut svm = LiteSVM::load_program();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();

    let payee = Pubkey::new_unique();
    let authorized_signer = Pubkey::new_unique();
    let deposit: u64 = 100_000_000;

    let mint = CreateMint::new(&mut svm, &payer)
        .decimals(0)
        .token_program_id(&SPL_TOKEN)
        .send()
        .unwrap();
    let payer_ata = CreateAssociatedTokenAccount::new(&mut svm, &payer, &mint)
        .token_program_id(&SPL_TOKEN)
        .send()
        .unwrap();
    MintTo::new(&mut svm, &payer, &mint, &payer_ata, deposit)
        .token_program_id(&SPL_TOKEN)
        .send()
        .unwrap();

    let (channel, channel_ata) = open_channel(
        &mut svm,
        &payer,
        &payee,
        &authorized_signer,
        1,
        deposit,
        &mint,
        &payer_ata,
        &SPL_TOKEN,
    );

    // Fully settled: deposit == settled → refund = 0.
    patch_channel_finalized(&mut svm, &channel, deposit);
    set_clock(&mut svm, 1_000_000);

    send_withdraw_payer(&mut svm, &payer, &channel, &channel_ata, &payer_ata, &mint)
        .expect("withdraw ok (zero refund)");

    assert_eq!(token_balance(&svm, &payer_ata), 0);
    assert_eq!(token_balance(&svm, &channel_ata), deposit);
    // payer_withdrawn_at stamped — distribute cannot double-refund.
    assert_ne!(read_payer_withdrawn_at(&svm, &channel), 0);
}
