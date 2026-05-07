//! End-to-end validation of `topUp` against the compiled .so.

#![allow(clippy::result_large_err)]

use litesvm::LiteSVM;
use litesvm_token::{CreateAssociatedTokenAccount, CreateMint, MintTo};
use payment_channels_client::instructions::{TopUp, TopUpInstructionArgs};
use payment_channels_client::types::TopUpArgs;
use payment_channels_core::PaymentChannelsError;
use solana_account::Account;
use solana_instruction::error::InstructionError;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;

use crate::common::token_2022::{EXT_TRANSFER_FEE_CONFIG, add_mint_extension};
use crate::common::{
    PROGRAM_ID, ProgramLoader, SPL_TOKEN, TOKEN_2022, expect_custom_err, open_channel,
    token_balance,
};

/// Inject a 216-byte Channel at `channel` owned by `PROGRAM_ID`.
fn seed_channel(svm: &mut LiteSVM, channel: &Pubkey, status: u8, deposit: u64, payer: &Pubkey) {
    let mut data = vec![0u8; 216];
    data[0] = 1; // AccountDiscriminator::Channel
    data[1] = 1; // CURRENT_CHANNEL_VERSION
    data[3] = status;
    data[12..20].copy_from_slice(&deposit.to_le_bytes());
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

fn read_deposit(svm: &LiteSVM, channel: &Pubkey) -> u64 {
    let acct = svm.get_account(channel).expect("channel exists");
    u64::from_le_bytes(acct.data[12..20].try_into().unwrap())
}

#[allow(clippy::too_many_arguments)]
fn build_top_up_ix(
    payer: &Pubkey,
    channel: &Pubkey,
    payer_token_account: &Pubkey,
    channel_token_account: &Pubkey,
    mint: &Pubkey,
    amount: u64,
    token_program: Pubkey,
) -> Instruction {
    TopUp {
        payer: *payer,
        channel: *channel,
        payer_token_account: *payer_token_account,
        channel_token_account: *channel_token_account,
        mint: *mint,
        token_program,
    }
    .instruction(TopUpInstructionArgs {
        top_up_args: TopUpArgs { amount },
    })
}

#[test]
fn top_up_increases_deposit() {
    let mut svm = LiteSVM::load_program();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();

    let payee = Pubkey::new_unique();
    let authorized_signer = Pubkey::new_unique();
    let deposit: u64 = 100_000_000;
    let top_up_amount: u64 = 50_000_000;

    let mint = CreateMint::new(&mut svm, &payer)
        .decimals(0)
        .token_program_id(&SPL_TOKEN)
        .send()
        .unwrap();
    let payer_ata = CreateAssociatedTokenAccount::new(&mut svm, &payer, &mint)
        .token_program_id(&SPL_TOKEN)
        .send()
        .unwrap();
    MintTo::new(&mut svm, &payer, &mint, &payer_ata, deposit + top_up_amount)
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

    assert_eq!(token_balance(&svm, &payer_ata), top_up_amount);
    assert_eq!(token_balance(&svm, &channel_ata), deposit);
    assert_eq!(read_deposit(&svm, &channel), deposit);

    let ix = build_top_up_ix(
        &payer.pubkey(),
        &channel,
        &payer_ata,
        &channel_ata,
        &mint,
        top_up_amount,
        SPL_TOKEN,
    );
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer],
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).expect("top_up ok");

    assert_eq!(read_deposit(&svm, &channel), deposit + top_up_amount);
    assert_eq!(token_balance(&svm, &payer_ata), 0);
    assert_eq!(token_balance(&svm, &channel_ata), deposit + top_up_amount);
}

#[test]
fn top_up_zero_amount_rejects() {
    let mut svm = LiteSVM::load_program();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 1_000_000_000).unwrap();

    let channel = Pubkey::new_unique();
    seed_channel(&mut svm, &channel, 0, 1_000_000, &payer.pubkey());

    let ix = build_top_up_ix(
        &payer.pubkey(),
        &channel,
        &Pubkey::new_unique(),
        &Pubkey::new_unique(),
        &Pubkey::new_unique(),
        0,
        SPL_TOKEN,
    );
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer],
        svm.latest_blockhash(),
    );
    expect_custom_err(
        svm.send_transaction(tx),
        PaymentChannelsError::DepositMustBeNonZero,
    );
}

#[test]
fn top_up_non_open_status_rejects() {
    let mut svm = LiteSVM::load_program();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 1_000_000_000).unwrap();

    let channel = Pubkey::new_unique();
    seed_channel(
        &mut svm,
        &channel,
        1, /* Finalized */
        1_000_000,
        &payer.pubkey(),
    );

    let ix = build_top_up_ix(
        &payer.pubkey(),
        &channel,
        &Pubkey::new_unique(),
        &Pubkey::new_unique(),
        &Pubkey::new_unique(),
        50_000,
        SPL_TOKEN,
    );
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

#[test]
fn top_up_wrong_payer_rejects() {
    let mut svm = LiteSVM::load_program();
    let alice = Keypair::new(); // channel.payer
    let bob = Keypair::new(); // unauthorized caller
    svm.airdrop(&bob.pubkey(), 1_000_000_000).unwrap();

    let channel = Pubkey::new_unique();
    seed_channel(&mut svm, &channel, 0, 1_000_000, &alice.pubkey());

    let ix = build_top_up_ix(
        &bob.pubkey(),
        &channel,
        &Pubkey::new_unique(),
        &Pubkey::new_unique(),
        &Pubkey::new_unique(),
        50_000,
        SPL_TOKEN,
    );
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
fn top_up_wrong_mint_rejects() {
    let mut svm = LiteSVM::load_program();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();

    let payee = Pubkey::new_unique();
    let authorized_signer = Pubkey::new_unique();
    let deposit: u64 = 100_000_000;
    let top_up_amount: u64 = 50_000_000;

    let mint = CreateMint::new(&mut svm, &payer)
        .decimals(0)
        .token_program_id(&SPL_TOKEN)
        .send()
        .unwrap();
    let payer_ata = CreateAssociatedTokenAccount::new(&mut svm, &payer, &mint)
        .token_program_id(&SPL_TOKEN)
        .send()
        .unwrap();
    MintTo::new(&mut svm, &payer, &mint, &payer_ata, deposit + top_up_amount)
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

    // The mint check fires before any CPI, so any address that differs from
    // the channel's recorded mint triggers the error.
    let wrong_mint = Pubkey::new_unique();

    let ix = build_top_up_ix(
        &payer.pubkey(),
        &channel,
        &payer_ata,
        &channel_ata,
        &wrong_mint,
        top_up_amount,
        SPL_TOKEN,
    );
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer],
        svm.latest_blockhash(),
    );
    expect_custom_err(
        svm.send_transaction(tx),
        PaymentChannelsError::MintAccountMismatch,
    );
}

#[test]
fn top_up_wrong_escrow_rejects() {
    let mut svm = LiteSVM::load_program();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();

    let payee = Pubkey::new_unique();
    let authorized_signer = Pubkey::new_unique();
    let deposit: u64 = 100_000_000;
    let top_up_amount: u64 = 50_000_000;

    let mint = CreateMint::new(&mut svm, &payer)
        .decimals(0)
        .token_program_id(&SPL_TOKEN)
        .send()
        .unwrap();
    let payer_ata = CreateAssociatedTokenAccount::new(&mut svm, &payer, &mint)
        .token_program_id(&SPL_TOKEN)
        .send()
        .unwrap();
    MintTo::new(&mut svm, &payer, &mint, &payer_ata, deposit + top_up_amount)
        .token_program_id(&SPL_TOKEN)
        .send()
        .unwrap();

    let (channel, _channel_ata) = open_channel(
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

    // Pass payer_ata in place of the channel escrow — same mint so the ATA
    // derivation check fires before the token CPI can catch it.
    let ix = build_top_up_ix(
        &payer.pubkey(),
        &channel,
        &payer_ata,
        &payer_ata,
        &mint,
        top_up_amount,
        SPL_TOKEN,
    );
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer],
        svm.latest_blockhash(),
    );
    expect_custom_err(
        svm.send_transaction(tx),
        PaymentChannelsError::EscrowAddressMismatch,
    );
}

#[test]
fn top_up_unsigned_payer_rejects() {
    let mut svm = LiteSVM::load_program();
    let fee_payer = Keypair::new();
    let channel_payer = Keypair::new();
    svm.airdrop(&fee_payer.pubkey(), 1_000_000_000).unwrap();

    let channel = Pubkey::new_unique();
    seed_channel(&mut svm, &channel, 0, 1_000_000, &channel_payer.pubkey());

    let mut data = vec![3u8]; // DISCRIMINATOR
    data.extend_from_slice(&50_000u64.to_le_bytes());
    let ix = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(channel_payer.pubkey(), false), // not signer
            AccountMeta::new(channel, false),
            AccountMeta::new(Pubkey::new_unique(), false),
            AccountMeta::new(Pubkey::new_unique(), false),
            AccountMeta::new_readonly(Pubkey::new_unique(), false),
            AccountMeta::new_readonly(SPL_TOKEN, false),
        ],
        data,
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
fn top_up_increases_deposit_token_2022() {
    let mut svm = LiteSVM::load_program();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();

    let payee = Pubkey::new_unique();
    let authorized_signer = Pubkey::new_unique();
    let deposit: u64 = 100_000_000;
    let top_up_amount: u64 = 50_000_000;

    let mint = CreateMint::new(&mut svm, &payer)
        .decimals(0)
        .token_program_id(&TOKEN_2022)
        .send()
        .unwrap();
    let payer_ata = CreateAssociatedTokenAccount::new(&mut svm, &payer, &mint)
        .token_program_id(&TOKEN_2022)
        .send()
        .unwrap();
    MintTo::new(&mut svm, &payer, &mint, &payer_ata, deposit + top_up_amount)
        .token_program_id(&TOKEN_2022)
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
        &TOKEN_2022,
    );

    assert_eq!(token_balance(&svm, &payer_ata), top_up_amount);
    assert_eq!(token_balance(&svm, &channel_ata), deposit);
    assert_eq!(read_deposit(&svm, &channel), deposit);

    let ix = build_top_up_ix(
        &payer.pubkey(),
        &channel,
        &payer_ata,
        &channel_ata,
        &mint,
        top_up_amount,
        TOKEN_2022,
    );
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer],
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).expect("top_up ok");

    assert_eq!(read_deposit(&svm, &channel), deposit + top_up_amount);
    assert_eq!(token_balance(&svm, &payer_ata), 0);
    assert_eq!(token_balance(&svm, &channel_ata), deposit + top_up_amount);
}

#[test]
fn top_up_token_2022_nonzero_decimals_succeeds() {
    let mut svm = LiteSVM::load_program();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();

    let payee = Pubkey::new_unique();
    let authorized_signer = Pubkey::new_unique();
    let deposit: u64 = 100_000_000;
    let top_up_amount: u64 = 50_000_000;

    let mint = CreateMint::new(&mut svm, &payer)
        .decimals(6)
        .token_program_id(&TOKEN_2022)
        .send()
        .unwrap();
    let payer_ata = CreateAssociatedTokenAccount::new(&mut svm, &payer, &mint)
        .token_program_id(&TOKEN_2022)
        .send()
        .unwrap();
    MintTo::new(&mut svm, &payer, &mint, &payer_ata, deposit + top_up_amount)
        .token_program_id(&TOKEN_2022)
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
        &TOKEN_2022,
    );

    let ix = build_top_up_ix(
        &payer.pubkey(),
        &channel,
        &payer_ata,
        &channel_ata,
        &mint,
        top_up_amount,
        TOKEN_2022,
    );
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer],
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).expect("top_up ok");

    assert_eq!(read_deposit(&svm, &channel), deposit + top_up_amount);
    assert_eq!(token_balance(&svm, &payer_ata), 0);
    assert_eq!(token_balance(&svm, &channel_ata), deposit + top_up_amount);
}

#[test]
fn top_up_unsupported_token_2022_mint_extension_rejects_without_state_changes() {
    let mut svm = LiteSVM::load_program();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();

    let payee = Pubkey::new_unique();
    let authorized_signer = Pubkey::new_unique();
    let deposit: u64 = 100_000_000;
    let top_up_amount: u64 = 50_000_000;

    let mint = CreateMint::new(&mut svm, &payer)
        .decimals(0)
        .token_program_id(&TOKEN_2022)
        .send()
        .unwrap();
    let payer_ata = CreateAssociatedTokenAccount::new(&mut svm, &payer, &mint)
        .token_program_id(&TOKEN_2022)
        .send()
        .unwrap();
    MintTo::new(&mut svm, &payer, &mint, &payer_ata, deposit + top_up_amount)
        .token_program_id(&TOKEN_2022)
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
        &TOKEN_2022,
    );

    assert_eq!(read_deposit(&svm, &channel), deposit);
    assert_eq!(token_balance(&svm, &payer_ata), top_up_amount);
    assert_eq!(token_balance(&svm, &channel_ata), deposit);

    add_mint_extension(&mut svm, &mint, EXT_TRANSFER_FEE_CONFIG, 108);

    let ix = build_top_up_ix(
        &payer.pubkey(),
        &channel,
        &payer_ata,
        &channel_ata,
        &mint,
        top_up_amount,
        TOKEN_2022,
    );
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer],
        svm.latest_blockhash(),
    );
    expect_custom_err(
        svm.send_transaction(tx),
        PaymentChannelsError::UnsupportedTokenExtensions,
    );

    assert_eq!(read_deposit(&svm, &channel), deposit);
    assert_eq!(token_balance(&svm, &payer_ata), top_up_amount);
    assert_eq!(token_balance(&svm, &channel_ata), deposit);
}

#[test]
fn top_up_wrong_escrow_rejects_token_2022() {
    let mut svm = LiteSVM::load_program();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();

    let payee = Pubkey::new_unique();
    let authorized_signer = Pubkey::new_unique();
    let deposit: u64 = 100_000_000;
    let top_up_amount: u64 = 50_000_000;

    let mint = CreateMint::new(&mut svm, &payer)
        .decimals(0)
        .token_program_id(&TOKEN_2022)
        .send()
        .unwrap();
    let payer_ata = CreateAssociatedTokenAccount::new(&mut svm, &payer, &mint)
        .token_program_id(&TOKEN_2022)
        .send()
        .unwrap();
    MintTo::new(&mut svm, &payer, &mint, &payer_ata, deposit + top_up_amount)
        .token_program_id(&TOKEN_2022)
        .send()
        .unwrap();

    let (channel, _channel_ata) = open_channel(
        &mut svm,
        &payer,
        &payee,
        &authorized_signer,
        1,
        deposit,
        &mint,
        &payer_ata,
        &TOKEN_2022,
    );

    // Pass payer_ata in place of the channel escrow — same mint so the ATA
    // derivation check fires before the token CPI can catch it.
    let ix = build_top_up_ix(
        &payer.pubkey(),
        &channel,
        &payer_ata,
        &payer_ata,
        &mint,
        top_up_amount,
        TOKEN_2022,
    );
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer],
        svm.latest_blockhash(),
    );
    expect_custom_err(
        svm.send_transaction(tx),
        PaymentChannelsError::EscrowAddressMismatch,
    );
}
