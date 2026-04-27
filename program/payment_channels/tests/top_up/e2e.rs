//! End-to-end validation of `topUp` against the compiled .so.

#![allow(clippy::result_large_err)]
#![allow(deprecated)]

use litesvm::LiteSVM;
use litesvm_token::{CreateAssociatedTokenAccount, CreateMint, MintTo};
use payment_channels::PaymentChannelsError;
use payment_channels::event_engine::EVENT_AUTHORITY_SEED;
use payment_channels::instructions::open::{
    DISCRIMINATOR as OPEN_DISCRIMINATOR, MAX_DISTRIBUTION_RECIPIENTS,
};
use payment_channels_client::instructions::{TopUp, TopUpInstructionArgs};
use payment_channels_client::types::TopUpArgs;
use solana_account::Account;
use solana_instruction::error::InstructionError;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::{Pubkey, pubkey};
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;

use crate::common::{PROGRAM_ID, expect_custom_err, load_program};

const SPL_TOKEN: Pubkey = pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const ATA_PROGRAM: Pubkey = pubkey!("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
const SYSTEM_PROGRAM: Pubkey = pubkey!("11111111111111111111111111111111");
const SYSVAR_RENT: Pubkey = pubkey!("SysvarRent111111111111111111111111111111111");

fn event_authority() -> Pubkey {
    Pubkey::find_program_address(&[EVENT_AUTHORITY_SEED], &PROGRAM_ID).0
}

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

fn read_token_balance(svm: &LiteSVM, ata: &Pubkey) -> u64 {
    let acct = svm.get_account(ata).expect("token account exists");
    u64::from_le_bytes(acct.data[64..72].try_into().unwrap())
}

#[allow(clippy::too_many_arguments)]
fn open_channel(
    svm: &mut LiteSVM,
    payer: &Keypair,
    payee: &Pubkey,
    authorized_signer: &Pubkey,
    salt: u64,
    deposit: u64,
    mint: &Pubkey,
    payer_ata: &Pubkey,
) -> (Pubkey, Pubkey) {
    let (channel, _) = Pubkey::find_program_address(
        &[
            b"channel",
            payer.pubkey().as_ref(),
            payee.as_ref(),
            mint.as_ref(),
            authorized_signer.as_ref(),
            &salt.to_le_bytes(),
        ],
        &PROGRAM_ID,
    );
    let (channel_ata, _) = Pubkey::find_program_address(
        &[channel.as_ref(), SPL_TOKEN.as_ref(), mint.as_ref()],
        &ATA_PROGRAM,
    );
    let event_auth = event_authority();

    let mut data = vec![OPEN_DISCRIMINATOR];
    data.extend_from_slice(&salt.to_le_bytes());
    data.extend_from_slice(&deposit.to_le_bytes());
    data.extend_from_slice(&3_600u32.to_le_bytes());
    data.push(1u8);
    data.extend_from_slice(&[1u8; 32]);
    data.extend_from_slice(&deposit.to_le_bytes());
    data.extend_from_slice(&[0u8; (MAX_DISTRIBUTION_RECIPIENTS - 1) * 40]);

    let ix = Instruction::new_with_bytes(
        PROGRAM_ID,
        &data,
        vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(*payee, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(*authorized_signer, false),
            AccountMeta::new(channel, false),
            AccountMeta::new(*payer_ata, false),
            AccountMeta::new(channel_ata, false),
            AccountMeta::new_readonly(SPL_TOKEN, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            AccountMeta::new_readonly(SYSVAR_RENT, false),
            AccountMeta::new_readonly(ATA_PROGRAM, false),
            AccountMeta::new_readonly(event_auth, false),
            AccountMeta::new_readonly(PROGRAM_ID, false),
        ],
    );
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[payer],
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).expect("open ok");

    (channel, channel_ata)
}

fn build_top_up_ix(
    payer: &Pubkey,
    channel: &Pubkey,
    payer_token_account: &Pubkey,
    channel_token_account: &Pubkey,
    mint: &Pubkey,
    amount: u64,
) -> Instruction {
    TopUp {
        payer: *payer,
        channel: *channel,
        payer_token_account: *payer_token_account,
        channel_token_account: *channel_token_account,
        mint: *mint,
        token_program: SPL_TOKEN,
    }
    .instruction(TopUpInstructionArgs {
        top_up_args: TopUpArgs { amount },
    })
}

#[test]
fn top_up_increases_deposit() {
    let mut svm = load_program();
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
    );

    assert_eq!(read_token_balance(&svm, &payer_ata), top_up_amount);
    assert_eq!(read_token_balance(&svm, &channel_ata), deposit);
    assert_eq!(read_deposit(&svm, &channel), deposit);

    let ix = build_top_up_ix(
        &payer.pubkey(),
        &channel,
        &payer_ata,
        &channel_ata,
        &mint,
        top_up_amount,
    );
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer],
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).expect("top_up ok");

    assert_eq!(read_deposit(&svm, &channel), deposit + top_up_amount);
    assert_eq!(read_token_balance(&svm, &payer_ata), 0);
    assert_eq!(
        read_token_balance(&svm, &channel_ata),
        deposit + top_up_amount
    );
}

#[test]
fn top_up_zero_amount_rejects() {
    let mut svm = load_program();
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
    let mut svm = load_program();
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
    let mut svm = load_program();
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
fn top_up_unsigned_payer_rejects() {
    let mut svm = load_program();
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
            AccountMeta::new_readonly(Pubkey::new_unique(), false),
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
