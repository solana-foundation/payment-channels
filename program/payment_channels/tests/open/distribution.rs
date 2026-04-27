//! Distribution-plan validation tests for the `open` instruction.
//!
//! Verifies that well-formed plans (any count in 1..=MAX) advance past plan
//! parsing and reach the channel-address check (`InvalidAccountData`).
//! Out-of-range counts are covered in `bounds.rs`.

use mollusk_svm::result::ProgramResult;
use payment_channels::PaymentChannelsError;
use payment_channels::instructions::open::MAX_DISTRIBUTION_RECIPIENTS;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::Message;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

use super::{
    ATA_PROGRAM, EVENT_AUTHORITY, SPL_TOKEN, SYSTEM_PROGRAM, SYSVAR_RENT, TOKEN_2022, derive_pdas,
    derive_pdas_with_token_program, open_ix_data, open_ix_with_token_program, run_open,
    setup_funded_svm, setup_funded_svm_with_token_program,
};
use crate::common::{PROGRAM_ID, expect_custom_err, load_program};

const SALT: u64 = 1;
const DEPOSIT: u64 = 1_000_000;
const GRACE: u32 = 3600;
const FIRST_RECIPIENT_OFFSET: usize = 1 + 8 + 8 + 4 + 1;
const FIRST_BPS_OFFSET: usize = FIRST_RECIPIENT_OFFSET + 32;
const ENTRY_LEN: usize = 34;
const TOKEN_2022_ACCOUNT_TYPE_OFFSET: usize = 165;
const TOKEN_2022_TLV_START: usize = TOKEN_2022_ACCOUNT_TYPE_OFFSET + 1;
const TOKEN_2022_ACCOUNT_TYPE_MINT: u8 = 1;
const TOKEN_2022_ACCOUNT_TYPE_ACCOUNT: u8 = 2;
const EXT_TRANSFER_FEE_CONFIG: u16 = 1;
const EXT_MINT_CLOSE_AUTHORITY: u16 = 3;
const EXT_IMMUTABLE_OWNER: u16 = 7;
const EXT_MEMO_TRANSFER: u16 = 8;
const EXT_CPI_GUARD: u16 = 11;
const EXT_TRANSFER_HOOK: u16 = 14;
const EXT_METADATA_POINTER: u16 = 18;
const EXT_TOKEN_METADATA: u16 = 19;
const EXT_GROUP_POINTER: u16 = 20;
const EXT_TOKEN_GROUP: u16 = 21;
const EXT_GROUP_MEMBER_POINTER: u16 = 22;
const EXT_TOKEN_GROUP_MEMBER: u16 = 23;
const POINTER_EXTENSION_LEN: usize = 64;
const TOKEN_METADATA_MIN_LEN: usize = 80;
const TOKEN_GROUP_LEN: usize = 80;
const TOKEN_GROUP_MEMBER_LEN: usize = 72;

fn open_ix_data_with_first_recipient(recipient: &Pubkey) -> Vec<u8> {
    let mut data = open_ix_data(SALT, DEPOSIT, GRACE, 1);
    data[FIRST_RECIPIENT_OFFSET..FIRST_RECIPIENT_OFFSET + 32].copy_from_slice(recipient.as_ref());
    data
}

fn set_bps(data: &mut [u8], index: usize, bps: u16) {
    let offset = FIRST_BPS_OFFSET + index * ENTRY_LEN;
    data[offset..offset + 2].copy_from_slice(&bps.to_le_bytes());
}

fn token_balance(svm: &litesvm::LiteSVM, token_account: &Pubkey) -> u64 {
    let acct = svm
        .get_account(token_account)
        .expect("token account exists");
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&acct.data[64..72]);
    u64::from_le_bytes(buf)
}

fn add_mint_extension(
    svm: &mut litesvm::LiteSVM,
    mint: &Pubkey,
    extension_type: u16,
    value_len: usize,
) {
    let mut acct = svm.get_account(mint).expect("mint exists");
    add_token_2022_extension(
        &mut acct.data,
        82,
        TOKEN_2022_ACCOUNT_TYPE_MINT,
        extension_type,
        value_len,
    );
    svm.set_account(*mint, acct).expect("overwrite mint");
}

fn add_account_extension(
    svm: &mut litesvm::LiteSVM,
    token_account: &Pubkey,
    extension_type: u16,
    value_len: usize,
) {
    let mut acct = svm
        .get_account(token_account)
        .expect("token account exists");
    add_token_2022_extension(
        &mut acct.data,
        165,
        TOKEN_2022_ACCOUNT_TYPE_ACCOUNT,
        extension_type,
        value_len,
    );
    svm.set_account(*token_account, acct)
        .expect("overwrite token account");
}

fn add_token_2022_extension(
    data: &mut Vec<u8>,
    base_len: usize,
    account_type: u8,
    extension_type: u16,
    value_len: usize,
) {
    if data.len() < TOKEN_2022_TLV_START {
        data.resize(TOKEN_2022_TLV_START, 0);
    }
    data[base_len..TOKEN_2022_ACCOUNT_TYPE_OFFSET].fill(0);
    data[TOKEN_2022_ACCOUNT_TYPE_OFFSET] = account_type;
    data.extend_from_slice(&extension_type.to_le_bytes());
    data.extend_from_slice(&(value_len as u16).to_le_bytes());
    data.resize(data.len() + value_len, 0);
}

#[test]
fn single_recipient_passes_arg_validation() {
    assert_eq!(
        run_open(open_ix_data(SALT, DEPOSIT, GRACE, 1)),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::ChannelAddressMismatch as u32
        )),
    );
}

#[test]
fn max_recipients_passes_arg_validation() {
    assert_eq!(
        run_open(open_ix_data(
            SALT,
            DEPOSIT,
            GRACE,
            MAX_DISTRIBUTION_RECIPIENTS as u8
        )),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::ChannelAddressMismatch as u32
        )),
    );
}

#[test]
fn bps_zero_rejected() {
    let mut data = open_ix_data(SALT, DEPOSIT, GRACE, 1);
    set_bps(&mut data, 0, 0);

    assert_eq!(
        run_open(data),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::InvalidSplitConfig as u32
        )),
    );
}

#[test]
fn bps_sum_equals_10000_rejected() {
    let mut data = open_ix_data(SALT, DEPOSIT, GRACE, 2);
    set_bps(&mut data, 0, 5000);
    set_bps(&mut data, 1, 5000);

    assert_eq!(
        run_open(data),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::InvalidSplitConfig as u32
        )),
    );
}

#[test]
fn channel_pda_recipient_rejected() {
    let mut svm = load_program();

    let payee = Pubkey::new_unique();
    let authorized_signer = Pubkey::new_unique();
    let (payer, mint, payer_token_account) = setup_funded_svm(&mut svm, DEPOSIT);
    let (channel, channel_token_account) =
        derive_pdas(&payer.pubkey(), &payee, &mint, &authorized_signer, SALT);
    let ix_data = open_ix_data_with_first_recipient(&channel);

    let ix = Instruction::new_with_bytes(
        PROGRAM_ID,
        &ix_data,
        vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(payee, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new_readonly(authorized_signer, false),
            AccountMeta::new(channel, false),
            AccountMeta::new(payer_token_account, false),
            AccountMeta::new(channel_token_account, false),
            AccountMeta::new_readonly(SPL_TOKEN, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            AccountMeta::new_readonly(SYSVAR_RENT, false),
            AccountMeta::new_readonly(ATA_PROGRAM, false),
            AccountMeta::new_readonly(EVENT_AUTHORITY, false),
            AccountMeta::new_readonly(PROGRAM_ID, false),
        ],
    );
    let msg = Message::new(&[ix], Some(&payer.pubkey()));
    let tx = Transaction::new(&[&payer], msg, svm.latest_blockhash());

    expect_custom_err(
        svm.send_transaction(tx),
        PaymentChannelsError::InvalidSplitConfig,
    );
}

#[test]
fn token_2022_allowed_mint_and_immutable_owner_payer_account_extensions_succeed() {
    let mut svm = load_program();

    let payee = Pubkey::new_unique();
    let authorized_signer = Pubkey::new_unique();
    let (payer, mint, payer_token_account) =
        setup_funded_svm_with_token_program(&mut svm, DEPOSIT, &TOKEN_2022);
    for (extension_type, value_len) in [
        (EXT_METADATA_POINTER, POINTER_EXTENSION_LEN),
        (EXT_TOKEN_METADATA, TOKEN_METADATA_MIN_LEN),
        (EXT_GROUP_POINTER, POINTER_EXTENSION_LEN),
        (EXT_TOKEN_GROUP, TOKEN_GROUP_LEN),
        (EXT_GROUP_MEMBER_POINTER, POINTER_EXTENSION_LEN),
        (EXT_TOKEN_GROUP_MEMBER, TOKEN_GROUP_MEMBER_LEN),
    ] {
        add_mint_extension(&mut svm, &mint, extension_type, value_len);
    }
    add_account_extension(&mut svm, &payer_token_account, EXT_IMMUTABLE_OWNER, 0);

    let (channel, channel_token_account) = derive_pdas_with_token_program(
        &payer.pubkey(),
        &payee,
        &mint,
        &authorized_signer,
        SALT,
        &TOKEN_2022,
    );
    let ix = open_ix_with_token_program(
        &payer.pubkey(),
        &payee,
        &mint,
        &authorized_signer,
        &channel,
        &payer_token_account,
        &channel_token_account,
        &TOKEN_2022,
        SALT,
        DEPOSIT,
        GRACE,
        1,
    );
    let msg = Message::new(&[ix], Some(&payer.pubkey()));
    let tx = Transaction::new(&[&payer], msg, svm.latest_blockhash());

    svm.send_transaction(tx).expect("open should succeed");

    assert!(svm.get_account(&channel).is_some());
    assert_eq!(token_balance(&svm, &payer_token_account), 0);
    assert_eq!(token_balance(&svm, &channel_token_account), DEPOSIT);
}

#[test]
fn unsupported_token_2022_mint_extensions_reject_before_channel_creation() {
    for (extension_type, value_len) in [
        (EXT_TRANSFER_FEE_CONFIG, 108),
        (EXT_TRANSFER_HOOK, 64),
        (EXT_MINT_CLOSE_AUTHORITY, 32),
    ] {
        let mut svm = load_program();

        let payee = Pubkey::new_unique();
        let authorized_signer = Pubkey::new_unique();
        let (payer, mint, payer_token_account) =
            setup_funded_svm_with_token_program(&mut svm, DEPOSIT, &TOKEN_2022);
        add_mint_extension(&mut svm, &mint, extension_type, value_len);
        let (channel, channel_token_account) = derive_pdas_with_token_program(
            &payer.pubkey(),
            &payee,
            &mint,
            &authorized_signer,
            SALT,
            &TOKEN_2022,
        );
        let ix = open_ix_with_token_program(
            &payer.pubkey(),
            &payee,
            &mint,
            &authorized_signer,
            &channel,
            &payer_token_account,
            &channel_token_account,
            &TOKEN_2022,
            SALT,
            DEPOSIT,
            GRACE,
            1,
        );
        let msg = Message::new(&[ix], Some(&payer.pubkey()));
        let tx = Transaction::new(&[&payer], msg, svm.latest_blockhash());

        expect_custom_err(
            svm.send_transaction(tx),
            PaymentChannelsError::UnsupportedTokenExtensions,
        );
        assert!(svm.get_account(&channel).is_none());
        assert_eq!(token_balance(&svm, &payer_token_account), DEPOSIT);
    }
}

#[test]
fn unsupported_token_2022_payer_account_extensions_reject_before_channel_creation() {
    for extension_type in [EXT_MEMO_TRANSFER, EXT_CPI_GUARD] {
        let mut svm = load_program();

        let payee = Pubkey::new_unique();
        let authorized_signer = Pubkey::new_unique();
        let (payer, mint, payer_token_account) =
            setup_funded_svm_with_token_program(&mut svm, DEPOSIT, &TOKEN_2022);
        add_account_extension(&mut svm, &payer_token_account, extension_type, 1);
        let (channel, channel_token_account) = derive_pdas_with_token_program(
            &payer.pubkey(),
            &payee,
            &mint,
            &authorized_signer,
            SALT,
            &TOKEN_2022,
        );
        let ix = open_ix_with_token_program(
            &payer.pubkey(),
            &payee,
            &mint,
            &authorized_signer,
            &channel,
            &payer_token_account,
            &channel_token_account,
            &TOKEN_2022,
            SALT,
            DEPOSIT,
            GRACE,
            1,
        );
        let msg = Message::new(&[ix], Some(&payer.pubkey()));
        let tx = Transaction::new(&[&payer], msg, svm.latest_blockhash());

        expect_custom_err(
            svm.send_transaction(tx),
            PaymentChannelsError::UnsupportedTokenExtensions,
        );
        assert!(svm.get_account(&channel).is_none());
        assert_eq!(token_balance(&svm, &payer_token_account), DEPOSIT);
    }
}
