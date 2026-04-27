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
    ATA_PROGRAM, EVENT_AUTHORITY, SPL_TOKEN, SYSTEM_PROGRAM, SYSVAR_RENT, derive_pdas,
    open_ix_data, run_open, setup_funded_svm,
};
use crate::common::{PROGRAM_ID, expect_custom_err, load_program};

const SALT: u64 = 1;
const DEPOSIT: u64 = 1_000_000;
const GRACE: u32 = 3600;
const FIRST_RECIPIENT_OFFSET: usize = 1 + 8 + 8 + 4 + 1;

fn open_ix_data_with_first_recipient(recipient: &Pubkey) -> Vec<u8> {
    let mut data = open_ix_data(SALT, DEPOSIT, GRACE, 1);
    data[FIRST_RECIPIENT_OFFSET..FIRST_RECIPIENT_OFFSET + 32].copy_from_slice(recipient.as_ref());
    data
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
