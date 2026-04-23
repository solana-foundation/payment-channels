//! Tests for distribution-plan parsing in the `open` instruction.
//!
//! `open` accepts the plan directly as typed `(recipient: Address, amount: u64)`
//! pairs (up to 30). It computes `blake3(num_recipients_byte || active_entry_bytes)`
//! on-chain and stores the digest in `Channel::distribution_hash`.
//!
//! These tests verify argument validation (num_recipients bounds) and that
//! well-formed plans advance past plan parsing to event emission.

use mollusk_svm::{Mollusk, result::ProgramResult};
use payment_channels::instructions::open::MAX_DISTRIBUTION_RECIPIENTS;
use payment_channels::state::Channel;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

use super::{PROGRAM_ID, open_ix_data, so_path};

const SALT: u64 = 1;
const DEPOSIT: u64 = 1_000_000;
const GRACE: u32 = 3600;

fn load_mollusk() -> Mollusk {
    let path = so_path();
    let elf = mollusk_svm::file::read_file(&path);
    let mut m = Mollusk::default();
    m.add_program_with_loader_and_elf(
        &PROGRAM_ID,
        &mollusk_svm::program::loader_keys::LOADER_V3,
        &elf,
    );
    m
}

/// Execute `open` with dummy accounts and the given instruction data.
/// Execution will either fail on arg validation (`InvalidInstructionData`)
/// or proceed past it and fail at the server-side channel-address check
/// (`InvalidAccountData`) — because the dummy channel pubkey is not the
/// derived PDA.
fn run_open(ix_data: Vec<u8>) -> ProgramResult {
    let mollusk = load_mollusk();

    let ix = Instruction::new_with_bytes(
        PROGRAM_ID,
        &ix_data,
        vec![
            AccountMeta::new(Pubkey::new_unique(), true), // payer
            AccountMeta::new_readonly(Pubkey::new_unique(), false), // payee
            AccountMeta::new_readonly(Pubkey::new_unique(), false), // mint
            AccountMeta::new_readonly(Pubkey::new_unique(), false), // authorized_signer
            AccountMeta::new(Pubkey::new_unique(), false), // channel
            AccountMeta::new(Pubkey::new_unique(), false), // payer_token_account
            AccountMeta::new(Pubkey::new_unique(), false), // channel_token_account
            AccountMeta::new_readonly(Pubkey::new_unique(), false), // token_program
            AccountMeta::new_readonly(Pubkey::new_unique(), false), // system_program
            AccountMeta::new_readonly(Pubkey::new_unique(), false), // rent
            AccountMeta::new_readonly(Pubkey::new_unique(), false), // associated_token_program
            AccountMeta::new_readonly(Pubkey::new_unique(), false), // event_authority (wrong PDA)
            AccountMeta::new_readonly(PROGRAM_ID, false), // self_program
        ],
    );

    let dummy = Account {
        lamports: 1_000_000,
        ..Default::default()
    };
    // The channel account must have Channel::LEN bytes so init_at's size check
    // passes and execution reaches event emission (where the wrong PDA is caught).
    let channel_account = Account {
        lamports: 1_000_000,
        data: vec![0u8; Channel::LEN],
        ..Default::default()
    };
    let accounts: Vec<(Pubkey, Account)> = ix
        .accounts
        .iter()
        .filter(|m| m.pubkey != PROGRAM_ID)
        .map(|m| {
            let acc = if m.pubkey == ix.accounts[4].pubkey {
                channel_account.clone()
            } else {
                dummy.clone()
            };
            (m.pubkey, acc)
        })
        .collect();

    mollusk.process_instruction(&ix, &accounts).program_result
}

/// A signed payer passes the signer check and advances to the channel-address
/// validation, which fails with `InvalidAccountData` because the dummy channel
/// pubkey is not the derived PDA.
#[test]
fn signed_payer_accepted() {
    assert_eq!(
        run_open(open_ix_data(SALT, DEPOSIT, GRACE, 1)),
        ProgramResult::Failure(ProgramError::InvalidAccountData),
    );
}

#[test]
fn unsigned_payer_rejected() {
    let mollusk = load_mollusk();

    let ix = Instruction::new_with_bytes(
        PROGRAM_ID,
        &open_ix_data(SALT, DEPOSIT, GRACE, 1),
        vec![
            AccountMeta::new(Pubkey::new_unique(), false), // payer — NOT a signer
            AccountMeta::new_readonly(Pubkey::new_unique(), false), // payee
            AccountMeta::new_readonly(Pubkey::new_unique(), false), // mint
            AccountMeta::new_readonly(Pubkey::new_unique(), false), // authorized_signer
            AccountMeta::new(Pubkey::new_unique(), false), // channel
            AccountMeta::new(Pubkey::new_unique(), false), // payer_token_account
            AccountMeta::new(Pubkey::new_unique(), false), // channel_token_account
            AccountMeta::new_readonly(Pubkey::new_unique(), false), // token_program
            AccountMeta::new_readonly(Pubkey::new_unique(), false), // system_program
            AccountMeta::new_readonly(Pubkey::new_unique(), false), // rent
            AccountMeta::new_readonly(Pubkey::new_unique(), false), // associated_token_program
            AccountMeta::new_readonly(Pubkey::new_unique(), false), // event_authority
            AccountMeta::new_readonly(PROGRAM_ID, false),  // self_program
        ],
    );

    let dummy = Account {
        lamports: 1_000_000,
        ..Default::default()
    };
    let accounts: Vec<(Pubkey, Account)> = ix
        .accounts
        .iter()
        .filter(|m| m.pubkey != PROGRAM_ID)
        .map(|m| (m.pubkey, dummy.clone()))
        .collect();

    assert_eq!(
        mollusk.process_instruction(&ix, &accounts).program_result,
        ProgramResult::Failure(ProgramError::MissingRequiredSignature),
    );
}

#[test]
fn zero_recipients_rejected() {
    assert_eq!(
        run_open(open_ix_data(SALT, DEPOSIT, GRACE, 0)),
        ProgramResult::Failure(ProgramError::InvalidInstructionData),
    );
}

#[test]
fn too_many_recipients_rejected() {
    assert_eq!(
        run_open(open_ix_data(
            SALT,
            DEPOSIT,
            GRACE,
            MAX_DISTRIBUTION_RECIPIENTS as u8 + 1
        )),
        ProgramResult::Failure(ProgramError::InvalidInstructionData),
    );
}

/// A valid plan must pass arg validation (blake3 hash runs without error)
/// then fail at the channel-address check with `InvalidAccountData`.
#[test]
fn single_recipient_passes_arg_validation() {
    assert_eq!(
        run_open(open_ix_data(SALT, DEPOSIT, GRACE, 1)),
        ProgramResult::Failure(ProgramError::InvalidAccountData),
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
        ProgramResult::Failure(ProgramError::InvalidAccountData),
    );
}
