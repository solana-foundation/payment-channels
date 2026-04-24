//! Account validation tests for the `open` instruction.
//!
//! Signer checks use Mollusk (fire before any CPI).
//! PDA / ATA key checks use LiteSVM (fire after the channel is initialised).

use mollusk_svm::result::ProgramResult;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::Message;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

use super::{derive_pdas, load_mollusk, open_ix, open_ix_data, run_open, setup_funded_svm};
use crate::common::{PROGRAM_ID, load_program};

const SALT: u64 = 1;
const DEPOSIT: u64 = 1_000_000;
const GRACE: u32 = 3600;

// ----- signer checks (Mollusk) -----------------------------------------------

/// A signed payer advances past signer validation and fails at the channel-address
/// check (`InvalidAccountData`) because the dummy channel pubkey is not the PDA.
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

// ----- PDA / ATA key checks (LiteSVM) ----------------------------------------

#[test]
fn wrong_channel_pda_rejected() {
    let mut svm = load_program();

    let payee = Pubkey::new_unique();
    let authorized_signer = Pubkey::new_unique();
    let (payer, mint, payer_token_account) = setup_funded_svm(&mut svm, DEPOSIT);
    let (_, channel_token_account) =
        derive_pdas(&payer.pubkey(), &payee, &mint, &authorized_signer, SALT);
    let wrong_channel = Pubkey::new_unique();

    let ix = open_ix(
        &payer.pubkey(),
        &payee,
        &mint,
        &authorized_signer,
        &wrong_channel,
        &payer_token_account,
        &channel_token_account,
        SALT,
        DEPOSIT,
        GRACE,
        1,
    );
    let msg = Message::new(&[ix], Some(&payer.pubkey()));
    let tx = Transaction::new(&[&payer], msg, svm.latest_blockhash());
    let err = svm.send_transaction(tx).unwrap_err();

    use solana_instruction::error::InstructionError;
    use solana_transaction_error::TransactionError;
    assert!(
        matches!(
            err.err,
            TransactionError::InstructionError(_, InstructionError::InvalidAccountData)
        ),
        "expected InvalidAccountData, got {:?}",
        err.err
    );
}

#[test]
fn wrong_escrow_ata_rejected() {
    let mut svm = load_program();

    let payee = Pubkey::new_unique();
    let authorized_signer = Pubkey::new_unique();
    let (payer, mint, payer_token_account) = setup_funded_svm(&mut svm, DEPOSIT);
    let (channel, _) = derive_pdas(&payer.pubkey(), &payee, &mint, &authorized_signer, SALT);
    let wrong_ata = Pubkey::new_unique();

    let ix = open_ix(
        &payer.pubkey(),
        &payee,
        &mint,
        &authorized_signer,
        &channel,
        &payer_token_account,
        &wrong_ata,
        SALT,
        DEPOSIT,
        GRACE,
        1,
    );
    let msg = Message::new(&[ix], Some(&payer.pubkey()));
    let tx = Transaction::new(&[&payer], msg, svm.latest_blockhash());
    let err = svm.send_transaction(tx).unwrap_err();

    use solana_instruction::error::InstructionError;
    use solana_transaction_error::TransactionError;
    assert!(
        matches!(
            err.err,
            TransactionError::InstructionError(_, InstructionError::InvalidAccountData)
        ),
        "expected InvalidAccountData, got {:?}",
        err.err
    );
}
