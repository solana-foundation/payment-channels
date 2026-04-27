//! Account-level validation tests for the `topUp` instruction.
//!
//! These errors fire before the token CPI, so Mollusk is sufficient.

use mollusk_svm::result::ProgramResult;
use payment_channels::PaymentChannelsError;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

use super::{DEPOSIT, channel_data, run_top_up};

#[test]
fn unsigned_payer_rejects() {
    let payer = Pubkey::new_unique();
    assert_eq!(
        run_top_up(&payer, false, channel_data(0, DEPOSIT, &payer), DEPOSIT),
        ProgramResult::Failure(ProgramError::MissingRequiredSignature),
    );
}

#[test]
fn non_open_status_rejects() {
    let payer = Pubkey::new_unique();
    assert_eq!(
        run_top_up(
            &payer,
            true,
            channel_data(1 /* Finalized */, DEPOSIT, &payer),
            DEPOSIT
        ),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::InvalidChannelStatus as u32
        )),
    );
}

#[test]
fn wrong_payer_rejects() {
    let alice = Pubkey::new_unique(); // channel.payer
    let bob = Pubkey::new_unique(); // unauthorized caller
    assert_eq!(
        run_top_up(&bob, true, channel_data(0, DEPOSIT, &alice), DEPOSIT),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::UnauthorizedPayer as u32
        )),
    );
}
