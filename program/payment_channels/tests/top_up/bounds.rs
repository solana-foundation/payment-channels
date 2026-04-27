//! Scalar range-check tests for the `topUp` instruction.
//!
//! These errors fire during argument validation, before any channel load,
//! so Mollusk is sufficient — no LiteSVM chain needed.

use mollusk_svm::result::ProgramResult;
use payment_channels::PaymentChannelsError;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

use super::{DEPOSIT, channel_data, run_top_up};

#[test]
fn zero_amount_rejects() {
    let payer = Pubkey::new_unique();
    assert_eq!(
        run_top_up(&payer, true, channel_data(0, DEPOSIT, &payer), 0),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::DepositMustBeNonZero as u32
        )),
    );
}
