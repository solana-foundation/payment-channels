//! Scalar range-check tests for the `open` instruction.
//!
//! These errors fire during argument validation, before any CPI, so Mollusk
//! (via `run_open`) is sufficient — no LiteSVM chain needed.

use mollusk_svm::result::ProgramResult;
use payment_channels::instructions::open::MAX_DISTRIBUTION_RECIPIENTS;
use solana_program_error::ProgramError;

use super::{open_ix_data, run_open};

const SALT: u64 = 1;
const DEPOSIT: u64 = 1_000_000;
const GRACE: u32 = 3600;

#[test]
fn zero_deposit_rejected() {
    assert_eq!(
        run_open(open_ix_data(SALT, 0, GRACE, 1)),
        ProgramResult::Failure(ProgramError::InvalidInstructionData),
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
