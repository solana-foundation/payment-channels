//! Distribution-plan validation tests for the `open` instruction.
//!
//! Verifies that well-formed plans (any count in 1..=MAX) advance past plan
//! parsing and reach the channel-address check (`InvalidAccountData`).
//! Out-of-range counts are covered in `bounds.rs`.

use mollusk_svm::result::ProgramResult;
use payment_channels::PaymentChannelsError;
use payment_channels::instructions::open::MAX_DISTRIBUTION_RECIPIENTS;
use solana_program_error::ProgramError;

use super::{open_ix_data, run_open};

const SALT: u64 = 1;
const DEPOSIT: u64 = 1_000_000;
const GRACE: u32 = 3600;

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
