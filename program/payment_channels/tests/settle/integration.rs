use mollusk_svm::result::ProgramResult;
use payment_channels::PaymentChannelsError;
use payment_channels::state::channel::ChannelStatus;
use solana_program_error::ProgramError;

use crate::common::ChannelBuilder;

use super::SettleRun;

#[test]
fn finalized_status_rejects() {
    assert_eq!(
        SettleRun::new(
            ChannelBuilder::new()
                .status(ChannelStatus::Finalized)
                .deposit(1_000_000)
                .build(),
        )
        .run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::InvalidChannelStatus as u32
        )),
    );
}

#[test]
fn closing_status_rejects() {
    assert_eq!(
        SettleRun::new(
            ChannelBuilder::new()
                .status(ChannelStatus::Closing)
                .deposit(1_000_000)
                .build(),
        )
        .run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::InvalidChannelStatus as u32
        )),
    );
}

#[test]
fn closed_channel_rejects() {
    // After FINALIZED `distribute` closes the PDA, the channel data is empty
    // (lamports drained, `resize(0)` clears the buffer). `Channel::load_mut`
    // length-gates inside `unsafe load_mut::<Channel>` before any
    // discriminator/version/status logic runs, so settle rejects with
    // `InvalidAccountData`.
    assert_eq!(
        SettleRun::new(Vec::new()).run(),
        ProgramResult::Failure(ProgramError::InvalidAccountData),
    );
}
