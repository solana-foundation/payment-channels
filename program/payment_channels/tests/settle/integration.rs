use mollusk_svm::result::ProgramResult;
use payment_channels::PaymentChannelsError;
use payment_channels::state::channel::ChannelStatus;
use solana_program_error::ProgramError;

use crate::common::ChannelBuilder;

use super::SettleRun;

#[test]
fn sealed_status_rejects() {
    assert_eq!(
        SettleRun::new(
            ChannelBuilder::new()
                .status(ChannelStatus::Sealed)
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
fn legacy_tombstone_account_rejects() {
    // 1-byte accounts carrying the reserved `ClosedChannel` discriminator
    // (= 2) are leftovers of the pre-launch deployment's tombstone close;
    // the program no longer produces them — a fully closed channel is
    // deallocated entirely. `Channel::load_mut` length-gates inside
    // `unsafe load_mut::<Channel>` before any discriminator/version/status
    // logic runs, so settle rejects with `InvalidAccountData`.
    assert_eq!(
        SettleRun::new(vec![2u8]).run(),
        ProgramResult::Failure(ProgramError::InvalidAccountData),
    );
}
