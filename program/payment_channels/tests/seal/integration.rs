use mollusk_svm::result::ProgramResult;
use payment_channels::PaymentChannelsError;
use payment_channels::state::channel::ChannelStatus;
use solana_program_error::ProgramError;

use crate::common::ChannelBuilder;

use super::SealRun;

#[test]
fn open_status_rejects() {
    assert_eq!(
        SealRun::new(ChannelBuilder::new().status(ChannelStatus::Open).build()).run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::InvalidChannelStatus as u32
        )),
    );
}

#[test]
fn sealed_status_rejects() {
    assert_eq!(
        SealRun::new(ChannelBuilder::new().status(ChannelStatus::Sealed).build()).run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::InvalidChannelStatus as u32
        )),
    );
}
