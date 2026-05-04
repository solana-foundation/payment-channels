use mollusk_svm::result::ProgramResult;
use payment_channels::PaymentChannelsError;
use payment_channels::state::channel::ChannelStatus;
use solana_program_error::ProgramError;

use crate::common::ChannelBuilder;

use super::FinalizeRun;

fn channel_data(result: &mollusk_svm::result::InstructionResult) -> &[u8] {
    &result.resulting_accounts[0].1.data
}

// closure_started_at = 1, grace_period = 3600 → deadline = 3601.
// Mollusk clock defaults to unix_timestamp = 0, so 0 < 3601 = mid-grace. ✓
const CLOSURE_STARTED_AT_MID_GRACE: i64 = 1;
const GRACE_PERIOD: u32 = 3600;

// closure_started_at = -1, grace_period = 0 → deadline = -1.
// now (0) >= -1 → post-grace. ✓
const CLOSURE_STARTED_AT_POST_GRACE: i64 = -1;
const GRACE_PERIOD_ZERO: u32 = 0;

// closure_started_at = -100, grace_period = 100 → deadline = 0.
// now (0) >= 0 → exactly at boundary. ✓
const CLOSURE_STARTED_AT_AT_DEADLINE: i64 = -100;
const GRACE_PERIOD_100: u32 = 100;

#[test]
fn open_status_rejects() {
    assert_eq!(
        FinalizeRun::new(ChannelBuilder::new().status(ChannelStatus::Open).build(),).run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::InvalidChannelStatus as u32
        )),
    );
}

#[test]
fn finalized_status_rejects() {
    assert_eq!(
        FinalizeRun::new(
            ChannelBuilder::new()
                .status(ChannelStatus::Finalized)
                .build(),
        )
        .run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::InvalidChannelStatus as u32
        )),
    );
}

#[test]
fn closing_mid_grace_rejects() {
    assert_eq!(
        FinalizeRun::new(
            ChannelBuilder::new()
                .status(ChannelStatus::Closing)
                .closure_started_at(CLOSURE_STARTED_AT_MID_GRACE)
                .grace_period(GRACE_PERIOD)
                .build(),
        )
        .run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::InvalidChannelStatus as u32
        )),
    );
}

#[test]
fn closing_at_exact_deadline_succeeds() {
    assert_eq!(
        FinalizeRun::new(
            ChannelBuilder::new()
                .status(ChannelStatus::Closing)
                .closure_started_at(CLOSURE_STARTED_AT_AT_DEADLINE)
                .grace_period(GRACE_PERIOD_100)
                .build(),
        )
        .run(),
        ProgramResult::Success,
    );
}

#[test]
fn closing_post_grace_succeeds() {
    assert_eq!(
        FinalizeRun::new(
            ChannelBuilder::new()
                .status(ChannelStatus::Closing)
                .closure_started_at(CLOSURE_STARTED_AT_POST_GRACE)
                .grace_period(GRACE_PERIOD_ZERO)
                .build(),
        )
        .run(),
        ProgramResult::Success,
    );
}

#[test]
fn closing_post_grace_writes_status_and_clears_timestamp() {
    let result = FinalizeRun::new(
        ChannelBuilder::new()
            .status(ChannelStatus::Closing)
            .closure_started_at(CLOSURE_STARTED_AT_POST_GRACE)
            .grace_period(GRACE_PERIOD_ZERO)
            .build(),
    )
    .run_inspect();

    assert_eq!(result.program_result, ProgramResult::Success);
    let data = channel_data(&result);
    assert_eq!(data[3], ChannelStatus::Finalized as u8);
    assert_eq!(i64::from_le_bytes(data[36..44].try_into().unwrap()), 0i64);
}
