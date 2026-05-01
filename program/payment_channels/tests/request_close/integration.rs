use mollusk_svm::result::ProgramResult;
use payment_channels::PaymentChannelsError;
use payment_channels::state::Channel;
use payment_channels::state::channel::ChannelStatus;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

use crate::common::ChannelBuilder;

use super::RequestCloseRun;

#[test]
fn unsigned_payer_rejects() {
    let payer = Pubkey::new_unique();
    assert_eq!(
        RequestCloseRun {
            is_signer: false,
            ..RequestCloseRun::new(
                payer,
                ChannelBuilder::new()
                    .status(ChannelStatus::Open)
                    .payer(payer)
                    .build(),
            )
        }
        .run(),
        ProgramResult::Failure(ProgramError::MissingRequiredSignature),
    );
}

#[test]
fn wrong_payer_rejects() {
    let alice = Pubkey::new_unique(); // channel.payer
    let bob = Pubkey::new_unique(); // unauthorized caller
    assert_eq!(
        RequestCloseRun::new(
            bob,
            ChannelBuilder::new()
                .status(ChannelStatus::Open)
                .payer(alice)
                .build(),
        )
        .run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::UnauthorizedPayer as u32
        )),
    );
}

#[test]
fn closing_status_rejects() {
    let payer = Pubkey::new_unique();
    assert_eq!(
        RequestCloseRun::new(
            payer,
            ChannelBuilder::new()
                .status(ChannelStatus::Closing)
                .payer(payer)
                .build(),
        )
        .run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::InvalidChannelStatus as u32
        )),
    );
}

#[test]
fn finalized_status_rejects() {
    let payer = Pubkey::new_unique();
    assert_eq!(
        RequestCloseRun::new(
            payer,
            ChannelBuilder::new()
                .status(ChannelStatus::Finalized)
                .payer(payer)
                .build(),
        )
        .run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::InvalidChannelStatus as u32
        )),
    );
}

// Mollusk's default `clock.unix_timestamp` is 0; seeding pre-state
// `closure_started_at = i64::MIN` makes the post-state stamp
// unambiguously distinguishable.
#[test]
fn open_succeeds_marks_closing_and_stamps_now() {
    let payer = Pubkey::new_unique();
    let result = RequestCloseRun::new(
        payer,
        ChannelBuilder::new()
            .status(ChannelStatus::Open)
            .closure_started_at(i64::MIN)
            .payer(payer)
            .build(),
    )
    .run_inspect();

    assert_eq!(result.program_result, ProgramResult::Success);

    let data = &result.resulting_accounts[1].1.data;
    assert_eq!(data.len(), Channel::LEN);
    assert_eq!(data[3], ChannelStatus::Closing as u8);
    assert_eq!(
        i64::from_le_bytes(data[36..44].try_into().unwrap()),
        0,
        "closure_started_at must equal Mollusk's default unix_timestamp",
    );
}
