use mollusk_svm::result::ProgramResult;
use payment_channels::PaymentChannelsError;
use payment_channels::state::Channel;
use payment_channels::state::channel::ChannelStatus;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

use crate::common::ChannelBuilder;

use super::SettleAndFinalizeRun;

fn channel(result: &mollusk_svm::result::InstructionResult) -> &Channel {
    let data = &result.resulting_accounts[1].1.data;
    assert_eq!(data.len(), Channel::LEN, "channel blob length mismatch");
    // SAFETY: `Channel` is `#[repr(C)]` with `align_of == 1`.
    unsafe { &*(data.as_ptr() as *const Channel) }
}

// closure_started_at = 1, grace_period = 3600 → deadline = 3601.
// Mollusk clock defaults to unix_timestamp = 0, so 0 < 3601 = mid-grace. ✓
const CLOSURE_STARTED_AT_MID_GRACE: i64 = 1;
const GRACE_PERIOD: u32 = 3600;

// closure_started_at = -1, grace_period = 0 → deadline = -1.
// now (0) >= -1 → post-grace. ✓
const CLOSURE_STARTED_AT_POST_GRACE: i64 = -1;
const GRACE_PERIOD_ZERO: u32 = 0;

#[test]
fn unsigned_merchant_rejects() {
    let merchant = Pubkey::new_unique();
    assert_eq!(
        SettleAndFinalizeRun {
            is_signer: false,
            ..SettleAndFinalizeRun::new(
                merchant,
                ChannelBuilder::new()
                    .status(ChannelStatus::Open)
                    .payee(merchant)
                    .build(),
            )
        }
        .run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::MissingRequiredSignature as u32
        )),
    );
}

#[test]
fn wrong_expected_open_slot_rejects() {
    // No-voucher path: channel blob has open_slot=0; a non-zero
    // `expected_open_slot` trips the incarnation guard.
    let merchant = Pubkey::new_unique();
    assert_eq!(
        SettleAndFinalizeRun {
            expected_open_slot: 1,
            ..SettleAndFinalizeRun::new(
                merchant,
                ChannelBuilder::new()
                    .status(ChannelStatus::Open)
                    .payee(merchant)
                    .build(),
            )
        }
        .run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::ChannelSlotMismatch as u32
        )),
    );
}

#[test]
fn finalized_status_rejects() {
    let merchant = Pubkey::new_unique();
    assert_eq!(
        SettleAndFinalizeRun::new(
            merchant,
            ChannelBuilder::new()
                .status(ChannelStatus::Finalized)
                .payee(merchant)
                .build(),
        )
        .run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::InvalidChannelStatus as u32
        )),
    );
}

#[test]
fn closing_post_grace_rejects() {
    let merchant = Pubkey::new_unique();
    assert_eq!(
        SettleAndFinalizeRun::new(
            merchant,
            ChannelBuilder::new()
                .status(ChannelStatus::Closing)
                .payee(merchant)
                .closure_started_at(CLOSURE_STARTED_AT_POST_GRACE)
                .grace_period(GRACE_PERIOD_ZERO)
                .build(),
        )
        .run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::InvalidChannelStatus as u32
        )),
    );
}

#[test]
fn wrong_merchant_rejects() {
    let payee = Pubkey::new_unique();
    let impostor = Pubkey::new_unique();
    assert_eq!(
        SettleAndFinalizeRun::new(
            impostor,
            ChannelBuilder::new()
                .status(ChannelStatus::Open)
                .payee(payee)
                .build(),
        )
        .run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::InvalidChannelPayee as u32
        )),
    );
}

#[test]
fn open_to_finalized_without_voucher_succeeds() {
    let merchant = Pubkey::new_unique();
    assert_eq!(
        SettleAndFinalizeRun::new(
            merchant,
            ChannelBuilder::new()
                .status(ChannelStatus::Open)
                .payee(merchant)
                .build(),
        )
        .run(),
        ProgramResult::Success,
    );
}

#[test]
fn closing_to_finalized_mid_grace_without_voucher_succeeds() {
    let merchant = Pubkey::new_unique();
    assert_eq!(
        SettleAndFinalizeRun::new(
            merchant,
            ChannelBuilder::new()
                .status(ChannelStatus::Closing)
                .payee(merchant)
                .closure_started_at(CLOSURE_STARTED_AT_MID_GRACE)
                .grace_period(GRACE_PERIOD)
                .build(),
        )
        .run(),
        ProgramResult::Success,
    );
}

/// Wrong merchant on CLOSING path (mid-grace): still fails on authority check,
/// not on the grace-period check.
#[test]
fn closing_wrong_merchant_rejects() {
    let payee = Pubkey::new_unique();
    let impostor = Pubkey::new_unique();
    assert_eq!(
        SettleAndFinalizeRun::new(
            impostor,
            ChannelBuilder::new()
                .status(ChannelStatus::Closing)
                .payee(payee)
                .closure_started_at(CLOSURE_STARTED_AT_MID_GRACE)
                .grace_period(GRACE_PERIOD)
                .build(),
        )
        .run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::InvalidChannelPayee as u32
        )),
    );
}

#[test]
fn open_to_finalized_writes_status() {
    let merchant = Pubkey::new_unique();
    let result = SettleAndFinalizeRun::new(
        merchant,
        ChannelBuilder::new()
            .status(ChannelStatus::Open)
            .payee(merchant)
            .build(),
    )
    .run_inspect();
    assert_eq!(result.program_result, ProgramResult::Success);
    let ch = channel(&result);
    assert_eq!(ch.status, ChannelStatus::Finalized as u8);
    assert_eq!(ch.closure_started_at(), 0i64);
}

#[test]
fn closing_mid_grace_resets_closure_started_at() {
    let merchant = Pubkey::new_unique();
    let result = SettleAndFinalizeRun::new(
        merchant,
        ChannelBuilder::new()
            .status(ChannelStatus::Closing)
            .payee(merchant)
            .closure_started_at(CLOSURE_STARTED_AT_MID_GRACE)
            .grace_period(GRACE_PERIOD)
            .settled(200_000)
            .build(),
    )
    .run_inspect();
    assert_eq!(result.program_result, ProgramResult::Success);
    let ch = channel(&result);
    assert_eq!(ch.status, ChannelStatus::Finalized as u8);
    assert_eq!(ch.closure_started_at(), 0i64);
    assert_eq!(ch.settled(), 200_000u64);
}
