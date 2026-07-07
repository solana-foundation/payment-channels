//! Mollusk guard tests for `reclaim`.
//!
//! Guard order pinned here: status (`Distributed` only) → rent-payer binding →
//! reclaim gate. Each test plants a 256-byte channel blob and exercises
//! exactly one guard.

use mollusk_svm::result::ProgramResult;
use payment_channels::PaymentChannelsError;
use payment_channels::constants::OPEN_SLOT_WINDOW;
use payment_channels::state::channel::ChannelStatus;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

use crate::common::ChannelBuilder;

use super::ReclaimRun;

fn custom_err(e: PaymentChannelsError) -> ProgramResult {
    ProgramResult::Failure(ProgramError::Custom(e as u32))
}

// ---------------------------------------------------------------------------
// Status: only a fully-drained `Distributed` channel may surrender its address.

#[test]
fn open_status_rejects() {
    assert_eq!(
        ReclaimRun::new(ChannelBuilder::new().status(ChannelStatus::Open).build()).run(),
        custom_err(PaymentChannelsError::InvalidChannelStatus),
    );
}

#[test]
fn closing_status_rejects() {
    assert_eq!(
        ReclaimRun::new(ChannelBuilder::new().status(ChannelStatus::Closing).build()).run(),
        custom_err(PaymentChannelsError::InvalidChannelStatus),
    );
}

#[test]
fn sealed_status_rejects() {
    // SEALED still owes its token legs to `distribute`; the rent may not
    // be freed before they are paid.
    assert_eq!(
        ReclaimRun::new(ChannelBuilder::new().status(ChannelStatus::Sealed).build()).run(),
        custom_err(PaymentChannelsError::InvalidChannelStatus),
    );
}

// ---------------------------------------------------------------------------
// Rent-payer binding: the freed rent must go to the funder recorded at
// `open`, not to whoever cranks the permissionless ix.

#[test]
fn wrong_rent_payer_rejects() {
    let recorded = Pubkey::new_unique();
    assert_eq!(
        ReclaimRun {
            rent_payer: Pubkey::new_unique(),
            // Past the gate, so only the rent-payer binding can fire.
            clock_slot: OPEN_SLOT_WINDOW + 1,
            ..ReclaimRun::new(
                ChannelBuilder::new()
                    .status(ChannelStatus::Distributed)
                    .rent_payer(recorded)
                    .build(),
            )
        }
        .run(),
        custom_err(PaymentChannelsError::InvalidChannelRentPayer),
    );
}

// ---------------------------------------------------------------------------
// Reclaim gate: strict `clock.slot > open_slot + OPEN_SLOT_WINDOW`. Keeping
// the address occupied through the window is what guarantees any
// reincarnation's epoch is strictly greater than the dead one's.

#[test]
fn gate_rejects_at_genesis_slot() {
    // Mollusk clock defaults to slot 0 == open_slot: deep inside the window.
    assert_eq!(
        ReclaimRun::new(
            ChannelBuilder::new()
                .status(ChannelStatus::Distributed)
                .build()
        )
        .run(),
        custom_err(PaymentChannelsError::ChannelCloseTooEarly),
    );
}

#[test]
fn gate_rejects_at_exact_window_boundary() {
    // `slot == open_slot + OPEN_SLOT_WINDOW` still fails: the gate is strict.
    assert_eq!(
        ReclaimRun {
            clock_slot: OPEN_SLOT_WINDOW,
            ..ReclaimRun::new(
                ChannelBuilder::new()
                    .status(ChannelStatus::Distributed)
                    .build()
            )
        }
        .run(),
        custom_err(PaymentChannelsError::ChannelCloseTooEarly),
    );
}

#[test]
fn success_drains_and_deallocates_past_gate() {
    let run = ReclaimRun {
        clock_slot: OPEN_SLOT_WINDOW + 1,
        ..ReclaimRun::new(
            ChannelBuilder::new()
                .status(ChannelStatus::Distributed)
                .build(),
        )
    };
    let channel_lamports = run.channel_lamports;
    let rent_payer_lamports = run.rent_payer_lamports;

    let result = run.run_inspect();
    assert_eq!(result.program_result, ProgramResult::Success);

    // Channel slot 0 of the ix: every lamport drained and the data
    // deallocated, so the runtime reaps the account at instruction end.
    let (_, channel_after) = &result.resulting_accounts[0];
    assert_eq!(channel_after.lamports, 0, "channel fully drained");
    assert!(channel_after.data.is_empty(), "channel data deallocated");

    // Rent payer receives the ENTIRE channel balance (rent + any surplus).
    let (_, rent_payer_after) = &result.resulting_accounts[1];
    assert_eq!(
        rent_payer_after.lamports,
        rent_payer_lamports + channel_lamports,
    );
}
