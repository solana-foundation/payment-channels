use mollusk_svm::result::ProgramResult;
use payment_channels::PaymentChannelsError;
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
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::MissingRequiredSignature as u32
        )),
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
            PaymentChannelsError::InvalidChannelPayer as u32
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
fn sealed_status_rejects() {
    let payer = Pubkey::new_unique();
    assert_eq!(
        RequestCloseRun::new(
            payer,
            ChannelBuilder::new()
                .status(ChannelStatus::Sealed)
                .payer(payer)
                .build(),
        )
        .run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::InvalidChannelStatus as u32
        )),
    );
}

/// The exact-slice destructure rejects extra accounts (surfaced as the
/// custom NotEnoughAccountKeys, despite the too-many direction).
#[test]
fn extra_account_rejects() {
    let payer = Pubkey::new_unique();
    assert_eq!(
        RequestCloseRun {
            extra_accounts: vec![solana_instruction::AccountMeta::new_readonly(
                Pubkey::new_unique(),
                false
            )],
            ..RequestCloseRun::new(
                payer,
                ChannelBuilder::new()
                    .status(ChannelStatus::Open)
                    .payer(payer)
                    .build(),
            )
        }
        .run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::NotEnoughAccountKeys as u32
        )),
    );
}
