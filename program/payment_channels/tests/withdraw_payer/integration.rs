use mollusk_svm::result::ProgramResult;
use payment_channels_core::{PaymentChannelsError, state::channel::ChannelStatus};
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

use crate::common::ChannelBuilder;

use super::WithdrawPayerRun;

fn finalized_channel(payer: Pubkey) -> Vec<u8> {
    ChannelBuilder::new()
        .status(ChannelStatus::Finalized)
        .payer(payer)
        .build()
}

#[test]
fn open_status_rejects() {
    let payer = Pubkey::new_unique();
    assert_eq!(
        WithdrawPayerRun::new(
            payer,
            ChannelBuilder::new()
                .status(ChannelStatus::Open)
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
fn closing_status_rejects() {
    let payer = Pubkey::new_unique();
    assert_eq!(
        WithdrawPayerRun::new(
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
fn already_withdrawn_rejects() {
    let payer = Pubkey::new_unique();
    assert_eq!(
        WithdrawPayerRun::new(
            payer,
            ChannelBuilder::new()
                .status(ChannelStatus::Finalized)
                .payer(payer)
                .payer_withdrawn_at(1)
                .build(),
        )
        .run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::PayerAlreadyWithdrawn as u32
        )),
    );
}

#[test]
fn unsigned_payer_rejects() {
    let payer = Pubkey::new_unique();
    assert_eq!(
        WithdrawPayerRun {
            is_signer: false,
            ..WithdrawPayerRun::new(payer, finalized_channel(payer))
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
        WithdrawPayerRun::new(
            bob,
            ChannelBuilder::new()
                .status(ChannelStatus::Finalized)
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
fn wrong_mint_rejects() {
    let payer = Pubkey::new_unique();
    let stored_mint = Pubkey::new_unique();
    let wrong_mint = Pubkey::new_unique();
    assert_eq!(
        WithdrawPayerRun {
            mint: wrong_mint,
            ..WithdrawPayerRun::new(
                payer,
                ChannelBuilder::new()
                    .status(ChannelStatus::Finalized)
                    .payer(payer)
                    .mint(stored_mint)
                    .build(),
            )
        }
        .run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::MintAccountMismatch as u32
        )),
    );
}

#[test]
fn unknown_token_program_rejects() {
    let payer = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let unknown_token_program = Pubkey::new_unique();
    assert_eq!(
        WithdrawPayerRun {
            mint,
            token_program: unknown_token_program,
            ..WithdrawPayerRun::new(
                payer,
                ChannelBuilder::new()
                    .status(ChannelStatus::Finalized)
                    .payer(payer)
                    .mint(mint)
                    .build(),
            )
        }
        .run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::InvalidTokenProgram as u32
        )),
    );
}

#[test]
fn tombstoned_channel_rejects() {
    assert_eq!(
        WithdrawPayerRun::new(Pubkey::new_unique(), vec![2u8]).run(),
        ProgramResult::Failure(ProgramError::InvalidAccountData),
    );
}
