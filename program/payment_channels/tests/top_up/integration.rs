use mollusk_svm::result::ProgramResult;
use payment_channels_core::PaymentChannelsError;
use payment_channels_core::state::channel::ChannelStatus;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

use crate::common::ChannelBuilder;

use super::{DEPOSIT, TopUpRun};

#[test]
fn zero_amount_rejects() {
    let payer = Pubkey::new_unique();
    assert_eq!(
        TopUpRun::new(
            payer,
            ChannelBuilder::new()
                .status(ChannelStatus::Open)
                .deposit(DEPOSIT)
                .payer(payer)
                .build(),
            0,
        )
        .run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::DepositMustBeNonZero as u32
        )),
    );
}

#[test]
fn unsigned_payer_rejects() {
    let payer = Pubkey::new_unique();
    assert_eq!(
        TopUpRun {
            is_signer: false,
            ..TopUpRun::new(
                payer,
                ChannelBuilder::new()
                    .status(ChannelStatus::Open)
                    .deposit(DEPOSIT)
                    .payer(payer)
                    .build(),
                DEPOSIT,
            )
        }
        .run(),
        ProgramResult::Failure(ProgramError::MissingRequiredSignature),
    );
}

#[test]
fn non_open_status_rejects() {
    let payer = Pubkey::new_unique();
    assert_eq!(
        TopUpRun::new(
            payer,
            ChannelBuilder::new()
                .status(ChannelStatus::Finalized)
                .deposit(DEPOSIT)
                .payer(payer)
                .build(),
            DEPOSIT,
        )
        .run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::InvalidChannelStatus as u32
        )),
    );
}

#[test]
fn wrong_payer_rejects() {
    let alice = Pubkey::new_unique(); // channel.payer
    let bob = Pubkey::new_unique(); // unauthorized caller
    assert_eq!(
        TopUpRun::new(
            bob,
            ChannelBuilder::new()
                .status(ChannelStatus::Open)
                .deposit(DEPOSIT)
                .payer(alice)
                .build(),
            DEPOSIT,
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
        TopUpRun {
            mint: wrong_mint,
            ..TopUpRun::new(
                payer,
                ChannelBuilder::new()
                    .status(ChannelStatus::Open)
                    .deposit(DEPOSIT)
                    .payer(payer)
                    .mint(stored_mint)
                    .build(),
                DEPOSIT,
            )
        }
        .run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::MintAccountMismatch as u32
        )),
    );
}

#[test]
fn tombstoned_channel_rejects() {
    // After FINALIZED `distribute` tombstones the PDA, the channel data
    // shrinks to a 1-byte `ClosedChannel` payload (discriminator = 2).
    // `Channel::load_mut` length-gates inside `unsafe load_mut::<Channel>`
    // before any discriminator/version/status logic runs, so top_up
    // rejects with `InvalidAccountData`.
    assert_eq!(
        TopUpRun::new(Pubkey::new_unique(), vec![2u8], 1).run(),
        ProgramResult::Failure(ProgramError::InvalidAccountData),
    );
}

#[test]
fn unknown_token_program_rejects() {
    // `validate_mint` runs after the mint-equality check and rejects any
    // `token_program` other than SPL Token or Token-2022.
    let payer = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let unknown_token_program = Pubkey::new_unique();
    assert_eq!(
        TopUpRun {
            mint,
            token_program: unknown_token_program,
            ..TopUpRun::new(
                payer,
                ChannelBuilder::new()
                    .status(ChannelStatus::Open)
                    .deposit(DEPOSIT)
                    .payer(payer)
                    .mint(mint)
                    .build(),
                DEPOSIT,
            )
        }
        .run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::InvalidTokenProgram as u32
        )),
    );
}
