use mollusk_svm::result::ProgramResult;
use payment_channels::PaymentChannelsError;
use payment_channels::state::channel::ChannelStatus;
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
fn wrong_escrow_rejects() {
    let payer = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let wrong_ata = Pubkey::new_unique();
    assert_eq!(
        TopUpRun {
            mint,
            channel_ata: wrong_ata,
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
            PaymentChannelsError::EscrowAddressMismatch as u32
        )),
    );
}
