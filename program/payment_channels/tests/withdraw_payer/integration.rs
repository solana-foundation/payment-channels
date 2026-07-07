use mollusk_svm::result::ProgramResult;
use payment_channels::PaymentChannelsError;
use payment_channels::state::channel::ChannelStatus;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

use crate::common::ChannelBuilder;

use super::WithdrawPayerRun;

fn sealed_channel(payer: Pubkey) -> Vec<u8> {
    ChannelBuilder::new()
        .status(ChannelStatus::Sealed)
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
                .status(ChannelStatus::Sealed)
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
            ..WithdrawPayerRun::new(payer, sealed_channel(payer))
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
        WithdrawPayerRun::new(
            bob,
            ChannelBuilder::new()
                .status(ChannelStatus::Sealed)
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
                    .status(ChannelStatus::Sealed)
                    .payer(payer)
                    .mint(stored_mint)
                    .build(),
            )
        }
        .run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::InvalidChannelMint as u32
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
                    .status(ChannelStatus::Sealed)
                    .payer(payer)
                    .mint(mint)
                    .build(),
            )
        }
        .run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::InvalidMintTokenProgram as u32
        )),
    );
}

#[test]
fn legacy_tombstone_account_rejects() {
    // 1-byte accounts carrying the reserved `ClosedChannel` discriminator
    // (= 2) are leftovers of the pre-launch deployment's tombstone close;
    // the program no longer produces them — a fully closed channel is
    // deallocated entirely. The 1-byte buffer fails `Channel::load_mut`'s
    // length gate, so withdraw_payer rejects with `InvalidAccountData`.
    assert_eq!(
        WithdrawPayerRun::new(Pubkey::new_unique(), vec![2u8]).run(),
        ProgramResult::Failure(ProgramError::InvalidAccountData),
    );
}
