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
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::MissingRequiredSignature as u32
        )),
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
fn closing_status_rejects() {
    let payer = Pubkey::new_unique();
    assert_eq!(
        TopUpRun::new(
            payer,
            ChannelBuilder::new()
                .status(ChannelStatus::Closing)
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
            PaymentChannelsError::InvalidChannelMint as u32
        )),
    );
}

#[test]
fn wrong_expected_open_slot_rejects() {
    // ChannelBuilder leaves `open_slot` at zero; passing a non-zero value
    // for `expected_open_slot` trips the incarnation guard. The mint is
    // aligned so the earlier mint-equality check doesn't short-circuit.
    let payer = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    assert_eq!(
        TopUpRun {
            expected_open_slot: 1,
            mint,
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
            PaymentChannelsError::ChannelSlotMismatch as u32
        )),
    );
}

#[test]
fn closed_channel_rejects() {
    // After FINALIZED `distribute` closes the PDA, the channel data is empty
    // (lamports drained, `resize(0)` clears the buffer). `Channel::load_mut`
    // length-gates inside `unsafe load_mut::<Channel>` before any
    // discriminator/version/status logic runs, so top_up rejects with
    // `InvalidAccountData`.
    assert_eq!(
        TopUpRun::new(Pubkey::new_unique(), Vec::new(), 1).run(),
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
            PaymentChannelsError::InvalidMintTokenProgram as u32
        )),
    );
}
