use mollusk_svm::result::ProgramResult;
use payment_channels::PaymentChannelsError;
use payment_channels::state::channel::ChannelStatus;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

use super::{ChannelBuilder, DEPOSIT, run_top_up, run_top_up_custom};

#[test]
fn zero_amount_rejects() {
    let payer = Pubkey::new_unique();
    assert_eq!(
        run_top_up(
            &payer,
            true,
            ChannelBuilder::new()
                .status(ChannelStatus::Open)
                .deposit(DEPOSIT)
                .payer(payer)
                .build(),
            0,
        ),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::DepositMustBeNonZero as u32
        )),
    );
}

#[test]
fn unsigned_payer_rejects() {
    let payer = Pubkey::new_unique();
    assert_eq!(
        run_top_up(
            &payer,
            false,
            ChannelBuilder::new()
                .status(ChannelStatus::Open)
                .deposit(DEPOSIT)
                .payer(payer)
                .build(),
            DEPOSIT,
        ),
        ProgramResult::Failure(ProgramError::MissingRequiredSignature),
    );
}

#[test]
fn non_open_status_rejects() {
    let payer = Pubkey::new_unique();
    assert_eq!(
        run_top_up(
            &payer,
            true,
            ChannelBuilder::new()
                .status(ChannelStatus::Finalized)
                .deposit(DEPOSIT)
                .payer(payer)
                .build(),
            DEPOSIT,
        ),
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
        run_top_up(
            &bob,
            true,
            ChannelBuilder::new()
                .status(ChannelStatus::Open)
                .deposit(DEPOSIT)
                .payer(alice)
                .build(),
            DEPOSIT,
        ),
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
        run_top_up_custom(
            &payer,
            true,
            ChannelBuilder::new()
                .status(ChannelStatus::Open)
                .deposit(DEPOSIT)
                .payer(payer)
                .mint(stored_mint)
                .build(),
            &wrong_mint,
            &Pubkey::new_unique(),
            DEPOSIT,
        ),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::MintAddressMismatch as u32
        )),
    );
}

#[test]
fn wrong_escrow_rejects() {
    let payer = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let wrong_ata = Pubkey::new_unique();
    assert_eq!(
        run_top_up_custom(
            &payer,
            true,
            ChannelBuilder::new()
                .status(ChannelStatus::Open)
                .deposit(DEPOSIT)
                .payer(payer)
                .mint(mint)
                .build(),
            &mint,
            &wrong_ata,
            DEPOSIT,
        ),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::EscrowAddressMismatch as u32
        )),
    );
}
