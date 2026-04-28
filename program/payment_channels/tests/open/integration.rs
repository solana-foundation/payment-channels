use mollusk_svm::result::ProgramResult;
use payment_channels::PaymentChannelsError;
use payment_channels::instructions::open::MAX_DISTRIBUTION_RECIPIENTS;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

use super::{OpenRun, derive_pdas};

const SALT: u64 = 1;
const DEPOSIT: u64 = 1_000_000;
const GRACE: u32 = 3_600;

#[test]
fn zero_deposit_rejected() {
    assert_eq!(
        OpenRun::new(SALT, 0, GRACE, 1).run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::DepositMustBeNonZero as u32
        )),
    );
}

#[test]
fn zero_recipients_rejected() {
    assert_eq!(
        OpenRun::new(SALT, DEPOSIT, GRACE, 0).run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::InvalidRecipientCount as u32
        )),
    );
}

#[test]
fn too_many_recipients_rejected() {
    assert_eq!(
        OpenRun::new(SALT, DEPOSIT, GRACE, MAX_DISTRIBUTION_RECIPIENTS as u8 + 1).run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::InvalidRecipientCount as u32
        )),
    );
}

#[test]
fn single_recipient_passes_arg_validation() {
    assert_eq!(
        OpenRun::new(SALT, DEPOSIT, GRACE, 1).run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::ChannelAddressMismatch as u32
        )),
    );
}

#[test]
fn max_recipients_passes_arg_validation() {
    assert_eq!(
        OpenRun::new(SALT, DEPOSIT, GRACE, MAX_DISTRIBUTION_RECIPIENTS as u8).run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::ChannelAddressMismatch as u32
        )),
    );
}

#[test]
fn unsigned_payer_rejected() {
    assert_eq!(
        OpenRun {
            payer_is_signer: false,
            ..OpenRun::new(SALT, DEPOSIT, GRACE, 1)
        }
        .run(),
        ProgramResult::Failure(ProgramError::MissingRequiredSignature),
    );
}

#[test]
fn payer_equals_payee_rejected() {
    let same = Pubkey::new_unique();
    assert_eq!(
        OpenRun {
            payer: same,
            payee: same,
            ..OpenRun::new(SALT, DEPOSIT, GRACE, 1)
        }
        .run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::PayerPayeeMustDiffer as u32
        )),
    );
}

#[test]
fn wrong_channel_pda_rejected() {
    let payer = Pubkey::new_unique();
    let payee = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let authorized_signer = Pubkey::new_unique();
    let wrong_channel = Pubkey::new_unique();
    assert_eq!(
        OpenRun {
            payer,
            payee,
            mint,
            authorized_signer,
            channel: wrong_channel,
            ..OpenRun::new(SALT, DEPOSIT, GRACE, 1)
        }
        .run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::ChannelAddressMismatch as u32
        )),
    );
}

#[test]
fn wrong_escrow_ata_rejected() {
    let payer = Pubkey::new_unique();
    let payee = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let authorized_signer = Pubkey::new_unique();
    let (channel, _) = derive_pdas(&payer, &payee, &mint, &authorized_signer, SALT);
    let wrong_ata = Pubkey::new_unique();
    assert_eq!(
        OpenRun {
            payer,
            payee,
            mint,
            authorized_signer,
            channel,
            channel_ata: wrong_ata,
            ..OpenRun::new(SALT, DEPOSIT, GRACE, 1)
        }
        .run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::EscrowAddressMismatch as u32
        )),
    );
}
