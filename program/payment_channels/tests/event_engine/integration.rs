use mollusk_svm::result::ProgramResult;
use payment_channels::PaymentChannelsError;
use payment_channels::event_engine::EVENT_AUTHORITY_SEED;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

use crate::common::PROGRAM_ID;

use super::EmitEventRun;

fn event_authority_pda() -> Pubkey {
    Pubkey::find_program_address(&[EVENT_AUTHORITY_SEED], &PROGRAM_ID).0
}

#[test]
fn rejects_zero_accounts() {
    assert_eq!(
        EmitEventRun {
            include_authority: false,
            ..EmitEventRun::new(Pubkey::default())
        }
        .run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::NotEnoughAccountKeys as u32
        )),
    );
}

#[test]
fn rejects_extra_accounts() {
    assert_eq!(
        EmitEventRun {
            extra_accounts: vec![Pubkey::new_unique()],
            ..EmitEventRun::new(event_authority_pda())
        }
        .run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::NotEnoughAccountKeys as u32
        )),
    );
}

#[test]
fn rejects_non_signer_authority() {
    assert_eq!(
        EmitEventRun {
            is_signer: false,
            ..EmitEventRun::new(event_authority_pda())
        }
        .run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::MissingRequiredSignature as u32
        )),
    );
}

#[test]
fn rejects_bad_authority() {
    assert_eq!(
        EmitEventRun::new(Pubkey::new_unique()).run(),
        ProgramResult::Failure(ProgramError::Custom(
            PaymentChannelsError::InvalidEventAuthority as u32
        )),
    );
}
