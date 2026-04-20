use pinocchio::{AccountView, Address, ProgramResult, error::ProgramError};

use crate::event_engine::verify_event_authority;

pub const DISCRIMINATOR: u8 = crate::event_engine::EMIT_EVENT_IX_DISC;

/// No-op self-CPI target; only the event authority PDA may invoke.
pub fn process(_program_id: &Address, accounts: &[AccountView]) -> ProgramResult {
    let [event_authority] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !event_authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    verify_event_authority(event_authority)?;
    Ok(())
}
