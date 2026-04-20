#[cfg(feature = "idl")]
use codama::CodamaType;
use core::mem::size_of;
use pinocchio::{AccountView, Address, ProgramResult, error::ProgramError};

use crate::event_engine::EventSerialize;
use crate::event_engine::emit_event;
use crate::events::Opened;

pub const DISCRIMINATOR: u8 = 0;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "idl", derive(CodamaType))]
pub struct OpenArgs {
    pub salt: u64,
    pub deposit: u64,
    pub grace_period: u32,
    pub distribution_hash: [u8; 32],
}

impl OpenArgs {
    pub const LEN: usize = size_of::<Self>();

    pub fn load(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() != Self::LEN {
            return Err(ProgramError::InvalidInstructionData);
        }
        Ok(unsafe { &*(data.as_ptr() as *const Self) })
    }
}

pub struct OpenAccounts<'a> {
    pub payer: &'a AccountView,
    pub payee: &'a AccountView,
    pub mint: &'a AccountView,
    pub authorized_signer: &'a AccountView,
    pub channel: &'a AccountView,
    pub payer_token_account: &'a AccountView,
    pub channel_token_account: &'a AccountView,
    pub token_program: &'a AccountView,
    pub system_program: &'a AccountView,
    pub rent: &'a AccountView,
    pub event_authority: &'a AccountView,
    pub self_program: &'a AccountView,
}

impl<'a> TryFrom<&'a [AccountView]> for OpenAccounts<'a> {
    type Error = ProgramError;

    fn try_from(accounts: &'a [AccountView]) -> Result<Self, Self::Error> {
        let [
            payer,
            payee,
            mint,
            authorized_signer,
            channel,
            payer_token_account,
            channel_token_account,
            token_program,
            system_program,
            rent,
            event_authority,
            self_program,
        ] = accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        Ok(Self {
            payer,
            payee,
            mint,
            authorized_signer,
            channel,
            payer_token_account,
            channel_token_account,
            token_program,
            system_program,
            rent,
            event_authority,
            self_program,
        })
    }
}

pub fn process(program_id: &Address, accounts: &[AccountView], _args: &OpenArgs) -> ProgramResult {
    let accs = OpenAccounts::try_from(accounts)?;

    let event = Opened {
        channel: *accs.channel.address(),
    };
    let bytes = event.to_bytes_fixed::<{ Opened::WIRE_LEN }>();
    emit_event(
        program_id,
        accs.event_authority,
        accs.self_program,
        bytes.as_slice(),
    )?;

    Ok(())
}
