use codama::CodamaType;
use core::mem::size_of;
use pinocchio::{AccountView, ProgramResult, error::ProgramError};

use crate::errors::PaymentChannelsError;

pub const DISCRIMINATOR: u8 = 2;

#[repr(C)]
#[derive(Debug, Clone, Copy, CodamaType)]
pub struct TopUpArgs {
    pub amount: u64,
}

impl TopUpArgs {
    pub const LEN: usize = size_of::<Self>();

    pub fn load(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() != Self::LEN {
            return Err(ProgramError::InvalidInstructionData);
        }
        Ok(unsafe { &*(data.as_ptr() as *const Self) })
    }
}

pub struct TopUpAccounts<'a> {
    pub payer: &'a AccountView,
    pub channel: &'a AccountView,
    pub payer_token_account: &'a AccountView,
    pub channel_token_account: &'a AccountView,
    pub mint: &'a AccountView,
    pub token_program: &'a AccountView,
}

impl<'a> TryFrom<&'a [AccountView]> for TopUpAccounts<'a> {
    type Error = ProgramError;

    fn try_from(accounts: &'a [AccountView]) -> Result<Self, Self::Error> {
        let [
            payer,
            channel,
            payer_token_account,
            channel_token_account,
            mint,
            token_program,
        ] = accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        Ok(Self {
            payer,
            channel,
            payer_token_account,
            channel_token_account,
            mint,
            token_program,
        })
    }
}

pub fn process(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let _args = TopUpArgs::load(data)?;
    let _accs = TopUpAccounts::try_from(accounts)?;
    Err(PaymentChannelsError::NotImplemented.into())
}
