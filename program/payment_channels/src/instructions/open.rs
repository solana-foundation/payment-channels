use codama::CodamaType;
use core::mem::size_of;
use pinocchio::{AccountView, ProgramResult, error::ProgramError};

use crate::errors::PaymentChannelsError;

pub const DISCRIMINATOR: u8 = 0;

#[repr(C)]
#[derive(Debug, Clone, Copy, CodamaType)]
pub struct OpenArgs {
    pub salt: u64,
    pub deposit: u64,
    pub grace_period: u32,
    pub distribution_hash: [u8; 16],
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
        })
    }
}

pub fn process(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let _args = OpenArgs::load(data)?;
    let _accs = OpenAccounts::try_from(accounts)?;
    Err(PaymentChannelsError::NotImplemented.into())
}
