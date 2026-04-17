use pinocchio::{AccountView, Address, ProgramResult, error::ProgramError};

use crate::errors::PaymentChannelsError;

pub const DISCRIMINATOR: u8 = 7;

pub struct WithdrawPayerAccounts<'a> {
    pub payer: &'a AccountView,
    pub channel: &'a AccountView,
    pub channel_token_account: &'a AccountView,
    pub payer_token_account: &'a AccountView,
    pub mint: &'a AccountView,
    pub token_program: &'a AccountView,
    pub clock: &'a AccountView,
}

impl<'a> TryFrom<&'a [AccountView]> for WithdrawPayerAccounts<'a> {
    type Error = ProgramError;

    fn try_from(accounts: &'a [AccountView]) -> Result<Self, Self::Error> {
        let [
            payer,
            channel,
            channel_token_account,
            payer_token_account,
            mint,
            token_program,
            clock,
        ] = accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        Ok(Self {
            payer,
            channel,
            channel_token_account,
            payer_token_account,
            mint,
            token_program,
            clock,
        })
    }
}

pub fn process(_program_id: &Address, accounts: &[AccountView]) -> ProgramResult {
    let _accs = WithdrawPayerAccounts::try_from(accounts)?;
    Err(PaymentChannelsError::NotImplemented.into())
}
