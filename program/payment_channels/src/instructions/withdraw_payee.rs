use pinocchio::{AccountView, ProgramResult, error::ProgramError};

use crate::errors::PaymentChannelsError;

pub const DISCRIMINATOR: u8 = 8;

pub struct WithdrawPayeeAccounts<'a> {
    pub cranker: &'a AccountView,
    pub channel: &'a AccountView,
    pub channel_token_account: &'a AccountView,
    pub payee_token_account: &'a AccountView,
    pub payer_token_account: &'a AccountView,
    pub payer: &'a AccountView,
    pub mint: &'a AccountView,
    pub token_program: &'a AccountView,
    pub clock: &'a AccountView,
}

impl<'a> TryFrom<&'a [AccountView]> for WithdrawPayeeAccounts<'a> {
    type Error = ProgramError;

    fn try_from(accounts: &'a [AccountView]) -> Result<Self, Self::Error> {
        let [
            cranker,
            channel,
            channel_token_account,
            payee_token_account,
            payer_token_account,
            payer,
            mint,
            token_program,
            clock,
        ] = accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        Ok(Self {
            cranker,
            channel,
            channel_token_account,
            payee_token_account,
            payer_token_account,
            payer,
            mint,
            token_program,
            clock,
        })
    }
}

pub fn process(accounts: &[AccountView], _data: &[u8]) -> ProgramResult {
    let _accs = WithdrawPayeeAccounts::try_from(accounts)?;
    Err(PaymentChannelsError::NotImplemented.into())
}
