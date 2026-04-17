use pinocchio::{AccountView, Address, ProgramResult, error::ProgramError};

use crate::errors::PaymentChannelsError;

pub const DISCRIMINATOR: u8 = 4;

pub struct RequestCloseAccounts<'a> {
    pub payer: &'a AccountView,
    pub channel: &'a AccountView,
    pub clock: &'a AccountView,
}

impl<'a> TryFrom<&'a [AccountView]> for RequestCloseAccounts<'a> {
    type Error = ProgramError;

    fn try_from(accounts: &'a [AccountView]) -> Result<Self, Self::Error> {
        let [payer, channel, clock] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        Ok(Self {
            payer,
            channel,
            clock,
        })
    }
}

pub fn process(_program_id: &Address, accounts: &[AccountView]) -> ProgramResult {
    let _accs = RequestCloseAccounts::try_from(accounts)?;
    Err(PaymentChannelsError::NotImplemented.into())
}
