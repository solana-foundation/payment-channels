use pinocchio::{AccountView, ProgramResult, error::ProgramError};

use crate::errors::PaymentChannelsError;

pub const DISCRIMINATOR: u8 = 5;

pub struct FinalizeAccounts<'a> {
    pub cranker: &'a AccountView,
    pub channel: &'a AccountView,
    pub clock: &'a AccountView,
}

impl<'a> TryFrom<&'a [AccountView]> for FinalizeAccounts<'a> {
    type Error = ProgramError;

    fn try_from(accounts: &'a [AccountView]) -> Result<Self, Self::Error> {
        let [cranker, channel, clock] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        Ok(Self {
            cranker,
            channel,
            clock,
        })
    }
}

pub fn process(accounts: &[AccountView], _data: &[u8]) -> ProgramResult {
    let _accs = FinalizeAccounts::try_from(accounts)?;
    Err(PaymentChannelsError::NotImplemented.into())
}
