use pinocchio::{AccountView, Address, ProgramResult, error::ProgramError};

use crate::errors::PaymentChannelsError;

/// Instruction discriminator byte for `withdrawPayer`.
pub const DISCRIMINATOR: u8 = 8;

pub struct WithdrawPayerAccounts<'a> {
    /// Must equal [`Channel::payer`](crate::Channel::payer).
    pub payer: &'a AccountView,
    /// [`payer_withdrawn_at`](crate::Channel::payer_withdrawn_at)
    /// stamped; not tombstoned.
    pub channel: &'a AccountView,
    pub channel_token_account: &'a AccountView,
    pub payer_token_account: &'a AccountView,
    pub mint: &'a AccountView,
    pub token_program: &'a AccountView,
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
        })
    }
}

/// Payer-only refund of [`deposit`](crate::Channel::deposit) `−`
/// [`settled`](crate::Channel::settled) during `FINALIZED`; records
/// [`payer_withdrawn_at`](crate::Channel::payer_withdrawn_at) `= now` and
/// does **not** tombstone the PDA.
pub fn process(_program_id: &Address, accounts: &[AccountView]) -> ProgramResult {
    let _accs = WithdrawPayerAccounts::try_from(accounts)?;
    Err(PaymentChannelsError::NotImplemented.into())
}
