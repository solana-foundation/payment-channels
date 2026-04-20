use pinocchio::{AccountView, Address, ProgramResult, error::ProgramError};

use crate::errors::PaymentChannelsError;

/// Instruction discriminator byte for `withdrawPayee`.
pub const DISCRIMINATOR: u8 = 8;

/// Post-grace timer-gated; tombstones the PDA.
pub struct WithdrawPayeeAccounts<'a> {
    pub channel: &'a AccountView,
    /// Escrow; source for both the payee payout and the payer refund.
    pub channel_token_account: &'a AccountView,
    /// Destination for [`settled`](crate::Channel::settled) `−`
    /// [`paid_out`](crate::Channel::paid_out).
    pub payee_token_account: &'a AccountView,
    /// Destination for [`deposit`](crate::Channel::deposit) `−`
    /// [`settled`](crate::Channel::settled); populated only when
    /// [`payer_withdrawn_at`](crate::Channel::payer_withdrawn_at) `== 0`
    /// at ix time.
    pub payer_token_account: &'a AccountView,
    /// Receives the PDA's lamport balance on close. Must equal
    /// [`Channel::payer`](crate::Channel::payer).
    pub payer: &'a AccountView,
    pub mint: &'a AccountView,
    pub token_program: &'a AccountView,
}

impl<'a> TryFrom<&'a [AccountView]> for WithdrawPayeeAccounts<'a> {
    type Error = ProgramError;

    fn try_from(accounts: &'a [AccountView]) -> Result<Self, Self::Error> {
        let [
            channel,
            channel_token_account,
            payee_token_account,
            payer_token_account,
            payer,
            mint,
            token_program,
        ] = accounts
        else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        Ok(Self {
            channel,
            channel_token_account,
            payee_token_account,
            payer_token_account,
            payer,
            mint,
            token_program,
        })
    }
}

/// Post-grace permissionless crank: pays
/// [`settled`](crate::Channel::settled) `−`
/// [`paid_out`](crate::Channel::paid_out) to
/// [`Channel::payee`](crate::Channel::payee) and, if
/// [`payer_withdrawn_at`](crate::Channel::payer_withdrawn_at) `== 0`,
/// atomically refunds [`deposit`](crate::Channel::deposit) `−`
/// [`settled`](crate::Channel::settled) to the payer in the same ix;
/// tombstones the PDA and returns rent to the payer.
pub fn process(_program_id: &Address, accounts: &[AccountView]) -> ProgramResult {
    let _accs = WithdrawPayeeAccounts::try_from(accounts)?;
    Err(PaymentChannelsError::NotImplemented.into())
}
