#[cfg(feature = "idl")]
use codama::CodamaType;
use core::mem::size_of;
use pinocchio::{AccountView, Address, ProgramResult, error::ProgramError};

use crate::errors::PaymentChannelsError;

/// Instruction discriminator byte for `topUp`.
pub const DISCRIMINATOR: u8 = 3;

/// Extends an `OPEN` channel's escrow. The full [`Self::amount`] is
/// transferred from [`TopUpAccounts::payer_token_account`] to
/// [`TopUpAccounts::channel_token_account`] and added to
/// [`Channel::deposit`](crate::Channel::deposit), raising the ceiling on
/// future [`settled`](crate::Channel::settled) growth.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "idl", derive(CodamaType))]
pub struct TopUpArgs {
    /// Base-unit amount to pull from the payer's token account into escrow.
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
    /// Must equal [`Channel::payer`](crate::Channel::payer).
    pub payer: &'a AccountView,
    /// [`deposit`](crate::Channel::deposit) grows by [`TopUpArgs::amount`].
    pub channel: &'a AccountView,
    pub payer_token_account: &'a AccountView,
    /// Escrow ATA owned by the channel PDA.
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

/// Payer-signed; extends
/// [`Channel::deposit`](crate::Channel::deposit) by [`TopUpArgs::amount`].
/// `OPEN` only — disallowed once
/// [`closure_started_at`](crate::Channel::closure_started_at) `> 0`.
pub fn process(
    _program_id: &Address,
    accounts: &[AccountView],
    _args: &TopUpArgs,
) -> ProgramResult {
    let _accs = TopUpAccounts::try_from(accounts)?;
    Err(PaymentChannelsError::NotImplemented.into())
}
