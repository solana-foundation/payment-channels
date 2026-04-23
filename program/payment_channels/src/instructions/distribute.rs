#[cfg(feature = "idl")]
use codama::CodamaType;
use core::mem::size_of;
use pinocchio::{AccountView, Address, ProgramResult, error::ProgramError};

use crate::errors::PaymentChannelsError;

/// Instruction discriminator byte for `distribute`.
pub const DISCRIMINATOR: u8 = 7;

/// Upper bound on the serialized splits blob:
/// `num_recipients(1) + 30 × (address(32) + amount(8))`.
pub const MAX_DISTRIBUTE_PREIMAGE: usize = 1 + crate::instructions::open::MAX_DISTRIBUTION_RECIPIENTS * 40;

/// Distribute with splits preimage submission.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "idl", derive(CodamaType))]
pub struct DistributeArgs {
    /// Active byte count inside [`Self::preimage`]. Bounds both the
    /// Blake3 input and the splits parser.
    pub preimage_len: u16,
    /// Blake3-hashed on-chain; digest must equal
    /// [`Channel::distribution_hash`](crate::Channel::distribution_hash).
    /// Carries the splits config committed at `open`.
    #[cfg_attr(feature = "idl", codama(type = fixed_size(bytes, 512)))]
    pub preimage: [u8; MAX_DISTRIBUTE_PREIMAGE],
}

impl DistributeArgs {
    pub const LEN: usize = size_of::<Self>();

    pub fn load(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() != Self::LEN {
            return Err(ProgramError::InvalidInstructionData);
        }
        Ok(unsafe { &*(data.as_ptr() as *const Self) })
    }
}

/// Permissionless with preimage-hash check, gates *who* is paid and *how* much.
pub struct DistributeAccounts<'a> {
    /// [`paid_out`](crate::Channel::paid_out) grows; tombstoned when called
    /// from `FINALIZED`.
    pub channel: &'a AccountView,
    /// Escrow; source for all splits and the payer refund.
    pub channel_token_account: &'a AccountView,
    /// Payer refund destination; populated only from `FINALIZED` with
    /// [`payer_withdrawn_at`](crate::Channel::payer_withdrawn_at) `== 0`.
    pub payer_token_account: &'a AccountView,
    pub mint: &'a AccountView,
    pub token_program: &'a AccountView,
}

impl<'a> TryFrom<&'a [AccountView]> for DistributeAccounts<'a> {
    type Error = ProgramError;

    fn try_from(accounts: &'a [AccountView]) -> Result<Self, Self::Error> {
        let [
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
            channel,
            channel_token_account,
            payer_token_account,
            mint,
            token_program,
        })
    }
}

/// Permissionless crank: verifies the committed preimage and pays splits
/// [`settled`](crate::Channel::settled) `−`
/// [`paid_out`](crate::Channel::paid_out) to merchant destinations. From
/// `OPEN`, advances [`paid_out`](crate::Channel::paid_out) and stays
/// open; from `FINALIZED`, also refunds
/// [`deposit`](crate::Channel::deposit) `−`
/// [`settled`](crate::Channel::settled) to the payer (when not already
/// withdrawn) and tombstones the PDA.
pub fn process(
    _program_id: &Address,
    accounts: &[AccountView],
    _args: &DistributeArgs,
) -> ProgramResult {
    let _accs = DistributeAccounts::try_from(accounts)?;
    Err(PaymentChannelsError::NotImplemented.into())
}
