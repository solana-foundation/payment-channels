#[cfg(feature = "idl")]
use codama::CodamaType;
use core::mem::size_of;
use pinocchio::{AccountView, Address, ProgramResult, error::ProgramError};

use crate::errors::PaymentChannelsError;

pub const DISCRIMINATOR: u8 = 6;

pub const MAX_DISTRIBUTE_PREIMAGE: usize = 512;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "idl", derive(CodamaType))]
pub struct DistributeArgs {
    pub preimage_len: u16,
    pub _pad: [u8; 6],
    /// Blake3-hashed on-chain; digest must equal `Channel::distribution_hash`.
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

pub struct DistributeAccounts<'a> {
    pub cranker: &'a AccountView,
    pub channel: &'a AccountView,
    pub channel_token_account: &'a AccountView,
    pub payer_token_account: &'a AccountView,
    pub mint: &'a AccountView,
    pub token_program: &'a AccountView,
}

impl<'a> TryFrom<&'a [AccountView]> for DistributeAccounts<'a> {
    type Error = ProgramError;

    fn try_from(accounts: &'a [AccountView]) -> Result<Self, Self::Error> {
        let [
            cranker,
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
            cranker,
            channel,
            channel_token_account,
            payer_token_account,
            mint,
            token_program,
        })
    }
}

pub fn process(
    _program_id: &Address,
    accounts: &[AccountView],
    _args: &DistributeArgs,
) -> ProgramResult {
    let _accs = DistributeAccounts::try_from(accounts)?;
    Err(PaymentChannelsError::NotImplemented.into())
}
