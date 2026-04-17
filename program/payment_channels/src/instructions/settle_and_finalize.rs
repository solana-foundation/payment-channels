use codama::CodamaType;
use core::mem::size_of;
use pinocchio::{AccountView, ProgramResult, error::ProgramError};

use crate::errors::PaymentChannelsError;
use crate::instructions::VoucherArgs;

pub const DISCRIMINATOR: u8 = 3;

#[repr(C)]
#[derive(Debug, Clone, Copy, CodamaType)]
pub struct SettleAndFinalizeArgs {
    pub voucher: VoucherArgs,
    pub has_voucher: u8,
    pub _pad: [u8; 7],
}

impl SettleAndFinalizeArgs {
    pub const LEN: usize = size_of::<Self>();

    pub fn load(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() != Self::LEN {
            return Err(ProgramError::InvalidInstructionData);
        }
        Ok(unsafe { &*(data.as_ptr() as *const Self) })
    }
}

pub struct SettleAndFinalizeAccounts<'a> {
    pub merchant: &'a AccountView,
    pub channel: &'a AccountView,
    pub instructions_sysvar: &'a AccountView,
}

impl<'a> TryFrom<&'a [AccountView]> for SettleAndFinalizeAccounts<'a> {
    type Error = ProgramError;

    fn try_from(accounts: &'a [AccountView]) -> Result<Self, Self::Error> {
        let [merchant, channel, instructions_sysvar] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        Ok(Self {
            merchant,
            channel,
            instructions_sysvar,
        })
    }
}

pub fn process(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let _args = SettleAndFinalizeArgs::load(data)?;
    let _accs = SettleAndFinalizeAccounts::try_from(accounts)?;
    Err(PaymentChannelsError::NotImplemented.into())
}
