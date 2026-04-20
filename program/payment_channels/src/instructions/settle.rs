#[cfg(feature = "idl")]
use codama::CodamaType;
use core::mem::size_of;
use pinocchio::{AccountView, Address, ProgramResult, error::ProgramError};

use crate::errors::PaymentChannelsError;
use crate::instructions::VoucherArgs;

/// Instruction discriminator byte for `settle`.
pub const DISCRIMINATOR: u8 = 1;

/// Mid-session watermark advance. Carries exactly one voucher; no token
/// movement — only [`Channel::settled`](crate::Channel::settled) is updated.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "idl", derive(CodamaType))]
pub struct SettleArgs {
    /// Payer-signed authorization. See [`VoucherArgs`].
    pub voucher: VoucherArgs,
}

impl SettleArgs {
    pub const LEN: usize = size_of::<Self>();

    pub fn load(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() != Self::LEN {
            return Err(ProgramError::InvalidInstructionData);
        }
        Ok(unsafe { &*(data.as_ptr() as *const Self) })
    }
}

pub struct SettleAccounts<'a> {
    pub merchant: &'a AccountView,
    /// [`settled`](crate::Channel::settled) is advanced in place.
    pub channel: &'a AccountView,
    /// Source for locating the bundled Ed25519 ix that covers the voucher.
    pub instructions_sysvar: &'a AccountView,
}

impl<'a> TryFrom<&'a [AccountView]> for SettleAccounts<'a> {
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

/// Merchant-signed; advances
/// [`Channel::settled`](crate::Channel::settled) against a payer-signed
/// voucher. `OPEN` only —
/// [`settled`](crate::Channel::settled) `<`
/// [`voucher.cumulative_amount`](VoucherArgs::cumulative_amount) `≤`
/// [`deposit`](crate::Channel::deposit) and voucher must be fresh.
pub fn process(
    _program_id: &Address,
    accounts: &[AccountView],
    _args: &SettleArgs,
) -> ProgramResult {
    let _accs = SettleAccounts::try_from(accounts)?;
    Err(PaymentChannelsError::NotImplemented.into())
}
