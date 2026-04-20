#[cfg(feature = "idl")]
use codama::CodamaType;
use core::mem::size_of;
use pinocchio::{AccountView, Address, ProgramResult, error::ProgramError};

use crate::errors::PaymentChannelsError;
use crate::instructions::VoucherArgs;

/// Instruction discriminator byte for `settleAndFinalize`.
pub const DISCRIMINATOR: u8 = 3;

/// Cooperative-close payload. Holds a stable wire size (voucher + tag) so
/// the struct is `#[repr(C, packed)]`-loadable; [`Self::has_voucher`] is
/// the option tag because a real `Option<`[`VoucherArgs`]`>` cannot be
/// zero-copy decoded over a packed wire format.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "idl", derive(CodamaType))]
pub struct SettleAndFinalizeArgs {
    /// Final voucher when [`Self::has_voucher`] == 1; ignored otherwise.
    /// Same freshness and monotonicity rules as `settle`.
    pub voucher: VoucherArgs,
    /// Option tag: `0` skips the voucher (lock whatever is already in
    /// [`settled`](crate::Channel::settled)), `1` applies [`Self::voucher`]
    /// first.
    pub has_voucher: u8,
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
    /// [`settled`](crate::Channel::settled),
    /// [`status`](crate::Channel::status), and
    /// [`closure_started_at`](crate::Channel::closure_started_at) all get
    /// written.
    pub channel: &'a AccountView,
    /// Consulted only when
    /// [`SettleAndFinalizeArgs::has_voucher`] == 1.
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

/// Merchant-signed cooperative close: optionally commits a final voucher,
/// locks the watermark, and moves to `FINALIZED`. From `OPEN`, sets
/// [`closure_started_at`](crate::Channel::closure_started_at) to `now`
/// (fresh grace for the merchant to `distribute`); from `CLOSING`,
/// callable only mid-grace and resets
/// [`closure_started_at`](crate::Channel::closure_started_at) to 0.
pub fn process(
    _program_id: &Address,
    accounts: &[AccountView],
    _args: &SettleAndFinalizeArgs,
) -> ProgramResult {
    let _accs = SettleAndFinalizeAccounts::try_from(accounts)?;
    Err(PaymentChannelsError::NotImplemented.into())
}
