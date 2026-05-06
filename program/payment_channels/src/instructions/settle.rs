#[cfg(feature = "idl")]
use codama::CodamaType;
use core::mem::size_of;
use pinocchio::{
    AccountView, Address, ProgramResult,
    error::ProgramError,
    sysvars::{Sysvar, clock::Clock},
};

use crate::errors::PaymentChannelsError;
use crate::instructions::VoucherArgs;
use crate::instructions::helpers::voucher::{WatermarkRule, verify_voucher};
use crate::state::channel::{Channel, ChannelStatus};
use crate::state::{Transmutable, load};

/// Instruction discriminator byte for `settle`.
pub const DISCRIMINATOR: u8 = 2;

/// Mid-session watermark advance. Carries exactly one voucher; no token
/// movement — only [`Channel::settled`](crate::Channel::settled) is updated.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "idl", derive(CodamaType))]
pub struct SettleArgs {
    /// Payer-signed authorization. See [`VoucherArgs`].
    pub voucher: VoucherArgs,
}

impl SettleArgs {
    pub const LEN: usize = size_of::<Self>();

    pub fn load(data: &[u8]) -> Result<&Self, ProgramError> {
        unsafe { load::<Self>(data) }.map_err(|_| ProgramError::InvalidInstructionData)
    }
}

unsafe impl Transmutable for SettleArgs {
    const LEN: usize = size_of::<Self>();
}

pub struct SettleAccounts<'a> {
    /// [`settled`](crate::Channel::settled) is advanced in place.
    pub channel: &'a mut AccountView,
    /// Source for locating the bundled Ed25519 ix that covers the voucher.
    pub instructions_sysvar: &'a mut AccountView,
}

impl<'a> TryFrom<&'a mut [AccountView]> for SettleAccounts<'a> {
    type Error = ProgramError;

    fn try_from(accounts: &'a mut [AccountView]) -> Result<Self, Self::Error> {
        let [channel, instructions_sysvar] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        Ok(Self {
            channel,
            instructions_sysvar,
        })
    }
}

/// Permissionless crank: authority is the payer-signed voucher, not the
/// signer. Advances [`Channel::settled`](crate::Channel::settled) in `OPEN`
/// only — `settled` `<`
/// [`voucher.cumulative_amount`](VoucherArgs::cumulative_amount) `≤`
/// [`deposit`](crate::Channel::deposit) and voucher must be fresh.
pub fn process(
    _program_id: &Address,
    accounts: &mut [AccountView],
    args: &SettleArgs,
) -> ProgramResult {
    let accs = SettleAccounts::try_from(accounts)?;

    let channel_address = *accs.channel.address();
    let now = Clock::get()?.unix_timestamp;

    let mut ch = Channel::from_account_mut(accs.channel)?;

    if ch.status != ChannelStatus::Open as u8 {
        return Err(PaymentChannelsError::InvalidChannelStatus.into());
    }

    let new_watermark = verify_voucher(
        &channel_address,
        &ch,
        &args.voucher,
        accs.instructions_sysvar,
        now,
        WatermarkRule::StrictIncrease,
    )?;

    ch.set_settled(new_watermark);
    Ok(())
}
