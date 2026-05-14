use pinocchio::{AccountView, Address, ProgramResult, error::ProgramError};

use crate::errors::PaymentChannelsError;
use crate::instructions::helpers::sysvars::unix_timestamp;
use crate::state::Channel;
use crate::state::channel::ChannelStatus;

/// Instruction discriminator byte for `finalize`.
pub const DISCRIMINATOR: u8 = 6;

pub struct FinalizeAccounts<'a> {
    /// [`status`](crate::Channel::status) →
    /// [`Finalized`](crate::ChannelStatus::Finalized),
    /// [`closure_started_at`](crate::Channel::closure_started_at) → 0.
    pub channel: &'a mut AccountView,
}

impl<'a> TryFrom<&'a mut [AccountView]> for FinalizeAccounts<'a> {
    type Error = ProgramError;

    fn try_from(accounts: &'a mut [AccountView]) -> Result<Self, Self::Error> {
        let [channel] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        Ok(Self { channel })
    }
}

/// Permissionless, voucher-free crank: freezes the watermark and moves
/// `CLOSING → FINALIZED` once `now ≥`
/// [`closure_started_at`](crate::Channel::closure_started_at) `+`
/// [`grace_period`](crate::Channel::grace_period); resets
/// [`closure_started_at`](crate::Channel::closure_started_at) to 0.
pub fn process(_program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let accs = FinalizeAccounts::try_from(accounts)?;

    let now = unix_timestamp()?;

    let mut ch = Channel::from_account_mut(accs.channel)?;

    if ch.status != ChannelStatus::Closing as u8 {
        return Err(PaymentChannelsError::InvalidChannelStatus.into());
    }

    let deadline = ch
        .closure_started_at()
        .checked_add(ch.grace_period() as i64)
        .ok_or(PaymentChannelsError::FinalizeDeadlineOverflow)?;

    if now < deadline {
        return Err(PaymentChannelsError::InvalidChannelStatus.into());
    }

    ch.status = ChannelStatus::Finalized as u8;
    ch.set_closure_started_at(0);

    Ok(())
}
