use pinocchio::{
    AccountView, Address, ProgramResult,
    error::ProgramError,
    sysvars::{Sysvar, clock::Clock},
};

use crate::errors::PaymentChannelsError;
use crate::instructions::helpers::voucher::verify_voucher;
use crate::state::channel::{Channel, ChannelStatus};

/// Instruction discriminator byte for `settle`.
pub const DISCRIMINATOR: u8 = 2;

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

/// Permissionless crank: authority is the authorized-signer voucher, not the
/// transaction signer. Advances [`Channel::settled`](crate::Channel::settled)
/// in `OPEN` only — `settled` `< cumulative_amount ≤`
/// [`deposit`](crate::Channel::deposit), and the voucher must be fresh.
///
/// The voucher rides entirely in the bundled Ed25519 precompile ix at
/// `current - 1` (its signed message *is* the voucher payload), so this
/// instruction carries no data beyond its discriminator.
pub fn process(_program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let accs = SettleAccounts::try_from(accounts)?;

    let channel_address = *accs.channel.address();
    let now = Clock::get()?.unix_timestamp;

    let mut ch = Channel::from_account_mut(accs.channel)?;

    if ch.status != ChannelStatus::Open as u8 {
        return Err(PaymentChannelsError::InvalidChannelStatus.into());
    }

    let new_watermark = verify_voucher(&channel_address, &ch, accs.instructions_sysvar, now)?;

    ch.set_settled(new_watermark);
    Ok(())
}
