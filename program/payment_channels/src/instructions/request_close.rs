use pinocchio::{
    AccountView, Address, ProgramResult,
    error::ProgramError,
    sysvars::{Sysvar, clock::Clock},
};

use crate::errors::PaymentChannelsError;
use crate::state::Channel;
use crate::state::channel::ChannelStatus;

/// Instruction discriminator byte for `requestClose`.
pub const DISCRIMINATOR: u8 = 5;

pub struct RequestCloseAccounts<'a> {
    /// Must equal [`Channel::payer`](crate::Channel::payer).
    pub payer: &'a AccountView,
    /// [`status`](crate::Channel::status) →
    /// [`Closing`](crate::ChannelStatus::Closing),
    /// [`closure_started_at`](crate::Channel::closure_started_at) → `now`.
    pub channel: &'a mut AccountView,
}

impl<'a> TryFrom<&'a mut [AccountView]> for RequestCloseAccounts<'a> {
    type Error = ProgramError;

    fn try_from(accounts: &'a mut [AccountView]) -> Result<Self, Self::Error> {
        let [payer, channel] = accounts else {
            return Err(PaymentChannelsError::NotEnoughAccountKeys.into());
        };
        Ok(Self { payer, channel })
    }
}

/// Payer-signed, no Args. Starts the grace period by setting
/// [`Channel::closure_started_at`](crate::Channel::closure_started_at) to
/// `now` and moves `OPEN → CLOSING`.
pub fn process(_program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let accs = RequestCloseAccounts::try_from(accounts)?;

    if !accs.payer.is_signer() {
        return Err(PaymentChannelsError::MissingRequiredSignature.into());
    }

    let now = Clock::get()?.unix_timestamp;

    let mut ch = Channel::from_account_mut(accs.channel)?;

    if ch.status != ChannelStatus::Open as u8 {
        return Err(PaymentChannelsError::InvalidChannelStatus.into());
    }

    if accs.payer.address() != &ch.payer {
        return Err(PaymentChannelsError::InvalidChannelPayer.into());
    }

    ch.set_closure_started_at(now);
    ch.status = ChannelStatus::Closing as u8;

    Ok(())
}
