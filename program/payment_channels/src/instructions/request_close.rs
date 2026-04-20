use pinocchio::{AccountView, Address, ProgramResult, error::ProgramError};

use crate::errors::PaymentChannelsError;

/// Byte-0 selector for `requestClose`. Payer-signed, no Args. Starts the
/// grace period by setting
/// [`Channel::closure_started_at`](crate::Channel::closure_started_at) to
/// `now` and moves `OPEN → CLOSING`.
pub const DISCRIMINATOR: u8 = 4;

pub struct RequestCloseAccounts<'a> {
    /// Must equal [`Channel::payer`](crate::Channel::payer).
    pub payer: &'a AccountView,
    /// [`status`](crate::Channel::status) →
    /// [`Closing`](crate::ChannelStatus::Closing),
    /// [`closure_started_at`](crate::Channel::closure_started_at) → `now`.
    pub channel: &'a AccountView,
}

impl<'a> TryFrom<&'a [AccountView]> for RequestCloseAccounts<'a> {
    type Error = ProgramError;

    fn try_from(accounts: &'a [AccountView]) -> Result<Self, Self::Error> {
        let [payer, channel] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        Ok(Self { payer, channel })
    }
}

pub fn process(_program_id: &Address, accounts: &[AccountView]) -> ProgramResult {
    let _accs = RequestCloseAccounts::try_from(accounts)?;
    Err(PaymentChannelsError::NotImplemented.into())
}
