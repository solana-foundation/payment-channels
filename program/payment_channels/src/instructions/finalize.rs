use pinocchio::{AccountView, Address, ProgramResult, error::ProgramError};

use crate::errors::PaymentChannelsError;

/// Byte-0 selector for `finalize`. Permissionless, voucher-free crank:
/// freezes the watermark and moves `CLOSING → FINALIZED` once
/// `now ≥` [`closure_started_at`](crate::Channel::closure_started_at) `+`
/// [`grace_period`](crate::Channel::grace_period); resets
/// [`closure_started_at`](crate::Channel::closure_started_at) to 0.
pub const DISCRIMINATOR: u8 = 5;

/// Timer-gated on `now ≥`
/// [`closure_started_at`](crate::Channel::closure_started_at) `+`
/// [`grace_period`](crate::Channel::grace_period).
pub struct FinalizeAccounts<'a> {
    /// [`status`](crate::Channel::status) →
    /// [`Finalized`](crate::ChannelStatus::Finalized),
    /// [`closure_started_at`](crate::Channel::closure_started_at) → 0.
    pub channel: &'a AccountView,
}

impl<'a> TryFrom<&'a [AccountView]> for FinalizeAccounts<'a> {
    type Error = ProgramError;

    fn try_from(accounts: &'a [AccountView]) -> Result<Self, Self::Error> {
        let [channel] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        Ok(Self { channel })
    }
}

pub fn process(_program_id: &Address, accounts: &[AccountView]) -> ProgramResult {
    let _accs = FinalizeAccounts::try_from(accounts)?;
    Err(PaymentChannelsError::NotImplemented.into())
}
