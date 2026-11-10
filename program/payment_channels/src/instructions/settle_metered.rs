use pinocchio::{
    AccountView, Address, ProgramResult,
    error::ProgramError,
    sysvars::{Sysvar, clock::Clock},
};

use crate::errors::PaymentChannelsError;
use crate::instructions::helpers::voucher::verify_metered_pair;
use crate::state::channel::{Channel, ChannelStatus};

/// Instruction discriminator byte for `settle_metered`.
pub const DISCRIMINATOR: u8 = 14;

pub struct SettleMeteredAccounts<'a> {
    /// [`settled`](crate::Channel::settled) is advanced in place.
    pub channel: &'a mut AccountView,
    /// Source for locating the bundled Ed25519 ixs that carry the cap and
    /// the claim.
    pub instructions_sysvar: &'a mut AccountView,
}

impl<'a> TryFrom<&'a mut [AccountView]> for SettleMeteredAccounts<'a> {
    type Error = ProgramError;

    fn try_from(accounts: &'a mut [AccountView]) -> Result<Self, Self::Error> {
        let [channel, instructions_sysvar] = accounts else {
            return Err(PaymentChannelsError::NotEnoughAccountKeys.into());
        };
        Ok(Self {
            channel,
            instructions_sysvar,
        })
    }
}

/// Permissionless crank: authority is the client-signed cap plus the
/// operator-signed claim, not the transaction signer. Advances
/// [`Channel::settled`](crate::Channel::settled) to the claim in `OPEN`
/// only — `settled < claim <= cap <=`
/// [`deposit`](crate::Channel::deposit), and both vouchers must be fresh.
///
/// The cap (signed by [`authorized_signer`](crate::Channel::authorized_signer))
/// and the claim (signed by the cap's `operator`) ride in the two bundled
/// Ed25519 precompile ixs at `current - 2` (cap) and `current - 1` (claim),
/// so this instruction carries no data beyond its discriminator.
pub fn process(_program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let accs = SettleMeteredAccounts::try_from(accounts)?;

    let channel_address = *accs.channel.address();
    let now = Clock::get()?.unix_timestamp;

    let mut ch = Channel::from_account_mut(accs.channel)?;

    if ch.status != ChannelStatus::Open as u8 {
        return Err(PaymentChannelsError::InvalidChannelStatus.into());
    }

    let new_watermark = verify_metered_pair(&channel_address, &ch, accs.instructions_sysvar, now)?;

    ch.set_settled(new_watermark);
    Ok(())
}
