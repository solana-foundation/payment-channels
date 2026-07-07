use pinocchio::{
    AccountView, Address, ProgramResult,
    error::ProgramError,
    sysvars::{Sysvar, clock::Clock},
};

use crate::constants::OPEN_SLOT_WINDOW;
use crate::errors::PaymentChannelsError;
use crate::instructions::helpers::deallocate_channel;
use crate::state::channel::{Channel, ChannelStatus};

/// Instruction discriminator byte for `reclaim`.
pub const DISCRIMINATOR: u8 = 9;

pub struct ReclaimAccounts<'a> {
    /// Fully-drained [`ChannelStatus::Distributed`] channel PDA; deallocated in
    /// place once the reclaim gate has passed.
    pub channel: &'a mut AccountView,
    /// Receives every remaining lamport of the channel PDA; must equal
    /// [`Channel::rent_payer`](crate::Channel::rent_payer). Not a signer —
    /// receiving lamports needs no signature, so `reclaim` stays
    /// permissionless.
    pub rent_payer: &'a mut AccountView,
}

impl<'a> TryFrom<&'a mut [AccountView]> for ReclaimAccounts<'a> {
    type Error = ProgramError;

    fn try_from(accounts: &'a mut [AccountView]) -> Result<Self, Self::Error> {
        let [channel, rent_payer] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        Ok(Self {
            channel,
            rent_payer,
        })
    }
}

/// Permissionless crank: deallocates a [`ChannelStatus::Distributed`] channel PDA
/// and returns all its lamports to the recorded `rent_payer`, once
/// `clock.slot > open_slot + OPEN_SLOT_WINDOW`.
///
/// A `Distributed` channel has already paid every token leg (the SEALED
/// `distribute` ran the payouts, payer refund, and treasury sweep, and
/// closed the escrow ATA) — the only value left at the address is the PDA
/// rent. Delaying this instruction therefore delays nobody's money; the gate
/// exists solely to keep the address occupied through the epoch window so
/// `(address, open_slot)` stays unique across incarnations (see
/// `constants::OPEN_SLOT_WINDOW`).
///
/// The account meta footprint is two writable accounts and no signers, so
/// operators can batch many `reclaim` instructions into one sweep
/// transaction.
pub fn process(_program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let accs = ReclaimAccounts::try_from(accounts)?;

    // Scoped borrow: validation reads must release the channel data before
    // `deallocate_channel` mutates lamports and closes the account.
    let open_slot = {
        let ch = Channel::from_account(accs.channel)?;

        if ch.status != ChannelStatus::Distributed as u8 {
            return Err(PaymentChannelsError::InvalidChannelStatus.into());
        }

        // Bind the rent recipient to the funder recorded at `open`, so a
        // caller cannot redirect the freed rent to an arbitrary account.
        if accs.rent_payer.address() != &ch.rent_payer {
            return Err(PaymentChannelsError::InvalidChannelRentPayer.into());
        }

        ch.open_slot()
    };

    // Reclaim gate: the address may only be freed once no earlier-incarnation
    // epoch can re-enter the open window.
    let close_unlock = open_slot
        .checked_add(OPEN_SLOT_WINDOW)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    if Clock::get()?.slot <= close_unlock {
        return Err(PaymentChannelsError::ChannelCloseTooEarly.into());
    }

    deallocate_channel(accs.channel, accs.rent_payer)
}
