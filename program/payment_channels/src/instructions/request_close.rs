#[cfg(feature = "idl")]
use codama::CodamaType;
use core::mem::size_of;
use pinocchio::{
    AccountView, Address, ProgramResult,
    error::ProgramError,
    sysvars::{Sysvar, clock::Clock},
};

use crate::errors::PaymentChannelsError;
use crate::state::channel::ChannelStatus;
use crate::state::{Channel, Transmutable, load};

/// Instruction discriminator byte for `requestClose`.
pub const DISCRIMINATOR: u8 = 5;

/// Payer-signed close request.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "idl", derive(CodamaType))]
pub struct RequestCloseArgs {
    /// Must equal [`Channel::open_slot`](crate::Channel::open_slot). Scopes
    /// the grace start to the intended channel incarnation.
    #[cfg_attr(feature = "idl", codama(type = number(u64)))]
    pub expected_open_slot: [u8; 8],
}

impl RequestCloseArgs {
    pub const LEN: usize = size_of::<Self>();

    #[inline(always)]
    pub fn expected_open_slot(&self) -> u64 {
        u64::from_le_bytes(self.expected_open_slot)
    }

    pub fn load(data: &[u8]) -> Result<&Self, ProgramError> {
        unsafe { load::<Self>(data) }.map_err(|_| ProgramError::InvalidInstructionData)
    }
}

unsafe impl Transmutable for RequestCloseArgs {
    const LEN: usize = size_of::<Self>();
}

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

/// Payer-signed. Starts the grace period by setting
/// [`Channel::closure_started_at`](crate::Channel::closure_started_at) to
/// `now` and moves `OPEN → CLOSING`.
pub fn process(
    _program_id: &Address,
    accounts: &mut [AccountView],
    args: &RequestCloseArgs,
) -> ProgramResult {
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

    if args.expected_open_slot() != ch.open_slot() {
        return Err(PaymentChannelsError::ChannelSlotMismatch.into());
    }

    ch.set_closure_started_at(now);
    ch.status = ChannelStatus::Closing as u8;

    Ok(())
}
