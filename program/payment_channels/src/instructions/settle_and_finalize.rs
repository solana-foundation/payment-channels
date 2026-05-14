#[cfg(feature = "idl")]
use codama::CodamaType;
use core::mem::size_of;
use pinocchio::{AccountView, Address, ProgramResult, error::ProgramError};

use crate::errors::PaymentChannelsError;
use crate::instructions::VoucherArgs;
use crate::instructions::helpers::sysvars::unix_timestamp;
use crate::instructions::helpers::voucher::verify_voucher;
use crate::state::channel::{Channel, ChannelStatus};
use crate::state::{Transmutable, load};

/// Instruction discriminator byte for `settleAndFinalize`.
pub const DISCRIMINATOR: u8 = 4;

/// Cooperative-close payload. [`Self::has_voucher`] is the option tag
/// because a Rust `Option<VoucherArgs>` cannot be carried over a zero-copy
/// wire format; the explicit u8 keeps the struct's length deterministic.
#[repr(C)]
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
        unsafe { load::<Self>(data) }.map_err(|_| ProgramError::InvalidInstructionData)
    }
}

unsafe impl Transmutable for SettleAndFinalizeArgs {
    const LEN: usize = size_of::<Self>();
}

pub struct SettleAndFinalizeAccounts<'a> {
    pub merchant: &'a AccountView,
    /// [`settled`](crate::Channel::settled),
    /// [`status`](crate::Channel::status), and
    /// [`closure_started_at`](crate::Channel::closure_started_at) all get
    /// written.
    pub channel: &'a mut AccountView,
    /// Consulted only when
    /// [`SettleAndFinalizeArgs::has_voucher`] == 1.
    pub instructions_sysvar: &'a AccountView,
}

impl<'a> TryFrom<&'a mut [AccountView]> for SettleAndFinalizeAccounts<'a> {
    type Error = ProgramError;

    fn try_from(accounts: &'a mut [AccountView]) -> Result<Self, Self::Error> {
        let [merchant, channel, instructions_sysvar] = accounts else {
            return Err(PaymentChannelsError::NotEnoughAccountKeys.into());
        };
        Ok(Self {
            merchant,
            channel,
            instructions_sysvar,
        })
    }
}

/// Merchant-signed cooperative close: optionally commits a final
/// voucher, locks the watermark, and moves to `FINALIZED`. From `OPEN`,
/// [`closure_started_at`](crate::Channel::closure_started_at) stays 0.
/// From `CLOSING`, callable only mid-grace and resets
/// [`closure_started_at`](crate::Channel::closure_started_at) to 0.
pub fn process(
    _program_id: &Address,
    accounts: &mut [AccountView],
    args: &SettleAndFinalizeArgs,
) -> ProgramResult {
    let accs = SettleAndFinalizeAccounts::try_from(accounts)?;

    if !accs.merchant.is_signer() {
        return Err(PaymentChannelsError::MissingRequiredSignature.into());
    }

    // Capture before mutable borrow of channel below.
    let channel_address = *accs.channel.address();
    let now = unix_timestamp()?;

    let mut ch = Channel::from_account_mut(accs.channel)?;

    match ChannelStatus::try_from(ch.status)? {
        ChannelStatus::Open => {}
        ChannelStatus::Closing => {
            let deadline = ch
                .closure_started_at()
                .checked_add(ch.grace_period() as i64)
                .ok_or(ProgramError::ArithmeticOverflow)?;
            if now >= deadline {
                return Err(PaymentChannelsError::InvalidChannelStatus.into());
            }
        }
        ChannelStatus::Finalized => {
            return Err(PaymentChannelsError::InvalidChannelStatus.into());
        }
    }

    if accs.merchant.address() != &ch.payee {
        return Err(PaymentChannelsError::InvalidChannelPayee.into());
    }

    if args.has_voucher != 0 {
        let new_watermark = verify_voucher(
            &channel_address,
            &ch,
            &args.voucher,
            accs.instructions_sysvar,
            now,
        )?;
        ch.set_settled(new_watermark);
    }

    ch.status = ChannelStatus::Finalized as u8;
    ch.set_closure_started_at(0);

    Ok(())
}
