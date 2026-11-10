#[cfg(feature = "idl")]
use codama::CodamaType;
use core::mem::size_of;
use pinocchio::{
    AccountView, Address, ProgramResult,
    error::ProgramError,
    sysvars::{Sysvar, clock::Clock},
};

use crate::errors::PaymentChannelsError;
use crate::instructions::helpers::voucher::{verify_metered_pair, verify_voucher};
use crate::state::channel::{Channel, ChannelStatus};
use crate::state::{Transmutable, load};

/// Instruction discriminator byte for `settleAndSeal`.
pub const DISCRIMINATOR: u8 = 4;

/// [`SettleAndSealArgs::has_voucher`] value that skips voucher verification.
pub const NO_VOUCHER: u8 = 0;

/// [`SettleAndSealArgs::has_voucher`] value that applies the v1 voucher in
/// the slot immediately before this instruction, as in `settle`.
pub const V1_VOUCHER: u8 = 1;

/// [`SettleAndSealArgs::has_voucher`] value that selects the metered
/// cap/claim pair in the two slots immediately before this instruction (cap
/// first, claim second), as in `settle_metered`.
pub const METERED_VOUCHER: u8 = 2;

/// Cooperative-close payload: a single option-tag byte. When a voucher is
/// applied it is read from the bundled Ed25519 precompile ix(s) — the same
/// source as `settle` / `settle_metered` — so it is never duplicated in this
/// instruction's data.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "idl", derive(CodamaType))]
pub struct SettleAndSealArgs {
    /// Voucher tag: `0` skips the voucher (lock whatever is already in
    /// [`settled`](crate::Channel::settled)); `1` applies the v1 voucher
    /// carried by the preceding Ed25519 precompile ix first, under the same
    /// freshness and monotonicity rules as `settle`; `2` applies the metered
    /// cap/claim precompile pair in the two slots immediately before this
    /// instruction (cap first, claim second) first, advancing `settled` to the claim
    /// under `settled < claim <= cap <= deposit`. Any other value is rejected
    /// with `InvalidInstructionData`.
    pub has_voucher: u8,
}

impl SettleAndSealArgs {
    pub const LEN: usize = size_of::<Self>();

    pub fn load(data: &[u8]) -> Result<&Self, ProgramError> {
        unsafe { load::<Self>(data) }.map_err(|_| ProgramError::InvalidInstructionData)
    }
}

unsafe impl Transmutable for SettleAndSealArgs {
    const LEN: usize = size_of::<Self>();
}

pub struct SettleAndSealAccounts<'a> {
    pub payee: &'a AccountView,
    /// [`settled`](crate::Channel::settled),
    /// [`status`](crate::Channel::status), and
    /// [`closure_started_at`](crate::Channel::closure_started_at) all get
    /// written.
    pub channel: &'a mut AccountView,
    /// Consulted only when
    /// [`SettleAndSealArgs::has_voucher`] != [`NO_VOUCHER`].
    pub instructions_sysvar: &'a AccountView,
}

impl<'a> TryFrom<&'a mut [AccountView]> for SettleAndSealAccounts<'a> {
    type Error = ProgramError;

    fn try_from(accounts: &'a mut [AccountView]) -> Result<Self, Self::Error> {
        let [payee, channel, instructions_sysvar] = accounts else {
            return Err(PaymentChannelsError::NotEnoughAccountKeys.into());
        };
        Ok(Self {
            payee,
            channel,
            instructions_sysvar,
        })
    }
}

/// Payee-signed cooperative close: optionally commits a final
/// voucher, locks the watermark, and moves to `SEALED`. From `OPEN`,
/// [`closure_started_at`](crate::Channel::closure_started_at) stays 0.
/// From `CLOSING`, callable only mid-grace and resets
/// [`closure_started_at`](crate::Channel::closure_started_at) to 0.
pub fn process(
    _program_id: &Address,
    accounts: &mut [AccountView],
    args: &SettleAndSealArgs,
) -> ProgramResult {
    let accs = SettleAndSealAccounts::try_from(accounts)?;

    if !accs.payee.is_signer() {
        return Err(PaymentChannelsError::MissingRequiredSignature.into());
    }

    // Capture before mutable borrow of channel below.
    let channel_address = *accs.channel.address();
    let now = Clock::get()?.unix_timestamp;

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
        ChannelStatus::Sealed | ChannelStatus::Distributed => {
            return Err(PaymentChannelsError::InvalidChannelStatus.into());
        }
    }

    if accs.payee.address() != &ch.payee {
        return Err(PaymentChannelsError::InvalidChannelPayee.into());
    }

    match args.has_voucher {
        NO_VOUCHER => {}
        V1_VOUCHER => {
            let new_watermark =
                verify_voucher(&channel_address, &ch, accs.instructions_sysvar, now)?;
            ch.set_settled(new_watermark);
        }
        METERED_VOUCHER => {
            let new_watermark =
                verify_metered_pair(&channel_address, &ch, accs.instructions_sysvar, now)?;
            ch.set_settled(new_watermark);
        }
        _ => return Err(ProgramError::InvalidInstructionData),
    }

    ch.status = ChannelStatus::Sealed as u8;
    ch.set_closure_started_at(0);

    Ok(())
}
