#[cfg(feature = "idl")]
use codama::{CodamaAccount, CodamaType};
use core::mem::size_of;
use pinocchio::{
    AccountView, Address,
    account::{Ref, RefMut},
    error::ProgramError,
};

use crate::errors::PaymentChannelsError;
use crate::state::common::{AccountDiscriminator, CURRENT_CHANNEL_VERSION};

/// Fixed on-chain byte length of the [`Channel`] PDA. Asserted at compile
/// time (see below).
pub const CHANNEL_LEN: usize = size_of::<Channel>();

/// PDA seed prefix. Full seeds:
/// `[CHANNEL_SEED, payer, payee, mint, authorized_signer, salt.to_le_bytes()]`.
pub const CHANNEL_SEED: &[u8] = b"channel";

/// Current position of a [`Channel`] in the FSM.
/// [`Open = 0`](ChannelStatus::Open) is deliberate: [`AccountDiscriminator`]
/// at byte 0 already rejects zero-initialized accounts before
/// [`Channel::status`] is read, so the status field can safely reuse 0 as
/// a real variant.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "idl", derive(CodamaType))]
pub enum ChannelStatus {
    /// Active channel: accepts `settle`, `topUp`, and the cooperative or
    /// adversarial transitions that exit toward [`Finalized`](Self::Finalized) /
    /// [`Closing`](Self::Closing).
    Open = 0,
    /// Watermark locked. Awaits `distribute` (splits + optional payer
    /// refund + tombstone) and/or a standalone `withdraw_payer`.
    Finalized = 1,
    /// `requestClose` has started the grace window. Exits to
    /// [`Finalized`](Self::Finalized) cooperatively (merchant
    /// `settleAndFinalize` mid-grace) or permissionlessly (`finalize`
    /// post-grace).
    Closing = 2,
}

impl TryFrom<u8> for ChannelStatus {
    type Error = ProgramError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Open),
            1 => Ok(Self::Finalized),
            2 => Ok(Self::Closing),
            _ => Err(PaymentChannelsError::InvalidChannelStatus.into()),
        }
    }
}

/// Active channel PDA: escrowed deposit, settled watermark, closure
/// timestamps, distribution commitment, and participant bindings. Fixed
/// 208-byte `#[repr(C, packed)]` layout for zero-copy load.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "idl", derive(CodamaAccount))]
pub struct Channel {
    /// [`AccountDiscriminator::Channel`]. First byte so zero-initialized
    /// account bytes fail load before any field is interpreted.
    pub discriminator: u8, //   0..1
    /// [`CURRENT_CHANNEL_VERSION`] at `open`. Any other value is rejected
    /// on load, gating future PDA-layout migrations.
    pub version: u8, //   1..2
    /// Canonical bump from `find_program_address` at `open`. Reused
    /// verbatim by subsequent ixs via `create_program_address`, avoiding
    /// rederivation cost.
    pub bump: u8, //   2..3
    /// [`ChannelStatus`] discriminant.
    pub status: u8, //   3..4
    /// Initial escrow; immutable ceiling on [`Self::settled`]. Grows only
    /// via `topUp` while [`Self::status`] == [`ChannelStatus::Open`] and
    /// [`Self::closure_started_at`] == 0.
    pub deposit: u64, //   4..12
    /// Cumulative authorized watermark. Advanced monotonically by signed
    /// vouchers in `settle` / `settleAndFinalize`; capped by
    /// [`Self::deposit`].
    pub settled: u64, //  12..20
    /// Cumulative tokens already paid out to merchant splits across
    /// `distribute` calls. Invariant:
    /// `paid_out` ≤ [`Self::settled`]. Lets mid-session `distribute`
    /// run without double-paying.
    pub paid_out: u64, //  20..28
    /// Set to `now` by `requestClose` (starts grace) and reset to 0 on
    /// `CLOSING → FINALIZED` via either `settleAndFinalize` (mid-grace)
    /// or `finalize` (post-grace). Always 0 in `OPEN` and `FINALIZED`;
    /// only `CLOSING` carries a live timestamp.
    pub closure_started_at: i64, //  28..36
    /// Unix ts of the payer's one-shot refund via `withdraw_payer`; 0
    /// means not yet withdrawn. Gates the atomic refund leg inside
    /// `distribute` when it runs from `FINALIZED`.
    pub payer_withdrawn_at: i64, //  36..44
    /// Per-channel grace duration in seconds, set at `open`. Governs
    /// the `CLOSING → FINALIZED` unlock for permissionless `finalize`.
    pub grace_period: u32, //  44..48
    /// Blake3 commitment to the distribution preimage.
    pub distribution_hash: [u8; 32], //  48..80
    /// Refund destination and payer-side authority signer (required for
    /// `topUp`, `requestClose`, `withdraw_payer`).
    pub payer: Address, //  80..112
    /// PDA seed binding; retained on-struct because every ix that
    /// re-derives the channel address needs the original pubkey.
    pub payee: Address, // 112..144
    /// Pubkey that signs vouchers; equals [`Self::payer`] unless a
    /// delegate was bound at `open`. Every voucher's
    /// [`signer`](crate::VoucherArgs::signer) field must match this value.
    pub authorized_signer: Address, // 144..176
    /// Token mint bound at `open`. All escrow and payout transfers ride
    /// this mint.
    pub mint: Address, // 176..208
}

impl Channel {
    pub const LEN: usize = CHANNEL_LEN;

    pub fn find_pda(
        payer: &Address,
        payee: &Address,
        mint: &Address,
        authorized_signer: &Address,
        salt: u64,
    ) -> (Address, u8) {
        Address::find_program_address(
            &[
                CHANNEL_SEED,
                payer.as_ref(),
                payee.as_ref(),
                mint.as_ref(),
                authorized_signer.as_ref(),
                &salt.to_le_bytes(),
            ],
            &crate::ID,
        )
    }

    /// Owner-checked borrow. `load` is module-private so callers cannot
    /// bypass the owner/discriminator/version checks.
    pub fn from_account<'a>(account: &'a AccountView) -> Result<Ref<'a, Self>, ProgramError> {
        if !account.owned_by(&crate::ID) {
            return Err(ProgramError::InvalidAccountOwner);
        }
        let data = account.try_borrow()?;
        Ref::try_map(data, Self::load).map_err(|(_, e)| e)
    }

    pub fn from_account_mut<'a>(
        account: &'a mut AccountView,
    ) -> Result<RefMut<'a, Self>, ProgramError> {
        if !account.owned_by(&crate::ID) {
            return Err(ProgramError::InvalidAccountOwner);
        }
        let data = account.try_borrow_mut()?;
        RefMut::try_map(data, Self::load_mut).map_err(|(_, e)| e)
    }

    fn load(bytes: &[u8]) -> Result<&Self, ProgramError> {
        if bytes.len() != Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        if bytes[0] != AccountDiscriminator::Channel as u8 {
            return Err(PaymentChannelsError::InvalidAccountDiscriminator.into());
        }
        if bytes[1] != CURRENT_CHANNEL_VERSION {
            return Err(PaymentChannelsError::UnsupportedChannelVersion.into());
        }
        Ok(unsafe { &*(bytes.as_ptr() as *const Self) })
    }

    fn load_mut(bytes: &mut [u8]) -> Result<&mut Self, ProgramError> {
        if bytes.len() != Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        if bytes[0] != AccountDiscriminator::Channel as u8 {
            return Err(PaymentChannelsError::InvalidAccountDiscriminator.into());
        }
        if bytes[1] != CURRENT_CHANNEL_VERSION {
            return Err(PaymentChannelsError::UnsupportedChannelVersion.into());
        }
        Ok(unsafe { &mut *(bytes.as_mut_ptr() as *mut Self) })
    }
}

const _: () = {
    assert!(Channel::LEN == 208);
};

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_bytes() -> [u8; Channel::LEN] {
        let mut bytes = [0u8; Channel::LEN];
        bytes[0] = AccountDiscriminator::Channel as u8;
        bytes[1] = CURRENT_CHANNEL_VERSION;
        bytes
    }

    #[test]
    fn size_is_208_bytes() {
        assert_eq!(core::mem::size_of::<Channel>(), 208);
    }

    #[test]
    fn load_rejects_wrong_length() {
        let short = [0u8; 100];
        assert!(Channel::load(&short).is_err());
    }

    #[test]
    fn load_rejects_missing_discriminator() {
        let bytes = [0u8; Channel::LEN];
        let err = Channel::load(&bytes).unwrap_err();
        assert_eq!(
            err,
            PaymentChannelsError::InvalidAccountDiscriminator.into()
        );
    }

    #[test]
    fn load_rejects_unsupported_version() {
        let mut bytes = valid_bytes();
        bytes[1] = CURRENT_CHANNEL_VERSION + 1;
        let err = Channel::load(&bytes).unwrap_err();
        assert_eq!(err, PaymentChannelsError::UnsupportedChannelVersion.into());
    }

    #[test]
    fn load_accepts_valid_header() {
        let bytes = valid_bytes();
        assert!(Channel::load(&bytes).is_ok());
    }
}
