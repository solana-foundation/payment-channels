#[cfg(feature = "idl")]
use codama::{CodamaAccount, CodamaType};
use core::mem::size_of;
use pinocchio::{
    AccountView, Address,
    account::{Ref, RefMut},
    error::ProgramError,
};

use crate::{
    errors::PaymentChannelsError,
    state::{
        common::{AccountDiscriminator, CURRENT_CHANNEL_VERSION},
        transmutable::{Transmutable, load, load_mut},
    },
};

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
/// 216-byte layout for zero-copy load.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "idl", derive(CodamaAccount))]
pub struct Channel {
    /// [`AccountDiscriminator::Channel`]. First byte so zero-initialized
    /// account bytes fail load before any field is interpreted.
    pub discriminator: u8,
    /// [`CURRENT_CHANNEL_VERSION`] at `open`. Any other value is rejected
    /// on load, gating future PDA-layout migrations.
    pub version: u8,
    /// Canonical bump from `find_program_address` at `open`. Reused
    /// verbatim by subsequent ixs via `create_program_address`, avoiding
    /// rederivation cost.
    pub bump: u8,
    /// [`ChannelStatus`] discriminant.
    pub status: u8,
    /// PDA disambiguator set at `open`. Stored so downstream instructions
    /// (`distribute`, `withdraw_payer`) can reconstruct the full PDA seeds
    /// and sign as the channel PDA without off-chain data.
    #[cfg_attr(feature = "idl", codama(type = number(u64)))]
    salt: [u8; 8],
    /// Initial escrow; immutable ceiling on [`Self::settled`]. Raised only
    /// by `topUp` while [`Self::status`] == [`ChannelStatus::Open`];
    /// `requestClose` locks it by atomically moving the channel to
    /// [`ChannelStatus::Closing`].
    #[cfg_attr(feature = "idl", codama(type = number(u64)))]
    deposit: [u8; 8],
    /// Cumulative authorized watermark. Advanced monotonically by signed
    /// vouchers in `settle` / `settleAndFinalize`; capped by
    /// [`Self::deposit`].
    #[cfg_attr(feature = "idl", codama(type = number(u64)))]
    settled: [u8; 8],
    /// Cumulative tokens already paid out to merchant splits across
    /// `distribute` calls. Invariant: `paid_out` ≤ [`Self::settled`].
    /// Lets mid-session `distribute` run without double-paying.
    #[cfg_attr(feature = "idl", codama(type = number(u64)))]
    paid_out: [u8; 8],
    /// Set to `now` by `requestClose` (starts grace) and reset to 0 on
    /// `CLOSING → FINALIZED` via either `settleAndFinalize` (mid-grace)
    /// or `finalize` (post-grace). Always 0 in `OPEN` and `FINALIZED`;
    /// only `CLOSING` carries a live timestamp.
    #[cfg_attr(feature = "idl", codama(type = number(i64)))]
    closure_started_at: [u8; 8],
    /// Unix ts of the payer's one-shot refund via `withdraw_payer`; 0
    /// means not yet withdrawn. Gates the atomic refund branch inside
    /// `distribute` when it runs from `FINALIZED`.
    #[cfg_attr(feature = "idl", codama(type = number(i64)))]
    payer_withdrawn_at: [u8; 8],
    /// Per-channel grace duration in seconds, set at `open`. Governs
    /// the `CLOSING → FINALIZED` unlock for permissionless `finalize`.
    #[cfg_attr(feature = "idl", codama(type = number(u32)))]
    grace_period: [u8; 4],
    /// Blake3 commitment to the distribution preimage.
    pub distribution_hash: [u8; 32],
    /// Refund destination and payer-side authority signer (required for
    /// `topUp`, `requestClose`, `withdraw_payer`).
    pub payer: Address,
    /// PDA seed binding; retained on-struct because every ix that
    /// re-derives the channel address needs the original pubkey. Also the
    /// implicit-remainder destination on `distribute` (the runtime payee
    /// ATA is `ATA(payee, mint, token_program)`).
    pub payee: Address,
    /// Pubkey that signs vouchers; equals [`Self::payer`] unless a
    /// delegate was bound at `open`. Matched against the pubkey
    /// embedded in the caller-bundled Ed25519 precompile ix.
    pub authorized_signer: Address,
    /// Token mint bound at `open`. All escrow and payout transfers ride
    /// this mint.
    pub mint: Address,
}

impl Channel {
    pub const LEN: usize = size_of::<Self>();

    #[inline(always)]
    pub fn salt(&self) -> u64 {
        u64::from_le_bytes(self.salt)
    }

    #[inline(always)]
    pub fn deposit(&self) -> u64 {
        u64::from_le_bytes(self.deposit)
    }
    #[inline(always)]
    pub fn set_deposit(&mut self, v: u64) {
        self.deposit = v.to_le_bytes();
    }

    #[inline(always)]
    pub fn settled(&self) -> u64 {
        u64::from_le_bytes(self.settled)
    }
    #[inline(always)]
    pub fn set_settled(&mut self, v: u64) {
        self.settled = v.to_le_bytes();
    }

    #[inline(always)]
    pub fn paid_out(&self) -> u64 {
        u64::from_le_bytes(self.paid_out)
    }
    #[inline(always)]
    pub fn set_paid_out(&mut self, v: u64) {
        self.paid_out = v.to_le_bytes();
    }

    #[inline(always)]
    pub fn closure_started_at(&self) -> i64 {
        i64::from_le_bytes(self.closure_started_at)
    }
    #[inline(always)]
    pub fn set_closure_started_at(&mut self, v: i64) {
        self.closure_started_at = v.to_le_bytes();
    }

    #[inline(always)]
    pub fn payer_withdrawn_at(&self) -> i64 {
        i64::from_le_bytes(self.payer_withdrawn_at)
    }
    #[inline(always)]
    pub fn set_payer_withdrawn_at(&mut self, v: i64) {
        self.payer_withdrawn_at = v.to_le_bytes();
    }

    #[inline(always)]
    pub fn grace_period(&self) -> u32 {
        u32::from_le_bytes(self.grace_period)
    }
    #[inline(always)]
    pub fn set_grace_period(&mut self, v: u32) {
        self.grace_period = v.to_le_bytes();
    }

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

    /// Write all fields into a freshly-allocated account buffer.
    ///
    /// Called by `open` after the system-program CPI that allocates the PDA.
    /// Fails if `bytes` is not exactly [`Self::LEN`] bytes.
    #[allow(clippy::too_many_arguments)]
    pub fn init_at(
        bytes: &mut [u8],
        bump: u8,
        salt: u64,
        deposit: u64,
        grace_period: u32,
        distribution_hash: [u8; 32],
        payer: Address,
        payee: Address,
        authorized_signer: Address,
        mint: Address,
    ) -> Result<(), ProgramError> {
        // SAFETY: `Channel` is `repr(C)` with alignment 1; load_mut checks length.
        let ch = unsafe { load_mut::<Self>(bytes) }?;
        ch.discriminator = AccountDiscriminator::Channel as u8;
        ch.version = CURRENT_CHANNEL_VERSION;
        ch.bump = bump;
        ch.status = ChannelStatus::Open as u8;
        ch.salt = salt.to_le_bytes();
        ch.deposit = deposit.to_le_bytes();
        ch.settled = 0u64.to_le_bytes();
        ch.paid_out = 0u64.to_le_bytes();
        ch.closure_started_at = 0i64.to_le_bytes();
        ch.payer_withdrawn_at = 0i64.to_le_bytes();
        ch.grace_period = grace_period.to_le_bytes();
        ch.distribution_hash = distribution_hash;
        ch.payer = payer;
        ch.payee = payee;
        ch.authorized_signer = authorized_signer;
        ch.mint = mint;
        Ok(())
    }

    fn load(bytes: &[u8]) -> Result<&Self, ProgramError> {
        let channel = unsafe { load::<Self>(bytes) }?;
        Self::validate_header(channel)?;
        Ok(channel)
    }

    fn load_mut(bytes: &mut [u8]) -> Result<&mut Self, ProgramError> {
        let channel = unsafe { load_mut::<Self>(bytes) }?;
        Self::validate_header(channel)?;
        Ok(channel)
    }

    fn validate_header(channel: &Self) -> Result<(), ProgramError> {
        if channel.discriminator != AccountDiscriminator::Channel as u8 {
            return Err(PaymentChannelsError::InvalidAccountDiscriminator.into());
        }
        if channel.version != CURRENT_CHANNEL_VERSION {
            return Err(PaymentChannelsError::UnsupportedChannelVersion.into());
        }
        Ok(())
    }
}

unsafe impl Transmutable for Channel {
    const LEN: usize = size_of::<Self>();
}

const _: () = {
    assert!(Channel::LEN == 216);
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
    fn size_is_216_bytes() {
        assert_eq!(core::mem::size_of::<Channel>(), 216);
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
