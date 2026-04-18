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

pub const CHANNEL_LEN: usize = size_of::<Channel>();

/// PDA seed prefix. Full seeds:
/// `[CHANNEL_SEED, payer, payee, mint, authorized_signer, salt.to_le_bytes()]`.
pub const CHANNEL_SEED: &[u8] = b"channel";

/// Starts at 0 because `AccountDiscriminator` at byte 0 already rejects
/// zero-initialized accounts before `status` is read.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "idl", derive(CodamaType))]
pub enum ChannelStatus {
    Open = 0,
    Finalized = 1,
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

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "idl", derive(CodamaAccount))]
pub struct Channel {
    pub discriminator: u8,       //   0..1    AccountDiscriminator::Channel
    pub version: u8,             //   1..2    CURRENT_CHANNEL_VERSION
    pub bump: u8,                //   2..3    PDA bump
    pub status: u8,              //   3..4    ChannelStatus
    pub deposit: u64,            //   4..12
    pub settled: u64,            //  12..20
    pub paid_out: u64,           //  20..28
    pub closure_started_at: i64, //  28..36
    pub payer_withdrawn_at: i64, //  36..44
    pub grace_period: u32,       //  44..48
    /// Blake3 commitment to the distribution preimage; see ADR-001 §Channel PDA.
    pub distribution_hash: [u8; 32], //  48..80
    pub payer: Address,          //  80..112
    pub payee: Address,          // 112..144
    pub authorized_signer: Address, // 144..176
    pub mint: Address,           // 176..208
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

    /// Owner-checked borrow — the only path to a `&Channel`. `load` is
    /// module-private, so callers cannot bypass the owner/discriminator
    /// checks.
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
