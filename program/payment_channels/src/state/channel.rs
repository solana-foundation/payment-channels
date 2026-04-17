use codama::{CodamaAccount, CodamaType};
use core::mem::size_of;
use pinocchio::{Address, error::ProgramError};

use crate::errors::PaymentChannelsError;

pub const CHANNEL_LEN: usize = size_of::<Channel>();

/// PDA seed prefix. Full seeds:
/// `[CHANNEL_SEED, payer, payee, mint, authorized_signer, salt.to_le_bytes()]`.
pub const CHANNEL_SEED: &[u8] = b"channel";

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, CodamaType)]
pub enum ChannelStatus {
    Open = 1,
    Finalized = 2,
    Closing = 3,
}

impl TryFrom<u8> for ChannelStatus {
    type Error = ProgramError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Open),
            2 => Ok(Self::Finalized),
            3 => Ok(Self::Closing),
            _ => Err(PaymentChannelsError::InvalidChannelStatus.into()),
        }
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, CodamaAccount)]
pub struct Channel {
    pub deposit: u64,                //   0..8
    pub settled: u64,                //   8..16
    pub paid_out: u64,               //  16..24
    pub closure_started_at: i64,     //  24..32
    pub payer_withdrawn_at: i64,     //  32..40
    pub grace_period: u32,           //  40..44
    pub distribution_hash: [u8; 16], //  44..60
    pub payer: Address,              //  60..92
    pub payee: Address,              //  92..124
    pub authorized_signer: Address,  // 124..156
    pub mint: Address,               // 156..188
    pub status: u8,                  // 188..189
    pub bump: u8,                    // 189..190
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

    pub fn load(bytes: &[u8]) -> Result<&Self, ProgramError> {
        if bytes.len() != Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(unsafe { &*(bytes.as_ptr() as *const Self) })
    }

    pub fn load_mut(bytes: &mut [u8]) -> Result<&mut Self, ProgramError> {
        if bytes.len() != Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(unsafe { &mut *(bytes.as_mut_ptr() as *mut Self) })
    }
}

const _: () = {
    assert!(Channel::LEN == 190);
};
