//! Read-only readers for the two frozen account layouts. These readers never
//! interpret a V1 account as V2 and never expose mutable accounting state.
use pinocchio::{Address, error::ProgramError};

use crate::HookState;

pub const CHANNEL_SEED: &[u8] = b"channel";
pub const CHANNEL_V1_LEN: usize = 256;
pub const CHANNEL_V2_LEN: usize = 1121;
pub const CHANNEL_DISCRIMINATOR: u8 = 1;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelStatus {
    Open = 0,
    Sealed = 1,
    Closing = 2,
    Distributed = 3,
}

impl TryFrom<u8> for ChannelStatus {
    type Error = ProgramError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Open),
            1 => Ok(Self::Sealed),
            2 => Ok(Self::Closing),
            3 => Ok(Self::Distributed),
            _ => Err(ProgramError::InvalidAccountData),
        }
    }
}

/// A checked byte view, not a Rust-layout cast. Raw readers check layout only;
/// callers must verify ownership (the callback validator does this).
#[derive(Debug, Clone, Copy)]
pub struct ChannelView<'a> {
    bytes: &'a [u8],
}

impl<'a> ChannelView<'a> {
    pub fn v1(bytes: &'a [u8]) -> Result<Self, ProgramError> {
        Self::read(bytes, 1, CHANNEL_V1_LEN)
    }

    pub fn v2(bytes: &'a [u8]) -> Result<Self, ProgramError> {
        Self::read(bytes, 2, CHANNEL_V2_LEN)
    }

    fn read(bytes: &'a [u8], version: u8, len: usize) -> Result<Self, ProgramError> {
        if bytes.len() != len || bytes[0] != CHANNEL_DISCRIMINATOR || bytes[1] != version {
            return Err(ProgramError::InvalidAccountData);
        }
        ChannelStatus::try_from(bytes[3])?;
        Ok(Self { bytes })
    }

    fn array<const N: usize>(&self, offset: usize) -> [u8; N] {
        let mut out = [0; N];
        out.copy_from_slice(&self.bytes[offset..offset + N]);
        out
    }

    pub fn bump(&self) -> u8 {
        self.bytes[2]
    }
    pub fn status(&self) -> Result<ChannelStatus, ProgramError> {
        ChannelStatus::try_from(self.bytes[3])
    }
    pub fn salt(&self) -> u64 {
        u64::from_le_bytes(self.array(4))
    }
    pub fn deposit(&self) -> u64 {
        u64::from_le_bytes(self.array(12))
    }
    pub fn settled(&self) -> u64 {
        u64::from_le_bytes(self.array(20))
    }
    pub fn payout_watermark(&self) -> u64 {
        u64::from_le_bytes(self.array(28))
    }
    pub fn payer_withdrawn_at(&self) -> i64 {
        i64::from_le_bytes(self.array(44))
    }
    pub fn distribution_hash(&self) -> [u8; 32] {
        self.array(56)
    }
    pub fn payer(&self) -> Address {
        Address::new_from_array(self.array(88))
    }
    pub fn payee(&self) -> Address {
        Address::new_from_array(self.array(120))
    }
    pub fn authorized_signer(&self) -> Address {
        Address::new_from_array(self.array(152))
    }
    pub fn mint(&self) -> Address {
        Address::new_from_array(self.array(184))
    }
    pub fn open_slot(&self) -> u64 {
        u64::from_le_bytes(self.array(248))
    }

    pub fn hooks(&self) -> Result<&'a HookState, ProgramError> {
        let bytes = self
            .bytes
            .get(CHANNEL_V1_LEN..)
            .filter(|bytes| bytes.len() == core::mem::size_of::<HookState>())
            .ok_or(ProgramError::InvalidAccountData)?;
        // SAFETY: exact length above; HookState has alignment one and only
        // byte arrays/Address/u8 fields, so every bit pattern is valid.
        Ok(unsafe { &*bytes.as_ptr().cast::<HookState>() })
    }

    pub fn find_pda(&self, program: &Address) -> (Address, u8) {
        channel_address(
            program,
            &self.payer(),
            &self.payee(),
            &self.mint(),
            &self.authorized_signer(),
            self.salt(),
            self.open_slot(),
        )
    }
}

pub fn channel_address(
    program: &Address,
    payer: &Address,
    payee: &Address,
    mint: &Address,
    authorized_signer: &Address,
    salt: u64,
    open_slot: u64,
) -> (Address, u8) {
    Address::find_program_address(
        &[
            CHANNEL_SEED,
            payer.as_ref(),
            payee.as_ref(),
            mint.as_ref(),
            authorized_signer.as_ref(),
            &salt.to_le_bytes(),
            &open_slot.to_le_bytes(),
        ],
        program,
    )
}
