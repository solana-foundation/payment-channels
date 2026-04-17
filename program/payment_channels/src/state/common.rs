#[cfg(feature = "idl")]
use codama::CodamaType;
use pinocchio::error::ProgramError;

use crate::errors::PaymentChannelsError;

pub const CURRENT_CHANNEL_VERSION: u8 = 1;

/// Starts at 1 so zero-initialized account bytes (the freshly-allocated
/// state) fail the load() discriminator check.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Debug)]
#[cfg_attr(feature = "idl", derive(CodamaType))]
pub enum AccountDiscriminator {
    Channel = 1,
}

impl TryFrom<u8> for AccountDiscriminator {
    type Error = ProgramError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Channel),
            _ => Err(PaymentChannelsError::InvalidAccountDiscriminator.into()),
        }
    }
}
