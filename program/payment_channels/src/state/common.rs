#[cfg(feature = "idl")]
use codama::CodamaType;
use pinocchio::error::ProgramError;

use crate::errors::PaymentChannelsError;

/// Schema version stamped into [`Channel::version`](crate::Channel::version)
/// at `open`. Bump when the PDA layout changes; [`Channel`](crate::Channel)
/// refuses any other value on load, so migrations must be explicit.
pub const CURRENT_CHANNEL_VERSION: u8 = 2;

/// Byte-0 tag for this program's account shapes. Starts at 1 so
/// zero-initialized bytes fail the [`Channel`](crate::Channel) load check
/// before any downstream field is interpreted.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Debug)]
#[cfg_attr(feature = "idl", derive(CodamaType))]
pub enum AccountDiscriminator {
    /// Active [`Channel`](crate::Channel) PDA.
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
