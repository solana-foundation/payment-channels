#[cfg(feature = "idl")]
use codama::CodamaType;
use pinocchio::error::ProgramError;

use crate::errors::PaymentChannelsError;

/// Frozen V1 version stamped by `open`. Hooked opens use version 2 without
/// converting existing accounts; both layouts remain supported at runtime.
pub const CURRENT_CHANNEL_VERSION: u8 = 1;

/// Byte-0 tag for this program's account shapes. Starts at 1 so
/// zero-initialized bytes fail the [`Channel`](crate::Channel) load check
/// before any downstream field is interpreted.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Debug)]
#[cfg_attr(feature = "idl", derive(CodamaType))]
pub enum AccountDiscriminator {
    /// Active [`Channel`](crate::Channel) PDA.
    Channel = 1,
    /// Tombstone written by a previous deployment of this program id. The
    /// program neither creates nor reads these accounts; the byte value is
    /// kept so no future account shape aliases the on-chain leftovers.
    ClosedChannel = 2,
}

impl TryFrom<u8> for AccountDiscriminator {
    type Error = ProgramError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Channel),
            2 => Ok(Self::ClosedChannel),
            _ => Err(PaymentChannelsError::InvalidAccountDiscriminator.into()),
        }
    }
}
