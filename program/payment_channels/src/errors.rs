#[cfg(feature = "idl")]
use codama::CodamaErrors;
use pinocchio::error::ProgramError;
use thiserror::Error;

impl From<PaymentChannelsError> for ProgramError {
    fn from(e: PaymentChannelsError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

#[derive(Debug, Copy, Clone, Error)]
#[cfg_attr(feature = "idl", derive(CodamaErrors))]
pub enum PaymentChannelsError {
    #[error("Not implemented")]
    NotImplemented = 0,
    #[error("Invalid channel status")]
    InvalidChannelStatus = 1,
    #[error("Invalid event authority")]
    InvalidEventAuthority = 2,
    #[error("Invalid account discriminator")]
    InvalidAccountDiscriminator = 3,
    #[error("Unsupported channel version")]
    UnsupportedChannelVersion = 4,
}
