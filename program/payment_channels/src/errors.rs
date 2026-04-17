use codama::CodamaErrors;
use pinocchio::error::ProgramError;
use thiserror::Error;

impl From<PaymentChannelsError> for ProgramError {
    fn from(e: PaymentChannelsError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

#[derive(Debug, Copy, Clone, Error, CodamaErrors)]
pub enum PaymentChannelsError {
    #[error("Not implemented")]
    NotImplemented = 0,
    #[error("Invalid channel status")]
    InvalidChannelStatus,
    #[error("Invalid event authority")]
    InvalidEventAuthority,
    #[error("Invalid event data")]
    InvalidEventData,
}
