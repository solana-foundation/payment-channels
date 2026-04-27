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
    #[error("Voucher channel_id does not match channel PDA")]
    VoucherChannelMismatch = 5,
    #[error("Voucher expired")]
    VoucherExpired = 6,
    #[error("Voucher watermark not strictly monotonic")]
    VoucherWatermarkNotMonotonic = 7,
    #[error("Voucher cumulative_amount exceeds channel deposit")]
    VoucherOverDeposit = 8,
    #[error("Missing Ed25519 precompile ix at current-1")]
    MissingEd25519Verification = 9,
    #[error("Malformed Ed25519 precompile instruction")]
    MalformedEd25519Instruction = 10,
    #[error("Ed25519 message does not match Borsh voucher payload")]
    VoucherMessageMismatch = 11,
    #[error("Voucher signer does not match channel authorized_signer")]
    VoucherSignerMismatch = 12,
    #[error("Distribution hash mismatch")]
    InvalidDistributionHash = 13,
    #[error("Deposit must be non-zero")]
    DepositMustBeNonZero = 14,
    #[error("Recipient count must be between 1 and 30")]
    InvalidRecipientCount = 15,
    #[error("Channel account does not match derived PDA")]
    ChannelAddressMismatch = 16,
    #[error("Escrow account does not match derived ATA")]
    EscrowAddressMismatch = 17,
    #[error("Payer and payee must be different accounts")]
    PayerPayeeMustDiffer = 18,
    #[error("Caller is not the channel payer")]
    UnauthorizedPayer = 19,
}
