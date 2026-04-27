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
    #[error("num_recipients outside [1, MAX_DISTRIBUTION_RECIPIENTS]")]
    InvalidRecipientCount = 15,
    #[error("Channel account does not match derived PDA")]
    ChannelAddressMismatch = 16,
    #[error("Escrow account does not match derived ATA")]
    EscrowAddressMismatch = 17,
    #[error("Payer and payee must be different accounts")]
    PayerPayeeMustDiffer = 18,
    #[error("Each shareBps must be non-zero and Σbps must be strictly less than 10_000")]
    InvalidSplitConfig = 19,
    #[error("Recipient token account is not the expected ATA")]
    InvalidRecipientAccount = 21,
    #[error("Mint account does not match channel.mint")]
    MintAccountMismatch = 22,
    #[error("Payer account does not match channel.payer")]
    PayerAccountMismatch = 23,
    #[error("Token program must be SPL Token or Token-2022")]
    InvalidTokenProgram = 24,
    #[error("Treasury token account is not ATA(TREASURY_OWNER, mint, token_program)")]
    TreasuryAddressMismatch = 25,
    #[error("Arithmetic overflow")]
    ArithmeticOverflow = 26,
    #[error("Channel is not in OPEN or FINALIZED")]
    ChannelNotClosable = 27,
    #[error("Channel token account is not ATA(channel, mint, token_program)")]
    InvalidChannelTokenAccount = 28,
    #[error("Payer token account is not ATA(payer, mint, token_program)")]
    InvalidPayerTokenAccount = 29,
    #[error("Token-2022 mint or token account uses unsupported extensions for exact distribution")]
    UnsupportedTokenExtensions = 30,
    #[error("No newly settled funds to distribute")]
    NothingToDistribute = 31,
}
