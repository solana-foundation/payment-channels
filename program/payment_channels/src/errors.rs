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
    #[error("num_recipients outside [0, 32]")]
    InvalidRecipientCount = 15,
    #[error("Channel account does not match derived PDA")]
    ChannelAddressMismatch = 16,
    #[error("Escrow account does not match derived ATA")]
    EscrowAddressMismatch = 17,
    #[error("Payer and payee must be different accounts")]
    PayerPayeeMustDiffer = 18,
    #[error("Each shareBps must be non-zero and Σbps must be at most 10_000")]
    InvalidSplitConfig = 19,
    #[error("Recipient token account is not the expected ATA")]
    InvalidRecipientAccount = 20,
    #[error("Mint account does not match channel.mint")]
    MintAccountMismatch = 21,
    #[error("Payer account does not match channel.payer")]
    PayerAccountMismatch = 22,
    #[error("Token program must be SPL Token or Token-2022")]
    InvalidTokenProgram = 23,
    #[error("Treasury token account is not ATA(TREASURY_OWNER, mint, token_program)")]
    TreasuryAddressMismatch = 24,
    #[error("Arithmetic overflow")]
    ArithmeticOverflow = 25,
    #[error("Channel is not in OPEN or FINALIZED")]
    ChannelNotDistributable = 26,
    #[error("Channel token account is not ATA(channel, mint, token_program)")]
    InvalidChannelTokenAccount = 27,
    #[error("Payer token account is not ATA(payer, mint, token_program)")]
    InvalidPayerTokenAccount = 28,
    #[error("Token-2022 mint or token account uses unsupported extensions for exact distribution")]
    UnsupportedTokenExtensions = 29,
    #[error("No newly settled funds to distribute")]
    NothingToDistribute = 30,
    #[error("Payee token account is not ATA(payee, mint, token_program)")]
    InvalidPayeeTokenAccount = 31,
    #[error("Distribution plan contains a duplicate recipient address")]
    DuplicateRecipient = 32,
    #[error("Recipient ATA tail length does not match the committed plan's entry count")]
    RecipientAccountCountMismatch = 33,
    #[error("Caller is not the channel payer")]
    UnauthorizedPayer = 34,
    #[error("Token account or mint TLV trailer is malformed")]
    MalformedTokenAccountData = 35,
    #[error("Caller is not the channel payee")]
    UnauthorizedPayee = 36,
}
