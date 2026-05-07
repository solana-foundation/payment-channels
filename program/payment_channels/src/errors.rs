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
    // generel channel validation errors
    #[error("Not implemented")]
    NotImplemented = 0,
    #[error("A signature was required but not found")]
    MissingRequiredSignature = 1,
    #[error("Invalid channel status")]
    InvalidChannelStatus = 2,
    #[error("Invalid account discriminator")]
    InvalidAccountDiscriminator = 3,
    #[error("Unsupported channel version")]
    UnsupportedChannelVersion = 4,
    #[error("Account does not match channel payer")]
    InvalidChannelPayer = 5,
    #[error("Account does not match channel payee")]
    InvalidChannelPayee = 6,
    #[error("Account does not match channel mint")]
    InvalidChannelMint = 7,
    #[error("Invalid event authority")]
    InvalidEventAuthority = 8,
    #[error("Not enough accounts were provided")]
    NotEnoughAccountKeys = 9,

    // general account validations
    #[error("Channel account does not match derived PDA")]
    ChannelAccountMismatch = 50,
    #[error("Channel token account is not ATA(channel, mint, token_program)")]
    InvalidChannelTokenAccount = 51,
    #[error("Channel token account has invalid extensions")]
    InvalidChannelTokenExtensions = 52,
    #[error("Mint account does not match channel.mint")]
    MintAccountMismatch = 53,
    #[error("Token program must be SPL Token or Token-2022")]
    InvalidMintTokenProgram = 54,
    #[error("Token account or mint TLV trailer is malformed")]
    MalformedMintTokenAccountData = 55,
    #[error("Token account or mint TLV trailer is malformed")]
    MalformedMintTokenExtensions = 56,
    #[error("Payer token account is not ATA(payer, token_program, mint)")]
    PayerAccountMismatch = 57,
    #[error("Payer token account is invalid")]
    InvalidPayerTokenAccount = 58,
    #[error("Payer token account has invalid extensions")]
    InvalidPayerTokenExtensions = 59,
    #[error("Payee token account is not ATA(payee, token_program, mint)")]
    PayeeAccountMismatch = 60,
    #[error("Payee token account is invalid")]
    InvalidPayeeTokenAccount = 61,
    #[error("Payee token account has invalid extensions")]
    InvalidPayeeTokenExtensions = 62,

    // general object validations
    #[error("Deposit must be non-zero")]
    DepositMustBeNonZero = 200,

    // voucher validation
    #[error("Missing Ed25519 precompile ix at current-1")]
    MissingEd25519Verification = 230,
    #[error("Malformed Ed25519 precompile instruction")]
    MalformedEd25519Instruction = 231,
    #[error("Voucher channel_id does not match channel PDA")]
    VoucherChannelMismatch = 232,
    #[error("Voucher expired")]
    VoucherExpired = 233,
    #[error("Voucher watermark not strictly monotonic")]
    VoucherWatermarkNotMonotonic = 234,
    #[error("Voucher cumulative_amount exceeds channel deposit")]
    VoucherOverDeposit = 235,
    #[error("Ed25519 message does not match Borsh voucher payload")]
    VoucherMessageMismatch = 236,
    #[error("Voucher signer does not match channel authorized_signer")]
    VoucherSignerMismatch = 237,

    // distribution validation
    #[error("num_recipients outside [0, 32]")]
    InvalidRecipientCount = 260,
    #[error("Each shareBps must be non-zero and Σbps must be at most 10_000")]
    InvalidSplitConfig = 261,
    #[error("num_recipients outside [0, 32]")]
    DistributionPartsOverflow = 262,
    #[error("Distribution plan contains a duplicate recipient address")]
    DuplicateRecipient = 263,
    #[error("num_recipients outside [0, 32]")]
    DistributionAmountOverflow = 264,
    #[error("Distribution preimage length calculation overflow")]
    DistributionPreimageLengthOverflow = 265,

    // ix open
    #[error("Derived channel account address does not match the user provided address")]
    ChannelAddressMismatch = 2000,
    #[error("Payer and payee must be different accounts")]
    PayerPayeeMustDiffer = 2001,

    // ix top_up
    #[error("Deposit must be non-zero")]
    TopUpDepositOverflow = 2100,

    // ix finalize
    #[error("Deadline overflow on grace period")]
    FinalizeDeadlineOverflow = 2200,

    // ix withdraw_payer
    #[error("Payer refund has already been claimed")]
    PayerAlreadyWithdrawn = 2300,
    #[error("Payer refund amount calculation underflow")]
    RefundCalculationOverflow = 2301,

    // ix distribute
    #[error("Channel is not in OPEN or FINALIZED")]
    ChannelNotDistributable = 2400,
    #[error("Treasury token account is not ATA(TREASURY_OWNER, mint, token_program)")]
    TreasuryAccountMismatch = 2401,
    #[error("Treasury token account is invalid")]
    InvalidTreasuryTokenAccount = 2402,
    #[error("Treasury token account has invalid extensions")]
    InvalidTreasuryTokenExtensions = 2403,
    #[error("Recipient token account is not ATA(recipient, token_program, mint)")]
    RecipientAccountMismatch = 2404,
    #[error("Recipient token account is invalid")]
    InvalidRecipientTokenAccount = 2405,
    #[error("Recipient token account has invalid extensions")]
    InvalidRecipientTokenExtensions = 2406,
    #[error("Distribution hash mismatch")]
    InvalidDistributionHash = 2407,
    #[error("No newly settled funds to distribute")]
    NothingToDistribute = 2408,
    #[error("Recipient ATA tail length does not match the committed plan's entry count")]
    RecipientAccountCountMismatch = 2409,
    #[error("Distribution pool calculation underflow")]
    DistributePoolOverflow = 2410,
    #[error("Channel rent rebalance calculation underflow")]
    DistributeBalanceCalculationOverflow = 2411,
    #[error("Payer lamports overflow on rent refund")]
    DistributePayerBalanceOverflow = 2412,
}
