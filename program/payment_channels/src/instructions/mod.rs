pub mod distribute;
pub mod emit_event;
pub mod finalize;
pub mod helpers;
pub mod open;
pub mod request_close;
pub mod settle;
pub mod settle_and_finalize;
pub mod top_up;
pub mod withdraw_payee;
pub mod withdraw_payer;

#[cfg(feature = "idl")]
use codama::{CodamaInstructions, CodamaType};
use pinocchio::{Address, error::ProgramError};

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "idl", derive(CodamaType))]
pub struct VoucherArgs {
    pub cumulative_amount: u64,
    pub expires_at: i64,
    pub channel_id: Address,
    pub signer: Address,
    pub signature: [u8; 64],
}

/// All instructions supported by the payment-channels program.
#[derive(Debug)]
#[cfg_attr(feature = "idl", derive(CodamaInstructions))]
#[repr(u8)]
pub(crate) enum PaymentChannelsInstruction<'a> {
    #[cfg_attr(
        feature = "idl",
        codama(account(name = "payer", signer, writable)),
        codama(account(name = "payee")),
        codama(account(name = "mint")),
        codama(account(name = "authorized_signer")),
        codama(account(name = "channel", writable)),
        codama(account(name = "payer_token_account", writable)),
        codama(account(name = "channel_token_account", writable)),
        codama(account(name = "token_program")),
        codama(account(name = "system_program", default_value = program("system"))),
        codama(account(name = "rent")),
        codama(account(name = "event_authority")),
        codama(account(name = "self_program"))
    )]
    Open(#[cfg_attr(feature = "idl", codama(name = "open_args"))] &'a open::OpenArgs) = 0,

    #[cfg_attr(
        feature = "idl",
        codama(account(name = "merchant", signer)),
        codama(account(name = "channel", writable)),
        codama(account(name = "instructions_sysvar"))
    )]
    Settle(#[cfg_attr(feature = "idl", codama(name = "settle_args"))] &'a settle::SettleArgs) = 1,

    #[cfg_attr(
        feature = "idl",
        codama(account(name = "payer", signer, writable)),
        codama(account(name = "channel", writable)),
        codama(account(name = "payer_token_account", writable)),
        codama(account(name = "channel_token_account", writable)),
        codama(account(name = "mint")),
        codama(account(name = "token_program"))
    )]
    TopUp(#[cfg_attr(feature = "idl", codama(name = "top_up_args"))] &'a top_up::TopUpArgs) = 2,

    #[cfg_attr(
        feature = "idl",
        codama(account(name = "merchant", signer)),
        codama(account(name = "channel", writable)),
        codama(account(name = "instructions_sysvar"))
    )]
    SettleAndFinalize(
        #[cfg_attr(feature = "idl", codama(name = "settle_and_finalize_args"))]
        &'a settle_and_finalize::SettleAndFinalizeArgs,
    ) = 3,

    #[cfg_attr(
        feature = "idl",
        codama(account(name = "payer", signer)),
        codama(account(name = "channel", writable)),
        codama(account(name = "clock"))
    )]
    RequestClose = 4,

    #[cfg_attr(
        feature = "idl",
        codama(account(name = "cranker")),
        codama(account(name = "channel", writable)),
        codama(account(name = "clock"))
    )]
    Finalize = 5,

    #[cfg_attr(
        feature = "idl",
        codama(account(name = "cranker")),
        codama(account(name = "channel", writable)),
        codama(account(name = "channel_token_account", writable)),
        codama(account(name = "payer_token_account", writable)),
        codama(account(name = "mint")),
        codama(account(name = "token_program"))
    )]
    Distribute(
        #[cfg_attr(feature = "idl", codama(name = "distribute_args"))]
        &'a distribute::DistributeArgs,
    ) = 6,

    #[cfg_attr(
        feature = "idl",
        codama(account(name = "payer", signer)),
        codama(account(name = "channel", writable)),
        codama(account(name = "channel_token_account", writable)),
        codama(account(name = "payer_token_account", writable)),
        codama(account(name = "mint")),
        codama(account(name = "token_program")),
        codama(account(name = "clock"))
    )]
    WithdrawPayer = 7,

    #[cfg_attr(
        feature = "idl",
        codama(account(name = "cranker")),
        codama(account(name = "channel", writable)),
        codama(account(name = "channel_token_account", writable)),
        codama(account(name = "payee_token_account", writable)),
        codama(account(name = "payer_token_account", writable)),
        codama(account(name = "payer", writable)),
        codama(account(name = "mint")),
        codama(account(name = "token_program")),
        codama(account(name = "clock"))
    )]
    WithdrawPayee = 8,

    // `228 = EVENT_IX_TAG_LE[0]`; self-CPI event data starts with this byte
    // so byte-0 dispatch routes straight to `emit_event::process`.
    #[cfg_attr(feature = "idl", codama(account(name = "event_authority", signer)))]
    EmitEvent = 228,
}

impl<'a> PaymentChannelsInstruction<'a> {
    pub(crate) fn from_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        let (disc, rest) = data
            .split_first()
            .ok_or(ProgramError::InvalidInstructionData)?;

        match *disc {
            open::DISCRIMINATOR => Ok(Self::Open(open::OpenArgs::load(rest)?)),
            settle::DISCRIMINATOR => Ok(Self::Settle(settle::SettleArgs::load(rest)?)),
            top_up::DISCRIMINATOR => Ok(Self::TopUp(top_up::TopUpArgs::load(rest)?)),
            settle_and_finalize::DISCRIMINATOR => Ok(Self::SettleAndFinalize(
                settle_and_finalize::SettleAndFinalizeArgs::load(rest)?,
            )),
            request_close::DISCRIMINATOR => Ok(Self::RequestClose),
            finalize::DISCRIMINATOR => Ok(Self::Finalize),
            distribute::DISCRIMINATOR => {
                Ok(Self::Distribute(distribute::DistributeArgs::load(rest)?))
            }
            withdraw_payer::DISCRIMINATOR => Ok(Self::WithdrawPayer),
            withdraw_payee::DISCRIMINATOR => Ok(Self::WithdrawPayee),
            emit_event::DISCRIMINATOR => Ok(Self::EmitEvent),
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}
