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
///
/// The discriminator byte (`repr(u8)` value) is serialized as the first byte
/// of instruction data; variants that carry a payload deserialize the
/// remaining bytes as their args struct. Runtime dispatch goes through
/// [`Self::from_bytes`] and the match in `lib.rs`. The same enum, via its
/// feature-gated codama derives + helper attrs, is the source of truth for
/// IDL generation — so adding or renaming an instruction is a single-site
/// change.
// Boxing the large variant would add a heap alloc, which is incompatible
// with `no_allocator!()`; the enum is destructured immediately at the
// single dispatch site so the footprint never leaves that stack frame.
#[derive(Debug)]
#[cfg_attr(feature = "idl", derive(CodamaInstructions))]
#[repr(u8)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum PaymentChannelsInstruction {
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
    Open(#[cfg_attr(feature = "idl", codama(name = "open_args"))] open::OpenArgs) = 0,

    #[cfg_attr(
        feature = "idl",
        codama(account(name = "merchant", signer)),
        codama(account(name = "channel", writable)),
        codama(account(name = "instructions_sysvar"))
    )]
    Settle(#[cfg_attr(feature = "idl", codama(name = "settle_args"))] settle::SettleArgs) = 1,

    #[cfg_attr(
        feature = "idl",
        codama(account(name = "payer", signer, writable)),
        codama(account(name = "channel", writable)),
        codama(account(name = "payer_token_account", writable)),
        codama(account(name = "channel_token_account", writable)),
        codama(account(name = "mint")),
        codama(account(name = "token_program"))
    )]
    TopUp(#[cfg_attr(feature = "idl", codama(name = "top_up_args"))] top_up::TopUpArgs) = 2,

    #[cfg_attr(
        feature = "idl",
        codama(account(name = "merchant", signer)),
        codama(account(name = "channel", writable)),
        codama(account(name = "instructions_sysvar"))
    )]
    SettleAndFinalize(
        #[cfg_attr(feature = "idl", codama(name = "settle_and_finalize_args"))]
        settle_and_finalize::SettleAndFinalizeArgs,
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
        #[cfg_attr(feature = "idl", codama(name = "distribute_args"))] distribute::DistributeArgs,
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

impl PaymentChannelsInstruction {
    /// Parse an instruction from raw bytes: first byte is the discriminator,
    /// remainder is the args payload for variants that carry one. Mirrors
    /// `solana-program/multi-delegator::MultiDelegatorInstruction::from_bytes`.
    pub(crate) fn from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        let (disc, rest) = data
            .split_first()
            .ok_or(ProgramError::InvalidInstructionData)?;

        match *disc {
            open::DISCRIMINATOR => Ok(Self::Open(*open::OpenArgs::load(rest)?)),
            settle::DISCRIMINATOR => Ok(Self::Settle(*settle::SettleArgs::load(rest)?)),
            top_up::DISCRIMINATOR => Ok(Self::TopUp(*top_up::TopUpArgs::load(rest)?)),
            settle_and_finalize::DISCRIMINATOR => Ok(Self::SettleAndFinalize(
                *settle_and_finalize::SettleAndFinalizeArgs::load(rest)?,
            )),
            request_close::DISCRIMINATOR => Ok(Self::RequestClose),
            finalize::DISCRIMINATOR => Ok(Self::Finalize),
            distribute::DISCRIMINATOR => {
                Ok(Self::Distribute(*distribute::DistributeArgs::load(rest)?))
            }
            withdraw_payer::DISCRIMINATOR => Ok(Self::WithdrawPayer),
            withdraw_payee::DISCRIMINATOR => Ok(Self::WithdrawPayee),
            emit_event::DISCRIMINATOR => Ok(Self::EmitEvent),
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}

// Verify enum discriminant literals match the handler-module DISCRIMINATOR
// constants. A mismatch would route tx bytes differently than clients
// (which read the IDL's enum values) expect. Stable Rust (`const _: () =
// assert!(...)` since 1.57) gives us this at zero runtime cost.
const _: () = {
    assert!(open::DISCRIMINATOR == 0);
    assert!(settle::DISCRIMINATOR == 1);
    assert!(top_up::DISCRIMINATOR == 2);
    assert!(settle_and_finalize::DISCRIMINATOR == 3);
    assert!(request_close::DISCRIMINATOR == 4);
    assert!(finalize::DISCRIMINATOR == 5);
    assert!(distribute::DISCRIMINATOR == 6);
    assert!(withdraw_payer::DISCRIMINATOR == 7);
    assert!(withdraw_payee::DISCRIMINATOR == 8);
    assert!(emit_event::DISCRIMINATOR == crate::event_engine::EMIT_EVENT_IX_DISC);
    assert!(emit_event::DISCRIMINATOR == 228);
};
