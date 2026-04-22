pub mod distribute;
pub mod emit_event;
pub mod finalize;
pub mod helpers;
pub mod open;
pub mod request_close;
pub mod settle;
pub mod settle_and_finalize;
pub mod top_up;
pub mod withdraw_payer;

#[cfg(feature = "idl")]
use codama::{CodamaInstructions, CodamaType};
use pinocchio::{Address, error::ProgramError};

use crate::state::Transmutable;

/// On-chain wire encoding of the voucher. Field order is re-packed vs.
/// the off-chain JSON shape to make the struct zero-copy loadable.
/// Ed25519-only; signature verification is offloaded to a caller-bundled
/// Ed25519 native-program ix whose message bytes are read back via the
/// Instructions sysvar.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "idl", derive(CodamaType))]
pub struct VoucherArgs {
    /// Monotonic watermark. Must satisfy
    /// [`settled`](crate::Channel::settled) `< cumulative_amount ≤`
    /// [`deposit`](crate::Channel::deposit); the strict increase also
    /// serves as the implicit nonce.
    #[cfg_attr(feature = "idl", codama(type = number(u64)))]
    cumulative_amount: [u8; 8],
    /// Unix-seconds TTL; `0` means no expiry. Freshness:
    /// `expires_at == 0 || now < expires_at`.
    #[cfg_attr(feature = "idl", codama(type = number(i64)))]
    expires_at: [u8; 8],
    /// Replay scope; must equal the [`Channel`](crate::Channel) PDA.
    pub channel_id: Address,
    /// Voucher author. Must equal
    /// [`Channel::authorized_signer`](crate::Channel::authorized_signer).
    pub signer: Address,
    /// Ed25519 signature over the JCS canonicalization (RFC 8785) of the
    /// logical voucher payload. Verified by matching the Ed25519
    /// native-program ix's message bytes against the JCS re-encoding of
    /// these fields.
    pub signature: [u8; 64],
}

impl VoucherArgs {
    #[inline(always)]
    pub fn cumulative_amount(&self) -> u64 {
        u64::from_le_bytes(self.cumulative_amount)
    }
    #[inline(always)]
    pub fn expires_at(&self) -> i64 {
        i64::from_le_bytes(self.expires_at)
    }
}

unsafe impl Transmutable for VoucherArgs {
    const LEN: usize = core::mem::size_of::<Self>();
}

/// Byte-0-dispatched instruction codomain. Each variant's discriminant
/// matches the `DISCRIMINATOR` const in the corresponding sibling module;
/// [`from_bytes`](Self::from_bytes) peels the first byte and routes to the
/// matching `Args::load`.
#[derive(Debug)]
#[cfg_attr(feature = "idl", derive(CodamaInstructions))]
#[repr(u8)]
pub(crate) enum PaymentChannelsInstruction<'a> {
    /// Payer-signed; creates the channel PDA, locks the deposit, and
    /// commits the distribution hash. `NONEXISTENT → OPEN`.
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
    Open(#[cfg_attr(feature = "idl", codama(name = "open_args"))] &'a open::OpenArgs) = 1,

    /// Advances the on-chain [`settled`](crate::Channel::settled) watermark
    /// against a payer-signed voucher. `OPEN → OPEN`.
    #[cfg_attr(
        feature = "idl",
        codama(account(name = "merchant", signer)),
        codama(account(name = "channel", writable)),
        codama(account(name = "instructions_sysvar"))
    )]
    Settle(#[cfg_attr(feature = "idl", codama(name = "settle_args"))] &'a settle::SettleArgs) = 2,

    /// Extends [`deposit`](crate::Channel::deposit) while `OPEN` and
    /// pre-`requestClose`. `OPEN → OPEN`.
    #[cfg_attr(
        feature = "idl",
        codama(account(name = "payer", signer, writable)),
        codama(account(name = "channel", writable)),
        codama(account(name = "payer_token_account", writable)),
        codama(account(name = "channel_token_account", writable)),
        codama(account(name = "mint")),
        codama(account(name = "token_program"))
    )]
    TopUp(#[cfg_attr(feature = "idl", codama(name = "top_up_args"))] &'a top_up::TopUpArgs) = 3,

    /// Merchant-signed cooperative close: optionally applies a final
    /// voucher, locks the watermark, and moves to `FINALIZED`. `OPEN →
    /// FINALIZED` leaves
    /// [`closure_started_at`](crate::Channel::closure_started_at) at 0;
    /// `CLOSING → FINALIZED` is only valid mid-grace and resets
    /// [`closure_started_at`](crate::Channel::closure_started_at) to 0.
    #[cfg_attr(
        feature = "idl",
        codama(account(name = "merchant", signer)),
        codama(account(name = "channel", writable)),
        codama(account(name = "instructions_sysvar"))
    )]
    SettleAndFinalize(
        #[cfg_attr(feature = "idl", codama(name = "settle_and_finalize_args"))]
        &'a settle_and_finalize::SettleAndFinalizeArgs,
    ) = 4,

    /// Payer-signed: starts the grace period by setting
    /// [`closure_started_at`](crate::Channel::closure_started_at) to `now`.
    /// `OPEN → CLOSING`.
    #[cfg_attr(
        feature = "idl",
        codama(account(name = "payer", signer)),
        codama(account(name = "channel", writable))
    )]
    RequestClose = 5,

    /// Permissionless post-grace crank: freezes the watermark and moves
    /// `CLOSING → FINALIZED` once the grace has elapsed; resets
    /// [`closure_started_at`](crate::Channel::closure_started_at) to 0.
    #[cfg_attr(feature = "idl", codama(account(name = "channel", writable)))]
    Finalize = 6,

    /// Permissionless crank. Verifies the committed preimage and pays
    /// [`settled`](crate::Channel::settled) `−`
    /// [`paid_out`](crate::Channel::paid_out) to merchant splits; from
    /// `FINALIZED` also refunds the payer (if not already withdrawn) and
    /// tombstones the PDA.
    #[cfg_attr(
        feature = "idl",
        codama(account(name = "channel", writable)),
        codama(account(name = "channel_token_account", writable)),
        codama(account(name = "payer_token_account", writable)),
        codama(account(name = "mint")),
        codama(account(name = "token_program"))
    )]
    Distribute(
        #[cfg_attr(feature = "idl", codama(name = "distribute_args"))]
        &'a distribute::DistributeArgs,
    ) = 7,

    /// Payer-signed one-shot refund of [`deposit`](crate::Channel::deposit)
    /// `−` [`settled`](crate::Channel::settled) during `FINALIZED`;
    /// records [`payer_withdrawn_at`](crate::Channel::payer_withdrawn_at)
    /// `= now`. Does not tombstone.
    #[cfg_attr(
        feature = "idl",
        codama(account(name = "payer", signer)),
        codama(account(name = "channel", writable)),
        codama(account(name = "channel_token_account", writable)),
        codama(account(name = "payer_token_account", writable)),
        codama(account(name = "mint")),
        codama(account(name = "token_program"))
    )]
    WithdrawPayer = 8,

    /// Self-CPI target for the event pipeline; not part of the public
    /// instruction set. `228 = EVENT_IX_TAG_LE[0]`: self-CPI event data
    /// starts with this byte, so byte-0 dispatch routes straight to
    /// [`emit_event::process`](crate::instructions::emit_event::process).
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
            emit_event::DISCRIMINATOR => Ok(Self::EmitEvent),
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // `#[repr(u8)]` lays the discriminant as the leading byte; reading
    // it back requires a raw-pointer cast because `mem::discriminant`
    // is opaque and variants with payloads can't `as u8`.
    fn tag(v: &PaymentChannelsInstruction<'_>) -> u8 {
        unsafe { *(v as *const _ as *const u8) }
    }

    #[test]
    fn discriminators_match_variants() {
        let open: open::OpenArgs = unsafe { core::mem::zeroed() };
        let settle: settle::SettleArgs = unsafe { core::mem::zeroed() };
        let top_up: top_up::TopUpArgs = unsafe { core::mem::zeroed() };
        let saf: settle_and_finalize::SettleAndFinalizeArgs = unsafe { core::mem::zeroed() };
        let distribute: distribute::DistributeArgs = unsafe { core::mem::zeroed() };

        assert_eq!(
            tag(&PaymentChannelsInstruction::Open(&open)),
            open::DISCRIMINATOR,
        );
        assert_eq!(
            tag(&PaymentChannelsInstruction::Settle(&settle)),
            settle::DISCRIMINATOR,
        );
        assert_eq!(
            tag(&PaymentChannelsInstruction::TopUp(&top_up)),
            top_up::DISCRIMINATOR,
        );
        assert_eq!(
            tag(&PaymentChannelsInstruction::SettleAndFinalize(&saf)),
            settle_and_finalize::DISCRIMINATOR,
        );
        assert_eq!(
            tag(&PaymentChannelsInstruction::RequestClose),
            request_close::DISCRIMINATOR,
        );
        assert_eq!(
            tag(&PaymentChannelsInstruction::Finalize),
            finalize::DISCRIMINATOR,
        );
        assert_eq!(
            tag(&PaymentChannelsInstruction::Distribute(&distribute)),
            distribute::DISCRIMINATOR,
        );
        assert_eq!(
            tag(&PaymentChannelsInstruction::WithdrawPayer),
            withdraw_payer::DISCRIMINATOR,
        );
        assert_eq!(
            tag(&PaymentChannelsInstruction::EmitEvent),
            emit_event::DISCRIMINATOR,
        );
    }
}
