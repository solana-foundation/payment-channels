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
use codama::{CodamaInstructions, CodamaPda, CodamaType};
use pinocchio::{Address, error::ProgramError};

use crate::state::Transmutable;

/// On-chain wire encoding of the voucher. Field order matches
/// Borsh(`{ channel_id, cumulative_amount, expires_at }`), so the
/// struct's raw bytes ARE the ed25519-signed payload — no repack.
/// Ed25519-only; signature verification is offloaded to a caller-bundled
/// Ed25519 native-program ix whose message bytes are read back via the
/// Instructions sysvar.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "idl", derive(CodamaType))]
pub struct VoucherArgs {
    /// Replay scope; must equal the [`Channel`](crate::Channel) PDA.
    pub channel_id: Address,
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
}

impl VoucherArgs {
    pub fn new(channel_id: Address, cumulative_amount: u64, expires_at: i64) -> Self {
        Self {
            channel_id,
            cumulative_amount: cumulative_amount.to_le_bytes(),
            expires_at: expires_at.to_le_bytes(),
        }
    }

    #[inline(always)]
    pub fn cumulative_amount(&self) -> u64 {
        u64::from_le_bytes(self.cumulative_amount)
    }
    #[inline(always)]
    pub fn expires_at(&self) -> i64 {
        i64::from_le_bytes(self.expires_at)
    }
}

/// Byte length of the signed voucher payload — `channel_id (32) ||
/// cumulative_amount (8 LE) || expires_at (8 LE)`, which is exactly the
/// in-memory layout of [`VoucherArgs`]. Also the canonical
/// `message_data_size` every Ed25519 precompile ix must declare; pinned
/// against a layout where an attacker has the precompile verify a
/// truncated or extended message.
pub const VOUCHER_PAYLOAD_SIZE: usize = core::mem::size_of::<VoucherArgs>();

/// Pins [`VOUCHER_PAYLOAD_SIZE`] to the Ed25519 precompile's `u16`
/// `message_data_size` field so the `as u16` casts at ix-build sites
/// can't silently truncate.
const _: () = assert!(VOUCHER_PAYLOAD_SIZE <= u16::MAX as usize);

unsafe impl Transmutable for VoucherArgs {
    const LEN: usize = VOUCHER_PAYLOAD_SIZE;
}

/// PDA signer for Anchor-compatible self-CPI event emission.
///
/// Runtime code derives the same address from
/// [`EVENT_AUTHORITY_SEED`](crate::event_engine::EVENT_AUTHORITY_SEED); this
/// IDL-only marker lets generated clients derive it for `open` and
/// `emitEvent`.
#[cfg(feature = "idl")]
#[allow(dead_code)]
#[derive(CodamaPda)]
#[codama(seed(type = string(utf8), value = "event_authority"))]
pub(crate) struct EventAuthority;

/// Byte-0-dispatched instruction codomain. Each variant's discriminant
/// matches the `DISCRIMINATOR` const in the corresponding sibling module;
/// [`from_bytes`](Self::from_bytes) peels the first byte and routes to the
/// matching `Args::load`.
#[derive(Debug)]
#[cfg_attr(feature = "idl", derive(CodamaInstructions))]
#[repr(u8)]
pub enum PaymentChannelsInstruction<'a> {
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
        codama(account(name = "associated_token_program")),
        codama(account(name = "event_authority", default_value = pda("eventAuthority"))),
        codama(account(name = "self_program"))
    )]
    Open(#[cfg_attr(feature = "idl", codama(name = "open_args"))] open::OpenArgs<'a>) = 1,

    /// Permissionless crank: advances the on-chain
    /// [`settled`](crate::Channel::settled) watermark against a voucher
    /// signed by [`Channel::authorized_signer`](crate::Channel::authorized_signer).
    /// `OPEN → OPEN`.
    #[cfg_attr(
        feature = "idl",
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
    /// cumulative floor deltas between
    /// [`payout_watermark`](crate::Channel::payout_watermark) and
    /// [`settled`](crate::Channel::settled) across recipients (per-bps) +
    /// payee's implicit remainder share. In `OPEN`, residual dust remains
    /// claimable by future cumulative deltas while
    /// [`payout_watermark`](crate::Channel::payout_watermark) advances to
    /// [`settled`](crate::Channel::settled). From `FINALIZED`, final floor
    /// residual is swept to treasury, the payer receives the unspent
    /// [`deposit`](crate::Channel::deposit) `−`
    /// [`settled`](crate::Channel::settled) headroom (if not already
    /// withdrawn) and tombstones the escrow ATA + the Channel PDA.
    /// Recipient token accounts are appended as remaining accounts in the
    /// same order as the`DistributionEntry`s in the preimage.
    #[cfg_attr(
        feature = "idl",
        codama(account(name = "channel", writable)),
        codama(account(name = "payer", writable)),
        codama(account(name = "channel_token_account", writable)),
        codama(account(name = "payer_token_account", writable)),
        codama(account(name = "payee_token_account", writable)),
        codama(account(name = "treasury_token_account", writable)),
        codama(account(name = "mint")),
        codama(account(name = "token_program")),
        codama(account(name = "event_authority", default_value = pda("eventAuthority"))),
        codama(account(name = "self_program"))
    )]
    Distribute(
        #[cfg_attr(feature = "idl", codama(name = "distribute_args"))]
        distribute::DistributeArgs<'a>,
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
    #[cfg_attr(
        feature = "idl",
        codama(account(name = "event_authority", signer, default_value = pda("eventAuthority")))
    )]
    EmitEvent = 228,
}

impl<'a> PaymentChannelsInstruction<'a> {
    /// Stable, lowercase-snake-case label for this variant. Used by the
    /// integration test CU tracker so report labels are derived from the
    /// instruction enum rather than a hand-rolled mapping in test code. The
    /// exhaustive `match` here means adding a variant without extending this method
    /// fails to compile.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Open(_) => "open",
            Self::Settle(_) => "settle",
            Self::TopUp(_) => "top_up",
            Self::SettleAndFinalize(_) => "settle_and_finalize",
            Self::RequestClose => "request_close",
            Self::Finalize => "finalize",
            Self::Distribute(_) => "distribute",
            Self::WithdrawPayer => "withdraw_payer",
            Self::EmitEvent => "emit_event",
        }
    }

    pub fn from_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
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
        unsafe { *core::ptr::from_ref(v).cast::<u8>() }
    }

    #[test]
    fn discriminators_match_variants() {
        let settle: settle::SettleArgs = unsafe { core::mem::zeroed() };
        let top_up: top_up::TopUpArgs = unsafe { core::mem::zeroed() };
        let saf: settle_and_finalize::SettleAndFinalizeArgs = unsafe { core::mem::zeroed() };

        let open_data = [0u8; 20 + 4];
        let open = open::OpenArgs::load(&open_data).unwrap();
        let distribute_data = 0u32.to_le_bytes();
        let distribute = distribute::DistributeArgs::load(&distribute_data).unwrap();

        assert_eq!(
            tag(&PaymentChannelsInstruction::Open(open)),
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
            tag(&PaymentChannelsInstruction::Distribute(distribute)),
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
