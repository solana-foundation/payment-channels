// Shared helpers for instruction handlers.

pub mod accounts;
pub mod distribution;
pub mod ed25519;
pub mod hash;
pub mod token;
pub mod transfer;
pub mod voucher;

pub use distribution::{DistributionEntry, DistributionPreimage, MAX_DISTRIBUTION_RECIPIENTS};
pub use transfer::Transfer;

use crate::errors::PaymentChannelsError;
use crate::state::channel::CHANNEL_SEED;
use pinocchio::{AccountView, ProgramResult, cpi::Seed};

/// Fully deallocates a channel PDA: drains EVERY lamport (rent plus any
/// prefund surplus) to `rent_payer`, then zeroes owner + lamports +
/// data_len so the runtime garbage-collects the account at instruction end.
/// Shared by `distribute`'s fast path and `reclaim`.
///
/// Draining to exactly 0 lamports is load-bearing: any residual balance
/// would leave a program-owned husk whose `Allocate` fails at the next
/// `open`, permanently bricking the address. Callers MUST have enforced the
/// reclaim gate (`clock.slot > open_slot + OPEN_SLOT_WINDOW`) first — it is
/// what keeps `(address, open_slot)` unique across incarnations.
pub fn deallocate_channel(
    channel: &mut AccountView,
    rent_payer: &mut AccountView,
) -> ProgramResult {
    // Direct lamport arithmetic is valid here: the channel is program-owned
    // (debitable by this program) and the instruction-wide lamport sum is
    // preserved.
    let drained = channel.lamports();
    let new_rent_payer_bal = rent_payer
        .lamports()
        .checked_add(drained)
        .ok_or(PaymentChannelsError::RentPayerBalanceOverflow)?;
    rent_payer.set_lamports(new_rent_payer_bal);
    channel.set_lamports(0);

    // Zero owner + data_len (lamports already 0); the runtime zeroes the
    // data bytes and reaps the account at instruction end. Within this
    // transaction any later instruction sees `data_len == 0`, so
    // `Channel::load` rejects the dead account on length before anything
    // else runs.
    channel.close()
}

/// Constructs the PDA signer seeds for a channel account.
///
/// The call site must keep `salt_bytes`, `open_slot_bytes`, and `bump_byte`
/// alive on the stack
/// for the duration of the `invoke_signed` call, since [`Seed`] borrows them.
pub fn channel_signer_seeds<'a>(
    payer: &'a [u8],
    payee: &'a [u8],
    mint: &'a [u8],
    authorized_signer: &'a [u8],
    salt_bytes: &'a [u8; 8],
    open_slot_bytes: &'a [u8; 8],
    bump_byte: &'a [u8; 1],
) -> [Seed<'a>; 8] {
    [
        Seed::from(CHANNEL_SEED),
        Seed::from(payer),
        Seed::from(payee),
        Seed::from(mint),
        Seed::from(authorized_signer),
        Seed::from(salt_bytes.as_ref()),
        Seed::from(open_slot_bytes.as_ref()),
        Seed::from(bump_byte.as_ref()),
    ]
}
