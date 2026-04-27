// Shared helpers for instruction handlers.

pub mod distribution;
pub mod ed25519;
pub mod hash;
pub mod token;
pub mod voucher;

pub use distribution::{
    BPS_DENOMINATOR, DistributionEntry, DistributionRecipients, MAX_DISTRIBUTION_RECIPIENTS,
    ValidatedDistribution, floor_bps_share,
};
pub use hash::blake3;
pub use token::{
    derive_ata, token_account_amount, transfer_checked_signed_if_nonzero, validate_ata_address,
    validate_ata_token_account, validate_mint, validate_token_account,
};

use crate::state::channel::CHANNEL_SEED;
use pinocchio::cpi::Seed;

/// Constructs the PDA signer seeds for a channel account.
///
/// The call site must keep `salt_bytes` and `bump_byte` alive on the stack
/// for the duration of the `invoke_signed` call, since [`Seed`] borrows them.
pub fn channel_signer_seeds<'a>(
    payer: &'a [u8],
    payee: &'a [u8],
    mint: &'a [u8],
    authorized_signer: &'a [u8],
    salt_bytes: &'a [u8; 8],
    bump_byte: &'a [u8; 1],
) -> [Seed<'a>; 7] {
    [
        Seed::from(CHANNEL_SEED),
        Seed::from(payer),
        Seed::from(payee),
        Seed::from(mint),
        Seed::from(authorized_signer),
        Seed::from(salt_bytes.as_ref()),
        Seed::from(bump_byte.as_ref()),
    ]
}
