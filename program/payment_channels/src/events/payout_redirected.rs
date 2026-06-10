use borsh::BorshSerialize;
#[cfg(feature = "idl")]
use codama::CodamaEvent;
use pinocchio::Address;

use crate::event_engine::{EventDiscriminator, EventSerialize};
use crate::helpers::accounts::view::{PayoutBeneficiary, RedirectReason};

/// Emitted when `distribute` forfeits a nonzero beneficiary share to the
/// treasury because the beneficiary's canonical ATA is unusable (unsupported
/// Token-2022 extension, closed/malformed, or frozen/uninitialized). Makes the
/// otherwise-silent redirect observable to off-chain indexers.
#[derive(BorshSerialize, Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "idl", derive(CodamaEvent))]
#[cfg_attr(feature = "idl", codama(discriminator(bytes = "d116b9d754a75450")))]
pub struct PayoutRedirected {
    /// Channel PDA whose crank performed the redirect.
    pub channel: Address,
    /// Intended beneficiary owner whose share was forfeited.
    pub owner: Address,
    /// Forfeited amount, in mint base units, swept to the treasury instead.
    pub amount: u64,
    /// Which payout role was redirected.
    pub beneficiary: PayoutBeneficiary,
    /// Why the redirect happened.
    pub reason: RedirectReason,
}

impl EventDiscriminator for PayoutRedirected {
    const DISCRIMINATOR: [u8; 8] = crate::anchor_event_disc!("PayoutRedirected");
}

impl EventSerialize for PayoutRedirected {
    // channel (32) + owner (32) + amount (8) + beneficiary (1) + reason (1).
    const DATA_LEN: usize = 32 + 32 + 8 + 1 + 1;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_len_matches_borsh_object_length() {
        let event = PayoutRedirected {
            channel: Address::new_from_array([1u8; 32]),
            owner: Address::new_from_array([2u8; 32]),
            amount: 42,
            beneficiary: PayoutBeneficiary::Recipient,
            reason: RedirectReason::ClosedOrMalformed,
        };
        assert_eq!(
            PayoutRedirected::DATA_LEN,
            borsh::object_length(&event).unwrap()
        );
    }
}
