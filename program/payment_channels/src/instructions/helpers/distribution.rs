#[cfg(feature = "idl")]
use codama::CodamaType;
use core::mem::size_of;
use pinocchio::{Address, error::ProgramError};

use crate::errors::PaymentChannelsError;
use crate::state::Transmutable;

/// Maximum number of distribution recipients per channel.
pub const MAX_DISTRIBUTION_RECIPIENTS: usize = 32;

/// Basis-point denominator. `Σ shareBps` may equal this value (recipients
/// fully drain the pool, payee carve-out is zero) or fall below it (the
/// remainder `BPS_DENOMINATOR − Σ` becomes the payee's implicit share at
/// `distribute`).
pub const BPS_DENOMINATOR: u32 = 10_000;

/// One entry in the distribution plan committed at `open`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "idl", derive(CodamaType))]
pub struct DistributionEntry {
    pub recipient: Address,
    #[cfg_attr(feature = "idl", codama(type = number(u16)))]
    bps: [u8; 2],
}

impl DistributionEntry {
    #[inline(always)]
    pub fn bps(&self) -> u16 {
        u16::from_le_bytes(self.bps)
    }
}

/// Packed distribution plan committed at `open` and verified by `distribute`.
///
/// Wire layout: `count(1) | entries(32×34)`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "idl", derive(CodamaType))]
pub struct DistributionRecipients {
    /// Number of active entries (0–[`MAX_DISTRIBUTION_RECIPIENTS`]).
    pub count: u8,
    // Codama requires a literal here; keep in sync with MAX_DISTRIBUTION_RECIPIENTS.
    pub entries: [DistributionEntry; 32],
}

/// Validated active view over a packed distribution preimage.
pub struct ValidatedDistribution<'a> {
    /// Active entries selected by `DistributionRecipients::count`.
    pub entries: &'a [DistributionEntry],
    /// Sum of all active recipient basis points.
    pub bps_sum: u32,
    /// Basis points left for the channel payee's implicit remainder share.
    pub payee_bps: u32,
}

// Fails to compile if the literal above drifts from MAX_DISTRIBUTION_RECIPIENTS.
const _: () = assert!(
    MAX_DISTRIBUTION_RECIPIENTS == 32,
    "update DistributionRecipients::entries literal to match MAX_DISTRIBUTION_RECIPIENTS",
);

impl DistributionRecipients {
    /// Validates `count` is in `0..=MAX_DISTRIBUTION_RECIPIENTS`, every
    /// active bps entry is non-zero, and the active bps sum is at most
    /// 10_000. `count == 0` collapses to a vanilla two-party channel where
    /// the payee receives 100 % of `pool` at `distribute`. `Σ bps == 10_000`
    /// drives the payee's implicit-remainder share to zero.
    pub fn validate_view(&self) -> Result<ValidatedDistribution<'_>, ProgramError> {
        let n = self.count as usize;
        if n > MAX_DISTRIBUTION_RECIPIENTS {
            return Err(PaymentChannelsError::InvalidRecipientCount.into());
        }
        let mut bps_sum = 0u32;
        let entries = &self.entries[..n];
        for entry in entries.iter() {
            let bps = entry.bps();
            if bps == 0 {
                return Err(PaymentChannelsError::InvalidSplitConfig.into());
            }
            bps_sum = bps_sum
                .checked_add(bps as u32)
                .ok_or(PaymentChannelsError::ArithmeticOverflow)?;
        }
        if bps_sum > BPS_DENOMINATOR {
            return Err(PaymentChannelsError::InvalidSplitConfig.into());
        }
        Ok(ValidatedDistribution {
            entries,
            bps_sum,
            payee_bps: BPS_DENOMINATOR - bps_sum,
        })
    }

    /// Raw bytes of `count(1) || entries[0..count](count×34)` — the blake3
    /// preimage for [`Channel::distribution_hash`](crate::Channel::distribution_hash).
    #[inline(always)]
    pub fn preimage(&self) -> &[u8] {
        let n = self.count as usize;
        &self.as_bytes()[..1 + n * DistributionEntry::LEN]
    }

    /// Blake3 hash of the active preimage committed into the channel at `open`.
    pub fn preimage_hash(&self) -> [u8; 32] {
        super::blake3(self.preimage())
    }
}

unsafe impl Transmutable for DistributionRecipients {
    const LEN: usize = size_of::<Self>();
}

unsafe impl Transmutable for DistributionEntry {
    const LEN: usize = size_of::<Self>();
}

const _: () = assert!(size_of::<DistributionEntry>() == 34);

/// `floor(pool * bps / 10_000)` in u128 to avoid overflow.
#[inline]
pub fn floor_bps_share(pool: u64, bps: u32) -> Result<u64, ProgramError> {
    let prod = (pool as u128)
        .checked_mul(bps as u128)
        .ok_or(PaymentChannelsError::ArithmeticOverflow)?;
    Ok((prod / (BPS_DENOMINATOR as u128)) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_recipients(count: u8) -> DistributionRecipients {
        let entry = DistributionEntry {
            recipient: Address::default(),
            bps: 100u16.to_le_bytes(),
        };
        DistributionRecipients {
            count,
            entries: [entry; MAX_DISTRIBUTION_RECIPIENTS],
        }
    }

    #[test]
    fn validate_zero_count_accepted() {
        assert_eq!(make_recipients(0).validate_view().unwrap().entries.len(), 0,);
    }

    #[test]
    fn validate_view_returns_active_entries_and_payee_bps() {
        let mut entries = [DistributionEntry {
            recipient: Address::default(),
            bps: 0u16.to_le_bytes(),
        }; MAX_DISTRIBUTION_RECIPIENTS];
        entries[0].bps = 2500u16.to_le_bytes();
        entries[1].bps = 3000u16.to_le_bytes();
        let r = DistributionRecipients { count: 2, entries };
        let view = r.validate_view().unwrap();

        assert_eq!(view.entries.len(), 2);
        assert_eq!(view.bps_sum, 5500);
        assert_eq!(view.payee_bps, 4500);
    }

    #[test]
    fn validate_max_count_accepted() {
        assert_eq!(
            make_recipients(MAX_DISTRIBUTION_RECIPIENTS as u8)
                .validate_view()
                .unwrap()
                .entries
                .len(),
            MAX_DISTRIBUTION_RECIPIENTS,
        );
    }

    #[test]
    fn validate_full_bps_sum_accepted() {
        let mut entries = [DistributionEntry {
            recipient: Address::default(),
            bps: 0u16.to_le_bytes(),
        }; MAX_DISTRIBUTION_RECIPIENTS];
        entries[0].bps = (BPS_DENOMINATOR as u16).to_le_bytes();
        let r = DistributionRecipients { count: 1, entries };
        assert_eq!(r.validate_view().unwrap().entries.len(), 1);
    }

    #[test]
    fn validate_over_10000_bps_rejected() {
        let mut entries = [DistributionEntry {
            recipient: Address::default(),
            bps: 0u16.to_le_bytes(),
        }; MAX_DISTRIBUTION_RECIPIENTS];
        entries[0].bps = (BPS_DENOMINATOR as u16 + 1).to_le_bytes();
        let r = DistributionRecipients { count: 1, entries };
        assert!(r.validate_view().is_err());
    }

    #[test]
    fn validate_over_max_rejected() {
        let r = DistributionRecipients {
            count: MAX_DISTRIBUTION_RECIPIENTS as u8 + 1,
            entries: [DistributionEntry {
                recipient: Address::default(),
                bps: [0u8; 2],
            }; MAX_DISTRIBUTION_RECIPIENTS],
        };
        assert!(r.validate_view().is_err());
    }

    #[test]
    fn preimage_length_matches_count() {
        for n in 1..=MAX_DISTRIBUTION_RECIPIENTS {
            let r = make_recipients(n as u8);
            assert_eq!(r.preimage().len(), 1 + n * DistributionEntry::LEN);
        }
    }

    #[test]
    fn preimage_first_byte_is_count() {
        let r = make_recipients(7);
        assert_eq!(r.preimage()[0], 7);
    }

    #[test]
    fn preimage_hash_is_deterministic() {
        let r = make_recipients(3);
        assert_eq!(r.preimage_hash(), r.preimage_hash());
    }

    #[test]
    fn preimage_hash_differs_by_count() {
        let mut r1 = make_recipients(1);
        let mut r2 = make_recipients(2);
        r1.entries[0].recipient = Address::default();
        r2.entries[0].recipient = Address::default();
        assert_ne!(r1.preimage_hash(), r2.preimage_hash());
    }

    #[test]
    fn floor_bps_share_rounds_down() {
        assert_eq!(floor_bps_share(10, 3333).unwrap(), 3);
        assert_eq!(floor_bps_share(10, 3334).unwrap(), 3);
    }
}
