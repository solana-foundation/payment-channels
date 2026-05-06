#[cfg(feature = "idl")]
use codama::CodamaType;
use core::mem::size_of;
use pinocchio::{Address, error::ProgramError};

use crate::{errors::PaymentChannelsError, state::Transmutable};

/// Maximum number of distribution recipients per channel.
pub const MAX_DISTRIBUTION_RECIPIENTS: usize = 32;

/// Basis-point denominator. `Σ shareBps` may equal this value (recipients
/// fully drain the pool, payee carve-out is zero) or fall below it (the
/// remainder `BPS_DENOMINATOR − Σ` becomes the payee's implicit share at
/// `distribute`).
const BPS_DENOMINATOR: u32 = 10_000;

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
    pub fn new(recipient: Address, bps: u16) -> Self {
        Self {
            recipient,
            bps: bps.to_le_bytes(),
        }
    }

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
    /// Basis points left for the channel payee's implicit remainder share.
    pub payee_bps: u32,
}

// Fails to compile if the literal above drifts from MAX_DISTRIBUTION_RECIPIENTS.
const _: () = assert!(
    MAX_DISTRIBUTION_RECIPIENTS == 32,
    "if MAX_DISTRIBUTION_RECIPIENTS changes, also update: \
     (1) DistributionRecipients::entries length literal here, \
     (2) PaymentChannelsError::InvalidRecipientCount #[error(...)] message in errors.rs",
);

impl DistributionRecipients {
    /// Validates `count` is in `0..=MAX_DISTRIBUTION_RECIPIENTS`, every
    /// active bps entry is non-zero, the active bps sum is at most 10_000,
    /// and no recipient address repeats among the active entries.
    /// `count == 0` collapses to a vanilla two-party channel where the payee
    /// receives 100 % of `pool` at `distribute`. `Σ bps == 10_000` drives the
    /// payee's implicit-remainder share to zero. Dedup is enforced only here
    /// because `distribute` re-establishes the same plan via the blake3
    /// preimage check; floored per-entry shares are biased against aggregated
    /// splits, so duplicates are rejected outright instead of summed downstream.
    pub fn validate(&self) -> Result<ValidatedDistribution<'_>, ProgramError> {
        let n = self.count as usize;
        if n > MAX_DISTRIBUTION_RECIPIENTS {
            return Err(PaymentChannelsError::InvalidRecipientCount.into());
        }
        let mut bps_sum = 0u32;
        let entries = &self.entries[..n];
        for (i, entry) in entries.iter().enumerate() {
            let bps = entry.bps();
            if bps == 0 {
                return Err(PaymentChannelsError::InvalidSplitConfig.into());
            }
            bps_sum = bps_sum
                .checked_add(bps as u32)
                .ok_or(PaymentChannelsError::ArithmeticOverflow)?;
            for prior in &entries[..i] {
                if prior.recipient == entry.recipient {
                    return Err(PaymentChannelsError::DuplicateRecipient.into());
                }
            }
        }
        if bps_sum > BPS_DENOMINATOR {
            return Err(PaymentChannelsError::InvalidSplitConfig.into());
        }
        Ok(ValidatedDistribution {
            entries,
            payee_bps: BPS_DENOMINATOR - bps_sum,
        })
    }

    /// Infallible view of an already-validated distribution plan.
    ///
    /// Caller must hold a proof that `count <= MAX_DISTRIBUTION_RECIPIENTS`
    /// and `Σ bps <= 10_000` — either freshly returned by [`Self::validate`]
    /// (open) or proven byte-identical to a validated plan via
    /// `distribution_hash` equality (distribute). Violating the precondition
    /// either panics on the slice or underflows on `payee_bps`.
    pub fn view_unchecked(&self) -> ValidatedDistribution<'_> {
        let entries = &self.entries[..self.count as usize];
        let bps_sum: u32 = entries.iter().map(|e| e.bps() as u32).sum();
        ValidatedDistribution {
            entries,
            payee_bps: BPS_DENOMINATOR - bps_sum,
        }
    }

    /// Raw bytes of `count(1) || entries[0..count](count×34)` — the blake3
    /// preimage for [`Channel::distribution_hash`](crate::Channel::distribution_hash).
    /// `count` is clamped to `MAX_DISTRIBUTION_RECIPIENTS` so a forged
    /// out-of-range count cannot panic the slice; the unclamped count byte
    /// is preserved verbatim as the first preimage byte, so distinct logical
    /// plans cannot alias to the same digest.
    #[inline(always)]
    pub fn preimage(&self) -> &[u8] {
        let n = (self.count as usize).min(MAX_DISTRIBUTION_RECIPIENTS);
        &self.as_bytes()[..1 + n * DistributionEntry::LEN]
    }

    /// Blake3 hash of the active preimage committed into the channel at `open`.
    pub fn preimage_hash(&self) -> [u8; 32] {
        super::hash::blake3(self.preimage())
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
        let mut entries = [DistributionEntry {
            recipient: Address::default(),
            bps: 100u16.to_le_bytes(),
        }; MAX_DISTRIBUTION_RECIPIENTS];
        // Distinct address per slot so `validate`'s dedup pass passes
        // for any `count`; tests that need duplicates assemble entries inline.
        for (i, e) in entries.iter_mut().enumerate() {
            e.recipient = Address::new_from_array([i as u8 + 1; 32]);
        }
        DistributionRecipients { count, entries }
    }

    #[test]
    fn validate_zero_count_accepted() {
        assert_eq!(make_recipients(0).validate().unwrap().entries.len(), 0,);
    }

    #[test]
    fn validate_returns_active_entries_and_payee_bps() {
        let mut entries = [DistributionEntry {
            recipient: Address::default(),
            bps: 0u16.to_le_bytes(),
        }; MAX_DISTRIBUTION_RECIPIENTS];
        entries[0].recipient = Address::new_from_array([1u8; 32]);
        entries[0].bps = 2500u16.to_le_bytes();
        entries[1].recipient = Address::new_from_array([2u8; 32]);
        entries[1].bps = 3000u16.to_le_bytes();
        let r = DistributionRecipients { count: 2, entries };
        let view = r.validate().unwrap();

        assert_eq!(view.entries.len(), 2);
        assert_eq!(view.payee_bps, 4500);
    }

    #[test]
    fn view_unchecked_returns_active_entries_and_payee_bps() {
        let mut entries = [DistributionEntry {
            recipient: Address::default(),
            bps: 0u16.to_le_bytes(),
        }; MAX_DISTRIBUTION_RECIPIENTS];
        entries[0].bps = 2500u16.to_le_bytes();
        entries[1].bps = 3000u16.to_le_bytes();
        let r = DistributionRecipients { count: 2, entries };
        let view = r.view_unchecked();

        assert_eq!(view.entries.len(), 2);
        assert_eq!(view.payee_bps, 4500);
    }

    #[test]
    fn preimage_clamps_count_above_max_without_panic() {
        // count = MAX + 1 = 33; preimage() must produce a 1 + 32*34 = 1089
        // byte slice (not panic) and its first byte must equal 33 (the
        // unclamped count byte preserved verbatim).
        let mut r = make_recipients(MAX_DISTRIBUTION_RECIPIENTS as u8);
        r.count = MAX_DISTRIBUTION_RECIPIENTS as u8 + 1;
        let bytes = r.preimage();
        assert_eq!(
            bytes.len(),
            1 + MAX_DISTRIBUTION_RECIPIENTS * DistributionEntry::LEN,
        );
        assert_eq!(bytes[0], MAX_DISTRIBUTION_RECIPIENTS as u8 + 1);
    }

    #[test]
    fn validate_max_count_accepted() {
        assert_eq!(
            make_recipients(MAX_DISTRIBUTION_RECIPIENTS as u8)
                .validate()
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
        assert_eq!(r.validate().unwrap().entries.len(), 1);
    }

    #[test]
    fn validate_over_10000_bps_rejected() {
        let mut entries = [DistributionEntry {
            recipient: Address::default(),
            bps: 0u16.to_le_bytes(),
        }; MAX_DISTRIBUTION_RECIPIENTS];
        entries[0].bps = (BPS_DENOMINATOR as u16 + 1).to_le_bytes();
        let r = DistributionRecipients { count: 1, entries };
        assert_eq!(
            r.validate().map(|_| ()),
            Err(ProgramError::from(PaymentChannelsError::InvalidSplitConfig)),
        );
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
        assert_eq!(
            r.validate().map(|_| ()),
            Err(ProgramError::from(
                PaymentChannelsError::InvalidRecipientCount
            )),
        );
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

    #[test]
    fn validate_accepts_distinct_recipients() {
        // make_recipients seeds slot i with address [i+1; 32], so all 32
        // active entries have distinct recipients.
        let r = make_recipients(3);
        assert!(r.validate().is_ok());
    }

    #[test]
    fn validate_rejects_duplicate_recipient() {
        let mut entries = [DistributionEntry {
            recipient: Address::default(),
            bps: 100u16.to_le_bytes(),
        }; MAX_DISTRIBUTION_RECIPIENTS];
        entries[0].recipient = Address::new_from_array([1u8; 32]);
        entries[1].recipient = Address::new_from_array([2u8; 32]);
        entries[2].recipient = Address::new_from_array([1u8; 32]);
        let r = DistributionRecipients { count: 3, entries };
        assert_eq!(
            r.validate().map(|_| ()),
            Err(ProgramError::from(PaymentChannelsError::DuplicateRecipient)),
        );
    }

    #[test]
    fn validate_ignores_inactive_tail() {
        // Active prefix is unique; inactive tail repeats an active address.
        // Dedup must scan only `entries[..count]`.
        let mut entries = [DistributionEntry {
            recipient: Address::default(),
            bps: 100u16.to_le_bytes(),
        }; MAX_DISTRIBUTION_RECIPIENTS];
        entries[0].recipient = Address::new_from_array([1u8; 32]);
        entries[1].recipient = Address::new_from_array([2u8; 32]);
        for e in entries[2..].iter_mut() {
            e.recipient = Address::new_from_array([1u8; 32]);
        }
        let r = DistributionRecipients { count: 2, entries };
        assert!(r.validate().is_ok());
    }
}
